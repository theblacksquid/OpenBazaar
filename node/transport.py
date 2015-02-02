import constants
from collections import defaultdict
import hashlib
import json
import logging
from pprint import pformat
import random
import sys
import traceback
import xmlrpclib

import gnupg
import obelisk
from bitcoin.main import privkey_to_pubkey, random_key
from pysqlcipher.dbapi2 import OperationalError, DatabaseError
from zmq.eventloop import ioloop
from zmq.eventloop.ioloop import PeriodicCallback

from node import connection, network_util, trust
from node.dht import DHT
from rudp.packet import Packet
import socket


class TransportLayer(object):
    """TransportLayer manages a list of peers."""

    def __init__(self, ob_ctx, guid, nickname=None):
        self.peers = {}
        self.callbacks = defaultdict(list)
        self.timeouts = []
        self.port = ob_ctx.server_port
        self.hostname = ob_ctx.server_ip
        self.guid = guid
        self.market_id = ob_ctx.market_id
        self.nickname = nickname
        self.handler = None
        self.uri = network_util.get_peer_url(self.hostname, self.port)
        self.listener = None

        self.mediate_peers = []

        self.log = logging.getLogger(
            '[%s] %s' % (ob_ctx.market_id, self.__class__.__name__)
        )

    def add_callbacks(self, callbacks):
        for section, callback in callbacks:
            self.callbacks[section] = []
            self.add_callback(section, callback)

    def set_websocket_handler(self, handler):
        self.handler = handler

    def add_callback(self, section, callback):
        if callback not in self.callbacks[section]:
            self.callbacks[section].append(callback)

    def trigger_callbacks(self, section, *data):
        """Run all callbacks in specified section."""
        for cb in self.callbacks[section]:
            if cb['validator_cb'](*data):
                cb['cb'](*data)

        # Run all callbacks registered under the 'all' section. Don't duplicate
        # calls if the specified section was 'all'.
        if not section == 'all':
            for cb in self.callbacks['all']:
                if cb['validator_cb'](*data):
                    cb['cb'](*data)


class CryptoTransportLayer(TransportLayer):

    def __init__(self, ob_ctx, db_connection):

        self.ob_ctx = ob_ctx

        self.log = logging.getLogger(
            '[%s] %s' % (ob_ctx.market_id, self.__class__.__name__)
        )
        requests_log = logging.getLogger("requests")
        requests_log.setLevel(logging.WARNING)

        self.db_connection = db_connection

        self.bitmessage_api = None
        if (ob_ctx.bm_user, ob_ctx.bm_pass, ob_ctx.bm_port) != (None, None, -1):
            if not self._connect_to_bitmessage():
                self.log.info('Bitmessage not installed or started')

        self.market_id = ob_ctx.market_id
        self.nick_mapping = {}
        self.uri = network_util.get_peer_url(ob_ctx.server_ip, ob_ctx.server_port)
        self.hostname = ob_ctx.server_ip
        self.nickname = ""
        self.dev_mode = ob_ctx.dev_mode

        self._connections = {}

        self.all_messages = (
            'hello',
            'goodbye',
            'findNode',
            'findNodeResponse',
            'store',
            'mediate',
            'register',
            'punch',
        )

        self._setup_settings()
        ob_ctx.market_id = self.market_id
        self.dht = DHT(self, self.market_id, self.settings, self.db_connection)
        TransportLayer.__init__(self, ob_ctx, self.guid, self.nickname)
        self.start_listener()

        if ob_ctx.enable_ip_checker and not ob_ctx.seed_mode and not ob_ctx.dev_mode:
            self.start_ip_address_checker()

    def start_mediation(self, guid):
        self.log.debug('Starting mediation %s' % self.ob_ctx)
        if self.ob_ctx.mediator:
            for peer in self.dht.activePeers:
                if peer.hostname == '205.186.156.31':
                    peer.send({
                        'type': 'mediate',
                        'guid': self.guid,
                        'guid2': guid
                    })

    def start_listener(self):
        self.add_callbacks([
            (
                msg,
                {
                    'cb': getattr(self, 'on_%s' % msg),
                    'validator_cb': getattr(self, 'validate_on_%s' % msg)
                }
            )
            for msg in self.all_messages
        ])

        self.listener = connection.CryptoPeerListener(
            self.hostname, self.port, self.pubkey, self.secret,
            self.guid,
            self._on_message
        )

        @self.listener.ee.on('on_message')
        def on_message(msg):

            data, addr = msg[0], msg[1]
            self.log.debug('on_message: %s %s %s' % (data, 'from', addr))

            try:
                data_body = json.loads(data)

                # Peer metadata
                guid = data_body.get('guid')
                pubkey = data_body.get('pubkey')
                port = addr[1]
                hostname = addr[0]
                nickname = data_body.get('nick')

                inbound_peer = self.dht.add_peer(hostname, port, pubkey, guid, nickname)

                if inbound_peer:

                    packet = Packet(data, buffer=True)

                    if packet._finish:
                        inbound_peer.reset()
                        return
                        # del self._connections[address_key]
                    else:
                        def receive_packet():
                            inbound_peer._rudp_connection.receive(packet)

                        receive_packet()

                    self.log.debug('Updated peers: %s', self.dht.activePeers)
                else:
                    self.log.debug('Did not find a peer')
            except Exception as e:
                self.log.error('Could not deserialize message: %s' % e)


        self.listener.set_ok_msg({
            'type': 'ok',
            'senderGUID': self.guid,
            'pubkey': self.pubkey,
            'senderNick': self.nickname
        })
        self.listener.listen()


    def start_ip_address_checker(self):
        '''Checks for possible public IP change'''
        if self.ob_ctx.enable_ip_checker:
            self.caller = PeriodicCallback(self._ip_updater_periodic_callback, 5000, ioloop.IOLoop.instance())
            self.caller.start()
            self.log.info("IP_CHECKER_ENABLED: Periodic IP Address Checker started.")

    def _ip_updater_periodic_callback(self):
        if self.ob_ctx.enable_ip_checker:
            new_ip = network_util.get_my_ip()

            if not new_ip or new_ip == self.ip:
                return

            self.ob_ctx.server_ip = new_ip
            self.ip = new_ip

            if self.listener is not None:
                self.listener.set_ip_address(new_ip)

            self.dht.iterative_find(self.guid, [], 'findNode')

    def save_peer_to_db(self, peer_tuple):
        hostname = peer_tuple[0]
        port = peer_tuple[1]
        pubkey = peer_tuple[2]
        guid = peer_tuple[3]
        nickname = peer_tuple[4]

        # Update query
        self.db.deleteEntries("peers", {"hostname": hostname, "guid": guid}, "OR")
        if guid is not None:
            self.db.insertEntry("peers", {
                "hostname": hostname,
                "port": port,
                "pubkey": pubkey,
                "guid": guid,
                "nickname": nickname,
                "market_id": self.market_id
            })

    def _connect_to_bitmessage(self):
        # Get bitmessage going
        # First, try to find a local instance
        result = False
        bm_user = self.ob_ctx.bm_user
        bm_pass = self.ob_ctx.bm_pass
        bm_port = self.ob_ctx.bm_port
        try:
            self.log.info(
                '[_connect_to_bitmessage] Connecting to Bitmessage on port %s',
                bm_port
            )
            self.bitmessage_api = xmlrpclib.ServerProxy(
                "http://{}:{}@localhost:{}/".format(bm_user, bm_pass, bm_port),
                verbose=0
            )
            result = self.bitmessage_api.add(2, 3)
            self.log.info(
                "[_connect_to_bitmessage] Bitmessage API is live: %s",
                result
            )
        # If we failed, fall back to starting our own
        except Exception as exc:
            self.log.info("Failed to connect to bitmessage instance: %s", exc)
            self.bitmessage_api = None
        return result

    def validate_on_goodbye(self, msg):
        self.log.debug('Validating goodbye message.')
        return True

    def on_goodbye(self, msg):
        self.log.info('Received Goodbye: %s', json.dumps(msg, ensure_ascii=False))
        self.dht.remove_peer(msg.get('senderGUID'))

    def validate_on_mediate(self, msg):
        """

        :param msg:
        :return:
        """
        self.log.debug('Validating mediate message.')
        return self.ob_ctx.seed_mode

    def on_mediate(self, msg):
        self.log.info('Received Mediate Message: %s', json.dumps(msg, ensure_ascii=False))

        def send_punches():

            peer1, peer2 = None, None

            # Send both peers a message to message each other
            for x in self.dht.activePeers:
                if x.guid == msg['senderGUID']:
                    self.log.debug('Found guid')
                    peer1 = x
                if x.guid == msg['guid2']:
                    self.log.debug('Found guid2')
                    peer2 = x
                if peer1 and peer2:
                    continue

            if peer1 and peer2:
                self.log.debug('Sending Punches')

                peer1.send_raw(json.dumps({
                    'type': 'punch',
                    'guid': peer2.guid,
                    'hostname': peer2.hostname,
                    'port': peer2.port
                }))

                peer2.send_raw(json.dumps({
                    'type': 'punch',
                    'guid': peer1.guid,
                    'hostname': peer2.hostname,
                    'port': peer2.port
                }))
            else:
                ioloop.IOLoop.instance().call_later(1, send_punches)
        send_punches()

    def validate_on_punch(self, msg):
        return True

    def on_punch(self, msg):
        self.log.debug('Got a punch request')

        hostname, port = msg['hostname'], msg['port']
        sock = socket.socket(socket.AF_INET, # Internet
             socket.SOCK_DGRAM) # UDP

        def send_packet(counter=0):
            if counter < 5:
                sock.sendto(json.dumps({}), (hostname, port))
                ioloop.IOLoop.instance().call_later(.5, send_packet, (counter+1,))

        send_packet()

    def validate_on_register(self, msg):
        self.log.debug('Validating register message.')
        return self.ob_ctx.seed_mode

    def on_register(self, msg):
        self.log.info('Received register: %s', json.dumps(msg, ensure_ascii=False))

        # Add entry to mediator table
        self.mediate_peers = [x for x in self.mediate_peers if not x.get('guid') == msg['senderGUID']]
        self.mediate_peers.append({
            'guid': msg['senderGUID'],
            'hostname': msg['hostname'],
            'port': msg['port']
        })

    def validate_on_hello(self, msg):
        self.log.debug('Validating hello message.')
        return True

    def on_hello(self, msg):

        self.log.info('Received Hello: %s', json.dumps(msg, ensure_ascii=False))

        peer = self.dht.routingTable.getContact(msg['senderGUID'])

        # new_peer = self.dht.add_peer(
        #     msg['hostname'],
        #     msg['port'],
        #     msg['pubkey'],
        #     msg['senderGUID'],
        #     msg['senderNick'],
        #     dump=True
        # )

        if peer:
            peer.send_raw(
                json.dumps({
                    'type': 'helloResponse',
                    'pubkey': self.pubkey,
                    'senderGUID': self.guid,
                    'hostname': self.hostname,
                    'port': self.port,
                    'senderNick': self.nickname,
                    'v': constants.VERSION
                })
            )

    def validate_on_store(self, msg):
        self.log.debugv('Validating store value message.')
        return True

    def on_store(self, msg):
        self.dht._on_store_value(msg)

    def validate_on_findNode(self, msg):
        self.log.debugv('Validating find node message.')
        return True

    def on_findNode(self, msg):
        self.dht.on_find_node(msg)

    def validate_on_findNodeResponse(self, msg):
        self.log.debugv('Validating find node response message.')
        return True

    def on_findNodeResponse(self, msg):  # pylint: disable=invalid-name
        self.dht.on_find_node_response(msg)

    def _setup_settings(self):
        try:
            self.settings = self.db_connection.select_entries("settings", {"market_id": self.market_id})
        except (OperationalError, DatabaseError) as err:
            print err
            raise SystemExit("database file %s corrupt or empty - cannot continue" % self.db_connection.db_path)

        if len(self.settings) == 0:
            self.settings = {"market_id": self.market_id, "welcome": "enable"}
            self.db_connection.insert_entry("settings", self.settings)
        else:
            self.settings = self.settings[0]

        # Generate PGP key during initial setup or if previous PGP gen failed
        if not self.settings.get('PGPPubKey'):
            try:
                self.log.info('Generating PGP keypair. This may take several minutes...')
                print 'Generating PGP keypair. This may take several minutes...'
                gpg = gnupg.GPG()
                input_data = gpg.gen_key_input(key_type="RSA",
                                               key_length=4096,
                                               name_email='pgp@openbazaar.org',
                                               name_comment="Autogenerated by Open Bazaar",
                                               passphrase="P@ssw0rd")
                assert input_data is not None
                key = gpg.gen_key(input_data)
                assert key is not None

                pubkey_text = gpg.export_keys(key.fingerprint)
                newsettings = {"PGPPubKey": pubkey_text, "PGPPubkeyFingerprint": key.fingerprint}
                self.db_connection.update_entries("settings", newsettings, {"market_id": self.market_id})
                self.settings.update(newsettings)

                self.log.info('PGP keypair generated.')
            except Exception as exc:
                sys.exit("Encountered a problem with GPG: %s" % exc)

        if not self.settings.get('pubkey'):
            # Generate Bitcoin keypair
            self._generate_new_keypair()

        if not self.settings.get('nickname'):
            newsettings = {'nickname': 'Default'}
            self.db_connection.update_entries('settings', newsettings, {"market_id": self.market_id})
            self.settings.update(newsettings)

        self.nickname = self.settings.get('nickname', '')
        self.namecoin_id = self.settings.get('namecoin_id', '')
        self.secret = self.settings.get('secret', '')
        self.pubkey = self.settings.get('pubkey', '')
        self.privkey = self.settings.get('privkey')
        self.btc_pubkey = privkey_to_pubkey(self.privkey)
        self.guid = self.settings.get('guid', '')
        self.sin = self.settings.get('sin', '')
        self.bitmessage = self.settings.get('bitmessage', '')

        if not self.settings.get('bitmessage'):
            # Generate Bitmessage address
            if self.bitmessage_api is not None:
                self._generate_new_bitmessage_address()

        # In case user wants to override with command line passed bitmessage values
        if self.ob_ctx.bm_user is not None and \
           self.ob_ctx.bm_pass is not None and \
           self.ob_ctx.bm_port is not None:
            self._connect_to_bitmessage()

    def _generate_new_keypair(self):
        secret = str(random.randrange(2 ** 256))
        self.secret = hashlib.sha256(secret).hexdigest()
        self.pubkey = privkey_to_pubkey(self.secret)
        self.privkey = random_key()
        self.btc_pubkey = privkey_to_pubkey(self.privkey)
        print 'PUBLIC KEY: ', self.btc_pubkey

        # Generate SIN
        sha_hash = hashlib.sha256()
        sha_hash.update(self.pubkey)
        ripe_hash = hashlib.new('ripemd160')
        ripe_hash.update(sha_hash.digest())

        self.guid = ripe_hash.hexdigest()
        self.sin = obelisk.EncodeBase58Check('\x0F\x02%s' % ripe_hash.digest())

        newsettings = {
            "secret": self.secret,
            "pubkey": self.pubkey,
            "privkey": self.privkey,
            "guid": self.guid,
            "sin": self.sin
        }
        self.db_connection.update_entries("settings", newsettings, {"market_id": self.market_id})
        self.settings.update(newsettings)

    def _generate_new_bitmessage_address(self):
        # Use the guid generated previously as the key
        self.bitmessage = self.bitmessage_api.createRandomAddress(
            self.guid.encode('base64'),
            False,
            1.05,
            1.1111
        )
        newsettings = {"bitmessage": self.bitmessage}
        self.db_connection.update_entries("settings", newsettings, {"market_id": self.market_id})
        self.settings.update(newsettings)

    def join_network(self, seeds=None, callback=None):
        if seeds is None:
            seeds = []

        self.log.info('Joining network')

        # Connect up through seed servers
        for idx, seed in enumerate(seeds):
            seeds[idx] = (seed[0], int(seed[1]))

        # Connect to persisted peers
        db_peers = self.get_past_peers()

        known_peers = list(set(seeds).union(db_peers))

        for known_peer in known_peers:

            hostname, port = known_peer[0], known_peer[1]
            peer_obj = self.get_crypto_peer(None, hostname, port)

            peer_obj.send_raw(
                json.dumps({
                    'type': 'hello',
                    'pubkey': self.pubkey,
                    'senderGUID': self.guid,
                    'hostname': self.hostname,
                    'port': self.port,
                    'senderNick': self.nickname,
                    'v': constants.VERSION
                })
            )

        # Populate routing table by searching for non-existent key
        def join_callback():
            if known_peers:
                self.search_for_my_node()
            else:
                ioloop.IOLoop.instance().call_later(2, join_callback)
        ioloop.IOLoop.instance().call_later(2, join_callback)

        if callback is not None:
            callback('Joined')

    def get_past_peers(self):
        result = self.db.selectEntries("peers", {"market_id": self.market_id})
        return [(peer['hostname'], peer['port']) for peer in result]

    def search_for_my_node(self):
        self.log.info('Searching for myself')
        self.dht._iterativeFind('0000000000000000000000000000000000000000', [], 'findNode')

    def get_crypto_peer(self, guid=None, hostname=None, port=None, pubkey=None, nickname=None):
        if guid == self.guid:
            self.log.error('Cannot get CryptoPeerConnection for your own node')
            return

        # self.log.debug(
        #     'Getting CryptoPeerConnection'
        #     '\nGUID: %s',
        #     '\nHost: %s:%s' % (hostname, port),
        #     '\nPubkey:%s'
        #     '\nNickname:%s',
        #     guid, hostname, '%d' % port, pubkey, nickname
        # )

        if guid not in self.peers:
            self.peers[guid] = connection.CryptoPeerConnection(
                self,
                hostname,
                port,
                pubkey,
                guid=guid,
                nickname=nickname,
                socket=self.listener.socket
            )
        else:
            # FIXME this is wrong to do here, but it keeps this as close as
            # possible to the original pre-connection-reuse behavior
            if hostname:
                self.peers[guid].hostname = hostname
            if port:
                self.peers[guid].port = port
            if pubkey:
                self.peers[guid].pub = pubkey
            if nickname:
                self.peers[guid].nickname = nickname

        return self.peers[guid]

    def send(self, data, send_to=None, callback=None):

        # Directed message
        if send_to is not None:

            peer = self.dht.routing_table.get_contact(send_to)
            if peer is None:
                for active_peer in self.dht.active_peers:
                    if active_peer.guid == send_to:
                        peer = active_peer
                        break

            if peer:
                msg_type = data.get('type', 'unknown')
                nickname = peer.nickname
                hostname, port = peer.hostname, peer.port

                self.log.info('Sending message type "%s" to "%s" %s %s',
                              msgType, nickname, hostname, send_to)
                self.log.datadump('Raw message: %s', data)

                try:
                    peer.send(data, callback=callback)
                except Exception as exc:
                    self.log.error('Failed to send message directly to peer %s', exc)

            else:
                self.log.warning("Couldn't find peer %s to send message type %s",
                                 send_to, data.get('type'))

        else:
            # FindKey and then send

            for peer in self.dht.active_peers:
                try:
                    routing_peer = self.dht.routing_table.get_contact(peer.guid)

                    if routing_peer is None:
                        self.dht.routing_table.add_contact(peer)
                        routing_peer = peer

                    data['senderGUID'] = self.guid
                    data['pubkey'] = self.pubkey

                    def cb(msg):
                        self.log.debug('Message Back: \n%s', pformat(msg))

                    routing_peer.send(data, cb)

                except Exception:
                    self.log.info("Error sending over peer!")
                    traceback.print_exc()

    def _on_message(self, msg):

        # here goes the application callbacks
        # we get a "clean" msg which is a dict holding whatever

        pubkey = msg.get('pubkey')
        hostname = msg.get('hostname')
        port = msg.get('port')
        guid = msg.get('senderGUID')
        nickname = msg.get('senderNick', '')[:120]
        msg_type = msg.get('type')
        namecoin = msg.get('senderNamecoin')

        # Checking for malformed URIs
        # if not network_util.is_valid_uri(uri):
        #     self.log.error('Malformed URI: %s', uri)
        #     return

        # Validate the claimed namecoin in DNSChain
        if not trust.is_valid_namecoin(namecoin, guid):
            msg['senderNamecoin'] = ''

        self.log.info('Received message type "%s" from "%s" %s %s',
                      msgType, nickname, hostname, guid)
        self.log.datadump('Raw message: %s', json.dumps(msg, ensure_ascii=False))
        #self.dht.add_peer(uri, pubkey, guid, nickname)
        self.trigger_callbacks(msg['type'], msg)

    def store(self, *args, **kwargs):
        """
        Store or republish data.

        Refer to the dht module (iterative_store()) for further details.
        """
        self.dht.iterative_store(*args, **kwargs)

    def shutdown(self):
        print "CryptoTransportLayer.shutdown()!"
        print "Notice: explicit DHT Shutdown not implemented."

        try:
            if self.bitmessage_api is not None:
                self.bitmessage_api.close()
        except Exception as exc:
            # It might not even be open; we can't do much more on our
            # way out if exception is thrown here.
            self.log.error(
                "Could not shutdown bitmessage_api's ServerProxy: %s", exc.message
            )
