import json
import logging
from pprint import pformat
from pyee import EventEmitter
from threading import Thread
import sys
import time

import obelisk
import socket

from node import constants, network_util
from node.crypto_util import Cryptor
from node.guid import GUIDMixin
from rudp.connection import Connection
from rudp.packetsender import PacketSender
from tornado import ioloop


class PeerConnection(GUIDMixin, object):
    def __init__(self, guid, transport, hostname, port=12345, nickname="", peer_socket=None, nat_type=None):

        GUIDMixin.__init__(self, guid)

        self.transport = transport
        self.hostname = hostname
        self.port = port
        self.nickname = nickname
        self.reachable = False
        self.nat_type = nat_type

        if nat_type == 'Symmetric NAT':
            self.relaying = True
        else:
            self.relaying = False

        self.seed = False
        self.punching = False

        self.log = logging.getLogger(
            '[%s] %s' % (self.transport.market_id, self.__class__.__name__)
        )

        self.log.info('Created a peer connection object')

        self.ee = EventEmitter()
        self.sock = peer_socket

        self.init_packetsender()

    def init_packetsender(self):
        self._packet_sender = PacketSender(
            self.sock,
            self.hostname,
            self.port,
            self.transport,
            self.nat_type
        )

        self._rudp_connection = Connection(self._packet_sender)

        self.packetsmasher = {}
        self.message_size = 0
        self.is_listening = True
        self.hello = False

    def send(self, data, callback):
        self.send_raw(json.dumps(data), callback)

    def send_raw(self, serialized, callback=None, relay=False):
        if self.transport.seed_mode or relay:
            self.send_to_rudp(serialized)
            return

        def sending_out():
            if self.reachable:
                if self.nat_type == 'Full Cone' or self.seed:
                    self.send_to_rudp(serialized)
                    return
                elif self.relaying or self.nat_type == 'Symmetric NAT' or self.transport.nat_type == 'Symmetric NAT':
                    # Relay through seed server
                    self.log.debug('Relay through seed')
                    self.transport.relay_message(serialized, self.guid)
                    return
            else:
                if self.nat_type == 'Restric NAT' and not self.punching and not self.relaying:
                    self.log.debug('Found restricted NAT client')
                    self.transport.start_mediation(self.guid)
                if self.nat_type == 'Full Cone':
                    self.send_to_rudp(serialized)

            ioloop.IOLoop.instance().call_later(0.5, sending_out)
        sending_out()

    def send_to_rudp(self, data):
        self._rudp_connection.send(data)

    def reset(self):
        self.log.debug('Reset 2')
        self._rudp_connection._sender._sending = None
        self._rudp_connection._sender._push()
        self.is_listening = False


class CryptoPeerConnection(PeerConnection):

    def __init__(self, transport, hostname, port, pub=None, guid=None, nickname="",
                 sin=None, rudp_connection=None, peer_socket=None, nat_type=None):

        PeerConnection.__init__(self, guid, transport, hostname, port, nickname, peer_socket, nat_type)

        self.pub = pub
        self.sin = sin
        self.waiting = False  # Waiting for ping-pong

        self.setup_emitters()

        if not self.reachable:
            self.log.debug('Peer is not reachable. Trying to ping.')

            # Test connectivity to peer
            self.waiting = True
            self.send_ping()

            def try_to_mediate():
                self.log.debug('Trying to reach peer: %s %s %s', self.reachable, self.waiting, id(self))

                if guid is not None and not self.nat_type:
                    self.transport.get_nat_type(guid)

            ioloop.IOLoop.instance().call_later(5, try_to_mediate)

    def send_ping(self):
        # Send ping over to peer and see if we get a quick response
        msg = {
            'type': 'ping',
            'senderGUID': self.transport.guid,
            'hostname': self.hostname,
            'port': self.port,
            'senderNick': self.nickname,
            'nat_type': self.transport.nat_type
        }
        self.send_raw(json.dumps(msg))
        return True

    def setup_emitters(self):
        self.log.debug('Setting up emitters')
        self.ee = EventEmitter()

        @self._rudp_connection._sender.ee.on('timeout')
        def on_timeout(data):  # pylint: disable=unused-variable
            self.log.debug('Node Sender Timed Out')
            #self.transport.dht.remove_peer(self.guid)

        @self._rudp_connection.ee.on('data')
        def handle_recv(msg):  # pylint: disable=unused-variable
            try:
                self.log.debug('Got the whole message: %s', msg.get('payload'))
                payload = json.loads(msg.get('payload'))
                self.transport.listener._on_raw_message(payload)
                return
            except Exception as e:
                self.log.debug('Problem with serializing: %s', e)

            try:
                payload = msg.get('payload').decode('hex')
                self.transport.listener._on_raw_message(payload)
            except Exception as e:
                self.log.debug('not yet %s', e)
                self.transport.listener._on_raw_message(msg.get('payload'))

    def start_handshake(self, initial_handshake_cb=None):
        # TODO: Think about removing completely
        self.log.debug('Deprecated')
        # def cb(msg, handshake_cb=None):
        #     if not msg:
        #         return
        #
        #     self.log.debugv('ALIVE PEER %s', msg[0])
        #     msg = msg[0]
        #     try:
        #         msg = json.loads(msg)
        #     except ValueError:
        #         self.log.error('[start_handshake] Bad JSON response: %s', msg)
        #         return
        #
        #     # Update Information
        #     self.guid = msg['senderGUID']
        #     self.sin = self.generate_sin(self.guid)
        #     self.pub = msg['pubkey']
        #     self.nickname = msg['senderNick']
        #
        #     # Add this peer to active peers list
        #     for idx, peer in enumerate(self.transport.dht.activePeers):
        #         if peer.guid == self.guid or \
        #                         (peer.hostname, peer.port) == (self.hostname, self.port):
        #             self.transport.dht.activePeers[idx] = self
        #             self.transport.dht.add_peer(
        #                 self.hostname,
        #                 self.port,
        #                 self.pub,
        #                 self.guid,
        #                 self.nickname
        #             )
        #             return
        #
        #     self.transport.dht.activePeers.append(self)
        #     self.transport.dht.routing_table.addContact(self)
        #     self.log.debug('Active Peers %s', self.transport.dht.activePeers)
        #
        #     if initial_handshake_cb is not None:
        #         initial_handshake_cb()

    def __repr__(self):
        return '{ guid: %s, hostname: %s, port: %s, pubkey: %s reachable: %s nat: %s}' % (
            self.guid, self.hostname, self.port, self.pub, self.reachable, self.nat_type
        )

    @staticmethod
    def generate_sin(guid):
        return obelisk.EncodeBase58Check('\x0F\x02%s' + guid.decode('hex'))

    def sign(self, data):
        return self.transport.cryptor.sign(data)

    def encrypt(self, data):
        """
        Encrypt the data with self.pub and return the ciphertext.
        @raises Exception: The encryption failed.
        """
        assert self.pub, "Attempt to encrypt without key."
        cryptor = Cryptor(pubkey_hex=self.pub)
        return cryptor.encrypt(data)

    def send(self, data, callback=None):
        assert self.guid, 'Uninitialized own guid'

        if not self.pub:
            self.log.warn('There is no public key for encryption')
            return

        # Include sender information and version
        data['guid'] = self.guid
        data['senderGUID'] = self.transport.guid
        data['pubkey'] = self.transport.pubkey
        data['senderNick'] = self.transport.nickname
        data['senderNamecoin'] = self.transport.namecoin_id
        data['v'] = constants.VERSION

        # Sign cleartext data
        sig_data = json.dumps(data).encode('hex')
        signature = self.sign(sig_data).encode('hex')

        self.log.datadump('Sending to peer: %s %s', self.hostname,
                          pformat(data))

        try:
            # Encrypt signature and data
            data = self.encrypt(json.dumps({
                'sig': signature,
                'data': sig_data
            }))
        except Exception as exc:
            self.log.error('Encryption failed. %s', exc)
            return

        try:
            # self.send_raw(base64.b64encode(data), callback)
            # TODO: Refactor to protobuf
            self.send_raw(data, callback)
        except Exception as exc:
            self.log.error("Was not able to send raw data: %s", exc)


class PeerListener(GUIDMixin):
    def __init__(self, hostname, port, guid, data_cb):
        super(PeerListener, self).__init__(guid)

        self.hostname = hostname
        self.port = port
        self._data_cb = data_cb
        self.is_listening = False
        self.socket = None
        self.stream = None
        self._ok_msg = None
        self._connections = {}

        self.log = logging.getLogger(self.__class__.__name__)

        self.ee = EventEmitter()

    def set_ip_address(self, new_ip):
        self.hostname = new_ip
        if not self.is_listening:
            return

        try:
            self.stream.close()
            self.listen()
        except Exception as e:
            self.log.error('[Requests] error: %s', e)

    def set_ok_msg(self, ok_msg):
        self._ok_msg = ok_msg

    def listen(self):
        self.log.info("Listening at: %s:%s", self.hostname, self.port)

        if network_util.is_loopback_addr(self.hostname):
            # we are in local test mode so bind that socket on the
            # specified IP
            self.log.info("PeerListener.socket.bind('%s') LOOPBACK", self.hostname)
            self._prepare_datagram_socket()
        elif '[' in self.hostname:
            self.log.info("PeerListener.socket.bind('tcp://[*]:%s') IPV6", self.port)
            self.socket.ipv6 = True
            self._prepare_datagram_socket(socket.AF_INET6)
        else:
            self.log.info("PeerListener.socket.bind('tcp://*:%s') IPV4", self.port)
            # Temporary while I fix things
            self.hostname = '0.0.0.0'
            self._prepare_datagram_socket()

        self.is_listening = True

        def start_listening():
            while self.is_listening:

                try:
                    data, addr = self.socket.recvfrom(2048)
                    self.log.debug('Got data from socket: %s', data[:50])

                    if data[:5] == 'punch':
                        self.log.debug('We just received a hole punch.')
                    else:
                        self.ee.emit('on_message', (data, addr))

                except socket.timeout as e:
                    err = e.args[0]

                    if err == 'timed out':
                        time.sleep(1)
                        continue
                    else:
                        sys.exit(1)
                except socket.error:
                    # No data. This is normal.
                    pass
                # except AttributeError as err:
                #     print 'Packet was jacked up: %s', err

        Thread(target=start_listening).start()

    def _on_raw_message(self, serialized):
        self.log.info("connected %d", len(serialized))
        try:
            msg = json.loads(serialized[0])
        except ValueError:
            self.log.info("incorrect msg! %s", serialized)
            return

        self._data_cb(msg)

    def _prepare_datagram_socket(self, family=socket.AF_INET):
        self.socket = socket.socket(family, socket.SOCK_DGRAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        #self.socket.setblocking(0)
        self.socket.bind((self.hostname, self.port))


class CryptoPeerListener(PeerListener):

    def __init__(self, hostname, port, pubkey, secret, guid, data_cb):

        super(CryptoPeerListener, self).__init__(hostname, port, guid, data_cb)

        self.pubkey = pubkey
        self.secret = secret

        # FIXME: refactor this mess
        # this was copied as is from CryptoTransportLayer
        # soon all crypto code will be refactored and this will be removed
        self.cryptor = Cryptor(pubkey_hex=self.pubkey, privkey_hex=self.secret)

    def is_plaintext_message(self, message):
        """
        Return whether message is a plaintext handshake

        :param message: serialized JSON
        :return: True if proper handshake message
        """
        if type(message) is 'dict':
            return message.get('type')

        try:
            message = json.loads(message)
        except (ValueError, TypeError) as e:
            self.log.debug('Error: %s ', e)
            return False

        return 'type' in message

    def _on_raw_message(self, serialized):
        """
        Handles receipt of encrypted/plaintext message
        and passes to appropriate callback.

        :param serialized:
        :return:
        """

        if not self.is_plaintext_message(serialized):
            message = self.process_encrypted_message(serialized)
        else:
            message = json.loads(serialized)

            # If relayed then unwrap and process again
            if message['type'] == 'relayed_msg':
                self._on_raw_message(message['data'].decode('hex'))
                return

        self.log.debugv('Received message of type "%s"',
                        message.get('type', 'unknown'))

        # Execute callback on message type
        if self._data_cb:
            self._data_cb(message)
        else:
            self.log.debugv('Callbacks not ready yet')

    def process_encrypted_message(self, encrypted_message):
        if type(encrypted_message) is dict:
            message = encrypted_message
        else:
            try:

                message = self.cryptor.decrypt(encrypted_message)
                message = json.loads(message)

                signature = message['sig'].decode('hex')
                signed_data = message['data']

                if CryptoPeerListener.validate_signature(signature, signed_data):
                    message = signed_data.decode('hex')
                    message = json.loads(message)

                    if message.get('guid') != self.guid:
                        return False

                else:
                    return
            except RuntimeError as e:
                self.log.error('Could not decrypt message properly %s', e)
                return False
            except Exception as e:
                self.log.error('Cannot unpack data: %s', e)
                return False

        return message

    @staticmethod
    def validate_signature(signature, data):
        data_json = json.loads(data.decode('hex'))
        sig_cryptor = Cryptor(pubkey_hex=data_json['pubkey'])

        if sig_cryptor.verify(signature, data):
            return True
        else:
            return False
