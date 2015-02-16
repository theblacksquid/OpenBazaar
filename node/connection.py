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


class PeerConnection(object):
    def __init__(self, transport, hostname, port=12345, nickname="", peer_socket=None):

        self.transport = transport
        self.hostname = hostname
        self.port = port
        self.nickname = nickname
        self.reachable = False
        self.nat_type = None

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
            self.transport
        )

        self._rudp_connection = Connection(self._packet_sender)

        self.packetsmasher = {}
        self.message_size = 0
        self.is_listening = True
        self.hello = False

    def send(self, data, callback):
        def send_out():
            if self.reachable:
                self.send_raw(json.dumps(data), callback)
            ioloop.IOLoop.instance().call_later(0.5, send_out)
        send_out()

    def send_raw(self, serialized, callback=None):
        data_encoded = serialized
        data_encoded = data_encoded.encode('hex')
        data = str(len(data_encoded)) + '|' + data_encoded
        self._rudp_connection.send(data)

    def reset(self):
        self.log.debug('Reset 2')
        self._rudp_connection._sender._sending = None
        self._rudp_connection._sender._push()
        self.is_listening = False


class CryptoPeerConnection(GUIDMixin, PeerConnection):

    def __init__(self, transport, hostname, port, pub=None, guid=None, nickname="",
                 sin=None, rudp_connection=None, peer_socket=None):

        GUIDMixin.__init__(self, guid)
        PeerConnection.__init__(self, transport, hostname, port, nickname, peer_socket)

        self.pub = pub
        self.sin = sin
        self.waiting = False  # Waiting for ping-pong

        self.setup_emitters()
        self.transport.get_nat_type(guid)

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
            self.transport.dht.remove_peer(self.guid)

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
                # payload = base64.b64decode(msg.get('payload'))
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

    @staticmethod
    def is_handshake(message):
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
            print 'Error: ', e
            return False

        return 'type' in message

    def _on_raw_message(self, serialized):
        """
        Handles receipt of encrypted/plaintext message
        and passes to appropriate callback.

        :param serialized:
        :return:
        """

        if not self.is_handshake(serialized):

            if type(serialized) is dict:
                message = serialized
            else:
                try:

                    message = self.cryptor.decrypt(serialized)
                    message = json.loads(message)

                    # self.log.debug(message)
                    # message = json.loads(serialized)

                    signature = message['sig'].decode('hex')
                    signed_data = message['data']

                    if CryptoPeerListener.validate_signature(signature, signed_data):
                        message = signed_data.decode('hex')
                        message = json.loads(message)

                        if message.get('guid') != self.guid:
                            return

                    else:
                        return
                except RuntimeError as e:
                    self.log.error('Could not decrypt message properly %s', e)
                    return
                except Exception as e:
                    self.log.error('Cannot unpack data: %s', e)
                    return
        else:
            self.log.debug('Loading JSON')
            message = json.loads(serialized)
            self.log.debug('Message: %s', message)

        self.log.debugv('Received message of type "%s"',
                        message.get('type', 'unknown'))
        if self._data_cb:
            self.log.debug('DATA CB: %s', self._data_cb)
            self._data_cb(message)
        else:
            self.log.debugv('Callbacks not ready yet')

    @staticmethod
    def validate_signature(signature, data):
        data_json = json.loads(data.decode('hex'))
        sig_cryptor = Cryptor(pubkey_hex=data_json['pubkey'])

        if sig_cryptor.verify(signature, data):
            return True
        else:
            return False
