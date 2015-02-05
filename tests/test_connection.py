import unittest

import mock

from node import connection, guid
import json
import socket


class TestPeerConnection(unittest.TestCase):

    @staticmethod
    def _mk_address(protocol, hostname, port):
        return "%s://%s:%s" % (protocol, hostname, port)

    @classmethod
    def setUpClass(cls):
        cls.protocol = "tcp"
        cls.hostname = "localhost"
        cls.port = 54321
        cls.address = cls._mk_address(cls.protocol, cls.hostname, cls.port)
        cls.nickname = "OpenBazaar LightYear"
        cls.pub = "YELLOW SUBMARINE"
        cls.transport = mock.Mock()

        cls.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # cls.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # cls.socket.bind((cls.hostname, cls.port))

        cls.default_nickname = ""

    def setUp(self):
        self.pc1 = connection.PeerConnection(self.transport, self.hostname, self.port, peer_socket=self.socket)
        self.pc2 = connection.PeerConnection(
            self.transport,
            self.hostname,
            self.port,
            self.nickname,
            self.socket
        )

    def test_init(self):
        self.assertEqual(self.pc1.transport, self.transport)
        self.assertEqual(self.pc1.hostname, self.hostname)
        self.assertEqual(self.pc1.nickname, self.default_nickname)
        # self.assertIsNotNone(self.pc1.ctx)

        self.assertEqual(self.pc2.nickname, self.nickname)


class TestCryptoPeerConnection(TestPeerConnection):

    @classmethod
    def setUpClass(cls):
        super(TestCryptoPeerConnection, cls).setUpClass()
        cls.guid = "42"
        cls.pub = "YELLOW SUBMARINE"
        cls.sin = "It's a sin"

        cls.default_guid = None
        cls.default_pub = None
        cls.default_sin = None

    @classmethod
    def _mk_default_CPC(cls):
        return connection.CryptoPeerConnection(
            cls.transport,
            cls.hostname,
            cls.port,
            peer_socket=cls.socket
        )

    @classmethod
    def _mk_complete_CPC(cls):
        return connection.CryptoPeerConnection(
            cls.transport,
            cls.hostname,
            cls.port,
            cls.pub,
            cls.guid,
            cls.nickname,
            cls.sin,
            peer_socket=cls.socket
        )

    def setUp(self):
        self.pc1 = self._mk_default_CPC()
        self.pc2 = self._mk_complete_CPC()

    def test_subclassing(self):
        self.assertTrue(
            issubclass(
                connection.CryptoPeerConnection,
                connection.PeerConnection
            )
        )

        self.assertTrue(
            issubclass(connection.CryptoPeerConnection, guid.GUIDMixin)
        )

    def test_init(self):
        super(TestCryptoPeerConnection, self).test_init()

        self.assertEqual(self.pc1.hostname, self.hostname)
        self.assertEqual(self.pc1.port, self.port)

        self.assertEqual(self.pc1.pub, self.default_pub)
        self.assertEqual(self.pc1.sin, self.default_sin)
        self.assertEqual(self.pc1.guid, self.default_guid)

        self.assertEqual(self.pc2.pub, self.pub)
        self.assertEqual(self.pc2.guid, self.guid)
        self.assertEqual(self.pc2.sin, self.sin)

    def test_eq(self):
        self.assertEqual(self.pc1, self._mk_default_CPC())

        other_addresses = (
            (self.hostname, self.port),
            ("openbazaar.org", self.port),
            (self.hostname, 8080)
        )
        for address in other_addresses:
            self.assertEqual(
                self.pc1,
                connection.CryptoPeerConnection(
                    self.transport,
                    address[0],
                    address[1],
                    peer_socket=self.socket
                )
            )

        self.assertNotEqual(self.pc1, None)

        self.assertEqual(self.pc2, self._mk_complete_CPC())
        self.assertEqual(self.pc2, self.guid)

        another_guid = "43"
        self.assertNotEqual(
            self.pc2,
            connection.CryptoPeerConnection(
                self.transport,
                self.hostname,
                self.port,
                self.pub,
                another_guid,
                self.nickname,
                self.sin,
                peer_socket=self.socket
            )
        )
        self.assertNotEqual(self.pc1, int(self.guid))

    @unittest.skip(
        "Comparing CryptoPeerConnection with default GUID"
        "to default GUID fails."
    )
    def test_eq_regression_none(self):
        self.assertEqual(self.pc1, self.default_guid)

    def test_repr(self):
        self.assertEqual(self.pc2.__repr__(), str(self.pc2))

    def test_is_handshake(self):

        real_handshake_dict = json.dumps({
            'type': 'ok'
        })
        fake_handshake_encrypted = "safjklawejfwoijsicjewiocjo"
        fake_handshake_no_type = json.dumps({
            'notype': 'ok'
        })

        self.assertTrue(connection.CryptoPeerListener.is_handshake(real_handshake_dict))
        self.assertFalse(connection.CryptoPeerListener.is_handshake(fake_handshake_encrypted))
        self.assertFalse(connection.CryptoPeerListener.is_handshake(fake_handshake_no_type))

    def test_validate_signature(self):
        signature = "304502201797bf55914db1ce4010d0787879dbc99f13dd127e96f666f61a66fa14d61d27022100a3aac2496558a2" \
                    "6cb01e299b1f7239c57bb33854a96b5c668337b43db03f1a0b"
        bad_signature = "304502201797bf55914db1ce4010d0787879dbc99f13dd127e96f666f61a66fa14d61d27022100a3aac24965" \
                        "58a26cb0299b1f7239c57bb33854a96b5c668337b43db03f1a0b"
        data = "7b2273656e6465724e69636b223a202244656661756c74222c202274797065223a202266696e644e6f6465526573706f6" \
               "e7365222c202276223a2022302e322e32222c2022757269223a20227463703a2f2f3132372e302e302e313a3132333435" \
               "222c202273656e64657247554944223a20226637393033366233316432366537383539373839336235613637656138363" \
               "2363862323235363433222c2022666f756e644e6f646573223a205b5d2c202266696e644944223a202230663561613338" \
               "356435346337303134363964633535306531356430373638626131346635383633222c202267756964223a20226562336" \
               "6386637393439623063663733623235636235303134396562646661393861386130366662222c20227075626b6579223a" \
               "2022303431303238383434643330343265303732636630643561326636333534373736373630636633666437323635393" \
               "4633035343938643938343731306161616535653562646233613566373231363433623237313936393861356439363861" \
               "3034303832303531663637336566633430363830393066623032383433306138303436227d"

        signature = signature.decode('hex')

        self.assertTrue(connection.CryptoPeerListener.validate_signature(signature, data))
        self.assertFalse(connection.CryptoPeerListener.validate_signature(bad_signature, data))

if __name__ == "__main__":
    unittest.main()
