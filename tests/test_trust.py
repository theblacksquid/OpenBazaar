import unittest

from node import constants, trust


class TestTrust(unittest.TestCase):

    def setUp(self):
        self.guid = 'a' * constants.HEX_NODE_ID_LEN

    def test_burnaddr_from_guid_no_testnet(self):
        trust.TESTNET = False
        burnaddr = trust.burnaddr_from_guid(self.guid)
        self.assertEqual('1GZQKjsC97yasxRj1wtYf5rC61AxtRdodJ', burnaddr)

    def test_burnaddr_from_guid_testnet(self):
        trust.TESTNET = True
        burnaddr = trust.burnaddr_from_guid(self.guid)
        self.assertEqual('mw5McnxAx9Qqf4uLjWrvV14WwzmfrxrWNu', burnaddr)

if __name__ == '__main__':
    unittest.main()
