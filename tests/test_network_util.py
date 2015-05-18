import mock
import unittest

import requests
import stun

from node import network_util


class TestNodeNetworkUtil(unittest.TestCase):

    def test_set_stun_servers(self):
        new_stun_servers = (
            'stun.openbazaar1.com',
            'stun.openbazaar2.com'
        )
        network_util.set_stun_servers(servers=new_stun_servers)
        self.assertItemsEqual(new_stun_servers, stun.stun_servers_list)

    @mock.patch.object(stun, 'get_ip_info')
    def test_get_NAT_status(self, method_mock):
        stun_response = ('Symmetric NAT', '123.45.67.89', '12345')
        method_mock.return_value = stun_response

        keys = ('nat_type', 'external_ip', 'external_port')
        dict_response = {key: value for key, value in zip(keys, stun_response)}

        self.assertEqual(dict_response, network_util.get_NAT_status())
        method_mock.assert_called_once_with(source_port=0, stun_host=None, stun_port=19302)

    def test_is_loopback_addr(self):
        self.assertTrue(network_util.is_loopback_addr("127.0.0.1"))
        self.assertTrue(network_util.is_loopback_addr("localhost"))

        self.assertFalse(network_util.is_loopback_addr("10.0.0.1"))
        self.assertFalse(network_util.is_loopback_addr("192.168.0.1"))

    def test_is_private_ip_address(self):
        self.assertTrue(network_util.is_private_ip_address('localhost'))
        self.assertTrue(network_util.is_private_ip_address('127.0.0.1'))
        self.assertTrue(network_util.is_private_ip_address('192.168.1.1'))
        self.assertTrue(network_util.is_private_ip_address('172.16.1.1'))
        self.assertTrue(network_util.is_private_ip_address('10.1.1.1'))

        self.assertFalse(network_util.is_private_ip_address('8.8.8.8'))

    @mock.patch.object(requests, 'get')
    def test_get_my_ip_from_default_site(self, mock_method):
        stub_ip = '123.45.67.89'
        response_mock = mock.NonCallableMock()
        response_mock.text = stub_ip
        mock_method.return_value = response_mock

        self.assertEqual(stub_ip, network_util.get_my_ip())
        mock_method.assert_called_once_with(network_util.IP_DETECT_SITE)

    @mock.patch.object(requests, 'get')
    def test_get_my_ip_from_user_specified_site(self, mock_method):
        stub_ip = '123.45.67.89'
        response_mock = mock.NonCallableMock()
        response_mock.text = stub_ip
        mock_method.return_value = response_mock

        ip_site = 'http://ip.stub.org'
        self.assertEqual(stub_ip, network_util.get_my_ip(ip_site=ip_site))
        mock_method.assert_called_once_with(ip_site)

    @mock.patch.object(requests, 'get', side_effect=requests.RequestException)
    def test_get_my_ip_failed_request(self, mock_method):
        self.assertIsNone(network_util.get_my_ip())

    @mock.patch.object(requests, 'get')
    def test_get_my_ip_bad_response(self, mock_method):
        mock_method.return_value = None
        self.assertIsNone(network_util.get_my_ip())

    def test_is_ipv6_address(self):
        self.assertTrue(network_util.is_ipv6_address('2a00::'))
        self.assertFalse(network_util.is_ipv6_address('8.8.8.8'))

    def test_get_peer_url(self):
        self.assertEqual(
            network_util.get_peer_url('8.8.8.8', 1234),
            'tcp://8.8.8.8:1234'
        )
        self.assertEqual(
            network_util.get_peer_url('8.8.8.8', 1234, protocol='udp'),
            'udp://8.8.8.8:1234'
        )
        self.assertEqual(
            network_util.get_peer_url('2a00::', 1234),
            'tcp://[2a00::]:1234'
        )
        self.assertEqual(
            network_util.get_peer_url('2a00::', 1234, protocol='udp'),
            'udp://[2a00::]:1234'
        )
        self.assertEqual(
            network_util.get_peer_url('www.openbazaar.com', 1234),
            'tcp://www.openbazaar.com:1234'
        )

    def test_valid_uri(self):
        self.assertTrue(
            network_util.is_valid_uri('tcp://localhost:12345')
        )
        self.assertFalse(
            network_util.is_valid_uri('udp://localhost:12345')
        )
        self.assertFalse(
            network_util.is_valid_uri('inproc://localhost:12345')
        )
        self.assertFalse(
            network_util.is_valid_uri('localhost:12345')
        )
        self.assertFalse(
            network_util.is_valid_uri('localhost')
        )
        self.assertFalse(
            network_util.is_valid_uri('@#FADSFJSK@#RKFSAJASDJKF@#lkdafj')
        )
        self.assertFalse(
            network_util.is_valid_uri('tcp://192.33..23.1:12345')
        )
        self.assertTrue(
            network_util.is_valid_uri('tcp://sub.domain.com:12345')
        )

    def test_is_valid_hostname(self):
        self.assertTrue(
            network_util.is_valid_hostname('192.168.1.1')
        )
        self.assertTrue(
            network_util.is_valid_hostname('sub.domain.com')
        )
        self.assertTrue(
            network_util.is_valid_hostname('domain.com')
        )
        self.assertTrue(
            network_util.is_valid_hostname('domain')
        )
        self.assertFalse(
            network_util.is_valid_hostname('@#FADSFJSK@#RKFSAJASDJKF@#lkdafj')
        )



if __name__ == '__main__':
    unittest.main()
