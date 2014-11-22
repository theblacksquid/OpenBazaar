import os
import platform
import unittest
import webbrowser

import mock

from node import util


class TestUtil(unittest.TestCase):

    @mock.patch.object(platform, 'uname', lambda: ['Darwin'])
    def test_is_mac_Darwin(self):
        self.assertTrue(util.is_mac())

    @mock.patch.object(platform, 'uname', lambda: ['Linux'])
    def test_is_mac_Linux(self):
        self.assertFalse(util.is_mac())

    @mock.patch.object(platform, 'uname', lambda: ['Windows'])
    def test_is_mac_Windows(self):
        self.assertFalse(util.is_mac())

    @mock.patch.object(webbrowser, 'open')
    def test_open_default_webbrowser_full_url(self, webbrowser_mock):
        full_url = 'http://www.openbazaar.org'
        self.assertTrue(util.open_default_webbrowser(full_url))
        webbrowser_mock.assert_called_once_with(full_url)

    @mock.patch.object(webbrowser, 'open')
    def test_open_default_webbrowser_bare_url(self, webbrowser_mock):
        url = 'www.openbazaar.org'
        self.assertTrue(util.open_default_webbrowser(url))
        webbrowser_mock.assert_called_once_with('http://%s' % url)

    @mock.patch.object(webbrowser, 'open')
    def test_open_default_webbrowser_protocol(self, webbrowser_mock):
        url = 'www.openbazaar.org'
        protocol = 'ftp'
        self.assertTrue(util.open_default_webbrowser(url, protocol=protocol))
        webbrowser_mock.assert_called_once_with('%s://%s' % (protocol, url))

    @mock.patch.object(webbrowser, 'open', side_effect=webbrowser.Error)
    def test_open_default_webbrowser_bad_open(self, mock_method):
        full_url = 'http://www.openbazaar.org'
        self.assertFalse(util.open_default_webbrowser(full_url))

    @mock.patch.object(os, 'environ', {})
    def test_osx_check_dyld_library_path_None(self):
        self.assertRaises(
            SystemExit,
            util.osx_check_dyld_library_path
        )

    @mock.patch.object(os, 'environ', {'DYLD_LIBRARY_PATH': False})
    def test_osx_check_dyld_library_path_False(self):
        self.assertRaises(
            SystemExit,
            util.osx_check_dyld_library_path
        )

    @staticmethod
    @mock.patch.object(os, 'environ', {'DYLD_LIBRARY_PATH': True})
    def test_osx_check_dyld_library_path_True():
        util.osx_check_dyld_library_path()


if __name__ == '__main__':
    unittest.main()
