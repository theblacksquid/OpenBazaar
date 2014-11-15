import os
import unittest

from node import data_uri

TEST_TXT_FILE = "data_uri_test.txt"
TEST_CONTENTS = "foo\n"

class TestDataURI(unittest.TestCase):

    def setUp(self):
        with open(TEST_TXT_FILE, 'w') as f:
            f.write(TEST_CONTENTS)

    def tearDown(self):
        os.remove(TEST_TXT_FILE)

    def test_init_from_file(self):
        uri = data_uri.DataURI.from_file(TEST_TXT_FILE, base64=False)
        self.assertEqual(uri.data, TEST_CONTENTS)
        self.assertEqual(uri.mimetype, "text/plain")
        self.assertFalse(uri.is_base64)

    def test_init_from_args(self):
        data = "I like trains"
        charset = 'us-ascii'
        mime = 'text/plain'
        uri = data_uri.DataURI.make(
            mime,
            charset,
            base64=True,
            data=data)

        self.assertEqual(uri.data, data)
        self.assertEqual(uri.charset, charset)
        self.assertEqual(uri.mimetype, mime)
        self.assertTrue(uri.is_base64)

if __name__ == '__main__':
    unittest.main()
