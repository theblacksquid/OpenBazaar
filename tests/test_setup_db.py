import os
import tempfile
import unittest

from node import setup_db


class TestSetupDB(unittest.TestCase):

    def setUp(self):
        self.db_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.db_dir, 'testdb.db')

    def tearDown(self):
        os.remove(self.db_path)
        os.rmdir(self.db_dir)

    def test_setup_db(self):
        setup_db.setup_db(self.db_path)

    def test_setup_db_nocrypt(self):
        setup_db.setup_db(self.db_path, disable_sqlite_crypt=True)

    def test_setup_existing(self):
        _, self.db_path = tempfile.mkstemp(suffix='.db')
        setup_db.setup_db(self.db_path, disable_sqlite_crypt=True)

if __name__ == '__main__':
    unittest.main()
