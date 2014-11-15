import json
import os
import unittest

from node import backuptool


class TestBackupTool(unittest.TestCase):

    @classmethod
    def on_success(cls, backup_file_path):
        cls.backup_file_path = backup_file_path

    def on_error(self, message):
        self.fail("Backup failed with error: %s" % message)

    def test_all(self):
        backuptool.BackupTool.backup(
            backuptool.BackupTool.get_installation_path(),
            backuptool.BackupTool.get_backup_path(),
            self.on_success,
            self.on_error
        )

        backup_path = backuptool.BackupTool.get_backup_path()
        for x in backuptool.Backup.get_backups(backup_path):
            print json.dumps(x, cls=backuptool.BackupJSONEncoder)

    @classmethod
    def tearDownClass(cls):
        os.remove(cls.backup_file_path)


if __name__ == '__main__':
    unittest.main()
