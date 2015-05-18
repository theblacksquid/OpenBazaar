import unittest
from db.migrations import migrations_util


class TestMigrationUtil(unittest.TestCase):
    """Test the CLI API."""

    @classmethod
    def setUpClass(cls):
        cls.db_path = '/some/random/path/file.db'

    def setUp(self):
        self.parser = migrations_util.make_argument_parser(self.db_path)

    def test_cli_parser_default(self):
        options = self.parser.parse_args(['upgrade'])

        self.assertEqual(options.path, self.db_path)
        self.assertEqual(options.action, 'upgrade')

    def test_cli_parser_user(self):
        other_db_path = '/some/other/path/file.db'
        options = self.parser.parse_args([
            'downgrade',
            '--path',
            other_db_path
        ])

        self.assertEqual(options.path, other_db_path)
        self.assertEqual(options.action, 'downgrade')

    def test_cli_parser_bad_action(self):
        self.assertRaises(
            SystemExit,
            self.parser.parse_args,
            ['retrograde']
        )

if __name__ == '__main__':
    unittest.main()
