import unittest
from node.openbazaar import create_argument_parser
from node.openbazaar_daemon import OpenBazaarContext


class TestLauncher(unittest.TestCase):
    def setUp(self):
        self.default_ctx = OpenBazaarContext.create_default_instance()

    def test_argument_parser(self):
        parser = create_argument_parser()

        # base case
        arguments = parser.parse_args(['start'])

        self.assertEqual(arguments.command, 'start')
        self.assertEqual(arguments.server_ip, self.default_ctx.server_ip)
        self.assertEqual(arguments.server_port, self.default_ctx.server_port)
        self.assertEqual(arguments.http_ip, self.default_ctx.http_ip)
        self.assertEqual(arguments.http_port, self.default_ctx.http_port)
        self.assertEqual(arguments.log, self.default_ctx.log_path)
        self.assertEqual(arguments.log_level, self.default_ctx.log_level)
        self.assertEqual(arguments.dev_mode, self.default_ctx.dev_mode)
        self.assertEqual(arguments.dev_nodes, self.default_ctx.dev_nodes)
        self.assertEqual(arguments.db_path, self.default_ctx.db_path)
        self.assertEqual(arguments.disable_sqlite_crypt, self.default_ctx.disable_sqlite_crypt)
        self.assertEqual(arguments.bm_user, self.default_ctx.bm_user)
        self.assertEqual(arguments.bm_pass, self.default_ctx.bm_pass)
        self.assertEqual(arguments.bm_port, self.default_ctx.bm_port)
        self.assertEqual(arguments.market_id, self.default_ctx.market_id)
        self.assertEqual(arguments.disable_upnp, self.default_ctx.disable_upnp)
        self.assertEqual(arguments.disable_stun_check, self.default_ctx.disable_stun_check)
        self.assertEqual(arguments.seed_mode, self.default_ctx.seed_mode)
        self.assertEqual(arguments.disable_open_browser, self.default_ctx.disable_open_browser)
        self.assertEqual(arguments.config_file, None)
        self.assertEqual(arguments.enable_ip_checker, self.default_ctx.enable_ip_checker)

        # todo: add more cases to make sure arguments are being parsed correctly.

if __name__ == "__main__":
    unittest.main()
