import unittest
from node.openbazaar_daemon import OpenBazaarContext
import mock

from node import transport


def get_mock_open_bazaar_context():
    return OpenBazaarContext.create_default_instance()


class TestTransportLayerCallbacks(unittest.TestCase):
    """Test the callback features of the TransportLayer class."""

    def setUp(self):
        # For testing sections
        self.callback1 = mock.Mock()
        self.callback2 = mock.Mock()
        self.callback3 = mock.Mock()
        self.validator1 = mock.Mock()
        self.validator2 = mock.Mock()
        self.validator3 = mock.Mock()

        ob_ctx = get_mock_open_bazaar_context()
        guid = 1
        nickname = None

        self.tl = transport.TransportLayer(ob_ctx, guid, nickname)
        self.tl.add_callback('section_one', {'cb': self.callback1, 'validator_cb': self.validator1})
        self.tl.add_callback('section_one', {'cb': self.callback2, 'validator_cb': self.validator2})
        self.tl.add_callback('all', {'cb': self.callback3, 'validator_cb': self.validator3})

        # For testing validators
        self.callback4 = mock.Mock()
        self.callback5 = mock.Mock()
        self.validator4 = mock.Mock(return_value=True)
        self.validator5 = mock.Mock(return_value=False)
        self.tl.add_callback('section_two', {'cb': self.callback4, 'validator_cb': self.validator4})
        self.tl.add_callback('section_two', {'cb': self.callback5, 'validator_cb': self.validator5})

    def _assert_called(self, one, two, three):
        self.assertEqual(self.callback1.call_count, one)
        self.assertEqual(self.callback2.call_count, two)
        self.assertEqual(self.callback3.call_count, three)

    def test_fixture(self):
        self._assert_called(0, 0, 0)

    def test_callbacks(self):
        self.tl.trigger_callbacks('section_one', None)
        self._assert_called(1, 1, 1)

    def test_all_callback(self):
        self.tl.trigger_callbacks('section_with_no_register', None)
        self._assert_called(0, 0, 1)

    def test_validators(self):
        self.tl.trigger_callbacks('section_two', None)
        self.assertEqual(self.validator4.call_count, 1)
        self.assertEqual(self.validator5.call_count, 1)
        self.assertEqual(self.callback4.call_count, 1)
        self.assertEqual(self.callback5.call_count, 0)


if __name__ == "__main__":
    unittest.main()
