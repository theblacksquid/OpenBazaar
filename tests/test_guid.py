import unittest

from node import guid


class TestGUIDMixin(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.guid = "42"
        cls.alt_guid = "43"
        cls.uguid = unicode(cls.guid)
        cls.alt_uguid = unicode(cls.alt_guid)

    def test_init(self):
        g = guid.GUIDMixin(self.guid)
        self.assertEqual(g.guid, self.guid)

        gu = guid.GUIDMixin(self.uguid)
        self.assertEqual(gu.guid, self.uguid)

    def _test_eq_true_scenario(self, guid1, guid2):
        a = guid.GUIDMixin(guid1)
        b = guid.GUIDMixin(guid1)
        c = guid.GUIDMixin(guid2)

        self.assertIsNot(a, b, "Separate instantiations produce same objects.")

        self.assertEqual(a, b, "GUIDMixin unequal to same GUIDMixin.")
        self.assertEqual(a, guid1, "GUIDMixin unequal to own GUID.")
        self.assertEqual(
            a, c, "GUIDMixin unequal to string-equivalent GUIDMixin."
        )

    def _test_eq_false_scenario(self, guid1, guid2):
        a = guid.GUIDMixin(guid1)
        b = guid.GUIDMixin(guid2)
        self.assertNotEqual(a, b, "GUIDMixin equal to different GUIDMixin.")
        self.assertNotEqual(a, guid2, "GUIDMixin equal to different GUID.")

    def test_eq_(self):
        self._test_eq_true_scenario(self.guid, self.uguid)
        self._test_eq_true_scenario(self.uguid, self.guid)

        self._test_eq_false_scenario(self.guid, self.alt_guid)
        self._test_eq_false_scenario(self.guid, self.alt_uguid)
        self._test_eq_false_scenario(self.uguid, self.alt_guid)
        self._test_eq_false_scenario(self.uguid, self.alt_uguid)

    def test_hash(self):
        a = guid.GUIDMixin(self.guid)
        self.assertEqual(hash(a), hash(self.guid))
        self.assertEqual(hash(a), hash(self.uguid))

        b = guid.GUIDMixin(self.uguid)
        self.assertEqual(hash(b), hash(self.guid))
        self.assertEqual(hash(b), hash(self.uguid))

    def test_repr(self):
        g = guid.GUIDMixin(self.guid)
        self.assertEqual(g.__repr__(), str(g))

        gu = guid.GUIDMixin(self.uguid)
        self.assertEqual(gu.__repr__(), str(gu))

if __name__ == "__main__":
    unittest.main()
