import random
import unittest

from node import constants, guid, kbucket


class TestKBucket(unittest.TestCase):

    @staticmethod
    def _mk_contact_by_num(i):
        return guid.GUIDMixin(str(i))

    @classmethod
    def setUpClass(cls):
        cls.range_min = 1
        cls.range_max = cls.range_min + 16 * constants.K

        cls.market_id = 42

        cls.init_contact_count = constants.K - 1

        cls.ghost_contact_id = 0
        cls.ghost_contact = cls._mk_contact_by_num(cls.ghost_contact_id)

    @classmethod
    def _make_kbucket(cls, count=None):
        if count is None:
            count = cls.init_contact_count

        new_kbucket = kbucket.KBucket(
            cls.range_min,
            cls.range_max,
            market_id=cls.market_id
        )

        for i in range(cls.range_min, cls.range_min + count):
            new_kbucket.add_contact(cls._mk_contact_by_num(i))

        return new_kbucket

    def setUp(self):
        self.bucket = self._make_kbucket()

    def test_init(self):
        k = kbucket.KBucket(1, 2, market_id=self.market_id)
        self.assertEqual(k.last_accessed, 0)
        self.assertEqual(k.range_min, 1)
        self.assertEqual(k.range_max, 2)
        self.assertEqual(k.market_id, self.market_id)
        self.assertEqual(k.contacts, [])
        self.assertTrue(hasattr(k, 'log'))

    def test_len(self):
        len_self = len(self.bucket)
        len_contacts = len(self.bucket.get_contacts())
        self.assertEqual(
            len_self,
            len_contacts,
            "Discrepancy in contact list length: Reported %d\tActual: %d" % (
                len_self,
                len_contacts
            )
        )

    def test_iter(self):
        self.assertEqual(list(iter(self.bucket)), self.bucket.contacts)

    def _test_add_contact_new_scenario(self, new_contact):
        prev_count = len(self.bucket.get_contacts())

        try:
            self.bucket.add_contact(new_contact)
        except kbucket.BucketFull:
            self.fail("Failed to add new contact in non-full bucket.")
            return

        # Assert new contact appears at end of contact list.
        self.assertEqual(
            self.bucket.contacts[-1],
            new_contact,
            "New contact is not at end of list"
        )

        # Assert new contact is a guid.GUIMixin.
        self.assertIsInstance(
            self.bucket.contacts[-1],
            guid.GUIDMixin,
            "New contact not converted to guid.GUIDMixin."
        )

        # Naively assert the list didn't lose an element by accident.
        cur_count = len(self.bucket.get_contacts())
        self.assertEqual(
            prev_count + 1,
            cur_count,
            "Expected list length: %d\tGot: %d\tInitial: %d" % (
                prev_count + 1,
                cur_count,
                prev_count
            )
        )

    def test_add_contact_new_guid(self):
        new_id = self.range_min + self.init_contact_count
        new_contact = self._mk_contact_by_num(new_id)
        self._test_add_contact_new_scenario(new_contact)

    def test_add_contact_new_str(self):
        new_id = self.range_min + self.init_contact_count
        new_contact = str(self._mk_contact_by_num(new_id).guid)
        self._test_add_contact_new_scenario(new_contact)

    def test_add_contact_new_unicode(self):
        new_id = self.range_min + self.init_contact_count
        new_contact = unicode(self._mk_contact_by_num(new_id).guid)
        self._test_add_contact_new_scenario(new_contact)

    def test_add_contact_existing(self):
        new_id = self.range_min
        new_contact = self._mk_contact_by_num(new_id)
        prev_count = len(self.bucket.get_contacts())

        try:
            self.bucket.add_contact(new_contact)
        except kbucket.BucketFull:
            self.fail("Failed to add existing contact in non-full bucket.")
            return

        # Assert new contact appears at end of contact list.
        self.assertEqual(
            self.bucket.contacts[-1],
            new_contact,
            "New contact is not at end of list"
        )

        # Assert the list didn't change size.
        cur_count = len(self.bucket.get_contacts())
        self.assertEqual(
            prev_count,
            cur_count,
            "Expected list length: %d\tGot: %d\tInitial: %d" % (
                prev_count,
                cur_count,
                prev_count
            )
        )

    def test_add_contact_full(self):
        self.assertEqual(
            len(self.bucket.get_contacts()),
            constants.K - 1,
            "Bucket is not full enough."
        )

        # Adding just one more is OK ...
        new_id1 = self.range_max - 1
        new_contact1 = self._mk_contact_by_num(new_id1)
        try:
            self.bucket.add_contact(new_contact1)
        except kbucket.BucketFull:
            self.fail("Bucket burst earlier than expected.")
            return

        # ... but adding one more will force a split
        prev_list = self.bucket.get_contacts()
        new_id2 = self.range_max - 2
        new_contact2 = self._mk_contact_by_num(new_id2)

        with self.assertRaises(kbucket.BucketFull):
            self.bucket.add_contact(new_contact2)

        # Assert list is intact despite exception.
        cur_list = self.bucket.get_contacts()
        self.assertEqual(
            prev_list,
            cur_list,
            "Contact list was modified before raising exception."
        )

    def test_get_contact(self):
        for i in range(self.init_contact_count):
            c_id = self.range_min + i
            self.assertEqual(
                self.bucket.get_contact(str(c_id)),
                self._mk_contact_by_num(c_id),
                "Did not find requested contact %d." % c_id
            )

        # Assert None is returned upon requesting nonexistent contact.
        self.assertIsNone(
            self.bucket.get_contact(self.ghost_contact_id),
            "Nonexistent contact found."
        )

    def _test_get_contacts_scenario(self, count_expected, count=-1, bucket=None):
        if bucket is None:
            bucket = self.bucket

        contacts = bucket.get_contacts(count=count)
        count_contacts = len(contacts)

        self.assertEqual(
            count_expected,
            count_contacts,
            "Expected contact list size: %d\tGot: %d" % (
                count_expected,
                count_contacts
            )
        )

    def test_get_contacts_empty(self):
        empty_bucket = self._make_kbucket(count=0)
        self._test_get_contacts_scenario(0, bucket=empty_bucket)

    def test_get_contacts_default(self):
        count = self.init_contact_count
        self._test_get_contacts_scenario(count, count)

    def test_get_contacts_count(self):
        count = self.init_contact_count // 2
        self._test_get_contacts_scenario(count, count)

    def test_get_contacts_available(self):
        count = self.init_contact_count + 1
        self._test_get_contacts_scenario(self.init_contact_count, count)

    def test_get_contacts_exclude(self):
        all_contacts = self.bucket.get_contacts()
        count_all = len(all_contacts)

        # Pick a random contact and exclude it ...
        target_contact_offset = random.randrange(0, self.init_contact_count)
        target_contact_id = self.range_min + target_contact_offset
        excl_contact = self._mk_contact_by_num(target_contact_id)
        rest_contacts = self.bucket.get_contacts(exclude_contact=excl_contact)
        count_rest = len(rest_contacts)

        # ... check it was indeed excluded ...
        self.assertNotIn(
            excl_contact,
            rest_contacts,
            "get_contacts() did not exclude the contact we asked for"
        )

        # ... naively ensure no other contact was excluded ...
        self.assertEqual(
            self.init_contact_count - 1,
            count_rest,
            "Expected contact list size: %d\tGot: %d\tInitial: %d" % (
                self.init_contact_count,
                count_rest,
                count_all
            )
        )

        # ... and the original list is not affected ...
        self.assertEqual(
            self.init_contact_count,
            count_all,
            "Original list was modified by exclusion."
        )

        # ... and check it's OK to exclude a contact that is not there yet.
        try:
            self.bucket.get_contacts(exclude_contact=self.ghost_contact)
        except Exception:
            self.fail("Crashed while excluding contact absent from bucket.")

    def test_remove_contact_existing_contact(self):
        rm_contact = self._mk_contact_by_num(self.range_min)
        prev_count = len(self.bucket.get_contacts())

        try:
            self.bucket.remove_contact(rm_contact)
        except ValueError:
            self.fail("Crashed while removing existing contact.")
            return

        cur_count = len(self.bucket.get_contacts())
        self.assertEqual(
            prev_count - 1,
            cur_count,
            "Expected contact list size: %d\tGot: %d\tInitial: %d" % (
                prev_count - 1,
                cur_count,
                prev_count,
            )
        )

    def test_remove_contact_existing_guid(self):
        rm_guid = str(self.range_min)
        prev_count = len(self.bucket.get_contacts())

        try:
            self.bucket.remove_contact(rm_guid)
        except ValueError:
            self.fail("Crashed while removing existing contact via GUID.")
            return

        cur_count = len(self.bucket.get_contacts())
        self.assertEqual(
            prev_count - 1,
            cur_count,
            "Expected contact list size: %d\tGot: %d\tInitial: %d" % (
                prev_count - 1,
                cur_count,
                prev_count,
            )
        )

    def test_remove_contact_absent(self):
        prev_list = self.bucket.get_contacts()

        with self.assertRaises(ValueError):
            self.bucket.remove_contact(self.ghost_contact)

        cur_list = self.bucket.get_contacts()
        self.assertEqual(
            prev_list,
            cur_list,
            "Contact list was modified before raising exception."
        )

    def test_key_in_range(self):
        self.assertTrue(self.bucket.key_in_range(self.range_min))
        self.assertTrue(self.bucket.key_in_range(self.range_max - 1))

        mid_key = self.range_min + (self.range_max - self.range_min) // 2
        mid_key_hex = hex(mid_key)
        mid_key_guid = guid.GUIDMixin(mid_key_hex)

        self.assertTrue(self.bucket.key_in_range(mid_key))
        self.assertTrue(self.bucket.key_in_range(mid_key_hex))
        self.assertTrue(self.bucket.key_in_range(mid_key_guid))

        self.assertFalse(self.bucket.key_in_range(self.range_min - 1))
        self.assertFalse(self.bucket.key_in_range(self.range_max))


if __name__ == "__main__":
    unittest.main()
