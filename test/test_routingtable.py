import time
import unittest

from node import constants, guid, kbucket, routingtable


class TestRoutingTable(unittest.TestCase):
    """Test the static methods of abstract class RoutingTable."""

    @classmethod
    def setUpClass(cls):
        cls.id1 = "a" * 20
        cls.id2 = "b" * 20
        cls.uid1 = unicode(cls.id1)
        cls.uid2 = unicode(cls.id2)
        cls.parent_node_id = cls.id1
        cls.market_id = 42
        cls.guid = guid.GUIDMixin(cls.id1)


    @staticmethod
    def _lpad_node_id_len(node_id):
        return node_id.rjust(constants.HEX_NODE_ID_LEN, "0")

    def test_distance(self):
        def dist(node_id1, node_id2):
            return routingtable.RoutingTable.distance(
                self._lpad_node_id_len(node_id1),
                self._lpad_node_id_len(node_id2)
            )

        self.assertEqual(0, dist("a", "a"))
        self.assertNotEqual(0, dist("abcd", "dcba"))
        self.assertEqual(1, dist("2", "3"))
        self.assertEqual(10, dist("2", "8"))
        self.assertEqual(4008636142L, dist("1" * 8, "f" * 8))

        d_ab = dist("a", "b")
        self.assertEqual(d_ab, dist("b", "a"))

        self.assertEqual(d_ab, dist(u"a", "b"))
        self.assertEqual(d_ab, dist("a", u"b"))

        self.assertEqual(
            d_ab,
            routingtable.RoutingTable.distance(
                guid.GUIDMixin(self._lpad_node_id_len("a")),
                self._lpad_node_id_len("b")
            )
        )
        self.assertEqual(
            d_ab,
            routingtable.RoutingTable.distance(
                self._lpad_node_id_len("a"),
                guid.GUIDMixin(self._lpad_node_id_len("b"))
            )
        )

        self.assertRaises(
            ValueError,
            routingtable.RoutingTable.distance,
            "a" * 4,
            "a" * constants.HEX_NODE_ID_LEN
        )

        self.assertRaises(
            ValueError,
            routingtable.RoutingTable.distance,
            "a" * constants.HEX_NODE_ID_LEN,
            "a" * 4
        )

    def test_num_to_id(self):
        self.assertEqual(
            routingtable.RoutingTable.numToId(0),
            '0000000000000000000000000000000000000000'
        )
        self.assertEqual(
            routingtable.RoutingTable.numToId(42),
            '000000000000000000000000000000000000002a'
        )
        self.assertEqual(
            routingtable.RoutingTable.numToId(2**100),
            '0000000000000010000000000000000000000000'
        )
        self.assertEqual(
            routingtable.RoutingTable.numToId(2**160 - 1),
            'ffffffffffffffffffffffffffffffffffffffff'
        )


class TestTreeRoutingTable(TestRoutingTable):
    """Test TreeRoutingTable implementation of RoutingTable."""

    def _ad_hoc_KBucket_eq(self, kbucket1, kbucket2, msg=None):
        self.assertEqual(kbucket1.rangeMin, kbucket2.rangeMin, msg)
        self.assertEqual(kbucket1.rangeMax, kbucket2.rangeMax, msg)
        self.assertItemsEqual(kbucket1.contacts, kbucket2.contacts, msg)

    @staticmethod
    def _make_KBucket(range_min, range_max, market_id):
        return kbucket.KBucket(
            rangeMin=range_min,
            rangeMax=range_max,
            market_id=market_id
        )

    @classmethod
    def setUpClass(cls):
        super(TestTreeRoutingTable, cls).setUpClass()
        cls.range_min = 0
        cls.range_max = 2**constants.BIT_NODE_ID_LEN
        cls.init_kbuckets = [
            cls._make_KBucket(cls.range_min, cls.range_max, cls.market_id)
        ]

    def setUp(self):
        self.rt = routingtable.TreeRoutingTable(
            self.parent_node_id,
            self.market_id
        )

    def test_subclassing(self):
        self.assertIsInstance(self.rt, routingtable.RoutingTable)

    def test_init(self):
        self.assertEqual(self.rt.parent_node_id, self.parent_node_id)
        self.assertEqual(self.rt.market_id, self.market_id)
        self.assertTrue(hasattr(self.rt, 'log'))
        self.assertTrue(hasattr(self.rt, 'buckets'))
        self.addTypeEqualityFunc(kbucket.KBucket, self._ad_hoc_KBucket_eq)
        # The following check cannot be simplified due to this bug
        # http://www.gossamer-threads.com/lists/python/bugs/1159468
        self.assertEqual(len(self.rt.buckets), 1)
        self.assertEqual(self.rt.buckets[0], self.init_kbuckets[0])

    def test_findCloseNodes(self):
        pass

    def test_getContact(self):
        self.rt.buckets[0].addContact(self.id1)
        self.assertEqual(self.id1, self.rt.getContact(self.id1))
        self.assertIsNone(self.rt.getContact(self.id2))

    def _init_N_buckets(self, N):
        bucket_range = self.range_max - self.range_min
        chop = bucket_range // N
        self.rt.buckets = [
            self._make_KBucket(
                self.range_min + i * chop,
                min(self.range_min + (i + 1) * chop, self.range_max),
                self.market_id
            )
            for i in range(N)
        ]
        return self.range_min + bucket_range // N

    def test_getRefreshList(self):
        # We will override the parent method case-by case.
        pass

    def test_getRefreshList_force(self):
        self._init_N_buckets(7)
        self.assertEqual(
            self.rt.buckets,
            self.rt.getRefreshList(force=True)
        )

        self.assertEqual(
            self.rt.buckets[1:],
            self.rt.getRefreshList(start_index=1, force=True)
        )

        # Check immutability
        refresh_list = self.rt.getRefreshList(force=True)
        refresh_list.pop(0)
        self.assertEqual(
            refresh_list,
            self.rt.getRefreshList(force=True)[1:]
        )

    def test_getRefreshList_noforce(self):
        bucket_count = 7
        self._init_N_buckets(bucket_count)
        stale_idxs = {0, 3, 6}
        for i in range(bucket_count):
            bucket = self.rt.buckets[i]
            self.assertEqual(0, bucket.lastAccessed)
            if i not in stale_idxs:
                self.rt.touchKBucket(self.rt.numToId(bucket.rangeMin))

        refresh_list = self.rt.getRefreshList()
        recovered_idxs = set()
        for node_id in refresh_list:
            bucket_idx = self.rt.kbucketIndex(node_id)
            recovered_idxs.add(bucket_idx)
        self.assertEqual(stale_idxs, recovered_idxs)

        # Check immutability
        refresh_list = self.rt.getRefreshList()
        refresh_list.pop(0)
        self.assertEqual(
            refresh_list,
            self.rt.getRefreshList()[1:]
        )

        refresh_list = self.rt.getRefreshList(start_index=4)
        recovered_idxs = set()
        for node_id in refresh_list:
            bucket_idx = self.rt.kbucketIndex(node_id)
            recovered_idxs.add(bucket_idx)
        new_stale_idxs = {idx for idx in stale_idxs if idx >= 4}
        self.assertEqual(new_stale_idxs, recovered_idxs)

    def _test_removeContact_scenario(self, contact):
        self.assertNotIn(contact, self.rt.buckets[0])
        self.rt.buckets[0].addContact(contact)
        self.assertIn(contact, self.rt.buckets[0])
        self.rt.removeContact(contact)
        self.assertNotIn(contact, self.rt.buckets[0])

    def test_removeContact(self):
        self._test_removeContact_scenario(self.id1)
        self._test_removeContact_scenario(unicode(self.id1))
        self._test_removeContact_scenario(guid.GUIDMixin(self.id1))

        # Removing an absent contact shouldn't raise a ValueError
        self._test_removeContact_scenario(self.id2)

    def test_touchKBucket(self):
        half_range = self._init_N_buckets(2)

        self.assertEqual(
            self.rt.buckets[0].lastAccessed,
            self.rt.buckets[1].lastAccessed
        )

        now = int(time.time())
        self.assertNotEqual(now, self.rt.buckets[0].lastAccessed)

        hex_key = self.rt.numToId(half_range)
        self.rt.touchKBucket(hex_key, timestamp=now)
        self.assertLessEqual(now, self.rt.buckets[1].lastAccessed)
        self.assertNotEqual(
            self.rt.buckets[0].lastAccessed,
            self.rt.buckets[1].lastAccessed
        )

        now2 = now + 1
        self.rt.touchKBucket(self.rt.numToId(half_range - 1), now2)
        self.assertEqual(now, self.rt.buckets[1].lastAccessed)
        self.assertEqual(now2, self.rt.buckets[0].lastAccessed)

    def test_kbucketIndex_bad_key(self):
        bad_hex_key = "z"  # not a hex value
        self.assertRaises(ValueError, self.rt.kbucketIndex, bad_hex_key)

    def test_kbucketIndex_not_found(self):
        ghost_hex_key = self.rt.numToId(self.range_max)
        self.assertRaises(KeyError, self.rt.kbucketIndex, ghost_hex_key)

    def test_kbucketIndex_many_found(self):
        hex_key = self.rt.numToId(self.range_min)
        # Insert duplicate kbucket
        self.rt.buckets.append(self.rt.buckets[0])
        self.assertRaises(RuntimeError, self.rt.kbucketIndex, hex_key)

    def test_kbucketIndex_default(self):
        hex_key = self.rt.numToId(self._init_N_buckets(2))
        self.assertEqual(1, self.rt.kbucketIndex(hex_key))
        self.assertEqual(1, self.rt.kbucketIndex(unicode(hex_key)))
        self.assertEqual(1, self.rt.kbucketIndex(guid.GUIDMixin(hex_key)))



class TestOptimizedTreeRoutingTable(TestTreeRoutingTable):
    """Test OptimizedTreeRoutingTable implementation of RoutingTable."""

    @classmethod
    def setUpClass(cls):
        super(TestOptimizedTreeRoutingTable, cls).setUpClass()

    def setUp(self):
        self.rt = routingtable.OptimizedTreeRoutingTable(
            self.parent_node_id,
            self.market_id
        )

    def test_subclassing(self):
        self.assertIsInstance(self.rt, routingtable.TreeRoutingTable)

    def test_init(self):
        super(TestOptimizedTreeRoutingTable, self).test_init()
        self.assertTrue(hasattr(self.rt, 'replacement_cache'))
        self.assertEqual(self.rt.replacement_cache, dict())

    def test_addContact(self):
        pass


if __name__ == "__main__":
    unittest.main()
