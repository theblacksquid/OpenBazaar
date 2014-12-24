"""
Interface and implementation of a Kademlia routing table.

Classes:
    RoutingTable -- Interface
    OptimizedTreeRoutingTable -- Implementation
"""

from abc import ABCMeta, abstractmethod
import logging
import time

from node import constants, guid, kbucket


class RoutingTable(object):
    """
    Interface for routing table implementations.

    Classes inheriting from this should provide a suitable routing table
    for a parent Node object (i.e. the local entity in the Kademlia
    network).
    """

    __metaclass__ = ABCMeta

    def __init__(self, parent_node_id, market_id):
        """
        Initialize a new RoutingTable.

        @param parent_node_id: The node ID of the node to which this
                               routing table belongs.
        @type parent_node_id: guid.GUIDMixin or str or unicode

        @param market_id: FILLME
        @type: int
        """
        self.market_id = market_id
        self.parent_node_id = parent_node_id

        self.log = logging.getLogger(
            '[%s] %s' % (self.market_id, self.__class__.__name__)
        )

    @abstractmethod
    def add_contact(self, node_id):
        """
        Add the given node to the correct KBucket; if it already
        exists, update its status.

        @param contact: The contact to add to this node's KBuckets
        @type contact: guid.GUIDMixin or str or unicode
        """
        pass

    @staticmethod
    def distance(node_id1, node_id2):
        """
        Calculate the XOR result between two string variables.

        @param node_id1: The ID of the first node.
        @type node_id1: guid.GUIDMixin or str or unicode

        @param node_id2: The ID of the second node.
        @type node_id1: guid.GUIDMixin or str or unicode

        @return: XOR result of two long variables
        @rtype: long

        @raises: ValueError: The strings have improper lengths for IDs.
        """
        if isinstance(node_id1, guid.GUIDMixin):
            key1 = node_id1.guid
        else:
            key1 = node_id1

        if isinstance(node_id2, guid.GUIDMixin):
            key2 = node_id2.guid
        else:
            key2 = node_id2

        if len(key1) != constants.HEX_NODE_ID_LEN:
            raise ValueError(
                "node_id1 has invalid length %d; must be %d" % (
                    len(key1),
                    constants.HEX_NODE_ID_LEN
                )
            )

        if len(key2) != constants.HEX_NODE_ID_LEN:
            raise ValueError(
                "node_id2 has invalid length %d; must be %d" % (
                    len(key2),
                    constants.HEX_NODE_ID_LEN
                )
            )

        val_key1 = int(key1, base=16)
        val_key2 = int(key2, base=16)
        return val_key1 ^ val_key2

    @staticmethod
    def num_to_id(node_num):
        """
        Converts an integer to a node ID.

        It is the caller's responsibility to ensure the resulting
        node ID falls in the ID space.

        @param node_num: The integer to convert.
        @type node_num: int

        @return: A node ID (hex) corresponding to the number given.
        @rtype: str
        """
        # Convert to hex string.
        node_id = hex(node_num)
        # Strip '0x' prefix and 'L' suffix.
        bare_node_id = node_id.lstrip("0x").rstrip("L")
        # Pad to proper length and return.
        return bare_node_id.rjust(constants.HEX_NODE_ID_LEN, '0')

    @abstractmethod
    def find_close_nodes(self, node_id, count, rpc_node_id=None):
        """
        Find a number of known nodes closest to the node/value with the
        specified ID.

        @param node_id: The node ID to search for
        @type node_id: guid.GUIDMixin or str or unicode

        @param count: The amount of contacts to return
        @type count: int

        @param rpc_node_id: Used during RPC, this is the sender's node ID.
                            The ID passed as parameter is excluded from
                            the list of returned contacts.
        @type rpc_node_id: guid.GUIDMixin or str or unicode

        @return: A list of nodes closest to the specified key.
                 This method will return constants.K (or count, if
                 specified) contacts if at all possible; it will only
                 return fewer if the node is returning all of the
                 contacts that it knows of.
        @rtype: list of guid.GUIDMixin
        """
        pass

    @abstractmethod
    def get_contact(self, node_id):
        """
        Return the known node with the specified ID, None if not found.

        @param: node_id: The ID of the node to search for.
        @type: guid.GUIDMixin or str or unicode

        @return: The node with the specified ID or None
        @rtype: guid.GUIDMixin or NoneType
        """
        pass

    @abstractmethod
    def get_refresh_list(self, start_index=0, force=False):
        """
        Find all KBuckets that need refreshing, starting at the KBucket
        with the specified index, and return IDs to be searched for in
        order to refresh those KBuckets.

        @param start_index: The index of the bucket to start refreshing
                            at; this bucket and those further away from
                            it will be refreshed. For example, when
                            joining the network, this node will set this
                            to the index of the bucket after the one
                            containing its closest neighbour.
        @type start_index: int

        @param force: If this is True, all buckets in the specified
                      range will be refreshed, regardless of the time
                      they were last accessed.
        @type force: bool

        @return: A list of node IDs that the parent node should search for
                 in order to refresh the routing Table.
        @rtype: list of guid.GUIDMixin
        """
        pass

    @abstractmethod
    def remove_contact(self, node_id):
        """
        Remove the node with the specified ID from the routing table.

        @param node_id: The ID of the node to remove.
        @type node_id: guid.GUIDMixin or str or unicode
        """
        pass

    @abstractmethod
    def touch_kbucket(self, node_id, timestamp=None):
        """
        Update the "last accessed" timestamp of the KBucket which covers
        the range containing the specified key in the key/ID space.

        @param node_id: A key in the range of the target KBucket
        @type node_id: guid.GUIDMixin or str or unicode

        @param timestamp: The timestamp to set on the bucket.
                          If None, it will be set to int(time.time()).
        @type timestamp: int
        """
        pass


class OptimizedTreeRoutingTable(RoutingTable):
    """
    This class implements a routing table used by a Node class.

    The Kademlia routing table is a binary tree whose leaves are KBuckets,
    where each KBucket contains nodes with some common prefix of their IDs.
    This prefix is the KBucket's position in the binary tree; it therefore
    covers some range of ID values, and together all of the KBuckets cover
    the entire ID space, without any overlaps.

    Note: This implementation adds nodes in the tree (the KBuckets) in
    an on-demand fashion, as described in section 2.4 of the 13-page
    version of the Kademlia paper[1]. It also uses the contact accounting
    optimization specified in section 4.1 of the said paper (optimized
    node accounting without PINGs). This results in much less network
    traffic, at the expense of some memory.

    [1]: http://pdos.csail.mit.edu/~petar/papers/maymounkov-kademlia-lncs.pdf
    """

    def __init__(self, parent_node_id, market_id):
        """
        Initialize a new OptimizedTreeRoutingTable.

        For details, see RoutingTable documentation.
        """
        super(OptimizedTreeRoutingTable, self).__init__(
            parent_node_id, market_id
        )

        # Cache containing nodes eligible to replace stale KBucket entries
        self.replacement_cache = {}

        self.buckets = [
            kbucket.KBucket(
                range_min=0,
                range_max=2**constants.BIT_NODE_ID_LEN,
                market_id=market_id
            )
        ]

    def add_contact(self, contact):
        """
        Add the given contact to the correct KBucket; if it already
        exists, update its status.

        For details, see RoutingTable documentation.
        """

        if not contact.guid:
            self.log.error('No guid specified')
            return

        if contact.guid == self.parent_node_id:
            self.log.info('Trying to add yourself. Leaving.')
            return

        bucket_index = self.kbucket_index(contact.guid)
        old_contact = self.buckets[bucket_index].get_contact(contact.guid)

        if not old_contact:
            try:
                self.buckets[bucket_index].add_contact(contact)
            except kbucket.BucketFull:
                # The bucket is full; see if it can be split (by checking if
                # its range includes the host node's id)
                if self.buckets[bucket_index].key_in_range(self.parent_node_id):
                    self.split_bucket(bucket_index)
                    # Retry the insertion attempt
                    self.add_contact(contact)
                else:
                    # We can't split the KBucket
                    # NOTE: This implementation follows section 4.1 of the 13
                    # page version of the Kademlia paper (optimized contact
                    # accounting without PINGs - results in much less network
                    # traffic, at the expense of some memory)

                    # Put the new contact in our replacement cache for the
                    # corresponding KBucket (or update it's position if it
                    # exists already)
                    if bucket_index not in self.replacement_cache:
                        self.replacement_cache[bucket_index] = []
                    if contact in self.replacement_cache[bucket_index]:
                        self.replacement_cache[bucket_index].remove(contact)
                    # TODO: Using k to limit the size of the contact
                    # replacement cache - maybe define a separate value for
                    # this in constants.py?
                    elif len(self.replacement_cache) >= constants.K:
                        self.replacement_cache.pop(0)
                    self.replacement_cache[bucket_index].append(contact)
        elif old_contact.address != contact.address:
            self.log.info('Remove contact')
            self.remove_contact(contact.guid)

            try:
                self.buckets[bucket_index].add_contact(contact)
            except kbucket.BucketFull:
                # The bucket is full; see if it can be split (by checking
                # if its range includes the host node's id)
                if self.buckets[bucket_index].key_in_range(self.parent_node_id):
                    self.split_bucket(bucket_index)
                    # Retry the insertion attempt
                    self.add_contact(contact)
                else:
                    # We can't split the KBucket
                    # NOTE: This implementation follows section 4.1 of the
                    # 13 page version of the Kademlia paper (optimized
                    # contact accounting without PINGs - results in much
                    # less network traffic, at the expense of some memory)

                    # Put the new contact in our replacement cache for the
                    # corresponding KBucket (or update it's position if
                    # it exists already)
                    if bucket_index not in self.replacement_cache:
                        self.replacement_cache[bucket_index] = []
                    if contact in self.replacement_cache[bucket_index]:
                        self.replacement_cache[bucket_index].remove(contact)
                    # TODO: Using k to limit the size of the contact
                    # replacement cache - maybe define a separate value
                    # for this in constants.py?
                    elif len(self.replacement_cache) >= constants.K:
                        self.replacement_cache.pop(0)
                    self.replacement_cache[bucket_index].append(contact)

    def find_close_nodes(self, key, count, node_id=None):
        """
        Find a number of known nodes closest to the node/value with the
        specified key.

        @param key: The key (i.e. the node or value ID) to search for.
        @type key: str

        @param count: the amount of contacts to return
        @type count: int
        @param nodeID: Used during RPC, this is the sender's Node ID.
                       The ID passed in the paramater is excluded from
                       the list of contacts returned.
        @type nodeID: str

        @return: A list of node contacts (C{guid.GUIDMixin instances})
                 closest to the specified key.
                 This method will return C{k} (or C{count}, if specified)
                 contacts if at all possible; it will only return fewer if the
                 node is returning all of the contacts that it knows of.
        @rtype: list
        """
        bucket_index = self.kbucket_index(key)
        bucket = self.buckets[bucket_index]
        closest_nodes = bucket.get_contacts(constants.K, node_id)

        # This method must return k contacts (even if we have the node with
        # the specified key as node ID), unless there is less than k remote
        # nodes in the routing table.
        i = 1
        can_go_lower = bucket_index - i >= 0
        can_go_higher = bucket_index + i < len(self.buckets)
        # Fill up the node list to k nodes, starting with the closest
        # neighbouring nodes known.
        while len(closest_nodes) < constants.K and (can_go_lower or can_go_higher):
            # TODO: this may need to be optimized
            if can_go_lower:
                bucket = self.buckets[bucket_index - i]
                closest_nodes.extend(
                    bucket.get_contacts(
                        constants.K - len(closest_nodes), node_id
                    )
                )
                can_go_lower = bucket_index - (i + 1) >= 0
            if can_go_higher:
                bucket = self.buckets[bucket_index + i]
                closest_nodes.extend(
                    bucket.get_contacts(
                        constants.K - len(closest_nodes), node_id
                    )
                )
                can_go_higher = bucket_index + (i + 1) < len(self.buckets)
            i += 1

        self.log.datadump('Closest Nodes: %s', closest_nodes)
        return closest_nodes

    def get_contact(self, node_id):
        """
        Return the known node with the specified ID, None if not found.

        For details, see RoutingTable documentation.
        """
        bucket_index = self.kbucket_index(node_id)
        return self.buckets[bucket_index].get_contact(node_id)

    def get_refresh_list(self, start_index=0, force=False):
        """
        Find all KBuckets that need refreshing, starting at the
        KBucket with the specified index, and return IDs to be searched for
        in order to refresh those KBuckets.

        For details, see RoutingTable documentation.
        """
        if force:
            # Copy the list to avoid accidental mutation.
            return list(self.buckets[start_index:])

        now = int(time.time())
        timeout = constants.REFRESH_TIMEOUT
        return [
            # Since range_min is always in the KBucket's range
            # return that as a representative.
            self.num_to_id(bucket.range_min)
            for bucket in self.buckets[start_index:]
            if now - bucket.last_accessed >= timeout
        ]

    def remove_contact(self, node_id):
        """
        Remove the node with the specified ID from the routing table.

        For details, see RoutingTable documentation.
        """
        bucket_index = self.kbucket_index(node_id)
        try:
            self.buckets[bucket_index].remove_contact(node_id)
        except ValueError:
            self.log.error("Attempted to remove absent contact %s.", node_id)
        else:
            # Replace this stale contact with one from our replacement
            # cache, if available.
            try:
                cached = self.replacement_cache[bucket_index].pop()
            except KeyError:
                # No replacement cache for this bucket.
                pass
            except IndexError:
                # No cached contact for this bucket.
                pass
            else:
                self.buckets[bucket_index].add_contact(cached)
        finally:
            self.log.datadump('Contacts: %s', self.buckets[bucket_index].contacts)

    def touch_kbucket(self, node_id, timestamp=None):
        """
        Update the "last accessed" timestamp of the KBucket which covers
        the range containing the specified key in the key/ID space.

        For details, see RoutingTable documentation.
        """
        if timestamp is None:
            timestamp = int(time.time())
        bucket_index = self.kbucket_index(node_id)
        self.buckets[bucket_index].last_accessed = timestamp

    def kbucket_index(self, node_id):
        """
        Calculate the index of the KBucket which is responsible for the
        specified key (or ID).

        @param key: The key for which to find the appropriate KBucket index
        @type key: guid.GUIDMixin or str or unicode

        @raises: KeyError: The key was no KBucket's responsibility; absent key.
                 RuntimeError: Many KBuckets responsible for same key;
                               invariants have been violated.
                 ValueError: The key is badly encoded.

        @return: The index of the KBucket responsible for the specified key
        @rtype: int
        """
        if isinstance(node_id, guid.GUIDMixin):
            key = node_id.guid
        else:
            key = node_id

        # TODO: Since we are using monotonic node ID spaces,
        # this *begs* to be done with binary search.
        indexes = [
            i
            for i, bucket in enumerate(self.buckets)
            if bucket.key_in_range(key)
        ]

        if not indexes:
            raise KeyError("No KBucket responsible for key %s." % key)
        elif len(indexes) > 1:
            raise RuntimeError(
                "Many KBuckets responsible for key %s." % key
            )
        return indexes[0]

    def split_bucket(self, old_bucket_index):
        """
        Split the specified KBucket into two new buckets which together cover
        the same range in the key/ID space.

        @param old_bucket_index: The index of KBucket to split (in this table's
                                 list of KBuckets)
        @type old_bucket_index: int
        """
        # Halve the range of the current (old) KBucket.
        old_bucket = self.buckets[old_bucket_index]
        split_point = (old_bucket.range_max -
                       (old_bucket.range_max - old_bucket.range_min) // 2)
        # Create a new KBucket to cover the range split off from the old one.
        new_bucket = kbucket.KBucket(
            split_point, old_bucket.range_max, self.market_id
        )
        old_bucket.range_max = split_point
        # Now, add the new bucket into the routing table tree
        self.buckets.insert(old_bucket_index + 1, new_bucket)
        # Finally, copy all nodes that belong to the new KBucket into it...
        for contact in old_bucket.contacts:
            if new_bucket.key_in_range(contact.guid):
                new_bucket.add_contact(contact)
        # ...and remove them from the old bucket
        for contact in new_bucket.contacts:
            old_bucket.remove_contact(contact)
