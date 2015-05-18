import logging

from node import constants, guid


class BucketFull(Exception):
    """Raised when the bucket is full."""
    pass


class KBucket(object):
    """FILLME"""

    def __init__(self, range_min, range_max, market_id):
        """
        Initialize a new KBucket with a range and a market_id.

        @param range_min: The lower boundary for the range in the ID space
                          covered by this KBucket.
        @type: int

        @param range_max: The upper boundary for the range in the ID space
                          covered by this KBucket.
        @type: int

        @param market_id: FILLME
        """

        self.last_accessed = 0
        self.range_min = range_min
        self.range_max = range_max
        self.contacts = []
        self.market_id = market_id

        self.log = logging.getLogger(
            '[%s] %s' % (market_id, self.__class__.__name__)
        )

    def __len__(self):
        return len(self.contacts)

    def __iter__(self):
        return iter(self.contacts)

    def add_contact(self, contact):
        """
        Add a contact to the contact list.

        The new contact is always appended to the contact list after removing
        any prior occurences of the same contact.

        @param contact: The ID of the contact to add.
        @type contact: guid.GUIDMixin or str or unicode

        @raise node.kbucket.BucketFull: The bucket is full and the contact
                                        to add is not already in it.
        """
        if isinstance(contact, basestring):
            contact = guid.GUIDMixin(contact)
        try:
            # Assume contact exists. Attempt to remove the old one...
            self.contacts.remove(contact)
            # ... and add the new one at the end of the list.
            self.contacts.append(contact)

            # The code above works as follows:
            # Assume C1 is the existing contact and C2 is the new contact.
            # Iff C1 is equal to C2, it will be removed from the list.
            # Since Contact.__eq__ compares only GUIDs, contact C1 will
            # be replaced even if it's not exactly the same as C2.
            # This is the intended behaviour; the fresh contact may have
            # updated add-on data (e.g. optimization-specific stuff).
        except ValueError:
            # The contact wasn't there after all, so add it.
            if len(self.contacts) < constants.K:
                self.contacts.append(contact)
            else:
                raise BucketFull('No space in bucket to insert contact')

    def get_contact(self, contact_id):
        """
        Return the contact with the specified ID or None if not present.

        @param contact_id: The ID to search.
        @type contact: guid.GUIDMixin or str or unicode

        @rtype: guid.GUIDMixin or None
        """
        self.log.debugv('[get_contact] %s', contact_id)
        for contact in self.contacts:
            if contact == contact_id:
                self.log.debugv('[get_contact] Found %s', contact)
                return contact
        self.log.debugv('[get_contact] No Results')
        return None

    def get_contacts(self, count=-1, exclude_contact=None):
        """
        Return a list containing up to the first `count` number of contacts.

        @param count: The amount of contacts to return;
                      if 0 or less, return all contacts.
        @type count: int
        @param exclude_contact: A contact to exclude; if this contact is in
                                the list of returned values, it will be
                                discarded before returning. If a str is
                                passed as this argument, it must be the
                                contact's ID.
        @type exclude_contact: guid.GUIDMixin or str or unicode

        @return: The first `count` contacts in the contact list.
                 This amount is capped by the available contacts
                 and the bucket size, of course. If no contacts
                 are present, an empty list is returned.
        @rtype:  list of guid.GUIDMixin
        """

        current_len = len(self)
        if not current_len:
            return []

        if count <= 0:
            count = current_len
        else:
            count = min(count, current_len)

        # Return no more contacts than bucket size.
        count = min(count, constants.K)

        contact_list = self.contacts[:count]
        if exclude_contact is not None:
            try:
                # NOTE: If the exclude_contact is removed, the resulting
                # list has one less contact than expected. Not sure if
                # this is a bug.
                contact_list.remove(exclude_contact)
            except ValueError:
                self.log.debug(
                    '[kbucket.get_contacts() warning] '
                    'tried to exclude non-existing contact (%s)',
                    exclude_contact
                )
        return contact_list

    def remove_contact(self, contact):
        """
        Remove given contact from contact list.

        @param contact: The ID of the contact to remove.
        @type contact: guid.GUIDMixin or str or unicode

        @raise ValueError: The specified contact is not in this bucket.
        """
        self.contacts.remove(contact)

    def key_in_range(self, key):
        """
        Tests whether the specified node ID is in the range of the ID
        space covered by this KBucket (in other words, it returns
        whether or not the specified key should be placed in this KBucket.

        @param key: The ID to test.
        @type key: guid.GUIDMixin or hex or int

        @return: True if key is in this KBucket's range, False otherwise.
        @rtype: bool
        """
        if isinstance(key, guid.GUIDMixin):
            key = key.guid
        if isinstance(key, basestring):
            key = int(key, base=16)
        return self.range_min <= key < self.range_max
