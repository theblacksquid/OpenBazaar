import UserDict
import logging
import ast
from abc import ABCMeta, abstractmethod


class DataStore(UserDict.DictMixin, object):
    """ Interface for classes implementing physical storage (for data
    published via the "STORE" RPC) for the Kademlia DHT

    @note: This provides an interface for a dict-like object
    """

    __metaclass__ = ABCMeta

    def __init__(self):
        return

    @abstractmethod
    def keys(self):
        """ Return a list of the keys in this data store """
        pass

    @abstractmethod
    def lastPublished(self, key):
        """ Get the time the C{(key, value)} pair identified by C{key}
        was last published """
        pass

    @abstractmethod
    def originalPublisherID(self, key):
        """ Get the original publisher of the data's node ID

        @param key: The key that identifies the stored data
        @type key: str

        @return: Return the node ID of the original publisher of the
        C{(key, value)} pair identified by C{key}.
        """
        pass

    @abstractmethod
    def originalPublishTime(self, key):
        """ Get the time the C{(key, value)} pair identified by C{key}
        was originally published """
        pass

    @abstractmethod
    def setItem(self, key, value, lastPublished, originallyPublished,
                originalPublisherID, market_id):
        """ Set the value of the (key, value) pair identified by C{key};
        this should set the "last published" value for the (key, value)
        pair to the current time
        """
        pass

    @abstractmethod
    def __getitem__(self, key):
        """ Get the value identified by C{key} """
        pass

    @abstractmethod
    def __delitem__(self, key):
        """ Delete the specified key (and its value) """
        pass

    def __setitem__(self, key, value):
        """
        Convenience wrapper to C{setItem}; this accepts a tuple in the format:
        (value, lastPublished, originallyPublished, originalPublisherID).
        """
        self.setItem(key, *value)


class SqliteDataStore(DataStore):
    """Sqlite database-based datastore."""
    def __init__(self, db_connection):
        super(SqliteDataStore, self).__init__()
        self.db = db_connection
        self.log = logging.getLogger(self.__class__.__name__)

    def keys(self):
        """ Return a list of the keys in this data store """
        keys = []
        try:
            db_keys = self.db.selectEntries("datastore")
            for row in db_keys:
                keys.append(row['key'].decode('hex'))
        except Exception:
            pass
        return keys

    def lastPublished(self, key):
        """ Get the time the C{(key, value)} pair identified by C{key}
        was last published """
        return int(self._dbQuery(key, 'lastPublished'))

    def originalPublisherID(self, key):
        """ Get the original publisher of the data's node ID

        @param key: The key that identifies the stored data
        @type key: str

        @return: Return the node ID of the original publisher of the
        C{(key, value)} pair identified by C{key}.
        """
        return self._dbQuery(key, 'originalPublisherID')

    def originalPublishTime(self, key):
        """ Get the time the C{(key, value)} pair identified by C{key}
        was originally published """
        return int(self._dbQuery(key, 'originallyPublished'))

    def setItem(self, key, value, lastPublished, originallyPublished,
                originalPublisherID, market_id=1):

        rows = self.db.selectEntries(
            "datastore",
            {"key": key,
             "market_id": market_id}
        )
        if len(rows) == 0:
            self.db.insertEntry(
                "datastore",
                {
                    'key': key,
                    'value': value,
                    'lastPublished': lastPublished,
                    'originallyPublished': originallyPublished,
                    'originalPublisherID': originalPublisherID,
                    'market_id': market_id
                }
            )
        else:
            self.db.updateEntries(
                "datastore",
                {
                    'key': key,
                    'value': value,
                    'lastPublished': lastPublished,
                    'originallyPublished': originallyPublished,
                    'originalPublisherID': originalPublisherID,
                    'market_id': market_id
                },
                {
                    'key': key,
                    'market_id': market_id
                }
            )

    def _dbQuery(self, key, columnName):

        row = self.db.selectEntries("datastore", {"key": key})

        if len(row) != 0:
            value = row[0][columnName]
            try:
                value = ast.literal_eval(value)
            except Exception:
                pass
            return value

    def __getitem__(self, key):
        return self._dbQuery(key, 'value')

    def __delitem__(self, key):
        self.db.deleteEntries("datastore", {"key": key.encode("hex")})
