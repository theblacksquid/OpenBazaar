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
    def get_last_published(self, key):
        """ Get the time the C{(key, value)} pair identified by C{key}
        was last published """
        pass

    @abstractmethod
    def get_original_publisher_id(self, key):
        """ Get the original publisher of the data's node ID

        @param key: The key that identifies the stored data
        @type key: str

        @return: Return the node ID of the original publisher of the
        C{(key, value)} pair identified by C{key}.
        """
        pass

    @abstractmethod
    def get_original_publish_time(self, key):
        """ Get the time the C{(key, value)} pair identified by C{key}
        was originally published """
        pass

    @abstractmethod
    def set_item(self, key, value, last_published, originally_published,
                 original_publisher_id, market_id):
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
        Convenience wrapper to C{set_item}; this accepts a tuple in the format:
        (value, last_published, originally_published, original_publisher_id).
        """
        self.set_item(key, *value)


class SqliteDataStore(DataStore):
    """Sqlite database-based datastore."""
    def __init__(self, db_connection):
        super(SqliteDataStore, self).__init__()
        self.db_connection = db_connection
        self.log = logging.getLogger(self.__class__.__name__)

    def keys(self):
        """ Return a list of the keys in this data store """
        keys = []
        try:
            db_keys = self.db_connection.select_entries("datastore")
            for row in db_keys:
                keys.append(row['key'].decode('hex'))
        except Exception:
            pass
        return keys

    def get_last_published(self, key):
        """ Get the time the C{(key, value)} pair identified by C{key}
        was last published """
        return int(self._db_query(key, 'lastPublished'))

    def get_original_publisher_id(self, key):
        """ Get the original publisher of the data's node ID

        @param key: The key that identifies the stored data
        @type key: str

        @return: Return the node ID of the original publisher of the
        C{(key, value)} pair identified by C{key}.
        """
        return self._db_query(key, 'originalPublisherID')

    def get_original_publish_time(self, key):
        """ Get the time the C{(key, value)} pair identified by C{key}
        was originally published """
        return int(self._db_query(key, 'originallyPublished'))

    def set_item(self, key, value, last_published, originally_published,
                 original_publisher_id, market_id=1):

        rows = self.db_connection.select_entries(
            "datastore",
            {"key": key,
             "market_id": market_id}
        )
        if len(rows) == 0:
            self.db_connection.insert_entry(
                "datastore",
                {
                    'key': key,
                    'value': value,
                    'lastPublished': last_published,
                    'originallyPublished': originally_published,
                    'originalPublisherID': original_publisher_id,
                    'market_id': market_id
                }
            )
        else:
            self.db_connection.update_entries(
                "datastore",
                {
                    'key': key,
                    'value': value,
                    'lastPublished': last_published,
                    'originallyPublished': originally_published,
                    'originalPublisherID': original_publisher_id,
                    'market_id': market_id
                },
                {
                    'key': key,
                    'market_id': market_id
                }
            )

    def _db_query(self, key, column_name):

        row = self.db_connection.select_entries("datastore", {"key": key})

        if len(row) != 0:
            value = row[0][column_name]
            try:
                value = ast.literal_eval(value)
            except Exception:
                pass
            return value

    def __getitem__(self, key):
        return self._db_query(key, 'value')

    def __delitem__(self, key):
        self.db_connection.delete_entries("datastore", {"key": key.encode("hex")})
