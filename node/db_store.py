import functools
import logging
import threading

from pysqlcipher import dbapi2


class Obdb(object):
    """
    API for DB storage. Serves as segregation of the persistence
    layer and the application logic.
    """
    def __init__(self, db_path, disable_sqlite_crypt=False):
        self.db_path = db_path
        self.con = None
        self.disable_sqlite_crypt = disable_sqlite_crypt

        self._log = logging.getLogger('DB')
        self._lock = threading.Lock()

        dbapi2.register_adapter(bool, int)
        dbapi2.register_converter("bool", lambda v: bool(int(v)))

    def _login(self, passphrase='passphrase'):
        """Enable access to an encrypted database."""
        cursor = self.con.cursor()
        cursor.execute("PRAGMA key = '%s';" % passphrase)

    def _make_db_connection(self):
        """Create and return a DB connection."""
        return dbapi2.connect(
            self.db_path,
            detect_types=dbapi2.PARSE_DECLTYPES,
            timeout=10
        )


    # pylint: disable=no-self-argument
    # pylint: disable=not-callable
    def _managedmethod(func):
        """
        Decorator for abstracting the setting up and tearing down of a
        DB operation. It handles:
            * Syncrhonizing multiple DB accesses.
            * Opening and closing DB connections.
            * Authenitcating the user if the database is encrypted.

        A function wrapped by this decorator may use the database
        connection (via self.con) in order to operate on the DB
        but shouldn't close the connection or manage it in any other way.
        """
        @functools.wraps(func)
        def managed_func(self, *args, **kwargs):
            with self._lock, self._make_db_connection() as self.con:
                self.con.row_factory = self._dict_factory
                if not self.disable_sqlite_crypt:
                    self._login()

                ret_val = func(self, *args, **kwargs)

                self.con.commit()
                return ret_val

        return managed_func

    @staticmethod
    def _dict_factory(cursor, row):
        """
        A factory that allows sqlite to return a dictionary instead of a tuple.
        """
        dictionary = {}
        for idx, col in enumerate(cursor.description):
            if row[idx] is None:
                dictionary[col[0]] = ""
            else:
                dictionary[col[0]] = row[idx]
        return dictionary

    @staticmethod
    def _before_storing(value):
        """Method called before executing SQL identifiers."""
        return unicode(value)

    def get_or_create(self, table, where_dict, data_dict=False):
        """
        This method attempts to grab the record first. If it fails to
        find it, it will create it.

        @param table: The table to search to
        @param where_dict: A dictionary with the WHERE/SET clauses
        @param data_dict: A dictionary with the SET clauses
        """
        if not data_dict:
            data_dict = where_dict

        entries = self.select_entries(table, where_dict)
        if not entries:
            self.insert_entry(table, data_dict)
        return self.select_entries(table, where_dict)[0]

    @_managedmethod
    def update_entries(self, table, set_dict, where_dict=None, operator="AND"):
        """
        A wrapper for the SQL UPDATE operation.

        @param table: The table to search to
        @param set_dict: A dictionary with the SET clauses
        @param where_dict: A dictionary with the WHERE clauses
        """
        if where_dict is None:
            where_dict = {'"1"': '1'}

        cur = self.con.cursor()
        sets = []
        wheres = []
        where_part = []
        set_part = []
        for key, value in set_dict.iteritems():
            if type(value) == bool:
                value = bool(value)
            key = self._before_storing(key)
            value = self._before_storing(value)
            sets.append(value)
            set_part.append("%s = ?" % key)
        set_part = ",".join(set_part)
        for key, value in where_dict.iteritems():
            sign = "="
            if isinstance(value, dict):
                sign = value["sign"]
                value = value["value"]
            key = self._before_storing(key)
            value = self._before_storing(value)
            wheres.append(value)
            where_part.append("%s %s ?" % (key, sign))
        operator = " " + operator + " "
        where_part = operator.join(where_part)
        query = "UPDATE %s SET %s WHERE %s" % (
            table, set_part, where_part
        )
        self._log.debug('query: %s', query)
        cur.execute(query, tuple(sets + wheres))

    @_managedmethod
    def insert_entry(self, table, update_dict):
        """
        A wrapper for the SQL INSERT operation.

        @param table: The table to search to
        @param update_dict: A dictionary with the values to set
        """
        cur = self.con.cursor()
        sets = []
        updatefield_part = []
        setfield_part = []
        for key, value in update_dict.iteritems():
            if type(value) == bool:
                value = bool(value)
            key = self._before_storing(key)
            value = self._before_storing(value)
            sets.append(value)
            updatefield_part.append(key)
            setfield_part.append("?")
        updatefield_part = ",".join(updatefield_part)
        setfield_part = ",".join(setfield_part)
        query = "INSERT INTO %s(%s) VALUES(%s)" % (
            table, updatefield_part, setfield_part
        )
        cur.execute(query, tuple(sets))
        lastrowid = cur.lastrowid
        self._log.debug("query: %s", query)
        if lastrowid:
            return lastrowid

    @_managedmethod
    def select_entries(self, table, where_dict=None, operator="AND", order_field="id",
                       order="ASC", limit=None, limit_offset=None, select_fields="*"):
        """
        A wrapper for the SQL SELECT operation. It will always return
        all the attributes for the selected rows.

        @param table: The table to search
        @param where_dict: A dictionary with the WHERE clauses. If ommited,
                           it will return all the rows of the table.
        """
        if where_dict is None:
            where_dict = {'"1"': '1'}

        cur = self.con.cursor()
        wheres = []
        where_part = []
        for key, value in where_dict.iteritems():
            sign = "="
            if isinstance(value, dict):
                sign = value["sign"]
                value = value["value"]
            key = self._before_storing(key)
            value = self._before_storing(value)
            wheres.append(value)
            where_part.append("%s %s ?" % (key, sign))
            if limit is not None and limit_offset is None:
                limit_clause = "LIMIT %s" % limit
            elif limit is not None and limit_offset is not None:
                limit_clause = "LIMIT %s, %s" % (limit_offset, limit)
            else:
                limit_clause = ""
        operator = " " + operator + " "
        where_part = operator.join(where_part)
        query = "SELECT * FROM %s WHERE %s ORDER BY %s %s %s" % (
            table, where_part, order_field, order, limit_clause
        )
        self._log.debug("query: %s", query)
        cur.execute(query, tuple(wheres))
        rows = cur.fetchall()
        return rows

    @_managedmethod
    def delete_entries(self, table, where_dict=None, operator="AND"):
        """
        A wrapper for the SQL DELETE operation.

        @param table: The table to search
        @param where_dict: A dictionary with the WHERE clauses. If ommited,
                           it will delete all the rows of the table.
        """
        if where_dict is None:
            where_dict = {'"1"': '1'}
        cur = self.con.cursor()
        dels = []
        where_part = []
        for key, value in where_dict.iteritems():
            sign = "="
            if isinstance(value, dict):
                sign = value["sign"]
                value = value["value"]
            key = self._before_storing(key)
            value = self._before_storing(value)
            dels.append(value)
            where_part.append("%s %s ?" % (key, sign))
        operator = " " + operator + " "
        where_part = operator.join(where_part)
        query = "DELETE FROM %s WHERE %s" % (
            table, where_part
        )
        self._log.debug('Query: %s', query)
        cur.execute(query, dels)
