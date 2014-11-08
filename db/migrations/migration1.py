#!/usr/bin/env python

import sys

from pysqlcipher import dbapi2

from node import constants


def upgrade(db_path):
    with dbapi2.connect(db_path) as con:
        cur = con.cursor()

        # Use PRAGMA key to encrypt / decrypt database.
        cur.execute("PRAGMA key = 'passphrase';")

        try:
            cur.execute("CREATE TABLE events("
                        "id INTEGER PRIMARY KEY "
                        "AUTOINCREMENT, "
                        "market_id TEXT, "
                        "event_id TEXT, "
                        "event_description TEXT, "
                        "updated INT, "
                        "created INT)")
            print 'Upgraded'
        except dbapi2.Error as e:
            print 'Exception: %s' % e


def downgrade(db_path):
    with dbapi2.connect(db_path) as con:
        cur = con.cursor()

        # Use PRAGMA key to encrypt / decrypt database.
        cur.execute("PRAGMA key = 'passphrase';")
        cur.execute("DROP TABLE IF EXISTS events;")

        print 'Downgraded'


if __name__ == "__main__":
    db_path = constants.DB_PATH
    if len(sys.argv) > 2:
        db_path = sys.argv[1]
        if sys.argv[2] == "downgrade":
            downgrade(db_path)
        else:
            upgrade(db_path)
