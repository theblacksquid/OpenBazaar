#!/usr/bin/env python

import argparse

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


def main():
    parser = argparse.ArgumentParser(description="Migrate the database")
    parser.add_argument("path", help="the location of the database",
                        nargs='?', default=constants.DB_PATH)
    parser.add_argument("action", help="the action you want to perform",
                        choices=("upgrade", "downgrade"))

    args = parser.parse_args()
    if args.action == "upgrade":
        upgrade(args.path)
    else:
        downgrade(args.path)

if __name__ == "__main__":
    main()
