#!/usr/bin/env python

from pysqlcipher import dbapi2

from db.migrations import migrations_util
from node import constants


def upgrade(db_path):
    with dbapi2.connect(db_path) as con:
        cur = con.cursor()

        # Use PRAGMA key to encrypt / decrypt database.
        cur.execute("PRAGMA key = '%s';" % constants.DB_PASSPHRASE)

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
        cur.execute("PRAGMA key = '%s';" % constants.DB_PASSPHRASE)
        cur.execute("DROP TABLE IF EXISTS events;")

        print 'Downgraded'


def main():
    parser = migrations_util.make_argument_parser(constants.DB_PATH)
    args = parser.parse_args()
    if args.action == "upgrade":
        upgrade(args.path)
    else:
        downgrade(args.path)

if __name__ == "__main__":
    main()
