#!/usr/bin/env python

from pysqlcipher import dbapi2

from db.migrations import migrations_util
from node import constants


def upgrade(db_path):
    with dbapi2.connect(db_path) as con:
        cur = con.cursor()

        # Use PRAGMA key to encrypt / decrypt database.
        cur.execute("PRAGMA key = 'passphrase';")

        try:
            cur.execute("ALTER TABLE settings "
                        "ADD COLUMN namecoin_id TEXT")
            print 'Upgraded'
            con.commit()
        except dbapi2.Error as e:
            print 'Exception: %s' % e


def downgrade(db_path):
    with dbapi2.connect(db_path) as con:
        cur = con.cursor()

        # Use PRAGMA key to encrypt / decrypt database.
        cur.execute("PRAGMA key = 'passphrase';")

        cur.execute("ALTER TABLE settings DROP COLUMN namecoin_id")

        print 'Downgraded'
        con.commit()


def main():
    parser = migrations_util.make_argument_parser(constants.DB_PATH)
    args = parser.parse_args()
    if args.action == "upgrade":
        upgrade(args.path)
    else:
        downgrade(args.path)

if __name__ == "__main__":
    main()
