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
            cur.execute("ALTER TABLE contracts "
                        "ADD COLUMN deleted INT DEFAULT 0")
            print 'Upgraded'
            con.commit()
        except dbapi2.Error as e:
            print 'Exception: %s' % e


def downgrade(db_path):
    with dbapi2.connect(db_path) as con:
        cur = con.cursor()

        # Use PRAGMA key to encrypt / decrypt database.
        cur.execute("PRAGMA key = '%s';" % constants.DB_PASSPHRASE)

        cur.execute("ALTER TABLE contracts DROP COLUMN deleted")

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
