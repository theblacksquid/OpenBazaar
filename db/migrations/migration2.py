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
        cur.execute("PRAGMA key = 'passphrase';")

        cur.execute("ALTER TABLE contracts DROP COLUMN deleted")

        print 'Downgraded'
        con.commit()

if __name__ == "__main__":

    db_path = constants.DB_PATH
    if sys.argv[1:] is not None:
        db_path = sys.argv[1:][0]
        if sys.argv[2:] is "downgrade":
            downgrade(db_path)
        else:
            upgrade(db_path)
