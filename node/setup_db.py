import os

from pysqlcipher import dbapi2

_PASSPHRASE = 'passphrase'

# TODO: Use indexes.
# TODO: Maybe it makes sense to put tags on a different table

_SCHEMA = (
    (
        'markets',
        (
            'id INTEGER PRIMARY KEY AUTOINCREMENT',
            'key TEXT',
            'value TEXT',
            'lastPublished TEXT',
            'originallyPublished TEXT',
            'originallyPublisherID INT',
            'secret TEXT'
        )
    ),
    (
        'contracts',
        (
            'id INTEGER PRIMARY KEY AUTOINCREMENT',
            'market_id INT',
            'item_images TEXT',
            'contract_body TEXT',
            'signed_contract_body TEXT',
            'unit_price INT',
            'item_title TEXT',
            'deleted INT DEFAULT 0',
            'item_desc TEXT',
            'item_condition TEXT',
            'item_quantity_available',  # XXX: No type for this field!
            'state TEXT',
            'key TEXT',
            'FOREIGN KEY(market_id) REFERENCES markets(id)'
        )
    ),
    (
        'events',
        (
            'id INTEGER PRIMARY KEY AUTOINCREMENT',
            'market_id TEXT',
            'event_id TEXT',
            'event_description TEXT',
            'updated INT',
            'created INT'
        )
    ),
    (
        'products',
        (
            'id INTEGER PRIMARY KEY AUTOINCREMENT',
            'market_id INT',
            'productTitle TEXT',
            'productDescription TEXT',
            'productPrice INT',
            'productShippingPrice TEXT',
            'imageData BLOB',
            'productQuantity INT',
            'productTags TEXT',
            'key TEXT',
            'FOREIGN KEY(market_id) REFERENCES markets(id)'
        )
    ),
    (
        'orders',
        (
            'id INTEGER PRIMARY KEY AUTOINCREMENT',
            'order_id INT',
            'market_id INT',
            'state TEXT',
            'type TEXT',
            'item_price TEXT',
            'shipping_price TEXT',
            'address TEXT',
            'buyer_order_id TEXT',
            'notary TEXT',
            'payment_address TEXT',
            'shipping_address TEXT',
            'refund_requested INT DEFAULT 0',
            'refund_address TEXT',
            'cancelled INT DEFAULT 0',
            'buyer TEXT',
            'merchant TEXT',
            'note_for_merchant TEXT',
            'escrows TEXT',
            'text TEXT',
            'contract_key TEXT',
            'signed_contract_body TEXT',
            'updated INT',
            'created INT',
            'FOREIGN KEY(market_id) REFERENCES markets(id)'
        )
    ),
    (
        'peers',
        (
            'id INTEGER PRIMARY KEY AUTOINCREMENT',
            'uri TEXT',
            'pubkey TEXT',
            'nickname TEXT',
            # not sure if peers.market_id is actually supposed to be a TEXT
            # field or an INT with foreign key referencing the markets(id).
            'market_id TEXT',
            'guid TEXT',
            'updated INT',
            'created INT'
        )
    ),
    (
        'settings',
        (
            'id INTEGER PRIMARY KEY AUTOINCREMENT',
            'market_id INT',
            'nickname TEXT',
            'namecoin_id TEXT',
            'secret TEXT',
            'sin TEXT',
            'pubkey TEXT',
            'guid TEXT',
            'email TEXT',
            'PGPPubKey TEXT',
            'PGPPubkeyFingerprint TEXT',
            'bcAddress TEXT',
            'bitmessage TEXT',
            'storeDescription TEXT',
            'street1 TEXT',
            'street2 TEXT',
            'city TEXT',
            'stateRegion TEXT',
            'stateProvinceRegion TEXT',
            'zip TEXT',
            'country TEXT',
            'countryCode TEXT',
            'welcome TEXT',
            'recipient_name TEXT',
            'arbiter BOOLEAN',
            'arbiterDescription TEXT',
            'trustedArbiters TEXT',
            'privkey TEXT',
            'obelisk TEXT',
            'notaries TEXT',
            'notary BOOLEAN',
            'FOREIGN KEY(market_id) REFERENCES markets(id)'
        )
    ),
    (
        'escrows',
        (
            'id INTEGER PRIMARY KEY AUTOINCREMENT',
            'order_id INT',
            'address TEXT',
            'FOREIGN KEY(order_id) REFERENCES orders(id)'
        )
    ),
    (
        'reviews',
        (
            'id INTEGER PRIMARY KEY AUTOINCREMENT',
            'pubKey TEXT',
            'subject TEXT',
            'signature TEXT',
            'text TEXT',
            'rating INT'
        )
    ),
    (
        'datastore',
        (
            'id INTEGER PRIMARY KEY AUTOINCREMENT',
            'market_id INT',
            'key TEXT',
            'lastPublished TEXT',
            'originallyPublished TEXT',
            'originalPublisherID TEXT',
            'value TEXT',
            'FOREIGN KEY(market_id) REFERENCES markets(id)'
        )
    )
)


def setup_db(db_path, disable_sqlite_crypt=False):
    if os.path.isfile(db_path):
        print 'Found database; not recreating.'
        return

    with dbapi2.connect(db_path) as con:
        print 'Created database file'
        cur = con.cursor()

        if not disable_sqlite_crypt:
            # Use PRAGMA key to encrypt / decrypt database.
            cur.execute("PRAGMA key = '%s';" % _PASSPHRASE)

        for table, fields in _SCHEMA:
            cur.execute('CREATE TABLE %s (%s)' % (table, ','.join(fields)))
