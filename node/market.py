"""
This module manages all market related activities
"""
from base64 import b64decode, b64encode
import gnupg
import hashlib
import json
import logging
from PIL import Image, ImageOps
import random
from StringIO import StringIO
import traceback
import re
from tornado import ioloop

from node import constants
from node.data_uri import DataURI
from node.orders import Orders
from node.protocol import proto_page, query_page
import bitcoin
import time


class Market(object):
    """This class manages the active market for the application"""

    def __init__(self, transport, db_connection):
        """Class constructor defines the basic attributes and callbacks

        Attributes:
          transport (CryptoTransportLayer): Transport layer
              for messaging between nodes.
          dht (DHT): For storage across the network (distributed hash table).
          market_id (int): Indicates which local market we're working with.
          peers: Active peers/nodes on the P2P network
          db_connection: Database ORM handler
          orders: Orders for goods from database
          pages:
          mypage:
          signature: Digitial signature
          nickname: Short name of the node - a synonym for GUID
          log: Log handler
          settings: Local settings
          gpg: Public PGP key class
        """

        # Current
        self.transport = transport
        self.dht = transport.dht
        self.market_id = transport.market_id
        self.peers = self.dht.get_active_peers()
        self.db_connection = db_connection

        self.pages = {}
        self.mypage = None
        self.signature = None
        self.nickname = ""
        self.log = logging.getLogger(
            "[%s] %s" % (self.market_id, self.__class__.__name__))
        self.settings = self.transport.settings

        self.gpg = gnupg.GPG()

        self.all_messages = (
            'query_myorders',
            'peer',
            'query_page',
            'query_listing',
            'query_listings',
            'inbox_message'
        )

        # Register callbacks for incoming events
        self.transport.add_callbacks([
            (
                msg,
                {
                    'cb': getattr(self, 'on_%s' % msg),
                    'validator_cb': getattr(self, 'validate_on_%s' % msg)
                }
            )
            for msg in self.all_messages
        ])

        self.nickname = self.settings.get('nickname', '')

        # Recurring republish for DHT
        self.start_listing_republisher()

        self.orders = Orders(transport, self.market_id, db_connection, self.gpg)

    def start_listing_republisher(self):
        # Periodically refresh buckets
        loop = ioloop.IOLoop.instance()
        refresh_cb = ioloop.PeriodicCallback(self.dht._refresh_node,
                                             constants.REFRESH_TIMEOUT,
                                             io_loop=loop)
        refresh_cb.start()

    def disable_welcome_screen(self):
        """This just flags the welcome screen to not show on startup"""
        self.db_connection.update_entries(
            "settings",
            {"welcome": "disable"},
            {'market_id': self.transport.market_id}
        )
        self.settings['welcome'] = 'disable'

    def private_key(self):
        """Returns private key for local node"""
        return self.settings['secret']

    def on_listing_results(self, results):
        """Add incoming information to log"""
        self.log.debug("Listings %s", results)

    @staticmethod
    def process_contract_image(image):
        """Get image from web client for use on server side"""
        uri = DataURI(image)
        image_data = uri.data
        # mime_type = uri.mimetype
        charset = uri.charset

        image = Image.open(StringIO(image_data))
        cropped_image = ImageOps.fit(image, (200, 200), centering=(0.5, 0.5))
        data = StringIO()
        cropped_image.save(data, format='PNG', quality=75, optimize=True)
        new_uri = DataURI.make(
            'image/png',
            charset=charset,
            base64=True,
            data=data.getvalue())
        data.close()

        return new_uri

    @staticmethod
    def get_contract_id():
        """Choice of number of new contract to prevent guessing the sequence of contract' id.
           Other members not to be able to extract order volume from peers by viewing the latest order id.

        """
        return random.randint(0, 1000000)

    @staticmethod
    def linebreak_signing_data(data):
        """For signing with gpg, the width of the text is formatted 52 characters long"""
        json_string = json.dumps(data, indent=0)
        seg_len = 52
        out_text = "\n".join(
            json_string[x:x + seg_len]
            for x in range(0, len(json_string), seg_len)
        )
        return out_text

    @staticmethod
    def generate_contract_key(signed_contract):
        """Generate digest of digital signature or digest key"""
        contract_hash = hashlib.sha1(str(signed_contract)).hexdigest()
        hash_value = hashlib.new('ripemd160')
        hash_value.update(contract_hash)
        return hash_value.hexdigest()

    def save_contract_to_db(self, contract_id, body, signed_body, key, updating_contract=False):
        """Insert contract to database"""
        if not updating_contract:
            self.db_connection.insert_entry(
                "contracts",
                {
                    "id": contract_id,
                    "market_id": self.transport.market_id,
                    "contract_body": json.dumps(body),
                    "signed_contract_body": str(signed_body),
                    "state": "seed",
                    "deleted": 0,
                    "key": key
                }
            )
        else:
            self.db_connection.update_entries(
                "contracts",
                {
                    "market_id": self.transport.market_id,
                    "contract_body": json.dumps(body),
                    "signed_contract_body": str(signed_body),
                    "state": "seed",
                    "deleted": 0,
                    "key": key
                },
                {
                    "id": contract_id
                }
            )

    def update_keywords_on_network(self, key, keywords):
        """Update keyword for sharing it with nodes"""
        for keyword in keywords:
            keyword = keyword.upper()
            hash_value = hashlib.new('ripemd160')
            keyword_key = 'keyword-%s' % keyword
            hash_value.update(keyword_key.encode('utf-8'))
            keyword_key = hash_value.hexdigest()

            self.log.debug("Sending keyword to network: %s", keyword_key)

            self.transport.store(
                keyword_key,
                json.dumps({
                    'keyword_index_add': {
                        "guid": self.transport.guid,
                        "key": key
                    }
                }),
                self.transport.guid
            )

    def refund_recipient(self, recipient_id, order_id):
        self.log.debug('Refunding recipient')

    def generate_new_pubkey(self, contract_id):
        self.log.debug('Generating new pubkey for contract')

        # Retrieve next key id from DB
        next_key_id = len(self.db_connection.select_entries("keystore", select_fields="id")) + 1

        # Store updated key in DB
        self.db_connection.insert_entry(
            "keystore",
            {
                'contract_id': contract_id
            }
        )

        # Generate new child key (m/1/0/n)
        wallet = bitcoin.bip32_ckd(bitcoin.bip32_master_key(self.settings.get('bip32_seed')), 1)
        wallet_chain = bitcoin.bip32_ckd(wallet, 0)
        bip32_identity_priv = bitcoin.bip32_ckd(wallet_chain, next_key_id)
        bip32_identity_pub = bitcoin.bip32_privtopub(bip32_identity_priv)
        pubkey = bitcoin.encode_pubkey(bitcoin.bip32_extract_key(bip32_identity_pub), 'hex')

        return pubkey

    def save_contract(self, contract, contract_id=None):
        """Sign, store contract in the database and update the keyword in the
        network
        """
        updating_contract = True if contract_id else False

        if not contract_id:
            contract_id = self.get_contract_id()

        # Refresh market settings
        self.settings = self.get_settings()

        seller = contract['Seller']
        seller['seller_PGP'] = self.gpg.export_keys(self.settings['PGPPubkeyFingerprint'])
        seller['seller_BTC_uncompressed_pubkey'] = self.generate_new_pubkey(contract_id)
        seller['seller_contract_id'] = contract_id
        seller['seller_GUID'] = self.settings['guid']
        seller['seller_Bitmessage'] = self.settings['bitmessage']
        seller['seller_refund_addr'] = self.settings['refundAddress']

        # Process and crop thumbs for images
        if 'item_images' in contract['Contract']:
            if 'image1' in contract['Contract']['item_images']:
                img = contract['Contract']['item_images']['image1']
                new_uri = self.process_contract_image(img)
                contract['Contract']['item_images'] = new_uri
        else:
            self.log.debug('No image for contract')

        # Line break the signing data
        out_text = self.linebreak_signing_data(contract)

        # Sign the contract
        signed_data = self.gpg.sign(
            out_text,
            passphrase='P@ssw0rd',
            keyid=self.settings.get('PGPPubkeyFingerprint'))

        # Save contract to DHT
        contract_key = self.generate_contract_key(signed_data)

        # Store contract in database
        self.save_contract_to_db(contract_id, contract, signed_data, contract_key, updating_contract)

        # Store listing
        self.transport.store(
            contract_key,
            str(signed_data),
            self.transport.guid)

        self.update_listings_index()

        # If keywords are present
        keywords = contract['Contract']['item_keywords']
        self.update_keywords_on_network(contract_key, keywords)

    def shipping_address(self):
        """Get shipping address"""
        settings = self.get_settings()
        shipping_address = {
            'recipient_name': settings.get('recipient_name'),
            'street1': settings.get('street1'),
            'street2': settings.get('street2'),
            'city': settings.get('city'),
            'stateRegion': settings.get('stateRegion'),
            'stateProvinceRegion': settings.get('stateProvinceRegion'),
            'zip': settings.get('zip'),
            'country': settings.get('country'),
            'countryCode': settings.get('countryCode'),
        }
        return shipping_address

    def add_trusted_notary(self, guid, nickname=""):
        """Add selected trusted notary to the local list"""
        self.log.debug("%s %s", guid, nickname)

        self.settings = self.get_settings()
        notaries = self.settings.get('notaries')

        self.log.debug("Notaries: %s", notaries)

        if not notaries:
            notaries = []
        elif not isinstance(notaries, list):
            notaries = json.loads(notaries)
        else:
            notaries = notaries

        for notary in notaries:
            self.log.info(notary)
            if notary.get('guid') == guid:
                if notary.get('nickname') != nickname:
                    notary['nickname'] = nickname
                    notary['idx'] = notary
                    self.settings['notaries'] = notaries
                return

        notaries.append({"guid": guid, "nickname": nickname})
        self.settings['notaries'] = json.dumps(notaries)

        if 'btc_pubkey' in self.settings:
            del self.settings['btc_pubkey']

        self.db_connection.update_entries(
            "settings",
            self.settings,
            {'market_id': self.transport.market_id}
        )

    def remove_trusted_notary(self, guid):
        """Not trusted to selected notary. Dlete notary from the local list"""
        self.log.debug('Notaries %s', self.settings)
        self.settings = self.get_settings()
        notaries = self.settings.get('notaries')

        for idx, notary in enumerate(notaries):

            if notary.get('guid') == guid:
                del notaries[idx]

        self.settings['notaries'] = json.dumps(notaries)

        self.db_connection.update_entries(
            "settings",
            self.settings,
            {'market_id': self.transport.market_id}
        )

    def republish_contracts(self):
        """Update information about contracts in the network"""
        listings = self.db_connection.select_entries("contracts", {"deleted": 0})
        for listing in listings:
            self.transport.store(
                listing['key'],
                listing.get('signed_contract_body'),
                self.transport.guid
            )

            # Push keyword index out again
            contract_body = json.loads(listing.get('contract_body'))
            self.log.debug('Listing: %s', listing)
            self.log.debug('Contract: %s', contract_body)

            contract = contract_body.get('Contract')

            keywords = contract.get('item_keywords') if contract is not None else []
            self.log.debug('Found keywords to republish: %s', keywords)

            self.update_keywords_on_network(listing.get('key'), keywords)

        # Updating the DHT index of your store's listings
        self.update_listings_index()

    def get_notaries(self):
        """Getting notaries and exchange contact in network"""
        self.log.debug('Retrieving trusted notaries')
        notaries = []
        settings = self.get_settings()
        self.log.debug(settings.get('notaries'))

        self.log.debug('Notaries Online: %s', notaries)
        return notaries

        # return settings['notaries']

    @staticmethod
    def valid_guid(guid):
        """Checking guid - global user ID secure hash of the public key"""
        return len(guid) == 40 and int(guid, 16)

    def republish_listing(self, msg):
        """Update information about products in the network"""
        listing_id = msg.get('productID')
        listing = self.db_connection.select_entries("products", {"id": listing_id})

        if listing:
            listing = listing[0]
        else:
            return

        listing_key = listing['key']

        self.transport.store(
            listing_key,
            listing.get('signed_contract_body'),
            self.transport.guid
        )
        # Updating the DHT index of your store's listings
        self.update_listings_index()

    def update_listings_index(self):
        """This method is responsible for updating the DHT index of your
           store's listings. There is a dictionary in the DHT that has an
           array of your listing IDs. This updates that listing index in
           the DHT, simply put.

        """
        # Store to marketplace listing index
        contract_index_key = hashlib.sha1('contracts-%s' %
                                          self.transport.guid).hexdigest()
        hashvalue = hashlib.new('ripemd160')
        hashvalue.update(contract_index_key)
        contract_index_key = hashvalue.hexdigest()

        # Calculate index of contracts
        contract_ids = self.db_connection.select_entries(
            "contracts",
            {"market_id": self.transport.market_id, "deleted": 0}
        )
        my_contracts = []
        for contract_id in contract_ids:
            my_contracts.append(contract_id['key'])

        self.log.debug("My Contracts: %s", my_contracts)

        # Sign listing index for validation and tamper resistance
        data_string = str({'guid': self.transport.guid,
                           'contracts': my_contracts})
        signature = self.transport.cryptor.sign(data_string)

        value = {
            'signature': signature.encode('hex'),
            'data': {
                'guid': self.transport.guid,
                'contracts': my_contracts
            }
        }

        # Pass off to thread to keep GUI snappy
        self.transport.store(
            contract_index_key,
            value,
            self.transport.guid
        )

    def remove_contract(self, msg):
        """Remove contract and update own list of contracts keywords"""
        self.log.info("Removing contract: %s", msg)

        # Remove from DHT keyword indices
        self.remove_from_keyword_indexes(msg['contract_id'])

        self.db_connection.update_entries(
            "contracts",
            {"deleted": 1},
            {"id": msg["contract_id"]}
        )
        # Updating the DHT index of your store's listings
        self.update_listings_index()

    def remove_from_keyword_indexes(self, contract_id):
        """Remove from DHT keyword indices"""
        contract = self.db_connection.select_entries("contracts", {"id": contract_id})[0]
        contract_key = contract['key']

        contract = json.loads(contract['contract_body'])
        contract_keywords = contract['Contract']['item_keywords']
        self.log.debug('Keywords to remove: %s', contract_keywords)

        for keyword in contract_keywords:
            # Remove keyword from index
            hash_value = hashlib.new('ripemd160')
            keyword_key = 'keyword-%s' % keyword
            hash_value.update(keyword_key.encode('utf-8'))
            keyword_key = hash_value.hexdigest()

            self.transport.store(
                keyword_key,
                json.dumps({
                    'keyword_index_remove': {
                        "guid": self.transport.guid,
                        "key": contract_key
                    }
                }),
                self.transport.guid
            )

    def get_messages(self):
        """Get messages listing for market"""
        self.log.info(
            "Listing messages for market: %s", self.transport.market_id)
        settings = self.get_settings()
        try:
            # Request all messages for our address
            if self.transport.bitmessage_api:
                inboxmsgs = json.loads(

                    self.transport.bitmessage_api.getInboxMessagesByReceiver(
                        settings['bitmessage']))
                for message in inboxmsgs['inboxMessages']:
                    # Base64 decode subject and content
                    message['subject'] = b64decode(message['subject'])
                    message['message'] = b64decode(message['message'])
                    # TODO: Augment with market, if available

                return {"messages": inboxmsgs}
        except Exception as exc:
            self.log.error("Failed to get inbox messages: %s", exc)
            self.log.error(traceback.format_exc())
            return {}

    def send_message(self, msg):
        """Send message for market by bitmessage"""
        self.log.info(
            "Sending message for market: %s", self.transport.market_id)
        settings = self.get_settings()
        try:
            # Base64 decode subject and content
            self.log.info("Encoding message: %s", msg)
            subject = b64encode(msg['subject'])
            body = b64encode(msg['body'])
            result = self.transport.bitmessage_api.sendMessage(
                msg['to'], settings['bitmessage'], subject, body
            )
            self.log.info("Send message result: %s", result)
            return {}
        except Exception as exc:
            self.log.error("Failed to send message: %s", exc)
            self.log.error(traceback.format_exc())
            return {}

    def send_inbox_message(self, msg):
        """Send message for market internally"""
        self.log.info(
            "Sending message for market: %s", self.transport.market_id)
        self.log.debug('Inbox Message: %s', msg)

        # Save message to DB
        message_id = hashlib.sha256()
        message_id.update('%d%s%s' % (time.time(), self.transport.guid, msg.get('recipient')))

        self.db_connection.insert_entry('inbox', {
            'created': time.time(),
            'subject': msg.get('subject', ''),
            'body': msg.get('body', ''),
            'sender_guid': self.transport.guid,
            'recipient_guid': msg.get('recipient', ''),
            'message_id': message_id.hexdigest()
        })

        # Send to peer
        peer = self.dht.routing_table.get_contact(msg.get('recipient'))
        if peer:
            peer.send({
                'type': 'inbox_message',
                'subject': msg.get('subject'),
                'body': msg.get('body'),
                'sender_guid': self.transport.guid,
                'created': time.time(),
                'message_id': message_id.hexdigest(),
                'v': constants.VERSION
            })

    def get_inbox_messages(self):
        """Get messages from inbox table"""
        messages = self.db_connection.select_entries("inbox", {
            'recipient_guid': self.transport.guid
        }, order='DESC')
        return messages

    def get_inbox_sent_messages(self):
        """Get messages from inbox table"""
        messages = self.db_connection.select_entries("inbox", {
            'sender_guid': self.transport.guid
        }, order='DESC')
        return messages

    def get_contract_by_id(self, contract_id):
        """Get Contract by ID"""
        contract = self.db_connection.select_entries(
            "contracts",
            {
                "deleted": 0,
                "key": contract_id
            }
        )
        if len(contract) == 1:
            return contract
        else:
            return None

    def get_contracts(self, page=0, remote=False):
        """Select contracts for market from database"""
        self.log.info(
            "Getting contracts for market: %s", self.transport.market_id)
        contracts = self.db_connection.select_entries(
            "contracts",
            {"market_id": self.transport.market_id, "deleted": 0},
            limit=10,
            limit_offset=(page * 10)
        )

        my_contracts = []

        for contract in contracts:
            try:
                contract_body = json.loads(u"%s" % contract['contract_body'])
            except (KeyError, ValueError) as err:
                self.log.error('Problem loading the contract body JSON: %s',
                               err.message)
                continue
            try:
                contract_field = contract_body['Contract']
            except KeyError:
                self.log.error('Contract field not found in contract_body')
                continue
            except TypeError:
                self.log.error('Malformed contract_body: %s',
                               str(contract_body))
                continue
            item_price = contract_field.get('item_price')
            if item_price is None or item_price < 0:
                item_price = 0
            try:
                item_delivery = contract_field['item_delivery']
            except KeyError:
                self.log.error('item_delivery not found in Contract field')
                continue
            except TypeError:
                self.log.error('Malformed Contract field: %s',
                               str(contract_field))
                continue
            shipping_price = item_delivery.get('shipping_price')
            if shipping_price is None or shipping_price < 0:
                shipping_price = 0

            my_contracts.append({
                'key': contract.get('key', ''),
                'id': contract.get('id', ''),
                'item_images': contract_field.get('item_images'),
                'signed_contract_body': contract.get('signed_contract_body', ''),
                'contract_body': contract_body,
                'unit_price': item_price,
                'deleted': contract.get('deleted'),
                'shipping_price': shipping_price,
                'item_title': contract_field.get('item_title'),
                'item_desc': contract_field.get('item_desc'),
                'item_condition': contract_field.get('item_condition'),
                'item_quantity_available': contract_field.get('item_quantity'),
                'item_remote_images': contract_field.get('item_remote_images')
            })

        return {
            "contracts": my_contracts, "page": page,
            "total_contracts": len(
                self.db_connection.select_entries("contracts", {"deleted": "0"}))}

    def undo_remove_contract(self, contract_id):
        """Restore removed contract"""
        self.log.info("Undo remove contract: %s", contract_id)
        self.db_connection.update_entries(
            "contracts",
            {"deleted": "0"},
            {"market_id": self.transport.market_id.replace("'", "''"), "id": contract_id}
        )

    def save_settings(self, msg):
        """Update local settings"""

        # Check for any updates to arbiter or notary status to push to the DHT
        if 'notary' in msg:
            # Generate notary index key
            hash_value = hashlib.new('ripemd160')
            hash_value.update('notary-index')
            key = hash_value.hexdigest()

            if msg['notary']:
                self.log.info('Letting the network know you are now a notary')
                data = json.dumps({'notary_index_add': self.transport.guid})
                self.transport.store(key, data, self.transport.guid)
            else:
                self.log.info('Letting the network know you are not a notary')
                data = json.dumps({'notary_index_remove': self.transport.guid})
                self.transport.store(key, data, self.transport.guid)

        # Validate that the namecoin id received is well formed
        self.log.debug(msg)
        if not re.match(r'^[a-z0-9\-]{1,39}$', msg['namecoin_id']):
            msg['namecoin_id'] = ''

        # Update nickname and namecoin id
        self.transport.nickname = msg['nickname']
        self.transport.namecoin_id = msg['namecoin_id']

        if 'burnAmount' in msg:
            del msg['burnAmount']
        if 'burnAddr' in msg:
            del msg['burnAddr']

        msg['notaries'] = json.dumps(msg['notaries'])

        # Update local settings
        self.db_connection.update_entries(
            "settings",
            msg,
            {'market_id': self.transport.market_id}
        )

    def get_settings(self):
        """Get local settings"""

        self.log.info(
            "Getting settings info for Market %s", self.transport.market_id)
        settings = self.db_connection.get_or_create(
            "settings",
            {"market_id": self.transport.market_id})

        if settings['arbiter'] == 1:
            settings['arbiter'] = True
        if settings['notary'] == 1:
            settings['notary'] = True

        settings['notaries'] = json.loads(settings['notaries']) if settings['notaries'] else []
        for i, notary in enumerate(settings['notaries']):
            guid = notary.get('guid')
            if guid:
                peer = self.dht.routing_table.get_contact(guid)
                if peer:
                    settings['notaries'][i]['online'] = True
                else:
                    settings['notaries'][i]['online'] = False

        settings['trustedArbiters'] = json.loads(settings['trustedArbiters']) if settings['trustedArbiters'] else []

        settings['secret'] = settings.get('secret')

        if settings:
            return settings
        else:
            return {}

    def query_page(self, find_guid, callback=lambda msg: None):
        """Query network for node"""
        self.log.info("Searching network for node: %s", find_guid)
        msg = query_page(find_guid)
        msg['hostname'] = self.transport.hostname
        msg['port'] = self.transport.port
        msg['nat_type'] = self.transport.nat_type
        msg['senderGUID'] = self.transport.guid
        msg['sin'] = self.transport.sin
        msg['pubkey'] = self.transport.pubkey

        self.transport.send(msg, find_guid, callback)

    def validate_on_query_page(self, *data):
        self.log.debug('Validating on query page message.')
        keys = ("senderGUID", "hostname", "port", "pubkey", "senderNick")
        return all(k in data[0] for k in keys)

    def on_query_page(self, msg):
        """Return your page info if someone requests it on the network"""
        self.log.info("Someone is querying for your page")
        settings = []
        settings = self.get_settings()

        peer = self.dht.routing_table.get_contact(msg['senderGUID'])
        if not peer:
            peer = self.transport.dht.add_peer(
                msg['hostname'],
                msg['port'],
                msg['pubkey'],
                msg['guid'],
                msg['senderNick'],
                msg['nat_type'],
                msg['avatar_url']
            )

        def send_page_query():
            """Send a request for the local identity page"""

            self.log.debug('Sending page')

            peer.send(proto_page(
                self.transport.uri,
                self.transport.pubkey,
                self.transport.guid,
                settings['storeDescription'],
                self.signature,
                settings['nickname'],
                settings.get('PGPPubKey', ''),
                settings.get('email', ''),
                settings.get('bitmessage', ''),
                settings.get('arbiter', ''),
                settings.get('notary', False),
                settings.get('notaryDescription', ''),
                settings.get('notaryFee', 0),
                settings.get('arbiterDescription', ''),
                self.transport.sin,
                settings['homepage'],
                settings['avatar_url']))

        if peer:
            send_page_query()
        else:
            self.log.error('Could not find peer to send page to.')

    def validate_on_query_myorders(self, *data):
        self.log.debug('Validating on query myorders message.')
        return True

    def on_query_myorders(self, peer):
        """Run if someone is querying for your page"""
        self.log.debug("Someone is querying for your page: %s", peer)

    def validate_on_inbox_message(self, *data):
        self.log.debug('Validating on inbox message.')
        return True

    def on_inbox_message(self, msg):
        """Accept incoming inbox message"""
        self.log.debug('Inbox Message: %s', msg)

        # Save to DB
        self.db_connection.insert_entry(
            'inbox',
            {
                'subject': msg.get('subject', ''),
                'body': msg.get('body', ''),
                'sender_guid': msg.get('sender_guid', ''),
                'recipient_guid': self.transport.guid,
                'message_id': msg.get('message_id', ''),
                'parent_id': msg.get('parent_id', ''),
                'created': msg.get('created', ''),
                'received': time.time()
            }
        )

        # Send to client
        if self.transport.handler:
            self.transport.handler.send_to_client(None, {
                "type": "inbox_notify",
                "msg": msg
            })

            messages = self.get_inbox_messages()
            self.transport.handler.send_to_client(None, {"type": "inbox_messages", "messages": messages})

            self.check_inbox_count()

    def check_inbox_count(self):
        messages = self.db_connection.select_entries(
            "inbox",
            {
                "recipient_guid": self.transport.guid
            },
            select_fields="id"
        )

        if self.transport.handler:
            self.transport.handler.send_to_client(
                None,
                {"type": "inbox_count", "count": len(messages)}
            )

    def validate_on_query_listing(self, *data):
        self.log.debug('Validating on query listing message.')
        return True

    def on_query_listing(self, msg):
        """Run if someone is querying for a specific listing ID"""
        sender_guid = msg.get('senderGUID')
        listing_id = msg.get('listing_id')

        listing = self.get_contract_by_id(listing_id)
        if listing:
            self.transport.send(
                {
                    "type": "query_listing_result",
                    "v": constants.VERSION,
                    "listing": listing
                },
                sender_guid
            )

    def validate_on_query_listings(self, *data):
        self.log.debug('Validating on query listings message.')
        return "senderGUID" in data[0]

    def on_query_listings(self, peer, page=0):
        """Run if someone is querying your listings"""
        self.log.info("Someone is querying your listings: %s", peer)
        contracts = self.get_contracts(page, remote=True)

        if len(contracts['contracts']) == 0:
            self.transport.send(
                {
                    "type": "no_listing_result",
                    'v': constants.VERSION
                },
                peer['senderGUID'])
            return
        else:
            for contract in contracts['contracts']:
                contract = contract
                contract['type'] = "listing_result"
                self.transport.send(contract, peer['senderGUID'])
                self.log.info('Send listing result')

    def validate_on_peer(self, *data):
        self.log.debug('Validating on peer message.')
        return True

    def on_peer(self, peer):
        pass

    def release_funds_to_recipient(self, buyer_order_id, tx, script, signatures, guid, buyer_id, refund=0):
        """Send TX to merchant"""
        self.log.debug("Release funds to merchant: %s %s %s %s", buyer_order_id, tx, signatures, guid)
        self.transport.send(
            {
                'type': 'release_funds_tx',
                'tx': tx,
                'script': script,
                'buyer_order_id': buyer_order_id,
                'signatures': signatures,
                'buyer_id': buyer_id,
                'refund': refund,
                'v': constants.VERSION
            },
            guid
        )
        self.log.debug('TX sent to merchant')
