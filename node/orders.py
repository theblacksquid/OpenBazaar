import StringIO
import hashlib
import json
import logging
import qrcode
import random
import time
import urllib
from bitcoin import (
    mk_multisig_script,
    mktx,
    multisign,
    scriptaddr
)

from decimal import Decimal
from node import trust
from node.multisig import Multisig
import obelisk
from twisted.internet import reactor
import bitcoin
from node import constants
import threading



class Orders(object):
    class State(object):
        """Enum inner class. Python introduces enums in Python 3.0, but this should be good enough"""
        SENT = 'Sent'
        ACCEPTED = 'Accepted'
        BID = 'Bid'
        BUYER_PAID = 'Buyer Paid'
        NEED_TO_PAY = 'Need to Pay'
        WAITING_FOR_MERCHANT = 'Order Pending'
        NEW = 'New'
        NOTARIZED = 'Notarized'
        PAID = 'Paid'
        RECEIVED = 'Received'
        SHIPPED = 'Shipped'
        WAITING_FOR_PAYMENT = 'Waiting for Payment'
        COMPLETED = 'Completed'

    def __init__(self, transport, market_id, db_connection, gpg):
        self.transport = transport
        self.market_id = market_id
        self.log = logging.getLogger('[%s] %s' % (self.market_id, self.__class__.__name__))
        self.gpg = gpg
        self.db_connection = db_connection
        self.orders = None

        self.transport.add_callbacks([
            (
                'order',
                {
                    'cb': getattr(self, 'on_order'),
                    'validator_cb': getattr(self, 'validate_on_order')
                }
            )
        ])

    def validate_on_order(self, *data):
        self.log.debug('Validating on order message.')
        return True

    def on_order(self, msg):

        state = msg.get('state')

        if state == self.State.NEW:
            self.new_order(msg)
            return

        if state == self.State.BID:
            self.handle_bid_order(msg)
            return

        if state == self.State.NOTARIZED:
            self.log.info('You received a notarized contract')
            self.handle_notarized_order(msg)
            return

        if state == self.State.WAITING_FOR_PAYMENT:
            self.log.info('The merchant accepted your order')
            self.handle_accepted_order(msg)
            return

        if state == self.State.PAID:
            self.log.info('You received a payment notification')
            self.handle_paid_order(msg)
            return

        if state == self.State.SHIPPED:
            self.log.info('You received a shipping notification')
            self.handle_shipped_order(msg)

    @staticmethod
    def get_offer_json(raw_contract, state):

        try:
            if state == Orders.State.SENT:
                offer_data = ''.join(raw_contract.split('\n')[5:])
                sig_index = offer_data.find('- -----BEGIN PGP SIGNATURE-----', 0, len(offer_data))
                offer_data_json = offer_data[0:sig_index]
                return json.loads(offer_data_json)

            if state in [Orders.State.WAITING_FOR_PAYMENT,
                         Orders.State.NOTARIZED,
                         Orders.State.NEED_TO_PAY,
                         Orders.State.WAITING_FOR_MERCHANT,
                         Orders.State.PAID,
                         Orders.State.BUYER_PAID,
                         Orders.State.SHIPPED]:
                start_line = 8
            elif state == Orders.State.COMPLETED:
                start_line = 10
            else:
                start_line = 4

            offer_data = ''.join(raw_contract.split('\n')[start_line:])

            if state in [Orders.State.NOTARIZED,
                         Orders.State.NEED_TO_PAY,
                         Orders.State.WAITING_FOR_MERCHANT,
                         Orders.State.PAID,
                         Orders.State.BUYER_PAID,
                         Orders.State.SHIPPED]:
                index_of_seller_signature = offer_data.find('- -----BEGIN PGP SIGNATURE-----', 0, len(offer_data))
            elif state == Orders.State.COMPLETED:
                index_of_seller_signature = offer_data.find('- - -----BEGIN PGP SIGNATURE-----', 0, len(offer_data))
            else:
                index_of_seller_signature = offer_data.find('-----BEGIN PGP SIGNATURE-----', 0, len(offer_data))

            if state in (
                    Orders.State.NEED_TO_PAY,
                    Orders.State.NOTARIZED,
                    Orders.State.WAITING_FOR_MERCHANT,
                    Orders.State.BUYER_PAID,
                    Orders.State.PAID,
                    Orders.State.SHIPPED
            ):
                offer_data_json = offer_data[0:index_of_seller_signature - 2]
                offer_data_json = json.loads(offer_data_json)
            elif state in (Orders.State.WAITING_FOR_PAYMENT, Orders.State.WAITING_FOR_MERCHANT):
                offer_data_json = offer_data[0:index_of_seller_signature - 4]
                offer_data_json = json.loads(str(offer_data_json))
            elif state == Orders.State.COMPLETED:
                offer_data_json = '{' + offer_data[0:index_of_seller_signature]
                print offer_data_json
                offer_data_json = json.loads(str(offer_data_json))
            else:
                offer_data_json = '{"Seller": {' + offer_data[0:index_of_seller_signature - 2]
                offer_data_json = json.loads(str(offer_data_json))
        except ValueError as e:
            print 'JSON error: %s' % e
            return ''

        return offer_data_json

    @staticmethod
    def get_buyer_json(raw_contract, state):

        print raw_contract, state

        if state in [Orders.State.NOTARIZED, Orders.State.NEED_TO_PAY]:
            start_line = 8
        else:
            start_line = 6
        offer_data = ''.join(raw_contract.split('\n')[start_line:])
        index_of_seller_signature = offer_data.find('-----BEGIN PGP SIGNATURE-----', 0, len(offer_data))

        # Find Buyer Data in Contract
        bid_data_index = offer_data.find('"Buyer"', index_of_seller_signature, len(offer_data))
        if state in [Orders.State.SENT]:
            end_of_bid_index = offer_data.find('-----BEGIN PGP SIGNATURE', bid_data_index, len(offer_data))
        else:
            end_of_bid_index = offer_data.find('- -----BEGIN PGP SIGNATURE', bid_data_index, len(offer_data))

        buyer_data_json = "{" + offer_data[bid_data_index:end_of_bid_index]
        buyer_data_json = json.loads(buyer_data_json)

        return buyer_data_json

    @staticmethod
    def get_notary_json(raw_contract, state):

        if state in [Orders.State.NOTARIZED, Orders.State.NEED_TO_PAY]:
            start_line = 8
        else:
            start_line = 6
        offer_data = ''.join(raw_contract.split('\n')[start_line:])
        index_of_seller_signature = offer_data.find('-----BEGIN PGP SIGNATURE-----', 0, len(offer_data))

        # Find Buyer Data in Contract
        bid_data_index = offer_data.find('"Buyer"', index_of_seller_signature, len(offer_data))
        end_of_bid_index = offer_data.find('- -----BEGIN PGP SIGNATURE', bid_data_index, len(offer_data))

        # Find Notary Data in Contract
        notary_data_index = offer_data.find('"Notary"', end_of_bid_index, len(offer_data))
        end_of_notary_index = offer_data.find('-----BEGIN PGP SIGNATURE', notary_data_index, len(offer_data))
        notary_data_json = "{" + offer_data[notary_data_index:end_of_notary_index]

        notary_data_json = json.loads(notary_data_json)

        return notary_data_json

    @staticmethod
    def get_qr_code(item_title, address, total):
        if isinstance(item_title, unicode):
            item_title = item_title.encode('utf-8', 'ignore')
        qr_url = urllib.urlencode({"url": item_title})
        qr_code = qrcode.make("bitcoin:" + address + "?amount=" + str(total) + "&message=" + qr_url)
        output = StringIO.StringIO()
        qr_code.save(output, "PNG")
        qr_code = output.getvalue().encode("base64")
        output.close()
        return qr_code

    def get_order(self, order_id, by_buyer_id=False):

        notary_fee = ""

        if not by_buyer_id:
            _order = self.db_connection.select_entries("orders", {"order_id": order_id})[0]
        else:
            _order = self.db_connection.select_entries("orders", {"buyer_order_id": order_id})[0]
        total_price = 0

        offer_data_json = self.get_offer_json(_order['signed_contract_body'], _order['state'])
        buyer_data_json = self.get_buyer_json(_order['signed_contract_body'], _order['state'])

        if _order['state'] != Orders.State.SENT:
            notary_json = self.get_notary_json(_order['signed_contract_body'], _order['state'])
            notary = notary_json['Notary']['notary_GUID']
        else:
            notary = ""

        if _order['state'] in (Orders.State.NEED_TO_PAY,
                               Orders.State.NOTARIZED,
                               Orders.State.WAITING_FOR_PAYMENT,
                               Orders.State.WAITING_FOR_MERCHANT,
                               Orders.State.PAID,
                               Orders.State.BUYER_PAID,
                               Orders.State.SHIPPED,
                               Orders.State.COMPLETED):

            def cb(total):
                if self.transport.handler is not None:
                    self.transport.handler.send_to_client(None, {"type": "order_payment_amount",
                                                                 "order_id": order_id,
                                                                 "value": total})

            pubkeys = [
                offer_data_json['Seller']['seller_BTC_uncompressed_pubkey'],
                buyer_data_json['Buyer']['buyer_BTC_uncompressed_pubkey'],
                notary_json['Notary']['notary_BTC_uncompressed_pubkey']
            ]

            script = mk_multisig_script(pubkeys, 2, 3)
            payment_address = scriptaddr(script)

            def get_unspent():
                trust.get_unspent(payment_address, cb)

            threading.Thread(target=get_unspent).start()

            if 'shipping_price' in _order:
                shipping_price = _order['shipping_price'] if _order['shipping_price'] != '' else 0
            else:
                shipping_price = 0

            try:
                total_price = str((Decimal(shipping_price) + Decimal(_order['item_price']))) \
                    if 'item_price' in _order else _order['item_price']
            except Exception as exc:
                self.log.error('Probably not a number %s', exc)

            notary_fee = notary_json['Notary']['notary_fee']

        # Generate QR code
        qr_code = self.get_qr_code(offer_data_json['Contract']['item_title'], _order['address'], total_price)
        merchant_bitmessage = offer_data_json.get('Seller', '').get('seller_Bitmessage')
        buyer_bitmessage = buyer_data_json.get('Buyer', '').get('buyer_Bitmessage')

        self.log.debug('Shipping Address: %s', _order.get('shipping_address'))
        if _order.get('buyer') == self.transport.guid:
            shipping_address = self.get_shipping_address()
        else:
            shipping_address = _order.get('shipping_address')

        # Get order prototype object before storing
        order = {"id": _order['id'],
                 "state": _order.get('state'),
                 "address": _order.get('address'),
                 "buyer": _order.get('buyer'),
                 "merchant": _order.get('merchant'),
                 "order_id": _order.get('order_id'),
                 "item_quantity": _order.get('item_quantity'),
                 "item_price": _order.get('item_price'),
                 "shipping_price": _order.get('shipping_price'),
                 "shipping_address": shipping_address,
                 "total_price": total_price,
                 "merchant_bitmessage": merchant_bitmessage,
                 "buyer_bitmessage": buyer_bitmessage,
                 "notary": notary,
                 "notary_fee": notary_fee,
                 "payment_address": _order.get('payment_address'),
                 "payment_address_amount": _order.get('payment_address_amount'),
                 "qrcode": 'data:image/png;base64,' + qr_code,
                 "item_title": offer_data_json['Contract']['item_title'],
                 "item_desc": offer_data_json['Contract']['item_desc'],
                 "signed_contract_body": _order.get('signed_contract_body'),
                 "note_for_merchant": _order.get('note_for_merchant'),
                 "merchant_tx": _order.get('merchant_tx'),
                 "merchant_sigs": _order.get('merchant_sigs'),
                 "merchant_script": _order.get('merchant_script'),
                 "updated": _order.get('updated')}

        if len(offer_data_json['Contract']['item_remote_images']):
            order['item_images'] = offer_data_json['Contract']['item_remote_images']
        else:
            order['item_images'] = []

        self.log.datadump('FULL ORDER: %s', order)

        return order

    def get_orders(self, page=0, merchant=None, notarizations=False):

        if not page:
            page = 0

        orders = []

        if merchant is None:
            if notarizations:
                self.log.info('Retrieving notarizations')
                order_ids = self.db_connection.select_entries(
                    "orders",
                    {"market_id": self.market_id},
                    order_field="updated",
                    order="DESC",
                    limit=10,
                    limit_offset=page * 10,
                    select_fields=['order_id']
                )
                for result in order_ids:
                    if result['merchant'] != self.transport.guid and result['buyer'] != self.transport.guid:
                        order = self.get_order(result['order_id'])
                        orders.append(order)
                all_orders = self.db_connection.select_entries(
                    "orders",
                    {"market_id": self.market_id}
                )
                total_orders = 0
                for order in all_orders:
                    if order['merchant'] != self.transport.guid and order['buyer'] != self.transport.guid:
                        total_orders += 1
            else:
                order_ids = self.db_connection.select_entries(
                    "orders",
                    {"market_id": self.market_id},
                    order_field="updated",
                    order="DESC",
                    limit=10,
                    limit_offset=page * 10,
                    select_fields=['order_id']
                )
                for result in order_ids:
                    order = self.get_order(result['order_id'])
                    orders.append(order)
                total_orders = len(self.db_connection.select_entries(
                    "orders",
                    {"market_id": self.market_id}
                ))
        else:
            if merchant:
                order_ids = self.db_connection.select_entries(
                    "orders",
                    {"market_id": self.market_id,
                     "merchant": self.transport.guid},
                    order_field="updated",
                    order="DESC",
                    limit=10,
                    limit_offset=page * 10,
                    select_fields=['order_id']
                )
                for result in order_ids:
                    order = self.get_order(result['order_id'])
                    orders.append(order)

                all_orders = self.db_connection.select_entries(
                    "orders",
                    {"market_id": self.market_id}
                )
                total_orders = 0
                for order in all_orders:
                    if order['merchant'] == self.transport.guid:
                        total_orders += 1
            else:
                order_ids = self.db_connection.select_entries(
                    "orders",
                    {"market_id": self.market_id},
                    order_field="updated",
                    order="DESC", limit=10,
                    limit_offset=page * 10
                )
                for result in order_ids:
                    if result['buyer'] == self.transport.guid:
                        order = self.get_order(result['order_id'])
                        orders.append(order)

                all_orders = self.db_connection.select_entries(
                    "orders",
                    {"market_id": self.market_id}
                )
                total_orders = 0
                for order in all_orders:
                    if order['buyer'] == self.transport.guid:
                        total_orders += 1

        for order in orders:

            buyer = self.db_connection.select_entries("peers", {"guid": order['buyer']})
            if len(buyer) > 0:
                order['buyer_nickname'] = buyer[0]['nickname']
            merchant = self.db_connection.select_entries("peers", {"guid": order['merchant']})
            if len(merchant) > 0:
                order['merchant_nickname'] = merchant[0]['nickname']

        return {"total": total_orders, "orders": orders}

    def get_signing_key(self, contract_id):
        # Get BIP32 child signing key for this order id
        rows = self.db_connection.select_entries("keystore", {
            'contract_id': contract_id
        })

        if len(rows):
            key_id = rows[0]['id']

            settings = self.get_settings()

            wallet = bitcoin.bip32_ckd(bitcoin.bip32_master_key(settings.get('bip32_seed')), 1)
            wallet_chain = bitcoin.bip32_ckd(wallet, 0)
            bip32_identity_priv = bitcoin.bip32_ckd(wallet_chain, key_id)
            # bip32_identity_pub = bitcoin.bip32_privtopub(bip32_identity_priv)
            return bitcoin.encode_privkey(bitcoin.bip32_extract_key(bip32_identity_priv), 'wif')

        else:
            self.log.error('No keys found for that contract id: #%s', contract_id)
            return


    def ship_order(self, order, order_id, payment_address):
        self.log.info('Shipping order %s', order)

        del order['qrcode']
        del order['item_images']
        del order['total_price']
        del order['item_title']
        del order['item_desc']
        del order['buyer_bitmessage']
        del order['merchant_bitmessage']
        del order['payment_address_amount']

        order['state'] = Orders.State.SHIPPED
        order['payment_address'] = payment_address
        order['type'] = 'order'
        self.db_connection.update_entries("orders", order, {"order_id": order_id})

        # Find Seller Data in Contract
        offer_data = ''.join(order['signed_contract_body'].split('\n')[8:])
        index_of_seller_signature = offer_data.find('- - -----BEGIN PGP SIGNATURE-----', 0, len(offer_data))
        offer_data_json = offer_data[0:index_of_seller_signature]
        self.log.info('Offer Data: %s', offer_data_json)
        offer_data_json = json.loads(str(offer_data_json))

        # Find Buyer Data in Contract
        self.log.info(offer_data)
        bid_data_index = offer_data.find('"Buyer"', index_of_seller_signature, len(offer_data))
        end_of_bid_index = offer_data.find('- -----BEGIN PGP SIGNATURE', bid_data_index, len(offer_data))
        bid_data_json = "{" + offer_data[bid_data_index:end_of_bid_index]
        bid_data_json = json.loads(bid_data_json)
        self.log.info('Bid Data: %s', bid_data_json)

        # Find Notary Data in Contract
        notary_data_index = offer_data.find(
            '"Notary"', end_of_bid_index, len(offer_data)
        )
        end_of_notary_index = offer_data.find(
            '-----BEGIN PGP SIGNATURE', notary_data_index, len(offer_data)
        )
        notary_data_json = "{"
        notary_data_json += offer_data[notary_data_index:end_of_notary_index]
        notary_data_json = json.loads(notary_data_json)
        self.log.info('Notary Data: %s', notary_data_json)

        # TODO: Check to ensure the OBelisk server is listening first


        try:
            client = obelisk.ObeliskOfLightClient(
                'tcp://%s' % self.transport.settings['obelisk']
            )

            seller = offer_data_json['Seller']
            buyer = bid_data_json['Buyer']
            notary = notary_data_json['Notary']

            pubkeys = [
                seller['seller_BTC_uncompressed_pubkey'],
                buyer['buyer_BTC_uncompressed_pubkey'],
                notary['notary_BTC_uncompressed_pubkey']
            ]

            script = mk_multisig_script(pubkeys, 2, 3)
            multi_address = scriptaddr(script)

            def cb(ec, history, order):

                self.log.debug('Callback for history %s', history)

                private_key = self.get_signing_key(seller['seller_contract_id'])

                if ec is not None:
                    self.log.error("Error fetching history: %s", ec)
                    # TODO: Send error message to GUI
                    return

                # Create unsigned transaction
                unspent = [row[:4] for row in history if row[4] is None]

                # Send all unspent outputs (everything in the address) minus
                # the fee
                total_amount = 0
                inputs = []
                for row in unspent:
                    assert len(row) == 4
                    inputs.append(
                        str(row[0].encode('hex')) + ":" + str(row[1])
                    )
                    value = row[3]
                    total_amount += value

                # Constrain fee so we don't get negative amount to send
                fee = min(total_amount, 10000)
                send_amount = total_amount - fee

                payment_output = order['payment_address']
                tx = mktx(
                    inputs, [str(payment_output) + ":" + str(send_amount)]
                )

                # Sign all the inputs
                signatures = []
                for x in range(0, len(inputs)):
                    ms = multisign(tx, x, script, private_key)
                    signatures.append(ms)

                self.log.debug('Merchant TX Signatures: %s', signatures)

                order['merchant_tx'] = tx
                order['merchant_script'] = script
                order['buyer_order_id'] = buyer['buyer_order_id']
                order['merchant_sigs'] = signatures

                self.transport.send(order, bid_data_json['Buyer']['buyer_GUID'])

            def get_history():
                self.log.debug('Getting history')

                client.fetch_history(
                    multi_address,
                    lambda ec, history, order=order: cb(ec, history, order)
                )

            reactor.callFromThread(get_history)
        except Exception as e:
            self.log.debug('Error: %s', e)

    def accept_order(self, new_order):

        # TODO: Need to have a check for the vendor to agree to the order

        new_order['state'] = Orders.State.ACCEPTED
        seller = new_order['seller']
        buyer = new_order['buyer']

        new_order['escrows'] = [new_order.get('escrows')[0]]
        escrow = new_order['escrows'][0]

        # Create 2 of 3 multisig address
        self._multisig = Multisig(None, 2, [seller, buyer, escrow])

        new_order['address'] = self._multisig.address

        if len(self.db_connection.select_entries("orders", {"order_id": new_order['id']})) > 0:
            self.db_connection.update_entries("orders", {new_order}, {"order_id": new_order['id']})
        else:
            self.db_connection.insert_entry("orders", new_order)

        self.transport.send(new_order, new_order['buyer'].decode('hex'))

    def pay_order(self, new_order, order_id):  # action
        new_order['state'] = Orders.State.PAID

        self.log.debug(new_order)

        del new_order['qrcode']
        del new_order['item_images']
        del new_order['item_desc']
        del new_order['total_price']
        del new_order['item_title']
        del new_order['buyer_bitmessage']
        del new_order['merchant_bitmessage']
        del new_order['payment_address_amount']

        self.db_connection.update_entries("orders", new_order, {"order_id": order_id})

        new_order['type'] = 'order'

        self.transport.send(new_order, new_order['merchant'])

    def offer_json_from_seed_contract(self, seed_contract):
        self.log.debug('Seed Contract: %s', seed_contract)
        contract_data = ''.join(seed_contract.split('\n')[6:])
        index_of_signature = contract_data.find('- -----BEGIN PGP SIGNATURE-----', 0, len(contract_data))
        contract_data_json = contract_data[0:index_of_signature]
        self.log.debug('json %s', contract_data_json)
        return json.loads(contract_data_json)

    def send_order(self, order_id, contract, notary):  # action

        self.log.info('Verify Contract and Store in Orders Table')
        self.log.debug('%s', contract)
        contract_data_json = self.offer_json_from_seed_contract(contract)

        try:
            self.log.debug('%s', contract_data_json)
            seller_pgp = contract_data_json['Seller']['seller_PGP']
            self.gpg.import_keys(seller_pgp)

            if self.gpg.verify(contract):
                self.log.info('Verified Contract')
                self.log.info(self.get_shipping_address())
                try:
                    self.db_connection.insert_entry(
                        "orders",
                        {
                            "order_id": order_id,
                            "state": "Sent",
                            "signed_contract_body": contract,
                            "market_id": self.market_id,
                            "shipping_address": json.dumps(self.get_shipping_address()),
                            "updated": time.time(),
                            "merchant": contract_data_json['Seller']['seller_GUID'],
                            "buyer": self.transport.guid
                        }
                    )
                except Exception as exc:
                    self.log.error('Cannot update DB %s', exc)

                order_to_notary = {
                    'type': 'order',
                    'rawContract': contract,
                    'state': Orders.State.BID,
                    'v': constants.VERSION
                }

                merchant = self.transport.dht.routing_table.get_contact(
                    contract_data_json['Seller']['seller_GUID']
                )
                order_to_notary['merchantURI'] = merchant.hostname+':'+str(merchant.port)
                order_to_notary['merchantGUID'] = merchant.guid
                order_to_notary['merchantNickname'] = merchant.nickname
                order_to_notary['merchantPubkey'] = merchant.pub

                self.log.info('Sending order to %s', notary)

                # Send order to notary for approval
                self.transport.send(order_to_notary, notary)

            else:
                self.log.error('Could not verify signature of contract.')

        except Exception as exc2:
            self.log.error(exc2)

    def receive_order(self, new_order):  # action
        new_order['state'] = Orders.State.RECEIVED

        order_id = random.randint(0, 1000000)
        while len(self.db_connection.select_entries("orders", {'id': order_id})) > 0:
            order_id = random.randint(0, 1000000)

        new_order['order_id'] = order_id
        self.db_connection.insert_entry("orders", new_order)
        self.transport.send(new_order, new_order['seller'].decode('hex'))

    def get_settings(self):
        settings = self.db_connection.select_entries("settings", {"market_id": self.market_id})
        settings = settings[0]
        return settings

    def get_shipping_address(self):

        settings = self.get_settings()

        shipping_info = {
            "street1": settings['street1'],
            "street2": settings.get('street2'),
            "city": settings.get('city'),
            "stateRegion": settings.get('stateRegion'),
            "stateProvinceRegion": settings.get('stateProvinceRegion'),
            "zip": settings.get('zip'),
            "country": settings.get('country'),
            "countryCode": settings.get('countryCode'),
            "recipient_name": settings.get('recipient_name')
        }
        self.log.debug('Shipping Info: %s', shipping_info)
        return shipping_info

    def generate_new_order_pubkey(self, order_id):
        self.log.debug('Generating new pubkey for order')

        settings = self.get_settings()

        # Retrieve next key id from DB
        next_key_id = len(self.db_connection.select_entries("keystore", select_fields="id")) + 1

        # Store updated key in DB
        self.db_connection.insert_entry(
            "keystore",
            {
                'order_id': order_id
            }
        )

        # Generate new child key (m/1/0/n)
        wallet = bitcoin.bip32_ckd(bitcoin.bip32_master_key(settings.get('bip32_seed')), 1)
        wallet_chain = bitcoin.bip32_ckd(wallet, 0)
        bip32_identity_priv = bitcoin.bip32_ckd(wallet_chain, next_key_id)
        bip32_identity_pub = bitcoin.bip32_privtopub(bip32_identity_priv)
        pubkey = bitcoin.encode_pubkey(bitcoin.bip32_extract_key(bip32_identity_pub), 'hex')

        return pubkey

    def new_order(self, msg):

        self.log.debug('New Order: %s', msg)

        # Save order locally in database
        order_id = random.randint(0, 1000000)
        while (len(self.db_connection.select_entries("orders", {"id": order_id}))) > 0:
            order_id = random.randint(0, 1000000)

        seller = self.transport.dht.routing_table.get_contact(msg['sellerGUID'])

        buyer = {'Buyer': {}}
        buyer['Buyer']['buyer_GUID'] = self.transport.guid
        buyer['Buyer']['buyer_BTC_uncompressed_pubkey'] = self.generate_new_order_pubkey(order_id)
        buyer['Buyer']['buyer_pgp'] = self.transport.settings['PGPPubKey']
        buyer['Buyer']['item_quantity'] = msg.get('productQuantity')
        #buyer['Buyer']['buyer_Bitmessage'] = self.transport.settings['bitmessage']
        buyer['Buyer']['buyer_deliveryaddr'] = seller.encrypt(json.dumps(self.get_shipping_address())).encode(
            'hex')
        buyer['Buyer']['note_for_seller'] = msg['message']
        buyer['Buyer']['buyer_order_id'] = order_id
        buyer['Buyer']['buyer_refund_addr'] = msg.get('buyerRefundAddress', '')

        # Add to contract and sign
        seed_contract = msg.get('rawContract')

        gpg = self.gpg

        # Prepare contract body
        json_string = json.dumps(buyer, indent=0)
        seg_len = 52
        out_text = "\n".join(
            json_string[x:x + seg_len]
            for x in range(0, len(json_string), seg_len)
        )

        # Append new data to contract
        out_text = "%s\n%s" % (seed_contract, out_text)

        signed_data = gpg.sign(out_text, passphrase='P@ssw0rd',
                               keyid=self.transport.settings.get('PGPPubkeyFingerprint'))

        self.log.debug('Double-signed Contract: %s', signed_data)

        # Hash the contract for storage
        contract_key = hashlib.sha1(str(signed_data)).hexdigest()
        hash_value = hashlib.new('ripemd160')
        hash_value.update(contract_key)
        contract_key = hash_value.hexdigest()

        self.db_connection.update_entries(
            "orders",
            {
                'market_id': self.transport.market_id,
                'contract_key': contract_key,
                'signed_contract_body': str(signed_data),
                'shipping_address': str(json.dumps(self.get_shipping_address())),
                'state': Orders.State.NEW,
                'updated': time.time(),
                'note_for_merchant': msg['message']
            },
            {
                'order_id': order_id
            }
        )

        # Send order to seller
        self.send_order(order_id, str(signed_data), msg['notary'])

    @staticmethod
    def get_seed_contract_from_doublesigned(contract):
        start_index = contract.find('- -----BEGIN PGP SIGNED MESSAGE-----', 0, len(contract))
        end_index = contract.find('- -----END PGP SIGNATURE-----', start_index, len(contract))
        contract = contract[start_index:end_index + 29]
        return contract

    def get_json_from_doublesigned_contract(self, contract):
        start_index = contract.find("{", 0, len(contract))
        end_index = contract.find('- -----BEGIN PGP SIGNATURE-----', 0, len(contract))
        self.log.info(contract[start_index:end_index])
        return json.loads("".join(contract[start_index:end_index].split('\n')))

    def handle_bid_order(self, bid):

        self.log.info('Bid Order: %s', bid)
        new_peer = self.transport.dht.routing_table.get_contact(bid.get('merchantGUID'))

        # for x in self.transport.dht.active_peers:
        #     if x.guid == bid.get('merchantGUID'):
        #         new_peer = x
        #         break

        peerinfo = bid.get('merchantURI').split(':', 1)
        hostname, port = peerinfo[0], int(peerinfo[1])

        new_peer = self.transport.dht.add_peer(hostname,
                                               port,
                                               bid.get('merchantPubkey'),
                                               bid.get('merchantGUID'))

            # new_peer = self.transport.get_crypto_peer(bid.get('merchantGUID'),
            #                                           hostname,
            #                                           port,
            #                                           bid.get('merchantPubkey'))

        self.log.debug('NEW PEER %s', new_peer)

        # Generate unique id for this bid
        order_id = random.randint(0, 1000000)
        while len(self.db_connection.select_entries("contracts", {"id": order_id})) > 0:
            order_id = random.randint(0, 1000000)

        # Add to contract and sign
        contract = bid.get('rawContract')

        contract_stripped = "".join(contract.split('\n'))

        bidder_pgp_start_index = contract_stripped.find("buyer_pgp", 0, len(contract_stripped))
        bidder_pgp_end_index = contract_stripped.find("buyer_GUID", 0, len(contract_stripped))
        bidder_pgp = contract_stripped[bidder_pgp_start_index + 13:bidder_pgp_end_index]

        self.gpg.import_keys(bidder_pgp)
        if self.gpg.verify(contract):
            self.log.info('Sellers contract verified')

        notary_section = {}
        notary_pubkey = self.generate_new_order_pubkey(order_id)

        settings = self.get_settings()

        notary_section['Notary'] = {
            'notary_GUID': self.transport.guid,
            'notary_refund_addr': settings.get('refundAddress'),
            'notary_BTC_uncompressed_pubkey': notary_pubkey,
            'notary_pgp': settings['PGPPubKey'],
            'notary_fee': settings.get('notaryFee', '0'),
            'notary_order_id': order_id
        }

        offer_data_json = self.get_offer_json(contract, Orders.State.SENT)
        bid_data_json = self.get_buyer_json(contract, Orders.State.SENT)

        pubkeys = [
            offer_data_json['Seller']['seller_BTC_uncompressed_pubkey'],
            bid_data_json['Buyer']['buyer_BTC_uncompressed_pubkey'],
            notary_pubkey
        ]

        script = mk_multisig_script(pubkeys, 2, 3)
        multisig_address = scriptaddr(script)

        notary_section['Escrow'] = {
            'multisig_address': multisig_address,
            'redemption_script': script
        }

        self.log.debug('Notary: %s', notary_section)

        gpg = self.gpg

        # Prepare contract body
        notary_json = json.dumps(notary_section, indent=0)
        seg_len = 52

        out_text = "\n".join(
            notary_json[x:x + seg_len]
            for x in range(0, len(notary_json), seg_len)
        )

        # Append new data to contract
        out_text = "%s\n%s" % (contract, out_text)

        signed_data = gpg.sign(out_text, passphrase='P@ssw0rd',
                               keyid=self.transport.settings.get('PGPPubkeyFingerprint'))

        self.log.debug('Double-signed Contract: %s', signed_data)

        # Hash the contract for storage
        contract_key = hashlib.sha1(str(signed_data)).hexdigest()
        hash_value = hashlib.new('ripemd160')
        hash_value.update(contract_key)
        contract_key = hash_value.hexdigest()

        self.log.info('Order ID: %s', order_id)

        # Push buy order to DHT and node if available
        # self.transport.store(contract_key, str(signed_data), self.transport.guid)
        # self.update_listings_index()

        # Find Seller Data in Contract
        offer_data = ''.join(contract.split('\n')[8:])
        index_of_seller_signature = offer_data.find('- -----BEGIN PGP SIGNATURE-----', 0, len(offer_data))
        offer_data_json = "{\"Seller\": {" + offer_data[0:index_of_seller_signature]
        self.log.info('Offer Data: %s', offer_data_json)
        offer_data_json = json.loads(str(offer_data_json))

        # Find Buyer Data in Contract
        bid_data_index = offer_data.find('"Buyer"', index_of_seller_signature, len(offer_data))
        end_of_bid_index = offer_data.find('-----BEGIN PGP SIGNATURE', bid_data_index, len(offer_data))
        bid_data_json = "{" + offer_data[bid_data_index:end_of_bid_index]
        bid_data_json = json.loads(bid_data_json)
        self.log.info('Bid Data: %s', bid_data_json)

        buyer_order_id = "%s-%s" % (
            bid_data_json['Buyer']['buyer_GUID'],
            bid_data_json['Buyer']['buyer_order_id']
        )

        pubkeys = [
            offer_data_json['Seller']['seller_BTC_uncompressed_pubkey'],
            bid_data_json['Buyer']['buyer_BTC_uncompressed_pubkey'],
            notary_pubkey
        ]

        script = mk_multisig_script(pubkeys, 2, 3)
        multisig_address = scriptaddr(script)

        self.db_connection.insert_entry(
            "orders", {
                'market_id': self.transport.market_id,
                'contract_key': contract_key,
                'signed_contract_body': str(signed_data),
                'state': Orders.State.NOTARIZED,
                'buyer_order_id': buyer_order_id,
                'order_id': order_id,
                'merchant': offer_data_json['Seller']['seller_GUID'],
                'buyer': bid_data_json['Buyer']['buyer_GUID'],
                'address': multisig_address,
                'item_price': offer_data_json['Contract'].get('item_price', 0),
                'shipping_price': offer_data_json['Contract']['item_delivery'].get('shipping_price', ""),
                'note_for_merchant': bid_data_json['Buyer']['note_for_seller'],
                "updated": time.time()
            }
        )

        # Send order to seller and buyer
        self.log.info('Sending notarized contract to buyer and seller %s', bid)

        if self.transport.handler is not None:
            self.transport.handler.send_to_client(None, {"type": "order_notify",
                                                         "msg": "You just auto-notarized a contract."})

        notarized_order = {
            "type": "order",
            "state": "Notarized",
            "rawContract": str(signed_data),
            'v': constants.VERSION
        }

        if new_peer is not None:
            self.log.debug('Sending order to Merchant')
            new_peer.send(notarized_order)
        else:
            self.log.error('Cannot send release to Merchant.')

        self.transport.send(notarized_order, bid_data_json['Buyer']['buyer_GUID'])

        self.log.info('Sent notarized contract to Seller and Buyer')

    def generate_order_id(self):
        order_id = random.randint(0, 1000000)
        while self.db_connection.contracts.find({'id': order_id}).count() > 0:
            order_id = random.randint(0, 1000000)
        return order_id

    def handle_paid_order(self, msg):
        self.log.info('Entering Paid Order handling')
        self.log.debug('Paid Order %s', msg)

        offer_data = ''.join(msg['signed_contract_body'].split('\n')[8:])
        index_of_seller_signature = offer_data.find('- - -----BEGIN PGP SIGNATURE-----', 0, len(offer_data))
        offer_data_json = offer_data[0:index_of_seller_signature]
        self.log.info('Offer Data: %s', offer_data_json)
        #offer_data_json = json.loads(str(offer_data_json))

        bid_data_index = offer_data.find('"Buyer"', index_of_seller_signature, len(offer_data))
        end_of_bid_index = offer_data.find('- -----BEGIN PGP SIGNATURE', bid_data_index, len(offer_data))
        bid_data_json = "{" + offer_data[bid_data_index:end_of_bid_index]
        bid_data_json = json.loads(bid_data_json)
        self.log.info('Bid Data: %s', bid_data_json)

        buyer_order_id = "%s-%s" % (
            bid_data_json['Buyer']['buyer_GUID'],
            bid_data_json['Buyer']['buyer_order_id']
        )

        self.db_connection.update_entries(
            "orders",
            {'state': Orders.State.BUYER_PAID, 'shipping_address': json.dumps(msg['shipping_address']),
             "updated": time.time()},
            {'buyer_order_id': buyer_order_id}
        )

        if self.transport.handler is not None:
            self.transport.handler.send_to_client(None, {"type": "order_notify",
                                                         "msg": "A buyer just paid for an order."})

    def handle_shipped_order(self, msg):
        self.log.info('Entering Shipped Order handling')
        self.log.debug('Shipped Order %s', msg)

        offer_data = ''.join(msg['signed_contract_body'].split('\n')[8:])
        index_of_seller_signature = offer_data.find('- - -----BEGIN PGP SIGNATURE-----', 0, len(offer_data))
        offer_data_json = offer_data[0:index_of_seller_signature]
        offer_data_json = json.loads(str(offer_data_json))

        bid_data_index = offer_data.find('"Buyer"', index_of_seller_signature, len(offer_data))
        end_of_bid_index = offer_data.find('- -----BEGIN PGP SIGNATURE', bid_data_index, len(offer_data))
        bid_data_json = "{" + offer_data[bid_data_index:end_of_bid_index]
        bid_data_json = json.loads(bid_data_json)

        self.db_connection.update_entries(
            "orders",
            {
                'state': Orders.State.SHIPPED,
                'updated': time.time(),
                'payment_address': msg['payment_address'],
                'merchant_tx': msg['merchant_tx'],
                'merchant_sigs': json.dumps(msg['merchant_sigs']),
                'merchant_script': msg['merchant_script']
            },
            {
                'order_id': bid_data_json['Buyer']['buyer_order_id']
            }
        )

        if self.transport.handler is not None:
            self.transport.handler.send_to_client(None, {"type": "order_notify",
                                                         "msg": "The seller just shipped your order."})

    def handle_accepted_order(self, msg):
        self.db_connection.update_entries('orders', {'state': Orders.State.NEED_TO_PAY,
                                                     'updated': time.time()},
                                          {'order_id': msg.get('buyer_order_id')})

        self.transport.handler.send_to_client(None, {"type": "order_notify",
                                                     "msg": "Your order requires payment now."})


    def handle_notarized_order(self, msg):

        self.log.info('Handling notarized order')

        contract = msg['rawContract']

        # Find Seller Data in Contract
        offer_data = ''.join(contract.split('\n')[8:])
        index_of_seller_signature = offer_data.find('- - -----BEGIN PGP SIGNATURE-----', 0, len(offer_data))
        offer_data_json = offer_data[0:index_of_seller_signature]
        self.log.info('Offer Data: %s', offer_data_json)
        offer_data_json = json.loads(str(offer_data_json))

        # Find Buyer Data in Contract
        bid_data_index = offer_data.find('"Buyer"', index_of_seller_signature, len(offer_data))
        end_of_bid_index = offer_data.find('- -----BEGIN PGP SIGNATURE', bid_data_index, len(offer_data))
        bid_data_json = "{" + offer_data[bid_data_index:end_of_bid_index]
        bid_data_json = json.loads(bid_data_json)
        self.log.info('Bid Data: %s', bid_data_json)

        # Find Notary Data in Contract
        notary_data_index = offer_data.find('"Notary"', end_of_bid_index, len(offer_data))
        end_of_notary_index = offer_data.find('-----BEGIN PGP SIGNATURE', notary_data_index, len(offer_data))
        notary_data_json = "{" + offer_data[notary_data_index:end_of_notary_index]
        notary_data_json = json.loads(notary_data_json)
        self.log.info('Notary Data: %s', notary_data_json)

        # Generate multi-sig address
        pubkeys = [offer_data_json['Seller']['seller_BTC_uncompressed_pubkey'],
                   bid_data_json['Buyer']['buyer_BTC_uncompressed_pubkey'],
                   notary_data_json['Notary']['notary_BTC_uncompressed_pubkey']]
        script = mk_multisig_script(pubkeys, 2, 3)

        multisig_address = scriptaddr(script)

        seller_guid = offer_data_json['Seller']['seller_GUID']

        order_id = bid_data_json['Buyer']['buyer_order_id']

        contract_key = hashlib.sha1(str(contract)).hexdigest()
        hash_value = hashlib.new('ripemd160')
        hash_value.update(contract_key)
        contract_key = hash_value.hexdigest()

        if seller_guid == self.transport.guid:
            self.log.info('I am the seller!')

            state = 'Waiting for Payment'

            merchant_order_id = random.randint(0, 1000000)
            while len(self.db_connection.select_entries("orders", {"id": order_id})) > 0:
                merchant_order_id = random.randint(0, 1000000)

            buyer_id = "%s-%s" % (
                bid_data_json['Buyer']['buyer_GUID'],
                bid_data_json['Buyer']['buyer_order_id']
            )

            shipping_address = bid_data_json['Buyer'].get('buyer_deliveryaddr', None)
            print 'address:', shipping_address
            # Decrypt shipping address
            if shipping_address and self.transport.cryptor:
                shipping_address = shipping_address.decode('hex')
                shipping_address = self.transport.cryptor.decrypt(shipping_address)
                shipping_address = shipping_address.decode('zlib')
            else:
                shipping_address = ''

            self.db_connection.insert_entry(
                "orders",
                {
                    'market_id': self.transport.market_id,
                    'contract_key': contract_key,
                    'order_id': merchant_order_id,
                    'signed_contract_body': str(contract),
                    'state': state,
                    'buyer_order_id': buyer_id,
                    'merchant': offer_data_json['Seller']['seller_GUID'],
                    'buyer': bid_data_json['Buyer']['buyer_GUID'],
                    'notary': notary_data_json['Notary']['notary_GUID'],
                    'address': multisig_address,
                    'shipping_address': shipping_address,
                    'item_price': offer_data_json['Contract'].get('item_price', 0),
                    'shipping_price': offer_data_json['Contract']['item_delivery'].get('shipping_price', 0),
                    'note_for_merchant': bid_data_json['Buyer']['note_for_seller'],
                    "updated": time.time()
                }
            )

            if self.transport.handler:
                self.transport.handler.send_to_client(None, {
                    "type": "order_notify",
                    "msg": "You just received a new order."
                })

            # Send notice to order receipt
            self.transport.send({
                'type': 'order',
                'state': Orders.State.WAITING_FOR_PAYMENT,
                'buyer_order_id': bid_data_json['Buyer']['buyer_order_id'],
                'v': constants.VERSION
            }, bid_data_json['Buyer']['buyer_GUID'])

        else:
            self.log.info('I am the buyer')
            state = Orders.State.WAITING_FOR_MERCHANT

            self.db_connection.update_entries(
                "orders",
                {
                    'market_id': self.transport.market_id,
                    'contract_key': contract_key,
                    'signed_contract_body': str(contract),
                    'state': state,
                    'merchant': offer_data_json['Seller']['seller_GUID'],
                    'buyer': bid_data_json['Buyer']['buyer_GUID'],
                    'notary': notary_data_json['Notary']['notary_GUID'],
                    'address': multisig_address,
                    'shipping_address': json.dumps(self.get_shipping_address()),
                    'item_price': offer_data_json['Contract'].get('item_price', 0),
                    'shipping_price': offer_data_json['Contract']['item_delivery'].get('shipping_price', ''),
                    'note_for_merchant': bid_data_json['Buyer']['note_for_seller'],
                    "updated": time.time()
                },
                {
                    'order_id': order_id
                }
            )

            self.transport.handler.send_to_client(None, {"type": "order_notify",
                                                         "msg": "Your order has been notarized."})
