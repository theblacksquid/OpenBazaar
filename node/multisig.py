import logging
import random
import re
import urllib2

import obelisk

# Create new private key:
#
# $ sx newkey > key1
#
# Show private secret:
#
#   $ cat key1 | sx wif-to-secret
#
# Show compressed public key:
#
#   $ cat key1 | sx pubkey
#
# You will need 3 keys for buyer, seller and arbitrer


class Multisig(object):
    def __init__(self, client, number_required, pubkeys):
        if number_required > len(pubkeys):
            raise Exception("number_required > len(pubkeys)")
        self.client = client
        self.number_required = number_required
        self.pubkeys = pubkeys
        self.log = logging.getLogger(self.__class__.__name__)

    @property
    def script(self):
        result = chr(80 + self.number_required)
        for pubkey in self.pubkeys:
            result += chr(33) + pubkey
        result += chr(80 + len(self.pubkeys))
        # checkmultisig
        result += "\xae"
        return result

    @property
    def address(self):

        raw_addr = obelisk.hash_160(self.script)
        return obelisk.hash_160_to_bc_address(raw_addr, addrtype=0x05)

    def create_unsigned_transaction(self, destination, finished_cb):
        def fetched(ec, history):
            if ec is not None:
                self.log.error("Error fetching history: %s", ec)
                return
            self._fetched(history, destination, finished_cb)

        self.client.fetch_history(self.address, fetched)

    def _fetched(self, history, destination, finished_cb):
        unspent = [row[:4] for row in history if row[4] is None]
        transaction = self._build_actual_tx(unspent, destination)
        finished_cb(transaction)

    @staticmethod
    def _build_actual_tx(unspent, destination):

        # Send all unspent outputs (everything in the address) minus the fee
        transaction = obelisk.Transaction()
        total_amount = 0
        for row in unspent:
            assert len(row) == 4
            outpoint = obelisk.OutPoint()
            outpoint.hash = row[0]
            outpoint.index = row[1]
            value = row[3]
            total_amount += value
            add_input(transaction, outpoint)

        # Constrain fee so we don't get negative amount to send
        fee = min(total_amount, 10000)
        send_amount = total_amount - fee
        add_output(transaction, destination, send_amount)
        return transaction

    def sign_all_inputs(self, transaction, secret):
        signatures = []
        key = obelisk.EllipticCurveKey()
        key.set_secret(secret)

        for i, _ in enumerate(transaction.inputs):
            sighash = generate_signature_hash(transaction, i, self.script)
            # Add sighash::all to end of signature.
            signature = key.sign(sighash) + "\x01"
            signatures.append(signature.encode('hex'))
        return signatures

    @staticmethod
    def make_request(*args):
        opener = urllib2.build_opener()
        opener.addheaders = [(
            'User-agent',
            'Mozilla/5.0' + str(random.randrange(1000000))
        )]
        try:
            return opener.open(*args).read().strip()
        except Exception as exc:
            try:
                stripped_exc = exc.read().strip()
            except Exception:
                stripped_exc = exc
            raise Exception(stripped_exc)

    @staticmethod
    def eligius_pushtx(transaction):
        print 'FINAL TRANSACTION: %s' % transaction
        request = Multisig.make_request(
            'http://eligius.st/~wizkid057/newstats/pushtxn.php',
            'transaction=' + transaction + '&send=Push'
        )
        strings = re.findall('string[^"]*"[^"]*"', request)
        for string in strings:
            quote = re.findall('"[^"]*"', string)[0]
            if len(quote) >= 5:
                return quote[1:-1]

    @staticmethod
    def broadcast(transaction):
        raw_tx = transaction.serialize().encode("hex")
        Multisig.eligius_pushtx(raw_tx)
        # gateway_broadcast(raw_tx)
        # bci_pushtx(raw_tx)


def add_input(transaction, prevout):
    tx_input = obelisk.TxIn()
    tx_input.previous_output.hash = prevout.hash
    tx_input.previous_output.index = prevout.index
    transaction.inputs.append(tx_input)


def add_output(transaction, address, value):
    output = obelisk.TxOut()
    output.value = value
    output.script = obelisk.output_script(address)
    transaction.outputs.append(output)


def generate_signature_hash(parent_tx, input_index, script_code):
    transaction = obelisk.copy_tx(parent_tx)
    if input_index >= len(transaction.inputs):
        return None
    for tx_input in transaction.inputs:
        tx_input.script = ""
    transaction.inputs[input_index].script = script_code
    raw_tx = transaction.serialize() + "\x01\x00\x00\x00"
    return obelisk.Hash(raw_tx)


class Escrow(object):
    def __init__(self, client, buyer_pubkey, seller_pubkey, arbit_pubkey):
        pubkeys = (buyer_pubkey, seller_pubkey, arbit_pubkey)
        self.multisig = Multisig(client, 2, pubkeys)

    # 1. BUYER: Deposit funds for seller
    @property
    def deposit_address(self):
        return self.multisig.address

    # 2. BUYER: Send unsigned transaction to seller
    def initiate(self, destination_address, finished_cb):
        self.multisig.create_unsigned_transaction(
            destination_address, finished_cb)

    # ...
    # 3. BUYER: Release funds by sending signature to seller
    def release_funds(self, transaction, secret):
        return self.multisig.sign_all_inputs(transaction, secret)

    # 4. SELLER: Claim your funds by generating a signature.
    def claim_funds(self, transaction, secret, buyer_sigs):
        seller_sigs = self.multisig.sign_all_inputs(transaction, secret)
        return Escrow.complete(transaction, buyer_sigs, seller_sigs,
                               self.multisig.script)

    @staticmethod
    def complete(tx, buyer_sigs, seller_sigs, script_code):
        for i, _ in enumerate(tx.inputs):
            sigs = (buyer_sigs[i], seller_sigs[i])
            script = "\x00"
            for sig in sigs:
                script += chr(len(sig)) + sig
            script += "\x4c"
            assert len(script_code) < 255
            script += chr(len(script_code)) + script_code
            tx.inputs[i].script = script
        return tx
