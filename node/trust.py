import logging

import bitcoin
import obelisk
from twisted.internet import reactor

_log = logging.getLogger('trust')

TESTNET = False


def burnaddr_from_guid(guid_hex):
    _log.debug("burnaddr_from_guid: %s", guid_hex)

    prefix = '6f' if TESTNET else '00'
    guid_full_hex = prefix + guid_hex
    _log.debug("GUID address on bitcoin net: %s", guid_full_hex)

    # Perturbate GUID to ensure unspendability through
    # near-collision resistance of SHA256 by flipping
    # the last non-checksum bit of the address.
    guid_full = guid_full_hex.decode('hex')
    guid_prt = guid_full[:-1] + chr(ord(guid_full[-1]) ^ 1)
    addr_prt = obelisk.bitcoin.EncodeBase58Check(guid_prt)
    _log.debug("Perturbated bitcoin proof-of-burn address: %s", addr_prt)

    return addr_prt


def get_unspent(addr, callback):
    _log.debug('get_unspent call')

    def get_history():
        history = bitcoin.history(addr)
        total = sum(tx['value'] for tx in history)
        callback(total)

    reactor.callFromThread(get_history)

def get_global(guid, callback):
    get_unspent(burnaddr_from_guid(guid), callback)
