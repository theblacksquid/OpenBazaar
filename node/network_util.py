import sys
from urlparse import urlparse
import re
import logging
import IPy
import requests
import rfc3986
import stun


# List taken from natvpn project and tested manually.
# NOTE: This needs periodic updating.
_STUN_SERVERS = (
    'stun.ekiga.net',
    'stun.ideasip.com',
    'stun.voiparound.com',
    'stun.voipbuster.com',
    'stun.voipstunt.com',
    'stun.voxgratia.org'
)

IP_DETECT_SITE = 'https://icanhazip.com'

def set_stun_servers(servers=_STUN_SERVERS):
    """Manually set the list of good STUN servers."""
    stun.stun_servers_list = tuple(servers)


def get_NAT_status(stun_host=None):
    """
    Given a server hostname, initiate a STUN request to it;
    and return the response in the form of a dict.
    """
    response = stun.get_ip_info(stun_host=stun_host, source_port=0)
    return {'nat_type': response[0],
            'external_ip': response[1],
            'external_port': response[2]}


def is_loopback_addr(addr):
    return addr.startswith("127.0.0.") or addr == 'localhost'


def str_to_ipy(addr):
    """Convert an address to an IPy.IP object or None if unsuccessful."""
    try:
        return IPy.IP(addr)
    except ValueError as err:
        print 'Not IP address:', err
    return None


def is_private_ip_address(addr):

    if is_loopback_addr(addr):
        return True

    ip_address = str_to_ipy(addr)

    if ip_address and ip_address.iptype() == 'PRIVATE':
        return True

    return False


def get_my_ip(ip_site=IP_DETECT_SITE):
    try:
        request = requests.get(ip_site)
        return request.text.strip()
    except (AttributeError, requests.RequestException) as exc:
        print '[Requests] error: %s' % exc
    return None


def is_ipv6_address(ip):
    return IPy.IP(ip).version() == 6


def get_peer_url(address, port, protocol='tcp'):
    """
    Return a URL.

    @param address: An IPv4 address, an IPv6 address or a DNS name.
    @type address: str

    @param port: The port that will be used to connect to the peer
    @type port: int

    @param protocol: The connection protocol
    @type protocol: str

    @rtype: str
    """
    try:
        # is_ipv6_address will throw an exception for a DNS name
        is_ipv6 = is_ipv6_address(address)
    except ValueError:
        is_ipv6 = False

    if is_ipv6:
        # An IPv6 address must be enclosed in brackets.
        return '%s://[%s]:%s' % (protocol, address, port)
    else:
        return '%s://%s:%s' % (protocol, address, port)


def test_stun_servers(servers=_STUN_SERVERS):
    """Check responses of the listed STUN servers."""
    for s in servers:
        print 'Probing', s, '...',
        sys.stdout.flush()
        status = get_NAT_status(s)
        if status['external_ip'] is None or status['external_port'] is None:
            print 'FAIL'
        else:
            print 'OK'


def is_valid_openbazaar_scheme(uri):
    """Check for OpenBazaar appropriate scheme"""
    return rfc3986.uri_reference(uri).scheme == u'tcp'


def is_valid_hostname(hostname):
    if len(hostname) > 255:
        return False
    if hostname[-1] == ".":
        hostname = hostname[:-1]
    allowed = re.compile(r'(?!-)[A-Z\d-]{1,63}(?<!-)$', re.IGNORECASE)
    return all(allowed.match(x) for x in hostname.split("."))


def is_valid_uri(uri):
    hostname = urlparse(uri).hostname

    return (
        uri
        and rfc3986.is_valid_uri(
            uri, 'utf-8', require_scheme=True, require_authority=True
        )
        and is_valid_openbazaar_scheme(uri)
        and is_valid_hostname(hostname)
    )


class PacketStats(object):
    def __init__(self):
        self.log = logging.getLogger(
            '%s' % self.__class__.__name__
        )
        # incoming
        self.num_packets_incoming = 0
        self.total_bytes_incoming = 0
        # outgoing
        self.num_packets_outgoing = 0
        self.total_bytes_outgoing = 0

    def add_incoming_packet(self, packet_size):
        if packet_size is None or packet_size < 0:
            return
        self.num_packets_incoming += 1
        self.total_bytes_incoming += packet_size

    def add_outgoing_packet(self, packet_size):
        if packet_size is None or packet_size < 0:
            return
        self.num_packets_outgoing += 1
        self.total_bytes_outgoing += packet_size

    def logStats(self, incoming=True, outgoing=True):
        if incoming:
            self.log.info("Incoming Packet Stats.")
            self.log.info("Total Incoming Packets:       {}".format(self.num_packets_incoming))
            self.log.info("Total Incoming bytes:         {}".format(self.total_bytes_incoming))
            self.log.info("Average Incoming Packet Size: {}".format(
                self.total_bytes_incoming/self.num_packets_incoming))

        if outgoing:
            self.log.info("Outgoing Packet Stats.")
            self.log.info("Total Outgoing Packets:       {}".format(self.num_packets_outgoing))
            self.log.info("Total Outgoing bytes:         {}".format(self.total_bytes_outgoing))
            self.log.info("Average Outgoing Packet Size: {}".format(
                self.total_bytes_outgoing/self.num_packets_outgoing))

PACKET_STATS = PacketStats()
PACKET_STATS_LOGS_EVERY_N_PACKETS = 50

def count_outgoing_packet(data):
    if PACKET_STATS is None:
        return

    stats = PACKET_STATS
    if data is not None:
        stats.add_outgoing_packet(len(data))
    if stats.num_packets_outgoing % PACKET_STATS_LOGS_EVERY_N_PACKETS == 0:
        stats.logStats(incoming=False)

def count_incoming_packet(packet):
    if PACKET_STATS is None:
        return

    stats = PACKET_STATS
    if packet is not None:
        if hasattr(packet, '_size'):
            stats.add_incoming_packet(packet._size)
        else:
            stats.add_incoming_packet(len(packet))
    if stats.num_packets_incoming % PACKET_STATS_LOGS_EVERY_N_PACKETS == 0:
        stats.logStats(outgoing=False)

def main():
    test_stun_servers()

if __name__ == '__main__':
    main()
