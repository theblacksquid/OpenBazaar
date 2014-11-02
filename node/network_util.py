import sys

import IPy
import requests
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


def is_private_ip_address(addr):
    return is_loopback_addr(addr) or IPy.IP(addr).iptype() != 'PUBLIC'


def get_my_ip(ip_site=IP_DETECT_SITE):
    try:
        r = requests.get(ip_site)
        return r.text.strip()
    except (AttributeError, requests.RequestException) as e:
        print '[Requests] error: %s' % e
    return None


def is_ipv6_address(ip):
    return IPy.IP(ip).version() == 6


def get_peer_url(address, port, protocol='tcp'):
    """
    Return a URL which can be used by ZMQ.

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


def main():
    test_stun_servers()

if __name__ == '__main__':
    main()
