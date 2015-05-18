import miniupnpc


class PortMapper(object):
    """
    UPnP Port Mapping tool, so we don't need to manually forward ports on a
    router.

    Ideally we'd use a random port within a range of about 1000 possible ports.
    Ideally we'd delete the mapping when we shutdown OpenBazaar but that might
    not be the case.

    Support port mapping for TCP and UDP ports.

    Created on Aug 14, 2014
    @author: gubatron
    """
    DEBUG = False  # boolean
    upnp = None  # miniupnpc.UPnP
    OPEN_BAZAAR_DESCRIPTION = 'OpenBazaar Server'
    UPNP_DEVICE_AVAILABLE = False

    @staticmethod
    def debug(*s):
        if PortMapper.DEBUG:
            print str(s)

    def debug_upnp_values(self):
        self.debug('discoverdelay', self.upnp.discoverdelay)
        self.debug('lanaddr', self.upnp.lanaddr)
        self.debug('multicastif', self.upnp.multicastif)
        self.debug('minissdpdsocket', self.upnp.minissdpdsocket)

    def debug_addresses(self):
        try:
            self.debug('local ip address :', self.upnp.lanaddr)
            self.debug('external ip address :', self.upnp.externalipaddress())
        except Exception:
            pass

    def __init__(self):
        self.upnp = miniupnpc.UPnP()

        self.debug('inital(default) values :')
        self.debug_upnp_values()
        self.upnp.discoverdelay = 200
        self.debug('Discovering... delay=%ums' % self.upnp.discoverdelay)
        self.debug(self.upnp.discover(), 'device(s) detected')

        try:
            self.upnp.selectigd()
            self.UPNP_DEVICE_AVAILABLE = True
        except Exception as exc:
            print 'Exception :', exc
            self.UPNP_DEVICE_AVAILABLE = False
            return

        # display information about the IGD and the internet connection
        self.debug_addresses()
        self.debug("Status Info:", self.get_status_info())
        self.debug("Connection Type:", self.get_connection_type())
        self.debug_upnp_values()

    def get_status_info(self):
        result = 'n/a'
        try:
            result = self.upnp.statusinfo()
        except Exception:
            pass

        return result

    def get_connection_type(self):
        result = 'n/a'
        try:
            result = self.upnp.connectiontype()
        except Exception:
            pass
        return result

    def add_port_mapping(self, externalPort, internalPort,
                         protocol='TCP', ipToBind=None):
        """
        Valid protocol values are: 'TCP', 'UDP'
        Usually you'll pass externalPort and internalPort as the same number.
        """
        result = False

        if self.UPNP_DEVICE_AVAILABLE:
            if protocol not in ('TCP', 'UDP'):
                raise Exception(
                    'PortMapper.add_port_mapping() invalid protocol ' +
                    'exception \'%s\'' %
                    str(protocol)
                )

            if ipToBind is None:
                ipToBind = self.upnp.lanaddr
                self.debug(
                    "INFO: add_port_mapping() -> No alternate ipToBind " +
                    "address passed, using default lan address (",
                    self.upnp.lanaddr, ")"
                )

            try:
                result = self.upnp.addportmapping(
                    externalPort,
                    protocol,
                    ipToBind,
                    internalPort,
                    PortMapper.OPEN_BAZAAR_DESCRIPTION + ' (' + protocol + ')',
                    ''
                )
            except Exception:
                # ConflictInMappingEntry
                result = False

            self.debug("add_port_mapping(%s)?:" % str(externalPort), result)
        return result

    def delete_port_mapping(self, port, protocol='TCP'):
        result = False
        if self.UPNP_DEVICE_AVAILABLE:
            try:
                result = self.upnp.deleteportmapping(port, protocol)
                self.debug(
                    "PortMapper.delete_port_mapping(%d, %s):" % (
                        port, protocol
                    )
                )
                self.debug(result)
            except Exception:
                self.debug(
                    "Could not delete mapping on port %d protocol %s" % (
                        port, protocol
                    )
                )
        return result

    def get_mapping_list(self):
        """Return [PortMappingEntry]."""
        mappings = []

        if self.UPNP_DEVICE_AVAILABLE:
            i = 0
            while True:
                port_mapping = self.upnp.getgenericportmapping(i)
                if port_mapping is None:
                    break
                port, proto, (ihost, iport), desc, cxx, dxx, exx = port_mapping
                mapping = PortMappingEntry(port, proto, ihost, iport, desc, exx)
                self.debug(
                    "port:", port,
                    desc, ihost,
                    "iport:", iport,
                    "c", cxx,
                    "d", dxx,
                    "e", exx
                )
                i += 1
                mappings.append(mapping)

        return mappings

    def clean_my_mappings(self, port):
        """Delete previous OpenBazaar UPnP Port mappings if found."""
        if self.UPNP_DEVICE_AVAILABLE:
            mappings = self.get_mapping_list()
            for mapping in mappings:
                if mapping.description.startswith(PortMapper.OPEN_BAZAAR_DESCRIPTION) \
                   and mapping.port == port:
                    self.debug('delete_port_mapping -> Found:', str(mapping))
                    try:
                        self.delete_port_mapping(mapping.port, mapping.protocol)
                    except Exception:
                        pass


class PortMappingEntry(object):
    """
    POPO to represent a port mapping entry;
    tuples are evil when used for abstractions.
    """
    def __init__(self, port, protocol, internalHost, internalPort,
                 description, expiration):
        self.port = port
        self.protocol = protocol
        self.internalHost = internalHost
        self.internalPort = internalPort
        self.description = description
        self.expiration = expiration

    def __str__(self):
        return '{ protocol:' + self.protocol + \
               ', description: ' + self.description + \
               ', port: ' + str(self.port) + \
               ', internalPort: ' + str(self.internalPort) + \
               ', internalHost: ' + self.internalHost + \
               ', expiration: ' + str(self.expiration) + \
               '}'


def main():
    # Test code
    PortMapper.DEBUG = True
    mapper = PortMapper()
    mapper.add_port_mapping(12345, 12345, 'TCP')
    mapper.add_port_mapping(12345, 12345, 'UDP')
    mappings = mapper.get_mapping_list()
    print len(mappings), "mappings"

    mapper.clean_my_mappings(12345)

    print "---- after deleting the mapping"
    mappings = mapper.get_mapping_list()
    print len(mappings), "mappings"

    print mapper.debug_upnp_values()

if __name__ == '__main__':
    main()
