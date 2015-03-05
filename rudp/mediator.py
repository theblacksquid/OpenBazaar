import logging
import socket
import threading


class Mediator(object):
    def __init__(self, ip, port):

        #threading.Thread.__init__(self)

        self.log = logging.getLogger(
            '%s' % self.__class__.__name__
        )

        self.log.debug('Starting mediator server at port: %d', port)

        self.hosts = {}

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # self.sock.setblocking(0)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((ip, port))

        def mediator_listen():
            while True:

                try:

                    data, addr = self.sock.recvfrom(512)

                    msg = data.split(' ')

                    if len(msg) > 1:
                        command = msg[0]
                        guid = msg[1]

                        if command == 'register':
                            self.hosts[guid] = dict(address=addr[0], port=addr[1])
                            self.log.debug('Registered %s, from host %s:%d', guid, addr[0], addr[1])

                        elif command == 'talk':
                            if guid not in self.hosts:
                                continue

                            self.log.debug('Talk request')

                            # Send to client that is requesting to talk.
                            to_send = '%s:%d' % (self.hosts[guid].get('address'), self.hosts[guid].get('port'))

                            self.sock.sendto(to_send, (addr[0], addr[1]))

                            # Send to the client that is waiting for a request to talk.
                            to_send = '%s:%d' % (addr[0], addr[1])
                            self.sock.sendto(to_send, (self.hosts[guid].get('address'),
                                                       self.hosts[guid].get('port')))

                except socket.error:
                    pass

        threading.Thread(target=mediator_listen).start()
