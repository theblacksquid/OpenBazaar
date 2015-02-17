from rudp.sender import Sender
from rudp.receiver import Receiver

from pyee import EventEmitter
import logging


class Connection(object):

    def __init__(self, packet_sender):

        self.log = logging.getLogger(
            '%s' % self.__class__.__name__
        )
        self.log.info('Init Connection')

        self.ee = EventEmitter()

        self._sender = Sender(packet_sender)
        self._receiver = Receiver(packet_sender)

        # pylint: disable=unused-variable
        @self._receiver.ee.on('data')
        def on_data(data):
            self.log.debug('Received IncomingMessage: %s', data)
            self.ee.emit('data', data)

        # pylint: disable=unused-variable
        @self._receiver.ee.on('_reset')
        def on_reset(data):
            self.log.debug('Received reset message')
            #self._sender = Sender(packet_sender)

    def send(self, data):
        self._sender.send(data)

    def receive(self, packet):
        if packet._acknowledgement:
            self._sender.verify_acknowledgement(packet._sequenceNumber)
        else:
            self._receiver.receive(packet)
