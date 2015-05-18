from pyee import EventEmitter
import logging
from tornado import ioloop


class PendingPacket(object):

    def __init__(self, packet, packet_sender):

        self.ee = EventEmitter()

        self._packet_sender = packet_sender
        self._packet = packet
        self._intervalID = None
        self._sending = False
        self._sending_count = 0

        self.log = logging.getLogger(
            '%s' % self.__class__.__name__
        )

        self.log.info('Init PendingPacket')

    def send(self):

        self._sending = True

        def packet_send(counter):

            def packet_lost():
                if self._sending:
                    self.log.info('Packet %s Lost', self._packet.get_sequence_number())

            if self._sending and counter < 2:
                self.log.debug('Sending Packet #%s: %s', self._packet.get_sequence_number(), self._sending)
                self._packet_sender.send(self._packet)
                packet_send(counter+1)
            else:
                ioloop.IOLoop.instance().call_later(5, packet_lost)

        packet_send(0)

        # self._intervalID = rudp.helpers.set_interval(
        #     packet_send,
        #     rudp.constants.TIMEOUT
        # )

        # self.log.debug('Packet %s sent %d times', self._packet.get_sequence_number(), self._sending_count)

    def get_sequence_number(self):
        return self._packet.get_sequence_number()

    def acknowledge(self):
        self.log.debug('Pending Packet Acknowledged: %s', self._packet.get_sequence_number())
        self._sending = None

        if self._intervalID:
            self._intervalID.cancel()
            self._intervalID = None

        self.ee.emit('acknowledge')
