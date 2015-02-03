__author__ = 'brianhoffman'

import rudp.constants
from pyee import EventEmitter
import rudp.helpers
import logging


class PendingPacket(object):

    def __init__(self, packet, packet_sender):

        self.ee = EventEmitter()

        self._packet_sender = packet_sender
        self._packet = packet
        self._intervalID = None
        self._sending_count = 0

        self.log = logging.getLogger(
            '%s' % self.__class__.__name__
        )

        self.log.info('Init PendingPacket')

    def send(self):

        self._sending_count += 1

        def packet_send():
            self._packet_sender.send(self._packet)

        if self._sending_count < 0:
            self.log.debug('Packet %s sent %d times', self._packet.get_sequence_number(), self._sending_count)
            self._intervalID = rudp.helpers.set_interval(
                packet_send,
                rudp.constants.TIMEOUT
            )
        else:
            self.log.debug('Max retries hit')

        self._packet_sender.send(self._packet)

    def get_sequence_number(self):
        return self._packet.get_sequence_number()

    def acknowledge(self):
        self.log.debug('Pending Packet Acknowledged: %s', self._packet.get_sequence_number())
        if self._intervalID:
            self._intervalID.cancel()
            # self._intervalID = None
        self.ee.emit('acknowledge')
