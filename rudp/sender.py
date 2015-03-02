from rudp.packet import Packet
from rudp.pendingpacket import PendingPacket
import rudp.constants
import rudp.helpers
import math
import random
import logging

from pyee import EventEmitter
import time
from tornado import ioloop


class Window(object):

    def __init__(self, packets):
        self.log = logging.getLogger(
            '%s' % self.__class__.__name__
        )
        self.log.info('Init Window')

        self.ee = EventEmitter()

        self._packets = packets

    def send(self):
        # Our packets to send.
        pkts = list(self._packets)

        if len(pkts) < 1:
            self.ee.emit('done')
            return

        # The initial synchronization packet. Always send this first.
        self.synchronization_packet = pkts.pop(0)

        # The final reset packet. It can be equal to the synchronization packet.
        self._reset_packet = pkts.pop() if len(pkts) else self.synchronization_packet

        # This means that the reset packet's acknowledge event thrown will be
        # different from that of the synchronization packet.
        if self._reset_packet is not self.synchronization_packet:
            # pylint: disable=unused-variable
            @self._reset_packet.ee.on('acknowledge')
            def on_acknowledge():
                self.log.debug('done for real')
                self.ee.emit('done')

        # Will be used to handle the case when all non sync or reset packets have
        # been acknowledged.

        @self.synchronization_packet.ee.on('acknowledge')
        def on_sync_knowledge():  # pylint: disable=unused-variable

            self.log.debug('Acknowledging sync packet')

            # We will either notify the owning class that this window has finished
            # sending all of its packets (that is, if this window only had one packet
            # in it), or keep looping through each each non sync-reset packets until
            # they have been acknowledged.

            if self._reset_packet is self.synchronization_packet:
                self.log.debug('Only one packet in this message. We are done.')
                self.ee.emit('done')
                return
            elif len(pkts) is 0:
                # This means that this window only had two packets, and the second one
                # was a reset packet.
                self._reset_packet.send()
                self.ee.emit('done')
                return

            # pylint: disable=unused-variable
            @self.ee.on('acknowledge')
            def on_sender_acknowledge():
                self.acknowledged = 0
                # This means that it is now time to send the reset packet.
                self._reset_packet.send()

            # And if there are more than two packets in this window, then send all
            # other packets.
            self.acknowledged = 0

            for packet in pkts:
                self.log.debug('Sending another packet')

                # pylint: disable=unused-variable
                @packet.ee.on('acknowledge')
                def on_packet_acknowledge():
                    self.acknowledged += 1
                    if self.acknowledged == len(pkts):
                        self.log.debug('ackd all packets')
                        self.ee.emit('acknowledge')
                        self.ee.emit('done')

                packet.send()

        self.synchronization_packet.send()

    def verify_acknowledgement(self, sequence_number):
        self.log.debug('Ack #%s in %s', sequence_number, len(self._packets))
        for i in range(0, len(self._packets)):
            self.log.debug('Check if %s matches %s' % (self._packets[i].get_sequence_number(), sequence_number))
            if self._packets[i].get_sequence_number() == sequence_number:
                self.log.debug('Found packet to ack')
                self._packets[i].acknowledge()
                return


class Sender(object):

    def __init__(self, packet_sender):
        self.log = logging.getLogger(
            '%s' % self.__class__.__name__
        )
        self.log.info('Init Sender')

        self._packet_sender = packet_sender
        self._windows = []
        self._sending = None
        self._last_sent = 0

        self.ee = EventEmitter()

    def send(self, data):
        data_encoded = data.encode('hex')
        data_size = str(len(data_encoded))

        # Unique message ID
        message_id = random.randint(0, 99999)

        # Split message into chunks
        chunks = rudp.helpers.splitArrayLike(data_encoded, rudp.constants.UDP_SAFE_SEGMENT_SIZE, message_id, data_size)
        self.log.debug('Sending %d chunks', len(chunks))

        # Organize into windows
        windows = rudp.helpers.splitArrayLike(chunks, rudp.constants.WINDOW_SIZE)

        self._windows = self._windows + windows
        self._windows = [x for x in self._windows if x != []]

        self.log.debug('Windows: %d', len(self._windows))
        self._push()

    def _push(self):

        # Clear stale window
        stale = False
        if time.time() - self._last_sent > 30:
            stale = True

        if (stale or not self._sending) and len(self._windows):

            self.log.debug('Sending New Window')
            self._last_sent = int(time.time())
            self._base_sequence_number = math.floor(random.random() *
                                                    (rudp.constants.MAX_SIZE - rudp.constants.WINDOW_SIZE))
            window = self._windows.pop(0)

            # Generate PendingPacket objects to store in Window
            def get_packet(i, pdata):
                packet = Packet(float(i) + self._base_sequence_number, pdata, not i, i is (len(window) - 1))
                return PendingPacket(packet, self._packet_sender)
            packets = [get_packet(i, data) for i, data in enumerate(window)]

            to_send = Window(packets)
            self._sending = to_send

            # pylint: disable=unused-variable
            @self._sending.ee.on('done')
            def on_done():
                self.log.debug('Window Complete: %s', len(self._sending._packets))
                for x in self._sending._packets:
                    x._sending = False
                self._sending = None
                self._last_sent = 0
                self._push()

            to_send.send()
        else:
            if self._sending:
                self.log.debug('Already sending a window. Waiting...')
            else:
                self.log.debug('All done.')

    def verify_acknowledgement(self, sequence_number):
        self.log.debug('Verifying Acknowledgement: %s', self._sending)
        if self._sending:
            self._sending.verify_acknowledgement(sequence_number)
