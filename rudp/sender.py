from packet import Packet
from pendingpacket import PendingPacket
import constants
import helpers
import math
import random
import logging

from pyee import EventEmitter
from rudp.linkedlist import LinkedList
import time
from zmq.eventloop import ioloop


class Window():

    def __init__(self, packets):
        self.log = logging.getLogger(
            '%s' % (self.__class__.__name__)
        )
        self.log.info('Init Window')

        self.ee = EventEmitter()

        self._packets = packets

    def send(self):
        # Our packets to send.
        pkts = list(self._packets)
        packet_count = len(pkts)

        if len(pkts) < 1:
            self.ee.emit('done')
            return

        # The initial synchronization packet. Always send this first.
        self._synchronization_packet = pkts.pop(0)

        # The final reset packet. It can be equal to the synchronization packet.
        self._reset_packet = pkts.pop() if len(pkts) else self._synchronization_packet

        # This means that the reset packet's acknowledge event thrown will be
        # different from that of the synchronization packet.
        if self._reset_packet is not self._synchronization_packet:
            @self._reset_packet.ee.on('acknowledge')
            def on_acknowledge():
                self.log.debug('done for real')
                self.ee.emit('done')

        # Will be used to handle the case when all non sync or reset packets have
        # been acknowledged.
        @self._synchronization_packet.ee.on('acknowledge')
        def on_sync_knowledge():

            self.log.debug('on_sync_knowledge')

            # We will either notify the owning class that this window has finished
            # sending all of its packets (that is, if this window only had one packet
            # in it), or keep looping through each each non sync-reset packets until
            # they have been acknowledged.

            if self._reset_packet is self._synchronization_packet:
                self.log.debug('Sync Packet equals Reset Packet')
                self.ee.emit('done')
                return
            elif len(pkts) is 0:
                # This means that this window only had two packets, and the second one
                # was a reset packet.
                self._reset_packet.send()
                self.ee.emit('done')
                return

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

                @packet.ee.on('acknowledge')
                def on_packet_acknowledge():
                    self.acknowledged += 1
                    if self.acknowledged == len(pkts):
                        self.log.debug('ackd all packets')
                        self.ee.emit('acknowledge')
                        #self._reset_packet.send()

                packet.send()

        self._synchronization_packet.send()

    def verify_acknowledgement(self, sequence_number):

        for i in range(0, len(self._packets)):
            #self.log.debug('Check if %s matches %s' % (self._packets[i].get_sequence_number(), sequence_number))
            if self._packets[i].get_sequence_number() == sequence_number:
                self._packets[i].acknowledge()



class Sender:

    def __init__(self, packet_sender):
        self.log = logging.getLogger(
            '%s' % (self.__class__.__name__)
        )
        self.log.info('Init Sender')

        self._packet_sender = packet_sender
        self._windows = []
        self._sending = None
        self._last_sent = 0

        self.ee = EventEmitter()

    def send(self, data):

        # while len(self._windows) > 0:
        #     time.sleep(1)
        #     self.log.debug('Waiting for windows')
        #     self._push()

        chunks = helpers.splitArrayLike(data, constants.UDP_SAFE_SEGMENT_SIZE)
        self.log.debug('Sending %d chunks' % len(chunks))
        windows = helpers.splitArrayLike(chunks, constants.WINDOW_SIZE)
        self._windows = self._windows + windows
        self._windows = [x for x in self._windows if x != []]
        self.log.debug('Windows: %s' % self._windows)
        self._push()

    def _push(self):

        print int(time.time()), self._last_sent

        self.log.debug('self._sending: %s' % self._sending)
        
        if not self._sending and len(self._windows):
            self._last_sent = int(time.time())
            self._base_sequence_number = math.floor(random.random() * (constants.MAX_SIZE - constants.WINDOW_SIZE))
            window = self._windows.pop(0)

            def get_packet(i, pdata):
                packet = Packet(float(i) + self._base_sequence_number, pdata, not i, i is (len(window) - 1))
                return PendingPacket(packet, self._packet_sender)

            packets = [get_packet(i, data) for i, data in enumerate(window)]
            to_send = Window(packets)

            self._sending = to_send

            @self._sending.ee.on('done')
            def on_done():
                self.log.debug('_sending done')
                self._sending = None
                self._last_sent = 0
                self._push()

            to_send.send()

        elif self._last_sent != 0 and int(time.time()) - self._last_sent > 30:
            self._last_sent = 0
            self._sending = None
            self._windows = []
            self.log.info('Peer may have timed out or be unreachable.')
            self.ee.emit('timeout', {})

        else:
            self.log.debug('None of the above')

        # def pushit():
        #
        #     if (not self._sending or self._counter > 10) and len(self._windows):
        #
        #         self._base_sequence_number = math.floor(random.random() * (constants.MAX_SIZE - constants.WINDOW_SIZE))
        #         window = self._windows.pop(0)
        #
        #         def get_packet(i, pdata):
        #             packet = Packet(float(i) + self._base_sequence_number, pdata, not i, i is (len(window) - 1))
        #             return PendingPacket(packet, self._packet_sender)
        #
        #         packets = [get_packet(i, data) for i, data in enumerate(window)]
        #         to_send = Window(packets)
        #
        #         self._sending = to_send
        #
        #         @self._sending.ee.on('done')
        #         def on_done():
        #             self.log.debug('_sending done')
        #             self._sending = None
        #             self._counter = 0
        #             self._push()
        #
        #         to_send.send()
        #     else:
        #         if len(self._windows):
        #             self._counter += 1
        #             self.log.debug('Cannot push %d' % self._counter)
        #             ioloop.IOLoop.instance().call_later(1, pushit)
        #
        # pushit()

    def verifyAcknowledgement(self, sequence_number):
        self.log.debug('Verifying Acknowledgement: %s', self._sending)
        if self._sending:
            self._sending.verify_acknowledgement(sequence_number)
