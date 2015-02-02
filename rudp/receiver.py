from packet import Packet
from linkedlist import LinkedList
import constants
import logging
import json
import helpers

from pyee import EventEmitter
import time
import threading
import base64


class Receiver():

    def __init__(self, packet_sender):
        print 'Init Receiver'

        # TODO: have this be a DuplexStream instead of an EventEmitter.
        # TODO: the Receiver should never send raw packets to the end host. It should
        #      only be acknowledgement packets. Please see [1]

        self.ee = EventEmitter()

        self._synced = False
        self._next_sequence_number = 0
        self._sync_sequence_number = None

        self._packets = LinkedList(helpers.sort_by_sequence)
        self._packet_sender = packet_sender
        self._closed = False

        self._message = ''
        self._fullmessage = ''
        self._message_size = 0
        self._waiting = False

        self.log = logging.getLogger(
            '%s' % (self.__class__.__name__)
        )

    def reset(self):
        self.log.debug('Reset')
        self.log.debug('Self Packets: %s' % self._packets.toArray())

        self._synced = False
        self._next_sequence_number = 0
        self._sync_sequence_number = None

        # try:
        #     message = self._message
        # except Exception as e:
        message = self._message

        try:
            self.log.debug('%s %s' % (len(self._message), self._message_size))
            self.log.debug('%s' % (len(message) == int(self._message_size)))

            if len(self._message) == int(self._message_size):
                self.log.debug('Matched up')
                self.ee.emit('data', {'payload': self._message, 'size': self._message_size})
                self._waiting = False
                self._message = ''
                self._message_size = 0
                return
            else:
                # print self._message, self._message_size
                self.log.debug('Not equal')
                self._waiting = True

        except Exception as e:
            self.log.debug('Not full yet: %s' % e)

        # Pass upstream to processor if message is complete
        # if self._message_size == len(self._message):
        #     self.ee.emit('data', {'payload': self._message, 'size': len(self._message)})
        #     self._message_size = 0
        #     self._message = ''
        #     self._waiting = False


    def receive(self, packet):

        try:
            if self._closed:
                # Since this is closed, don't do anything.
                return

            # Ignores packets that have a sequence number less than the next sequence
            # number
            if not packet._synchronize and packet._sequenceNumber < self._sync_sequence_number:
                self.log.debug('Just returning')
                return

            self.log.debug('Incoming Packet #%s', packet._sequenceNumber)
            #self.log.debug('Message Value: %s', self._message)
            # if self._packets:
            #     self.log.debug('Reset: %s Window Exceeded: %s', packet._reset, (packet._sequenceNumber >= (self._packets.currentValue()._sequenceNumber + constants.WINDOW_SIZE)))
            self.log.debug('Synced: %s, Sync Packet: %s', self._synced, packet._synchronize)

            if packet._synchronize and not self._synced:

                # This is the beginning of the stream.
                self.log.debug('Beginning of stream %s %s', packet._sequenceNumber, self._sync_sequence_number)

                data = packet._payload.split('|', 1)

                if len(data) > 1:
                    self._message_size = data[0]
                    packet._payload = data[1]

                self.log.debug('Send Ack Packet')
                self._packet_sender.send(Packet.createAcknowledgementPacket(
                    packet._sequenceNumber,
                    self._packet_sender._transport.guid,
                    self._packet_sender._transport.pubkey
                ))

                if packet._sequenceNumber == self._sync_sequence_number:
                    return

                # Send the packet upstream, send acknowledgement packet to end host, and
                # increment the next expected packet.
                self._packets.clear()

                self.log.debug('Inserting Packet #%s', packet._sequenceNumber)
                self.log.debug('Before Packets: %s' % self._packets)
                self._packets.insert(packet)

                self.log.debug('Before Updated Message: %s' % self._message)

                if not self._waiting:
                    self._message = packet._payload
                else:
                    self._message += packet._payload

                self.log.debug('Updated Message: %s' % self._message)

                self._next_sequence_number = packet._sequenceNumber + 1
                self._synced = True
                self._sync_sequence_number = packet._sequenceNumber

                if packet._reset:
                    self.reset()

                # if packet._reset:
                #     self.log.debug('Received Reset')
                #     self._synced = False
                #     self._next_sequence_number = 0
                #     self._sync_sequence_number = None
                #     self.ee.emit('_reset', 'test')
                    # self.log.debug('Passing Message Upstream: %s', self._message)
                    # self.ee.emit('data', {'payload': self._message, 'size': len(self._message)})

                # We're done.
                #self._packet_sender.send(Packet.createFinishPacket())

                return

            elif not self._synced:
                # If we are not synchronized with sender, then this means that we should
                # wait for the end host to send a synchronization packet.

                # We are done.
                self.log.debug('Waiting for sync packet first.')
                return

            elif packet._sequenceNumber < self._sync_sequence_number:
                # This is a troll packet. Ignore it.
                print 'Troll packet'
                return

            elif packet._sequenceNumber >= (self._packets.currentValue()._sequenceNumber + constants.WINDOW_SIZE):
                # This means that the next packet received is not within the window size.
                self.ee.emit('_window_size_exceeded')
                self.log.debug('Packet window exceeded')

                return

            elif packet._reset:
                if self._message != '':
                    self.log.debug('Before Updated 3 Message: %s' % self._message)
                    self._message += packet._payload
                    self.log.debug('After Updated Message: %s' % self._message)
                    self._packet_sender.send(Packet.createAcknowledgementPacket(
                        packet._sequenceNumber,
                        self._packet_sender._transport.guid,
                        self._packet_sender._transport.pubkey
                    ))
                    self.reset()
                    return

        except Exception as e:
            self.log.error(e)

        # This means that we should simply insert the packet. If the packet's
        # sequence number is the one that we were expecting, then send it upstream,
        # acknowledge the packet, and increment the next expected sequence number.
        #
        # Once acknowledged, check to see if there aren't any more pending packets
        # after the current packet. If there are, then check to see if the next
        # packet is the expected packet number. If it is, then start the
        # acknowledgement process anew.

        self.log.debug('Inserting Packet #%s', packet._sequenceNumber)

        result = self._packets.insert(packet)

        if result is LinkedList.insertion_result.get('INSERTED'):
            self._pushIfExpectedSequence(packet)
        elif result is LinkedList.insertion_result.get('EXISTS'):
            self._packet_sender.send(Packet.createAcknowledgementPacket(
                packet._sequenceNumber,
                self._packet_sender._transport.guid,
                self._packet_sender._transport.pubkey
            ))

    def _pushIfExpectedSequence(self, packet):

        if packet.get_sequence_number() == self._next_sequence_number:

            self.log.debug('Before Updated 2 Message: %s' % self._message)
            self._message += packet._payload
            self.log.debug('After Updated Message: %s' % self._message)

            # [1] Never send packets directly!
            self._packet_sender.send(Packet.createAcknowledgementPacket(packet.get_sequence_number(),
                                                                        self._packet_sender._transport.guid,
                                                                        self._packet_sender._transport.pubkey))
            self._next_sequence_number += 1

            self._packets.seek()
            if self._packets.hasNext():
                self._pushIfExpectedSequence(self._packets.nextValue())

    def end(self):
        self._closed = True
        self.ee.emit('end')
