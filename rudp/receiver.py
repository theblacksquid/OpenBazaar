import logging
from pyee import EventEmitter
from rudp.packet import Packet
from rudp.sortedlist import SortedList


class IncomingMessage(object):
    def __init__(self, im_id, size):
        self.log = logging.getLogger(
            '%s' % self.__class__.__name__
        )

        self.log.debug('New IncomingMessage Created')

        self.im_id = im_id
        self.size = size

        self.ee = EventEmitter()

        self.synced = False
        self._next_sequence_number = 0
        self._sync_sequence_number = None
        self._packets = SortedList()

        self.body = ''
        self.waiting = False

    def add_to_body(self, payload):
        if payload in self.body:
            self.log.debug('This content is already in the body.')
            return
        else:
            self.body += payload


    def reset(self):
        self.log.debug('IncomingMessage Reset')
        self.log.debug('Self Packets: %s', self._packets)

        self._packets.clear()
        self.synced = False
        self._next_sequence_number = 0
        self._sync_sequence_number = None

        try:
            self.log.debug('Downloaded (%s) | Total Size (%s)', len(self.body), self.size)

            if len(self.body) >= int(self.size):
                self.log.debug('Download Complete')
                if len(self.body) > int(self.size):
                    self.log.debug('Oversized Message')
                self.ee.emit('complete', {'body': self.body})
                return
            else:
                # print self._message, self._message_size
                self.log.debug('Still downloading...')
                self.waiting = True

        except Exception as e:
            self.log.debug('Problem with resetting IncomingMessage: %s', e)


class Receiver(object):
    def __init__(self, packet_sender):

        # TODO: have this be a DuplexStream instead of an EventEmitter.
        # TODO: the Receiver should never send raw packets to the end host. It should
        # only be acknowledgement packets. Please see [1]

        self.ee = EventEmitter()

        self.incoming_messages = {}

        self._synced = False
        self._next_sequence_number = 0
        self._sync_sequence_number = None

        self._packets = SortedList()
        self._packet_sender = packet_sender
        self._closed = False

        self._message = ''
        self._message_id = None
        self._fullmessage = ''
        self._message_size = 0
        self._waiting = False

        self.log = logging.getLogger(
            '%s' % self.__class__.__name__
        )
        self.log.debug('Init Receiver')

    def reset(self):
        self.log.debug('Reset')
        self.log.debug('Self Packets: %s', self._packets)

        self._packets.clear()
        self._synced = False
        self._next_sequence_number = 0
        self._sync_sequence_number = None
        self._message_id = None

        # try:
        # message = self._message
        # except Exception as e:
        message = self._message

        try:
            self.log.debug('%s %s', len(self._message), self._message_size)

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
            self.log.debug('Not full yet: %s', e)

    def receive(self, packet):

        self.log.debug('Receive Packet #%s', packet.get_sequence_number())

        try:
            packet_data = packet._payload.split('|')

            message_id = packet_data[0]
            message_size = packet_data[1]
            payload = packet_data[2]

            if message_id not in self.incoming_messages:
                message = IncomingMessage(message_id, message_size)
                self.incoming_messages[message_id] = message

                # pylint: disable=unused-variable
                @message.ee.on('complete')
                def on_complete(body):
                    self.log.debug('IncomingMessage Complete')
                    self.ee.emit('data', {'payload': message.body, 'size': message.size})
            else:
                message = self.incoming_messages[message_id]

            # Process Packet Contents
            if packet._synchronize:
                if not message.synced:
                    self.log.debug('Receive Sync Packet')
                    if packet._sequenceNumber == message._sync_sequence_number:
                        return

                    self.log.debug('Inserting Packet #%s', packet._sequenceNumber)
                    message._packets.insertSorted(packet)

                    if not message.waiting:
                        message.body = payload
                    else:
                        self.log.debug('Appending to Waiting Message: %s', self._message)
                        message.add_to_body(payload)

                    message._next_sequence_number = packet._sequenceNumber + 1
                    message.synced = True
                    message._sync_sequence_number = packet._sequenceNumber

                    if packet._reset:
                        message.reset()

                    self._packet_sender.send(Packet.createAcknowledgementPacket(
                        packet._sequenceNumber,
                        self._packet_sender._transport.guid,
                        self._packet_sender._transport.pubkey
                    ))

                    return

            elif packet._reset:
                self.log.debug('Receive Reset Packet')

                if message._next_sequence_number == packet.get_sequence_number():
                    if payload in message.body:
                        self.log.debug('This content is already in here.')
                        return
                    else:
                        message.body += payload
                    self.log.debug('Message Updated: %s', message.body)
                    message.reset()
                self._packet_sender.send(Packet.createAcknowledgementPacket(
                    packet._sequenceNumber,
                    self._packet_sender._transport.guid,
                    self._packet_sender._transport.pubkey
                ))
                return
            else:
                self.log.debug('Receive Inside Packet')

                if message._packets.count(packet) == 0:
                    message._packets.insertSorted(packet)
                    if packet.get_sequence_number() == message._next_sequence_number:
                        if payload in message.body:
                            self.log.debug('This content is already in here.')
                            return
                        else:
                            message.body += payload
                        message._next_sequence_number += 1
                        # message._packets.seek()
                        # if message._packets.hasNext():
                        #     self._push_if_expected_sequence(self._packets.nextValue())
                    self._packet_sender.send(Packet.createAcknowledgementPacket(
                        packet._sequenceNumber,
                        self._packet_sender._transport.guid,
                        self._packet_sender._transport.pubkey
                    ))
                else:
                    self.log.debug('Already have this packet')

            # Ignores packets that have a sequence number less than the next sequence
            # number
            # if not packet._synchronize and packet._sequenceNumber < self._sync_sequence_number:
            #     self.log.debug('Just ignoring this packet')
            #     return

            # if packet._synchronize and not self._synced:
            #
            #     # This is the beginning of the stream.
            #     self.log.debug('Beginning of stream %s %s', packet._sequenceNumber, self._sync_sequence_number)
            #
            #     data = packet._payload.split('|', 2)
            #
            #     if len(data) > 1:
            #         self._message_id = data[0]
            #         self._message_size = data[1]
            #         packet._payload = data[2]
            #         self.log.debug('Message #%s (%s bytes): %s', self._message_id, self._message_size, packet._payload)
            #
            #     self._packet_sender.send(Packet.createAcknowledgementPacket(
            #         packet._sequenceNumber,
            #         self._packet_sender._transport.guid,
            #         self._packet_sender._transport.pubkey
            #     ))
            #
            #     if packet._sequenceNumber == self._sync_sequence_number:
            #         return
            #
            #     # Send the packet upstream, send acknowledgement packet to end host, and
            #     # increment the next expected packet.
            #     self._packets.clear()
            #
            #     self.log.debug('Inserting Packet #%s', packet._sequenceNumber)
            #     # self.log.debug('Before Packets: %s', self._packets)
            #     self._packets.insertSorted(packet)
            #
            #     if not self._waiting:
            #         self._message = packet._payload
            #     else:
            #         self.log.debug('Appending to Waiting Message: %s', self._message)
            #         self._message += packet._payload
            #
            #     self.log.debug('Updated Message: %s', self._message)
            #
            #     self._next_sequence_number = packet._sequenceNumber + 1
            #     self._synced = True
            #     self._sync_sequence_number = packet._sequenceNumber
            #
            #     if packet._reset:
            #         self.reset()
            #
            #     return
            #
            # elif not self._synced:
            #     # If we are not synchronized with sender, then this means that we should
            #     # wait for the end host to send a synchronization packet.
            #
            #     # We are done.
            #     self.log.debug('Got an out of order packet.')
            #     return
            #
            # elif packet._sequenceNumber < self._sync_sequence_number:
            #     # This is a troll packet. Ignore it.
            #     self.log.debug('Ignoring packet out of the current window.')
            #     return
            #
            # elif packet._sequenceNumber >= (self._packets.currentValue()._sequenceNumber
            #                                 + rudp.constants.WINDOW_SIZE):
            #     # This means that the next packet received is not within the window size.
            #     self.ee.emit('_window_size_exceeded')
            #     self.log.debug('Ignoring packet out of the current window.')
            #
            #     return
            #
            # elif packet._reset:
            #
            #     data = packet._payload.split('|')
            #     payload = data[1]
            #
            #     self.log.debug(data)
            #     if self._message != '' and data[0] == self._message_id:
            #         self.log.debug('Message Before Appending: %s', self._message)
            #         self._message += payload
            #         self.log.debug('After Updated Message: %s', self._message)
            #         self._packet_sender.send(Packet.createAcknowledgementPacket(
            #             packet._sequenceNumber,
            #             self._packet_sender._transport.guid,
            #             self._packet_sender._transport.pubkey
            #         ))
            #         self.reset()
            #         return

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

    def _push_if_expected_sequence(self, packet):

        if packet.get_sequence_number() == self._next_sequence_number:

            data = packet._payload.split('|')
            payload = data[1]

            self.log.debug('Before Updated 2 Message: %s', self._message)
            if payload in self._message:
                self.log.debug('This content is already in here.')
            else:
                self._message += payload
            self.log.debug('After Updated Message: %s', self._message)

            # [1] Never send packets directly!
            self._packet_sender.send(Packet.createAcknowledgementPacket(packet.get_sequence_number(),
                                                                        self._packet_sender._transport.guid,
                                                                        self._packet_sender._transport.pubkey))
            self._next_sequence_number += 1

            self._packets.seek()
            if self._packets.hasNext():
                self._push_if_expected_sequence(self._packets.nextValue())

    def end(self):
        self._closed = True
        self.ee.emit('end')
