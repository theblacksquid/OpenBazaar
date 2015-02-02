from pyee import EventEmitter
import struct
import ctypes
import binascii
import constants
import json
import logging
import base64


class Packet:

    def __init__(self, sequence_number, payload=None, synchronize=None, reset=None, buffer=False):

        self.ee = EventEmitter()

        self.segment = sequence_number
        self.offset = 0
        bools = 0
        self._transmission_count = 0

        if buffer:

            try:
                data = json.loads(sequence_number)
                bools = data.get('bools')
                self._sequenceNumber = data.get('seq_num')
            except ValueError as e:
                data = sequence_number
                self.log.error(e)

            self._payload = data.get('payload')
            self._size = data.get('size')
            self._acknowledgement = (bools & 0x80)
            self._synchronize = (bools & 0x40)
            self._finish = (bools & 0x20)
            self._reset = (bools & 0x10)

        else:
            self._acknowledgement = False
            self._synchronize = bool(synchronize)
            self._finish = False
            self._reset = bool(reset)
            self._sequenceNumber = sequence_number
            self._payload = payload

        self.log = logging.getLogger(
            '%s' % self.__class__.__name__
        )

    @staticmethod
    def createAcknowledgementPacket(sequenceNumber, guid, pubkey):
        ack_data = json.dumps({
            'type': 'ack',
            'senderGUID': guid,
            'pubkey': pubkey
        })
        packet = Packet(sequenceNumber, ack_data, False)
        packet._acknowledgement = True
        return packet

    @staticmethod
    def createFinishPacket():
        packet = Packet(0, '', False, False)
        packet._finish = True
        return packet

    def __eq__(self, other):
        return (
            self._acknowledgement is other._acknowledgement and
            self._synchronize is other._synchronize and
            self._finish is other._finish and
            self._reset is other._reset and
            self._sequenceNumber is other._sequenceNumber and
            self._payload is other._payload
        )

    def get_sequence_number(self):
        return self._sequenceNumber

    def to_buffer(self, guid, pubkey, hostname, port, nick='Default'):

        bools = 0 + (
            (self._acknowledgement and 0x80) |
            (self._synchronize and 0x40) |
            (self._finish and 0x20) |
            (self._reset and 0x10)
        )

        buffer = {
            'bools': bools,
            'seq_num': self._sequenceNumber,
            'guid': guid,
            'hostname': hostname,
            'port': port,
            'pubkey': pubkey,
            'size': len(self._payload),
            'payload': self._payload.encode('utf-8'),
            'nick': nick
        }

        return json.dumps(buffer)
