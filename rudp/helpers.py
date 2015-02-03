__author__ = 'brianhoffman'

import threading
import math


def splitArrayLike(data, length):
    length = length or 1
    retval = []

    blocks = int(math.ceil(len(data) / length))
    blocks += 1

    for i in range(0, blocks):
        retval.append(data[i*length:i*length + length])

    return retval


def set_interval(func, sec=0, times=3):
    def func_wrapper():
        set_interval(func, sec, times-1)
        func()
    func()
    t = threading.Timer(sec, func_wrapper)
    t.start()
    return t


def sort_by_sequence(packet_a, packet_b):
    return packet_a.get_sequence_number() - packet_b.get_sequence_number()
