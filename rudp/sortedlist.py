from collections import deque
import bisect

class SortedList(deque):
    '''
    This container extends a high performance deque (double ended queue)
    to included an insertion operation that keeps all elements on the list sorted.

    NOTE: The elements being inserted must implement the rich comparator methods (__lt__, __gt__, etc.)
    so that we know how to keep things in order
    '''
    def __init__(self):
        deque.__init__(self)

    def insertSorted(self, obj):
        index = bisect.bisect_left(self, obj)
        self.rotate(-index)
        self.appendleft(obj)
        self.rotate(index)