"""Wireless Packet Trace

This module can load a packet trace, and yields a sequence of packets.
Currently, only IEEE802.11 pakcet traces saved in Pcap or Omnipeek's peek-tagged
format are supported. For Pcap format, this module can parse the Radiotap header
if exists.
"""

import os
import binascii
import abc
import io
import collections

import pcap
import peektagged

import dot11

MAGIC_LEN = 4
"""File type magic length in bytes.
"""

FILE_TYPE_HANDLER = {
    pcap.PCAP_FILE_MAGIC_LE: pcap.PcapCapture,
    pcap.PCAP_FILE_MAGIC_BE: pcap.PcapCapture,
    pcap.PCAP_FILE_MAGIC_LE_NS: pcap.PcapCapture,
    pcap.PCAP_FILE_MAGIC_BE_NS: pcap.PcapCapture,
    peektagged.PEEKTAGGED_FILE_MAGIC: peektagged.PeektaggedCapture,
}
"""A map from magic bytes to file handler.
"""


def is_packet_trace(path):
    """Determine if a file is a packet trace that is supported by this module.
    """
    path = os.path.abspath(path)
    if not os.path.isfile(path):
        return False

    try:
        f = open(path, 'rb')
    except:
        return False

    magic = f.read(4)
    f.close()

    return magic in FILE_TYPE_HANDLER


def load_trace(path, *args, **kwargs):
    """Read a packet trace file, return a :class:`pyparser.capture.common.WlTrace` object.

    No packet trace type is needed, this function will read the file's magic
    (first ``FILE_TYPE_HANDLER`` bytes), and automatically determine the
    file type, and call appropriate handler to process the file.

    Args:
        path (str): the file's path to be loaded.

    Returns:
        ``WlTrace`` object.
    """
    with open(path, 'rb') as f:
        magic = f.read(MAGIC_LEN)
    if magic not in FILE_TYPE_HANDLER:
        raise Exception('Unknown file magic: %s' % (binascii.hexlify(magic)))

    return FILE_TYPE_HANDLER[magic](path, *args, **kwargs)


class WlTrace(object):
    """Base class that represents a (wireless) packet trace.

    A packet trace is nothing but a sequence of packets. Therefore, the main
    interface of this object is to yield packet in order. In fact, the object
    itself is an iterator, which means the packets can only be accessed once in
    sequence. This is suffice for most purpose, and also reduces memory
    consumption. Users can always store the packets outside this object if needed.

    Args:
        path (str): the path of the packet trace file.

    Example:
        This is how ``WlTrace`` is supposed to be used::

          cap = WlTrace('path/to/packet/trace.pcap')
          for pkt in cap:
            print pkt.counter
    """
    __metaclass__ = abc.ABCMeta

    def __init__(self, path, *args, **kwargs):
        super(WlTrace, self).__init__()

        self.path = path
        self.fh = io.BufferedReader(io.open(path, 'rb'))
        self.counter = 1

        self.pkt_queue = collections.deque()

        self.fix_timestamp = kwargs.get('fix_timestamp', False)

    def __iter__(self):
        return self

    def __next__(self):
        return self.next()

    @abc.abstractmethod
    def _next(self, n=100):
        """Get next n packets.

        Subclass must implement this method.

        Args:
            n (int): number of packets to read

        Returns:
          list: a list of :class:`pyparser.capture.dot11.Dot11Packet` object.
        """
        pass

    def _fetch(self):
        if len(self.pkt_queue) < 2:
            pkts = self._next(1024)
            self.pkt_queue.extend(pkts)

    def _infer_acked(self, pkt):
        # first assume this pkt is not acked
        pkt.acked = False
        pkt.ack_pkt = None

        # infer ``acked`` for non-multicast mgmt or data packet
        if (pkt.type == dot11.DOT11_TYPE_MANAGEMENT or
            pkt.type == dot11.DOT11_TYPE_DATA) and\
                not dot11.is_broadcast(pkt.dest):

            # looking for its ack packet
            if len(self.pkt_queue) > 0:
                next_pkt = self.pkt_queue[0]
                if dot11.is_ack(next_pkt)\
                        and next_pkt.dest == pkt.src and\
                        next_pkt.epoch_ts - pkt.end_epoch_ts < 1e-4:
                    pkt.acked = True
                    pkt.ack_pkt = next_pkt
                    return

            # if ack packet is not present, look for the next packet from the same station
            next_pkt = None
            for p in self.pkt_queue:
                if hasattr(p, 'addr2') and p.src == pkt.src:
                    next_pkt = p
                    break
            if next_pkt is not None and next_pkt.seq_num != pkt.seq_num:
                # the station moves on to next packet, hinting that
                # current packet was probably acked and the sniffer just
                # missed the ack packet
                pkt.acked = True

    def _infer_retry(self, pkt):
        if hasattr(pkt, 'retry_count'):
            return

        if not pkt.retry:
            # this is the first transmission
            pkt.retry_count = 0
        else:
            # sniffer missed the first transmission, assume this is the first
            # retry
            pkt.retry_count = 1
        current_retry = pkt.retry_count + 1
        if pkt.type in [dot11.DOT11_TYPE_MANAGEMENT, dot11.DOT11_TYPE_DATA] and\
                not dot11.is_broadcast(pkt.dest):
            for p in self.pkt_queue:
                if hasattr(p, 'addr2') and p.src == pkt.src and hasattr(p, 'seq_num'):
                    if not p.retry or p.seq_num != pkt.seq_num:
                        break
                    p.retry_count = current_retry
                    current_retry += 1

    def next(self):
        """Iteration function.

        Note that it is possible to yield dangling ack packets as well, so user can
        detect if the sniffer missed the previous packet.
        """

        try:
            self._fetch()
            pkt = self.pkt_queue.popleft()
            try:
                self._infer_acked(pkt)
            except:
                pass
            try:
                self._infer_retry(pkt)
            except:
                pass

            return pkt
        except IndexError:
            raise StopIteration()

    def peek(self):
        try:
            self._fetch()
            pkt = self.pkt_queue[0]
            return pkt
        except IndexError:
            raise StopIteration()

    def appendleft(self, pkt):
        self.pkt_queue.appendleft(pkt)
