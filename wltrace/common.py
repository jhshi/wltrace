"""Common interfaces.
"""

import struct
import abc
import io
import collections


class GenericHeader(object):
    """Base class for general header structure.

    This can be a file header, section header (peek-tagged), per-packet header
    (pcap).

    Args:
        fh (file object): the file handle, which internal pointer points to the
          start of the header.
    """

    PACK_PATTERN = None
    """:mod:`struct` format string used to decode the header bytes.
    """

    FIELDS = None
    """A list of string representing name of each field in the header, in the
    order they appear in the ``PACK_PATTERN`` format.

    It is important that the order of the filed names correspond *strictly* with
    the order they appear in the header format. If the header has dummy fields,
    such as padding bytes, you will have to also name them, although you can use
    the same name for multiple dummy fields.
    """

    def __init__(self, fh, *args, **kwargs):
        cls = self.__class__
        header_len = struct.calcsize(cls.PACK_PATTERN)
        raw = fh.read(header_len)
        if len(raw) != header_len:
            raise IOError('Short read bytes, excect %d, got %d' %
                          (header_len, len(raw)))

        self.payload = raw
        self.offset = 0

        fields = self.unpack(cls.PACK_PATTERN)
        for i, attr in enumerate(cls.FIELDS):
            setattr(self, attr, fields[i])

    def unpack(self, fmt):
        val = struct.unpack_from(fmt, self.payload, self.offset)
        self.offset += struct.calcsize(fmt)
        return val


class PhyInfo(object):
    """Packet PHY layer information.

    PHY information is usually provided in the format of physical layer header,
    such as Radiotap. PHY information includes:

    * signal (int): received RSSI in dBm.
    * noise (int): noise level in dBm.
    * freq_mhz (int): channel central frequency (MHz)
    * has_fcs (bool)
    * fcs_error (bool): True if this packet fails the FCS check.
    * epoch_ts (float): POSIX timestamp of the first bit of this packet
    * end_epoc_ts (float): POSIX timestamp of the last bit of this packet
    * rate (float): packet modulation rate (Mbps)
    * mcs (int): MCS index (http://mcsindex.com/)
    * len (int): packet original length in bytes, including 4 FCS bytes.
    * caplen (int): actually stored bytes, probably smaller than ``len``.
    * mactime (int): MAC layer TSF counter.
    * ampdu_ref (int): AMPDU reference number.
    * last_ampdu (bool): True if this packet was the last packet in the AMPDU.
    """

    def __init__(self, *args, **kwargs):
        for attr in ['signal', 'noise', 'freq_mhz', 'has_fcs', 'fcs_error',
                     'epoch_ts', 'end_epoch_ts', 'rate', 'mcs', 'len', 'caplen',
                     'mactime', 'ampdu_ref', 'last_ampdu']:
            setattr(self, attr, kwargs.get(attr, None))


import dot11


class WlTrace(object):
    """Base class that represents a (wireless) packet trace.

    A packet trace is nothing but a sequence of packets. Therefore, the main
    interface of this object is to yield packet in order. In fact, the object
    itself is an iterator, which means the packets can only be accessed once in
    sequence. This is suffice for most purpose, and also reduces memory
    consumption. Users can always store the packets outside this object if
    needed.

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
        self.has_phy_info = False

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

            # if ack packet is not present, look for the next packet from the
            # same station
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
                if hasattr(p, 'addr2') and p.src == pkt.src and\
                        hasattr(p, 'seq_num'):
                    if not p.retry or p.seq_num != pkt.seq_num:
                        break
                    p.retry_count = current_retry
                    current_retry += 1

    def next(self):
        """Iteration function.

        Note that it is possible to yield dangling ack packets as well, so user
        can detect if the sniffer missed the previous packet.
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
        """Get the current packet without consuming it.
        """
        try:
            self._fetch()
            pkt = self.pkt_queue[0]
            return pkt
        except IndexError:
            raise StopIteration()
