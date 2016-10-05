"""Pcap file parser.
"""

import struct
import binascii
try:
    from cStringIO import StringIO
except:
    from StringIO import StringIO

import radiotap
import dot11

from common import WlTrace, GenericHeader, PhyInfo

_PCAP_FILE_MAGIC_NUMBER = 0xa1b2c3d4
_PCAP_FILE_MAGIC_NUMBER_NS = 0xa1b23c4d

_PCAP_VERSION_MAJOR = 2
_PCAP_VERSION_MINOR = 4

_LINKTYPE_IEEE802_11 = 105
_LINKTYPE_IEEE802_11_RADIOTAP = 127

PCAP_FILE_MAGIC_LE = struct.pack('<I', _PCAP_FILE_MAGIC_NUMBER)
PCAP_FILE_MAGIC_LE_NS = struct.pack('<I', _PCAP_FILE_MAGIC_NUMBER_NS)
PCAP_FILE_MAGIC_BE = struct.pack('>I', _PCAP_FILE_MAGIC_NUMBER)
PCAP_FILE_MAGIC_BE_NS = struct.pack('>I', _PCAP_FILE_MAGIC_NUMBER_NS)


class PcapException(Exception):
    pass


class PcapHeader(GenericHeader):
    """Pcap file header.

    The format is documented here:
    https://wiki.wireshark.org/Development/LibpcapFileFormat

    Note that the file header does not contain the total number of packets in
    the file.

    Args:
        fh (file object): the packet trace file.
    """

    _PACK_PATTERN_BASE = "IHHiIII"
    FIELDS = [
        'magic_number',
        'version_major',
        'version_minor',
        'thiszone',
        'sigfigs',
        'snaplen',
        'network',
    ]

    def __init__(self, fh, *args, **kwargs):
        fh.seek(0)
        magic = fh.read(4)
        fh.seek(0)

        if magic not in [PCAP_FILE_MAGIC_LE, PCAP_FILE_MAGIC_LE_NS,
                         PCAP_FILE_MAGIC_BE, PCAP_FILE_MAGIC_BE_NS]:
            raise Exception("Unknown file magic: %s" % (binascii(magic)))

        self.endian = '<' if magic in [PCAP_FILE_MAGIC_LE,
                                       PCAP_FILE_MAGIC_LE_NS] else '>'
        self.nano_ts = magic in [PCAP_FILE_MAGIC_LE_NS, PCAP_FILE_MAGIC_BE_NS]

        cls = self.__class__
        cls.PACK_PATTERN = '%s%s' % (self.endian, cls._PACK_PATTERN_BASE)
        super(cls, self).__init__(fh, *args, **kwargs)

        if self.version_major != _PCAP_VERSION_MAJOR or\
                self.version_minor != _PCAP_VERSION_MINOR:
            raise PcapException('Expect PCAP version 2.4, got %d.%d'
                                % (self.version_major, self.version_minor))

    @classmethod
    def to_binary(cls, endian='@', snaplen=65535,
                  network=_LINKTYPE_IEEE802_11_RADIOTAP):
        pattern = '%s%s' % (endian, cls._PACK_PATTERN_BASE)
        return struct.pack(pattern, _PCAP_FILE_MAGIC_NUMBER,
                           _PCAP_VERSION_MAJOR,
                           _PCAP_VERSION_MINOR, 0, 0, snaplen, network)


class PcapPacketHeader(GenericHeader):
    """Per packet header in Pcap format.
    """

    _PACK_PATTERN_BASE = 'IIII'
    FIELDS = [
        'ts_sec',
        'ts_usec',
        'incl_len',
        'orig_len',
    ]

    def __init__(self, fh, header, *args, **kwargs):
        cls = self.__class__
        cls.PACK_PATTERN = '%s%s' % (header.endian, cls._PACK_PATTERN_BASE)

        super(cls, self).__init__(fh, *args, **kwargs)
        self.epoch_ts = self.ts_sec
        self.epoch_ts += self.ts_usec / (1e9 if header.nano_ts else 1e6)
        self.epoch_ts += header.thiszone

    @classmethod
    def encapsulate(cls, pkt, endian='@'):
        pattern = '%s%s' % (endian, cls._PACK_PATTERN_BASE)
        ts_sec = int(pkt.epoch_ts)
        ts_usec = int((pkt.epoch_ts - ts_sec) * 1e6)
        phy = pkt.phy.to_binary()
        incl_len = len(phy) + pkt.phy.caplen
        orig_len = len(phy) + pkt.phy.len
        return '%s%s%s' % (struct.pack(pattern, ts_sec, ts_usec, incl_len,
                                       orig_len), phy, pkt.raw)


class PcapCapture(WlTrace):
    """Represent a Pcap packet trace.

    Currently only support two link types.
    """

    LINKTYPES = [
        _LINKTYPE_IEEE802_11,
        _LINKTYPE_IEEE802_11_RADIOTAP,
    ]

    def __init__(self, path, *args, **kwargs):
        cls = self.__class__
        super(cls, self).__init__(path, *args, **kwargs)

        self.header = PcapHeader(self.fh)
        if self.header.network not in cls.LINKTYPES:
            raise PcapException("Unsupported link type: %d" %
                                (self.header.network))
        if self.header.network == _LINKTYPE_IEEE802_11_RADIOTAP:
            self.has_phy_info = True

    @classmethod
    def save(cls, path, pkts):
        with open(path, 'wb') as f:
            f.write(PcapHeader.to_binary())
            for pkt in pkts:
                f.write(PcapPacketHeader.encapsulate(pkt))

    def _read_one_pkt(self):
        pkt_header = PcapPacketHeader(self.fh, self.header)
        if pkt_header.incl_len > self.header.snaplen:
            raise PcapException("snaplen: %d, incl_len: %d" %
                                (self.header.snaplen, pkt_header.incl_len))

        raw = self.fh.read(pkt_header.incl_len)
        if len(raw) != pkt_header.incl_len:
            raise IOError("Short read: expect %d, got %d" %
                          (pkt_header.incl_len, len(raw)))

        pkt_fh = StringIO(raw)
        if self.header.network == _LINKTYPE_IEEE802_11_RADIOTAP:
            rh = radiotap.RadiotapHeader(pkt_fh)
            phy = rh.to_phy()
            phy.len = pkt_header.orig_len - rh._it_len
            phy.caplen = pkt_header.incl_len - rh._it_len
        else:
            phy = PhyInfo(has_fcs=False, len=self.header.orig_len)
            phy.caplen = pkt_header.incl_len

        phy.epoch_ts = pkt_header.epoch_ts
        if self.fix_timestamp and phy.rate is not None:
            phy.epoch_ts -= phy.len * 8 / phy.rate * 1e-6

        pkt = dot11.Dot11Packet(pkt_fh, phy=phy, counter=self.counter)
        try:
            phy.end_epoch_ts = phy.epoch_ts + pkt.air_time()
        except:
            pass
        self.counter += 1
        return pkt

    def _next(self, n=100):
        if self.fh is None:
            return []

        pkts = []
        for unused in xrange(n):
            try:
                pkt = self._read_one_pkt()
                if pkt.phy.ampdu_ref is not None:
                    # read all packets in this ampdu
                    ampdu_ref = pkt.phy.ampdu_ref
                    while pkt.phy.ampdu is not None and\
                            pkt.phy.ampdu_ref == ampdu_ref:
                        if pkt.phy.last_frame:
                            # update previous ampdu's rate info
                            for p in reversed(pkts):
                                if p.phy.ampdu is None or\
                                        p.phy.ampdu_ref != ampdu_ref:
                                    break
                                p.phy.rate = pkt.phy.rate
                            break
                        pkts.append(pkt)
                        pkt = self._read_one_pkt()

                pkts.append(pkt)

            except IOError:
                self.fh.close()
                self.fh = None
                break

        return pkts
