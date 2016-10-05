"""Omnipeek peek-tagged packet trace parser.

Peek-tagged file contains several sections:

  * ``0x7fver``: Omnipeek software version information.
  * ``sess``: Session information, include total packet number.
  * ``pkts``: Packets.

Each section starts with a fixed-sized section header, then variable sized
payloads. The format is documented here:
http://varsanofiev.com/inside/airopeekv9.htm

"""
import struct
import datetime

try:
    from cStringIO import StringIO
except:
    from StringIO import StringIO

import dot11
import xml.etree.ElementTree as ET


from common import WlTrace, GenericHeader, PhyInfo
import utils

PEEKTAGGED_FILE_MAGIC = '\x7fver'

EXT_FLAGS_BANDWIDTH =       0x00000007
EXT_FLAGS_GI =              0x00000018
EXT_FLAGS_MCS_INDEX_USED =  0x00000100


class PeektaggedException(Exception):
    pass


class PeektaggedSectionHeader(GenericHeader):
    """Peek-tagged section header.

    Args:
        fh (file object): file to be read.
        load_payload (bool): whether or not read the payload from the file. By
            default, it is ``False``. For small sections, such as "0x7fver",
            "sess", it is no big deal. But for "pkts" section, which can be
            huge, we do not want to load the entire section at once.
    """

    PACK_PATTERN = '<4sII'
    FIELDS = [
        'tag',
        'len',
        'pad',
    ]

    def __init__(self, fh, *args, **kwargs):
        cls = self.__class__
        super(cls, self).__init__(fh, *args, **kwargs)


class PeektaggedPacketHeader(object):
    """Per packet header.

    This is peek-tagged format's specific way to convey PHY layer information in
    packet trace.
    """

    TAGS = {
        0x00: ('len', '<I'),
        0x01: ('ts_low', '<I'),
        0x02: ('ts_high', '<I'),
        0x03: ('flags', '<I'),
        0x04: ('channel', '<I'),
        0x05: ('rate', '<I'),
        0x06: ('signal_level', '<I'),
        0x07: ('signal', '<i'),
        0x08: ('noise_level', '<I'),
        0x09: ('noise', '<i'),
        0x0d: ('freq_mhz', '<I'),
        0x15: ('ext_flags', '<I'),
        0xffff: ('caplen', '<I'),
    }

    def __init__(self, fh, *args, **kwargs):
        cls = self.__class__
        super(cls, self).__init__(*args, **kwargs)

        while True:
            tag_raw = fh.read(2)
            val_raw = fh.read(4)
            if len(tag_raw) != 2 or len(val_raw) != 4:
                raise IOError("Short read.")

            tag, = struct.unpack('<H', tag_raw)
            if tag not in cls.TAGS:
                continue
            attr, fmt = cls.TAGS[tag]
            setattr(self, attr, struct.unpack(fmt, val_raw)[0])

            if tag == 0xffff:
                break

        if hasattr(self, 'ext_flags') and\
                self.ext_flags & EXT_FLAGS_MCS_INDEX_USED:
            self.mcs = self.rate
            self.rate = dot11.mcs_to_rate(self.mcs)
        else:
            self.mcs = None
            self.rate /= 2.0

        self.epoch_ts = utils.win_ts_to_unix_epoch(self.ts_high, self.ts_low)

        # the timestamp in the header is the last bit of the packet, convert it
        # to the first bit of the packet
        if self.rate > 0:
            pkt_duration = self.len * 8 / self.rate * 1e-6
            self.end_epoch_ts = self.epoch_ts
            self.epoch_ts -= pkt_duration
        else:
            self.end_epoch_ts = None

        self.fcs_error = (self.flags & 0x0002) > 0

    def to_phy(self):
        """Convert this to the standard :class:`pyparser.capture.common.PhyInfo`
        class.
        """
        kwargs = {}
        for attr in ['signal', 'noise', 'freq_mhz', 'fcs_error', 'rate', 'mcs',
                     'len', 'caplen', 'epoch_ts', 'end_epoch_ts']:
            kwargs[attr] = getattr(self, attr, None)
        kwargs['has_fcs'] = True
        return PhyInfo(**kwargs)


class PeektaggedCapture(WlTrace):
    """Peek-tagged capture file.

    Here we know the total number of packets beforehand from the "sess"
    section.  So this class has an extra ``total_packets`` attribute.
    """

    def __init__(self, path, *args, **kwargs):
        cls = self.__class__
        super(cls, self).__init__(path, *args, **kwargs)

        while True:
            sess = PeektaggedSectionHeader(self.fh)
            if sess.tag == 'pkts':
                break

            sess.payload = self.fh.read(sess.len)

            if sess.tag == PEEKTAGGED_FILE_MAGIC:
                root = ET.fromstring(sess.payload)
                if root.tag != 'VersionInfo':
                    raise PeektaggedException("Corrupted version info")

                for child in root:
                    setattr(self, child.tag, child.text)

            elif sess.tag == 'sess':
                root = ET.fromstring(sess.payload)
                for child in root:
                    if child.tag == 'PacketCount':
                        setattr(self, 'total_packets', int(child.text))
                        break

    def _next(self, n=100):
        if self.fh is None:
            return []

        pkts = []
        for unused in xrange(n):
            try:
                peektagged_header = PeektaggedPacketHeader(self.fh)

                pkt_raw = self.fh.read(peektagged_header.caplen)
                if len(pkt_raw) != peektagged_header.caplen:
                    break

                pkt = dot11.Dot11Packet(StringIO(
                    pkt_raw), phy=peektagged_header.to_phy(),
                    counter=self.counter)
                self.counter += 1
                pkts.append(pkt)
            except IOError:
                self.fh.close()
                self.fh = None
                break

        return pkts
