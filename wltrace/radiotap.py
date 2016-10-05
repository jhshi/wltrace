"""Radiotap header parser.
"""
import struct
import binascii


import common
import utils

import dot11

_IT_VERSION = 0

_CHANNEL_FLAG_TURBO = 0x0010
_CHANNEL_FLAG_CCK = 0x0020
_CHANNEL_FLAG_OFDM = 0x0040
_CHANNEL_FLAG_2GHZ = 0x0080
_CHANNEL_FLAG_5GHZ = 0x0100
_CHANNEL_FLAG_PASSIVE_ONLY = 0x0200
_CHANNEL_FLAG_DYNAMIC = 0x0400
_CHANNEL_FLAG_GFSK = 0x0800

_FLAG_HAS_FCS = 0x10
_FLAG_FCS_ERROR = 0x40

_MCS_KNOWN_BANDWIDTH = 0x01
_MCS_KNOWN_MCS = 0x02
_MCS_KNOWN_GI = 0x04
_MCS_KNOWN_HT = 0x08

_MCS_FLAG_BANDWIDTH = 0x03
_MCS_FLAG_GI = 0x04
_MCS_FLAG_HT = 0x08

_PRESENT_FLAG_TSFT = 1 << 0
_PRESENT_FLAG_FLAG = 1 << 1
_PRESENT_FLAG_RATE = 1 << 2
_PRESENT_FLAG_CHANNEL = 1 << 3
_PRESENT_FLAG_SIGNAL = 1 << 5
_PRESENT_FLAG_NOISE = 1 << 6
_PRESENT_FLAG_MCS = 1 << 19
_PRESENT_FLAG_AMPDU = 1 << 20


class RadiotapHeader(common.GenericHeader):
    """Radiotap header.

    See this document for radiotap header format:
    http://www.radiotap.org/

    See this document for all defined radiotap fields:
    http://www.radiotap.org/defined-fields/all
    """

    PACK_PATTERN = '<BBHI'
    """Radiotap header is always in little endian.
    """
    FIELDS = [
        '_it_version',
        '_it_pad',
        '_it_len',
        '_it_present',
    ]

    PRESENT_FLAGS = [
        # (idx, unpack_fmt, field, align)
        (0, 'Q', 'mactime', 8),
        (1, 'B', '_flags', 1),
        (2, 'B', 'rate', 1),
        (3, 'I', '_channel', 2),
        (4, 'xx', 'unused', 1),
        (5, 'b', 'signal', 1),
        (6, 'b', 'noise', 1),
        (7, 'xx', 'unused', 2),
        (8, 'xx', 'unused', 2),
        (9, 'xx', 'unused', 2),
        (10, 'x', 'unused', 1),
        (11, 'x', 'unused', 1),
        (12, 'x', 'unused', 1),
        (13, 'x', 'unused', 1),
        (14, 'xx', 'unused', 2),
        (19, 'bbb', 'mcs', 1),
        (20, 'IHxx', '_ampdu', 4),
    ]

    def __init__(self, fh, *args, **kwargs):
        cls = self.__class__
        super(cls, self).__init__(fh, *args, **kwargs)

        if self._it_version != _IT_VERSION:
            raise Exception('Incorrect version: expect %d, got %d' %
                            (cls._it_version, self._it_version))

        rest_len = self._it_len - struct.calcsize(cls.PACK_PATTERN)
        rest = fh.read(rest_len)
        if len(rest) != rest_len:
            raise Exception('Short read: expect %d, got %d' %
                            (rest_len, len(rest)))

        offset = 0
        present = self._it_present
        while (present >> 31) > 0:
            present, = struct.unpack_from('<I', rest, offset)
            offset += 4
            self._it_present = (present << (offset*8)) + self._it_present

        for idx, fmt, field, align in cls.PRESENT_FLAGS:
            if self._it_present & (1 << idx):
                offset = utils.align_up(offset, align)
                val = struct.unpack_from(fmt, rest, offset)
                if len(val) == 1:
                    val = val[0]
                setattr(self, field, val)
                offset += struct.calcsize(fmt)
            else:
                setattr(self, field, None)

        if self._it_present & _PRESENT_FLAG_CHANNEL:
            self.freq_mhz = self._channel & 0x0000ffff
            self.freq_flag = self._channel >> 16
        else:
            self.freq_mhz = None
            self.freq_flag = None

        if self._it_present & _PRESENT_FLAG_FLAG:
            self.has_fcs = self._flags & _FLAG_HAS_FCS
            self.fcs_error = self._flags & _FLAG_FCS_ERROR
        else:
            self.has_fcs = False
            self.fcs_error = None

        if self._it_present & _PRESENT_FLAG_RATE:
            self.rate /= 2.0

        if self._it_present & _PRESENT_FLAG_MCS:
            mcs_known, mcs_flags, self.mcs = self.mcs
            if mcs_flags & 0x3 in [0, 2, 3]:
                bw = 20
            else:
                bw = 40
            long_gi = (mcs_flags & 0x4) == 0
            self.rate = dot11.mcs_to_rate(self.mcs, bw, long_gi)

        if self._it_present & _PRESENT_FLAG_AMPDU:
            self.ampdu_ref, ampdu_flag = self._ampdu
            self.last_frame = ampdu_flag & 0x8 > 0

    @classmethod
    def from_phy_info(cls, phy):
        header = cls()
        header.freq_mhz = phy.freq_mhz
        if header.freq_mhz < 3000:
            header.freq_flag = _CHANNEL_FLAG_2GHZ | _CHANNEL_FLAG_OFDM
        else:
            header.freq_flag = _CHANNEL_FLAG_5GHZ | _CHANNEL_FLAG_OFDM
        header._channel = (header.freq_flag << 16) + header.freq_mhz

        header._flags = _FLAG_HAS_FCS
        if phy.fcs_error:
            header._flags |= _FLAG_FCS_ERROR

        if phy.rate < 256:
            header.rate = phy.rate

        header.epoch_ts = phy.epoch_ts
        header.len = phy.len
        header.caplen = phy.caplen
        return header

    def to_phy(self):
        return common.PhyInfo(**self.__dict__)

    def to_binary(self):
        cls = self.__class__

        offset = 0
        present_flag = 0
        payload = ''

        for idx, fmt, field, align in cls.PRESENT_FLAGS:
            if getattr(self, field, None) is None:
                continue
            present_flag |= (1 << idx)
            aligned_offset = utils.align_up(offset, align)
            if aligned_offset != offset:
                fmt = '%s%s' % ('x' * (aligned_offset - offset), fmt)
            try:
                attr = getattr(self, field)
                if type(attr) != tuple:
                    attr = (attr, )
                payload += struct.pack(fmt, *attr)
            except:
                raise Exception('%s: %s' % (field, getattr(self, field)))
            offset += struct.calcsize(fmt)

        header = struct.pack(cls.PACK_PATTERN, 0, 0,
                             struct.calcsize(cls.PACK_PATTERN) + len(payload),
                             present_flag)
        return header + payload
