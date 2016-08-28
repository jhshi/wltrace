"""Common interfaces for :mod:`pyparser.capture` module.
"""

import struct


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


class CapturePacket(object):
    """A minimal packet wrapper which only contains the counter and timestamp.

    Many statistic information only need these two information. This is to let
    them discard the original packet, which could potentially be very large, and
    use this compact object instead, with the hope to reduce memory footprint.
    """

    def __init__(self, pkt):
        for attr in ['counter', 'ts', 'epoch_ts', 'seq_num', 'retry']:
            try:
                setattr(self, attr, getattr(pkt, attr))
            except:
                pass


class PhyInfo(object):
    """Packet PHY layer information.

    PHY information is usually provided in the format of physical layer header,
    such as Radiotap. PHY information includes:

    * signal (int): received RSSI in dBm.
    * noise (int): noise level in dBm.
    * freq_mhz (int): channel central frequency.
    * fcs_error (bool): True if this packet fails the FCS check.
    * timestamp (:class:`datetime.datetime`): timestamp when this packet was
      collected.
    * rate (int): packet modulation rate, in the unit of 500 Kbps. For example, if
      packet was sent at MCS 1 in 802.11n, that is, 13 Mbps, then this value is 26.
    * len (int): packet original length in bytes, including 4 FCS bytes.
    * caplen (int): actually stored bytes, probably smaller than ``len``.
    """

    def __init__(self, *args, **kwargs):
        for attr in ['signal', 'noise', 'freq_mhz', 'has_fcs', 'fcs_error', 'timestamp',
                     'rate', 'len', 'caplen', 'mactime', 'epoch_ts']:
            setattr(self, attr, kwargs.get(attr, None))
