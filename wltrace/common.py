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


class PhyInfo(object):
    """Packet PHY layer information.

    PHY information is usually provided in the format of physical layer header,
    such as Radiotap. PHY information includes:

    * signal (int): received RSSI in dBm.
    * noise (int): noise level in dBm.
    * freq_mhz (int): channel central frequency (MHz)
    * channel (int): channel number.
    * fcs_error (bool): True if this packet fails the FCS check.
    * epoch_ts (float): Unix timestamp of the first bit of this packet
    * end_epoc_ts (float): Unix timestamp of the last bit of this packet
    * mcs (int): MCS index (http://mcsindex.com/)
    * rate (float): packet modulation rate (Mbps)
    * len (int): packet original length in bytes, including 4 FCS bytes.
    * caplen (int): actually stored bytes, probably smaller than ``len``.
    # mactime: MAC layer TSF counter.
    """

    def __init__(self, *args, **kwargs):
        for attr in ['signal', 'noise', 'freq_mhz', 'has_fcs', 'fcs_error', 'epoch_ts',
                     'end_epoch_ts', 'rate', 'mcs', 'len', 'caplen',
                     'mactime']:
            setattr(self, attr, kwargs.get(attr, None))
