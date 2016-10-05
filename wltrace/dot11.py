"""IEEE802.11 protocol definitions and utilities.
"""

import struct
import datetime
import math
import binascii
import hashlib

from common import GenericHeader, PhyInfo
import utils


class Dot11Exception(Exception):
    pass


DOT11_TYPE_MANAGEMENT = 0
DOT11_TYPE_CONTROL = 1
DOT11_TYPE_DATA = 2
DOT11_TYPE_RSVD = 3


DOT11_SUBTYPE_ASSOC_REQ = 0
DOT11_SUBTYPE_ASSOC_RESP = 1
DOT11_SUBTYPE_REASSOC_REQ = 2
DOT11_SUBTYPE_REASSOC_RESP = 3
DOT11_SUBTYPE_PROBE_REQ = 4
DOT11_SUBTYPE_PROBE_RESP = 5
DOT11_SUBTYPE_RSVD = 7
DOT11_SUBTYPE_BEACON = 8
DOT11_SUBTYPE_DISASSOC = 10
DOT11_SUBTYPE_AUTH = 11
DOT11_SUBTYPE_DEAUTH = 12

DOT11_SUBTYPE_BLOCK_ACK = 9
DOT11_SUBTYPE_ACK = 0xd

DOT11_SUBTYPE_DATA = 0
DOT11_SUBTYPE_NULL = 4
DOT11_SUBTYPE_QOS_DATA = 8
DOT11_SUBTYPE_QOS_NULL = 0xc

MAX_ACK_LATENCY_US = 100
"""Maximum allowed gap between a packet and its ack in the packet trace.
"""

SEQ_NUM_MODULO = 4096

MGMT_SUBTYPE_NAMES = {
    0: 'Assoc Req',
    1: 'Assoc Resp',
    2: 'Reassoc Req',
    3: 'Reassoc Resp',
    4: 'Probe Req',
    5: 'Probe Resq',
    6: 'Timing Adv',
    7: 'Rsvd',
    8: 'Beacon',
    9: 'ATIM',
    10: 'Disassoc',
    11: 'Auth',
    12: 'Deauth',
    13: 'Action',
    14: 'Action no Ack',
    15: 'Rsvd',
}

CTRL_SUBTYPE_NAMES = {
    0: 'Rsvd',
    1: 'Rsvd',
    2: 'Rsvd',
    3: 'Rsvd',
    4: 'Rsvd',
    5: 'Rsvd',
    6: 'Rsvd',
    7: 'Ctrl wrapper',
    8: 'Block Ack req',
    9: 'Block Ack',
    10: 'PS-Poll',
    11: 'RTS',
    12: 'CTS',
    13: 'Ack',
    14: 'CF-End',
    15: 'CF-End + CF-Ack',
}

DATA_SUBTYPE_NAMES = {
    0: 'Data',
    1: 'Data + CF-Ack',
    2: 'Data + CF-Poll',
    3: 'Data + CF-Ack + CF-Poll',
    4: 'Null',
    5: 'CF-Ack',
    6: 'CF-Poll',
    7: 'CF-Ack + CF-Poll',
    8: 'QoS Data',
    9: 'Qos Data + CF-Ack',
    10: 'QoS Data + CF-Poll',
    11: 'QoS Data + CF-Poll + CF-Ack',
    12: 'QoS Null',
    13: 'Rsvd',
    14: 'QoS CF-Poll',
    15: 'QoS CF-Ack + CF-Poll',
}


MCS_TABLE = {
    # http://mcsindex.com
    # MCS: [20MHz-LGI, 20MHz-SGI, 40MHz-LGI, 40MHz-SGI,...]
    0: [6.5, 7.2, 13.5, 15, 29.3, 32.5, 58.5, 65],
    1: [13, 14.4, 27, 30, 58.5, 65, 117, 130],
    2: [19.5, 21.7, 40.5, 45, 87.8, 97.5, 175.5, 195],
    3: [26, 28.9, 54, 60, 117, 130, 234, 260],
    4: [39, 43.3, 81, 90, 175.5, 195, 351, 390],
    5: [52, 57.8, 108, 120, 234, 260, 468, 520],
    6: [58.5, 65, 121.5, 135, 263.3, 292.5, 526.5, 585],
    7: [65, 72.2, 135, 150, 292.5, 325, 585, 650],
    8: [13, 14.4, 27,  30,  58.5, 65,  117, 130],
    9: [26, 28.9, 54, 60, 117, 130, 234, 260],
    10: [39, 43.3, 81, 90, 175.5, 195, 351, 390],
    11: [52, 57.8, 108, 120, 234, 260, 468, 520],
    12: [78, 86.7, 162, 180, 351, 390, 702, 780],
    13: [104, 115.6, 216, 240, 468, 520, 936, 1040],
    14: [117, 130.3, 243, 270, 526.5, 585, 1053, 1170],
    15: [130, 144.4, 270, 300, 585, 650, 1170, 1300],
}


def mcs_to_rate(mcs, bw=20, long_gi=True):
    """Convert MCS index to rate in Mbps.

    See http://mcsindex.com/

    Args:
        mcs (int): MCS index
        bw (int): bandwidth, 20, 40, 80, ...
        long_gi(bool): True if long GI is used.

    Returns:
        rate (float): bitrate in Mbps


    >>> mcs_to_rate(5, bw=20, long_gi=False)
    57.8

    >>> mcs_to_rate(4, bw=40, long_gi=True)
    81

    >>> mcs_to_rate(3, bw=80, long_gi=False)
    130

    >>> mcs_to_rate(13, bw=160, long_gi=True)
    936
    """
    if bw not in [20, 40, 80, 160]:
        raise Exception("Unknown bandwidth: %d MHz" % (bw))
    if mcs not in MCS_TABLE:
        raise Exception("Unknown MCS: %d" % (mcs))

    idx = int((math.log(bw/10, 2)-1)*2)
    if not long_gi:
        idx += 1
    return MCS_TABLE[mcs][idx]


def rate_to_mcs(rate, bw=20, long_gi=True):
    """Convert bit rate to MCS index.

    Args:
        rate (float): bit rate in Mbps
        bw (int): bandwidth, 20, 40, 80, ...
        long_gi (bool): True if long GI is used.

    Returns:
        mcs (int): MCS index

    >>> rate_to_mcs(120, bw=40, long_gi=False)
    5
    """
    if bw not in [20, 40, 80, 160]:
        raise Exception("Unknown bandwidth: %d MHz" % (bw))
    idx = int((math.log(bw/10, 2)-1)*2)
    if not long_gi:
        idx += 1

    for mcs, rates in MCS_TABLE.items():
        if abs(rates[idx] - rate) < 1e-3:
            return mcs

    raise Exception("MCS not found: rate=%f, bw=%d, long_gi=%s" %
                    (rate, bw, long_gi))


def is_broadcast(mac):
    """Whether or not a mac is broadcast MAC address.

    Args:
        mac (str): MAC address in string format (``xx:xx:xx:xx:xx:xx``). Case
          insensitive.
    Returns:
        bool.
    """
    return mac.lower() == 'ff:ff:ff:ff:ff:ff'


def is_multicast(mac):
    """Whether a MAC address is IPV4/V6 multicast address.

    See https://en.wikipedia.org/wiki/Multicast_address#Ethernet

    ARgs:
        mac (str): MAC address

    Returns:
        bool

    >>> is_multicast('01:80:C2:00:00:08')
    True

    """
    octet = int(mac.split(':')[0], base=16)
    return octet & 0x01 > 0


def is_lowest_rate(rate):
    """Whether or not the rate is the lowest rate in rate table.

    Args:
        rate (int): rate in Mbps . Can be 802.11g/n rate.

    Returns:
        bool: ``True`` if the rate is lowest, otherwise ``False``. Note that if
        ``rate`` is not valid, this function returns ``False``, instead of
        raising an exception.
    """
    return rate_to_mcs(rate) == 0


def is_highest_rate(rate):
    """Whether or not the rate is the highest rate (single spatial stream) in
    rate table.

    Args:
        rate (int): rate in Mbps. Can be 802.11g/n rate.

    Returns:
        bool: ``True`` if the rate is highest, otherwise ``False``. Note that if
        ``rate`` is not valid, this function returns ``False``, instead of
        raising an exception.
    """
    return rate_to_mcs(rate) == 7


def is_ack(pkt):
    """Whether or not the packet is an ack packet.

    Args:
        pkt (:class:`wltrace.dot11.Dot11Packet`): the packet.

    Returns:
        bool: ``True`` if it is an ack packet, otherwise ``False``.

    """
    return pkt.type == DOT11_TYPE_CONTROL and pkt.subtype == DOT11_SUBTYPE_ACK


def is_block_ack(pkt):
    """Whether a packet is a Block Ack packet.
    """
    return pkt.type == DOT11_TYPE_CONTROL and\
        pkt.subtype == DOT11_SUBTYPE_BLOCK_ACK


def is_beacon(pkt):
    """Whether a packet is a Beacon packet.
    """
    return pkt.type == DOT11_TYPE_MANAGEMENT and\
        pkt.subtype == DOT11_SUBTYPE_BEACON


def is_qos_data(pkt):
    """Whether a packet is a QoS Data packet.
    """
    return pkt.type == DOT11_TYPE_DATA and pkt.subtype == DOT11_SUBTYPE_QOS_DATA


def next_seq(seq):
    """Next sequence number.

    Args:
        seq (int): current sequence number

    Returns:
        int: next sequence number, may wrap around

    >>> next_seq(3)
    4

    >>> next_seq(4095)
    0
    """
    return (seq + 1) % SEQ_NUM_MODULO


class Beacon(object):
    """Payload for 802.11 Beacon packet.
    """

    def __init__(self, pkt):
        self.timestamp, self.interval, self.capabilities = pkt.unpack('<QHH')
        tag, len = pkt.unpack('<BB')
        if tag == 0:
            self.ssid, = pkt.unpack('<%ds' % (len))


class Dot11Packet(GenericHeader):
    """IEEE802.11 packet.

    This class parse as much as possible depending on the packet type and
    subtype.

    Args:
        fh (file object): the file's read pointer points to the beginning of a
          802.11 packet.
        phy (:class:`pyparser.capture.common.PhyInfo`): PHY information.
        counter (int): packet index in trace file, starting from 1.
    """

    PACK_PATTERN = '<HH6s'
    FIELDS = [
        'fc',
        'duration',
        'addr1'
    ]

    def parse_mgmt(self):
        self.addr2, self.addr3, self.seq = self.unpack('<6s6sH')
        if self.order:
            self.ht, = self.unpack('<I')

        if self.subtype == DOT11_SUBTYPE_BEACON:
            try:
                self.beacon = Beacon(self)
            except:
                pass

    def parse_data(self):
        self.addr2, self.addr3, self.seq = self.unpack('<6s6sH')
        if self.from_ds and self.to_ds:
            self.addr4, = self.unpack('<6s')
        if self.subtype >= 8:
            self.qos, = self.unpack('<H')

    def parse_control(self):
        if self.subtype == DOT11_SUBTYPE_BLOCK_ACK:
            self.addr2, ba_control = self.unpack('<6sH')
            self.ba_tid = ba_control >> 12
            self.ba_compressed = ba_control & 0x0004 > 0
            self.ba_multi_tid = ba_control & 0x0002 > 0
            self.ba_policy = ba_control & 0x0001 > 0

            if not self.ba_multi_tid and self.ba_compressed:
                ba_seq_control, self.ba_bitmap = self.unpack('<HQ')
                self.ba_begin_seq = ba_seq_control >> 4
                self.ba_begin_frag = ba_seq_control & 0x000f

    def __init__(self, fh=None, phy=None, counter=1, *args, **kwargs):
        if fh is None:
            self.real = False
            for k, v in kwargs.items():
                setattr(self, k, v)
            self.phy = PhyInfo()
            return

        packet_start = fh.tell()

        cls = self.__class__
        super(cls, self).__init__(fh, *args, **kwargs)

        self.real = True
        self.phy = phy
        self.counter = counter

        self.acked = False
        self.ack_pkt = None

        self.type = (self.fc & 0x000c) >> 2
        self.subtype = (self.fc & 0x00f0) >> 4
        for shift, flag in enumerate(['to_ds', 'from_ds', 'more_frag', 'retry',
                                      'power', 'more_data', 'protected',
                                      'order'], start=8):
            setattr(self, flag, (self.fc & (1 << shift)) > 0)

        self.payload = fh.read()
        self.offset = 0

        if self.type == DOT11_TYPE_MANAGEMENT:
            self.parse_mgmt()
        elif self.type == DOT11_TYPE_DATA:
            self.parse_data()
        elif self.type == DOT11_TYPE_CONTROL:
            try:
                self.parse_control()
            except:
                pass

        for attr in ['addr1', 'addr2', 'addr3', 'addr4']:
            if hasattr(self, attr):
                setattr(self, attr, utils.bin_to_mac(getattr(self, attr)))

        if hasattr(self, 'seq'):
            self.frag_num = self.seq & 0x000f
            self.seq_num = (self.seq & 0xfff0) >> 4
            del self.seq
        else:
            self.seq_num = None
            self.frag_num = None

        fh.seek(packet_start)
        self.raw = fh.read()
        self._hash = None

        fh.close()

    @property
    def src(self):
        """Shortcut to ``pkt.addr2``.
        """
        return getattr(self, 'addr2', None)

    @src.setter
    def src(self, val):
        self.addr2 = val

    @property
    def dest(self):
        """Shortcut to ``pkt.addr1``.
        """
        return getattr(self, 'addr1', None)

    @dest.setter
    def dest(self, val):
        self.addr1 = val

    @property
    def ts(self):
        """Shortcut to ``pkt.phy.timestamp``.
        """
        return datetime.datetime.fromtimestamp(self.phy.epoch_ts)

    @property
    def end_ts(self):
        return datetime.datetime.fromtimestamp(self.phy.end_epoch_ts)

    @property
    def epoch_ts(self):
        return self.phy.epoch_ts

    @property
    def end_epoch_ts(self):
        return self.phy.end_epoch_ts

    @property
    def hash(self):
        if self._hash is None:
            self._hash = hashlib.md5(self.raw).hexdigest()
        return self._hash

    def __eq__(self, other):
        if not isinstance(other, Dot11Packet):
            return False
        return self.hash == other.hash

    def air_time(self):
        """Duration of the packet in air.

        Returns:
            float: duration in seconds.
        """
        return self.phy.len * 8 / self.phy.rate * 1e-6
