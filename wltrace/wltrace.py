"""Wireless Packet Trace

This module can load a packet trace, and yields a sequence of packets.
Currently, only IEEE 802.11 (aka Wifi) pakcet traces saved in Pcap or Omnipeek's
peek-tagged format are supported. For Pcap format, this module can parse the
Radiotap header if exists.
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

    Args:
        path (str): path to the trace file.

    Returns:
        bool: True if the file is a valid packet trace.
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
    """Read a packet trace file, return a :class:`wltrace.common.WlTrace` object.

    This function first reads the file's magic
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
