"""Packet trace parser.

This module can load a packet trace, and yields a sequence of packets.
Currently, only IEEE802.11 pakcet traces saved in Pcap or Omnipeek's peek-tagged
format are supported. For Pcap format, this module can parse the Radiotap header
if exists.
"""

import struct
import os
import binascii

import pcap
import peektagged

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


def load_file(path, *args, **kwargs):
    """Read a packet trace file, return a :class:`pyparser.capture.common.CaptureFile` object.

    No packet trace type is needed, this function will read the file's magic
    (first ``FILE_TYPE_HANDLER`` bytes), and automatically determine the
    file type, and call appropriate handler to process the file.

    Args:
        path (str): the file's path to be loaded.

    Returns:
        ``CaptureFile`` object.
    """
    with open(path, 'rb') as f:
        magic = f.read(MAGIC_LEN)
    if magic not in FILE_TYPE_HANDLER:
        raise Exception('Unknown file magic: %s' % (binascii.hexlify(magic)))

    return FILE_TYPE_HANDLER[magic](path, *args, **kwargs)
