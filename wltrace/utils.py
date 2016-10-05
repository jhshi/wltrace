"""Various utilitis for packet trace parsing.
"""
import datetime
import struct
import itertools
import binascii

UTC_EPOCH = datetime.datetime(1970, 1, 1)


def calc_padding(fmt, align):
    """Calculate how many padding bytes needed for ``fmt`` to be aligned to
    ``align``.

    Args:
        fmt (str): :mod:`struct` format.
        align (int): alignment (2, 4, 8, etc.)

    Returns:
        str: padding format (e.g., various number of 'x').

    >>> calc_padding('b', 2)
    'x'

    >>> calc_padding('b', 3)
    'xx'
    """
    remain = struct.calcsize(fmt) % align
    if remain == 0:
        return ""
    return 'x' * (align - remain)


def align_up(offset, align):
    """Align ``offset`` up to ``align`` boundary.

    Args:
        offset (int): value to be aligned.
        align (int): alignment boundary.

    Returns:
        int: aligned offset.

    >>> align_up(3, 2)
    4

    >>> align_up(3, 1)
    3
    """
    remain = offset % align
    if remain == 0:
        return offset
    else:
        return offset + (align - remain)


def win_ts_to_unix_epoch(high, low):
    """Convert Windows timestamp to POSIX timestamp.

    See https://goo.gl/VVX0nk

    Args:
        high (int): high 32 bits of windows timestamp.
        low (int): low 32 bits of windows timestamp.

    Returns:
        float
    """
    return high * ((2 ** 32) / 1e9) + low / 1e9 - 11644473600


def win_ts(high, low):
    """Convert Windows timestamp to Unix timestamp.

    Windows timestamp is a 64-bit integer, the value of which is the number of
    100 ns intervals from 1/1/1601-UTC.

    Args:
        high (int): high 32 bits of windows timestamp.
        low (int): low 32 bits of windows timestamp.

    Returns:
        Python timestamp (``datetime.datetime`` object).
    """
    return datetime.datetime.fromtimestamp(win_ts_to_unix_epoch(high, low))


def bin_to_mac(bin, size=6):
    """Convert 6 bytes into a MAC string.

    Args:
        bin (str): hex string of lenth 6.

    Returns:
        str: String representation of the MAC address in lower case.

    Raises:
        Exception: if ``len(bin)`` is not 6.
    """
    if len(bin) != size:
        raise Exception("Invalid MAC address: %s" % (bin))
    return ':'.join([binascii.hexlify(o) for o in bin])


def pairwise(it):
    a, b = itertools.tee(it)
    next(b, None)
    return itertools.izip(a, b)


def packet_gap(first, second):
    # this is the gap between arrival of first and second packet
    gap = (second.ts - first.ts).total_seconds()
    if first.phy.mactime is not None and second.phy.mactime is not None and\
            first.phy.rate is not None and second.phy.rate is not None:
        # account for the duration of first packet
        gap -= first.phy.len * 8 / first.phy.rate * 1e-6
    return gap
