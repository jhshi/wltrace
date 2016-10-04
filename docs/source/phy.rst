PHY Information
===============

These attributes are available in the ``PhyInfo`` object.

- ``signal``: RSSI in dBm

- ``noise``: noise level in dBm

- ``freq_mhz``

- ``has_fcs``

- ``fcs_error``

- ``epoch_ts``, ``end_epoch_ts``: POSIX timestamp of the first and last bit of
  the packet

- ``rate``: bit rate in Mbps

- ``mcs``: `MCS index <http://mcsindex.com/>`_

- ``len``: length of the packet, not including any PHY header such as Radiotap
  header.

- ``caplen``: number of bytes actually captured.

- ``mactime``: MAC layer TSF count, 64 bit integer.

- ``ampdu_ref``: AMPDU reference number if this packet was sent in a AMPDU

- ``last_ampdu``: whether this packet was the last packet in the AMPDU.
