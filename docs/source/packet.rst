Dot11Packet
===========

``wltrace.load_trace`` returns a iterator over ``Dot11Packet`` objects. The
following attributes of ``Dot11Packet`` are available.

802.11 Attributes
-----------------

- ``type``: int

- ``subtype``: int

- Flags (boolean): ``to_ds``, ``from_ds``, ``more_frag``, ``retry``, ``power``,
  ``more_data``, ``protected``, ``order``

- ``addr1``, ``addr2``, ``addr3``, ``addr4``: these are the MAC address in
  ``11:22:33:aa:bb:cc`` format.

- ``src``: alias to ``addr2``

- ``dest``: alias to ``addr1``


Packet Trace Attributes
-----------------------

- ``counter``: an integer index of this packet in the trace, starts from 1.

- ``ts``, ``end_ts``: Python ``datetime`` object representation the first and
  last bit of the packet.

- ``epoch_ts``, ``end_epoch_ts``: POSIX timestamp (float) of the first and last
  bit of the packet.

- ``hash``: a hex digest of the MD5 hash of the packet raw bytes.


PHY Information
---------------

- ``phy``: a ``PhyInfo`` object containing various PHY layer information. See
  :doc:`phy` for details.


Inferred Information
--------------------

- ``acked``: boolean, whether this packet is acknowledged or not. Only valid for
  non-broadcast packets.

- ``ack_pkt``: reference of the acknowledged packet.

