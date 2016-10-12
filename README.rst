.. image:: https://travis-ci.org/jhshi/wltrace.svg?branch=master
    :target: https://travis-ci.org/jhshi/wltrace

.. image:: https://readthedocs.org/projects/wltrace/badge/?version=latest
    :target: http://wltrace.readthedocs.io/en/latest/?badge=latest
    :alt: Documentation Status

.. image:: https://coveralls.io/repos/github/jhshi/wltrace/badge.svg?branch=master
    :target: https://coveralls.io/github/jhshi/wltrace?branch=master


WlTrace: A Python Library to Pcap and Peektagged Packet Traces
==============================================================

Features
--------

- Support Pcap (w/ optical Radiotap header) and Peektagged format.
- Simple and easy to use interface


Installation
------------

You can install this package using ``pip``.

.. code-block:: bash

    $ pip install -U wltrace


Usage
-----


.. code-block:: python

    from wltrace import wltrace

    trace = wltrace.load_trace('/path/to/trace')
    for pkt in trace:
        # do stuff with pkt

See full documentation at http://wltrace.readthedocs.io.
