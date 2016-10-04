Quick Start
===========

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
