import os
import sys

TEST_ROOT = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(TEST_ROOT)
TEST_INPUT_DIR = os.path.join(TEST_ROOT, 'testing_inputs')

sys.path.insert(0, PROJECT_ROOT)

from wltrace import wltrace, dot11


def test_pcap():
    trace = wltrace.load_trace(os.path.join(TEST_INPUT_DIR, 'trace.pcap'))
    pkts = list(trace)

    assert len(pkts) == 318

    pkt = pkts[0]
    assert pkt.counter == 1

    # PHY
    assert pkt.phy.signal == -47
    assert pkt.phy.noise is None
    assert pkt.phy.freq_mhz == 5200
    assert pkt.phy.has_fcs
    assert not pkt.phy.fcs_error
    assert pkt.phy.len == 117
    assert pkt.phy.caplen == 117
    assert pkt.phy.rate == 6
    assert pkt.phy.mcs is None
    assert pkt.phy.mactime == 84523414517
    assert abs(pkt.phy.epoch_ts - 1474410869.121930000) < 1e-6
    assert (pkt.phy.end_epoch_ts - pkt.phy.epoch_ts)*6e6/8 == pkt.phy.len

    # MAC
    assert pkt.type == dot11.DOT11_TYPE_MANAGEMENT
    assert pkt.subtype == dot11.DOT11_SUBTYPE_BEACON
    assert not pkt.from_ds
    assert not pkt.to_ds
    assert not pkt.more_frag
    assert not pkt.rety
    assert not pkt.power
    assert not pkt.more_data
    assert not pkt.protected
    assert not pkt.order
    assert pkt.duration == 0
    assert dot11.is_broadcast(pkt.dest)
    assert pkt.src == '10:fe:ed:e5:8c:97'
    assert pkt.seq_num == 2651
