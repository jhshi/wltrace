import os

from wltrace import wltrace
from wltrace import dot11

PROJECT_ROOT = os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))))
TEST_INPUT_DIR = os.path.join(PROJECT_ROOT, 'testing_inputs')


def test_pcap():
    trace = wltrace.load_trace(os.path.join(TEST_INPUT_DIR, 'trace.pcap'))
    pkts = list(trace)

    assert len(pkts) == 318

    pkt = pkts[0]

    # PHY
    assert pkt.counter == 1
    assert pkt.phy.mactime == 84523414517
    assert pkt.phy.has_fcs
    assert not pkt.phy.fcs_error
    assert pkt.phy.rate == 6
    assert pkt.phy.freq_mhz == 5200
    assert abs(pkt.epoch_ts - 1474410869.121930000) < 1e-6
    assert pkt.phy.len == 117
    assert pkt.phy.caplen == 117

    # MAC
    assert pkt.type == dot11.DOT11_TYPE_MANAGEMENT
    assert pkt.subtype == dot11.DOT11_SUBTYPE_BEACON
    assert pkt.duration == 0
    assert dot11.is_broadcast(pkt.dest)
    assert pkt.src == '10:fe:ed:e5:8c:97'
    assert pkt.seq_num == 2651
