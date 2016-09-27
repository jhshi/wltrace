import os
import sys

from wltrace import wltrace

PROJECT_ROOT = os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))))
TEST_INPUT_DIR = os.path.join(PROJECT_ROOT, 'testing_inputs')


def test_one_packet():
    trace = wltrace.load_trace(os.path.join(TEST_INPUT_DIR, 'trace.pcap'))
    pkt = trace.next()

    assert pkt.counter == 1
    assert pkt.phy.mactime == 84523414517
    assert pkt.phy.has_fcs
    assert not pkt.phy.fcs_error
    assert pkt.phy.rate == 6
    assert pkt.phy.freq_mhz == 5200
    assert abs(pkt.epoch_ts - 1474410869.121930000) < 1e-6
