import os
import sys
import pytest

TEST_ROOT = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(TEST_ROOT)
TEST_INPUT_DIR = os.path.join(TEST_ROOT, 'testing_inputs')

sys.path.insert(0, PROJECT_ROOT)

from wltrace import wltrace, dot11


def test_pcap():
    path = os.path.join(TEST_INPUT_DIR, 'trace.pcap')
    assert wltrace.is_packet_trace(path)

    trace = wltrace.load_trace(path)
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
    assert pkt.phy.epoch_ts == pytest.approx(1474410869.121930000)
    assert (pkt.phy.end_epoch_ts - pkt.air_time()) ==\
        pytest.approx(pkt.phy.epoch_ts)
    assert pkt.phy.ampdu_ref is None
    assert pkt.phy.last_frame

    # MAC
    assert pkt.type == dot11.DOT11_TYPE_MANAGEMENT
    assert pkt.subtype == dot11.DOT11_SUBTYPE_BEACON
    assert not pkt.from_ds
    assert not pkt.to_ds
    assert not pkt.more_frag
    assert not pkt.retry
    assert not pkt.power
    assert not pkt.more_data
    assert not pkt.protected
    assert not pkt.order
    assert pkt.duration == 0
    assert dot11.is_broadcast(pkt.dest)
    assert pkt.src == '10:fe:ed:e5:8c:97'
    assert pkt.seq_num == 2651
    assert pkt.frag_num == 0

    assert pkt.crc_ok


def test_pkt():
    path = os.path.join(TEST_INPUT_DIR, 'trace.pkt')
    assert wltrace.is_packet_trace(path)

    trace = wltrace.load_trace(path)
    pkts = list(trace)

    assert len(pkts) == 10

    pkt = pkts[0]
    assert pkt.counter == 1

    # PHY
    assert pkt.phy.signal == -77
    assert pkt.phy.noise == -91
    assert pkt.phy.freq_mhz == 5825
    assert pkt.phy.has_fcs
    assert not pkt.phy.fcs_error
    assert pkt.phy.len == 450
    assert pkt.phy.caplen == 60
    assert pkt.phy.rate == 65
    assert pkt.phy.mcs is None
    assert pkt.phy.mactime is None
    assert pkt.phy.epoch_ts == pytest.approx(1463018844.098017400)
    assert (pkt.phy.end_epoch_ts - pkt.air_time()) ==\
        pytest.approx(pkt.phy.epoch_ts)

    # MAC
    assert pkt.type == dot11.DOT11_TYPE_DATA
    assert pkt.subtype == dot11.DOT11_SUBTYPE_QOS_DATA
    assert not pkt.from_ds
    assert pkt.to_ds
    assert not pkt.more_frag
    assert not pkt.retry
    assert pkt.power
    assert not pkt.more_data
    assert pkt.protected
    assert not pkt.order
    assert pkt.duration == 160
    assert pkt.dest == '62:45:b0:fd:d3:ba'
    assert pkt.src == '7e:ed:8c:b4:95:28'
    assert pkt.seq_num == 3739
    assert pkt.frag_num == 0

    # acknowledgement
    assert pkt.acked
    assert pkt.ack_pkt is not None
    assert pkt.ack_pkt.counter == 2


def test_non_radiotap():
    path = os.path.join(TEST_INPUT_DIR, 'non_radiotap.pcap')
    assert wltrace.is_packet_trace(path)

    trace = wltrace.load_trace(path)
    pkts = list(trace)

    assert len(pkts) == 2001
