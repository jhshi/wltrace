from wltrace import dot11


class CaptureQuality(object):

    @property
    def missing_tx_count(self):
        if not hasattr(self, '_missing_tx_count'):
            self._missing_tx_count = 0
        return self._missing_tx_count

    @missing_tx_count.setter
    def missing_tx_count(self, val):
        diff = val - self._missing_tx_count
        assert diff >= 0
        self._missing_tx_count = val
        self.tx_count += diff

    @property
    def missing_ack_count(self):
        if not hasattr(self, '_missing_ack_count'):
            self._missing_ack_count = 0
        return self._missing_ack_count

    @missing_ack_count.setter
    def missing_ack_count(self, val):
        diff = val - self._missing_ack_count
        assert diff >= 0
        self._missing_ack_count = val
        self.ack_count += diff

    def __init__(self, cap, ta, ra, *args, **kwargs):
        self.tx_pkts_count = 0
        self.ack_count = 0

        self.dangling_ack = []
        self.missing_ack = []
        self.missing_seq = []

        last_data_pkt = None

        for pkt in cap:
            if pkt.phy.fcs_error:
                continue

            if pkt.type == dot11.DOT11_TYPE_DATA:
                if not (pkt.src == self.ta and pkt.dest == self.ra):
                    continue
            if dot11.is_ack(pkt):
                if pkt.dest != self.ta:
                    continue

            if pkt.acked or dot11.is_ack(pkt):
                self.ack_count += 1

            if dot11.is_ack(pkt):
                self.dangling_ack.append(pkt.counter)
                # missed the data packet
                self.missing_tx_count += 1
            else:
                self.tx_pkts_count += 1

                if last_data_pkt is None and pkt.retry:
                    # missed the first transmission
                    self.missing_tx_count += 1

                if last_data_pkt is not None:
                    seq_diff = (pkt.seq_num - last_data_pkt.seq_num +
                                dot11.SEQ_NUM_MODULO) % dot11.SEQ_NUM_MODULO
                    if seq_diff > 0:
                        self.missing_tx_count += seq_diff - 1
                        if seq_diff > 1:
                            self.missing_seq.append(last_data_pkt.counter)
                        if pkt.retry:
                            # missed the first transmission
                            self.missing_tx_count += 1
                        if not last_data_pkt.acked and not\
                                dot11.is_lowest_rate(last_data_pkt.phy.rate):
                            self.missing_ack_count += 1
                            self.missing_ack.append(last_data_pkt.counter)

                last_data_pkt = pkt
