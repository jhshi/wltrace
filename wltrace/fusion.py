#!/usr/bin/env python

import argparse
import datetime

from collections import OrderedDict
import numpy as np

import progressbar as pbar

import dot11
import wltrace
import pcap
import utils

import logging
logging.basicConfig(
    format='[%(asctime)s] %(levelname)s [%(filename)11s:%(lineno)4d]'
    ' %(message)s',
    level=logging.DEBUG)
logger = logging.getLogger('pyparser')


def arg_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('--traces', nargs='+', required=True,
                        help="Traces to fusion.")
    parser.add_argument('--out', required=True, help="Output trace.")
    parser.add_argument('--verbose', action='store_true',
                        help="Verbose output.")
    return parser


class Aggregator(object):

    def __init__(self, trace1, trace2, verbose=False, *args, **kwargs):
        self.trace1 = trace1
        self.trace2 = trace2
        self.merged_trace = []
        self.drifts = []
        self.verbose = verbose

    def do_aggregate(self):
        if not isinstance(self.trace1, list):
            self.trace1 = list(self.trace1)
        if not isinstance(self.trace2, list):
            self.trace2 = list(self.trace2)

        hash1 = OrderedDict((p.hash, p) for p in self.trace1
                            if dot11.is_beacon(p) and p.phy.mactime is not None)
        hash2 = OrderedDict((p.hash, p) for p in self.trace2
                            if dot11.is_beacon(p) and p.phy.mactime is not None)
        common_hash = [h for h in hash1 if h in hash2]

        if self.verbose:
            logger.debug("Beacons:: Trace1: %d, Trace2: %d, Common: %d" %
                         (len(hash1), len(hash2), len(common_hash)))

        if len(common_hash) < 2:
            logger.warning("Less than 2 common beacons, can not merge.")
            self.merged_trace = self.trace1

        base_mactime = hash1[common_hash[0]].phy.mactime
        base_ts = hash1[common_hash[0]].ts

        widgets = [pbar.Percentage(), pbar.Bar(), pbar.ETA()]
        bar = pbar.ProgressBar(widgets=widgets, maxval=len(common_hash))
        if self.verbose:
            progress = 0
            bar.start()

        for first_beacon, second_beacon in utils.pairwise(common_hash):
            t1_a, t2_a = hash1[first_beacon].phy.mactime, hash1[
                second_beacon].phy.mactime
            t1_b, t2_b = hash2[first_beacon].phy.mactime, hash2[
                second_beacon].phy.mactime
            duration = t2_a - t1_a
            ratio = float(duration) / (t2_b - t1_b)
            drift = (t2_b - t1_b) - (t2_a - t1_a)
            self.drifts.append((duration, drift))

            for p in self.trace2[hash2[first_beacon].counter:
                                 (hash2[second_beacon].counter - 1)]:
                if p.phy.mactime is not None:
                    p.phy.mactime = int(ratio * (p.phy.mactime - t1_b) + t1_a)

            self.merged_trace.append(hash1[first_beacon])
            for pkt in sorted(
                    self.trace1[hash1[first_beacon].counter:
                                (hash1[second_beacon].counter - 1)] +
                    self.trace2[hash2[first_beacon].counter:(
                        hash2[second_beacon].counter - 1)],
                    key=lambda p: p.phy.mactime):
                if pkt.phy.mactime is None:
                    continue
                if (pkt.phy.mactime - self.merged_trace[-1].phy.mactime) < 5\
                        and pkt.hash == self.merged_trace[-1].hash:
                    continue
                self.merged_trace.append(pkt)

            if self.verbose:
                bar.update(progress)
                progress += 1

        self.merged_trace.append(hash1[common_hash[-1]])
        if self.verbose:
            bar.finish()
            intervals = [t[0] for t in self.drifts]
            drifts = [t[1] for t in self.drifts]
            logger.debug("Intervals: %d, min: %d, max: %d, mean: %d" %
                         (len(intervals), min(intervals), max(intervals),
                          np.mean(intervals)))
            logger.debug("drifts: %d, min: %d, max: %d, mean: %d" %
                         (len(drifts), min(drifts), max(drifts),
                          np.mean(drifts)))
            logger.debug("Trace1: %d, Trace2: %d, Merged: %d" %
                         (len(self.trace1), len(self.trace2),
                          len(self.merged_trace)))

        # adjust packet timestamp and counter
        for c, p in enumerate(self.merged_trace, start=1):
            p.ts = base_ts + \
                datetime.timedelta(microseconds=(p.phy.mactime - base_mactime))
            p.counter = c


def main():
    args = arg_parser().parse_args()
    traces = [wltrace.load_file(p, aggregate_ack=False) for p in args.traces]
    fused = traces[0]
    logger.debug("Starting with %s" % (traces[0].path))
    for t in traces[1:]:
        logger.debug("Merging %s" % (t.path))
        a = Aggregator(fused, t, verbose=args.verbose)
        a.do_aggregate()
        fused = a.merged_trace
    pcap.PcapCapture.save(args.out, fused)


if __name__ == '__main__':
    main()
