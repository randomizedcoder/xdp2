#!/usr/bin/env python3
# dist_metrics2.py — flow-hash distribution metrics (expanded).
# Reads `test_parser -c flowdis -o text -H` output. Buckets model any
# hash-mod-N consumer (RSS table, RPS/RFS CPU map, ECMP nexthops, LAG members).
# Adds realistic bucket counts and a load-imbalance (max/mean) ratio — the
# "hot queue/path" factor an operator feels — plus distinct-hash resolution.
import argparse
import math
import re
import sys

HASH_RE = re.compile(r"hash=([0-9a-fA-F]+)")
BUCKETS = (2, 4, 8, 16, 32, 64, 128, 256, 512)


def load(fh):
    return [int(m.group(1), 16) for line in fh for m in [HASH_RE.search(line)] if m]


def metrics(h, buckets=BUCKETS):
    n = len(h)
    distinct = len(set(h))
    rows = []
    for N in buckets:
        c = [0] * N
        for x in h:
            c[x % N] += 1
        occ = sum(1 for v in c if v)
        mean = n / N
        chi2 = sum((v - mean) ** 2 / mean for v in c) if mean else 0.0
        imb = (max(c) / mean) if mean else 0.0        # hot-bucket factor (1.0 ideal)
        ent = 0.0
        for v in c:
            if v:
                p = v / n; ent -= p * math.log2(p)
        entn = ent / math.log2(N) if N > 1 else 0.0
        rows.append((N, occ, imb, chi2, entn))
    return n, distinct, rows


def report(label, n, distinct, rows):
    print("== %s ==  packets=%d  distinct-hashes=%d (flow-identity resolution)"
          % (label, n, distinct))
    print("     N   occupied   max/mean    chi2    entropy")
    for N, occ, imb, chi2, entn in rows:
        print("  %4d  %5d/%-4d  %7.2fx  %9.1f   %.3f" % (N, occ, N, imb, chi2, entn))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--label", default="dist")
    ap.add_argument("--cmp", nargs=2, metavar=("OUTER", "INNER"))
    ap.add_argument("--scaling", action="store_true",
                    help="print one summary line (for flow-count sweeps)")
    a = ap.parse_args()
    if a.cmp:
        for lab, p in (("OUTER-only (today)", a.cmp[0]),
                       ("INNER-descent (patch)", a.cmp[1])):
            n, d, rows = metrics(load(open(p)))
            if a.scaling:
                # one line: distinct + imbalance at N=64
                imb64 = [r for r in rows if r[0] == 64][0][2]
                print("  %-24s distinct=%-7d imbalance@64=%.2fx" % (lab, d, imb64))
            else:
                report(lab, n, d, rows); print()
        return
    n, d, rows = metrics(load(sys.stdin))
    report(a.label, n, d, rows)


if __name__ == "__main__":
    main()
