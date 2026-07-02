#!/usr/bin/env python3
# dist_metrics.py — flow-hash distribution metrics for the encap study.
#
# Reads `test_parser -c flowdis -o text -H` output (the real kernel
# flow_hash_from_keys per packet) and reports, for several bucket counts N,
# how the flows spread. Buckets model any hash-mod-N consumer at once: RSS
# indirection tables, RPS/RFS CPU maps, ECMP nexthop selection, bonding/LAG
# member selection. No qdisc is assumed — these are properties of the hash.
#
# Metrics per N:
#   occupied   number of non-empty buckets (the intuitive "collapse" number)
#   chi2       chi-squared vs uniform (df=N-1; ~df means uniform, >>df means skewed)
#   entropy    Shannon entropy of the bucket distribution / log2(N)  (1.0 = ideal)
#   gini       Gini coefficient of bucket loads (0 = even, ->1 = concentrated)
# Plus, independent of N:
#   distinct   number of distinct hash values = flow-identity resolution
#              (what any consumer that reads the actual flow can tell apart)
#
# Usage:
#   test_parser -i pcap,X -c flowdis -o text -H | python3 dist_metrics.py --label outer
#   dist_metrics.py --cmp outer.hashes inner.hashes     # side-by-side A/B

import argparse
import math
import re
import sys

HASH_RE = re.compile(r"hash=([0-9a-fA-F]+)")


def load_hashes(fh):
    out = []
    for line in fh:
        m = HASH_RE.search(line)
        if m:
            out.append(int(m.group(1), 16))
    return out


def metrics(hashes, buckets=(8, 16, 64, 256)):
    n = len(hashes)
    distinct = len(set(hashes))
    rows = []
    for N in buckets:
        counts = [0] * N
        for h in hashes:
            counts[h % N] += 1
        occ = sum(1 for c in counts if c)
        exp = n / N
        chi2 = sum((c - exp) ** 2 / exp for c in counts) if exp else 0.0
        # Shannon entropy over occupied buckets, normalized to log2(N)
        ent = 0.0
        for c in counts:
            if c:
                p = c / n
                ent -= p * math.log2(p)
        ent_norm = ent / math.log2(N) if N > 1 else 0.0
        # Gini of loads
        s = sorted(counts)
        cum = 0
        for i, c in enumerate(s, 1):
            cum += i * c
        gini = (2 * cum) / (N * n) - (N + 1) / N if n else 0.0
        rows.append((N, occ, chi2, ent_norm, gini))
    return n, distinct, rows


def fmt_report(label, n, distinct, rows):
    print("== %s ==  packets=%d  distinct-hashes=%d (flow-identity resolution)"
          % (label, n, distinct))
    print("   N    occupied     chi2     entropy   gini")
    for N, occ, chi2, ent, gini in rows:
        print("  %4d  %5d/%-4d  %9.1f   %.3f    %.3f"
              % (N, occ, N, chi2, ent, gini))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--label", default="dist")
    ap.add_argument("--cmp", nargs=2, metavar=("OUTER", "INNER"),
                    help="two files of test_parser output to compare")
    args = ap.parse_args()

    if args.cmp:
        for lab, path in (("OUTER-only (today)", args.cmp[0]),
                          ("INNER-descent (patch)", args.cmp[1])):
            with open(path) as fh:
                h = load_hashes(fh)
            n, distinct, rows = metrics(h)
            fmt_report(lab, n, distinct, rows)
            print()
        return
    h = load_hashes(sys.stdin)
    n, distinct, rows = metrics(h)
    fmt_report(args.label, n, distinct, rows)


if __name__ == "__main__":
    main()
