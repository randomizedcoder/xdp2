# Encapsulation inner-descent: comprehensive flow-distribution study (2026-07-01)

Extends `ANALYSIS.md` to be exhaustive across the axes a netdev reviewer or a
cloud/telco operator would probe. Same method (real kernel `flow_hash_from_keys`
via `test_parser -H`; OUTER = today's dissect on the overlay frame, INNER =
inner-descent, byte-equivalent via the stripped inner frame). Metric additions:
realistic bucket counts N∈{2..512} (ECMP paths / RSS tables / LAG members) and a
**load-imbalance = max_bucket/mean** ratio (the hot-queue factor an operator
feels), plus distinct-hash count (flow-identity resolution).

Tooling: `gen_encap_dist2.py`, `dist_metrics2.py`, `run_ab2.sh`; raw in
`results2.txt`. 2000 flows / 10000 pkts unless noted.

## 1. Address-family completeness (inner v4/v6 × outer v4/v6)

The result is **identical across all four combinations** (inner IPv4/IPv6,
outer/underlay IPv4/IPv6):

| case | OUTER distinct | INNER distinct | OUTER imbalance@256 | INNER imbalance@256 |
|---|---|---|---|---|
| VXLAN/GENEVE fixed-sport | **1** | ~1983 | **256×** (one queue) | ~2.1× |
| GTP-U (no sport entropy) | **1** | ~1989 | **256×** | ~2.1× |
| VXLAN/GENEVE kernel-sport | ~1880 | ~1991 | ~2.2× | ~2.1× |

So the story generalises to IPv6 inner flows **and** IPv6 tunnel underlays — no
address family is a special case. (Full per-N tables for all 12 cells in
`results2.txt` Part 1.)

## 2. Flow-count scaling — the kernel-sport ceiling (headline)

Inner IPv4, distinct-hash resolution as inner-flow count grows:

| flows | VXLAN kernel-sport OUTER | INNER | GTP-U OUTER | INNER |
|---|---|---|---|---|
| 100 | 95 | 97 | **1** | 98 |
| 1 000 | 961 | 987 | **1** | 979 |
| 10 000 | 7 425 | 9 821 | **1** | 9 818 |
| 50 000 | **14 434** (ceiling) | **34 872** | **1** | 34 944 |

Kernel-sourced VXLAN/GENEVE keeps up with inner resolution only up to ~1k flows.
Beyond that the outer UDP source port — a **14-bit** field (~16 384 values) —
**saturates**: at 50k flows the outer tuple resolves 14.4k distinct flows while
inner-descent resolves 34.9k (2.4×). Busy VTEP pairs and GTP-U tunnels routinely
carry far more than 16k concurrent flows, so at datacenter/telco scale even the
sport-hashing case loses per-flow identity. GTP-U resolves **1** at every scale.

Caveat (honest): at a realistic queue count (N=64) the imbalance is ~1.1–1.2×
for both outer and inner even at 50k flows — 14k distinct is plenty to fill 64
RSS queues. So the sport ceiling costs **identity/resolution** (classification,
conntrack, very-high-fanout ECMP), not queue-spread at typical N. We do not claim
a spreading win for kernel-sport VXLAN at typical queue counts.

## 3. Load imbalance (hot-queue factor)

For the collapse cases the imbalance equals the bucket count — every flow on one
queue/path:

| case | imbalance@64 | imbalance@256 | imbalance@512 |
|---|---|---|---|
| fixed-sport / GTP-U OUTER | **64×** | **256×** | **512×** |
| inner-descent | ~1.4× | ~2.1× | ~3.0× |

A 64× hot queue is a saturated core while 63 idle; inner-descent brings it to
~1.4×. This is the operator-visible consequence, independent of qdisc.

## 4. VTEP-pair topology

Fixed-sport outer resolution equals the number of tunnel endpoints, **not** the
number of flows:

| VTEP pairs | OUTER distinct | OUTER imbalance@64 | INNER distinct | INNER imbalance@64 |
|---|---|---|---|---|
| 1 | 1 | 64× | 1983 | 1.5× |
| 4 | 4 | 16.2× | 1983 | 1.5× |
| 16 | 16 | 4.5× | 1983 | 1.5× |

Even a 16-endpoint fabric with fixed-sport tunnels spreads across only 16 buckets
(4.5× imbalance on 64 queues); inner-descent is 1.5× regardless of topology.

## 5. Non-standard tunnel port (Cilium VXLAN 8472)

The descent patch matches `dport == 4789` (IANA VXLAN) only. For Cilium's 8472 it
**falls back to outer-only**, so fixed-sport 8472 stays collapsed (outer distinct
= 1). This is the honest boundary of the patch as written and motivates the open
design question: per-netns / tunnel-netdev port discovery instead of a hardcoded
constant. (kernel-sport 8472 outer still spreads via sport, but the patch would
not descend either way.)

## Summary for the cover letter

Across address families, flow scales, topologies, and bucket counts the picture
is consistent and honest:

- **GTP-U and fixed-sport tunnels: total, scale-independent collapse** (1 flow,
  imbalance = N). Descent fixes it completely. Flagship, unattackable.
- **Kernel-sourced VXLAN/GENEVE: spreads fine at typical queue counts**, but the
  14-bit source-port ceiling caps flow *identity* at ~16k — descent restores full
  resolution for classification/conntrack and very-high-fanout, and is robust to
  topology and non-standard ports (given the port-config fix).
- Every number is the real kernel hash, so it holds for **all** consumers
  (RSS/RPS/RFS, ECMP/multipath, bonding/LAG, tc-flower, aRFS) at once.
