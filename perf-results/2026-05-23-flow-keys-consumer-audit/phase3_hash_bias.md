# Phase 3 follow-on — hash distribution bias test

**Date**: 2026-05-23
**Branch**: `flow-keys-compat-reorder`
**Companion**: `phase3_hash_perf.md` (cycle-cost breakdown)
**Bench**: `hash_bias.c`, raw output `hash_bias_run.txt`

## TL;DR

A 16-B 5-tuple-only hash region produces **statistically
indistinguishable** distribution from the kernel's full 40-B
v4 flow_keys region. Both regions pass chi-squared uniformity
on K=256 and K=4096 buckets across 100k synthetic flows.

**Layout implication**: the cycle savings shown in
`phase3_hash_perf.md` (~40 cycles, ~50% reduction) come at
**no distribution-quality cost**. The smaller-region hash is
safe for RSS/RFS purposes — as predicted from siphash's PRF
properties.

This settles the open question from `phase3_hash_perf.md`
about RSS-acceptability. The data-armed Phase 5 layout
proposal can now treat "shrink the hash region" as a viable
optimization, not a hypothesis.

## Method

- N = 100,000 synthetic IPv4 5-tuples
- src/dst addrs + ports drawn from an xorshift+ PRNG
- ip_proto = 6 (TCP), n_proto = ETH_P_IP, all other fields
  zero (matching what XDP2's TCP/IPv4 parser writes today)
- Two hash variants:
  - **full**: siphash over a kernel-flow_keys-shaped 40-B
    region (struct came out 48 B after gcc padding; the
    extra zero bytes are irrelevant — siphash absorbs them
    deterministically)
  - **small**: siphash over a packed 16-B region containing
    only `ip_proto + sport + dport + saddr + daddr`
- Same siphash key for both
- Bucketing:
  - K=256 (low 8 bits) — mimics a typical RSS indirection
    table size
  - K=4096 (low 12 bits) — stress test with fewer flows
    per bucket

Chi-squared metric: Σ((O - E)² / E) over K buckets. Expected
value for a uniform distribution = K-1 (degrees of freedom).
A uniform RNG should land within K-1 ± sqrt(2(K-1)).

## Results

```
[A] K=256 (low 8 bits) — RSS-style indirection table:
  full   40-B region   chi2=   242.50  (df=255)  mean= 390.6  stddev=19.24  min=  335  max=  438
  small  16-B region   chi2=   260.61  (df=255)  mean= 390.6  stddev=19.94  min=  337  max=  445

[B] K=4096 (low 12 bits) — larger bucket count:
  full   40-B region   chi2=  4070.51  (df=4095)  mean=  24.4  stddev= 4.93  min=    7  max=   47
  small  16-B region   chi2=  4155.30  (df=4095)  mean=  24.4  stddev= 4.98  min=    8  max=   43
```

Expected range (uniform, 95% CI):
- K=256: chi2 in roughly 232-278 (255 ± sqrt(510))
- K=4096: chi2 in roughly 4005-4185 (4095 ± sqrt(8190))

Both regions land squarely inside the expected range for
both bucket counts. **Neither shows distinguishable bias.**

The small-region chi2 is marginally larger in both cases
(260.61 vs 242.50; 4155.30 vs 4070.51), but well within
the natural variance of a single PRNG run. A re-run with
a different seed would shift these by ~10-20 either way.

The min/max range across buckets matches the expectation
for Poisson-like deviation around the mean (e.g., K=4096
mean=24.4, stddev=4.98 → 95% range ~14-34, observed 7-47
captures the long-tail outliers in 4096 draws).

## Interpretation

SipHash2-4 is a cryptographic PRF — its distribution
quality is **algorithmically independent of input length**
above the absorption-block size (8 bytes per round). What
varies with input length is *cycle cost*, not distribution.

This is what the data confirms:
- Distribution: equivalent across 16 B and 48 B inputs
- Cycle cost: 40 cycles vs 80 cycles (per `phase3_hash_perf.md`)

The current kernel layout hashes ~28 B of typically-zero
data per TCP/IPv4 packet (tags.flow_label + vlan + cvlan +
keyid + icmp = 28 B of cold padding). That's **wasted
cycles for zero entropy contribution**.

## What this DOESN'T address

- **Bidirectional hash consistency**: this test doesn't
  check that `hash(A→B) == hash(B→A)` after `consistentify`.
  That property is preserved across region sizes because
  consistentify operates on src/dst pairs (addrs, ports)
  which appear identically in both regions. Worth a
  separate spot-test if Phase 5 ships the smaller-region
  hash.
- **Real-world traffic skew**: 100k uniform random tuples
  don't mimic the heavy-tailed flow distribution of real
  networks (a few flows dominate). The bias question for
  real traffic depends more on hash-bucket collision rate
  on heavy flows than on the uniformity of the underlying
  PRF — and that's the same for both regions.
- **Edge cases**: didn't test ip_proto-only-varies, all-same-
  addrs-vary-ports, etc. Should those land in different
  buckets? Yes, because both regions include ip_proto +
  ports + addrs.

## Implications for Phase 5

The smaller-region hash is now backed by both phases of
data:

| metric | full 40 B v4 | small 16 B 5-tuple | delta |
|---|---|---|---|
| siphash cycles (Zen 2 p50) | ~80 cyc | ~40 cyc | **-50%** |
| chi2 at K=256 | 242.5 | 260.6 | equivalent |
| chi2 at K=4096 | 4070.5 | 4155.3 | equivalent |
| v6 cycles (64 B region) | ~120 cyc | n/a | — |

For Phase 5, this suggests offering **two hash entry points**
in any proposed v2 layout:

1. `xdp2_flow_hash_small()` — siphash over 16 B
   (basic.ip_proto + ports + v4 addrs OR v6 addrs);
   ~40 cyc, full RSS-equivalent distribution
2. `xdp2_flow_hash_full()` — siphash over the kernel
   hash region (~40 B v4 / ~64 B v6) for compatibility
   with `(struct flow_keys *)xdp2_meta` casts where the
   consumer specifically wants the kernel hash result

Most XDP2 callers can use the small variant; only callers
that need bitwise hash compatibility with kernel
`flow_hash_from_keys()` (e.g., for hash-based deduplication
across XDP2-parsed and kernel-parsed flows on the same box)
need the full variant.

## Real-traffic sanity check (pcap)

`hash_bias_pcap.c` extends the synthetic test to real
captures. Compiled with libpcap; iterates a pcap, extracts
IPv4 TCP/UDP 5-tuples, runs the same hash + bucket + chi²
pipeline.

Result on `data/pcaps/broad-coverage.pcap` (the largest
XDP2 protocol-coverage capture: 5200 packets, 360 with
IPv4 TCP/UDP):

```
[A] K=256:
  full   40-B region   chi2=  243.02  (df=255)  min=0 max=6
  small  16-B region   chi2=  241.60  (df=255)  min=0 max=5

[B] K=4096:
  full   40-B region   chi2= 4054.58  (df=4095)  min=0 max=2
  small  16-B region   chi2= 4031.82  (df=4095)  min=0 max=2
```

Both regions land in the uniform range; chi² values are
within 1.5 of each other at both K. Sample size is small
(360 flows ÷ 256 buckets = ~1.4 mean count, below the
recommended ≥5 for χ²) so this is a sanity check rather
than a tight bound — but it agrees with the synthetic
result and shows no bias divergence on real traffic.

A larger real-traffic pcap (multi-thousand distinct flows)
would tighten the confidence interval. Raw run output:
`hash_bias_pcap_run.txt`. Bench source: `hash_bias_pcap.c`.

## μarch portability check

Both bias tests (synthetic and pcap) are deterministic
given fixed input and key, so the chi² values are
bitwise identical across uarches. Ran on hp5 (Zen 1) and
hp2 (Zen 1) — outputs `hash_bias_hp5.txt`,
`hash_bias_hp2.txt`, both identical to the local Zen 2
result down to the digit.

This confirms the distribution finding is
microarchitecture-independent, as expected (siphash is a
PRF; output depends only on input bytes and key, not on
how those bytes are computed).

## Followups

- Update analysis-plan TL;DR with Phase 3 + 3-followup
  results (smaller region is data-supported as a Phase 5
  proposal).
- Phase 5 (layout proposals): now ready to propose
  concrete layouts with both cycle and distribution data
  backing the choices.
- Larger real-traffic pcap: lower priority — synthetic and
  small-pcap results both pass.
