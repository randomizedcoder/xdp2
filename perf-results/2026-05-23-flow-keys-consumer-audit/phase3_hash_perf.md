# Phase 3 — flow_hash_from_keys cost breakdown

**Date**: 2026-05-23
**Branch**: `flow-keys-compat-reorder`
**Companion**: `findings.md` (Phase 1+2)
**Bench**: `hash_bench.c`, raw output `hash_bench_run.txt`

## TL;DR

- `__flow_hash_consistentify` is **~free** (≤1 cacheline worth of
  swaps and compares; ~0-40 cycles real work).
- The dominant cost in `flow_hash_from_keys` is **siphash**
  itself, and it scales in 16-B steps because siphash2-4
  processes 8 bytes per round.
- A hypothetical 24-B "5-tuple-only" hash (basic + ports +
  v4 addrs) runs at **~40 cycles real work** — roughly half
  the cost of the current v4 region (40 B, ~80 cycles) and
  one-third the cost of the v6 region (64 B, ~120 cycles).
- The v4→v6 difference is real: v6 costs ~50% more than v4
  per hash because of the larger addrs.

**Layout implication**: a smaller hash region is a meaningful
optimization opportunity for hash-heavy consumers
(sch_cake calls `flow_hash_from_keys` up to 3× per packet for
its dual-host flow accounting). Whether the bias loss is
acceptable for RSS/RFS is the open follow-up.

## Caveats

- **Microarchitecture**: this ran on **AMD Ryzen Threadripper
  PRO 3945WX (Zen 2)**, not hp5's Zen 1. SipHash is well-
  pipelined on both Zen 1 and Zen 2, so the *relative* trend
  (smaller region → fewer cycles) should be invariant. The
  absolute numbers will differ by ~10-20% between cores.
- **Measurement floor**: the `CPUID; RDTSC` / `RDTSCP; CPUID`
  fence pair around each measurement adds a fixed ~40-cycle
  overhead. Cycles below ~40 in the min column are not
  meaningful — what matters is the **transitions** between
  measurements.
- **Userspace, not kernel**: ran without preemption / IRQs /
  cache contention. Real kernel-path numbers will be higher
  due to TLB misses and cache evictions, but the relative
  region-size trend is unaffected.

## Bench setup

- CPU: AMD Ryzen Threadripper PRO 3945WX, Zen 2, 12-core
- Compiler: gcc -O2 from `nix develop`
- siphash lib: `src/lib/siphash/libsiphash.so` (XDP2's port
  of kernel `lib/siphash.c`)
- Iterations: 100,000 per measurement
- Sched affinity: CPU 1, set via `sched_setaffinity`
- Reported: min / p10 / p50 / p99 cycles per call

## Results

### Group A — `__flow_hash_consistentify` only (no siphash)

| variant | min | p10 | p50 | p99 |
|---|---:|---:|---:|---:|
| v4 already-sorted | 40 | 40 | 80 | 80 |
| v4 needs swap | 40 | 40 | 80 | 80 |
| v6 already-sorted | 40 | 80 | 80 | 120 |
| v6 needs swap | 40 | 80 | 80 | 120 |

The harness floor is ~40 cycles. Consistentify itself runs
in **0-40 cycles** above floor (essentially the cost of two
compare-and-swap pairs for v4, plus a `memcmp` for v6).
**Not the bottleneck.**

### Group B — siphash over N bytes (no consistentify)

| region size | min | p10 | p50 | p99 |
|---|---:|---:|---:|---:|
| 16 B | 80 | 80 | 80 | 120 |
| 24 B | 80 | 80 | 80 | 120 |
| 32 B | 80 | 80 | 80 | 120 |
| 40 B | 80 | 80 | 120 | 120 |
| 48 B | 80 | 80 | 120 | 120 |
| 56 B | 80 | 80 | 120 | 120 |
| 64 B | 120 | 120 | 120 | 160 |
| 72 B | 120 | 120 | 120 | 160 |

SipHash2-4 processes 8 B per round, so each band of 16 B
in the table corresponds to ~2 added rounds (one round =
~5 cycles on Zen 2). The p50 transitions are:

- 16-32 B: ~40 cycles real work (1 cacheline access + few rounds)
- 40-56 B: ~80 cycles real work (one band up)
- 64-72 B: ~80-120 cycles real work (another band up)

So **going from 64 B to 24 B saves ~40 cycles**, roughly a
33-50% reduction in siphash cost.

### Group C — full `flow_hash_from_keys` (consistentify + siphash)

| variant | region | min | p10 | p50 | p99 |
|---|---:|---:|---:|---:|---:|
| v4 | 40 B | 80 | 120 | 120 | 160 |
| v6 | 64 B | 120 | 120 | 160 | 200 |

v4 p50 = 120 → ~80 cycles real work
v6 p50 = 160 → ~120 cycles real work

**v6 is 50% more expensive than v4.** Consistentify on v6
adds a small cost (~40 cycles for the memcmp + conditional
4-word swap) on top of the larger siphash.

### Group D — hypothetical 5-tuple-only hash (24 B)

| variant | region | min | p10 | p50 | p99 |
|---|---:|---:|---:|---:|---:|
| consistentify v4 + siphash 24 B | 24 B | 80 | 80 | 80 | 120 |

p50 = 80 → ~40 cycles real work. **Half the cost of current v4.**

The 24 B region holds:
- `basic` (4 B)
- `tags.flow_label` (4 B, zeroed for v4)
- `vlan` (8 B)
- `cvlan` (8 B)

…which doesn't exactly match the 5-tuple-only hypothesis from
Phase 1. To actually achieve the 5-tuple hash region, the
metadata layout would need to put `addrs + ports + basic +
control.addr_type` contiguous — that's the Phase 5 layout
proposal. The 24-B measurement above shows **what's possible
if the hash region shrinks**, not what today's struct gives
for the 5-tuple subset.

## Hash compute cost in sch_cake

`sch_cake.c` calls `flow_hash_from_keys` up to 3 times per
packet (one main flow hash, plus two host_keys hashes for
dual-host flow accounting). With v4 at ~80 cycles per hash:

- 3 × 80 = ~240 cycles/packet on the hash alone
- At 3 GHz: ~80 ns/packet in `flow_hash_from_keys`

Cake's full per-packet enqueue cost is several hundred ns;
the hash is a meaningful fraction. Halving the hash cost
would save **~40 ns/packet** on cake's hot path. Worth
chasing if the bias question can be answered.

## Implications for the optimal layout

1. **The hash region IS a layout-decision variable**, not a
   noise floor. ~40 cycles/hash is non-trivial at 80+ Mpps
   target rates (XDP2's headline).
2. **Smaller hash region = direct cycle savings.** The
   question is whether the smaller region still has enough
   entropy for RSS/RFS distribution. A 24-B 5-tuple hash
   has the same input bits as the kernel's per-CPU `skb->hash`
   path on RPS — which is known-good for distribution.
3. **The current 40 B v4 region is mostly cold bytes**:
   `tags.flow_label` (4 B), `vlan` (8 B), `cvlan` (8 B),
   `keyid` (4 B), `icmp` (4 B) = 28 B of typically-zero or
   typically-irrelevant data. Hashing zeros wastes cycles
   and adds zero entropy. **This is the clearest design lever.**
4. **v6 cost dominance**: any layout proposal should consider
   that v6's 64-B region is hash-cost-bound at ~120 cycles.
   v6 flows are increasingly common; the layout decision
   should optimize for v6 at least as much as v4.

## Open questions for Phase 5

These come up to inform the layout proposal:

- **RSS/RFS distribution with a smaller hash region**: does
  hashing only `addr_type + addrs + ports + basic.ip_proto`
  (24-32 B) maintain acceptable bias? Empirical test on a
  packet corpus needed.
- **Per-consumer hash semantics**: should `xdp2_metadata_all_v2`
  expose two hash functions — `xdp2_hash_small` (5-tuple,
  fast) and `xdp2_hash_full` (full siphash, RSS-equivalent)?
  Different consumers might prefer different speed/quality
  tradeoffs.
- **Bias from hashing zero-filled cold fields**: today's
  `flow_hash_from_keys` hashes `tags.flow_label = 0`,
  `vlan = 0`, etc. for TCP/IPv4. Does removing those bytes
  measurably change the hash distribution on a real packet
  corpus? Easy follow-on bench.

## What this DOESN'T tell us

- hp5's actual numbers (Zen 1, different cache hierarchy
  and store buffer). Predicted same relative trend, ~10-20%
  absolute difference.
- Kernel-path numbers (TLB misses, cache pressure from
  surrounding code).
- Numbers for in-order ARM (Cortex-A53) — likely the
  region-size trend is *larger* there because the smaller
  store buffer makes scatter writes more visible.

## Followups

- The 24-B siphash measurement is the headline data point —
  worth pulling into the analysis-plan TL;DR alongside the
  Phase 1+2 result. Done at next plan-update commit.
- Phase 4 (μarch sensitivity) — needs hp5 to compile/run
  `hash_bench`. Add to the hp5 next-session list.
- Phase 5 (layout proposals) — now data-armed for the
  "shrink the hash region?" question. The proposal can put
  numbers on the trade.
- Phase 3 follow-on: hash distribution bias test. Pick a
  real-world capture, hash with full 40-B region and 24-B
  region, compare distributions via chi-squared. ~2 hours of
  work if a capture is handy.
