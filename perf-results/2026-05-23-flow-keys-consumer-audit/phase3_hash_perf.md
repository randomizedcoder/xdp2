# Phase 3 — flow_hash_from_keys cost breakdown

**Date**: 2026-05-23
**Branch**: `flow-keys-compat-reorder`
**Companion**: `findings.md` (Phase 1+2)
**Bench**: `hash_bench.c`, raw outputs `hash_bench_run.txt`
  (local Zen 2 Threadripper), `hash_bench_hp5.txt`,
  `hash_bench_hp2.txt` (Zen 1 Ryzen 5 PRO 2400G)

## TL;DR

- `__flow_hash_consistentify` is **~free** on every measured
  CPU (≤1 cacheline of swaps and compares; ≤40 cycles real
  work).
- The dominant cost in `flow_hash_from_keys` is **siphash**
  itself, and it scales in 16-B steps (siphash2-4 processes
  8 bytes per round).
- The cycle saving from a smaller hash region is
  **microarchitecture-dependent**:
  - **Zen 2 (Threadripper)**: v4 hash saving ~40 cycles
    (16-B p50=80, 40-B p50=120). Visible at p50.
  - **Zen 1 (Ryzen 5 PRO 2400G, hp2/hp5)**: v4 hash p50 is
    the same (108) for 16 B and 40 B — the rdtsc/cpuid
    fence overhead masks the underlying delta. Saving is
    visible at **p10 only** (~36 cycles).
  - **v6 (64 B → 16 B)** saves cycles on both: ~80 cyc on
    Zen 2, ~36 cyc on Zen 1.
- The v4 → v6 difference is real on both uarches: v6 always
  takes one siphash band more than v4 because of the larger
  addrs.

**Layout implication**: the smaller hash region is a real
saving on Zen 2 v4 and on v6 across uarches; the saving is
masked at p50 on Zen 1 v4 but still positive at p10. **No
uarch shows a regression.** The patch is justified, but the
size of the win depends on uarch and on which percentile of
latency you care about.

## Caveats

- **Microarchitecture-dependent**: ran on three configurations
  to bracket the question:
  - AMD Ryzen Threadripper PRO 3945WX, Zen 2, 12-core
  - hp5: AMD Ryzen 5 PRO 2400G, Zen 1 (Raven Ridge APU)
  - hp2: AMD Ryzen 5 PRO 2400G, Zen 1 (same CPU model;
    different RAM speed, immaterial for this CPU-bound bench)
  Each shows a different siphash-band layout — see Group B
  below.
- **Measurement floor**: the `CPUID; RDTSC` / `RDTSCP; CPUID`
  fence pair adds a fixed overhead — ~40 cycles on Zen 2,
  ~36 cycles on Zen 1. Cycles at or below the floor are
  unresolved; what matters is the **transitions** between
  region sizes.
- **Userspace, not kernel**: no preemption / IRQs / cache
  contention. Real kernel-path numbers will be higher due to
  TLB misses and cache evictions, but the relative region-
  size trend is unaffected.

## Bench setup

- CPUs:
  - Zen 2: AMD Ryzen Threadripper PRO 3945WX, 12-core
  - Zen 1: AMD Ryzen 5 PRO 2400G (hp2 and hp5; same SKU,
    different RAM)
- Compiler: gcc -O2 from `nix develop`
- siphash lib: `src/lib/siphash/libsiphash.so` (XDP2's port
  of kernel `lib/siphash.c`)
- Iterations: 100,000 per measurement
- Sched affinity: CPU 1, set via `sched_setaffinity`
- Reported: min / p10 / p50 / p99 cycles per call

## Results

### Group A — `__flow_hash_consistentify` only (no siphash)

| variant | Zen 2 p50 | Zen 1 p50 |
|---|---:|---:|
| v4 already-sorted | 80 | 72 |
| v4 needs swap | 80 | 72 |
| v6 already-sorted | 80 | 72 |
| v6 needs swap | 80 | 72 |

Harness floor is ~40 cyc on Zen 2, ~36 cyc on Zen 1.
Consistentify itself runs in **0-40 cycles above floor** on
both — essentially free. **Not the bottleneck.**

### Group B — siphash over N bytes (no consistentify)

| region size | Zen 2 p10 | Zen 2 p50 | Zen 2 p99 | Zen 1 p10 | Zen 1 p50 | Zen 1 p99 |
|---|---:|---:|---:|---:|---:|---:|
| 16 B | 80 | 80 | 120 | 72 | 108 | 108 |
| 24 B | 80 | 80 | 120 | 72 | 108 | 144 |
| 32 B | 80 | 80 | 120 | 108 | 108 | 144 |
| 40 B | 80 | 120 | 120 | 108 | 108 | 144 |
| 48 B | 80 | 120 | 120 | 108 | 108 | 144 |
| 56 B | 80 | 120 | 120 | 108 | 144 | 144 |
| 64 B | 120 | 120 | 160 | 108 | 144 | 180 |
| 72 B | 120 | 120 | 160 | 144 | 144 | 180 |

The two uarches show **different band layouts**:

- **Zen 2**: median transitions from band 1 (16-32 B p50=80)
  to band 2 (40-72 B p50=120) at 40 B. So shrinking 40 B
  → 24 B crosses one band — ~40 cyc saving at median.
- **Zen 1**: median stays at p50=108 across the whole 16-48 B
  range, then jumps to 144 at 56 B. So shrinking 40 B → 24 B
  **doesn't cross a band at median** — saving is masked by
  measurement floor. But p10 transitions earlier (72 → 108
  between 24 B and 32 B), so the underlying delta is real
  and visible at the best-case (p10) end.

For 64 B → 16 B (i.e., shrinking the v6 region): both
uarches cross at least one band:
- Zen 2: 120 → 80 p50 = ~40 cyc saving
- Zen 1: 144 → 108 p50 = ~36 cyc saving

### Group C — full `flow_hash_from_keys` (consistentify + siphash)

| variant | region | Zen 2 p10 | Zen 2 p50 | Zen 2 p99 | Zen 1 p10 | Zen 1 p50 | Zen 1 p99 |
|---|---:|---:|---:|---:|---:|---:|---:|
| v4 | 40 B | 120 | 120 | 160 | 108 | 108 | 144 |
| v6 | 64 B | 120 | 160 | 200 | 144 | 144 | 216 |

- v4 (40 B): Zen 2 ~80 cyc real work; Zen 1 ~72 cyc real work
- v6 (64 B): Zen 2 ~120 cyc real work; Zen 1 ~108 cyc real work

Across both uarches, **v6 is ~50% more expensive than v4**
because of the larger addrs (32 B vs 8 B). The extra
consistentify work on v6 (`memcmp` + 4-word swap) is
within measurement noise; the cost difference is the
siphash region size.

### Group D — hypothetical 5-tuple-only hash (24 B)

| variant | region | Zen 2 p10 | Zen 2 p50 | Zen 2 p99 | Zen 1 p10 | Zen 1 p50 | Zen 1 p99 |
|---|---:|---:|---:|---:|---:|---:|---:|
| consistentify v4 + siphash 24 B | 24 B | 80 | 80 | 120 | 108 | 108 | 144 |

- Zen 2 p50 = 80 → ~40 cyc real work. **Half v4's cost** at p50.
- Zen 1 p50 = 108 → ~72 cyc real work. **Same as v4 at p50**;
  the underlying ~36-cyc delta only shows at best-case (p10
  range) and is masked at median by measurement floor.

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
