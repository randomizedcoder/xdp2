# Extended validation plan — controlled comparison + soak tests

**Date**: 2026-05-24
**Goal**: turn the questionable "23% fewer retransmits" single-run
observation into either a defensible claim or a cleanly-dropped
non-claim, AND demonstrate stability of the patched kernel under
sustained load (12-24h) for the first-kernel-submission framing.
**Hosts**: hp1 (gen) ↔ hp3 (DUT), Mellanox CX-4 Lx 25 GbE, Zen 1.

## Phase A — Short controlled experiment (~90 min)

The goal is to isolate the patch's effect from kernel-version
differences. The original baseline-vs-patched test changed two
things at once (7.0.9 → 7.1.0-rc4 AND no-patch → patched). To
make a defensible claim about the patch alone, build two
kernels from the SAME 7.1.0-rc4 base and only differ in patch 3.

### A.1 Variance baseline (~12 min, IN PROGRESS as task b8l7xohsn)

10× iperf3 runs on the current patched kernel. Establishes
natural run-to-run variance in retransmit count. If variance
is ±20%+, the 23% delta is statistically meaningless and we
drop the claim immediately. If variance is ≤10%, the 23%
delta is signal and the controlled experiment is worth
running.

### A.2 Controlled patched vs no-patch-3 (~60 min if A.1 passes)

Build a "no-patch-3" kernel from the same 7.1.0-rc4 base
(combined-test-rfc with commit 1ddc5f7 reverted). Only diff
from the patched kernel: sch_cake uses flow_hash_from_keys()
instead of flow_hash_from_keys_small() for the two host_keys
hashes. Everything else identical.

- 10× iperf3 with each kernel (~10 min/kernel)
- 10× iperf2 with each kernel (~10 min/kernel) — different
  tool, multi-threaded, catches different bugs
- Mann-Whitney U test on retransmit counts: with-patch-3 vs
  no-patch-3 distributions

### A.3 Statistical decision

Three possible outcomes:

1. **Distributions overlap heavily** (p > 0.05): no signal,
   drop the retransmit claim from the cover letter entirely.
2. **Distributions separate cleanly** (p < 0.01): real
   effect attributable to patch 3. Cover letter can claim
   the retransmit improvement with the statistical test
   results cited.
3. **Marginal** (0.01 ≤ p ≤ 0.05): suggestive but not
   conclusive. Mention as a footnote, propose follow-up.

## Phase B — Soak tests (12-24h each)

For the first-kernel-submission framing, "we ran it for 24
hours under sustained load with no issues" is a much stronger
claim than "we ran for 60 seconds and it worked." Soak tests
catch leaks, slow drift, intermittent dmesg warnings, qdisc
counter overflow bugs, scheduler hangs.

### B.1 24h iperf3 soak on patched kernel

```
On hp3 (DUT):
  iperf3 -s -B 10.10.2.3 -p 5201 -D --logfile /tmp/iperf3_soak_server.log
  tc qdisc replace dev enp1s0f0np0 root cake bandwidth 25Gbit triple-isolate

On hp1 (gen): rolling iperf3 sessions, with 5-min cooldown between
  each to let TCP state cycle, for 24h total
```

Capture every hour:
- `tc -s qdisc show dev enp1s0f0np0` (cake stats — drops,
  requeues, memory, class populations)
- `free -h` (memory usage trend)
- `cat /proc/net/snmp | grep ^Tcp:` (kernel TCP counters)
- `dmesg | tail -50` (any new WARN/BUG?)
- iperf3 throughput sample (current Mbit/s)

Look for:
- Memory leak — cake memory growing without bound
- Counter saturation — drops climbing, requeues climbing
- dmesg anomalies — kernel warnings from cake or flow_dissector
- Throughput degradation — gradual decline over the 24h

### B.2 24h iperf2 soak on patched kernel

Same as B.1 but with iperf2 -d (bidirectional) -P 16 -t 86400.
iperf2 is multi-threaded — better at saturating the link and
more stressful on the kernel scheduler. Catches issues iperf3's
single-threaded model wouldn't surface.

### B.3 (optional, if Phase A shows signal)

12h soak with patched kernel, 12h with no-patch-3, compare
retransmit cumulative counts. Most definitive way to claim a
soak-scale retransmit effect.

## Phase C — pktgen at line rate (optional, separate session)

The honest finding from the baseline comparison is that iperf3
was CPU-bound on the receiver, not cake-bound. To actually
saturate cake's per-packet processing path, we need
small-packet generation at line rate:

```
ssh root@hp1 'modprobe pktgen
  # Set up pktgen on enp1s0f0np0 with 64-byte packets,
  # destination = hp3 (10.10.2.3), full line rate
  echo "..." > /proc/net/pktgen/...
'
```

At 25 GbE with 64-byte packets, that's ~37 Mpps. Cake's
host_keys hash runs twice per packet = 74 M hashes/sec. Even
at ~36 cycles saving on Zen 1 at p10, that's 74e6 × 36 / 3e9 =
0.9 s of CPU per second per CPU = potentially 90% of one core
saved on the hash specifically (BUT cake has many other
per-packet costs, so the actual aggregate saving will be a
small fraction of this).

This is the experiment most likely to manifest a measurable
cake throughput lift from the patch. Worth running but heavier
to set up.

## Timing summary

| phase | time | priority |
|---|---:|---|
| A.1 variance baseline | 12 min | NOW |
| A.2 controlled with/without patch | 60 min | if A.1 signal |
| A.3 statistical decision | 5 min | always |
| B.1 24h iperf3 soak | 24h | high |
| B.2 24h iperf2 soak | 24h | high (catches different bugs) |
| B.3 24h with/without patch | 24h+24h | only if A signal |
| C pktgen line-rate test | ~2h | optional |

Total active hands-on time: ~90 min. Total wall-clock with
soaks: 2-4 days depending on how parallel we can run them
(can't run two soaks on the same hp1↔hp3 link).

## Cover-letter framing once Phase A+B complete

If Phase A drops the retransmit claim:

> "Validated the patch is safe under high-bandwidth load: 24h
> iperf3 soak + 24h iperf2 soak on Zen 1 + 25 GbE produced
> zero kernel warnings, no memory growth, no throughput
> degradation, no cake stat anomalies."

If Phase A confirms the retransmit claim:

> "Validated the patch is safe under high-bandwidth load and
> observed a [N]% reduction in TCP retransmits in controlled
> comparison (10× runs per kernel, p < 0.01 by Mann-Whitney U
> test). Mechanism likely [proposed explanation]; further
> investigation in [follow-up]."

Either way, the soak data demonstrates production-readiness
beyond the typical "I built it and the tests passed" baseline
that most first-time kernel submissions bring.
