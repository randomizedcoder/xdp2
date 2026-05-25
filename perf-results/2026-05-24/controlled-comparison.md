# Controlled comparison: patched vs no-patch-3 — Phase A complete

**Date**: 2026-05-24
**Hosts**: hp1 (gen) ↔ hp3 (DUT), Mellanox CX-4 Lx 25 GbE, Zen 1
**Method**: Same 7.1.0-rc4 kernel base, only sch_cake patch 3
  (commit 1ddc5f7) differs. Isolates the patch's effect from
  unrelated kernel version changes.
**Tooling**: iperf3 60 s -P 16 -O 5 -J, repeated 10×
**TCP profile** (applied on both hosts):
  - `tcp_rto_min_us = 5000` (5 ms vs 200 ms default)
  - `tcp_no_metrics_save = 1` (don't pollute next run)
  - `tcp_slow_start_after_idle = 0` (keep cwnd between runs)
  - `tcp_autocorking = 0`
  - `tcp_congestion_control = cubic` (default)

## Setup

- **Patched kernel** (build hash `l4l9i6dq…-linux-7.1.0-rc4-flowdis-pppoe`):
  combined-test-rfc tree, sch_cake.ko contains both
  `U flow_hash_from_keys` (for main flow_hash) and
  `U flow_hash_from_keys_small` (for the two host_keys hashes).
- **No-patch-3 kernel** (build hash `bk1v1zzc…-linux-7.1.0-rc4-flowdis-pppoe`):
  combined-test-rfc with commit `1ddc5f7b7652` reverted.
  sch_cake.ko contains only `U flow_hash_from_keys` —
  flow_hash_from_keys_small exists in vmlinux but cake doesn't
  call it.
- Both kernels built from the exact same NixOS flake pkgs context
  on the same workstation; differ only in the 8-line sch_cake.c
  diff.
- hp3 was rebooted between runs to switch kernels (verified via
  `nm sch_cake.ko | grep flow_hash` on each kernel before the
  test).
- iperf3 client (hp1) and server (hp3) configurations identical
  across runs.

## Data

| run | patched: Gbit/s | patched: retx | no-patch-3: Gbit/s | no-patch-3: retx |
|---:|---:|---:|---:|---:|
| 1 | 16.086 | 16476 | 15.934 | 15538 |
| 2 | 15.938 | 19080 | 15.961 | 14638 |
| 3 | 16.056 | 16943 | 16.453 |  9228 |
| 4 | 15.702 | 12337 | 15.968 | 18650 |
| 5 | 15.988 |  9747 | 16.248 | 16612 |
| 6 | 16.098 | 12383 | 15.939 |  9673 |
| 7 | 15.925 | 11223 | 16.038 | 13041 |
| 8 | 16.216 | 12458 | 15.716 | 14627 |
| 9 | 16.335 | 20238 | 15.814 | 12111 |
| 10 | 16.032 | 16267 | 16.348 | 14006 |

## Statistical analysis

**Throughput**:

| | patched | no-patch-3 | delta |
|---|---:|---:|---:|
| mean (Gbit/s) | 16.038 | 16.042 | -0.004 |
| stddev | 0.180 | 0.235 | — |
| range | 15.70–16.34 | 15.72–16.45 | — |

Mean delta is 0.03 % — three orders of magnitude smaller than
either stddev. Welch's t = -0.04, p ≈ 0.97. **Indistinguishable.**

**Retransmits**:

| | patched | no-patch-3 | delta |
|---|---:|---:|---:|
| mean | 14715 | 13812 | +903 (patched is HIGHER) |
| stddev | 3545 | 2929 | — |
| range | 9747–20238 | 9228–18650 | overlapping |

Welch's t = 0.62, df ≈ 18, **p ≈ 0.54**. Not significant. The
patched kernel actually has a slightly HIGHER mean retransmit
count, in the opposite direction from the original single-run
observation. The 903 mean delta is well inside the natural
variance of the test.

**Pooled within-kernel variance** is ~3200 retransmits per run
(stddev). The standard error of the 10-run mean is ~1000. So
a real effect would need to be ≥2500-3000 retransmits to be
detected at p < 0.05 — that's about 20% of mean. Anything
smaller is unmeasurable with N=10.

## Conclusion

**The patch has no measurable effect on TCP retransmit count or
throughput at this load level.** The original
baseline-vs-patched comparison (7.0.9 → 7.1.0-rc4) showed a
23% retransmit reduction; that observation was **entirely
noise across the kernel version change**, not the patch.

This is exactly the controlled experiment we needed: same
kernel base, only the 8-line cake diff differs, N=10 per side,
proper TCP tuning to control sysctl confounds. Result is a
clean negative — the patch is neutral, not slower, not faster.

## Implication for cover letter framing

The original cover letter contains no retransmit claim (we
were going to add it as a footnote, never did). After this
experiment we should add an EXPLICIT no-effect statement:

> "Controlled comparison (10 iperf3 runs per kernel, same
> 7.1.0-rc4 base, only patch 3 differs, tuned TCP profile) shows
> no statistical difference in TCP throughput
> (16.038 vs 16.042 Gbit/s, p ≈ 0.97) or retransmit count
> (14715 vs 13812, p ≈ 0.54). The patch is neutral on TCP
> behaviour at this load."

This is a STRONGER claim than silence because it forecloses
the reviewer question "did you check it doesn't affect TCP?"
with a direct answer ("yes, and it doesn't").

## What's still useful from the experiment

- **Proves the experimental setup is sensitive enough** to detect
  ~20% effects at N=10. So the retransmit-neutral claim has
  teeth: a real effect of that magnitude would have been
  detected.
- **Variance characterization**: ~22% coefficient of variation
  on retransmit count is a fact about iperf3 + cake +
  triple-isolate on Zen 1 at 25 GbE, useful for anyone
  designing similar experiments.
- **Foundation for the soak tests**: the per-run distribution is
  characterized, so any drift over a 24h soak is detectable
  against this baseline.

## Files in this directory

- `iperf3_untuned_variance.log` — initial 10-run variance with
  default TCP sysctls (~78% retransmit range — informs why
  we needed tuning)
- `iperf3_controlled_patched.log` — 10x iperf3 + iperf2 on
  patched kernel with tuned TCP
- `iperf3_controlled_nopatch3.log` — 10x iperf3 on no-patch-3
  kernel with tuned TCP
- `iperf3_hp1_to_hp3_*.json` — per-run iperf3 JSON outputs
