# Series 3 Phase 3 microbench — RISC-V (SpacemiT K1 X60)

**Date**: 2026-06-25
**Host**: bpi-f3 (Banana Pi BPI-F3, SpacemiT K1, 8× X60, riscv64
  rv64gcv / RVA22 + RVV 1.0, ~1.6 GHz nominal — no cpufreq sysfs, so
  the governor step is skipped; the clock is fixed).
**Patched code**: series 3 v1 RFC, gated form. Userspace libflowdis
  port at `src/lib/flowdis/flow_dissector.c` (commit `5960a9c6`, the
  same single-file +217-line fast-path the x86/ARM microbenches use).
  Baseline is that file at `5960a9c6^` (no port).
**Test packet**: synthetic eth + IPv4 + TCP, 64 bytes; always hits the
  fast-path. Identical bench source to
  `perf-results/2026-06-04-series3-phase3-t/micro_flowdis.c`.
**Method**: `taskset -c 3` to pin the bench to one core, 10 runs of
  10 M dissect calls per variant, patched vs baseline `libflowdis.so`
  swapped via `LD_LIBRARY_PATH`. Distinct SHA256 on the two `.so`s
  confirms a genuine A/B (patched `4df73351…`, baseline `65e02772…`).
**Build note**: the full `nix run .#xdp2-debug-riscv64` cross path
  fails on an unrelated transitive dep (`sox`, via scapy → audio libs,
  doesn't cross-compile), and a native build on the K1 has no riscv64
  binary cache. So both `libflowdis.so` variants + the bench were
  **cross-compiled on `l`** with `pkgsCross.riscv64.stdenv.cc`
  (riscv64-unknown-linux-gnu-gcc 15.2.0, rv64gc, `-O3`), then copied to
  bpi-f3 (with the cross-glibc closure) and run. Both variants built
  identically, so the A/B ratio is valid; absolute ns/pkt is generic
  rv64gc (not `-march=native` / rv64gcv), so it is not directly
  comparable to the ARM `-march=native` absolutes below — the
  **speedup** is.

## TL;DR

**The series 3 fast-path roughly halves dissector cost on RISC-V:
−48.88 ns/pkt, −49.8%** — squarely in the ARM range and far above the
noise floor (stdev ≈ 0.3 ns/pkt). This is the clean CPU-bound A/B that
the 1 GbE-limited Phase F/G runs on this host could not show, and it
confirms the fast-path generalises to a third ISA. The `static_branch`
/ `jump_label` gate resolves via `arch/riscv/kernel/jump_label.c`.

| uarch | host | clock | baseline ns/pkt | patched ns/pkt | delta | speedup |
|---|---|---|---:|---:|---:|---:|
| SpacemiT X60 (RISC-V) | bpi-f3 | ~1.6 GHz | 98.16 ± 0.21 | 49.27 ± 0.32 | -48.88 | **-49.8%** |

Cross-architecture comparison (ARM, same harness, from
`perf-results/2026-06-09-series3-arm-microbench/`; note those used
`-march=native` so their absolutes reflect each native ISA):

| uarch | host | clock | baseline ns/pkt | patched ns/pkt | speedup |
|---|---|---|---:|---:|---:|
| Cortex-A53 (in-order) | pi3-1 | 1.2 GHz | 118.97 | 61.27 | -48.5% |
| Cortex-A72 (OoO, 3-wide) | pi4-1 | 1.8 GHz | 42.37 | 19.05 | -55.0% |
| Cortex-A76 (OoO, 4-wide) | pi5-2 | 2.4 GHz | 19.37 | 9.25 | -52.3% |
| **SpacemiT X60 (RISC-V)** | **bpi-f3** | **~1.6 GHz** | **98.16** | **49.27** | **-49.8%** |

The fast-path delivers a ~50% dissector-cost reduction consistently
across AMD/Intel x86, three ARM uarches, and now RISC-V — the
cross-architecture generality claim is complete.

See `bpi-f3/summary.txt` and `bpi-f3/micro_flowdis_bpi-f3.log` for the
raw runs.
