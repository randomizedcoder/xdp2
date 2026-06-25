# Per-shape userland libflowdis microbench — RISC-V (SpacemiT K1 X60)

**Date**: 2026-06-25
**Host**: bpi-f3 (SpacemiT K1, 8× X60, riscv64). `taskset -c 3`,
  10 runs × 10 M dissect calls per (shape, variant).
**Goal**: close the "per-shape microbench isolation" TODO in the v4
  cover letter — measure the fast-path A/B per packet shape, not just
  the eth_ip headline.

## Method

The userspace libflowdis only carried the eth_ip fast-path; the v3
single-VLAN and QinQ fast-paths were **ported into the userland lib**
for this measurement (`userland-vlan-qinq-port.diff` here — a faithful
adaptation of kernel v3 patches 2-3: outer tag → KEY_VLAN, inner →
KEY_CVLAN, then tail-call the eth_ip fast-path; the skb hw-offload
branch is dropped since the userland skb is always NULL). The bench
(`micro_flowdis_shapes.c`) builds a synthetic packet per shape and
times `__skb_flow_dissect_err`. patched `.so` = HEAD + the VLAN/QinQ
port (all fast-paths present); baseline `.so` = `5960a9c6^` (no
fast-path at all, pure slow path) — same baseline as the eth_ip
headline run. Both cross-compiled on l with
`pkgsCross.riscv64.stdenv.cc` (rv64gc, -O3).

**Byte-identical check (patched vs baseline, same packet):** PASS for
all three shapes — identical addr_type / ip_proto / v4 addrs / ports,
and VLAN/QinQ tags correctly extracted (vlan=100 for vlan; vlan=200
outer + cvlan=100 inner for qinq).

## Results (mean over N=10, ns/pkt)

| shape  | baseline (slow) | patched (fast) | delta   | speedup |
|--------|----------------:|---------------:|--------:|--------:|
| eth_ip |           98.08 |          68.89 |  -29.19 | **-29.8%** |
| vlan   |          131.65 |          88.10 |  -43.55 | **-33.1%** |
| qinq   |          156.36 |         101.01 |  -55.35 | **-35.4%** |

stdev ≤ 2.2 ns/pkt; all well above noise. The saving **grows with
header complexity** (eth_ip < vlan < qinq) because the slow path does
progressively more generic per-tag work that the straight-line
fast-path collapses.

## Important nuance — code-footprint effect

The eth_ip row here is **-29.8%** (68.89 ns patched), versus **-49.8%**
(49.27 ns) in the standalone eth_ip-only run
(`../bpi-f3/`). The baselines agree (~98 ns), so the difference is
entirely the **patched `.so` being larger** — with the VLAN/QinQ
fast-path functions compiled in, the hot eth_ip path's instruction
cache / code layout shifts on the in-order X60. Re-running the
eth_ip-only `.so` confirms it (49.2 ns, stable).

Interpretation: the **-49.8%** figure is the eth_ip-only lib (v1 RFC,
smallest footprint). The **-30%/-33%/-35%** figures are the realistic
"all fast-paths present" lib (v3) — which is what a kernel carrying the
full series looks like, since each shape's code is in the binary even
when its static_branch gate is off. Both are honest; they measure
different binaries. The per-shape A/B *within the v3 lib* is the
internally-consistent comparison.

## Reproduce / extend to other arches

The same two `.so`s + `micro_shapes` binary cross-compile for any
target (swap `pkgsCross.riscv64` for `.aarch64`/native x86) and run via
`LD_LIBRARY_PATH` switching — so this per-shape harness extends to the
x86/ARM fleet for a full cross-arch per-shape matrix (not yet run).
PPPoE / MPLS / IPIP (v4 shapes) still need their userland ports added
to the same `.diff` to be measured here.
