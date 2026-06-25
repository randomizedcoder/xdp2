# Cross-architecture per-shape userland microbench — series 3 flow_dissector

**Date**: 2026-06-25
**Goal**: the complete matrix — every byte-identical fast-path shape ×
every CPU uarch in the fleet. Closes the per-shape microbench TODO from
the v3/v4 cover letters across all three ISAs.

## Method

Userspace `libflowdis` A/B isolating the dissector from NIC / qdisc /
scheduler. **patched `.so`** = HEAD + the v3/v4 per-shape fast-paths
ported into the userland lib (`userland-allshapes-port.diff` —
single-VLAN, QinQ depth-2, PPPoE-session, single-label MPLS, and the
IP-in-IP inner descent, faithful adaptations of kernel v3 patches 2-3
and v4 patches 1-3; metadata-key writes the bench dissector never
requests — NUM_OF_VLANS, KEY_PPPOE, KEY_MPLS — are omitted, and the skb
hw-offload branch is dropped since the userland skb is always NULL).
**baseline `.so`** = `5960a9c6^` (no fast-path; pure slow path).

One bench (`micro_shapes.c`) builds a synthetic packet per shape and
times `__skb_flow_dissect_err`, 10 runs × 10 M iterations,
`taskset -c 3`. Both `.so`s cross-compiled on `l` with
`pkgsCross.{riscv64,aarch64}.stdenv.cc` (rv64gc / armv8-a) and native
x86, then copied to each host with their glibc closure and run.

**Byte-identical verified** for all six shapes (patched vs baseline
produce identical L3/L4 + VLAN/CVLAN tags + ENCAP flag): eth_ip/vlan/
qinq/pppoe extract the inner 5-tuple; mpls stops without inner descent
(matching the slow path's KEY_MPLS-not-requested early-out — both empty);
ipip overwrites the outer 172.16 addrs with the inner 5-tuple and stamps
FLOW_DIS_ENCAPSULATION.

## Results — % reduction in dissector ns/pkt (slow `.so` → fast `.so`)

| uarch | eth_ip | vlan | qinq | pppoe | mpls | ipip |
|---|---|---|---|---|---|---|
| x86 Zen2 (TR 3945WX) | -23.1% | -38.5% | -36.5% | -27.0% | -10.5% | -41.1% |
| x86 Skylake (i9-10885H) | -30.6% | -26.8% | -19.9% | -24.5% | -11.6% | -41.7% |
| x86 Zen1 (Ryzen 2400G) | -4.7% | -18.1% | -16.1% | -8.6% | -9.7% | -36.8% |
| ARM Cortex-A76 (pi5) | -21.8% | -31.3% | -39.8% | -24.9% | -15.0% | -46.2% |
| ARM Cortex-A72 (pi4) | -21.2% | -32.1% | -38.6% | -25.6% | -12.2% | -47.0% |
| ARM Cortex-A53 (pi3) | -23.2% | -32.8% | -37.3% | -23.2% | -6.7% | -39.4% |
| RISC-V SpacemiT X60 | -31.6% | -34.3% | -34.5% | -28.0% | -11.4% | -46.7% |

Absolute ns/pkt for the cheapest and dearest shapes:

| uarch | eth_ip base→fast | ipip base→fast |
|---|---|---|
| x86 Zen2 | 10.03 → 7.71 | 18.05 → 10.64 |
| x86 Skylake | 9.83 → 6.82 | 16.00 → 9.33 |
| x86 Zen1 | 14.97 → 14.27 | 26.29 → 16.61 |
| ARM A76 | 19.93 → 15.59 | 35.46 → 19.07 |
| ARM A72 | 42.08 → 33.15 | 74.73 → 39.63 |
| ARM A53 | 121.98 → 93.73 | 200.70 → 121.63 |
| RISC-V X60 | 98.09 → 67.06 | 165.77 → 88.42 |

## Reading the matrix

- **Every shape on every uarch is faster** with the fast-path. The win
  generally grows with header complexity, because the slow path's
  generic per-layer parse does proportionally more work that the
  straight-line fast-path collapses.
- **IPIP is the biggest win everywhere (-37% … -47%)** — the slow path
  re-dispatches the entire generic dissector a second time for the inner
  IP; the fast-path does a straight-line second IP read.
- **MPLS is the smallest (-7% … -15%)** — with KEY_MPLS not requested
  both paths stop after the single label, so this only measures the
  label-read shortcut.
- **x86 Zen1 eth_ip is the outlier at -4.7%** — the same "masked at p50"
  behaviour seen in the standalone eth_ip microbench; the per-call saving
  is hidden on that older uarch. Note even Zen1 still shows a clear win on
  the more complex shapes (vlan -18%, ipip -37%), where there is more
  slow-path work to remove.

## Caveats (honest, for the netdev audience)

- Absolute ns/pkt are generic ISA baselines (rv64gc / armv8-a / native
  x86, all -O3); the cross-arch **ratios** are the claim, not absolutes
  across ISAs.
- These run the **all-shapes lib** (every fast-path compiled in), the
  kernel-representative case. The eth_ip column here is lower than the
  eth_ip-only-lib headline (-49.8% on RISC-V) because the larger code
  footprint shifts the hot path's icache — same effect, documented in
  `../2026-06-25-series3-riscv-microbench/bpi-f3-pershape/`.
- The userland ports omit metadata-key writes and the skb hw-offload
  branch; they are measurement artifacts, not a shippable libflowdis
  patch. GRE / Geneve-inner / GTP-U-inner (the RFC-EXPERIMENT descent
  shapes) are out of scope here.

Raw per-host logs in `logs/`; per-cell means in `matrix.csv`.
