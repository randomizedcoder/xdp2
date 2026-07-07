# Series4 byte-identical-descent — hp-pair kernel cyc/pkt A/B (no-regression check)

**Date**: 2026-07-06
**Question**: Does the byte-identical-descent round (series4-rfc-tail-v2 — slow
  path grows the same descent as fast; descent helpers refactored through the
  shared `flow_dissect_fast_udp_inner` tail; a gated UDP-tunnel descent hook
  added to `__skb_flow_dissect` after the outer UDP ports) add any measurable
  per-packet cost to the common (gates-off) path or regress the byte-identical
  fast paths vs the prior series4?
**Method**: Kernel cyc/pkt gold standard — kernel-pktgen TX (2 threads, 64 B,
  random source ports) → receiver-side ksoftirqd `perf stat`, cycles /
  packets-received. `DUR=30`, 3 replicates/cell, gate off (sysctl=0) vs on
  (sysctl=1). `nix run .#series3-cpu-bound-soak`.
**Kernel**: net-next 7.2-rc1 (base b73bc9ca3686) + `series4-rfc-tail-v2`
  (a208f86be2ce), all `net.flow_dissector.*` gates default-off, deployed to all
  four hp hosts (built on `l`, cross-checked booting: gates present, 0 failed
  units).
**Pairs**:
  - **hp1 ↔ hp3** — AMD Ryzen 5 PRO 2400G (Zen 1), Mellanox ConnectX-4 Lx
    25 GbE (`mlx5_core`), back-to-back DAC.
  - **hp2 ↔ hp5** — AMD Ryzen 5 PRO 2400G (Zen 1), Intel X710 10 GbE
    (`i40e`), back-to-back fibre.

## TL;DR

**No measurable regression.** Across all six byte-identical shapes on both
pairs, gate-off → gate-on cyc/pkt moves within the ~±4 % ksoftirqd noise floor
and bounces both directions — the same picture as the prior series4 A/B on
l↔l2. Gate-off cyc/pkt is in the normal range on every shape, i.e. the new
slow-path descent hook (a handful of not-taken `static_branch`es on the UDP
path when gates are off) adds no measurable cost to the common path, and the
byte-identical fast-path bodies (unchanged code this round) behave exactly as
before.

## Results — cyc/pkt, gate-off → gate-on (mean of 3 reps)

| Shape | hp1↔hp3 (mlx5 25G) off→on | Δ | hp2↔hp5 (X710 10G) off→on | Δ |
| --- | --- | --- | --- | --- |
| eth_ip | 2194 → 2205 | +0.5 % | 2692 → 2675 | −0.6 % |
| vlan   | 2240 → 2259 | +0.8 % | 2874 → 2840 | −1.2 % |
| qinq   | 2110 → 2188 | +3.7 % | 2851 → 2813 | −1.3 % |
| mpls   | 2195 → 2154 | −1.9 % | 2809 → 2802 | −0.2 % |
| ipip   | 2197 → 2198 |  0.0 % | 2794 → 2867 | +2.6 % |
| gre    | 2176 → 2198 | +1.0 % | 2763 → 2648 | −4.2 % |

Receiver stayed at ~3.7–3.8 Mpps (mlx5) / ~3.1–3.3 Mpps (X710) across cells;
`pps_recv` steady, so cyc/pkt is comparable cell-to-cell. As with every prior
at-line-rate run, the fast-path per-call saving is small relative to the full
RX-softirq cost per 64 B packet, so the gate on/off effect sits inside noise
here — the quantified fast-path wins live in the isolated microbenches, not the
line-rate cyc/pkt. The point of this run was the **regression** direction, and
there is none.

## Descent shapes (vxlan / geneve): not measurable on this harness

Both descent scenarios reported `status=overlay-unsupported` with `pps_sent=0`
on both pairs — the series3 cpu-bound-soak runner cannot generate VXLAN/Geneve
overlay traffic through kernel pktgen on these NICs, so there is no wire A/B for
the descents here. This is a test-harness limitation, not a kernel issue: the
descents' byte-identity (fast == slow) is already enforced in-tree by the KUnit
equivalence suite (53/53, incl. the descent-equivalence cases), and their CPU
cost is ~net-zero by construction (the inner work cancels the outer fast-path
saving). gtpu/fou/gue were excluded from this run (gtpu has no sysctl mapping in
the series3 runner; fou/gue require per-netns fou config and aren't
pktgen-scriptable).

## Conclusion

The byte-identical-descent promotion introduces **no unexpected performance
impact** on two AMD Zen 1 pairs (mlx5 25 GbE and i40e 10 GbE): the common path
is unchanged within noise and the byte-identical fast paths match the prior
series4. Raw per-cell artifacts + `matrix.csv` in this directory.
