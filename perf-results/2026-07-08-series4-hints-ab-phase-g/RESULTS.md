# series4 v3: hints layout A/B + first real in-kernel Phase G — 2026-07-08

Three Phase G runs on hp2→hp5 (X710, 64B pktgen, `perf stat` on ksoftirqd,
RPS/RFS only, cake/flower off, **rxhash off** so RPS software-hashes and the
eligible dissector actually runs; fast-path engagement verified live at
~1.25 M fast_hits/s during gate-on cells):

1. `2026-07-08-series4-v3-phase-g-rxhash-off/` — v3 kernel (shipped hints,
   `static_branch_unlikely`), boot 1.
2. `2026-07-08-series4-hints-ab-phase-g/` — hints-reverted kernel
   (`series4-hints-ab` @ 0dd06703: dispatcher gates back to
   `static_branch_likely`, everything else identical; A/B only, not shipped).
3. `2026-07-08-series4-v3-phase-g-aba-control/` — v3 kernel again (A-B-A
   control), boot 3.

## Verdict 1: likely→unlikely has no measurable in-kernel impact

Run 2 (AB) initially appeared ~5% faster than run 1 across *every* cell —
including gate-off, where the hint difference is a single branch and cannot
cost 300+ cycles. The A-B-A control resolved it: run 3, on the **same v3
kernel** as run 1, came back at AB levels (pps_recv 1.373M vs AB 1.370M vs
run-1 1.289M; cycles/pkt overlapping AB throughout). The offset tracks the
**boot**, not the kernel: post-reboot IRQ/RSS-to-CPU mapping and layout luck
produce a ~5% between-boot floor on this pair. Adjacent-boot AB-vs-control
deltas are mixed-sign and within noise. The hint change stands on its
architectural merits (default-off gate = not-taken NOP fall-through,
consistent with kernel convention for DEFINE_STATIC_KEY_FALSE).

**Methodology rule this bakes in: never compare Phase G numbers across
boots. Only same-boot sysctl 0/1 cells are meaningful.**

## Verdict 2: first real in-kernel gate on/off numbers (same-boot, pooled
over both v3 boots, N=6/cell, cycles/pkt lower=better)

| scenario | gate off | gate on | delta | pooled sd |
|---|---|---|---|---|
| eth_ip | 6506.7 | 6476.6 | −0.46% | 217.9 |
| vlan   | 6870.9 | 6793.6 | −1.13% | 178.1 |
| qinq   | 6639.1 | 6657.7 | +0.28% | 208.2 |
| mpls   | 6677.2 | 6645.2 | −0.48% | 293.7 |
| ipip   | 6699.5 | 6726.9 | +0.41% | 181.1 |
| gre    | 6862.8 | 6679.0 | −2.68% | 237.4 |

Honest reading: with software-RPS hashing the total softirq path is ~6.7k
cycles/pkt; the dissector's isolated saving (47–55% of dissector cost per
the userspace microbench ≈ 50–150 cycles) is a 1–2% end-to-end effect —
at or below this instrument's same-boot noise (sd ≈ 3%) for most shapes.
GRE (−2.7%) is the only shape approaching clean signal, consistent with the
microbench (ipip/gre have the largest per-dissect savings). Direction is
right in 4/6 shapes; nothing is negative beyond noise → **no regression,
no surprise from the v3 changes (hints, flag admit, label defer)**.

Implication for the cover letter: keep the isolated microbench numbers as
the perf claim (they are the honest instrument for dissector cost), state
the end-to-end effect is proportional to the dissector's share of the
receive path, and do not quote cross-boot in-kernel deltas.

Note run 1 of this date (`2026-07-08-series4-v3-phase-g-fixed-kernel/`,
rxhash ON, cake+flower on) is retained as evidence of the engagement trap:
its dissection volume was tc-flower's ineligible custom-dissector calls and
fast_hits moved by ~52 in an hour — the configuration every historical
Phase F/G run used unknowingly. vxlan/geneve cells are overlay-unsupported
on X710 (mlx5-only pktgen trick); descent perf claims stay ~net-zero as
before.
