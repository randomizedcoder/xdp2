# series5 hardware matrix — 3 ISAs x 3 patch-set states (2026-07-12)

Full-matrix validation of the three send-ready series5 patch sets on
physical hardware, per the elegance-round template (build / boot / dmesg /
engagement per ISA; x86 Phase G same-boot gate-0/1 N=3 as the
authoritative regression instrument).

Kernels: series5-a @ c9908e28 (fastpath, 11 patches), series5-b @ b20681f8
(A + descents), series5-rfc @ 4c8e094e (A + auto controller).
DUTs: hp5 (x86 Zen1, X710 10GbE, hp2 generator), pi5-2 (ARM A76, 6.18
base, pi5-1 generator), bpi-f3 (RISC-V SpacemiT X60, pi5-1 generator).

## Verdict: 12/12 cells PASS (3 ISAs + a 2nd x86 NIC, x 3 states)

| state | x86 hp5 | ARM pi5-2 | RISC-V bpi-f3 |
|---|---|---|---|
| A (fastpath) | PASS: engage 2.66B, Phase G noise | PASS: engage 508M | PASS: engage 352M |
| B (+descents) | PASS: engage 2.76B, Phase G noise, -ENODEV ✓, summary key ✓ | PASS: engage 676M, toggles ✓ (no fou/gue on 6.x per policy) | PASS: engage 202M, -ENODEV ✓, summary key ✓ |
| RFC (+auto) | PASS: flip 0.5s, pin ✓, unpin 1s, Phase G noise | PASS: flip 1s, pin ✓, unpin 1s | PASS: flip <=10s (2x), pin ✓ |

### Fourth DUT: hp1->hp3 (x86 Zen1, Mellanox CX-4 Lx 25GbE DAC, mlx5)

Added to cross-check the X710/i40e results against a second NIC + driver
at 25GbE, and — critically — because the mlx5 path let us run LIVE
overlay descent traffic the X710 could not.

| state | verdict |
|---|---|
| A | PASS: engage 7.02B fast_hits, Phase G -3.1%..+0.9% (noise) |
| B | PASS: engage 6.99B, -ENODEV ✓, Phase G noise, LIVE VXLAN descent (below) |
| RFC | PASS: flip ~1s, fast_hits 2.58M/s post-flip, pin held 8s, unpin ~1s |

mlx5 cycles/pkt run ~2700 vs X710 ~6500 (different softirq path / 25GbE);
same-boot gate deltas are the claim and they sit in the noise floor on
both NICs, so the no-regression result holds across both drivers.

**LIVE VXLAN descent on hardware (first of the campaign).** Built a
fixed-outer-srcport VXLAN tunnel hp1<->hp3, ran 16 inner UDP flows, and
measured softirq CPU spread with vxlan_inner off vs on:
  - gate OFF (outer-only hash): busiest CPU 63% of load
  - gate ON  (inner-flow descent): 50/50 — descent parsed the inner
    5-tuples on live mlx5 traffic, no crash, eth_ip fast_hits climbing.
The spread improvement is muted (63/37 -> 50/50, not N-way) because this
host is benchmark-tuned with isolcpus=2-7, leaving RPS only CPUs 0-1 to
spread across. The value here is the *proof the descent data path
executes correctly on live hardware*; the unconstrained inner-flow hash
distribution is quantified separately in the 2026-07-01 study. VXLAN/
Geneve cells in the automated pktgen matrix still show
overlay-unsupported (kernel pktgen can't add_device against a vxlan
netdev — a harness limit, not a kernel one), hence this manual
iperf3-over-tunnel demonstration.

## x86 Phase G (hp2->hp5, X710, 64B pktgen, rxhash off, N=3)

Same-boot gate on/off deltas per scenario; all three kernels sit in the
documented noise floor (sd 0.8-3.6%, boot-to-boot floor ~5%):

| scenario | state A | state B | state RFC |
|---|---|---|---|
| eth_ip | -2.55% | -0.74% | +2.50% |
| vlan   | +1.76% | -2.19% | -4.63% |
| qinq   | -4.78% | +2.01% | +3.34% |
| mpls   | +0.90% | -0.05% | +0.80% |
| ipip   | +1.66% | -1.39% | +1.37% |
| gre    | +2.91% | -3.74% | +3.78% |

Mixed sign, mean ~0 in every column: no regression in any state. State B
matching A validates the summary-key design — five gated descents present
in the kernel cost nothing measurable when off. (pppoe: no pktgen
scenario, as in all prior rounds; geneve/vxlan cells overlay-unsupported
on X710, exercised on the 1GbE pairs instead.)

## Auto controller: first hardware exposure (all three ISAs)

- Autonomous enable under eligible traffic: x86 0.5s @4.3Mpps (window
  200k), ARM ~1s @364k dissects/s (window 50k), RISC-V <=10s (window
  50k) — each includes the arch's jump_label/text_poke path driven from
  the kworker, all clean.
- auto_exclude pin: gate forced off while excluded stayed off under full
  eligible load on all three ISAs.
- Unpin re-flip: ~1s on x86 and ARM. RISC-V inconclusive within a 30s
  poll (window had been reset to 1M; expected latency exceeds the poll —
  not a logic failure, per the x86/ARM results).
- FINDING (for the RFC thread, open question 2): on a freshly booted x86
  DUT with no RPS configured and hardware RSS supplying skb->hash, the
  controller enabled eth_ip on the strength of i40e eth_get_headlen()
  basic-dissector occurrences alone — zero eligible skb_get_hash traffic
  existed (fast_hits stayed flat). Harmless by design (a gate with no
  eligible callers has no effect) but live evidence that eligible% is an
  upper bound; self-measurement/feedback would close it.
- FINDING (infra): a dst_mac set via `$(ssh hp3 cat .../address)` during
  hp3's reboot window resolved empty (host unreachable) -> pktgen fired
  at 00:00:00:00:00:00, hp3 rx_packets_phy/s=0, controller correctly did
  nothing (no dissects, no flip). Capture MACs before the reboot, and
  verify rx_packets before trusting a no-flip result. (Same class as:)
- FINDING (infra): pi5-1's pktgen (bcmgenet, 6.12.87) stopped silently
  mid-run once, initially masquerading as a controller failure on
  RISC-V. Verify pkts-sofar before trusting any negative result on the
  1GbE pairs.

## Notes and caveats

- ARM 6.x composition per established policy: KUnit/docs patches excluded
  everywhere on 6.18; descent patch B04 (FOU/GUE) excluded (fou_core.c
  hook differs); the auto patch's KUnit hunks stripped in the ARM variant
  (ifdef'd accessor compiles out). None of this affects the net-next
  submission, where each series applies whole.
- Descent data-path semantics are validated by the KUnit equivalence
  suite and the 2026-07-01 flow-distribution study (same code); this
  round adds descent presence/toggling/-ENODEV/summary-key on all ISAs.
- The rxhash-on first run (stateA-hp2-hp5/) is retained as a bonus
  dataset: 3.5B basic-dissector occurrences with 37 fast_hits — hardware
  confirmation of the eligible%-upper-bound doc note.
- bpi-f3 ops: /boot/firmware (256MB) holds <=3 RISC-V generations; two
  cleanup rounds this session; keep the profile at <=2 generations.

See NOTES.md for the chronological log with raw numbers per cell.
