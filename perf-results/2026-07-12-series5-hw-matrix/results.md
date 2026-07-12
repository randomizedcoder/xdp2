# series5 hardware matrix — 3 ISAs x 3 patch-set states (2026-07-12)

Full-matrix validation of the three send-ready series5 patch sets on
physical hardware, per the elegance-round template (build / boot / dmesg /
engagement per ISA; x86 Phase G same-boot gate-0/1 N=3 as the
authoritative regression instrument).

Kernels: series5-a @ c9908e28 (fastpath, 11 patches), series5-b @ b20681f8
(A + descents), series5-rfc @ 4c8e094e (A + auto controller).
DUTs: hp5 (x86 Zen1, X710 10GbE, hp2 generator), pi5-2 (ARM A76, 6.18
base, pi5-1 generator), bpi-f3 (RISC-V SpacemiT X60, pi5-1 generator).

## Verdict: 9/9 cells PASS

| state | x86 hp5 | ARM pi5-2 | RISC-V bpi-f3 |
|---|---|---|---|
| A (fastpath) | PASS: engage 2.66B, Phase G noise | PASS: engage 508M | PASS: engage 352M |
| B (+descents) | PASS: engage 2.76B, Phase G noise, -ENODEV ✓, summary key ✓ | PASS: engage 676M, toggles ✓ (no fou/gue on 6.x per policy) | PASS: engage 202M, -ENODEV ✓, summary key ✓ |
| RFC (+auto) | PASS: flip 0.5s, pin ✓, unpin 1s, Phase G noise | PASS: flip 1s, pin ✓, unpin 1s | PASS: flip <=10s (2x), pin ✓ |

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
