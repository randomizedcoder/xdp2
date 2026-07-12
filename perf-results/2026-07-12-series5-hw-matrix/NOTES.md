# series5 hardware matrix — running notes (2026-07-12)

Template: 2026-07-10 elegance re-validation (build/boot/dmesg/engagement per
ISA; x86 Phase G same-boot gate 0/1 N=3 = authoritative regression check).
Kernels: series5-a c9908e28, series5-b b20681f8, series5-rfc 4c8e094e.

## x86 hp5 (Zen1, X710) — hp2 generator

### State A (fastpath, 11 patches): PASS
- build ✓ (l, netnext pin) | boot ✓ 7.2.0-rc1 | dmesg ✓ (8 matches all
  pre-existing fw/errata noise, zero flow/jump_label)
- sysctl dir = exactly 7 shape gates, NO descent/auto entries (split
  verified on hardware)
- engagement: eth_ip fast_hits 0 -> 2,661,659,617 (2.66B) over the
  rxhash-off matrix; dissects 10.3B
- Phase G (stateA-hp2-hp5-rxhash-off/): deltas eth_ip -2.55% vlan +1.76%
  qinq -4.78% mpls +0.90% ipip +1.66% gre +2.91% (sd 0.8-3.6%) — mixed
  sign, mean ~0, all within the documented noise floor. NO REGRESSION.
- pppoe: no pktgen scenario (same as all prior rounds)
- BONUS finding: first run accidentally executed with rxhash ON ->
  fast_hits 37 while occurrences hit 3.5B from i40e eth_get_headlen()
  basic-dissector calls (eligibility gate correctly rejects them).
  Real-hardware confirmation of the "eligible% is an upper bound" doc
  note. Kept in stateA-hp2-hp5/ for reference.

## RISC-V bpi-f3 (SpacemiT X60) — pi5-1 generator

### State A: PASS
- engagement: eth_ip fast_hits 0 -> 352,764,670 (352M; occurrences 641M)
  over the pi5-1 pktgen matrix — rv64gcv jump_label static-branch patching
  exercised under live gate toggling, clean. Harness correctly reports
  kernel_has_sysctl=no for descent scenarios on this state.
### (boot chain details)
- cross-build ✓ (l) | deploy: bootloader initially failed (/boot/firmware
  256MB SD full, 13 generations accumulated; also gens 4/5 survived an
  earlier partial delete-generations). Cleaned to gens 7+8, partition 50%.
  Boot ✓ 7.2.0-rc1, sysctl dir = 7 shape gates only, dmesg clean.
- Infra lesson recorded in memory: keep <=2 generations on bpi-f3.

## ARM pi5-2 (A76, 6.18 base) — pi5-1 generator
- State A native build: running

## Pending
x86 B (deploy queued) / x86 RFC / riscv engagement + B + RFC / ARM A/B/RFC

## Completed since last update (2026-07-12 cont.)

### x86 State B: PASS
- boot ✓ (12 sysctls: 7 shapes + 5 descents, no auto) | dmesg ✓
- fou_inner -ENODEV without fou module, works after modprobe ✓ (first
  hardware exercise); all descent gates toggle via summary-key handler ✓
- engagement 2.76B fast_hits; Phase G deltas -3.7%..+2.0% (mean ~-1%,
  noise) — descents present-but-off cost nothing measurable: summary-key
  design validated on hardware.

### x86 State RFC: PASS
- boot ✓ (auto/auto_exclude/auto_window_packets + 7 shapes, NO descent
  gates — RFC rides on A, verified) | auto_exclude default 0x10 ✓
- LIVE controller test @4.3Mpps pktgen, window 200k:
  * autonomous flip ON in 0.5s after auto=1 ✓ (matches dwell x window +
    scheduling theory)
  * pin (auto_exclude |= eth_ip) + forced off: held 0 for 8s under full
    eligible load ✓
  * unpin: re-flip in ~1s ✓ | dmesg clean ✓
- FINDING for the RFC thread: with no RPS configured (fresh boot,
  hardware RSS covering hashing), the controller flipped the gate ON
  based purely on the i40e eth_get_headlen basic-dissector occurrences —
  eligible traffic for the fast path was ZERO (fast_hits flat). Harmless
  by design (gate on with no eligible callers = no effect) but live
  evidence for open question 2 (self-measurement / feedback).
- Phase G stateRFC (auto off): running at time of writing.

### RISC-V State B: PASS
- boot ✓ (12 sysctls) | -ENODEV then modprobe fou -> works ✓ | summary
  key toggles ✓ | engagement 201.8M fast_hits | overlay cells ran ok.
- Boot-partition lesson round 2: 4 generations hit 100% again; trimmed
  to 2 (B, RFC) post-validation.

### RISC-V State RFC: PASS
- boot ✓ (auto sysctls + 7 shapes, auto_exclude=16) 
- controller flipped eth_ip autonomously TWICE under verified pktgen
  (rv64 jump_label text_poke driven by the kworker — first ever); pin
  held 10s under load ✓; unpin re-flip inconclusive within a 30s poll
  (window had been reset to 1M — expected latency exceeds the poll;
  unpin logic proven on x86 at ~1s).
- Test-infra caveat recorded: pi5-1 pktgen (bcmgenet, 6.12.87) stopped
  silently mid-run once — verify pkts-sofar before trusting any
  negative result on this pair.

### Descent data-path scope note
Descent counters deliberately exclude descended packets, so descent
data-path behaviour is validated by KUnit equivalence + the 2026-07-01
flow-distribution study (same code); this round validates descent
presence/toggling/ENODEV/summary-key on all ISAs.

### x86 State RFC Phase G: PASS
Deltas +2.50/-4.63/+3.34/+0.80/+1.37/+3.78% (eth_ip/vlan/qinq/mpls/ipip/
gre) — mixed sign, mean ~+1%, same noise family as states A and B.
The RFC kernel with auto off regresses nothing.

### ARM State B: PASS
- boot ✓ 6.18.34, 10 sysctls (7 shapes + vxlan/geneve/gtpu_inner; no
  fou/gue — B04 excluded on 6.x per policy, composition exactly as
  intended) | descent toggle ✓ | engagement 676.6M fast_hits.

### ARM State RFC: build note
The auto patch carries KUnit test hunks; ARM's 6.x base excludes the
KUnit patch (testbed policy), so the test-file and header-accessor
hunks were stripped from the ARM variant (in-code accessor is
ifdef-guarded and compiles out). NOT a series defect: on net-next the
RFC applies atop full series A including its KUnit patch.
