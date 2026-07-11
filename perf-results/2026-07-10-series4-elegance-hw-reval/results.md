# series4 elegance round — 3-ISA hardware re-validation (2026-07-10)

Post code-elegance-round check: the refactor (shared `__always_inline`
tunnel classifiers, tri-state enum dispatch, `FIELD_GET`, `guard(rcu)`,
`str_on_off`, `READ_ONCE`) is KUnit-proven byte-identical in *output*, so
this round confirms on real hardware that the changed *codegen* still
builds + boots + engages per-ISA and did not regress performance.

Kernel: `series4-rfc-tail-v3` @ ab72526d (elegance tip).

## Verdict: PASS — build + boot + engagement on all 3 ISAs; no x86 regression.

| ISA | DUT | build | boot | dmesg | engagement (fast_hits) | Phase G |
|---|---|---|---|---|---|---|
| x86 Zen1 | hp5 (X710 10GbE) | ✓ native | ✓ 7.2.0-rc1 | clean | 0 → **1,374,151,531** | **valid, clean** |
| RISC-V K1 | bpi-f3 (rv64gcv) | ✓ cross | ✓ 7.2.0-rc1 | clean | 5 → 7.1M+ | queue-noise |
| ARM A76 | pi5-2 (6.x base) | ✓ **native on Pi** | ✓ 6.18.34 | clean | 5 → 4,816 (369M in matrix) | queue-bound |

(dmesg "clean" = zero flow/dissect/BUG/jump-label matches; the one hp5 line
is an unrelated HP-WMI firmware bug at boot. The RISC-V run exercised
`arch/riscv/kernel/jump_label.c` static-branch patching under gate toggling
with no warnings — the doc's cited RISC-V-specific value.)

## x86 Phase G — the authoritative regression check

hp2→hp5, X710 10GbE, 64B pktgen, ksoftirqd `perf stat`, rxhash off (RPS
software-hashes so the eligible dissector runs), same-boot gate 0/1, N=3.
Engagement confirmed: eth_ip fast_hits reached 1.37 **billion** over the run.
**Interpret same-boot gate deltas only** (≈5% boot-to-boot floor).

| scenario | off c/p | on c/p | delta | sd | pre-refactor delta |
|---|---|---|---|---|---|
| eth_ip | 6240 | 6211 | -0.46% | 175 | -1.33% |
| vlan | 6606 | 6446 | -2.41% | 189 | +1.01% |
| qinq | 6257 | 6299 | +0.68% | 160 | +0.30% |
| mpls | 6362 | 6381 | +0.29% | 113 | +0.27% |
| ipip | 6448 | 6409 | -0.61% | 154 | -2.45% |
| gre | 6575 | 6613 | +0.57% | 280 | -2.65% |

All gate on/off deltas sit in the noise floor (sd ≈ 2-4% of a ~6.4k-cycle
softirq path; the dissector is a 1-2% end-to-end effect). The elegance vs
pre-refactor (2026-07-08) column shows the two kernels' deltas scatter
symmetrically around zero (mean shift ≈ +0.5pp, mixed sign) — a uniform
codegen regression would push *every* elegance delta consistently worse;
instead they cancel. **The refactor is codegen-neutral. No regression.**

vxlan/geneve show 0 cells on X710 (overlay-unsupported — mlx5-only pktgen
trick; unchanged from pre-refactor).

## ARM / RISC-V matrices — engagement-proven, delta-noisy (expected)

Both 1GbE pairs are queue-bound (documented: "RISC-V dual-sender stress
proves the K1 macro is queue-bound; the microbench is the right instrument
there"). RISC-V cycles/pkt carried sd 12-35% (deltas −25%..+66%, random
scatter); ARM's receiver ran near-idle at line rate so ksoftirqd captured
almost nothing (cycles/pkt 3-16, meaningless ratios). Neither yields a
usable regression signal — but both **engaged** (fast_hits climbed under
pktgen), which is the per-ISA proof that the refactored code executes
correctly on rv64gcv and aarch64. The regression conclusion rests on x86
(CPU-bound, clean), as it always has.

## Infra notes
- pi5-1 (ARM+RISC-V pktgen generator) must run **6.12.87** (its 6.18
  bcmgenet wedges the NIC under pktgen TX — it hung mid-run and needed a
  power-cycle). Restored to a cached 6.12.87 system (the documented-correct
  pktgen generator kernel); left there.
- ARM kernel now builds **natively on pi5-2** (A76 + NVMe) via
  `nixos-rebuild --build-host root@pi5-2` — no qemu binfmt emulation, much
  faster than the emulated x86 build. (The cross-compile path via
  `nixpkgs.buildPlatform = "x86_64-linux"` also works and is kept on the
  pi5-2-sdimage variant.)
