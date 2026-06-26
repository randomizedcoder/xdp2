# Resume notes — Phase H continuation (2026-06-21)

**Last written before a planned reboot of `l`** (the workstation Claude is SSHed into for orchestration). Read this on the next session to pick up cleanly.

## Where we left off (TL;DR)

Phase H foundation + first overnight matrix already shipped to `flow-keys-compat-reorder` (commits `307d1a7`, `ce4687e1`). Cover-letter summary at `perf-results/2026-06-19-phase-h-summary/SUMMARY.md` documents the honest finding from N=3 reps: **hp2-hp5 VLAN UDP -148 cyc/pkt (-4.9%) is the one cleanly above-noise Phase G result**.

Three loose ends remain, in priority order:

1. **l-l2 25 GbE pair** has come online (l2's HP-firmware ConnectX-4 Lx arrived 2026-06-21). Link verified at 20 Gbits/sec TCP with 4 streams, 0.148ms RTT. Currently CANNOT be driven by the orchestrator because both l and l2 carry the OLD v1 series-3 patches (3 patches, no `net.flow_dissector.*` sysctls). Bringing l-l2 into Phase H needs the v3-namespace 10-patch series on at least l2 (receiver-side is what matters for the fast-path measurement).
2. **pi5-pair Phase G data** stuck at 1 cell. Pi5-1 (sender) on 6.18.34 reproducibly takes its NIC offline within ~30s of pktgen TX (bcmgenet regression). Pi5-2 (receiver) is fine on 6.18 and produced clean perf-stat data (570k cycles for 60s in the one good cell). Rollback strategy decided but not yet executed (see §pi5 below).
3. **DUR=300 N=3 replicate run** flagged as "gold-standard cover-letter follow-up" in both Phase F and Phase G SUMMARY.md files. Combined ~46h wall-clock — not started; lowest priority.

## Current testbed state

| Host | Kernel | Patches | Sysctls | Status | Notes |
|---|---|---|---|---|---|
| **hp1** | 7.0.9 | v3-namespace 10 patches | ✓ all 10 | up | Phase H matrix done (iperf3 + pktgen, N=3) |
| **hp3** | 7.0.9 | v3-namespace 10 patches | ✓ all 10 | up | Phase H matrix done |
| **hp2** | 7.0.0 | v3-namespace 10 patches | ✓ all 10 | up | Phase H matrix done — produced the headline (vlan -148 cyc/pkt) |
| **hp5** | 7.0.0 | v3-namespace 10 patches | ✓ all 10 | up | Phase H matrix done |
| **pi5-1** | 6.18.34 (rpi develop) | v3-namespace 10 patches | ✓ all 10 | up (just power-cycled) | bcmgenet TX wedges under pktgen. Either rollback to 6.12.87 or use as receiver only |
| **pi5-2** | 6.18.34 (rpi develop) | v3-namespace 10 patches | ✓ all 10 | up | Stable as receiver. Has `linuxPackages.perf` installed. Produced clean cycles data |
| **l** | 6.18.35 | **OLD v1 series-3** (3 patches via flowdis-fastpath service) | ✗ no `net.flow_dissector.*` | up | Workstation we're on. Needs v3-namespace patches for Phase H driving |
| **l2** | 7.0.12 | **OLD v1 series-3** (3 patches in test-kernel/) | ✗ no `net.flow_dissector.*` | up | NIC verified 25GbE both ports. Needs v3-namespace patches |

## Recent commits worth knowing

```
ce4687e1 perf-results: Phase H comprehensive matrix + cover-letter summary
307d1a76 nix: Phase H foundation - comprehensive coverage + summary table
ab3995eb perf-results: Phase G CPU-bound matrix (pktgen, DUR=60, 28 cells)
669a8bb6 nix/series3-cpu-bound-soak: Phase G pktgen+perf-stat orchestrator
234656c8 nix/scenarios: emit L_SCENARIO_MAC / L2_SCENARIO_MAC
b4f0f90c perf-results: Phase F CONSUMER_ALL=1 matrix - floor lift validated
87bcb82d nix/series3-extensions-soak: add consumer activation (RPS/RFS/CAKE/FLOWER)
```

## Key files to know

| Path | What's there |
|---|---|
| `~/Downloads/xdp2/nix/series3-extensions-soak.nix` | Phase F orchestrator (iperf3 + RPS/CAKE/FLOWER consumers, REPLICATES knob) |
| `~/Downloads/xdp2/nix/series3-cpu-bound-soak.nix` | Phase G orchestrator (kernel pktgen + ksoftirqd perf-stat, REPLICATES knob, overlay-unsupported tagging) |
| `~/Downloads/xdp2/nix/series3-summary-report.nix` | Cover-letter table generator (awk; detects rep column; ranks by abs(% improvement)) |
| `~/Downloads/xdp2/nix/series3-comprehensive-{iperf3,pktgen}-soak.nix` | Phase H wrappers with overnight defaults |
| `~/Downloads/xdp2/nix/scenarios/netconf-eth_ip.nix` | Bare ETH+IP "scenario" — no encap; emits underlay as scenario |
| `~/Downloads/xdp2/nix/scenarios/lib.sh` | `read_mac` helper |
| `~/nixos/hp/hp5/test-kernel/` | Reference test-kernel with the 10 v3-namespace patches (copy this shape for l and l2) |
| `~/nixos/arm/pi5-1/test-kernel/` | Pi version of same (uses `nixos-raspberrypi` linux_rpi5 base instead of `linuxPackages_latest`) |
| `~/nixos/desktop/l/test-kernel/` | **DOES NOT EXIST** — needs creating, mirroring hp/hp5/ |
| `~/nixos/desktop/l/flowdis-fastpath-module.nix` | Old v1 series — to be REMOVED from `imports` when switching to v3-namespace |
| `~/nixos/desktop/l2/test-kernel/` | Exists with OLD 3-patch series; replace 3 patches with the v3-namespace 10 |
| `~/Downloads/xdp2/perf-results/2026-06-19-phase-h-summary/SUMMARY.md` | First Phase H run's honest writeup |
| `~/Downloads/xdp2/perf-results/2026-06-19-phase-h-summary/SUMMARY-cover-letter.md` | Auto-generated cover-letter table |

## Pre-reboot work (do before rebooting l)

### 1. Build the l test-kernel (mirroring hp5's pattern)

```sh
cd ~/nixos/desktop/l
mkdir -p test-kernel
cp ~/nixos/hp/hp5/test-kernel/default.nix test-kernel/
cp ~/nixos/hp/hp5/test-kernel/000{1..9}-*.patch test-kernel/
cp ~/nixos/hp/hp5/test-kernel/0010-*.patch test-kernel/
ls test-kernel/  # should show default.nix + 10 .patch files
```

### 2. Edit `~/nixos/desktop/l/configuration.nix`

- Remove `./flowdis-fastpath-module.nix` from `imports` (or comment out)
- Remove any `services.flowdis-fastpath.enable = true;` line
- Add `boot.kernelPackages = pkgs.linuxPackagesFor (pkgs.callPackage ./test-kernel { });` (look at `~/nixos/hp/hp5/configuration.nix:65-67` for the exact pattern — note hp's pattern uses `pkgs.linuxPackages_latest` as the base which is what we want here, NOT `nixos-raspberrypi`'s linux_rpi5)

### 3. Mirror to l2

```sh
cd ~/nixos/desktop/l2
# l2 already has test-kernel/ but with 3 old patches — replace
rm test-kernel/0001-series3.patch test-kernel/0002-series3.patch test-kernel/0003-series3.patch
cp ~/nixos/hp/hp5/test-kernel/000{1..9}-*.patch test-kernel/
cp ~/nixos/hp/hp5/test-kernel/0010-*.patch test-kernel/
# diff l2/test-kernel/default.nix vs hp5/test-kernel/default.nix — make them match
```

### 4. Deploy l2 (no session disruption)

```sh
cd ~/nixos/desktop/l2
nixos-rebuild switch --flake .#l2 --target-host root@l2 --use-substitutes
ssh root@l2 reboot
# wait for ssh up, verify
ssh root@l2 "uname -r; sysctl net.flow_dissector.eth_ip"
```

### 5. Deploy l locally (THIS DROPS THE SESSION)

```sh
cd ~/nixos/desktop/l
sudo nixos-rebuild switch --flake .#l
sudo reboot
# session ends here — reconnect manually
```

## Post-reboot work (resume here in a new session)

### 1. Verify both l and l2 came up healthy

```sh
uname -r                                           # l, should be 6.18.x or later with v3 patches
sysctl net.flow_dissector.eth_ip                   # should print "= 0"
ssh root@l2 "uname -r; sysctl net.flow_dissector.eth_ip"
ping -c 3 10.10.4.5                                # 25GbE link still up
```

### 2. Smoke test l-l2 with the orchestrator (DUR=30, 1 rep)

```sh
cd ~/Downloads/xdp2
PAIRS=l-l2 SCENARIOS=eth_ip DUR=30 REPLICATES=1 CONSUMER_ALL=1 \
  OUT=/tmp/l-l2-smoke nix run .#series3-extensions-soak
# Check: matrix.csv has 4 rows (1 pair × 1 scen × 2 protos × 2 sysctl × 1 rep)
# Expected mbps: ~20Gbps TCP, ~12-18Gbps UDP
```

### 3. Full Phase H run on l-l2 (foreground or background per session policy)

```sh
today=$(date +%Y-%m-%d)
PAIRS=l-l2 OUT=perf-results/${today}-phase-h-l-l2-iperf3 \
  nix run .#series3-comprehensive-iperf3-soak  # ~1.9h: 96 cells * 70s
PAIRS=l-l2 OUT=perf-results/${today}-phase-h-l-l2-pktgen \
  nix run .#series3-comprehensive-pktgen-soak  # ~0.9h: 48 cells * 70s
```

### 4. Regenerate cover-letter summary across all matrices

```sh
mkdir -p perf-results/${today}-phase-h-summary
nix run .#series3-summary-report -- \
  perf-results/2026-06-19-phase-h-iperf3/matrix.csv \
  perf-results/2026-06-19-phase-h-pktgen/matrix.csv \
  perf-results/${today}-phase-h-l-l2-iperf3/matrix.csv \
  perf-results/${today}-phase-h-l-l2-pktgen/matrix.csv \
  > perf-results/${today}-phase-h-summary/SUMMARY-cover-letter-v2.md
# Top entry of the Phase G table should be the strongest |% improvement|
# Expect l-l2 to show stronger signal than hp pairs due to faster CPU
```

### 5. Commit + push

```sh
cd ~/Downloads/xdp2
git add nix/ perf-results/${today}-phase-h-l-l2-iperf3/ perf-results/${today}-phase-h-l-l2-pktgen/ perf-results/${today}-phase-h-summary/
git commit -m "perf-results: Phase H + l-l2 25 GbE pair (4th testbed)"
git push origin flow-keys-compat-reorder
```

## Decisions parked for the user

These are the open trade-offs we haven't resolved. Pick one when convenient:

### Pi5 disposition (low priority — receiver-side data already exists)
- **A.** Roll pi5-1 back to 6.12.87 (gen-7 still installed: `nixos-rebuild switch --rollback --target-host root@pi5-1`), keep pi5-2 on 6.18. Re-run pi5-pair Phase G with sender on 6.12 + receiver on 6.18.
- **B.** Roll BOTH pi5s back to 6.12.87, install `linuxPackages.perf` to systemPackages (this was the original cheap fix we skipped). Symmetric; no asymmetric-kernel weirdness.
- **C.** Document pi5 Phase G as "1 cell of clean 6.18 receiver data" and move on. Pi5 Phase F data exists from the 2026-06-19 run and is already in the summary.

Recommendation: **B** is cleanest. Was the right move from the start. 

### Should l send or just l2 receive?
Plan above assumes BOTH l and l2 get the v3-namespace patches (Option A from the earlier conversation). Lower-risk alternative was Option B: patch only l2, leave l on whatever it had. Decision: user picked **A** (full patch on both) since the l-reboot is handled by this resume doc.

### DUR=300 N=3 follow-up
Both Phase F and Phase G SUMMARY.md flag this as the gold-standard for tightening confidence intervals on the cover-letter quotes. ~46h wall-clock. Not started; only pursue if a reviewer pushes back on noise-tagged rows in the current summary table.

## What changed in the operator's reach in this session

Active tasks in the task tracker (likely stale on resume — recheck `TaskList`):
- #74 was the original "comprehensive overnight run + SUMMARY-cover-letter.md" — marked completed at end of 2026-06-19 cycle
- No active in_progress tasks at write-time. New session will likely want to create fresh tasks for l-l2 work.

Quick-reference of where the working flake outputs live:
```sh
nix flake show ~/Downloads/xdp2 | grep -E 'series3|netconf' | head -30
```
