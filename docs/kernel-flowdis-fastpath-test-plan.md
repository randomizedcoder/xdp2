# Kernel flow_dissector fast-path series — physical test plan

**Date**: 2026-05-27
**Series**: 3 (kernel-patches/series3-flowdis-fastpath/v1)
**Patched kernel**: net-next `flowdis-fastpath-rfc` branch,
  HEAD `28bc2795d2fe` (3 patches on top of net-next
  `c0aa5f13826dcb...`)
**Companion**: `docs/kernel-flowdis-fastpath-plan.md` (the
  series plan), `kernel-patches/series3-flowdis-fastpath/v1/STATUS.md`
  (in-flight state)

## Goal

Validate the 3-patch fast-path series on real network hardware,
across two NIC families and two link speeds, before sending the
non-RFC submission to netdev. Specifically:

  1. The patched kernel boots cleanly on all four testbed hosts
     (hp1, hp2, hp3, hp5).
  2. flow_dissector output is functionally correct — connections
     work, sch_cake hashes packets to consistent classes, no
     RX-path scatter from broken hash.
  3. Microbench (matrix harness) shows the expected
     ~25-30 % ns/pkt reduction on the flat workloads where the
     fast-path hits.
  4. Macrobench (iperf3 + iperf2 through cake) shows no
     throughput regression vs the unpatched baseline; ideally a
     small win as CPU is freed.
  5. 24-hour soak on both pairs shows no leaks, no kernel
     warnings, no drop drift, stable throughput.

If any of these fail, fix and re-test before sending.

## Testbed inventory

| pair | NIC family | link | gen | dut | DUT NIC tuning |
|---|---|---|---|---|---|
| #1 | Intel X710 i40e | 10 GbE SFP+ fibre | hp2 | hp5 | ethtool ntuple (Flow Director) |
| #2 | Mellanox CX-4 Lx mlx5_core | 25 GbE DAC | hp1 | hp3 | tc-flower steering |

All four hosts: AMD Ryzen 5 PRO 2400G (Zen 1, 4c/8t),
NixOS 26.05, currently running 7.1.0-rc4-flowdis-pppoe
(the series 1+2 combined-test-rfc kernel). For series 3
testing we swap to `flowdis-fastpath-rfc` (3 patches on
the same net-next base, but on TOP of net-next mainline
rather than the series 1+2 tree, to test in isolation).

Existing back-to-back v4 subnets:

  pair #1: hp2 10.10.0.2/29 .1.2/29 <-> hp5 10.10.0.5 .1.5
  pair #2: hp1 10.10.2.1/29 .3.1/29 <-> hp3 10.10.2.3 .3.3

IPv6 on the testbed interfaces is NOT configured (verified
2026-05-27); see Phase 0 below for the bring-up steps.

## Phase 0 — Prerequisites (do once before Phase 1)

### 0.1 Build the patched kernel

Update `/home/das/nixos/hp/hp3/test-kernel/default.nix` (and
hp2, hp5 if they have separate test-kernel definitions — check)
to point at the new branch:

```nix
# Was: src = /home/das/Downloads/net-next; branch combined-test-rfc
# Now: src = /home/das/Downloads/net-next; branch flowdis-fastpath-rfc
```

The fetchGit URL stays local. Override `localversion` to keep
the kernels distinguishable from series 1+2:

```nix
"-flowdis-fastpath"  # not "-flowdis-pppoe"
```

Build via:
```bash
cd /home/das/nixos/hp/hp3
nixos-rebuild build
```

Expected build time: ~20-40 min (full kernel + initrd).
Resulting derivation hash captures the patched bzImage.

### 0.2 Add IPv6 addresses to testbed interfaces

The back-to-back links currently have only IPv4 + link-local
IPv6. To exercise the IPv6 fast-path (patch 3), we need
IPv6 unicast addresses on the testbed interfaces.

Proposed ULA (fd00::/8 private) layout, mirroring the v4 /29
addressing scheme:

  pair #1 (i40e):
    hp2 enp1s0f0np0: fd10:10:0::2/64  <-> hp5: fd10:10:0::5/64
    hp2 enp1s0f1np1: fd10:10:1::2/64  <-> hp5: fd10:10:1::5/64

  pair #2 (mlx5):
    hp1 enp1s0f0np0: fd10:10:2::1/64  <-> hp3: fd10:10:2::3/64
    hp1 enp1s0f1np1: fd10:10:3::1/64  <-> hp3: fd10:10:3::3/64

Add to `xdp2.testbed.addresses` in each host's
`configuration.nix`. The `xdp2.testbed` NixOS module needs an
`ipv6` sub-key (or extend the existing
`addresses.enp1s0f0np0` schema to take both v4 and v6). Check
`nix/modules/physical-testbed.nix` for the current schema.

Alternative for v1 testing (skip the NixOS config change for
now): apply addresses ad-hoc via `ip -6 addr add` on each
host. Documented in the test commands; revert after testing.

### 0.3 Ensure perf tools available

The matrix benchmark is invoked via
`nix run .#flow-dissector-matrix-unified`. Verify it builds
clean from the current xdp2 repo state.

iperf3 and iperf2 (`nixpkgs#iperf2`, resolves to iperf-2.2.1)
are already validated on the testbed from B.1 / B.2 work.

## Phase 1 — Deploy + boot (~30-60 min)

Per host, sequentially (so we catch a boot failure on hp2 before
breaking hp5):

```bash
# From workstation, after Phase 0.1 build:
nix-copy-closure --to root@hp2 /nix/store/<patched-kernel-out>
nix-copy-closure --to root@hp2 /nix/store/<patched-system-out>

ssh root@hp2 'nixos-rebuild switch --rollback-on-boot-failure'
# Wait for SSH to return after reboot. Then verify:
ssh root@hp2 'uname -r'
# Expected: 7.1.0-rc4-flowdis-fastpath
ssh root@hp2 'dmesg -t | grep -iE "WARN|BUG|oops" | grep -vE "(known boot-time noise: Zen1 DIV0/FPDSS, ACPI, amdgpu)" | head -10'
# Expected: no output (clean dmesg)
```

Repeat for hp5, hp1, hp3. Total time: ~5-10 min per host
including the boot wait.

Pass criteria:
- All four hosts return from SSH within 2 min of reboot
- `uname -r` matches the expected patched version string
- dmesg has no new WARN/BUG/oops vs the series 1+2 baseline

## Phase 2 — Functional smoke (~30 min)

Verify the patched kernel passes packets correctly. If the
fast-path is producing wrong flow_keys output, things break here
(connection scatter, cake mis-classification, ssh churn).

### 2.1 IPv4 ping both pairs

```bash
# Pair #1: hp2 -> hp5
ssh root@hp2 'ping -c 10 -i 0.2 10.10.0.5; ping -c 10 -i 0.2 10.10.1.5'
# Pair #2: hp1 -> hp3
ssh root@hp1 'ping -c 10 -i 0.2 10.10.2.3; ping -c 10 -i 0.2 10.10.3.3'
```
Expected: 0 % loss, RTT <100 µs steady-state on both pairs.

### 2.2 IPv6 ping both pairs (after Phase 0.2)

```bash
ssh root@hp2 'ping -6 -c 10 -i 0.2 fd10:10:0::5'
ssh root@hp1 'ping -6 -c 10 -i 0.2 fd10:10:2::3'
```
Same pass criteria.

### 2.3 Cake smoke test (each pair, IPv4)

```bash
# Set up cake on the DUT, send brief iperf3
ssh root@hp5 'tc qdisc replace dev enp1s0f0np0 root cake bandwidth 10Gbit triple-isolate; nix run nixpkgs#iperf3 -- -s -B 10.10.0.5 -p 5201 -D'
ssh root@hp2 'nix run nixpkgs#iperf3 -- -c 10.10.0.5 -p 5201 -t 10 -P 4 -f m'

# Check cake class population looks reasonable
ssh root@hp5 'tc -s qdisc show dev enp1s0f0np0 | head -10'
```
Expected:
- iperf3 completes with non-trivial throughput (~9 Gbit/s on
  i40e, ~16 Gbit/s on mlx5 — both consistent with prior
  baselines)
- `tc -s qdisc show cake` shows Sent bytes/pkt incrementing,
  dropped=0 or very low (a few drops are normal startup),
  requeues low

Repeat for pair #2 with `dev enp1s0f0np0 bandwidth 25Gbit` on
hp3.

**Critical: if iperf3 throughput is WAY off baseline (e.g.
1 Gbit/s instead of 9 Gbit/s on i40e), STOP — flow_keys hash
output is probably wrong, RX path is scattering.**

Pass criteria:
- iperf3 completes with throughput within 20 % of unpatched
  baseline on each pair
- cake stats show normal class population (Sent incrementing,
  drops <0.01 %)

## Phase 3 — Microbench (~1-2 hours)

The matrix benchmark drives the kernel's `__skb_flow_dissect_err`
via libflowdis.so in userspace. Measures ns/pkt on the parser
specifically (separated from network I/O cost).

### 3.1 hp5 canonical (i40e DUT)

```bash
nix run .#flow-dissector-matrix-unified -- \
    --pcap data/pcaps/https-web.pcap \
    --testbed testbeds/hp2-hp5-x710.toml \
    --hosts hp5 \
    --parsers c-flowdis-usp
```

Run with 200-iter full mode (not --smoke). Compare ns/pkt to
the unpatched 7.0.x baseline measured pre-series-3
(116-119 ns/pkt on https-web).

**Expected**: ~85-90 ns/pkt patched, ~25-30 % reduction.
Within ±2 ns is the noise band on hp5.

Run on the full sweep (all 6 sweep pcaps):
- https-web (TCP/IPv4) - patch 2 hits
- nfs-server (TCP/IPv4) - patch 2 hits
- pppoe-isp (PPPoE+TCP) - misses (no PPPoE fast-path), 117 ns expected (no change)
- vlan-tcp-mix (VLAN+TCP) - misses (no VLAN fast-path yet), 121 ns expected
- k8s-microservices (mixed) - partial hit (outer flat shapes)
- vxlan-k8s-pure (VXLAN+TCP) - misses encap, 111 ns expected

The "no-change" cells matter: they verify the fall-through cost
is <2 ns/pkt on packet shapes the fast-path declines. If they
regress by >2 ns/pkt, the framework dispatch is too expensive.

### 3.2 hp3 microbench (mlx5 DUT)

Same as 3.1 but on hp3. Both DUTs are Zen 1 4c/8t — numbers
should match within ±2 ns. If hp5 and hp3 diverge by more, that
flags a build-specific issue.

```bash
nix run .#flow-dissector-matrix-unified -- \
    --pcap data/pcaps/https-web.pcap \
    --testbed testbeds/hp1-hp3-mlx5.toml \
    --hosts hp3 \
    --parsers c-flowdis-usp
```

### 3.3 hp2 sanity (i40e GEN)

Same as 3.1 on hp2 (the gen, but its CPU is the same SKU so
this is just a noise-floor check). Within ±2-3 ns of hp5.

## Phase 4 — Macro short tests (~3-4 hours)

Run each protocol variant on each pair for 60 seconds with both
iperf3 (single-threaded server, classic socket-per-stream) and
iperf2 (thread-per-stream, multi-threaded server, stresses
kernel scheduler differently). Verify no regression vs
unpatched baseline. Each cell exercises a specific fast-path
arm; iperf3 and iperf2 vs the same arm catch different
kernel-side bugs (TCP-stack vs scheduler-driven).

### 4.1 Test matrix

| pair | tool | protocol | duration | expected fast-path arm |
|---|---|---|---|---|
| #1 i40e | iperf3 | IPv4 TCP -P 16 | 60 s | patch 2 (IPv4 TCP) |
| #1 i40e | iperf3 | IPv6 TCP -P 16 | 60 s | patch 3 (IPv6 TCP) |
| #1 i40e | iperf3 | IPv4 UDP -P 16 | 60 s | patch 2 (IPv4 UDP) |
| #1 i40e | iperf3 | IPv6 UDP -P 16 | 60 s | patch 3 (IPv6 UDP) |
| #1 i40e | iperf2 | IPv4 TCP -P 16 | 60 s | patch 2 (IPv4 TCP) |
| #1 i40e | iperf2 | IPv6 TCP -P 16 | 60 s | patch 3 (IPv6 TCP) |
| #1 i40e | iperf2 | IPv4 UDP -P 16 | 60 s | patch 2 (IPv4 UDP) |
| #1 i40e | iperf2 | IPv6 UDP -P 16 | 60 s | patch 3 (IPv6 UDP) |
| #2 mlx5 | iperf3 | IPv4 TCP -P 16 | 60 s | patch 2 (IPv4 TCP) |
| #2 mlx5 | iperf3 | IPv6 TCP -P 16 | 60 s | patch 3 (IPv6 TCP) |
| #2 mlx5 | iperf3 | IPv4 UDP -P 16 | 60 s | patch 2 (IPv4 UDP) |
| #2 mlx5 | iperf3 | IPv6 UDP -P 16 | 60 s | patch 3 (IPv6 UDP) |
| #2 mlx5 | iperf2 | IPv4 TCP -P 16 | 60 s | patch 2 (IPv4 TCP) |
| #2 mlx5 | iperf2 | IPv6 TCP -P 16 | 60 s | patch 3 (IPv6 TCP) |
| #2 mlx5 | iperf2 | IPv4 UDP -P 16 | 60 s | patch 2 (IPv4 UDP) |
| #2 mlx5 | iperf2 | IPv6 UDP -P 16 | 60 s | patch 3 (IPv6 UDP) |

16 cells × ~1.5 min each ≈ 25-30 min per pair. Run pairs
sequentially (don't share the gen host). iperf2 cells start
fresh after iperf3 cells per pair so the test kernel's RPS /
TCP state doesn't have to handle protocol-mode mixing.

### 4.2 Commands per cell

```bash
# === iperf3 cells ===
# Server on DUT (one-time setup per pair):
ssh root@hp5 'tc qdisc replace dev enp1s0f0np0 root cake bandwidth 10Gbit triple-isolate'
ssh root@hp5 'nix run nixpkgs#iperf3 -- -s -B 10.10.0.5 -p 5201 -D'

# Client (example: IPv4 TCP):
ssh root@hp2 'nix run nixpkgs#iperf3 -- -c 10.10.0.5 -p 5201 -P 16 -t 60'
# IPv6 TCP:  -c fd10:10:0::5  (or with explicit -6)
# IPv4 UDP:  add -u -b 0
# IPv6 UDP:  -c fd10:10:0::5 -u -b 0

# === iperf2 cells ===
# After iperf3 cells finish on this pair, stop iperf3 server,
# start iperf2 server on port 5202:
ssh root@hp5 'pkill iperf3'
IPERF=/nix/store/iinq9szmz7c60iqlbdhynldky4xri8v9-iperf-2.2.1/bin/iperf
# Hold-open ssh from launcher (pattern validated in B.2 pre-soak):
ssh root@hp5 "$IPERF -s -B 10.10.0.5 -p 5202" > /tmp/iperf2_srv_hp5.log 2>&1 &

# Client (IPv4 TCP):
ssh root@hp2 "$IPERF -c 10.10.0.5 -p 5202 -P 16 -t 60 -f m"
# IPv6 TCP:  -c fd10:10:0::5  -V (force IPv6) OR address auto-detect
# IPv4 UDP:  -u -b 0  (uncapped) OR -b 10G (capped to link)
# IPv6 UDP:  -c fd10:10:0::5 -V -u -b 0
```

**iperf2 IPv6 note**: iperf-2.2.1 supports IPv6 either by
auto-detection of the address family from `-c <addr>` or via the
explicit `-V` flag. Prefer auto-detect; fall back to `-V` if a
test cell hangs at connect.

**iperf2 server lifecycle**: per the B.2 readiness doc, use a
held-open ssh from the test workstation (`ssh root@DUT "$IPERF
-s ..."`) rather than `iperf -D` (the latter doesn't survive
the `nix shell` exit). The held-open ssh is killed via an EXIT
trap when the Phase 4 driver script completes.

Use the TCP-tuning script that we used for B.1 / B.2:
```bash
sysctl -w net.ipv4.tcp_rto_min_us=5000 \
           net.ipv4.tcp_no_metrics_save=1 \
           net.ipv4.tcp_slow_start_after_idle=0 \
           net.ipv4.tcp_autocorking=0
```
(See `perf-results/2026-05-24/extended-validation-plan.md`.)

### 4.3 Pass criteria

Per cell:
- Throughput within 5 % of unpatched baseline (B.1's 16.023
  Gbit/s on mlx5, equivalent ~9.4 Gbit/s expected on i40e)
- 0 % packet loss (UDP cells: <0.1 %)
- No dmesg WARN/BUG/oops appears during the run
- For TCP cells: retransmits per second similar to baseline

Capture per-cell:
- Throughput (Gbit/s)
- Retransmits (for TCP)
- cake stats delta (`tc -s qdisc show` before + after)
- dmesg alert count delta

Save to `perf-results/2026-05-XX-series3-phase4/`.

## Phase 5 — 30-min sustained per pair (~70 min, can parallelize)

Two 30-min runs per pair: one iperf3, one iperf2. Catches slow
memory drift, cumulative cake drop counter creep, and
late-arriving dmesg warnings under both single-threaded and
multi-threaded server load.

```bash
# Round 1: iperf3 30 min, both pairs in parallel
ssh root@hp1 'nix run nixpkgs#iperf3 -- -c 10.10.2.3 -p 5201 -t 1800 -P 16' &
ssh root@hp2 'nix run nixpkgs#iperf3 -- -c 10.10.0.5 -p 5201 -t 1800 -P 16' &
wait

# Round 2: iperf2 30 min, both pairs in parallel (after iperf3
# servers are killed and iperf2 servers brought up — see Phase 4.2
# for the iperf2 server lifecycle pattern)
IPERF=/nix/store/iinq9szmz7c60iqlbdhynldky4xri8v9-iperf-2.2.1/bin/iperf
ssh root@hp1 "$IPERF -c 10.10.2.3 -p 5202 -P 16 -t 1800 -f m" &
ssh root@hp2 "$IPERF -c 10.10.0.5 -p 5202 -P 16 -t 1800 -f m" &
wait
```

Both pairs run in parallel within each round (independent
links, independent host pairs). Round 2 (iperf2) starts after
Round 1 (iperf3) completes — different L7 tools, but the
DUT's kernel state should be reset between rounds.

Pass per round per pair:
- Throughput stable (no degradation over 30 min)
- RSS on DUTs (hp3, hp5) stable (+<50 MB)
- No new dmesg alerts
- cake drops cumulative <100

## Phase 6 — 24h soak (parallel on both pairs, different tools)

Pair the soak coverage so we exercise BOTH NIC families AND
BOTH iperf modes in one 24h wall-clock window:

  Pair #1 (i40e 10 GbE hp2<->hp5): **24h iperf3** soak
    -> validates iperf3 stability on i40e (new — never soaked
       this pair before; complements B.1 mlx5 iperf3 result)

  Pair #2 (mlx5 25 GbE hp1<->hp3): **24h iperf2** soak
    -> validates iperf2 stability on mlx5 (new — B.2 was only
       prepared, never fired against series 3 kernel)

Pairs run in parallel; total wall clock 24h. This gives us four
new long-duration data points:
  - iperf3 / i40e / 24h: new (mlx5 was B.1)
  - iperf2 / mlx5 / 24h: new

Plus the prior B.1 iperf3/mlx5 24h result as a comparison
baseline.

### 6.1 Reuse the B.1 + B.2 soak scripts

Two scripts, one per pair:

`perf-results/2026-05-25/soak_iperf3_main.log` and friends
captured the iperf3 script shape. Parameterise for pair #1:

```bash
PAIR=hp2-hp5-x710 SERVER=hp5 SERVER_IP=10.10.0.5 \
  DEV=enp1s0f0np0 BANDWIDTH=10Gbit \
  /home/das/Downloads/xdp2/perf-results/2026-05-25/soak_iperf3_pair.sh &
```

`perf-results/2026-05-25/soak_iperf2_ready.sh` is the iperf2
soak launcher (already parameterisable, validated in the B.2
1h pre-soak). Adapt for pair #2:

```bash
PAIR=hp1-hp3-mlx5 SERVER=hp3 SERVER_IP=10.10.2.3 \
  DEV=enp1s0f0np0 BANDWIDTH=25Gbit \
  /home/das/Downloads/xdp2/perf-results/2026-05-25/soak_iperf2_ready.sh &
```

Neither script exists as a parameterised version yet — small
editing task during Phase 6 setup. The B.1 script needs the
SERVER_IP and DEV factored out; the B.2 script needs DEV and
BANDWIDTH factored out.

### 6.2 Snapshot collection (per pair, every hour)

Same as B.1:
- `tc -s qdisc show dev <iface>` (cake stats)
- `free -m` (RSS trend)
- `dmesg -t | grep -ciE 'WARN|BUG|oops|sch_cake|flow_hash|flow_dissect'`
- `grep '^Tcp:' /proc/net/snmp` (TCP counters)
- Last completed iperf3 JSON's throughput + retx

Save snapshots to per-pair files.

### 6.3 Pass criteria

Per pair, after 24 h:
- Throughput drift <1 % first 30 runs vs last 30 runs
- RSS within +100 MB of start (process churn only)
- Cake drops <100 total over 24h
- dmesg alert count unchanged from start
- No connection failures requiring iperf3 restart
- No NIC errors / dropped on `ip -s link`

Same standards as B.1's pass.

## Phase 7 — Analysis + cover-letter update (~2-3 hours)

Aggregate the measurements into a results doc at
`perf-results/2026-05-XX-series3-results/results.md`:

- Phase 3 microbench: per-workload before/after table
- Phase 4 macrobench: 10-cell summary table
- Phase 5 sustained: drift number, dmesg observations
- Phase 6 soak: hourly throughput series, drift, dmesg

Update `kernel-patches/series3-flowdis-fastpath/v1/0000-cover-letter.patch`:

- Replace the "expected" ~25-30 % claim with the MEASURED
  percentage (e.g. "Measured 117 -> 87 ns/pkt on hp5
  https-web, a 25.6 % reduction")
- Add a "Multi-NIC + multi-link-rate coverage" section mirroring
  series 1's cover letter, with the same 4-host table
- Add a "24h soak" bullet to the pre-post checklist confirming
  stability
- Move VLAN fast-path / kernel selftest from "TODO" to
  "follow-up v2 items"

Commit cover letter update. Format-patch again. Re-checkpatch.

## Time budget summary

| phase | active hands-on | wall clock |
|---|---:|---:|
| 0 — prerequisites | 2-4 h | 2-4 h |
| 1 — deploy + boot | 30-60 min | 30-60 min |
| 2 — functional smoke | 30 min | 30 min |
| 3 — microbench | 1-2 h | 1-2 h |
| 4 — macro short (16 cells) | 3-4 h | 3-4 h |
| 5 — 30-min sustained × 2 rounds | 10 min setup | 70 min (parallel within each round) |
| 6 — 24 h soak | 30 min setup + check-ins | 24 h |
| 7 — analysis + cover-letter | 2-3 h | 2-3 h |

**Active hands-on total**: ~12-18 hours
**Wall clock total** (with parallel soaks): ~38-42 hours

## Parallelisation notes

Pair #1 (hp2↔hp5) and pair #2 (hp1↔hp3) are physically and
electrically independent. Soaks and 30-min sustained tests can
run simultaneously. Microbench is single-host (driven by hp5
matrix harness or hp3 matrix harness) and can be parallelised
across DUTs.

Phase 4 macro tests SHOULD be sequential per pair — same
host serves both as iperf server and the workstation's
ssh-driver target. Running both pairs simultaneously could
contaminate measurements if workstation CPU or network is
shared between the two ssh streams.

## Risks and what to watch for

| risk | indicator | response |
|---|---|---|
| Patch 1 dispatch site is wrong | iperf3 throughput collapses or scatters across CPUs | Stop. Revert series 3 build. Investigate dispatch placement. |
| Fast-path produces wrong key_addrs | cake class population looks wrong (concentration on one class) | Stop. Spot-check the v4addrs write — likely memcpy length or pointer. |
| Fast-path produces wrong key_ports | hash mis-distribution shows in cake stats | Stop. Verify the __be32 ports read at thoff. |
| Fall-through cost is high (>5 cycles) | non-matching pcap workloads (pppoe-isp, vxlan) regress in microbench | Investigate dispatch shape; possibly inline the dissector identity check. |
| IPv6 fast-path defers more than expected | low hit rate on IPv6 cells, ns/pkt unchanged | Verify flow-label check; verify nexthdr range. Tighten/loosen as needed. |
| Cake memory grows under load | RSS drift during 30-min or 24h soak | Standard memory-leak investigation; might be unrelated to series 3. |

If any risk fires DURING the test, capture full state
(dmesg, cake stats, tcpdump sample, perf top) before reverting
or rebooting. The faster we catch a defect, the faster v2
iteration.

## After v1 testing — paths forward

If all phases pass:
- Update cover letter with measured numbers
- Send series 3 v1 to netdev (cc Jakub Kicinski, Paolo Abeni,
  Eric Dumazet; same list as series 1)
- Wait 1-2 weeks for review feedback
- v2 work: kernel selftest, VLAN fast-path, address review
  comments

If Phase 2-3 reveal correctness defects:
- Don't send v1 to netdev — iterate locally
- Fix in flowdis-fastpath-rfc branch (use --amend or new
  commits depending on what's affected)
- Re-run from Phase 0.1 (rebuild)

If Phase 4-6 reveal performance regressions (>5 % macro
throughput loss):
- Don't send v1 to netdev — investigate
- Possible cause: framework dispatch cost too high (need to
  restructure patch 1) or fast-path code emitting bad
  branches under PGO

## Followups (after v1 lands or is iterated)

- Kernel selftest (`tools/testing/selftests/net/flow_dissect_fast.c`)
  — exercise both fast-path and slow-path on a packet corpus,
  byte-compare struct flow_keys.
- VLAN fast-path (patch 4 in v2)
- Submit v2 with measured numbers + selftest baked in
- Re-run all of Phases 1-7 before each subsequent vX
