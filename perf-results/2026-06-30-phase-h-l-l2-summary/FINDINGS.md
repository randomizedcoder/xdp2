# Phase H on the l↔l2 25 GbE pair — findings (2026-06-30)

First live run of the **l↔l2** pair (AMD Threadripper PRO 3945WX Zen 2 ×2,
Mellanox ConnectX-4 Lx 25 GbE back-to-back). This pair had never completed a
run before — the 25 GbE link was dead until the HP-OEM NIC swap. Goals:
(1) how close to 25 GbE line rate, (2) how much the series-3 flow_dissector
fast-path helps. Method: same-kernel sysctl A/B (`net.flow_dissector.*`
0=slow path vs 1=fast path), N=3, DUR=60, `CONSUMER_ALL=1` (RPS/RFS/cake/flower).

## Bring-up gaps fixed (first run on this pair)

- **HP NIC swap verified.** Both ends now HP-OEM ConnectX-4 Lx (PSID
  `HP_2420110034`, fw 14.27.4000); both back-to-back DACs up at 25000Mb/s.
  Resolves `2026-06-15-l-l2-dac-eeprom-issue.md` (the generic-OEM firmware
  refused the DAC EEPROM).
- **`ssh root@l` was rejected** — the orchestrator drives the generator (`l`)
  entirely over `ssh root@l`. Fixed declaratively: added the das@t key to
  `users.users.root.openssh.authorizedKeys.keys` in `~/nixos/desktop/l/`.
- **iperf3 not installed** on either host — the orchestrator's `nix eval`
  fallback returns an unrealized store path. Added `iperf3` to
  `systemPackages` on both `l` and `l2` (edits staged in `~/nixos`); realized
  into both stores to run immediately.

## Line-rate ceiling: ~16 Gbps, and why (not the silicon)

| Config (l→l2) | Throughput | Bottleneck |
|---|---|---|
| Baseline (testbed-tuned) | 16.4 Gbps | l2 receiver: 4 cores (0-3) at 73-88% |
| Server on all 24 cores + RPS-all | 11.0 Gbps | worse |
| GRO/LRO on (runtime) | 7.4 Gbps | worse (LRO misbehaves on mlx5) |
| Flipped (l2→l) | 13.1 Gbps | l receiver saturated (608% CPU) |

The generator is **not** CPU-bound (sender uses <1 core; TSO offload). The cap
is the **receiver `l2`**, which is configured for **AF_XDP**, not kernel-stack
throughput: `isolcpus=4-23` + `nohz_full=4-23` + `rcu_nocbs=4-23` leave only 4
schedulable cores for the RX stack + iperf3 server; NIC offloads are **off**
(GRO/TSO/GSO, for parser reproducibility); and NIC queues/IRQs are pinned to
the isolated cores. Relaxing these at runtime made throughput *worse* (the
`nohz_full` cores are hostile to softirq/RPS). Reaching 25 GbE kernel-stack
would require re-tuning l2 (offloads on, isolation off, queues/IRQs spread) +
a reboot — a separate effort, orthogonal to the patch test. **Decision:** ran
the patch campaign in the clean-measurement config; ~16 Gbps is the honest
line-rate number for it. The Zen 2 silicon and the link are not the limit.

## Patch results

**Phase G — pktgen cycles/pkt (cleanest CPU-bound signal).** 3.24 Mpps of 64 B
UDP; cyc/pkt = total ksoftirqd cycles/packet under the full consumer stack (so
flow_dissect is a small fraction → small % but real).

- **eth_ip: 2303 → 2191 = −112 cyc/pkt (−4.9%)** — clean, above noise.
  Consistent with the hp fleet headline (hp2-hp5 −148 cyc/pkt, −4.9%).
- vlan/qinq/mpls/ipip/gre: within ±2× pooled stddev (noise) at N=3.
- vxlan/geneve: `overlay-unsupported` (kernel pktgen can't `add_device` a
  vxlan/geneve netdev) — expected, filtered.

**Phase F — iperf3 receiver softirq % (RPS/cake/flower loaded).** Fast-path
savings strongest on encap TCP, where the slow path re-parses more:

- vxlan tcp −1.33pp (−15.5%), qinq tcp −1.18pp (−11.6%), gre tcp −0.53pp (−7.9%).
- eth_ip and several udp cells within noise; a few small +regressions
  (qinq udp +9.6%) reflect the small signal + run-to-run variance.

Full ranked tables: `SUMMARY.md`. Raw matrices:
`../2026-06-30-phase-h-l-l2-iperf3/matrix.csv`,
`../2026-06-30-phase-h-l-l2-pktgen/matrix.csv`.

## Follow-ups

- Optional: re-tune l2 for kernel-stack throughput (offloads on, isolation
  relaxed, queues/IRQs spread) to characterize the true 25 GbE ceiling.
- Commit the `~/nixos/desktop/{l,l2}/` edits (root key on l; iperf3 in
  systemPackages on both) — currently staged locally, separate repo.
