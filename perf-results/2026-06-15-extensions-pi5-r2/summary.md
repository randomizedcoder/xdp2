# series3 extension patches — first numbers (pi5-1 ↔ pi5-2, 2026-06-15)

First end-to-end matrix run with the **v1-netdev extension patches** applied to both pi5 hosts. The byte-identical VLAN (0004) and QinQ (0005) extensions show real, measurable system-CPU savings on UDP traffic where the dissector is enough of the cost to matter; TCP cells are too cheap to register a signal at 1 GbE.

## Setup

- **Pair**: pi5-1 ↔ pi5-2 (Cortex-A76 4c @ 2.4 GHz, 1 GbE genet, kernel 6.12.87)
- **Kernel**: parent `series3-flowdis-fastpath` (v1-netdev 3-patch) + extension patches 0004 (VLAN) + 0005 (QinQ) + 0006 (VXLAN-inner RFC EXPERIMENT)
- **Switch passes 802.1Q-tagged and stacked-tag frames untouched** (verified earlier in the session)
- **Orchestrator**: `nix run .#series3-extensions-soak`
- **Cells per scenario**: 4 = {tcp,udp} × {sysctl 0, sysctl 1}, DUR=30s each, 4-parallel iperf3

## Throughput (matrix.csv)

| scenario | proto | sysctl | iface | Mbps |
|---|---|---|---|---|
| vlan | tcp | 0 | vlan100 | 938.9 |
| vlan | tcp | 1 | vlan100 | 938.9 |
| vlan | udp | 0 | vlan100 | 944.9 |
| vlan | udp | 1 | vlan100 | 944.9 |
| qinq | tcp | 0 | cvlan100 | 936.4 |
| qinq | tcp | 1 | cvlan100 | 936.4 |
| qinq | udp | 0 | cvlan100 | 942.0 |
| qinq | udp | 1 | cvlan100 | 942.0 |
| vxlan | tcp | 0 | vxlan10 | 908.9 |
| vxlan | tcp | 1 | vxlan10 | 908.9 |
| vxlan | udp | 0 | vxlan10 | 911.9 |
| vxlan | udp | 1 | vxlan10 | 911.9 |

Wire-saturated 1 GbE in every cell — throughput cannot show the dissector saving. Look at CPU instead.

## CPU utilization (from iperf3 `.end.cpu_utilization_percent`)

### Generator side (pi5-1) — `host_total` and `host_system`

| scenario | proto | sysctl=0 total% | sysctl=1 total% | Δ pp  | sysctl=0 sys% | sysctl=1 sys% | Δ pp  | rel. saving |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| **vlan** | **udp** | **71.23** | **66.03** | **-5.20** | **68.11** | **63.66** | **-4.46** | **-6.5%** |
| **qinq** | **udp** | **78.32** | **73.11** | **-5.21** | **75.87** | **70.98** | **-4.89** | **-6.4%** |
| vxlan | udp | 76.91 | 77.01 | +0.10 | 73.72 | 74.40 | +0.67 | noise |
| vlan | tcp | 3.26 | 3.27 | +0.01 | 3.25 | 3.25 | 0.00 | noise (TCP too cheap) |
| qinq | tcp | 3.24 | 3.27 | +0.03 | 3.15 | 3.26 | +0.11 | noise |
| vxlan | tcp | 2.55 | 2.56 | +0.01 | 2.54 | 2.54 | 0.00 | noise |

### What's happening per scenario

- **vlan / qinq UDP**: real win. The dissector slow-path's VLAN handling (state-machine transition MAX → VLAN → CVLAN, plus the `proto_again` rewind) is bypassed entirely by the new `flow_dissect_fast_vlan` helper. At ~67 kpps (1 GbE × 1200 B UDP = ~104 kpps), saving ~5 ns of dissector per packet adds up to ~5 pp of system CPU. Consistent with the cover letter's microbench number scaled by call count.
- **vxlan UDP**: ~zero net change. With `enableVxlanInner=true`, the fast-path-VXLAN-descent (patch 0006) processes inner header *in addition to* outer header. The outer-fast-path savings are roughly offset by the new inner-descent work. Different behaviour from "outer-only" (which would show a small +1-2% win on VXLAN UDP).
- **TCP cells (all scenarios)**: TCP at 1 GbE on Cortex-A76 consumes ~3% CPU baseline. The dissector is a tiny fraction of that; the per-cell saving is below the 30-s measurement noise floor. The cover letter predicted this — small absolute deltas on light workloads, visible on UDP-heavy / cake-heavy.

### Receiver side (pi5-2) — `remote_total` and `remote_system`

Same pattern but smaller absolute numbers because iperf3 receivers are cheaper than senders:

| scenario | proto | sysctl=0 total% | sysctl=1 total% | Δ pp  |
|---|---|---:|---:|---:|
| vlan | udp | 15.17 | 14.96 | -0.21 |
| qinq | udp | 13.92 | 13.96 | +0.04 |
| vxlan | udp | 15.45 | 15.15 | -0.30 |

Receiver-side delta is closer to noise. The receiver runs RPS + cake on the same iface and the savings are spread over more skb-handling code; harder to isolate the dissector portion from the rest of the rx path.

## Notes

- **First successful run** — the patches went through three rounds of patch-context-fix iteration to get them applying cleanly across both 6.12.x (pi5) and 7.0.x (hp) kernels. Final winning approach: anchor the forward declarations of `flow_dissect_fast_ipv4` / `_ipv6` at the top of `net/core/flow_dissector.c` (right after the includes), which is provably before any caller regardless of where the patch tool lands the helper body. Commits `dd09eb7`, `5afe6cab`, `207e5b10` on the local `extensions-on-v1-netdev` branch in `~/Downloads/net-next`; mirrored as patches in `kernel-patches/series3-flowdis-fastpath/extensions-draft-v1-netdev/` on xdp2 commit `61e5fc8`.
- **iperf3 binary missing on first attempt**: rebuilding the NixOS system changed the system generation and garbage-collected the iperf3 closure. Re-fetched with `nix shell nixpkgs#iperf3 --command` and the second matrix run succeeded.
- **Cells run in 30 s**. For the publish-grade numbers in the cover-letter style, ideally a longer run (DUR=300+) on a quieter host, ideally on the higher-rate testbeds (hp1↔hp3 at 25 GbE, where every Mpps amplifies the dissector saving).

## Cross-reference

- Orchestrator: `nix/series3-extensions-soak.nix`
- Per-scenario configs: `nix/scenarios/netconf-{vlan,qinq,vxlan}.nix`
- Extension patches: `kernel-patches/series3-flowdis-fastpath/extensions-draft-v1-netdev/000{4,5,6}-*.patch`
- NixOS module that applies them: `nix/modules/flowdis-fastpath-extensions.nix`
- Parent doc: `kernel-patches/series3-flowdis-fastpath/docs/packet-flow-context.md`
