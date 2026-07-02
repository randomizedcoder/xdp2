# Where the flow_dissector fast-path fits in the Linux packet stack

Companion doc to `series3-flowdis-fastpath` v1 (cover letter in `../v1-netdev/0000-cover-letter.patch`). The cover letter is good at **what the patch does** and **why it's safe**. This doc is for the **big-picture question**: where in the Linux packet path does `__skb_flow_dissect()` actually get invoked, who calls it, and which of those callers does the fast-path improve?

Audience: kernel reviewers who want stack placement, and engineers reading background material before tuning a real system.

## TL;DR

- `__skb_flow_dissect()` is called from roughly **50 sites across the kernel** — RX softirq, qdisc enqueue, ECMP routing, multi-queue TX, hardware-accelerated RFS, OVS, BPF helpers, tunneling, wireless.
- The patch makes the dissector body itself **~5 ns/skb faster** on Eth + IPv4/IPv6 + TCP/UDP packets (cover-letter measurement: 12.44 → 6.56 ns on Zen 2, 10.61 → 5.62 ns on Skylake-derived Intel — both ~47 %). All callers benefit when the packet matches the eligible shape.
- Real-world impact is bounded by **how often the dissector is called per packet** and **what fraction of packets match the eligible shape**. Measured on a representative TCP cake workload: +2.0 % end-to-end (cover-letter `series3-gated-ab` data). A targeted hot-helper optimization, not a stack-wide speedup.
- Two fast-paths exist today (IPv4 and IPv6 over Eth, TCP/UDP). The same template is extensible: section 9 walks through what someone would do to add a fast-path for VLAN, PPPoE, VXLAN, or another common shape.

## 1. Diagram L1 — high-level packet path (Wire ↔ Application)

The full RX and TX paths. Annotations on the right indicate which stages invoke `__skb_flow_dissect()` either directly or via `skb_get_hash()`.

```
        RX (ingress)                                       TX (egress)
        ────────────                                       ───────────

  Wire                                              Application
   ↓                                                  ↓
  NIC                                               sendmsg() / sys_send()
   ↓                                                  ↓
  RX Ring                                           Socket Buffer
   ↓                                                  ↓
  NAPI Poll          ← (GRO bucket select)          TCP / UDP
   ↓                                                  ↓
  XDP                                               IP        ← (ECMP fib_multipath_hash)
   ↓                                                  ↓
  build_skb()                                       OUTPUT
   ↓                                                  ↓
  RPS / RFS          ← (get_rps_cpu)                POSTROUTING
   ↓                                                  ↓
  TC ingress         ← (cls_flower, cls_flow)       TC egress     ← (cls_flower, act_skbedit)
   ↓                                                  ↓
  Netfilter PREROUTING                              Qdisc         ← (cake, fq, fq_codel, sfq, …)
   ↓                                                  ↓
  Routing            ← (ECMP fib_multipath_hash)    Driver TX     ← (skb_tx_hash / XPS / select_queue)
   ↓                                                  ↓
  INPUT                                             TX Ring
   ↓                                                  ↓
  TCP / UDP                                         NIC
   ↓                                                  ↓
  Socket Queue                                      Wire
   ↓
  Application
```

External references for the broader stack (this doc doesn't try to duplicate them):

- *Linux Networking — Quick Survey of the Linux Networking Stack*, TUM NET-2024-04-1 §5 (PDF). The user-supplied figure showing the socket-layer transit (`write() → sys_send() → udp_sendmsg() → ip_queue_xmit() → dev_queue_xmit() → Wire`, symmetric on RX) is the application-layer counterpart of the diagram above.
- `Documentation/networking/scaling.rst` in the kernel tree — authoritative deep-dive on RPS, RFS, aRFS, and XPS. The flow_dissector is the helper that *all* of those subsystems use to derive a flow hash; this doc is the dissector-side perspective.

## 2. Diagram L2 — caller → dissector entry → fast vs slow path

Two patterns in the kernel for invoking the dissector, both relevant. Pattern A is the lazy-cached form most callers use; Pattern B is the direct form used by qdiscs and routing.

```
        Pattern A — lazy, cached on skb->hash
        ─────────────────────────────────────

  caller (e.g. get_rps_cpu, fq_classify, skb_tx_hash, fq_codel_hash)
    │
    └──► skb_get_hash(skb)
           │
           ├── skb->l4_hash || skb->sw_hash  →  return cached skb->hash   (no dissect)
           │
           └──► __skb_get_hash_net(net, skb)
                  │
                  └──► __skb_flow_dissect()  ← THE dissector entry point


        Pattern B — direct, no cache (caller wants the keys themselves)
        ──────────────────────────────────────────────────────────────

  caller (e.g. cake_classify, choke_match_flow, fib_multipath_hash,
               cls_flower, skb_flow_dissect_flow_keys_basic)
    │
    └──► skb_flow_dissect_flow_keys(skb, &keys, flags)
           │
           └──► __skb_flow_dissect()  ← same entry point


        Inside __skb_flow_dissect()  (this is what the patch changes)
        ───────────────────────────────────────────────────────────

  __skb_flow_dissect()
    │
    ├──► static_branch_likely(&flow_dissector_fastpath_key)   ← sysctl gate
    │      │
    │      ├── gate=0 (default):  one not-taken JMP, fall through to slow path
    │      │
    │      └── gate=1 (opted in): try fast path ▼
    │
    ├──► [fast path]  ← THIS PATCH adds the two helpers below
    │      eligibility:
    │        flow_dissector == &flow_keys_dissector
    │        || flow_dissector == &flow_keys_dissector_symmetric
    │        && flags subset of {PARSE_1ST_FRAG}
    │      ethertype switch:
    │        ETH_P_IP   → flow_dissect_fast_ipv4()     (straight-line, ~5 ns)
    │        ETH_P_IPV6 → flow_dissect_fast_ipv6()     (straight-line, ~5 ns)
    │        anything else, or any miss in either → goto slow_path
    │
    └──► [slow path]  ← unchanged behaviour
           parse-graph traversal:
             lookup_node (linear search per layer)
             + function-pointer dispatch per layer
             ~3 indirect calls per packet on the canonical eth+IP+L4 shape
```

Both paths write the same `struct flow_keys` into the caller's `target_container`. The contract is byte-identical: the same flow hash, the same dissector keys, no observable difference in any downstream consumer.

## 3. Diagram L3 — inside one fast-path body (`flow_dissect_fast_ipv4`)

The IPv4 helper in detail. The IPv6 helper has the same structure with `sizeof(struct ipv6hdr) == 40` and an extension-header gate instead of an IHL gate.

```
  flow_dissect_fast_ipv4(skb, flow_dissector, target, data, nhoff, hlen)
    │
    ├── length sanity:        hlen - nhoff >= sizeof(*iph) + 4    ─── miss → goto slow_path
    │
    ├── read iph pointer:     iph = data + nhoff
    │
    ├── version + IHL == 5:   *(const u8 *)iph == 0x45            ─── miss → goto slow_path
    │   (One byte covers both: high nibble = IP version 4,
    │    low nibble = IHL count of 32-bit words = 5 → 20 bytes.
    │    Codified at compile time by static_assert(sizeof(struct iphdr) == 20).)
    │
    ├── not fragmented:       (iph->frag_off & htons(IP_MF | IP_OFFSET)) == 0   ─── miss → goto slow_path
    │
    ├── L4 known:             iph->protocol in {IPPROTO_TCP, IPPROTO_UDP}      ─── miss → goto slow_path
    │
    ├── thoff = nhoff + 20
    │
    ├── if dissector_uses_key(KEY_CONTROL):  write addr_type=IPV4_ADDRS, thoff, flags
    ├── if dissector_uses_key(KEY_BASIC):    write n_proto=IPv4, ip_proto=iph->protocol
    ├── if dissector_uses_key(KEY_IPV4_ADDRS): memcpy 4 B src + 4 B dst from iph
    ├── if dissector_uses_key(KEY_PORTS):    one __be32 read at thoff
    │                                        (the TCP and UDP port pair is at
    │                                         offset 0 of the L4 header — a
    │                                         single 32-bit load covers both)
    │
    └── return true   ← caller skips the entire parse-graph walk

  Cost:  branch + 4 byte-level checks + ≤4 conditional writes
         ≈ 5–10 ns on a modern Zen 2 / Cortex-A76 core.
  Cost on a miss:  the not-taken JMP returning to slow_path is the
         same ~one ethertype switch the unpatched code already had.
```

## 4. Where `__skb_flow_dissect()` is called from

Condensed map across the net-next tree (HEAD `8013aee91ccb` at the time of writing). Full long-form list is one `grep` away:

```sh
git grep -nE '__skb_flow_dissect|skb_flow_dissect_flow_keys|skb_get_hash' \
   net/ drivers/net/ include/
```

### RX softirq early/mid

| File | Function | Purpose | Hot path |
|---|---|---|---|
| `net/core/dev.c:5139` | `get_rps_cpu` (via `skb_get_hash`) | RPS — select target CPU for upper-layer processing | per-packet when RPS enabled |
| `net/core/dev.c:5348` | `skb_flow_limit` (via `skb_get_hash`) | Per-flow softirq rate limiting | per-packet when limit configured |
| `net/core/gro.c` | GRO bucket selection (via `skb_get_hash`) | Choose the bucket the skb hashes to | per-packet when GRO enabled |
| `drivers/net/bonding/bond_main.c:4182` | Bond hash selection | Pick slave under LACP / active-backup | per-packet on bonded ifaces |

### RX socket-side

| File | Function | Purpose | Hot path |
|---|---|---|---|
| `net/packet/af_packet.c:987` | `prb_fill_rxhash` | Fill RX hash for TPACKET_V3 ring | per-packet when AF_PACKET active |
| `net/packet/af_packet.c:1344,1362` | `fanout_demux_hash`, `fanout_flow_is_huge` | AF_PACKET fanout queue + huge-flow detection | per-packet on `PACKET_FANOUT_HASH` |

### TX qdisc (the cake-soak motivator)

| File | Function | Pattern | Hot path |
|---|---|---|---|
| `net/sched/sch_cake.c:730` | `cake_classify` | B (direct `skb_flow_dissect_flow_keys`) | per-packet on `flow_mode != CAKE_FLOW_NONE` |
| `net/sched/sch_fq.c:372` | `fq_classify` | A (via `skb_get_hash`) | per-packet on fair queueing |
| `net/sched/sch_fq_codel.c:73` | `fq_codel_hash` | A | per-packet |
| `net/sched/sch_fq_pie.c` | `fq_pie_hash` | A | per-packet |
| `net/sched/sch_sfq.c:153` | `sfq_hash` (`skb_get_hash_perturb`) | A | per-packet |
| `net/sched/sch_hhf.c:268` | `hhf_hash` | A | per-packet on heavy-hitter filter |
| `net/sched/sch_sfb.c:327` | `sfb_hash` | A | per-packet on Stochastic Fair Blue |
| `net/sched/sch_choke.c:158` | `choke_match_flow` | B | per-packet on CHOKe |
| `net/sched/cls_flower.c:335` | `fl_classify` | B (via `skb_flow_dissect_*`) | per-packet on tc-flower filters |
| `net/sched/cls_flow.c:238` | `flow_get_rxhash` | A (or B with FLOW_KEYS_NEEDED) | per-packet on `cls_flow` |
| `net/sched/act_skbedit.c:32` | `tcf_skbedit_act` | A | per-packet on `SKBEDIT_F_TXQ_SKBHASH` |

### TX driver / multi-queue selection

| File | Function | Purpose | Hot path |
|---|---|---|---|
| `net/core/dev.c:3509-3540` | `skb_tx_hash` | Distribute outbound packets across TX queues | per-packet on multi-queue NICs |
| `net/core/dev.c:4609` | `__get_xps_queue_idx` | XPS queue selection from flow hash | per-packet when XPS configured |
| `drivers/net/ethernet/intel/ixgbe/ixgbe_main.c` | `ixgbe_select_queue` | Driver-private TX queue selection | per-packet |
| `drivers/net/ethernet/microsoft/mana/mana_en.c` | `mana_get_tx_queue` | MANA driver TX | per-packet |
| `drivers/net/xen-netfront.c` | `xennet_select_queue` | xen-netfront TX | per-packet |
| `drivers/net/tap.c`, `drivers/net/veth.c` | `tap_get_queue`, `veth_xdp_rx_hash` | Virtual-device TX/RX | per-packet |
| `drivers/net/vxlan/vxlan_core.c:2659,2690` | `vxlan_xmit_nh`, `vxlan_xmit_nhid` | VXLAN multipath nexthop | per-packet on VXLAN encap |

### Routing — ECMP

| File | Function | Purpose | Hot path |
|---|---|---|---|
| `net/ipv4/route.c:1957,1993,2098,2128` | `fib_multipath_custom_hash_outer/inner`, `fib_multipath_hash` | IPv4 ECMP route selection | per-packet on multipath routes |
| `net/ipv6/route.c:2416,2454,2561,2591` | `ip6_route_multipath_hash` | IPv6 ECMP route selection | per-packet on multipath routes |

### Tunneling

| File | Function | Purpose | Hot path |
|---|---|---|---|
| `net/ipv4/ip_tunnel.c:602,765` | `ip_md_tunnel_xmit`, `ip_tunnel_xmit` | Tunnel metadata flow hash | per-packet on tunnel TX |
| `net/ipv4/ip_gre.c:642` | `gre_fill_metadata_dst` | GRE metadata-dst flow hash | per-packet |
| `net/ipv6/seg6_iptunnel.c:130` | `seg6_make_flowlabel` | Generate IPv6 flow label from hash | per-packet on SRv6 |

### Hardware-accelerated RFS (ARFS)

| File | Driver | Purpose |
|---|---|---|
| `drivers/net/ethernet/mellanox/mlx5/core/en_arfs.c:740` | mlx5 | Steer flows to NIC RX rings |
| `drivers/net/ethernet/intel/ice/ice_arfs.c:463` | ice | Same, Intel E810 |
| `drivers/net/ethernet/broadcom/bnxt/bnxt.c` | bnxt | Same, BCM5/57xxx |
| `drivers/net/ethernet/cisco/enic/enic_clsf.c:181` | enic | Same, Cisco VIC |
| `drivers/net/ethernet/sfc/{rx_common.c,siena/rx_common.c,falcon/rx.c}` | sfc | Same, Solarflare |
| `drivers/net/ethernet/hisilicon/hns3/hns3_enet.c:2968` | hns3 | Same, Hisilicon |

### Other

| File | Function | Purpose |
|---|---|---|
| `net/openvswitch/datapath.c`, `net/openvswitch/vport.c`, `net/openvswitch/actions.c` | OVS flow lookup, upcall steering, hash action | OVS datapath |
| `net/core/filter.c:3174` | `bpf_get_hash_recalc` | BPF helper |
| `net/sched/bpf_qdisc.c:192` | `bpf_skb_get_hash` | BPF qdisc kfunc |
| `net/xfrm/xfrm_policy.c:3508` | `xfrm_session_dissector` | IPsec policy selector |
| `net/mac80211/wme.c:126,155` | `ieee80211_select_queue*` | WiFi TX queue selection |

About 30 high-signal callers shown; the full grep yields ~50.

> **Note (series4):** the shipped set now covers VLAN, QinQ, PPPoE, MPLS,
> IP-in-IP, GRE and the VXLAN/Geneve/GTP-U inner-descent gates, so the
> "partial/neutral" and "future candidate" framing below (written when only
> eth_ip existed) is superseded for those shapes. For the definitive
> per-feature "when to enable" guidance see `RECOMMENDATIONS.md`.

## 5. Which callers does the patch improve — and by how much?

The fast-path is **inside `__skb_flow_dissect()` itself**, so its benefit is uniform per *call*. The interesting variation is at the *workload* level — how often a caller hits the dissector and how often the packets match the eligible shape.

### When the fast-path is a win

- **Single-stack TCP/UDP traffic**, no VLAN, no encapsulation. Every packet matches the IPv4 or IPv6 helper; every dissector call saves ~5 ns. This is the headline target.
- **RPS-heavy receivers** on plain TCP/UDP workloads. RPS calls the dissector once per packet (via `get_rps_cpu`), and the result is cached on `skb->hash` so other callers reuse it. The first call is the only one that pays the dissector cost — the fast-path makes exactly that call cheaper.
- **cake / fq / fq_codel / sfq / hhf qdisc-shaped links** on simple IP traffic. The qdisc classifies every packet using the dissector. Cover-letter measurement: +2.0 % macro throughput on a real TCP workload through `sch_cake` on a 25 GbE mlx5_core pair, and across three other qdiscs:
  - cake: +2.0 %
  - fq_codel (kernel default): +2.4 %
  - fq (Eric Dumazet's pacing qdisc): +1.0 %
  - noqueue: +0.8 % (no qdisc dissect — residual saving comes from RPS, `skb_get_hash`, etc.)

  Roughly **60 % of the gain comes from qdisc classify, 40 % from non-qdisc dissector callers** in this workload.
- **ECMP routers** on IPv4/IPv6 unicast flows. Every forwarded packet on a multipath route invokes `fib_multipath_hash`. Each call saves ~5 ns.

### When the patch is partial or neutral

- **VXLAN overlays in k8s / cloud**: the dissector wants to dissect the *inner* flow for proper hashing of encapsulated traffic. The current fast-path matches the outer Eth + IPv4 + UDP shape and exits cleanly, but the dissector still has to recurse into the VXLAN payload for inner addresses/ports — the patch as-shipped captures the outer-header work, not the inner. **No regression**, partial win. Section 9 discusses a VXLAN-inner fast-path.
- **VLAN-tagged traffic** (most DC LANs): the outer ethertype is `ETH_P_8021Q` not `ETH_P_IP`, so the current fast-path bails to slow path on the very first check. **No regression**, no win. This is the **biggest near-future gap** the doc calls out — see section 9 / 10.
- **GRE tunnels, IPsec, MPLS, PPPoE, QinQ**: same story. Outer ethertype doesn't match; slow path handles it as before.

### When the patch is irrelevant

- **Custom dissectors** (`flow_dissector` instances that are *not* `flow_keys_dissector` or `flow_keys_dissector_symmetric`): excluded by the eligibility gate. The fast-path never runs. Examples: custom TC matchall filters with extra keys, the BPF flow_dissector hook when a program is loaded.
- **Workloads where the dissector is a tiny fraction of the packet-handling budget**: XDP receive (dissector skipped entirely), AF_XDP zero-copy (same), full hardware-offloaded qdisc (qdisc runs on NIC, not host). No measurable change.
- **BPF flow_dissector program loaded for the netns**: the patch's eligibility check runs *after* the existing BPF override, so BPF semantics are preserved.

## 6. Real-world example — one packet under cake on a forwarding host

Annotated walk-through of a single 1500 B IPv4 TCP packet on a host that's forwarding (so all three relevant dissector callers fire) and shaping the egress link with cake:

```
NAPI poll on RX core
  │
  ├──► RPS:                get_rps_cpu()          → 1× dissector call
  │                                                 (writes skb->hash; cached)
  │
  └──► (steered to softirq on another CPU)
        │
        ├──► netfilter PREROUTING                   no dissect
        ├──► routing decision (no ECMP)             no dissect
        │
        └── forwarding host (not local socket):
             │
             ├──► TC egress (no flower rule)        no dissect
             ├──► cake_classify (qdisc hash):     → 1× dissector call
             │                                      (Pattern B: bypasses
             │                                       skb_get_hash cache,
             │                                       gets keys directly)
             ├──► skb_tx_hash() (multi-queue NIC) → 1× dissector call
             │                                      (Pattern A: uses cached
             │                                       skb->hash if set; on a
             │                                       fresh skb here it would
             │                                       run, but RPS already set
             │                                       it — so this is a cache
             │                                       hit, no second dissect)
             └──► driver TX

Per-packet (worst case):  3× dissector calls
Per-packet (realistic):   1–2 calls thanks to skb->hash caching

Per-call saving on fast-path:  ~5 ns
Per-packet saving (realistic): ~5–10 ns

At 10 Gbit/s with line-rate 1500 B frames (~830 kpps):
   ~4–8 µs/sec of CPU back per core.
At 25 Gbit/s (~2 Mpps):
   ~10–20 µs/sec of CPU back per core.
```

That's modest in absolute terms, but it scales linearly with packet rate and stacks with other small optimizations in the receive path. The cover letter's +2.0 % cake-soak result is the realistic end-to-end shape of this win.

## 7. Magnitude in context

The honest framing:

- **Isolated dissector cost**, userspace microbench, always-hit eth+IPv4+TCP, 10 M iter, gcc -O3 (cover-letter table):

  | uarch | host | baseline | patched | delta |
  |---|---|---|---|---|
  | Zen 2 | Threadripper PRO 3945WX | 12.44 ns | 6.56 ns | -47.3 % |
  | Skylake-deriv | Intel i9-10885H | 10.61 ns | 5.62 ns | -47.0 % |
  | Zen 1 | Ryzen 5 PRO 2400G | 20.50 ns | 20.53 ns | noise |
  | Haswell-ULT | Intel Celeron 2955U | 35.94 ns | 17.97 ns | -50.0 % |

The fast-path body is ~5 ns shorter than the slow-path graph walk; the saving shows up at the dissector entry point and is the upper bound for any single caller.

- **Macro end-to-end**, cake soak on 25 GbE mlx5_core pair, real TCP workload (cover-letter `series3-gated-ab` data set):
  - cake: +2.0 %
  - fq_codel: +2.4 %
  - fq: +1.0 %
  - noqueue: +0.8 %

The +2.0 % is the realistic shape — not 50 %, not 0.1 %. The dissector is roughly 5–10 % of receive CPU on cake-shaped workloads, and a ~30 % faster dissector lifts the macro number proportionally.

- **Not measurable in**: XDP / AF_XDP receive paths (dissector skipped entirely), hardware-offloaded qdisc, workloads where the packets don't match the fast-path shape (VLAN-tagged DC LANs, inside-VXLAN payloads).

This is a **targeted hot-helper optimization**, not a stack-wide speedup. The right way to read the gain is per-call, and the per-call gain shows up in every workload that calls the dissector enough times to matter.

## 8. How to add a fast-path for a different shape

The reusable recipe. This section is for someone reading these patches and asking *"my workload has shape X, not Eth+IP+TCP/UDP — could I add a similar fast-path?"*.

### Eligibility checklist

A shape is fast-path-able if **all** of these hold:

- The header layout is **fixed-offset**. No length-by-flag fields, no variable-depth option walks. The fast-path body must compute every field offset as a constant or with a single arithmetic step.
- The shape is **common enough** in the workload of interest to justify a hot-text branch. The dispatcher cost is one ethertype switch on miss; that's cheap but not free.
- All keys the dissector reads (the `flow_keys_dissector`'s configured keys: `KEY_CONTROL`, `KEY_BASIC`, `KEY_IPV4_ADDRS` or `KEY_IPV6_ADDRS`, `KEY_PORTS`) are at fixed offsets from the shape's start.
- The eligibility check itself can be done in O(1) byte reads. The existing IPv4 helper does this in four byte-level checks (version+IHL, frag-off, protocol, L4 minimum length).

### Recipe (mirrors `flow_dissect_fast_ipv4`)

1. Add `flow_dissect_fast_<shape>(skb, flow_dissector, target, data, nhoff, hlen)` following the structure in Diagram L3. Keep it under ~80 lines of straight-line C; no loops, no indirect calls.
2. Extend the ethertype switch (or add a deeper dispatch under `ETH_P_IP` / `ETH_P_IPV6` — see the VLAN worked example below) in `__skb_flow_dissect()`. Branch to the new helper on the shape's discriminator.
3. Add your own per-shape sysctl in the `net.flow_dissector.*` subtree (the v3 series moved away from a single umbrella knob — see `v3-namespace/0000-cover-letter.patch`). Mirror the existing `proc_set_vlan_key` / `proc_set_qinq_key` shape when your shape has a sibling-key dependency (e.g. depth-2 extending depth-1). Each per-shape gate is a separate `DEFINE_STATIC_KEY_FALSE`; cost when disabled is one forward not-taken JMP in the dispatcher switch.
4. Add a `static_assert(...)` for any fixed header size the body assumes (the existing patch does this for `struct iphdr` and `struct ipv6hdr`).
5. Add a selftest in `tools/testing/selftests/net/` comparing fast-path output byte-for-byte against the slow path on crafted pcaps of the new shape. The byte-identical contract is what makes the change safe to enable globally.
6. Measure: microbench (always-hit synthetic case) should show a similar dissector-cost saving; macro soak should show comparable +0.x–2 % depending on how shape-heavy the workload is.

### Worked example — single VLAN (the cheapest extension)

VLAN-tagged Eth + IPv4 + TCP/UDP is overwhelmingly common in DCs. The existing `flow_dissect_fast_ipv4` doesn't handle it because the outer ethertype is `ETH_P_8021Q`, not `ETH_P_IP`. Two ways to extend:

```
  Option A — wrap-and-recurse
  ───────────────────────────

  flow_dissect_fast_vlan(skb, flow_dissector, target, data, nhoff, hlen):
    │
    ├── length sanity:   hlen - nhoff >= 4
    ├── read vlan tag:   tci = ntohs(*(__be16 *)(data + nhoff))
    │                    inner_proto = *(__be16 *)(data + nhoff + 2)
    │
    ├── if dissector_uses_key(KEY_VLAN):
    │     write key_vlan->vlan_id = tci & VLAN_VID_MASK
    │     write key_vlan->vlan_priority = (tci & VLAN_PRIO_MASK) >> 13
    │
    └── dispatch on inner_proto:
          ETH_P_IP   → flow_dissect_fast_ipv4(... nhoff + 4 ...)
          ETH_P_IPV6 → flow_dissect_fast_ipv6(... nhoff + 4 ...)
          anything else → goto slow_path

  Option B — strip-and-restart
  ────────────────────────────

  In the ethertype switch, on ETH_P_8021Q:
    nhoff += 4
    proto = *(__be16 *)(data + nhoff - 2)
    re-enter the ethertype switch (one extra iteration)
```

Either way: ~30 extra lines of C, same selftest discipline. Unlocks the very large fraction of DC traffic that's VLAN-tagged. Option A is slightly cleaner because it keeps the hot-text path predictable; Option B is fewer lines but harder for the branch predictor.

A reviewer concern to anticipate: the kernel already handles hardware-stripped VLAN tags (in `skb_vlan_tag_present(skb)` slots). The fast-path would need to honour both forms — see the existing slow-path code in `__skb_flow_dissect` around the `case htons(ETH_P_8021Q)` block for the canonical pattern.

## 9. Other obvious fast-path candidates

A table of shapes worth fast-pathing, ranked roughly by **value-per-line-of-code**. None of these are committed; they're the candidates someone reading these patches should look at next.

| Shape | Feasibility | Who benefits |
|---|---|---|
| **Single VLAN** (`ETH_P_8021Q` over IPv4/IPv6 + TCP/UDP) | Easy — fixed 4 B tag, dispatch to existing v4/v6 helpers | Data centers, anyone with VLAN-isolated tenants |
| **QinQ** (`ETH_P_8021AD` + `ETH_P_8021Q` + IP) | Easy — fixed 8 B prefix, then existing helpers | Carriers, service providers |
| **PPPoE session** (`ETH_P_PPP_SES` + PPP-proto + IPv4/IPv6) | Easy — 6 B PPPoE + 2 B PPP-proto. The slow path already has `is_pppoe_ses_hdr_valid()` (`net/core/flow_dissector.c:1034`) which the fast-path could reuse | ISP edges, DSL bridges, home routers, anyone running PPPoE in software |
| **VXLAN inner** (outer Eth + IPv4 + UDP + VXLAN → inner Eth + IPv4) | Medium — outer fast-path is partial today; an inner-recursion fast-path would save another ~10 ns/skb on overlay traffic. Outer UDP dst=4789 (or configurable) is the common case | k8s / cloud overlays, any Linux box doing VXLAN encap/decap in the data path |
| **MPLS single-label** (`ETH_P_MPLS_UC` + 4 B label + IP) | Medium — variable depth in general; the single-label case is a clean special-case worth doing | SP networks, MPLS-VPN providers |
| **GRE (no flags)** (`ETH_P_IP` + `IPPROTO_GRE` + 4 B base header, flags == 0) | Medium — variable GRE header in general; the flags=0 case is straight-line | GRE tunnel terminators |
| **IP-in-IP, 6in4, 6to4** | Easy but narrow — small audience | Specific tunnel users |
| **GTP-U** (UDP dst=2152 + 8 B GTP base + IP) | Hard — variable extension headers; the common-case (no extensions, T-PDU only) is straight-line but extension presence is a config bit | Telco / 5G UPFs |
| **MPLS multi-label** | Hard — depth determined by walking the S-bit per label | (deferred; harder to fast-path) |

Two observations worth flagging explicitly:

- **VLAN is the highest-leverage extension.** Nearly every DC packet has at least one VLAN tag, the slow-path's VLAN handling is itself a non-trivial block, and the implementation is ~30 lines of C. Best ratio of code-to-impact in the candidate list.
- **VXLAN inner is the most-asked-for.** k8s overlay prevalence makes it the case real operators care about, and it's also the case where the dissector's value is most degraded by the patch as-shipped (outer matches cleanly, inner has to slow-path). Both important *and* partial — likely the second extension someone would tackle.

A nudge for future work: the simplest path to broad coverage is probably **VLAN + VXLAN-inner** as a combined v2 follow-up. That covers DC traffic shape and k8s overlay shape with one extension, which together account for a very large fraction of modern Linux data-path packets.

## 10. References

- *Linux Networking — Quick Survey of the Linux Networking Stack*, TUM NET-2024-04-1 §5 "Conclusion" diagram. PDF: <https://www.net.in.tum.de/fileadmin/TUM/NET/NET-2024-04-1/NET-2024-04-1_16.pdf>
- `Documentation/networking/scaling.rst` (in the kernel tree), the authoritative deep-dive on RPS / RFS / aRFS / XPS — every one of those subsystems consumes the dissector via `skb_get_hash`.
- `../v1-netdev/0000-cover-letter.patch` — what the patch does and the safety arguments.
- `../v1-netdev/000{1,2,3}-*.patch` — the three patches: framework + IPv4 fast-path + IPv6 fast-path.
- net-next at the time of writing: HEAD `8013aee91ccb` on branch `flowdis-fastpath-rfc-v2-inline`.
- `../../../xdp2-rs/docs/dispatch-architecture-cost.md` — the userspace measurements (xdp2-rs benchmark matrix) that motivated the "skip the graph walk for common shapes" technique.
