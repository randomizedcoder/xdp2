# flow_dissector fast-path — when to enable each feature

Definitive per-feature enablement guidance for the `net.flow_dissector.*` gates.
All gates default **off**; an unused gate costs one not-taken branch per dissect,
so enabling only the shapes present in your traffic is the rule. This supersedes
the eth_ip-era "future gaps" framing in `packet-flow-context.md` §5/§9 for the
shipped set.

Two classes of feature:
- **Byte-identical** (`eth_ip`, `vlan`, `qinq`, `pppoe`, `mpls`, `ipip`, `gre`):
  pure CPU optimizations. Output is bit-for-bit the slow path. **Safe to enable
  whenever that shape appears in your traffic** — no behaviour change, ever.
- **Encapsulation descent** (`vxlan_inner`, `geneve_inner`, `gtpu_inner`):
  **behaviour-changing** — they make consumers hash on the *inner* flow instead
  of the outer tunnel. Enable deliberately, per the guidance below.

## Where any of this helps (the consumers)

The dissector feeds `flow_keys`/`skb->hash`, consumed by RPS, RFS, RSS, ECMP /
`fib_multipath`, bonding/LAG (`xmit_hash_policy` layer3+4), tc-flower, hardware
aRFS, and the hashing qdiscs (fq/fq_codel/cake/sfq/hhf). The wins scale with
**packet rate × how often the dissector is called per packet × fraction of
packets matching the enabled shape**. It is a per-packet CPU/identity win, not a
throughput win — on a link-, pps- or queue-bound host it shows as reclaimed CPU
headroom or better spread, not higher Gbit/s.

**Irrelevant (do not bother):** XDP / AF_XDP zero-copy paths (dissector skipped);
fully HW-offloaded qdiscs; netns with a BPF flow_dissector program loaded (the
gate is checked after the BPF override); custom dissectors other than
`flow_keys_dissector[_symmetric]` (excluded by the eligibility gate).

## Byte-identical features

| gate | traffic it targets | enable when | benefit |
|---|---|---|---|
| **eth_ip** | plain Eth + IPv4/IPv6 + TCP/UDP (no tag, no encap) | almost always — it is the base gate and the highest call-volume shape; any host doing RPS/RFS/cake/ECMP/bonding on plain IP | −47%…−55% dissector cost isolated; −4.9% cyc/pkt in-kernel |
| **vlan** | single 802.1Q-tagged IP | VLAN access/trunk LANs (most DC and campus edge) | −18%…−39%; highest leverage (nearly every DC packet is tagged) |
| **qinq** | 802.1ad / double-tagged (depth 2) | QinQ provider/metro-E, service-tagged aggregation | −16%…−40% |
| **pppoe** | PPPoE session (0x8864) + IP | BNG / broadband access concentrators, residential edge | −9%…−28% |
| **mpls** | single MPLS label + IP | MPLS PE/P routers, MPLS-over-Eth edges | −7%…−15% (smallest — enable only if MPLS is material) |
| **ipip** | IPIP / 4in6 / 6in4 | IP-in-IP tunnel endpoints and transit | −37%…−47% (**largest** — slow path re-parses the inner IP) |
| **gre** | plain GRE (no flags) + IP | GRE tunnel endpoints/transit (no key/seq/csum) | descent family, ≈ipip |

Guidance: turn on the set matching your traffic mix. There is no downside to
enabling several — each off-path shape is one branch. A DC top-of-rack host
typically wants `eth_ip` + `vlan` (+`qinq` if double-tagged); a tunnel/transit
box adds `ipip`/`gre`; a BNG adds `pppoe`; an MPLS router adds `mpls`.

## Encapsulation descent (behaviour-changing — enable deliberately)

These make RSS/RPS/ECMP/cake/tc-flower see the **inner** 5-tuple of overlay
traffic. Today the dissector stops at the outer tunnel header, so all inner flows
between two endpoints collapse onto one hash bucket (measured: 1 flow, up to
**512× hot-bucket imbalance**; see `../../perf-results/2026-07-01-encap-flow-distribution/`).

| gate | enable when | leave off when | caveats |
|---|---|---|---|
| **gtpu_inner** | **telco/5G mobile core (UPF/PGW-U)** — GTP-U has no outer source-port entropy, so inner flows *always* collapse to one queue/path. The strongest case. | you deliberately pin a subscriber tunnel to one core/path | GTP-U v1 G-PDU only (no seq/N-PDU/ext-header, no GTP'); inner is naked IP |
| **vxlan_inner** | k8s / cloud VXLAN overlays where east-west inner flows must spread or be classified per-inner-flow; **essential** for fixed-source-port or hardware VTEPs (which collapse) | pure Linux-sourced VXLAN whose outer UDP sport already carries inner entropy *and* you only need RSS/ECMP spread (not inner identity for tc-flower/CT) | outer port hardcoded **4789** (IANA) — does **not** match Cilium's 8472; needs the per-netns port-config follow-up |
| **geneve_inner** | as vxlan_inner, for Geneve (dport 6081) overlays | as vxlan_inner | standard TEB inner Ethernet, no Geneve options (`opt_len==0`) |

Key nuance (be honest with yourself): for **VXLAN/Geneve with a Linux sender**,
the outer UDP source port is already derived from the inner flow, so RSS/ECMP
*spreading* is usually fine without descent — its value there is giving
**tc-flower / conntrack / accounting the real inner 5-tuple** and removing the
14-bit source-port resolution ceiling at very high flow counts (>~16k flows per
endpoint pair). For **GTP-U and fixed-source-port / hardware tunnels**, descent
is the only way to spread or distinguish inner flows at all.

Because these change hashing behaviour, roll out per-netns / per-host and verify
your ECMP/RSS distribution and any tc-flower rules still behave as intended.

## Quick decision guide

- Plain IP DC/edge host → `eth_ip` (+`vlan`/`qinq`).
- Tunnel/transit box → add `ipip`/`gre`.
- BNG / MPLS router → add `pppoe` / `mpls`.
- k8s/cloud overlay node needing per-inner-flow spread or classification →
  consider `vxlan_inner`/`geneve_inner` (behaviour change).
- Telco UPF/5G user-plane → `gtpu_inner` (behaviour change; highest-impact case).
