[Back to Summary](../SUMMARY.md)

## Protocol Coverage

14 parsers provide coverage across ~65 protocol types, backed by 76
reusable `proto_def` headers organized into 14 subdirectories under
`xdp2/proto_defs/` (ethernet/, ip/, transport/, tunnel/, security/,
management/, storage/, wireless/, bluetooth/, infiniband/, can/,
netlink/, legacy/, other/).

### L3/L4 Protocol Coverage (ipv4_table / ipv6_table)

| IP Protocol | Constant | Node | Kernel parity | Notes |
|---|---|---|---|---|
| TCP | IPPROTO_TCP | ports_node | Yes | Port extraction |
| UDP | IPPROTO_UDP | udp_node | Yes | Port extraction + tunnel dispatch |
| UDP-Lite | IPPROTO_UDPLITE | ports_node | Yes | Same 4-byte port layout as UDP |
| SCTP | IPPROTO_SCTP | ports_node | Yes | Port extraction |
| DCCP | IPPROTO_DCCP | ports_node | Yes | Port extraction |
| ICMP | IPPROTO_ICMP | icmpv4_node | Yes | IPv4 only |
| ICMPv6 | IPPROTO_ICMPV6 | icmpv6_node | Yes | IPv6 only |
| IGMP | IPPROTO_IGMP | igmp_node | Yes | IPv4 only, leaf |
| GRE | IPPROTO_GRE | gre_base_node | Yes | Version dispatch → v0/v1 |
| MPLS-in-IP | IPPROTO_MPLS | mpls_node | Yes | Leaf |
| IPv4-in-IPv4 | IPPROTO_IPIP | ipv4ip_node | Yes | Encapsulation |
| IPv6-in-IPv4 | IPPROTO_IPV6 | ipv6ip_node | Yes | Encapsulation |
| ESP | IPPROTO_ESP | esp_node | Yes | Leaf, SPI as keyid |
| AH | IPPROTO_AH | ah_ipv4/v6_node | Yes | Chains to next proto |
| L2TPv3 | IPPROTO_L2TP | l2tp_node | Yes | Session ID extraction |

IPv6 extension headers: Hop-by-Hop, Destination Options, Routing, Fragment.

### L2 Ethertype Coverage (ether_table / etype_table)

| Ethertype | Constant | Node | Category | Notes |
|---|---|---|---|---|
| 0x0800 | ETH_P_IP | ip_check_node | Core | IPv4 |
| 0x86DD | ETH_P_IPV6 | ip_check_node | Core | IPv6 |
| 0x88A8 | ETH_P_8021AD | e8021AD_node | VLAN | 802.1AD (Q-in-Q) |
| 0x8100 | ETH_P_8021Q | e8021Q_node | VLAN | 802.1Q |
| 0x8847 | ETH_P_MPLS_UC | mpls_node | Carrier | MPLS unicast |
| 0x8848 | ETH_P_MPLS_MC | mpls_node | Carrier | MPLS multicast |
| 0x0806 | ETH_P_ARP | arp_node | Core | ARP |
| 0x8035 | ETH_P_RARP | rarp_node | Core | RARP |
| 0x88CA | ETH_P_TIPC | tipc_node | Cluster | TIPC |
| 0x8864 | ETH_P_PPP_SES | pppoe_node | Access | PPPoE session |
| 0x8906 | ETH_P_FCOE | fcoe_node | Storage | Fibre Channel over Ethernet |
| 0x4305 | ETH_P_BATMAN | batman_node | Mesh | B.A.T.M.A.N. |
| 0x88CC | ETH_P_LLDP | lldp_node | Management | Link Layer Discovery |
| 0x8809 | ETH_P_SLOW | slow_node | Management | LACP/Marker/OAM |
| 0x8808 | ETH_P_PAUSE | mac_control_node | Management | Pause/PFC |
| 0x888E | ETH_P_PAE | eapol_node | Security | 802.1X |
| 0x88F7 | ETH_P_1588 | ptp_node | Timing | IEEE 1588 PTP |
| 0x88F5 | ETH_P_MVRP | mvrp_node | Management | MRP |
| 0x8902 | ETH_P_CFM | cfm_node | Management | 802.1ag OAM |
| 0x8914 | ETH_P_FIP | fip_node | Storage | FCoE Initialization |
| 0x88E5 | ETH_P_MACSEC | macsec_node | Security | MACsec (802.1AE) |
| 0x88A4 | ETH_P_ETHERCAT | ethercat_node | Industrial | EtherCAT |
| 0x88E7 | ETH_P_8021AH | pbb_node | Carrier | PBB/MAC-in-MAC |
| 0x22F3 | ETH_P_TRILL | trill_node | DC | TRILL |
| 0x892F | ETH_P_HSR | hsr_node | Redundancy | HSR (IEC 62439-3) |
| 0x88FB | ETH_P_PRP | hsr_node | Redundancy | PRP (same format as HSR) |
| 0x894F | ETH_P_NSH | nsh_node | SFC | Network Service Header |
| ≤1500 | ETH_P_802_2 | llc_node | Framing | LLC/802.2 → SNAP/STP |
| 0x8915 | ETH_P_IBOE | ib_grh_node | RDMA | RoCE v1 (GRH→BTH) |
| 0x8892 | ETH_P_PROFINET | profinet_node | Industrial | PROFINET |
| 0x88A2 | ETH_P_AOE | aoe_node | Storage | ATA over Ethernet |
| 0x88F8 | ETH_P_NCSI | ncsi_node | Management | NC-SI (BMC↔NIC) |
| 0x000C | ETH_P_CAN | can_node | Automotive | Classical CAN |
| 0x000D | ETH_P_CANFD | canfd_node | Automotive | CAN FD |
| 0x000E | ETH_P_CANXL | canxl_node | Automotive | CAN XL (SDT dispatch) |
| 0x00F5 | ETH_P_PHONET | phonet_node | Mobile | Nokia Phonet/ISI |
| 0x00F6 | ETH_P_IEEE802154 | ieee802154_node | IoT | 802.15.4 WPAN |
| 0x884C | ETH_P_ATMMPOA | atm_mpoa_node | Legacy | ATM MPOA |
| 0x8137 | ETH_P_IPX | ipx_node | Legacy | Novell IPX |
| 0x809B | ETH_P_ATALK | atalk_node | Legacy | AppleTalk DDP |
| 0x0805 | ETH_P_X25 | x25_node | Legacy | X.25 |
| 0x001B | ETH_P_DSA | dsa_node | Switching | DSA tag |
| 0xDADA | ETH_P_EDSA | edsa_node | Switching | Extended DSA |

Total: 43 ethertype entries.

### Tunnel/Encapsulation Inner Dispatch

| Tunnel | Table | Inner protocols dispatched |
|---|---|---|
| GRE v0 | gre_v0_table | IPv4, IPv6, Ethernet (TEB), MPLS UC/MC, ERSPAN v1/v2 |
| GRE v1/PPTP | pptp_inner_table → pptp_ppp_table | PPP → IPv4, IPv6 |
| PPPoE | pppoe_table | IPv4, IPv6, MPLS UC/MC |
| VXLAN | vxlan_inner_table | Ethernet (TEB) |
| Geneve | geneve_inner_table | Ethernet (TEB), IPv4, IPv6 |
| NSH | nsh_inner_table | IPv4, IPv6, Ethernet (TEB), MPLS |
| UDP tunnel | udp_tunnel_table | VXLAN (4789), Geneve (6081), RoCE v2 BTH (4791) |
| PBB | → ether_table | Full ethertype dispatch (inner Ethernet) |
| TRILL | → ether_table | Full ethertype dispatch (inner Ethernet) |
| HSR/PRP | → ether_table | Full ethertype dispatch (encap_proto) |
| Batman | → ether_table | Full ethertype dispatch (inner Ethernet) |
| EDSA | → ether_table | Full ethertype dispatch (inner ethertype) |

### Behavioral Differences from Kernel

| Behavior | Kernel | xdp2 | Rationale |
|---|---|---|---|
| GRE with routing | Stops | Stops | Can't determine header length without parsing SRE |
| MPLS label depth | 1 label | 1 label (leaf) | Flow keys need outermost label only |
| Geneve TLV parsing | Skips | Skips | Flow keys don't need TLV options |
| RARP | Not handled | Handled | Reuses ARP metadata extractor |
| FCoE/Batman/LLDP/etc | Not handled | Handled | Extended coverage beyond flow dissector |
| L2TP session length | min_len=2 | min_len=4 | Need 4 bytes for session_id extraction |

### Non-Ethernet Parse Graphs

Each graph has its own `XDP2_PARSER()` with a dedicated root node,
avoiding dispatch overhead at a shared root. Userspace only
(`#ifndef XDP2_XDP_BUILD`).

#### WiFi 802.11 (`xdp2_parser_ieee80211`)

**Root:** `ieee80211_node` — dispatches on `frame_control & 0x000c`.

```
ieee80211_node
├── FTYPE_MGMT (0x0000) → ieee80211_mgmt_node (leaf)
├── FTYPE_CTL  (0x0004) → ieee80211_ctl_node (leaf)
├── FTYPE_DATA (0x0008) → ieee80211_data_node (leaf)
└── FTYPE_EXT  (0x000c) → ieee80211_ext_node (leaf)
```

Proto_defs: `proto_ieee80211.h`, `proto_ieee80211_mgmt.h`, `proto_ieee80211_data.h`

#### Bluetooth HCI (`xdp2_parser_hci`)

**Root:** `hci_node` — dispatches on 1-byte packet type indicator.

```
hci_node
├── 0x01 → hci_cmd_node (leaf — opcode + plen)
├── 0x02 → hci_acl_node → l2cap_node (leaf)
├── 0x03 → hci_sco_node (leaf)
├── 0x04 → hci_event_node (leaf)
└── 0x05 → hci_iso_node (leaf)
```

Proto_defs: `proto_hci.h`, `proto_hci_cmd.h`, `proto_hci_event.h`,
`proto_hci_acl.h`, `proto_hci_sco.h`, `proto_hci_iso.h`, `proto_l2cap.h`

#### InfiniBand (`xdp2_parser_infiniband`)

**Root:** `ib_lrh_node` — dispatches on LNH (Link Next Header) field.

```
ib_lrh_node
├── LNH=0 → ib_raw_node (leaf)
├── LNH=1 → ip_check_node (IPv6, reused from Ethernet graph)
├── LNH=2 → ib_bth_node (leaf — opcode, pkey, dest QP)
└── LNH=3 → ib_grh_node → ib_bth_node
```

Also reachable via Ethernet: RoCE v1 (`ETH_P_IBOE → ib_grh_node → ib_bth_node`)
and RoCE v2 (`UDP port 4791 → ib_bth_node`).

Proto_defs: `proto_ib_lrh.h`, `proto_ib_grh.h`, `proto_ib_bth.h`

#### CAN Bus (3 parsers)

| Parser | Root | Frame type |
|---|---|---|
| `xdp2_parser_can` | `can_node` | Classical CAN (16 bytes) |
| `xdp2_parser_canfd` | `canfd_node` | CAN FD (72 bytes) |
| `xdp2_parser_canxl` | `canxl_node` | CAN XL (SDT dispatch) |

Proto_defs: `proto_can.h`, `proto_canfd.h`, `proto_canxl.h`

#### Netlink (`xdp2_parser_netlink`)

**Root:** `netlink_node` — dispatches on `nlmsg_type`.

```
netlink_node
├── NLMSG_NOOP (1)  → netlink_leaf_node
├── NLMSG_ERROR (2) → netlink_leaf_node
├── NLMSG_DONE (3)  → netlink_leaf_node
└── (other types)   → table miss → stop
```

Proto_defs: `proto_netlink.h`, `proto_genetlink.h`, `proto_nlattr.h`

#### Simple Leaf Parsers

| Parser | Root | Link layer |
|---|---|---|
| `xdp2_parser_ieee802154` | `ieee802154_node` | 802.15.4 WPAN |
| `xdp2_parser_phonet` | `phonet_node` | Nokia Phonet/ISI |
| `xdp2_parser_mctp` | `mctp_node` | MCTP (DMTF DSP0236) |
| `xdp2_parser_atm` | `atm_node` | ATM cells |
| `xdp2_parser_x25` | `x25_pkt_node` | X.25 packet layer |

Proto_defs: `proto_ieee802154.h`, `proto_phonet.h`, `proto_mctp.h`,
`proto_atm.h`, `proto_x25.h`

### Architecture: Multi-Parser Design

Each protocol family gets its own `XDP2_PARSER()` with a dedicated root
node, following the `parser_big.c` pattern of multiple parsers sharing
node definitions in a single `.c` file.

- **Root isolation:** No dispatch overhead at a shared root — each parser
  enters directly at its link-layer header.
- **Node sharing:** Shared nodes (`ip_check_node`, `ether_inner_node`,
  `ib_bth_node`) are reused across Ethernet and non-Ethernet graphs.
- **Compile unit:** A single `.c` file can define unlimited parsers for
  userspace. BPF/XDP is limited to 1 root per compile unit.
- **Ethertype tables:** `ether_table` and `etype_table` are kept in sync,
  both containing all 43 ethertype entries.

### Kernel Source References

| Protocol family | Linux source |
|---|---|
| Flow dissector | `net/core/flow_dissector.c` |
| BPF flow dissector | `tools/testing/selftests/bpf/progs/bpf_flow.c` |
| WiFi 802.11 | `include/linux/ieee80211.h`, `net/mac80211/` |
| Bluetooth HCI | `include/net/bluetooth/bluetooth.h`, `net/bluetooth/hci_core.c` |
| InfiniBand | `include/rdma/ib_pack.h`, `drivers/infiniband/` |
| CAN | `include/uapi/linux/can.h`, `net/can/` |
| Netlink | `include/uapi/linux/netlink.h`, `net/netlink/` |
| IEEE 802.15.4 | `include/net/ieee802154_netdev.h`, `net/ieee802154/` |
| Phonet | `include/uapi/linux/phonet.h`, `net/phonet/` |
| MCTP | `include/net/mctp.h`, `net/mctp/` |
| ATM | `include/uapi/linux/atm.h`, `net/atm/` |
| X.25 | `include/uapi/linux/x25.h`, `net/x25/` |
| GRE/PPTP | `include/uapi/linux/if_tunnel.h`, `net/ipv4/ip_gre.c` |
| ERSPAN | `include/uapi/linux/erspan.h`, `net/ipv4/ip_gre.c` |
| RoCE | `drivers/infiniband/hw/mlx5/`, UDP port 4791 |

### Protocol Count Summary

| Metric | Count |
|---|---|
| Parsers | 14 (2 Ethernet/IP + 12 non-Ethernet) |
| Proto_def headers | 76 |
| Ethertype entries | 43 |
| IP protocol entries | 15 (IPv4) + 17 (IPv6) |
| Tunnel inner dispatch entries | 20+ |
| Total unique protocol types | ~65 |
| Non-Ethernet protocol families | 10 (WiFi, Bluetooth, IB, CAN, Netlink, 802.15.4, Phonet, MCTP, ATM, X.25) |

### UDP Tunnel Dispatch

The `udp_node` extracts port metadata AND dispatches on destination port:
- Port 4789 → VXLAN → inner Ethernet → full protocol stack
- Port 6081 → Geneve → inner protocol
- Port 4791 → RoCE v2 → IB BTH (leaf)
- Other ports → `XDP2_STOP_UNKNOWN_PROTO` (ports already extracted)

### Carrier Network Coverage

The combinatorial PCAP generator (`gen_test_pcap.py`) produces packets for
all valid combinations of these protocol stacks:

- **ISP subscriber access**: PPPoE / VLAN+PPPoE / QinQ+PPPoE / PPPoE+MPLS
- **Carrier backbone**: MPLS 1-4 labels, VPLS (MPLS→Ethernet→inner)
- **Data center overlay**: VXLAN (EVPN), Geneve, NSH (SFC)
- **IPsec**: ESP, AH→TCP, AH→ESP, MACsec
- **Tunneling**: GRE v0, GRE+key, GRE+TEB, GRE+MPLS, GRE+ERSPAN,
  GRE v1/PPTP→PPP, IPv4-in-IPv4, IPv6-in-IPv4, PBB, TRILL, HSR/PRP
- **RDMA**: RoCE v1 (ETH_P_IBOE), RoCE v2 (UDP 4791)
- **IPv6 extension headers**: HbH, Destination, Routing, Fragment
- **Network management**: LLDP, STP/RSTP/MSTP, CFM/OAM, MVRP, PTP, NC-SI
- **Access control**: EAPOL (802.1X), MAC Control (Pause/PFC)
- **Storage networking**: FCoE, FIP, AoE
- **Industrial**: EtherCAT, PROFINET
- **Mesh/Overlay**: B.A.T.M.A.N., EDSA
- **Automotive**: CAN, CAN FD, CAN XL
- **LLC/SNAP**: 802.2 LLC framing with DSAP dispatch, SNAP bridge to ethertypes

### Known Limitations

1. **Fast parser incompatible.** The expanded L2 graph has ~70 unique
   reachable nodes, exceeding `NUM_FAST_NODES` (64) in
   `xdp2_parse_validate_fast()`. The `-F` (fast parser) flag is no longer
   usable with the L2 parser. The optimized parser (`-O`) provides better
   performance anyway. See [challenge #14](challenges.md#14-fast-parser-incompatible-with-expanded-graph).

2. **BPF build uses reduced table.** The BPF build (`parser_xdp.c`) only
   sees 28 core ethertype entries via `ETHER_TABLE_CORE_ENTRIES` and 2 UDP
   tunnel entries via `UDP_TUNNEL_TABLE_CORE_ENTRIES`. The 15 extended L2
   ethertypes (PROFINET, AoE, CAN, etc.) and RoCE v2 are userspace-only.
   All 12 non-Ethernet parse graphs are also userspace-only. This is
   necessary to keep the BPF program within branch target range limits.
   See [challenge #12](challenges.md#12-bpf-program-size-exceeded-branch-target-range).

3. **Non-Ethernet parsers are untested.** The 12 non-Ethernet parse graphs
   (WiFi, Bluetooth HCI, InfiniBand, CAN, Netlink, etc.) compile and link
   correctly, but have no test PCAPs or correctness benchmarks. They serve
   as demonstrations of the multi-graph architecture. Testing would require
   protocol-specific PCAP generation and reference parsers.

4. **No metadata extractors for new protocols.** The new L2 leaf nodes and
   non-Ethernet graph nodes do not have custom `XDP2_METADATA_TEMP_*`
   instantiations. They parse and validate headers but do not extract
   protocol-specific fields into the metadata struct. Adding metadata
   extraction would require either extending `xdp2_metadata_all` or
   creating per-family metadata structs.

5. **Metadata struct oversized.** `struct xdp2_metadata_all` is ~200 bytes,
   more than 2x the kernel's `struct flow_keys` (~88 bytes). The per-packet
   `memset` cost (~15 ns) accounts for most of the gap between "with memset"
   and "parse-only" performance. See [metadata optimization](metadata-optimization.md).

### Potential Improvements

1. **Purpose-built metadata struct.** Define `struct flow_dissector_metadata`
   (~88 bytes) containing only the fields the flow dissector extractors
   write to. This would close the memset gap and give the optimized parser
   an expected 1.0–1.3x speedup including all setup overhead.

2. **BPF split compilation.** Split the L3 flow dissector into a minimal
   BPF-only parser file with just the core Ethernet/IP protocol stack,
   separate from the multi-graph userspace parser. This would allow the BPF
   program to have full ethertype coverage without hitting size limits.

3. **Non-Ethernet test PCAPs.** Generate test PCAPs for WiFi, Bluetooth HCI,
   InfiniBand, CAN, and Netlink protocol families. Write reference parsers
   or use `tcpdump`/`tshark` dissection as ground truth.

4. **WiFi 802.11 data frame chaining.** The data frame node is currently a
   leaf. It could chain to LLC/SNAP and then to `etype_dispatch_node` for
   inner protocol parsing (e.g., IPv4/IPv6 inside 802.11 data frames).

5. **Netlink TLV parsing.** The Netlink graph currently only dispatches on
   `nlmsg_type`. It could use `XDP2_NODE_TYPE_TLVS` for nlattr iteration,
   enabling structured extraction of Netlink attributes.

6. **Increase NUM_FAST_NODES.** The library constant `NUM_FAST_NODES` (64)
   could be increased to accommodate larger graphs. This is a one-line
   change in `src/lib/xdp2/parser.c` but would need upstream coordination.
