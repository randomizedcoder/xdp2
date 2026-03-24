[Back to Summary](../SUMMARY.md)

## Proto_defs Directory Layout and Adding New Protocols

### Directory Hierarchy

76 reusable protocol definition headers organized by protocol family:

```
src/include/xdp2/proto_defs/
├── ethernet/       (4)   L2 Ethernet framing
│   ├── proto_ether.h          Ethernet II header
│   ├── proto_vlan.h           802.1Q / 802.1AD VLAN tags
│   ├── proto_pbb.h            802.1ah Provider Backbone Bridging
│   └── proto_edsa.h           Extended DSA tag (Marvell)
│
├── ip/            (11)   IP and related L3
│   ├── proto_ip.h             IP version overlay (dispatches v4/v6)
│   ├── proto_ipv4.h           IPv4 header
│   ├── proto_ipv6.h           IPv6 header
│   ├── proto_ipv6_eh.h        IPv6 extension headers (HbH, Dst, Routing)
│   ├── proto_ipv6_nd.h        IPv6 Neighbor Discovery
│   ├── proto_ipv4ip.h         IPv4-in-IPv4 (IPIP tunnel)
│   ├── proto_ipv6ip.h         IPv6-in-IPv4 tunnel
│   ├── proto_arp_rarp.h       ARP / RARP
│   ├── proto_icmp.h           ICMPv4 / ICMPv6
│   ├── proto_igmp.h           IGMP
│   └── proto_srv6.h           Segment Routing v6
│
├── transport/      (6)   L4 transport
│   ├── proto_tcp.h            TCP (with TLV option parsing)
│   ├── proto_udp.h            UDP
│   ├── proto_ports.h          Generic 4-byte port reader (TCP/UDP/SCTP/DCCP)
│   ├── proto_tipc.h           TIPC
│   ├── proto_l2tp.h           L2TPv3
│   └── proto_l2tp_v0.h        L2TPv2
│
├── tunnel/         (9)   Encapsulation and tunneling
│   ├── proto_gre.h            GRE v0 + v1/PPTP (flag-fields)
│   ├── proto_vxlan.h          VXLAN
│   ├── proto_geneve.h         Geneve (with TLV option parsing)
│   ├── proto_mpls.h           MPLS label stack
│   ├── proto_erspan.h         ERSPAN v1/v2
│   ├── proto_nsh.h            Network Service Header (SFC)
│   ├── proto_ppp.h            PPP
│   ├── proto_pppoe.h          PPPoE
│   └── proto_hsr.h            HSR / PRP (IEC 62439-3)
│
├── security/       (4)   IPsec and access control
│   ├── proto_ah.h             Authentication Header
│   ├── proto_esp.h            Encapsulating Security Payload
│   ├── proto_macsec.h         MACsec (802.1AE)
│   └── proto_eapol.h          802.1X (EAP over LAN)
│
├── management/    (10)   Network management and control
│   ├── proto_lldp.h           Link Layer Discovery Protocol
│   ├── proto_cfm.h            Connectivity Fault Management (802.1ag)
│   ├── proto_ptp.h            Precision Time Protocol (IEEE 1588)
│   ├── proto_slow.h           Slow Protocols (LACP/Marker/OAM)
│   ├── proto_trill.h          TRILL (RFC 6325)
│   ├── proto_mvrp.h           MRP (802.1ak)
│   ├── proto_fip.h            FCoE Initialization Protocol
│   ├── proto_mac_control.h    MAC Control (Pause/PFC)
│   ├── proto_profinet.h       PROFINET
│   └── proto_ncsi.h           NC-SI (BMC↔NIC management)
│
├── storage/        (2)   Storage over Ethernet
│   ├── proto_aoe.h            ATA over Ethernet
│   └── proto_ethercat.h       EtherCAT (industrial)
│
├── wireless/       (3)   WiFi 802.11
│   ├── proto_ieee80211.h      802.11 frame control dispatch
│   ├── proto_ieee80211_mgmt.h Management frames
│   └── proto_ieee80211_data.h Data frames
│
├── bluetooth/      (7)   Bluetooth HCI + L2CAP
│   ├── proto_hci.h            HCI packet type dispatch
│   ├── proto_hci_cmd.h        HCI command packets
│   ├── proto_hci_event.h      HCI event packets
│   ├── proto_hci_acl.h        HCI ACL data
│   ├── proto_hci_sco.h        HCI SCO audio
│   ├── proto_hci_iso.h        HCI ISO streaming
│   └── proto_l2cap.h          L2CAP (logical link)
│
├── infiniband/     (3)   InfiniBand / RoCE
│   ├── proto_ib_lrh.h         Local Route Header
│   ├── proto_ib_grh.h         Global Route Header
│   └── proto_ib_bth.h         Base Transport Header
│
├── can/            (3)   CAN bus (automotive)
│   ├── proto_can.h            Classical CAN 2.0
│   ├── proto_canfd.h          CAN FD
│   └── proto_canxl.h          CAN XL
│
├── netlink/        (3)   Netlink
│   ├── proto_netlink.h        Netlink message header
│   ├── proto_genetlink.h      Generic Netlink
│   └── proto_nlattr.h         Netlink attributes
│
├── legacy/        (10)   Legacy and niche protocols
│   ├── proto_batman.h         B.A.T.M.A.N.
│   ├── proto_ipx.h            Novell IPX
│   ├── proto_atalk.h          AppleTalk DDP
│   ├── proto_x25.h            X.25
│   ├── proto_atm.h            ATM MPOA
│   ├── proto_phonet.h         Nokia Phonet/ISI
│   ├── proto_mctp.h           MCTP (DMTF DSP0236)
│   ├── proto_dsa.h            DSA tag (Memory-mapped switches)
│   ├── proto_ieee802154.h     802.15.4 WPAN
│   └── proto_protobuf.h       Protocol Buffers (experimental)
│
├── other/          (1)
│   └── proto_fcoe.h           Fibre Channel over Ethernet
│
└── Makefile                   Hierarchical install
```

### Choosing a Subdirectory

| If your protocol is... | Put it in |
|---|---|
| An L2 Ethernet framing variant | `ethernet/` |
| An IP-layer or L3 protocol | `ip/` |
| A transport/session protocol (has ports or connections) | `transport/` |
| An encapsulation or tunneling protocol | `tunnel/` |
| Security/authentication related | `security/` |
| Network management, control plane, or OAM | `management/` |
| Storage networking | `storage/` |
| Wireless (802.11 family) | `wireless/` |
| Bluetooth | `bluetooth/` |
| InfiniBand / RoCE | `infiniband/` |
| CAN bus | `can/` |
| Netlink | `netlink/` |
| Legacy, niche, or doesn't fit elsewhere | `legacy/` |
| Anything else | `other/` |

### How to Add a New Protocol

Adding a protocol requires changes in three places:

1. **Create a proto_def header** (`src/include/xdp2/proto_defs/<category>/proto_foo.h`)
2. **Register it** in `src/include/xdp2/proto_defs.h`
3. **Wire it into the parse graph** in the flow dissector (or your own parser)

#### Step 1: Create the proto_def header

A proto_def has two halves separated by `#ifdef XDP2_DEFINE_PARSE_NODE`:

```c
#ifndef __XDP2_PROTO_FOO_H__
#define __XDP2_PROTO_FOO_H__

#include "xdp2/parser.h"

/* Protocol header struct — network byte order types */
struct foo_hdr {
    __be16 type;
    __be16 length;
};

#endif /* __XDP2_PROTO_FOO_H__ */

#ifdef XDP2_DEFINE_PARSE_NODE

static const struct xdp2_proto_def xdp2_parse_foo __unused() = {
    .name = "Foo",
    .min_len = sizeof(struct foo_hdr),
};

#endif /* XDP2_DEFINE_PARSE_NODE */
```

For a **leaf protocol** (no further dispatch), that's all you need.

For a **dispatching protocol** (chains to inner protocols), add ops:

```c
/* Returns next protocol number for table lookup */
static inline int foo_proto(const void *vhdr)
{
    return ((struct foo_hdr *)vhdr)->type;
}

/* Variable-length header (optional — omit for fixed-length) */
static inline int foo_len(const void *vhdr)
{
    return ntohs(((struct foo_hdr *)vhdr)->length);
}

#ifdef XDP2_DEFINE_PARSE_NODE

static const struct xdp2_proto_def xdp2_parse_foo __unused() = {
    .name = "Foo",
    .min_len = sizeof(struct foo_hdr),
    .ops.next_proto = foo_proto,    /* enables table dispatch */
    .ops.len = foo_len,             /* variable-length header */
};

#endif
```

For an **encapsulation protocol** (tunnel), add `.encap = true`.

#### Step 2: Register in proto_defs.h

Add the include to the appropriate section in `src/include/xdp2/proto_defs.h`:

```c
/* Management / control */
#include "xdp2/proto_defs/management/proto_lldp.h"
#include "xdp2/proto_defs/management/proto_foo.h"    /* ← new */
```

Also add the file to `src/include/xdp2/proto_defs/Makefile` — the Makefile
uses a wildcard (`$$dir/proto_*.h`), so no change is needed unless you
create a new subdirectory.

#### Step 3: Wire into the parse graph

In the flow dissector's parser fragments (or your own parser.c):

**Leaf protocol** — add a node and a table entry:

```c
/* In flow_dissector_nodes.h (or flow_dissector_nodes_l2.h for userspace-only): */
XDP2_MAKE_LEAF_PARSE_NODE(foo_node, xdp2_parse_foo, ());

/* In flow_dissector_tables.h — add to the appropriate table: */
XDP2_MAKE_PROTO_TABLE(ether_table,
    ...
    ( __cpu_to_be16(ETH_P_FOO), foo_node ),    /* ← new entry */
);
```

**Dispatching protocol** — add a node, a dispatch table, and a table entry:

```c
/* In flow_dissector_nodes.h: */
XDP2_MAKE_PARSE_NODE(foo_node, xdp2_parse_foo, foo_table, ());

/* In flow_dissector_tables.h: */
XDP2_MAKE_PROTO_TABLE(foo_table,
    ( FOO_TYPE_BAR, bar_node ),
    ( FOO_TYPE_BAZ, baz_node ),
);
```

**With metadata extraction** — define a metadata template or inline function:

```c
/* In flow_dissector_metadata.h: */
XDP2_METADATA_TEMP_foo(foo_metadata, xdp2_metadata_all)

/* In the node definition: */
XDP2_MAKE_LEAF_PARSE_NODE(foo_node, xdp2_parse_foo,
    (.ops.extract_metadata = foo_metadata));
```

#### BPF build considerations

If the protocol is only needed in userspace builds, wrap it in
`#ifndef XDP2_XDP_BUILD`. The BPF build uses reduced tables
(`ETHER_TABLE_CORE_ENTRIES`) to stay within BPF instruction limits.
Extended L2 protocols go in `flow_dissector_nodes_l2.h` (already
wrapped by parser.c). Non-Ethernet graph fragments go in their own
`graph_*.h` files.

### Parser Fragment Layout

The flow dissector's `parser.c` is an orchestrator that `#include`s
11 header fragments (all in the same translation unit for `static const`
internal linkage):

```
parser.c                         ← entry point (orchestrator)
├── flow_dissector_metadata.h    ← 18 metadata extractors
├── flow_dissector_proto_defs.h  ← 6 local proto_defs (LLC, SNAP, STP, ...)
├── flow_dissector_nodes.h       ← ~40 core Ethernet/IP parse nodes
├── flow_dissector_nodes_l2.h    ← extended L2 leaf nodes (userspace only)
├── flow_dissector_tables.h      ← ~15 protocol dispatch tables
├── graph_ieee80211.h            ← WiFi 802.11 graph (userspace only)
├── graph_bluetooth.h            ← Bluetooth HCI graph (userspace only)
├── graph_infiniband.h           ← InfiniBand graph (userspace only)
├── graph_netlink.h              ← Netlink graph (userspace only)
├── graph_misc.h                 ← X.25, MCTP, ATM roots (userspace only)
└── flow_dissector_parsers.h     ← 14 XDP2_PARSER() declarations
```

For BPF builds, `parser_xdp.c` does `#define XDP2_XDP_BUILD` then
`#include "parser.c"`, which excludes the L2 and non-Ethernet fragments.

### Quick Reference: Where to Put New Code

| What you're adding | Where it goes |
|---|---|
| New reusable proto_def | `src/include/xdp2/proto_defs/<category>/` |
| Local proto_def (sample-specific) | `flow_dissector_proto_defs.h` |
| Leaf parse node | `flow_dissector_nodes.h` (core) or `flow_dissector_nodes_l2.h` (extended) |
| Table entry for existing table | `flow_dissector_tables.h` |
| New dispatch table | `flow_dissector_tables.h` |
| Metadata extractor | `flow_dissector_metadata.h` |
| New non-Ethernet graph | New `graph_*.h` file + include in `parser.c` |
| New parser root | `flow_dissector_parsers.h` |
