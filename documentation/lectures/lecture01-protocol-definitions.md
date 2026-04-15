# Lecture 1: Protocol Definitions -- The Vocabulary of Parsing

A **protocol definition** describes how to parse one type of protocol header.
It answers two questions:

1. **How long is this header?** (so we know where the next header starts)
2. **What protocol comes next?** (so we know which node to visit next)

These are the only two pieces of information the parse engine needs to walk
from one node to the next.

## 1.1 The `struct xdp2_proto_def` Data Structure

Defined in
[src/include/xdp2/parser_types.h](../src/include/xdp2/parser_types.h) at
lines 153--160:

```c
struct xdp2_proto_def {
    enum xdp2_parser_node_type node_type;  /* Plain, TLVs, flag-fields, array */
    __u8 encap;                            /* Encapsulation protocol flag */
    __u8 overlay;                          /* Overlay protocol flag */
    __u16 min_len;                         /* Minimum header length (bytes) */
    const char *name;                      /* Debug name string */
    const struct xdp2_parse_ops ops;       /* Parsing operations */
};
```

The `ops` field contains the two essential function pointers
([parser_types.h:133--137](../src/include/xdp2/parser_types.h)):

```c
struct xdp2_parse_ops {
    ssize_t (*len)(const void *hdr, size_t maxlen);
    int (*next_proto)(const void *hdr);
    int (*next_proto_keyin)(const void *hdr, __u32 key);
};
```

Here is a field-by-field breakdown:

```
+-----------------------------------------------------------+
| struct xdp2_proto_def                                     |
+------------------+----------------------------------------+
| node_type        | XDP2_NODE_TYPE_PLAIN (most protocols)  |
|                  | XDP2_NODE_TYPE_TLVS  (TCP options)     |
|                  | XDP2_NODE_TYPE_FLAG_FIELDS (GRE)       |
|                  | XDP2_NODE_TYPE_ARRAY (SRv6)            |
+------------------+----------------------------------------+
| encap            | 1 if this protocol encapsulates        |
|                  | another packet (e.g., GRE, IPIP)       |
+------------------+----------------------------------------+
| overlay          | 1 if this is a "version check" node    |
|                  | that doesn't consume bytes (e.g., IP   |
|                  | version check dispatching to v4 or v6) |
+------------------+----------------------------------------+
| min_len          | Minimum header size in bytes            |
|                  | (14 for Ethernet, 20 for IPv4)         |
+------------------+----------------------------------------+
| name             | Human-readable string for debugging     |
+------------------+----------------------------------------+
| ops.len          | Returns actual header length            |
|                  | NULL => use min_len as fixed length     |
+------------------+----------------------------------------+
| ops.next_proto   | Returns next protocol number            |
|                  | NULL => this is a leaf protocol         |
+------------------+----------------------------------------+
| ops.next_proto   | Variant that takes an additional key    |
|    _keyin        | parameter from inter-node state         |
+------------------+----------------------------------------+
```

**Key design rule**: If `ops.len` is NULL, the header is fixed-length and
`min_len` is used directly. If `ops.len` is non-NULL, the function is called
and the result is checked against both `min_len` and the remaining packet
length.

## 1.2 Walk-through: Ethernet Protocol Definition

The Ethernet protocol definition is in
[src/include/xdp2/proto_defs/ethernet/proto_ether.h](../src/include/xdp2/proto_defs/ethernet/proto_ether.h):

```c
/* Line 36: The next_proto function reads the EtherType field */
static inline int ether_proto(const void *veth)
{
    return ((struct ethhdr *)veth)->h_proto;
}

/* Line 52: The protocol definition */
static const struct xdp2_proto_def xdp2_parse_ether = {
    .name = "Ethernet",
    .min_len = sizeof(struct ethhdr),       /* 14 bytes */
    .ops.next_proto = ether_proto,
};
```

Note what is **not** set:
- `ops.len` is NULL because Ethernet headers are always exactly 14 bytes
- `encap` and `overlay` are 0 (Ethernet is neither)
- `node_type` defaults to `XDP2_NODE_TYPE_PLAIN`

The `ether_proto` function simply returns the 16-bit EtherType field from the
Ethernet header. This value (e.g., `0x0800` for IPv4, `0x86DD` for IPv6) is
used by the parse engine to look up the next node in a protocol table.

## 1.3 Walk-through: IPv4 Protocol Definition

IPv4 is more complex because it has a variable-length header. Defined in
[src/include/xdp2/proto_defs/ip/proto_ipv4.h](../src/include/xdp2/proto_defs/ip/proto_ipv4.h):

```c
/* Line 41: Compute header length from the IHL field */
static inline size_t ipv4_len(const void *viph)
{
    return ((struct iphdr *)viph)->ihl * 4;
}

/* Line 51: Return the next protocol number, handling fragments */
static inline int ipv4_proto(const void *viph)
{
    const struct iphdr *iph = viph;

    if (ip_is_fragment(iph) && (iph->frag_off & htons(IP_OFFSET))) {
        /* Stop at a non-first fragment */
        return XDP2_STOP_OKAY;
    }

    return iph->protocol;
}

/* Line 75: Wrapper for the ops.len signature */
static inline ssize_t ipv4_length(const void *viph, size_t maxlen)
{
    return ipv4_len(viph);
}

/* Line 100: The protocol definition */
static const struct xdp2_proto_def xdp2_parse_ipv4 = {
    .name = "IPv4",
    .min_len = sizeof(struct iphdr),         /* 20 bytes */
    .ops.len = ipv4_length,
    .ops.next_proto = ipv4_proto,
};
```

Key points:
- `ops.len` is set because IPv4 headers vary from 20 to 60 bytes (IHL field)
- `ipv4_proto` returns `XDP2_STOP_OKAY` for non-first fragments (a negative
  value), which tells the parse engine to stop successfully
- `min_len` is 20 bytes (`sizeof(struct iphdr)`); the engine checks that the
  returned length is >= `min_len`

## 1.4 Overlays: IP Version Checking

The same file also defines an **overlay** variant
([proto_ipv4.h:126--132](../src/include/xdp2/proto_defs/ip/proto_ipv4.h)):

```c
static const struct xdp2_proto_def xdp2_parse_ipv4_check = {
    .name = "IPv4-check",
    .min_len = sizeof(struct iphdr),
    .ops.len = ipv4_length_check,      /* Returns error if version != 4 */
    .ops.next_proto = ipv4_proto,
    .overlay = 1,                      /* Does NOT consume header bytes */
};
```

When `overlay = 1`, the parse engine does **not** advance the packet pointer
past the header. This allows an "IP version check" node to inspect the version
field and dispatch to IPv4 or IPv6, each of which will re-read the same header
bytes with their own parsing logic.

## 1.5 The `encap` Flag

When `encap = 1`, the protocol is an encapsulation protocol (e.g., GRE, IPIP,
VXLAN). This triggers special behavior in the parse engine:

1. The encapsulation counter is incremented
2. A new metadata frame is allocated (if available)
3. The `atencap_node` callback is invoked (if configured)

This allows the parser to track multiple layers of encapsulated headers with
separate metadata for each layer.

## 1.6 The Protocol Definitions Library

XDP2 ships with 100+ protocol definitions organized by category in
[src/include/xdp2/proto_defs/](../src/include/xdp2/proto_defs/):

| Category | Examples | Directory |
|---|---|---|
| Ethernet | Ethernet, VLAN, PBB | `ethernet/` |
| IP | IPv4, IPv6, IPv6 extension headers | `ip/` |
| Transport | TCP, UDP, SCTP | `transport/` |
| Tunneling | GRE, VXLAN, MPLS, Geneve | `tunnel/` |
| Security | ESP, AH, TLS | `security/` |
| Management | BGP, DNS, HTTP, MQTT | `management/` |
| Storage | NVMe-oF, iSCSI | `storage/` |
| Wireless | 802.11, Zigbee | `wireless/` |
| Bluetooth | HCI, L2CAP | `bluetooth/` |
| InfiniBand | IB headers | `infiniband/` |
| CAN | CAN bus | `can/` |
| Legacy | IPX, Appletalk | `legacy/` |

All protocol definitions follow the same pattern: a set of static inline
helper functions and one or more `static const struct xdp2_proto_def`
instances.

## 1.7 Exercise

Design a protocol definition for a hypothetical protocol with:
- A 4-byte fixed header
- A 1-byte "type" field at offset 0 that indicates the next protocol
- No variable-length options

What fields in `struct xdp2_proto_def` would you set? What would the
`next_proto` function look like?

---

[< Lecture 0: Orientation and Motivation](lecture00-xdp2-overview.md) | [Table of Contents](README.md) | [Lecture 2: Parse Nodes, Protocol Tables, and Parsers -- Building the Graph >](lecture02-parse-graph.md)
