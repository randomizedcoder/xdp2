# Adding Protocol Support to xdp2-rs

This document describes the process for adding new protocol/packet type support
to the xdp2-rs benchmark parser. It covers all four parser variants (graph,
mono, compiled, SIMD/template) and the corresponding protocol Ops definitions.

## Architecture Overview

Protocol support in xdp2-rs spans four layers:

```
┌──────────────────────────────────────────────────────────────────┐
│  xdp2-protocols   Protocol Ops traits (header struct + parsing) │
├──────────────────────────────────────────────────────────────────┤
│  xdp2-core         Engine, ParseNode, ProtoTable, callbacks     │
├──────────────────────────────────────────────────────────────────┤
│  xdp2-bench         Concrete parse graphs (graph, mono, compiled)│
├──────────────────────────────────────────────────────────────────┤
│  xdp2-compiler      IR → generated Rust parser (graph_compiled)  │
└──────────────────────────────────────────────────────────────────┘
```

Each protocol requires changes at multiple layers. The steps are ordered by
dependency — later steps depend on earlier ones.

---

## Step 1: Define Protocol Ops (`xdp2-protocols`)

Create a file in the appropriate category under `crates/xdp2-protocols/src/`:

| Category | Protocols |
|----------|-----------|
| `ethernet/` | Ethernet, VLAN, QinQ, PBB, LLDP, etc. |
| `ip/` | IPv4, IPv6, IPv6 EH, ARP, ICMP |
| `transport/` | TCP, UDP, SCTP, DCCP |
| `tunnel/` | GRE, VXLAN, Geneve, IP-in-IP, MPLS |
| `security/` | AH, ESP |

### 1a. Header Struct

Use `zerocopy` for zero-copy header parsing:

```rust
use zerocopy::{FromBytes, Immutable, KnownLayout, NetworkEndian, U16};

#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct MyProtoHeader {
    pub field_a: U16<NetworkEndian>,  // network-byte-order u16
    pub field_b: u8,                  // single byte (no endian concern)
    pub field_c: [u8; 4],             // raw bytes
}

impl MyProtoHeader {
    pub fn some_accessor(&self) -> u16 {
        self.field_a.get()  // returns host-order u16
    }
}
```

Key conventions:
- `#[repr(C, packed)]` — matches wire layout exactly
- `U16<NetworkEndian>` / `U32<NetworkEndian>` — multi-byte network-order fields
- Single bytes use plain `u8`
- Raw byte arrays `[u8; N]` for opaque fields (MACs, IPs)

### 1b. ProtocolOps Implementation

Implement the `ProtocolOps` trait from `xdp2-core`:

```rust
use xdp2_core::{ParseError, ProtocolOps};

pub struct MyProtoOps;

impl ProtocolOps for MyProtoOps {
    const MIN_LEN: usize = 8;           // minimum header size in bytes
    const NAME: &'static str = "MyProto";

    // Optional overrides (defaults shown):
    // const NODE_TYPE: NodeType = NodeType::Plain;
    // const ENCAP: bool = false;
    // const OVERLAY: bool = false;

    // Override for variable-length headers:
    // fn header_len(&self, hdr: &[u8], _maxlen: usize) -> Result<usize, ParseError> {
    //     Ok(Self::MIN_LEN)  // default: fixed-length
    // }

    fn next_proto(&self, hdr: &[u8]) -> Result<i32, ParseError> {
        // Leaf node — no next protocol:
        Err(ParseError::UnknownProto)

        // Or: intermediate node — return next protocol number:
        // Ok(hdr[6] as i32)
    }
}
```

### Protocol Node Types

| Node Type | `next_proto()` returns | `proto_table` | Special Constants |
|-----------|----------------------|---------------|-------------------|
| **Leaf** (TCP, ARP) | `Err(UnknownProto)` | `None` | — |
| **Intermediate** (IPv4, Ethernet) | `Ok(proto_number)` | `Some(&TABLE)` | — |
| **Overlay** (IP version check) | `Ok(proto_number)` | `Some(&TABLE)` | `OVERLAY = true` |
| **Encapsulation** (VXLAN, GRE) | `Ok(inner_ethertype)` | `Some(&TABLE)` | `ENCAP = true` |
| **Flag-fields** (GRE v0) | `Ok(inner_proto)` | `Some(&TABLE)` | `NODE_TYPE = FlagFields`, `ENCAP = true` |

### Variable-Length Headers

Override `header_len()` when the header size depends on packet content:

```rust
// IPv4: IHL field (lower nibble of byte 0) * 4
fn header_len(&self, hdr: &[u8], _maxlen: usize) -> Result<usize, ParseError> {
    let ihl = (hdr[0] & 0x0F) as usize * 4;
    if ihl < Self::MIN_LEN { return Err(ParseError::Length); }
    Ok(ihl)
}

// TCP: data offset field (upper nibble of byte 12) * 4
fn header_len(&self, hdr: &[u8], _maxlen: usize) -> Result<usize, ParseError> {
    let tcp = TcpHeader::ref_from_prefix(hdr).map_err(|_| ParseError::Length)?.0;
    Ok(tcp.data_offset_bytes())
}

// IPv6 Extension Header: (pkt[1] * 8) + 8
fn header_len(&self, hdr: &[u8], _maxlen: usize) -> Result<usize, ParseError> {
    let len = hdr[1] as usize * 8 + 8;
    Ok(len)
}
```

### 1c. Export from Module

Add to the category's `mod.rs`:

```rust
pub mod my_proto;
```

### 1d. Tests

Every protocol Ops should have tests for:
- `header_len()` with valid and edge-case inputs
- `next_proto()` with valid protocol values
- Leaf behavior (returns `Err(UnknownProto)`)
- Header struct field accessors

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn my_proto_standard_header() {
        let hdr = [0u8; 8];
        let ops = MyProtoOps;
        assert_eq!(ops.header_len(&hdr, 100).unwrap(), 8);
    }

    #[test]
    fn my_proto_is_leaf() {
        let ops = MyProtoOps;
        assert!(ops.next_proto(&[0u8; 8]).is_err());
    }
}
```

---

## Step 2: Wire into Graph (`xdp2-bench/src/graph.rs`)

### 2a. Import the Ops Type

```rust
use xdp2_protocols::tunnel::my_proto::MyProtoOps;
```

### 2b. Create ParseNode

For a **leaf** node:

```rust
static MY_PROTO_NODE: ParseNode<FlowMeta, MyProtoOps> = ParseNode {
    proto: MyProtoOps,
    ops: ParseNodeOps { extract_metadata: None, handler: None, post_handler: None },
    proto_table: None,        // leaf — no dispatch table
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "my-proto",
};
```

For an **intermediate** node (dispatches to children):

```rust
// First define the child dispatch table
static MY_PROTO_TABLE: ProtoTable<FlowMeta> = proto_table![
    (6, &TCP_NODE),       // IPPROTO_TCP
    (17, &UDP_NODE),      // IPPROTO_UDP
];

// Then the node itself
static MY_PROTO_NODE: ParseNode<FlowMeta, MyProtoOps> = ParseNode {
    proto: MyProtoOps,
    ops: ParseNodeOps { extract_metadata: None, handler: None, post_handler: None },
    proto_table: Some(&MY_PROTO_TABLE),
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "my-proto",
};
```

### 2c. Add to Parent's ProtoTable

Add an entry mapping the protocol number to your node in the parent's table:

```rust
// Example: adding to ETHER_TABLE (EtherType dispatch)
static ETHER_TABLE: ProtoTable<FlowMeta> = proto_table![
    (0x0800, &IPV4_NODE),
    (0x86DD, &IPV6_NODE),
    (0x8100, &VLAN_NODE),
    (0x88A8, &QINQ_NODE),
    (0x0806, &ARP_NODE),
    (0x8847, &MY_PROTO_NODE),  // new entry
];

// Example: adding to IPV4_TABLE (IP protocol number dispatch)
static IPV4_TABLE: ProtoTable<FlowMeta> = proto_table![
    (6, &TCP_NODE),
    (17, &UDP_NODE),
    // ...
    (47, &GRE_BASE_NODE),  // new entry
];
```

**Important**: Protocol table keys are host-order integers matching what
`next_proto()` returns. Ethertypes are literal hex values (0x0800, not
big-endian). IP protocol numbers are plain integers (6, 17, 47).

### 2d. Metadata Extraction (Optional)

When `FlowMeta` extraction is needed, define an extractor function:

```rust
fn extract_my_proto_metadata(
    hdr: &[u8],
    hdr_len: usize,
    meta: &mut FlowMeta,
    _ctrl: &CtrlData,
) {
    // Populate metadata fields from header bytes
    meta.some_field = hdr[4];
}
```

Then wire it into the node:

```rust
ops: ParseNodeOps {
    extract_metadata: Some(extract_my_proto_metadata),
    handler: None,
    post_handler: None,
},
```

### 2e. Graph Tests

```rust
#[test]
fn parse_eth_my_proto() {
    let parser = make_parser();
    let mut pkt = Vec::new();
    pkt.extend_from_slice(&[0u8; 12]);               // MACs
    pkt.extend_from_slice(&0x8847u16.to_be_bytes());  // EtherType
    pkt.extend_from_slice(&[0u8; 8]);                 // Protocol header
    let result = parse_packet(&parser, &pkt).unwrap();
    assert_eq!(result.result, ParseResult::Okay);
}
```

---

## Step 3: Update Monomorphized Parser (`graph_mono.rs`)

The mono parser replicates the graph topology using direct function calls and
`match` dispatch instead of `&dyn` trait objects and `ProtoTable` lookups.

### 3a. Add Parse Function

For a **leaf** node:

```rust
fn parse_my_proto(pkt: &[u8]) -> Result<(), ParseError> {
    parse_leaf(&MyProtoOps, pkt)
}
```

For an **intermediate** node:

```rust
fn parse_my_proto(pkt: &[u8]) -> Result<(), ParseError> {
    let proto = MyProtoOps;
    let hlen = hdr_len(&proto, pkt)?;
    let next = match next_or_stop(proto.next_proto(&pkt[..hlen]))? {
        Some(p) => p,
        None => return Ok(()),
    };
    let rest = &pkt[hlen..];
    match next {
        6 => parse_leaf(&TcpOps, rest),
        17 => parse_leaf(&UdpOps, rest),
        _ => Err(ParseError::UnknownProto),
    }
}
```

### 3b. Add to Parent's `match` Arms

The mono parser uses a shared `dispatch_ether()` function so all Ethernet-level
dispatch points (parse_eth, parse_vlan, parse_qinq, and chainable L2 nodes) share
the same match arms:

```rust
fn dispatch_ether(next: i32, rest: &[u8], depth: u32) -> Result<(), ParseError> {
    match next {
        // existing arms...
        0x8847 => parse_my_proto(rest),  // new arm
        _ => Err(ParseError::UnknownProto),
    }
}
```

Similarly, `dispatch_ipv4()` centralizes IPv4 protocol dispatch.

### 3c. Recursion Depth

If the node can appear in cycles (e.g., VLAN re-dispatching to Ethernet),
add a depth parameter:

```rust
fn parse_my_proto(pkt: &[u8], depth: u32) -> Result<(), ParseError> {
    if depth >= MAX_ETH_DEPTH {
        return Err(ParseError::MaxNodes);
    }
    // ...
}
```

The mono parser does NOT call metadata extractors — it benchmarks pure parse
speed only.

---

## Step 4: Update Compiled Parser (`graph_compiled.rs`)

The compiled parser inlines all protocol operations as literal byte reads — no
ProtocolOps calls, no vtable dispatch. Currently it is **hand-maintained** to
match the graph topology. When xdp2-compiler matures, it will be auto-generated
from JSON IR.

**Adding a leaf protocol:**

```rust
// In dispatch_ether():
0x8847 => leaf(rest, 8),  // MY_PROTO: MIN_LEN=8
```

**Adding an intermediate protocol** — inline header_len and next_proto reads:

```rust
fn parse_my_proto(pkt: &[u8]) -> Result<(), ParseError> {
    if pkt.len() < 8 { return Err(ParseError::Length); }
    let next = pkt[4] as i64;  // next protocol field
    let rest = &pkt[8..];
    match next {
        6 => leaf(rest, 20),  // TCP
        _ => Err(ParseError::UnknownProto),
    }
}
```

For reference, here is the xdp2-compiler IR format (for future use):

### 4a. Leaf Node

```json
{
  "name": "my_proto",
  "min-hdr-length": 8
}
```

### 4b. Intermediate Node

```json
{
  "name": "my_proto",
  "min-hdr-length": 8,
  "next-proto": {
    "field-off": 4,
    "field-len": 1,
    "ents": [
      {"key": 6, "node": "tcp"},
      {"key": 17, "node": "udp"}
    ]
  }
}
```

### 4c. Variable-Length Header

```json
{
  "name": "my_proto",
  "min-hdr-length": 8,
  "hdr-length": {
    "field-off": 0,
    "field-len": 1,
    "mask": "0xf",
    "multiplier": 4
  },
  "next-proto": { ... }
}
```

The `hdr-length` formula is: `(read_field & mask >> shift) * multiplier + add`

### 4d. Encapsulation Node

```json
{
  "name": "vxlan",
  "min-hdr-length": 8,
  "encap": true,
  "next-proto": {
    "field-off": 0,
    "field-len": 1,
    "ents": [
      {"key": "0x6558", "node": "ethernet_inner"}
    ]
  }
}
```

### 4e. Add to Parent's Dispatch Entries

```json
{
  "name": "ethernet",
  "min-hdr-length": 14,
  "next-proto": {
    "field-off": 12,
    "field-len": 2,
    "ents": [
      {"key": "0x0800", "node": "ipv4"},
      {"key": "0x8847", "node": "my_proto"}
    ]
  }
}
```

### 4f. Regenerate `graph_compiled.rs`

```bash
nix develop --command cargo run -p xdp2-compiler -- \
  --input crates/xdp2-compiler/testdata/bench-graph.json \
  --format rust \
  > crates/xdp2-bench/src/graph_compiled.rs
```

---

## Step 5: Assess SIMD and Template Variants

### SIMD Batch Parser (`simd_batch.rs`)

The AVX2 batch parser only accelerates the fast path:
`Ethernet(14B) → IPv4(IHL=5, 20B) → TCP/UDP/ICMP leaf`

All other packets fall back to the scalar compiled parser. New protocols
generally require no changes here unless:

- You're adding a new fast-path variant (e.g., IPv6 SIMD path)
- You're changing the scalar fallback function

### Template Extraction (`template.rs`)

Template extraction uses compile-time-constant offsets for NIC-classified
packets. Add new template IDs and extractors only when:

- A new NIC classification queue exists (e.g., Eth/IPv6/UDP)
- All header offsets are known at compile time (no variable IHL, no options)

```rust
pub const ETH_IPV4_UDP: PacketTemplate = PacketTemplate {
    name: "eth_ipv4_udp",
    min_length: 42,
    fields: &[
        FieldDef { name: "dst_mac", offset: 0, length: 6 },
        // ...
    ],
};
```

---

## Step 6: Verify

Run after each step to catch regressions:

```bash
# Unit tests (all crates)
nix develop --command cargo test

# Release build (catches optimization-only issues)
nix develop --command cargo build --release -p xdp2-bench

# Benchmark smoke test
nix develop --command cargo run --release -p xdp2-bench -- \
  --pcap test.pcap --mode both

# graph and mono success counts should match
```

After all steps:

```bash
# Full C vs Rust comparison benchmark
nix build .#parser-benchmark
./result/bin/xdp2-parser-benchmark 100 500000
```

---

## Quick Reference: The Engine's Per-Node Processing Order

The parse engine (`xdp2-core/src/engine.rs`) executes this sequence at each
node in the graph:

```
1. Length check      — remaining >= MIN_LEN
2. header_len()      — compute actual header size
3. Validate          — hdr_len >= MIN_LEN && hdr_len <= remaining
4. extract_metadata  — optional callback: populate FlowMeta
5. handler           — optional callback: arbitrary processing
6. sub_parse         — TLVs / flag-fields / arrays (if NODE_TYPE != Plain)
7. post_handler      — optional callback: post-processing
8. proto_table check — None means leaf → stop
9. next_proto()      — get next protocol number
10. Table lookup     — find next ParseNode in ProtoTable
11. Encap check      — increment counter if ENCAP, check max_encaps
12. Advance offset   — skip for OVERLAY nodes
13. Node count check — decrement, fail if exceeded
14. Loop             — continue to next node
```

---

## Common Patterns

### Chaining Back to a Parent Table

Protocols like AH (Authentication Header) or IPv6 Extension Headers chain
back to their parent's dispatch table:

```rust
// AH after IPv4 dispatches back into the IPv4 table
static AH_V4_NODE: ParseNode<FlowMeta, AhOps> = ParseNode {
    proto: AhOps,
    proto_table: Some(&IPV4_TABLE),  // chains back to IPv4 dispatch
    name: "ah-v4",
    // ...
};

// Same AhOps, different table for IPv6 context
static AH_V6_NODE: ParseNode<FlowMeta, AhOps> = ParseNode {
    proto: AhOps,
    proto_table: Some(&IPV6_TABLE),  // chains back to IPv6 dispatch
    name: "ah-v6",
    // ...
};
```

### UDP Dport Dispatch (Tunnel Detection)

To dispatch UDP packets to tunnels by destination port, create a separate
Ops type that returns the dport instead of `Err(UnknownProto)`:

```rust
pub struct UdpDportOps;

impl ProtocolOps for UdpDportOps {
    const MIN_LEN: usize = 8;
    const NAME: &'static str = "UDP-dport";

    fn next_proto(&self, hdr: &[u8]) -> Result<i32, ParseError> {
        Ok(u16::from_be_bytes([hdr[2], hdr[3]]) as i32)
    }
}
```

Wire with a tunnel dispatch table and a **wildcard stop-leaf** so non-tunnel
UDP packets succeed instead of failing with UnknownProto:

```rust
static UDP_TUNNEL_TABLE: ProtoTable<FlowMeta> = proto_table![
    (4789, &VXLAN_NODE),   // VXLAN
    (6081, &GENEVE_NODE),  // Geneve
];

static UDP_NODE: ParseNode<FlowMeta, UdpDportOps> = ParseNode {
    proto: UdpDportOps,
    proto_table: Some(&UDP_TUNNEL_TABLE),
    wildcard_node: Some(&STOP_LEAF_NODE),  // non-tunnel dport → parse OK
    unknown_ret: ParseError::UnknownProto,
    name: "udp",
    // ...
};
```

### StopLeafOps (Wildcard Fallback)

When a table lookup misses but the parse should still succeed (e.g., UDP
with a non-tunnel dport), use a `StopLeafOps` wildcard node:

```rust
struct StopLeafOps;
impl ProtocolOps for StopLeafOps {
    const MIN_LEN: usize = 0;  // consumes no bytes
    const NAME: &'static str = "stop-leaf";
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}
```

### IP-in-IP Tunneling

For IP-in-IP (protocols 4/41), route directly to `IP_CHECK_NODE` which
reads the version nibble and dispatches to IPv4/IPv6. Do **not** use
`IpInIpOps` — it reads the inner IP protocol field, not the version nibble,
causing misrouted dispatch:

```rust
static IPV4_TABLE: ProtoTable<FlowMeta> = proto_table![
    (4, &IP_CHECK_NODE),    // IPPROTO_IPIP → version dispatch
    (41, &IP_CHECK_NODE),   // IPPROTO_IPV6 → version dispatch
    // ...
];
```

### Reusing Existing Ops vs Local Ops

- Use protocol Ops from `xdp2-protocols` when they match the C implementation
  behavior exactly
- Define local Ops types in `graph.rs` when the benchmark needs different
  behavior (e.g., `UdpDportOps` vs the leaf `UdpOps`)

---

## C Cross-Reference

The C flow_dissector uses equivalent macros in `samples/flow_dissector/`:

| Rust | C | File |
|------|---|------|
| `ParseNode { ... }` | `XDP2_MAKE_PARSE_NODE(...)` | `flow_dissector_nodes.h` |
| `proto_table![...]` | `XDP2_MAKE_PROTO_TABLE(...)` | `flow_dissector_tables.h` |
| `extract_metadata: Some(fn)` | `.ops.extract_metadata = fn` | `flow_dissector_metadata.h` |
| `ParseNode { NODE_TYPE: FlagFields }` | `XDP2_MAKE_FLAG_FIELDS_PARSE_NODE(...)` | `flow_dissector_nodes.h` |
| `ProtocolOps` trait | `struct xdp2_parse_ops` + `struct xdp2_proto_def` | `parser_types.h` |

---

## Checklist

Copy and fill in for each new protocol:

```
Protocol: ___________
Category: ___________  (ethernet/ip/transport/tunnel/security)
Node type: __________  (leaf/intermediate/overlay/encap/flag-fields)

[ ] Step 1: Protocol Ops in xdp2-protocols
    [ ] Header struct (zerocopy)
    [ ] ProtocolOps impl (MIN_LEN, NAME, header_len, next_proto)
    [ ] Module export (mod.rs)
    [ ] Unit tests

[ ] Step 2: Graph wiring in graph.rs
    [ ] Import Ops type
    [ ] Static ParseNode
    [ ] ProtoTable entry in parent
    [ ] Graph integration test

[ ] Step 3: Monomorphized parser in graph_mono.rs
    [ ] parse_*() function
    [ ] Match arm in parent dispatch
    [ ] Depth parameter if cyclic

[ ] Step 4: Compiler IR in bench-graph.json
    [ ] Node definition
    [ ] Dispatch entry in parent
    [ ] Regenerate graph_compiled.rs

[ ] Step 5: SIMD/template assessment
    [ ] simd_batch.rs — changes needed? (usually no)
    [ ] template.rs — new template ID needed?

[ ] Step 6: Verify
    [ ] cargo test passes
    [ ] cargo build --release -p xdp2-bench succeeds
    [ ] graph and mono success counts match on test PCAP
```
