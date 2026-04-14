# XDP2 Rust Reimplementation: Detailed Implementation Plan

## 1. Overview

### 1.1 Goals

- Reimplement XDP2's parse graph engine in safe Rust
- Maintain behavioral compatibility with the C implementation (verified via golden tests)
- Provide a clean, idiomatic Rust API while preserving the parse graph abstraction
- Integrate as a first-class Nix citizen with build, test, lint, format, doc, and golden targets

### 1.2 Non-Goals (this phase)

- eBPF/XDP runtime (Phase 4+)
- Full 205 protocol coverage immediately (incremental)
- Performance parity benchmarking (Phase 3) — **done** as of 2026-04-14

### 1.3 Architecture

Cargo workspace with 3 crates:

```
xdp2-rs/
  Cargo.toml              # workspace root
  crates/
    xdp2-core/             # Parse engine: types, traits, main loop, TLV/flag-fields/arrays
    xdp2-protocols/        # Protocol definitions: Ethernet, IPv4, IPv6, TCP, UDP, ...
    xdp2-compiler/         # Optimizing compiler (Phase 4, stub initially)
```

### 1.4 Recommended Crates

| Crate | Purpose | Replaces |
|-------|---------|----------|
| zerocopy 0.8 | Zero-copy packet header parsing | Direct struct casts via `void*` |
| bitflags 2 | Protocol flag handling | Manual bitmask operations |
| proptest 1 | Property-based testing | - |
| insta 1 | Golden/snapshot testing | Manual diff comparison |
| petgraph 0.6 | Graph algorithms (Phase 4) | Boost Graph Library |
| tera 1 | Template code generation (Phase 4) | Custom pyrex templates |
| serde + serde_json | JSON IR (Phase 4) | Custom JSON |
| clap 4 | CLI (Phase 4) | getopt |


## 2. C-to-Rust Mapping Reference

All C source paths are relative to the repository root.

### 2.1 Core Structs

| C Struct | C Source (file:lines) | Rust Type | Rust File |
|----------|----------------------|-----------|-----------|
| `struct xdp2_parse_ops` | `src/include/xdp2/parser_types.h:133-137` | `trait ProtocolOps` | `proto_def.rs` |
| `struct xdp2_proto_def` | `src/include/xdp2/parser_types.h:153-160` | `struct ProtoDef<P: ProtocolOps>` | `proto_def.rs` |
| `struct xdp2_parse_node_ops` | `src/include/xdp2/parser_types.h:221-229` | `struct ParseNodeOps<M>` (fn pointers) | `parse_node.rs` |
| `struct xdp2_parse_node` | `src/include/xdp2/parser_types.h:270-281` | `struct ParseNode<M>` | `parse_node.rs` |
| `struct xdp2_proto_table_entry` | `src/include/xdp2/parser_types.h:244-247` | `struct ProtoTableEntry<M>` | `proto_table.rs` |
| `struct xdp2_proto_table` | `src/include/xdp2/parser_types.h:254-257` | `struct ProtoTable<M>` | `proto_table.rs` |
| `struct xdp2_parser_config` | `src/include/xdp2/parser_types.h:301-312` | `struct ParserConfig<M>` | `parser.rs` |
| `struct xdp2_parser` | `src/include/xdp2/parser_types.h:320-327` | `struct Parser<M>` | `parser.rs` |
| `struct xdp2_ctrl_data` | `src/include/xdp2/parser_types.h:202-206` | `struct CtrlData` | `types.rs` |
| `struct xdp2_ctrl_var_data` | `src/include/xdp2/parser_types.h:186-194` | `struct CtrlVarData` | `types.rs` |
| `struct xdp2_ctrl_packet_data` | `src/include/xdp2/parser_types.h:174-184` | `struct CtrlPacketData` | `types.rs` |
| `struct xdp2_ctrl_key_data` | `src/include/xdp2/parser_types.h:196-200` | `struct CtrlKeyData` | `types.rs` |
| `struct xdp2_proto_tlvs_opts` | `src/include/xdp2/tlvs.h:64-68` | `struct TlvOps` | `tlvs.rs` |
| `struct xdp2_parse_tlv_node_ops` | `src/include/xdp2/tlvs.h:83-89` | `struct ParseTlvNodeOps<M>` | `tlvs.rs` |
| `struct xdp2_parse_tlv_node` | `src/include/xdp2/tlvs.h:94-102` | `struct ParseTlvNode<M>` | `tlvs.rs` |
| `struct xdp2_proto_tlvs_table_entry` | `src/include/xdp2/tlvs.h:108-111` | `struct TlvTableEntry<M>` | `tlvs.rs` |
| `struct xdp2_proto_tlvs_table` | `src/include/xdp2/tlvs.h:117-120` | `struct TlvTable<M>` | `tlvs.rs` |
| `struct xdp2_parse_tlvs_node` | `src/include/xdp2/tlvs.h:136-143` | `struct ParseTlvsNode<M>` | `tlvs.rs` |
| `struct xdp2_proto_tlvs_def` | `src/include/xdp2/tlvs.h:158-166` | `struct ProtoTlvsDef` | `tlvs.rs` |
| `struct xdp2_proto_tlv_def` | `src/include/xdp2/tlvs.h:184-187` | `struct ProtoTlvDef` | `tlvs.rs` |
| `struct xdp2_flag_field` | `src/include/xdp2/flag_fields.h:64-68` | `struct FlagField` | `flag_fields.rs` |
| `struct xdp2_flag_fields` | `src/include/xdp2/flag_fields.h:78-81` | `struct FlagFields` | `flag_fields.rs` |
| `struct xdp2_proto_flag_fields_ops` | `src/include/xdp2/flag_fields.h:162-165` | `struct FlagFieldsOps` | `flag_fields.rs` |
| `struct xdp2_parse_flag_field_node_ops` | `src/include/xdp2/flag_fields.h:180-186` | `struct ParseFlagFieldNodeOps<M>` | `flag_fields.rs` |
| `struct xdp2_parse_flag_field_node` | `src/include/xdp2/flag_fields.h:189-192` | `struct ParseFlagFieldNode<M>` | `flag_fields.rs` |
| `struct xdp2_proto_flag_fields_table_entry` | `src/include/xdp2/flag_fields.h:198-201` | `struct FlagFieldsTableEntry<M>` | `flag_fields.rs` |
| `struct xdp2_proto_flag_fields_table` | `src/include/xdp2/flag_fields.h:209-212` | `struct FlagFieldsTable<M>` | `flag_fields.rs` |
| `struct xdp2_parse_flag_fields_node` | `src/include/xdp2/flag_fields.h:217-220` | `struct ParseFlagFieldsNode<M>` | `flag_fields.rs` |
| `struct xdp2_proto_flag_fields_def` | `src/include/xdp2/flag_fields.h:225-229` | `struct ProtoFlagFieldsDef` | `flag_fields.rs` |
| `struct xdp2_proto_array_opts` | `src/include/xdp2/arrays.h:59-63` | `struct ArrayOps` | `arrays.rs` |
| `struct xdp2_parse_arrel_node_ops` | `src/include/xdp2/arrays.h:78-84` | `struct ParseArrayElNodeOps<M>` | `arrays.rs` |
| `struct xdp2_parse_arrel_node` | `src/include/xdp2/arrays.h:89-92` | `struct ParseArrayElNode<M>` | `arrays.rs` |
| `struct xdp2_proto_array_table_entry` | `src/include/xdp2/arrays.h:98-101` | `struct ArrayTableEntry<M>` | `arrays.rs` |
| `struct xdp2_proto_array_table` | `src/include/xdp2/arrays.h:108-111` | `struct ArrayTable<M>` | `arrays.rs` |
| `struct xdp2_parse_array_node` | `src/include/xdp2/arrays.h:126-132` | `struct ParseArrayNode<M>` | `arrays.rs` |
| `struct xdp2_proto_array_def` | `src/include/xdp2/arrays.h:140-144` | `struct ProtoArrayDef` | `arrays.rs` |

### 2.2 Function Pointers to Traits

C pattern (`src/include/xdp2/parser_types.h:133-137`):

```c
struct xdp2_parse_ops {
    ssize_t (*len)(const void *hdr, size_t maxlen);
    int (*next_proto)(const void *hdr);
    int (*next_proto_keyin)(const void *hdr, __u32 key);
};
```

Rust equivalent:

```rust
pub trait ProtocolOps: Send + Sync {
    const MIN_LEN: usize;
    const NAME: &'static str;
    const NODE_TYPE: NodeType = NodeType::Plain;
    const ENCAP: bool = false;
    const OVERLAY: bool = false;

    fn header_len(&self, hdr: &[u8], maxlen: usize) -> Result<usize, ParseError> {
        Ok(Self::MIN_LEN)
    }

    fn next_proto(&self, hdr: &[u8]) -> Result<i32, ParseError>;

    fn next_proto_keyin(&self, hdr: &[u8], key: u32) -> Result<i32, ParseError> {
        self.next_proto(hdr)
    }
}
```

Key differences from C:

- `const void *hdr` becomes `&[u8]` (bounds-checked slice)
- NULL function pointer becomes trait method with default impl
- Negative return codes become `Result<T, ParseError>`
- Static fields (`min_len`, `name`, `encap`, `overlay`) become associated constants
- The separate `xdp2_proto_def` struct and `xdp2_parse_ops` are unified into one trait

### 2.3 void* Metadata to Generic `M`

C uses `void *metadata` and `void *frame` everywhere. Rust parameterizes:

```rust
pub struct Parser<M: Default> {
    pub name: &'static str,
    pub config: ParserConfig<M>,
    pub root_node: &'static ParseNode<M>,
}
```

The metadata type is defined by the user (e.g., `FlowTrackerMetadata`) and must implement `Default`.

### 2.4 Return Codes to Enums

C (`src/include/xdp2/parser_types.h:59-95`):

```c
enum { XDP2_OKAY = 0, XDP2_STOP_OKAY = -4, XDP2_STOP_LENGTH = -13, ... };
```

Rust:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum ParseResult {
    Okay = 0,
    RetOkay = -1,
    UseWild = -2,
    UseAltWild = -3,
    StopOkay = -4,
    StopNodeOkay = -5,
    StopSubNodeOkay = -6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    Fail,              // XDP2_STOP_FAIL = -12
    Length,            // XDP2_STOP_LENGTH = -13
    UnknownProto,      // XDP2_STOP_UNKNOWN_PROTO = -14
    EncapDepth,        // XDP2_STOP_ENCAP_DEPTH = -15
    UnknownTlv,        // XDP2_STOP_UNKNOWN_TLV = -16
    TlvLength,         // XDP2_STOP_TLV_LENGTH = -17
    BadFlag,           // XDP2_STOP_BAD_FLAG = -18
    FailCmp,           // XDP2_STOP_FAIL_CMP = -19
    LoopCnt,           // XDP2_STOP_LOOP_CNT = -20
    TlvPadding,        // XDP2_STOP_TLV_PADDING = -21
    OptionLimit,       // XDP2_STOP_OPTION_LIMIT = -22
    MaxNodes,          // XDP2_STOP_MAX_NODES = -23
    Compare,           // XDP2_STOP_COMPARE = -24
    BadExtract,        // XDP2_STOP_BAD_EXTRACT = -25
    BadCntr,           // XDP2_STOP_BAD_CNTR = -26
    Cntr1,             // XDP2_STOP_CNTR1 = -27
    Cntr2,             // XDP2_STOP_CNTR2 = -28
    Cntr3,             // XDP2_STOP_CNTR3 = -29
    Cntr4,             // XDP2_STOP_CNTR4 = -30
    Cntr5,             // XDP2_STOP_CNTR5 = -31
    Cntr6,             // XDP2_STOP_CNTR6 = -32
    Cntr7,             // XDP2_STOP_CNTR7 = -33
    ThreadsFail,       // XDP2_STOP_THREADS_FAIL = -34
}
```

Both enums provide `From<i32>` and `Into<i32>` for C interop.

### 2.5 Macro API to Builder/macro_rules!

| C Macro | C Source | Rust Equivalent |
|---------|---------|-----------------|
| `XDP2_MAKE_PROTO_TABLE(NAME, ...)` | `src/include/xdp2/parser.h:198-205` | `proto_table![]` macro |
| `XDP2_MAKE_PARSE_NODE(NAME, ...)` | `src/include/xdp2/parser.h:234-242` | `ParseNode::new()` const fn or builder |
| `XDP2_MAKE_LEAF_PARSE_NODE(NAME, ...)` | `src/include/xdp2/parser.h:256-261` | `ParseNode::leaf()` const fn |
| `XDP2_PARSER(NAME, ...)` | `src/include/xdp2/parser.h:133-134` | `Parser::new()` const fn |
| `XDP2_MAKE_TLV_TABLE(NAME, ...)` | `src/include/xdp2/tlvs.h:221-228` | `tlv_table![]` macro |
| `XDP2_MAKE_TLVS_PARSE_NODE(...)` | `src/include/xdp2/tlvs.h:257-268` | `ParseTlvsNode::new()` const fn |
| `XDP2_MAKE_FLAG_FIELDS_TABLE(...)` | `src/include/xdp2/flag_fields.h:248-257` | `flag_fields_table![]` macro |
| `XDP2_MAKE_FLAG_FIELDS_PARSE_NODE(...)` | `src/include/xdp2/flag_fields.h:284-299` | `ParseFlagFieldsNode::new()` const fn |
| `XDP2_MAKE_ARRAY_TABLE(...)` | `src/include/xdp2/arrays.h:163-170` | `array_table![]` macro |
| `XDP2_MAKE_ARRAY_PARSE_NODE(...)` | `src/include/xdp2/arrays.h:213-219` | `ParseArrayNode::new()` const fn |

### 2.6 Endianness

| C | Rust |
|---|------|
| `ntohs(x)` / `htons(x)` | `u16::from_be(x)` / `x.to_be()` |
| `__be16` field in packed struct | `zerocopy::U16<NetworkEndian>` |
| Direct cast `*(struct iphdr *)hdr` | `Ipv4Header::ref_from_prefix(hdr)` via zerocopy |

### 2.7 Key Function Mappings

| C Function | C Source (file:lines) | Rust Function | Rust File |
|------------|----------------------|---------------|-----------|
| `lookup_node()` | `src/lib/xdp2/parser.c:38-48` | `ProtoTable::lookup()` | `proto_table.rs` |
| `lookup_tlv_node()` | `src/lib/xdp2/parser.c:51-61` | `TlvTable::lookup()` | `tlvs.rs` |
| `lookup_array_node()` | `src/lib/xdp2/parser.c:64-74` | `ArrayTable::lookup()` | `arrays.rs` |
| `lookup_flag_field_node()` | `src/lib/xdp2/parser.c:85-96` | `FlagFieldsTable::lookup()` | `flag_fields.rs` |
| `xdp2_parse_one_tlv()` | `src/lib/xdp2/parser.c:103-183` | `parse_one_tlv()` | `tlvs.rs` |
| `xdp2_parse_tlvs()` | `src/lib/xdp2/parser.c:185-296` | `parse_tlvs()` | `tlvs.rs` |
| `xdp2_parse_flag_fields()` | `src/lib/xdp2/parser.c:298-358` | `parse_flag_fields()` | `flag_fields.rs` |
| `xdp2_parse_array()` | `src/lib/xdp2/parser.c:360-448` | `parse_array()` | `arrays.rs` |
| `__xdp2_parse()` | `src/lib/xdp2/parser.c:461-701` | `parse()` | `engine.rs` |
| `__xdp2_parse_fast()` | `src/lib/xdp2/parser.c:703-814` | `parse_fast()` | `engine.rs` |
| `xdp2_parse_validate_fast()` | `src/lib/xdp2/parser.c:893-918` | `Parser::validate_fast()` | `parser.rs` |
| `__xdp2_parse_run_exit_node()` | `src/include/xdp2/parser.h:440-456` | `run_exit_node()` | `engine.rs` |
| `xdp2_flag_fields_offset()` | `src/include/xdp2/flag_fields.h:116-130` | `FlagFields::offset()` | `flag_fields.rs` |
| `xdp2_flag_fields_length()` | `src/include/xdp2/flag_fields.h:107-113` | `FlagFields::length()` | `flag_fields.rs` |
| `xdp2_flag_fields_check_invalid()` | `src/include/xdp2/flag_fields.h:133-136` | `FlagFields::check_invalid()` | `flag_fields.rs` |


## 3. Phase 1: xdp2-core

### 3.1 types.rs

C reference: `src/include/xdp2/parser_types.h:59-95` (return codes), `src/include/xdp2/parser_types.h:97-117` (type enums), `src/include/xdp2/parser_types.h:174-206` (ctrl data)

Contents:

- `ParseError` enum -- 22 error variants mapping to `XDP2_STOP_*` codes (-12 through -34)
- `ParseResult` enum -- `Okay`, `StopOkay`, `StopNodeOkay`, `UseWild`, `UseAltWild`
- `NodeType` enum -- `Plain`, `Tlvs`, `FlagFields`, `Array` (maps `xdp2_parser_node_type`)
- `ParserType` enum -- `Generic`, `Optimized`, `Xdp` (maps `xdp2_parser_type`)
- `CtrlVarData` struct -- `last_node`, `ret_code`, `encaps`, `node_cnt`, `tlv_levels`, `pkt_csum`, `hdr_csum`
- `CtrlPacketData` struct -- `pkt_len`, `seqno`, `timestamp`, `in_port`, `vrf_id`, `pkt_csum`, `flags`
- `CtrlKeyData` struct -- `counters: Vec<u8>`, `keys: Vec<u32>`, `arg` (generic or `Box<dyn Any>`)
- `CtrlData` struct -- aggregates `var`, `pkt`, `key`
- `impl From<i32> for ParseError` and `impl From<ParseError> for i32` for C interop

Key design note: C uses raw `void *packet` and `void *start` in `CtrlPacketData`. In Rust, these are removed because the parse function takes `&[u8]` directly. The `CtrlPacketData` retains only the non-pointer metadata fields.

### 3.2 proto_def.rs

C reference: `src/include/xdp2/parser_types.h:133-161`

Contents:

- `trait ProtocolOps` -- the central abstraction replacing both `xdp2_parse_ops` (function pointers at lines 133-137) and the static fields from `xdp2_proto_def` (lines 153-160)
- Associated constants: `MIN_LEN`, `NAME`, `NODE_TYPE`, `ENCAP`, `OVERLAY`
- Default method implementations:
  - `header_len()` returns `MIN_LEN` (mirrors C's NULL len function pointer behavior)
  - `next_proto()` -- no default, must be implemented
  - `next_proto_keyin()` defaults to calling `next_proto()`

The C `xdp2_proto_def` struct packs `node_type`, `encap`, `overlay`, `min_len`, `name`, and `ops` together in one cache-line-aligned struct. Rust moves the static fields into trait associated constants and the operations into trait methods. The `ProtoDef` struct wraps a `dyn ProtocolOps` for type-erased usage in the parse graph.

### 3.3 parse_node.rs

C reference: `src/include/xdp2/parser_types.h:221-229` (ops), `src/include/xdp2/parser_types.h:270-281` (node)

Contents:

- Callback type aliases:

```rust
pub type ExtractMetadataFn<M> = fn(hdr: &[u8], hdr_len: usize, metadata: &mut M,
                                    ctrl: &CtrlData);
pub type HandlerFn<M> = fn(hdr: &[u8], hdr_len: usize, metadata: &mut M,
                            ctrl: &CtrlData) -> Result<(), ParseError>;
pub type PostHandlerFn<M> = fn(hdr: &[u8], hdr_len: usize, metadata: &mut M,
                                ctrl: &CtrlData) -> Result<(), ParseError>;
```

- `ParseNodeOps<M>` struct -- holds `Option<ExtractMetadataFn<M>>`, `Option<HandlerFn<M>>`, `Option<PostHandlerFn<M>>`
- `ParseNode<M>` struct:
  - `node_type: NodeType`
  - `unknown_ret: i8` (default: `XDP2_STOP_UNKNOWN_PROTO`)
  - `key_sel: u8`
  - `flags: u8`
  - `proto_def: &'static dyn ProtocolOps`
  - `ops: ParseNodeOps<M>`
  - `proto_table: Option<&'static ProtoTable<M>>`
  - `wildcard_node: Option<&'static ParseNode<M>>`
  - `name: &'static str`
- `ParseNode::new()` and `ParseNode::leaf()` const fn constructors

The C `XDP2_PARSE_NODE_F_ZERO_LEN_OK` flag (value 1, at `parser_types.h:259`) is preserved as a constant.

### 3.4 proto_table.rs

C reference: `src/include/xdp2/parser_types.h:244-257`, `src/lib/xdp2/parser.c:38-48`

Contents:

- `ProtoTableEntry<M>` struct -- `value: i32`, `node: &'static ParseNode<M>`
- `ProtoTable<M>` struct -- `entries: &'static [ProtoTableEntry<M>]`
- `ProtoTable::lookup(&self, proto: i32) -> Option<&'static ParseNode<M>>` -- linear scan, preserving C's cache-friendly approach
- `proto_table![]` macro for static construction

```rust
/// Reimplements: `lookup_node()` in `src/lib/xdp2/parser.c:38-48`
///
/// Differences from C:
/// - Returns `Option<&ParseNode>` instead of raw pointer (NULL becomes None)
/// - Preserves linear scan for cache locality (matches C behavior)
pub fn lookup(&self, proto: i32) -> Option<&'static ParseNode<M>> {
    self.entries.iter()
        .find(|e| e.value == proto)
        .map(|e| e.node)
}
```

### 3.5 parser.rs

C reference: `src/include/xdp2/parser_types.h:301-327`, `src/include/xdp2/parser.h:99-104` (defaults)

Contents:

- `ParserConfig<M>` struct:
  - `max_nodes: u16` (default 255, per `parser.h:99`)
  - `max_encaps: u16` (default 4, per `parser.h:100`)
  - `max_frames: u16` (default 4, per `parser.h:101`)
  - `metameta_size: usize` (default 64, per `parser.h:102`)
  - `frame_size: usize` (default 256, per `parser.h:103`)
  - `num_counters: u8`
  - `num_keys: u8`
  - `okay_node: Option<&'static ParseNode<M>>`
  - `fail_node: Option<&'static ParseNode<M>>`
  - `atencap_node: Option<&'static ParseNode<M>>`
- `Parser<M>` struct:
  - `name: &'static str`
  - `config: ParserConfig<M>`
  - `root_node: &'static ParseNode<M>`
  - `parser_type: ParserType`
- `Parser::validate_fast()` -- reimplements `xdp2_parse_validate_fast()` from `parser.c:893-918`

### 3.6 engine.rs -- THE CRITICAL FILE

C reference: `src/lib/xdp2/parser.c:461-701` (`__xdp2_parse` main loop), `src/lib/xdp2/parser.c:703-814` (`__xdp2_parse_fast`)

This is the single most important file. It reimplements the main parse loop.

Contents:

- `ParseOutput<M>` struct -- metadata, ctrl_data, frames
- `pub fn parse<M: Default>(parser: &Parser<M>, packet: &[u8]) -> Result<ParseOutput<M>, ParseError>`
- `pub fn parse_fast<M: Default>(parser: &Parser<M>, packet: &[u8]) -> Result<ParseOutput<M>, ParseError>`
- Internal helper: `run_exit_node()` -- reimplements `__xdp2_parse_run_exit_node()` from `parser.h:440-456`

The C `__xdp2_parse` loop is a `do { ... } while(1)` with `goto out` and `goto found_next`. The Rust translation uses `loop { ... break; }` with labeled blocks:

```rust
let result = 'parse: loop {
    // Length check
    // extract_metadata callback
    // handler callback
    // Node-type dispatch (TLV/flags/array)
    // post_handler callback
    // next_proto + table lookup
    // Advance pointer
};
```

Key callback ordering contract (matching `parser.c:509-516`):

1. `proto_def.ops.len()` -- get header length
2. `parse_node.ops.extract_metadata()` -- extract metadata into frame
3. `parse_node.ops.handler()` -- per-protocol handler
4. TLV/flag-fields/array sub-parsing (if `node_type != Plain`)
5. `parse_node.ops.post_handler()` -- post-processing
6. `proto_def.ops.next_proto()` -- determine next protocol number
7. Protocol table lookup -- find next parse node

Control flow mapping from C to Rust:

| C Pattern | Rust Pattern |
|-----------|-------------|
| `goto out` with `ret = XDP2_STOP_LENGTH` | `break 'parse Err(ParseError::Length)` |
| `goto found_next` | `continue 'parse` after setting `parse_node` |
| `hdr += hlen; len -= hlen;` | `offset += hlen;` (index into slice, no pointer arithmetic) |
| `void *frame = metadata + metameta_size` | `frames[frame_num]` (Vec of frame structs) |
| `frame += frame_size` / `frame_num++` | `frame_num += 1` |

The `__xdp2_parse_fast` variant (lines 703-814) omits:

- Debug printing
- `post_handler` callbacks
- `okay_node`/`fail_node` exit processing
- `num_counters`/`num_keys` support
- `next_proto_keyin` support
- Node-type vs proto_def type mismatch checks

### 3.7 tlvs.rs

C reference: `src/include/xdp2/tlvs.h:64-187` (types), `src/lib/xdp2/parser.c:50-296` (parsing logic)

Contents:

- `TlvOps` struct -- `len`, `type_fn`, `start_offset` function pointers (from `xdp2_proto_tlvs_opts` at `tlvs.h:64-68`)
- `ProtoTlvsDef` struct -- wraps base proto_def + TLV ops + `pad1_val`, `eol_val`, `pad1_enable`, `eol_enable`, `min_len` (from `xdp2_proto_tlvs_def` at `tlvs.h:158-166`)
- `ProtoTlvDef` struct -- per-TLV-type definition with `min_len` and optional `overlay_type`/`nested_offset` ops (from `xdp2_proto_tlv_def` at `tlvs.h:184-187` and `xdp2_proto_tlv_def_ops` at `tlvs.h:174-177`)
- `ParseTlvNodeOps<M>` -- `extract_metadata`, `handler` callbacks (from `tlvs.h:83-89`)
- `ParseTlvNode<M>` -- `proto_tlv_def`, `tlv_ops`, `overlay_table`, `overlay_wildcard_node`, `nested_node`, `unknown_overlay_ret`, `name` (from `tlvs.h:94-102`)
- `TlvTableEntry<M>` and `TlvTable<M>` (from `tlvs.h:108-120`)
- `ParseTlvsNode<M>` -- extends `ParseNode` with `tlv_proto_table`, `max_tlvs`, `max_tlv_len`, `unknown_tlv_type_ret`, `tlv_wildcard_node` (from `tlvs.h:136-143`)
- `parse_one_tlv()` -- reimplements `xdp2_parse_one_tlv()` from `parser.c:103-183`
- `parse_tlvs()` -- reimplements `xdp2_parse_tlvs()` from `parser.c:185-296`
- `tlv_table![]` macro

The C `parse_again:` label with `goto parse_again` in `xdp2_parse_one_tlv` becomes a Rust `loop` with `continue`.

### 3.8 flag_fields.rs

C reference: `src/include/xdp2/flag_fields.h:64-229` (types + helpers), `src/lib/xdp2/parser.c:298-358` (parsing logic)

Contents:

- `FlagField` struct -- `flag: u32`, `mask: u32`, `size: usize` (from `flag_fields.h:64-68`)
- `FlagFields` struct -- `fields: &'static [FlagField]` (from `flag_fields.h:78-81`)
- `FlagFields::offset(targ_idx, flags)` -- reimplements `xdp2_flag_fields_offset()` from `flag_fields.h:116-130`. Returns `Option<usize>` instead of `ssize_t` (-1 for absent).
- `FlagFields::length(flags)` -- reimplements `xdp2_flag_fields_length()` from `flag_fields.h:107-113`
- `FlagFields::check_invalid(flags, mask)` -- reimplements `flag_fields.h:133-136`
- `FlagFields::get::<T>(fields, targ_idx, flags)` -- generic typed field access replacing the `__XDP_FLAG_FIELDS_MAKE_GET` family (`flag_fields.h:138-154`)
- `FlagFieldsOps` struct -- `get_flags`, `start_fields_offset` fn pointers (from `flag_fields.h:162-165`)
- `ProtoFlagFieldsDef` struct -- wraps proto_def + ops + flag_fields reference (from `flag_fields.h:225-229`)
- `ParseFlagFieldNodeOps<M>` -- extract_metadata, handler (from `flag_fields.h:180-186`)
- `ParseFlagFieldNode<M>` -- ops + name (from `flag_fields.h:189-192`)
- `FlagFieldsTableEntry<M>` and `FlagFieldsTable<M>` (from `flag_fields.h:198-212`)
- `ParseFlagFieldsNode<M>` -- extends ParseNode with table (from `flag_fields.h:217-220`)
- `parse_flag_fields()` -- reimplements `xdp2_parse_flag_fields()` from `parser.c:298-358`
- `flag_fields_table![]` macro

Key behavioral note: the C `mask ?: flag` pattern (GCC ternary with empty true branch at `flag_fields.h:93-94`) means "if mask is 0 use flag as mask". Rust: `let mask = if ff.mask != 0 { ff.mask } else { ff.flag };`

### 3.9 arrays.rs

C reference: `src/include/xdp2/arrays.h:59-144` (types), `src/lib/xdp2/parser.c:360-448` (parsing logic)

Contents:

- `ArrayOps` struct -- `num_els`, `el_type`, `start_offset` fn pointers (from `arrays.h:59-63`)
- `ProtoArrayDef` struct -- wraps proto_def + array ops + `el_length` (from `arrays.h:140-144`)
- `ParseArrayElNodeOps<M>` -- `extract_metadata`, `handler` (from `arrays.h:78-84`)
- `ParseArrayElNode<M>` -- ops + name (from `arrays.h:89-92`)
- `ArrayTableEntry<M>` and `ArrayTable<M>` (from `arrays.h:98-111`)
- `ParseArrayNode<M>` -- extends ParseNode with `array_proto_table`, `max_els`, `unknown_array_type_ret`, `array_wildcard_node` (from `arrays.h:126-132`)
- `parse_array()` -- reimplements `xdp2_parse_array()` from `parser.c:360-448`
- `array_table![]` macro

The C `goto parse_one_arrel` pattern (`parser.c:400`) becomes a helper closure or extracted function in Rust.

### 3.10 Phase 1 Verification

- Unit tests for all type conversions (`i32` to `ParseError` round-trip for all 22 error codes)
- Unit tests for `ProtoTable::lookup()` with known tables (empty table, single entry, miss)
- Unit tests for `FlagFields::offset()` and `FlagFields::length()` against hand-computed values
- Unit tests for TLV parsing with pad1, eol, nested, and overlay paths
- Property test: arbitrary bytes through a minimal Ethernet-only parser produces valid `ParseResult`/`ParseError` (never panics)
- `cargo test`, `cargo clippy -- -D warnings`, `cargo fmt --check`


## 4. Phase 2: xdp2-protocols (Core 15 Protocols)

### 4.1 Protocol Module Template

Every protocol file follows this pattern:

```rust
//! Ethernet protocol definition
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C Source | C Item |
//! |-----------|---------|--------|
//! | `EthernetOps` | `proto_defs/ethernet/proto_ether.h:52-56` | `xdp2_parse_ether` |
//! | `EthernetOps::next_proto` | `proto_ether.h:36-39` | `ether_proto()` |
//!
//! ## Behavioral Differences
//! - None (byte-for-byte compatible)

use zerocopy::{FromBytes, KnownLayout, Immutable, NetworkEndian, U16};
use xdp2_core::{ProtocolOps, ParseError};

#[derive(FromBytes, KnownLayout, Immutable)]
#[repr(C, packed)]
pub struct EthernetHeader {
    pub dst: [u8; 6],
    pub src: [u8; 6],
    pub ethertype: U16<NetworkEndian>,
}

pub struct EthernetOps;

impl ProtocolOps for EthernetOps {
    const MIN_LEN: usize = 14;  // sizeof(struct ethhdr)
    const NAME: &'static str = "Ethernet";

    fn next_proto(&self, hdr: &[u8]) -> Result<i32, ParseError> {
        let eth = EthernetHeader::ref_from_prefix(hdr)
            .map_err(|_| ParseError::Length)?;
        Ok(eth.ethertype.get() as i32)
    }
}
```

### 4.2 Priority Protocols

| # | Protocol | C Source | C proto_def | Rust Module |
|---|----------|---------|-------------|-------------|
| 1 | Ethernet | `proto_defs/ethernet/proto_ether.h` | `xdp2_parse_ether` (line 52) | `ethernet::ether` |
| 2 | VLAN (802.1Q) | `proto_defs/ethernet/proto_vlan.h` | `xdp2_parse_vlan` | `ethernet::vlan` |
| 3 | IPv4 | `proto_defs/ip/proto_ipv4.h` | `xdp2_parse_ipv4` (line 100) | `ip::ipv4` |
| 4 | IPv6 | `proto_defs/ip/proto_ipv6.h` | `xdp2_parse_ipv6` | `ip::ipv6` |
| 5 | TCP | `proto_defs/transport/proto_tcp.h` | `xdp2_parse_tcp` | `transport::tcp` |
| 6 | UDP | `proto_defs/transport/proto_udp.h` | `xdp2_parse_udp` | `transport::udp` |
| 7 | GRE | `proto_defs/tunnel/proto_gre.h` | `xdp2_parse_gre` | `tunnel::gre` |
| 8 | ARP/RARP | `proto_defs/ip/proto_arp_rarp.h` | `xdp2_parse_arp` | `ip::arp` |
| 9 | ICMP (v4+v6) | `proto_defs/ip/proto_icmp.h` | `xdp2_parse_icmpv4` (line 115), `xdp2_parse_icmpv6` (line 127) | `ip::icmp` |
| 10 | VXLAN | `proto_defs/tunnel/proto_vxlan.h` | `xdp2_parse_vxlan` | `tunnel::vxlan` |
| 11 | MPLS | `proto_defs/tunnel/proto_mpls.h` | `xdp2_parse_mpls` | `tunnel::mpls` |
| 12 | Ports (generic) | `proto_defs/transport/proto_ports.h` | `xdp2_parse_ports` | `transport::ports` |
| 13 | IP overlay | `proto_defs/ip/proto_ip.h` | `xdp2_parse_ip` (line 75) | `ip::ip_overlay` |
| 14 | IPv6 ext headers | `proto_defs/ip/proto_ipv6_eh.h` | `xdp2_parse_ipv6_eh` | `ip::ipv6_eh` |
| 15 | SCTP | `proto_defs/transport/proto_sctp.h` | `xdp2_parse_sctp` | `transport::sctp` |

Notes on specific protocols:

- **IPv4** (`proto_ipv4.h`): Has multiple proto_def variants -- `xdp2_parse_ipv4` (standard), `xdp2_parse_ipv4_stop1stfrag` (stops at all fragments), `xdp2_parse_ipv4_check` (validates version=4, overlay=1). Rust provides these as separate `ProtocolOps` implementations or builder options.
- **IP overlay** (`proto_ip.h`): Uses `overlay = 1` and reads the IP version nibble. Has a `next_proto_keyin` variant (`xdp2_parse_ip_by_key` at line 82). Rust implements both trait methods.
- **ICMP** (`proto_icmp.h`): Single file defines both ICMPv4 and ICMPv6 proto_defs. Both use `overlay = true` and `ops.len = icmp_all_len` (returns remaining packet length). Rust has `IcmpV4Ops` and `IcmpV6Ops` in the same module.
- **GRE** (`proto_gre.h`): Uses flag-fields (`NODE_TYPE_FLAG_FIELDS`). This is a key test of the flag-fields sub-parser.

### 4.3 Phase 2 Verification

- Golden snapshot tests (insta): run Rust parser on `src/test/parser/test-in.raw`, compare output
- PCAP cross-comparison Nix derivation: `nix build .#xdp2-rs-golden`
- Build sample parsers equivalent to `samples/parser/ports_parser/` and `samples/parser/simple_parser/`
- Each protocol gets at least one unit test with a hand-crafted packet and expected `next_proto` return value


## 5. Phase 3: Remaining 190 Protocols

15 categories matching `src/include/xdp2/proto_defs/` subdirectories:

| Category | Protocol Count | C Source Directory | Rust Module | Priority |
|----------|---------------|-------------------|-------------|----------|
| ethernet | 9 | `proto_defs/ethernet/` | `ethernet/` | High (Phase 2) |
| ip | 17 | `proto_defs/ip/` | `ip/` | High (Phase 2) |
| transport | 11 | `proto_defs/transport/` | `transport/` | High (Phase 2) |
| tunnel | 22 | `proto_defs/tunnel/` | `tunnel/` | Medium |
| security | 14 | `proto_defs/security/` | `security/` | Medium |
| management | 78 | `proto_defs/management/` | `management/` | Low |
| bluetooth | 13 | `proto_defs/bluetooth/` | `bluetooth/` | Low |
| infiniband | 10 | `proto_defs/infiniband/` | `infiniband/` | Low |
| legacy | 10 | `proto_defs/legacy/` | `legacy/` | Low |
| storage | 7 | `proto_defs/storage/` | `storage/` | Low |
| other | 5 | `proto_defs/other/` | `other/` | Low |
| wireless | 3 | `proto_defs/wireless/` | `wireless/` | Low |
| can | 3 | `proto_defs/can/` | `can/` | Low |
| netlink | 3 | `proto_defs/netlink/` | `netlink/` | Low |
| **Total** | **205** | | | |

Each protocol file includes the C cross-reference table. Protocols are ported one category at a time with tests after each category.

Category porting order:

1. **ethernet** (9) -- completes VLAN, QinQ, PBB, SLL/SLL2, LLC, EDSA, PPPoE-D
2. **ip** (remaining 12) -- IPv6 ext headers, SRv6, IGMPv3, MLD, PIM, RSVP, RTP/RTCP, IPv4-in-IPv4, IPv6-in-IPv6
3. **transport** (remaining 6) -- DCCP, QUIC, L2TP, L2TPv0, UDPLite, TIPC, SCTP chunks
4. **tunnel** (22) -- Geneve, NVGRE, GUE, IP-in-IP, GTP, NSH, ERSPAN, STT, etc.
5. **security** (14) -- AH, ESP, MACsec, TLS, WireGuard, EAP, etc.
6. Remaining categories as needed


## 6. Phase 4: xdp2-compiler

### 6.1 JSON IR Bridge

- C++ compiler already emits PIR (Parser IR) in JSON format
- Rust compiler reads this JSON as input (avoids reimplementing Clang AST)
- Defined in `documentation/parser-ir.md`

### 6.2 Graph Construction

- `petgraph::DiGraph<VertexProperty, EdgeProperty>` replaces Boost `adjacency_list`
- Cycle detection: `petgraph::algo::is_cyclic_directed()` replaces custom BFS visitor
- BFS depth leveling: `petgraph::visit::Bfs` replaces custom visitor
- Graphviz: `petgraph::dot::Dot` replaces custom `dotify()`

### 6.3 Code Generation

- Tera templates replace pyrex `<!--(macro)-->` template syntax
- `templates/c_def.tera` generates optimized C parser
- `templates/xdp_def.tera` generates XDP/eBPF C code

### 6.4 Verification

- Byte-level diff: Rust-generated C code vs C++-generated C code for same input
- Same test parsers, same expected output


## 7. Verification Strategy

### 7.1 Testing Pyramid

| Level | Tool | What | When |
|-------|------|------|------|
| Unit | `cargo test` / proptest | Individual functions, type conversions | Every commit |
| Integration | insta snapshots | Parser output on test packets | Every commit |
| Golden | Nix derivation | C vs Rust output comparison | Every PR |
| Property | proptest | No panics on arbitrary input | Every commit |
| Lint | clippy | Code quality | Every commit |
| Format | rustfmt | Style consistency | Every commit |

### 7.2 Golden Test Infrastructure

```
nix build .#xdp2-rs-golden
```

This derivation:

1. Builds the C parser (xdp2-debug)
2. Builds the Rust parser (xdp2-rs)
3. Runs both on `src/test/parser/test-in.raw` and `src/test/parser/test-in.pcap`
4. Diffs output line-by-line
5. Fails if any unexpected differences

### 7.3 Documenting Intentional Improvements

When the Rust implementation intentionally differs from C (e.g., better error messages, stricter validation):

```rust
/// ## Behavioral Differences from C
///
/// - **Improvement**: Returns `ParseError::Length` with the actual vs expected
///   lengths, whereas C returns bare `XDP2_STOP_LENGTH` with no context.
///   This aids debugging without affecting parse semantics.
```


## 8. Cross-Reference Documentation Standard

### 8.1 Module Level

Every `.rs` file starts with:

```rust
//! # Module Name
//!
//! Brief description.
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `ProtoDef` | `parser_types.h:153-161` | `struct xdp2_proto_def` |
//! | `ProtocolOps` | `parser_types.h:133-137` | `struct xdp2_parse_ops` |
```

### 8.2 Function Level

```rust
/// Reimplements: `lookup_node()` in `src/lib/xdp2/parser.c:38-48`
///
/// Differences from C:
/// - Returns `Option<&ParseNode>` instead of raw pointer (NULL becomes None)
/// - Preserves linear scan for cache locality (matches C behavior)
```

### 8.3 Behavioral Differences

Any intentional deviation gets a `## Behavioral Differences` section explaining:

- What changed
- Why it is an improvement (or necessity for safety)
- Whether it affects parse output (semantic vs cosmetic)


## 9. Nix Integration

### 9.1 Nix Targets

| Target | Command | Purpose |
|--------|---------|---------|
| Build | `nix build .#xdp2-rs` | Production binary |
| Check | `nix build .#xdp2-rs-check` | Fast cargo check |
| Test | `nix build .#xdp2-rs-test` | Full test suite |
| Clippy | `nix build .#xdp2-rs-clippy` | Lint (deny warnings) |
| Format | `nix build .#xdp2-rs-fmt-check` | `rustfmt --check` |
| Docs | `nix build .#xdp2-rs-doc` | `cargo doc` |
| Golden | `nix build .#xdp2-rs-golden` | C vs Rust comparison |

### 9.2 nix/xdp2-rs.nix

Modular file exporting all targets. Follows `nix/analysis/default.nix` pattern. Uses `rustPlatform.buildRustPackage` with shared `commonArgs`.

```nix
{ pkgs, ... }:
let
  commonArgs = {
    pname = "xdp2-rs";
    version = "0.1.0";
    src = ../xdp2-rs;
    cargoHash = "sha256-AAAA...";  # Update via fakeHash method
  };
in {
  xdp2-rs = pkgs.rustPlatform.buildRustPackage (commonArgs // { });

  xdp2-rs-check = pkgs.rustPlatform.buildRustPackage (commonArgs // {
    cargoBuildCommand = "cargo check";
  });

  # ... clippy, test, fmt-check, doc variants
}
```

### 9.3 flake.nix

Exports all targets as flat package names (`xdp2-rs`, `xdp2-rs-check`, etc.). Pattern matches existing `analysis-*` exports.

### 9.4 Dev Shell

Adds to `nix/devshell.nix`: cargo, rustc, clippy, rustfmt, rust-analyzer, cargo-audit.

### 9.5 CI

All Nix targets can run in parallel:

```bash
nix build .#xdp2-rs-check .#xdp2-rs-test .#xdp2-rs-clippy .#xdp2-rs-fmt-check
```


## 10. Risk Assessment and Mitigations

| Risk | Impact | Likelihood | Mitigation |
|------|--------|-----------|-----------|
| Circular static references (GRE->Ethernet->GRE) | Compile error | High | Use `std::sync::LazyLock` (stable since Rust 1.80) or index-based references into a global registry |
| Generic metadata `M` makes static node construction hard | Verbose types, cannot use `static` | Medium | Provide `type DefaultParser = Parser<()>` for testing; builder macros for users; consider type-erased `Box<dyn Any>` path |
| 205 protocols is a lot of boilerplate | Slow progress | High | Prioritize by test coverage; consider proc macro to auto-generate from C headers |
| Performance regression vs C | Slower parsing | Medium | Benchmark with same PCAPs; profile hotspots; zerocopy avoids copies; bounds checks are the main cost |
| zerocopy API changes between versions | Build breaks | Low | Pin to 0.8.x; use `cargo audit` |
| petgraph index invalidation | Runtime panic in Phase 4 | Medium | Use `StableGraph` when nodes may be removed |
| Tera template errors are runtime | Silent wrong output in Phase 4 | Medium | Golden tests catch divergence from C++ compiler |
| eBPF verifier rejects Rust-generated code | Blocks XDP target | High | Keep generating C for eBPF initially; migrate to Aya when mature |
| C `void *frame` pointer arithmetic maps poorly to Rust | Unsound or complex code | Medium | Use `Vec<Vec<u8>>` for frame storage with indexed access instead of raw pointer offsets |
| C `goto` control flow in `__xdp2_parse` | Subtle translation bugs | Medium | Labeled loops with explicit `break`/`continue`; exhaustive test coverage of all exit paths |


## Appendix A: File Layout

```
xdp2-rs/
  Cargo.toml
  crates/
    xdp2-core/
      Cargo.toml
      src/
        lib.rs
        types.rs          # ParseError, ParseResult, NodeType, CtrlData
        proto_def.rs      # ProtocolOps trait, ProtoDef wrapper
        parse_node.rs     # ParseNode, ParseNodeOps, callback types
        proto_table.rs    # ProtoTable, ProtoTableEntry, proto_table! macro
        parser.rs         # Parser, ParserConfig
        engine.rs         # parse(), parse_fast(), run_exit_node()
        tlvs.rs           # TLV types, parse_tlvs(), parse_one_tlv()
        flag_fields.rs    # FlagField types, parse_flag_fields()
        arrays.rs         # Array types, parse_array()
    xdp2-protocols/
      Cargo.toml
      src/
        lib.rs
        ethernet/
          mod.rs
          ether.rs        # EthernetOps
          vlan.rs         # VlanOps
          qinq.rs         # QinQOps
          ...
        ip/
          mod.rs
          ipv4.rs         # Ipv4Ops, Ipv4Stop1stFragOps, Ipv4CheckOps
          ipv6.rs         # Ipv6Ops
          ip_overlay.rs   # IpOverlayOps, IpOverlayByKeyOps
          icmp.rs         # IcmpV4Ops, IcmpV6Ops
          arp.rs          # ArpOps
          ...
        transport/
          mod.rs
          tcp.rs          # TcpOps
          udp.rs          # UdpOps
          sctp.rs         # SctpOps
          ports.rs        # PortsOps
          ...
        tunnel/
          mod.rs
          gre.rs          # GreOps (flag-fields node type)
          vxlan.rs        # VxlanOps (encap)
          mpls.rs         # MplsOps
          ...
        security/
          mod.rs
          ...
        management/
          mod.rs
          ...
        # remaining categories follow same pattern
    xdp2-compiler/
      Cargo.toml          # stub, Phase 4
      src/
        lib.rs
```


## Appendix B: Constants Cross-Reference

| C Constant | C Source | Value | Rust Constant |
|-----------|---------|-------|---------------|
| `XDP2_OKAY` | `parser_types.h:60` | 0 | `ParseResult::Okay` |
| `XDP2_RET_OKAY` | `parser_types.h:61` | -1 | `ParseResult::RetOkay` |
| `XDP2_OKAY_USE_WILD` | `parser_types.h:63` | -2 | `ParseResult::UseWild` |
| `XDP2_OKAY_USE_ALT_WILD` | `parser_types.h:64` | -3 | `ParseResult::UseAltWild` |
| `XDP2_STOP_OKAY` | `parser_types.h:66` | -4 | `ParseResult::StopOkay` |
| `XDP2_STOP_NODE_OKAY` | `parser_types.h:67` | -5 | `ParseResult::StopNodeOkay` |
| `XDP2_STOP_SUB_NODE_OKAY` | `parser_types.h:68` | -6 | `ParseResult::StopSubNodeOkay` |
| `XDP2_STOP_FAIL` | `parser_types.h:71` | -12 | `ParseError::Fail` |
| `XDP2_STOP_LENGTH` | `parser_types.h:72` | -13 | `ParseError::Length` |
| `XDP2_STOP_UNKNOWN_PROTO` | `parser_types.h:73` | -14 | `ParseError::UnknownProto` |
| `XDP2_STOP_ENCAP_DEPTH` | `parser_types.h:74` | -15 | `ParseError::EncapDepth` |
| `XDP2_STOP_UNKNOWN_TLV` | `parser_types.h:75` | -16 | `ParseError::UnknownTlv` |
| `XDP2_STOP_TLV_LENGTH` | `parser_types.h:76` | -17 | `ParseError::TlvLength` |
| `XDP2_STOP_BAD_FLAG` | `parser_types.h:77` | -18 | `ParseError::BadFlag` |
| `XDP2_STOP_FAIL_CMP` | `parser_types.h:78` | -19 | `ParseError::FailCmp` |
| `XDP2_STOP_LOOP_CNT` | `parser_types.h:79` | -20 | `ParseError::LoopCnt` |
| `XDP2_STOP_TLV_PADDING` | `parser_types.h:80` | -21 | `ParseError::TlvPadding` |
| `XDP2_STOP_OPTION_LIMIT` | `parser_types.h:81` | -22 | `ParseError::OptionLimit` |
| `XDP2_STOP_MAX_NODES` | `parser_types.h:82` | -23 | `ParseError::MaxNodes` |
| `XDP2_STOP_COMPARE` | `parser_types.h:83` | -24 | `ParseError::Compare` |
| `XDP2_STOP_BAD_EXTRACT` | `parser_types.h:84` | -25 | `ParseError::BadExtract` |
| `XDP2_STOP_BAD_CNTR` | `parser_types.h:85` | -26 | `ParseError::BadCntr` |
| `XDP2_STOP_CNTR1` through `CNTR7` | `parser_types.h:86-92` | -27 to -33 | `ParseError::Cntr1` through `Cntr7` |
| `XDP2_STOP_THREADS_FAIL` | `parser_types.h:94` | -34 | `ParseError::ThreadsFail` |
| `XDP2_NODE_TYPE_PLAIN` | `parser_types.h:110` | 0 | `NodeType::Plain` |
| `XDP2_NODE_TYPE_TLVS` | `parser_types.h:112` | 1 | `NodeType::Tlvs` |
| `XDP2_NODE_TYPE_FLAG_FIELDS` | `parser_types.h:114` | 2 | `NodeType::FlagFields` |
| `XDP2_NODE_TYPE_ARRAY` | `parser_types.h:116` | 3 | `NodeType::Array` |
| `XDP2_GENERIC` | `parser_types.h:100` | 0 | `ParserType::Generic` |
| `XDP2_OPTIMIZED` | `parser_types.h:102` | 1 | `ParserType::Optimized` |
| `XDP2_XDP` | `parser_types.h:104` | 2 | `ParserType::Xdp` |
| `XDP2_PARSER_DEFAULT_MAX_NODES` | `parser.h:99` | 255 | `ParserConfig::DEFAULT_MAX_NODES` |
| `XDP2_PARSER_DEFAULT_MAX_ENCAPS` | `parser.h:100` | 4 | `ParserConfig::DEFAULT_MAX_ENCAPS` |
| `XDP2_PARSER_DEFAULT_MAX_FRAMES` | `parser.h:101` | 4 | `ParserConfig::DEFAULT_MAX_FRAMES` |
| `XDP2_PARSER_DEFAULT_METAMETA_SIZE` | `parser.h:102` | 64 | `ParserConfig::DEFAULT_METAMETA_SIZE` |
| `XDP2_PARSER_DEFAULT_FRAME_SIZE` | `parser.h:103` | 256 | `ParserConfig::DEFAULT_FRAME_SIZE` |
| `XDP2_PARSE_NODE_F_ZERO_LEN_OK` | `parser_types.h:259` | 1 | `ParseNode::F_ZERO_LEN_OK` |
| `XDP2_F_DEBUG` | `parser.h:266` | 1 | `ParseFlags::DEBUG` |
