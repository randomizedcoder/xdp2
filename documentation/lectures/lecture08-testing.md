# Lecture 8: Testing and Clean-Room Reimplementation Guide

## 8.1 Test Infrastructure

XDP2 includes a modular test framework in
[src/test/parser/](../src/test/parser/). The framework separates testing into
three components:

<img src="../images/parser-test-infra.png" alt="Parser test infrastructure"/>

*The parser test infrastructure.*

| Component | Options | Description |
|---|---|---|
| **Input method** | tcpdump, raw, pcap, fuzz | How packets are fed to the parser |
| **Core parser** | xdp2, xdp2opt, flowdis, parselite, null | Which parsing engine to use |
| **Output method** | text, error, null | How results are reported |

Tests are run via `run-tests.sh` and validate that the parser produces
correct metadata for known packets. The test suite achieves 38/38 PASS across
x86_64, RISC-V, and AArch64.

For details, see [documentation/test-parser.md](test-parser.md).

## 8.2 The Parse-Dump Tool

The `parse_dump` tool in [src/test/parse_dump/](../src/test/parse_dump/) is a
comprehensive parser that defines nodes for all supported protocols. It can
parse pcap files and dump the metadata extracted at each layer. This is
invaluable for debugging new protocol definitions.

See [documentation/parse-dump.md](parse-dump.md) for usage.

## 8.3 Clean-Room Reimplementation Roadmap

If you were to reimplement XDP2 from scratch, here is the recommended order:

### Phase 1: Minimum Viable Parser

**Goal**: Parse Ethernet/IPv4/TCP packets with metadata extraction.

**Implement these four structures:**
1. `struct proto_def` -- protocol definition with `min_len`, `ops.len`,
   `ops.next_proto`
2. `struct parse_node` -- parse node with `proto_def`, `ops.extract_metadata`,
   `proto_table`
3. `struct proto_table` -- array of (protocol_number, parse_node*) pairs
4. `struct parser` -- root_node + configuration

**Implement the main loop:**
- A `do/while` loop that:
  - Checks length, calls `ops.len` if set
  - Calls `extract_metadata` if set
  - Calls `ops.next_proto` to get the next type
  - Looks up the type in `proto_table` (linear scan)
  - Advances the header pointer
  - Stops at leaf nodes or errors

**Write three protocol definitions:**
- Ethernet (fixed 14 bytes, next_proto = EtherType)
- IPv4 (variable length via IHL, next_proto = protocol field)
- TCP (variable length via data offset, leaf node)

**Test**: Parse a pcap file and print extracted IPs and ports.

This phase corresponds to the
[ports_parser sample](../samples/parser/ports_parser/).

### Phase 2: TLVs, Flag-Fields, and Arrays

**Add `node_type` to parse nodes** to distinguish PLAIN from TLVS,
FLAG_FIELDS, and ARRAY.

**Implement TLV parsing:**
- TLV protocol definitions with `tlv_type`, `tlv_len`, `tlv_data_offset`
- TLV tables and TLV parse nodes
- The TLV iteration loop (handle pad1, eol, unknown types)

**Implement flag-fields parsing:**
- Flag descriptor tables (`flag`, `mask`, `size`)
- The flag scanning loop

**Implement array parsing:**
- Array protocol definitions with `num_els`, `start_offset`, `el_type`
- The element iteration loop

**Test**: Parse TCP with timestamp options, GRE with flag-fields.

### Phase 3: The Optimizing Compiler

**Goal**: Generate optimized C code from parse graph definitions.

**Implement the compiler pipeline:**
1. Extract parse graph from C source (using Clang AST or by parsing macros)
2. Build a directed graph data structure
3. Detect cycles (back-edges = encapsulation)
4. Generate linear C code with inlined callbacks

**Start simple**: Generate code for a fixed parser (hardcode the graph),
then generalize to reading from source.

### Phase 4: The XDP/eBPF Target

**Goal**: Generate eBPF-compatible code with tail call support.

**Key challenges:**
- Replace indirect calls with inline code
- Use `#pragma unroll` for bounded loops
- Implement tail-call architecture for deep parsing
- Use per-CPU maps for context storage

## 8.4 Architectural Invariants

These properties must be preserved in any reimplementation:

| Invariant | Reason |
|---|---|
| Protocol definitions are `static const` | Enables compiler optimization; ensures thread safety |
| Callback ordering (len → metadata → handler → sub-structs → post_handler → next_proto) | Protocols may depend on this order |
| Linear scan for table lookup | Deterministic performance; cache-friendly for small tables |
| Overlay nodes do not advance the packet pointer | Required for version-check dispatch pattern |
| Encapsulation increments the frame pointer | Ensures outer and inner headers have separate metadata |
| `min_len` is always checked before `ops.len` | Prevents reading garbage from truncated packets |
| Negative return from `ops.len` or `ops.next_proto` stops parsing | This is how protocols signal errors or stopping conditions |

## 8.5 Performance Considerations

- **Cache line alignment**: `xdp2_proto_def` and `xdp2_parse_node` are aligned
  to cache line size (`__aligned(XDP2_CACHELINE_SIZE)`)
- **Static const structures**: Protocol definitions and parse nodes should be
  `static const` to enable the C compiler to inline and constant-fold
- **Small protocol tables**: Linear scan beats hash tables for < ~16 entries
  due to cache locality
- **Restrict to one compilation unit**: Keeping all parser structures in one
  `.c` file allows the compiler to see all definitions and optimize
  aggressively

## 8.6 Further Reading

- [Parser Architecture](parser.md) -- detailed API documentation
- [Parser IR](parser-ir.md) -- intermediate representation specification
- [XDP2 Compiler](xdp2-compiler.md) -- compiler documentation
- [XDP Target](xdp.md) -- XDP compilation target details
- [Getting Started Guide](getting-started.md) -- full build walkthrough
- [Nix Development Environment](nix/nix.md) -- build system guide

---

[< Lecture 7: Worked Examples -- Packets Walking the Parse Graph](lecture07-worked-examples.md) | [Table of Contents](README.md) | [Lecture 9: Porting the Runtime -- C to Rust >](lecture09-rust-runtime.md)
