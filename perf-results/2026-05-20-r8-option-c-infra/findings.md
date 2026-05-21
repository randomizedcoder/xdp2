# R8-Option C — Per-parser metadata-field mask (infrastructure shipment)

Date: 2026-05-20. Phase 1 of Option C: ship the per-parser
metadata-field mask infrastructure end-to-end through API,
IR, codegen, template. Default behavior unchanged (parsers
without explicit mask declaration get all fields, identical
to pre-Option-C).

User direction: "This code will need to work on a wide range
of CPUs, and so we shouldn't assume the struct layout doesn't
matter (maybe it doesn't matter on this CPU)." Forward-looking
shipment — Zen 1 with a forgiving store buffer is expected to
show null perf delta on narrowing, but smaller CPUs (in-order
ARM, embedded RISC-V, older Intel) should benefit from reduced
metadata-write count per packet.

## What ships

### 1. API addition (`src/include/xdp2/parser_types.h`)

`xdp2_parser_config` gains `__u64 used_field_mask` field.
Default 0 means "use all fields" (backward-compatible).
Non-zero declares a parser-specific subset.

### 2. Field enum (`src/include/xdp2/parser_metadata.h`)

`enum xdp2_metadata_fields`: 21 bit-per-field flags mapping
every distinct extractor name seen in the R3.3.4 IR analysis:

```c
enum xdp2_metadata_fields {
    XDP2_MD_ETH_PROTO    = 1ULL << 0,
    XDP2_MD_ETH_ADDRS    = 1ULL << 1,
    XDP2_MD_IP_PROTO     = 1ULL << 2,
    XDP2_MD_ADDR_TYPE    = 1ULL << 3,
    XDP2_MD_ADDRS        = 1ULL << 4,
    XDP2_MD_PORTS        = 1ULL << 5,
    XDP2_MD_L2_OFF       = 1ULL << 6,
    XDP2_MD_L3_OFF       = 1ULL << 7,
    XDP2_MD_L4_OFF       = 1ULL << 8,
    XDP2_MD_FLOW_LABEL   = 1ULL << 9,
    XDP2_MD_VLAN         = 1ULL << 10,
    XDP2_MD_VLAN_COUNT   = 1ULL << 11,
    XDP2_MD_IS_FRAGMENT  = 1ULL << 12,
    XDP2_MD_FIRST_FRAG   = 1ULL << 13,
    XDP2_MD_ICMP         = 1ULL << 14,
    XDP2_MD_KEYID        = 1ULL << 15,
    XDP2_MD_TCP_OPTIONS  = 1ULL << 16,
    XDP2_MD_ARP          = 1ULL << 17,
    XDP2_MD_GRE          = 1ULL << 18,
    XDP2_MD_GRE_PPTP     = 1ULL << 19,
    XDP2_MD_MPLS         = 1ULL << 20,
};
#define XDP2_MD_FIELDS_ALL ((__u64)~0ULL)
```

### 3. IR plumbing (`src/tools/compiler/include/xdp2gen/`)

- `graph.h`: new `unsigned long long used_field_mask = 0;` on
  the `parser` vertex_property.
- `ast-consumer/graph_consumer.h`: captures `.used_field_mask`
  from the parser-config init list. Handles both
  `IntegerLiteralClass` (literal `0`) and
  `BinaryOperatorClass` (constant expressions like
  `X | Y | Z`) via `isIntegerConstantExpr`.
- `python_generators.h`: surfaces both `used_field_mask`
  (integer) and `used_field_names` (Python list of strings)
  to the template. When mask is 0, the list contains all
  21 field names for backward compatibility.

### 4. Codegen gate (`src/templates/xdp2/mono_def.template.c`)

The R3.3.4 inline metadata-transfer block now gates each
transfer on whether its name is in `root['used_field_names']`:

```python-template
<!--(for t in graph[node]['metadata_transfers'])-->
    <!--(if t['name'] in root['used_field_names'])-->
        /* typed-store or memcpy emit, unchanged */
    <!--(else)-->
        /* R8-Option C: <name> elided per parser used_field_mask. */
    <!--(end)-->
<!--(end)-->
```

When the parser doesn't declare a mask (default 0 → all-names
list), every transfer is emitted exactly as before. When it
declares a narrow mask, transfers writing fields outside the
mask are elided.

## Verification

### Mechanism test (temporary mask, then reverted)

To verify the elision actually fires, temporarily set the
flow-dissector parser's mask to exclude `KEYID`:

```c
.used_field_mask = XDP2_MD_FIELDS_ALL & ~XDP2_MD_KEYID
```

(Expressed via explicit `X | Y | Z` chain — `& ~` would also
work; the AST consumer handles both via `isIntegerConstantExpr`.)

Generated `parser.mono.c` after this change:
- 4 elision markers added (matches the number of nodes that
  write `keyid` in the in-tree graph: gre, gre_keyid,
  gre_pptp_key, mpls)
- R3.3.4 emit count drops 154 → 150
- Specifically `keyid` transfers are missing; others retained

Reverted before commit — the in-tree flow-dissector parser
needs the full metadata for the parity contract (the matrix
checks per-protocol that `keyid` is set correctly on
GRE/MPLS/L2TP pcaps).

### Production shipment

Default behavior on the in-tree flow-dissector parser:
- `used_field_mask` not set (= 0 = "all fields")
- 154 R3.3.4 transfers emitted (unchanged from pre-Option-C)
- Parity-gate: 32/32 OK
- Protocol-coverage-matrix: 4914 cells, 0 OK!N, 0 REJ-undeclared,
  0 REJ-unexpected
- mono-perf ceiling: 0 violations

## What's NOT in phase 1

This phase only gates the **R3.3.4 inlineable transfers**
(those the LLVM IR analysis identified as byte-aligned
constant-width copies). Currently 4 distinct field names
appear in this category: `eth_proto`, `ip_proto`, `keyid`,
`ports`. The other ~17 fields are written via per-protocol
`ops.extract_metadata` callbacks defined in
`src/include/xdp2/parser_metadata.h` (the `XDP2_METADATA_TEMP_*`
macros). Those callbacks are not generated per-parser; they're
hand-written and write all-fields-or-none per call.

Phase 2 (deferred) would extend the gating to those callbacks
by either:
1. Generating per-parser `extract_metadata` functions with
   mask-gated writes (requires significant codegen extension).
2. Or adding a `__u64 used_fields` parameter to the existing
   callback signature and gating each write at runtime
   (gcc constant-folds it away under static-const proto_def).

Either is a larger project than phase 1. Phase 1 is the
foundation: API, IR, codegen plumbing, end-to-end mechanism
test. Phase 2 can build on it incrementally as use-cases
arrive.

## Forward-looking value

On Zen 1 (our current testbed):
- The 21-byte payload of an inlineable transfer is one mov
  instruction at the same IPC. The store buffer absorbs the
  scatter pattern (per R6 finding). Narrowing the mask saves
  some bytes of struct space but not ns/pkt.

On smaller cores (anticipated):
- In-order ARM (Cortex-A53, A55): ~10-entry store buffer.
  Scatter writes to many metadata fields fill the store
  buffer faster, causing pipeline stalls. Smaller per-packet
  write count reduces stalls.
- Embedded RISC-V: similar.
- Older Intel (Atom, Skylake-X energy-efficient cores):
  smaller store buffers than Zen 1's.
- ARM Neoverse N1/V1: 40-entry store buffer, similar to Zen 1;
  smaller benefit.

The infrastructure ships now so that when other CPU testbeds
become available, parsers can opt into narrower masks without
codegen-tool changes.

## How to use

For a specialised parser that only needs the L4 5-tuple
(no L2 addresses, no ICMP, no GRE-specific fields), declare:

```c
XDP2_PARSER(my_l4_parser, "L4-only flow dissector",
    root_node,
    (.frame_size = sizeof(struct xdp2_metadata_all),
     .max_frames = 0,
     .used_field_mask =
         XDP2_MD_ADDR_TYPE | XDP2_MD_ADDRS |
         XDP2_MD_IP_PROTO | XDP2_MD_PORTS |
         XDP2_MD_L3_OFF | XDP2_MD_L4_OFF
    )
);
```

The codegen will elide eth_addrs / l2_off / flow_label / vlan /
keyid / icmp / tcp_options / arp / gre / gre_pptp / mpls
inlineable transfers. The per-protocol `ops.extract_metadata`
callbacks still write those fields, but the inline R3.3.4
transfers (eth_proto, ip_proto, keyid, ports) are gated.

For an even narrower struct, the parser can use a smaller
metadata-type definition (not requiring all `XDP2_METADATA_*`
fields). That's phase 2 work.

## Decision

R8-Option C phase 1 **ships** as infrastructure foundation.
- Zero behavior change on existing parsers
- Mechanism end-to-end verified
- Correctness gates clean (32/32 + 4914/4914)
- Forward-looking value for future CPU testbeds and
  specialised parsers

Phase 2 (per-parser callback codegen) deferred. The phase 1
foundation makes it incremental.

## Files

- `findings.md` — this analysis
- Code changes:
  - `src/include/xdp2/parser_types.h` (API addition)
  - `src/include/xdp2/parser_metadata.h` (enum + name map)
  - `src/tools/compiler/include/xdp2gen/graph.h`
  - `src/tools/compiler/include/xdp2gen/ast-consumer/graph_consumer.h`
  - `src/tools/compiler/include/xdp2gen/python_generators.h`
  - `src/templates/xdp2/mono_def.template.c`
  - `samples/flow_dissector/flow_dissector_parsers.h` (doc-only
    comment; no behavior change)
