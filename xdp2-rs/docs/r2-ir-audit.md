# R2 — IR Audit for Monolithic Codegen

## Goal

Before R3 (mono_parser.template.c), confirm the xdp2-compiler IR has
the information needed to emit a single specialised function per
parser graph — kernel-flowdis-shaped output instead of the current
N-per-node-helper structure.

## TL;DR

**The IR is largely sufficient.** Per-node metadata, dispatch
expressions, edges, and lengths are all present in
`xdp2gen::vertex_property`. The Python template already gets most of
what it needs.

**Three small gaps** to close before R3:

1. **3 of 5 `metadata_transfer` variants are not exposed to
   Python.** Currently only `llvm::metadata_transfer` (bit-level copy)
   and `llvm::metadata_write_constant` make it to the template; the
   3 missing variants are `metadata_write_header_offset`,
   `metadata_write_header_length`, `metadata_value_transfer`. Mono
   codegen needs all 5.
2. **No `inline_shape` annotation per vertex.** R3 needs a per-node
   "emit-as-label vs emit-as-direct-call vs emit-as-tail-of-graph"
   decision. Currently the template treats every node identically
   (each becomes a `static inline` function).
3. **No hot-edge / cold-edge ordering.** The `out_edges` list is the
   protocol-table order (whatever the parser .c file declared); R3
   would benefit from sorting common protocols first so the emitted
   switch has its hot arms early.

R2.3 (a validator pass that rejects post-handlers / okay / fail /
counters / keys) is straightforward — those fields already exist on
`xdp2gen::parser` and the vertex_property.

## What the IR has (no work needed)

`xdp2gen::vertex_property` already carries per-node:

| Field | Purpose | R3 use |
|---|---|---|
| `name`, `parser_node`, `metadata`, `handler`, `post_handler` | XDP2 identifiers | label naming |
| `table`, `tlv_table`, `flag_fields_table` | proto-table refs | edge enumeration |
| `proto_min_len` | required header length | inline length check |
| `proto_decl_name`, `proto_name`, `proto_len`, `proto_next_proto` | protocol metadata | direct field access |
| `next_proto_data` (`packet_buffer_offset_masked_multiplied`) | bit_offset + bit_size + bit_mask + multiplier for next-proto extraction | inline `next` computation |
| `len_data` (`packet_buffer_offset_masked_multiplied`) | dynamic header length expression | inline `hlen` computation |
| `flags_data` | flag-fields extraction | flags branches |
| `cond_exprs` | conditional dispatch | guard emission |
| `metadata_transfers` (vector of 5-variant transfers) | per-field metadata writes | direct stores |
| `overlay`, `encap` | structural flags | encap bookkeeping |
| `unknown_proto_ret`, `wildcard_proto_node` | default-arm behaviour | switch fallback |
| `out_edges` (via boost graph) | next-protocol edges | switch arms |

The bytes of code that the existing `_opt` template puts into a
per-node function (length check, metadata extraction via callback,
handler, encap bookkeeping, next-proto switch) are all derivable from
this IR without consulting the original .c source.

`xdp2gen::edge_property` carries `{macro_name, parser_node, back,
macro_name_value}` — enough to emit `case ETH_P_IP: goto parse_ipv4;`
arms.

`xdp2gen::parser` carries the root parser config (root node, okay/fail/
atencap exit nodes, max_nodes / max_encaps / max_frames / metameta_size
/ frame_size / num_counters / num_keys).

## Gap 1 — Python binding for `metadata_transfer` variants

`src/tools/compiler/include/xdp2gen/python_generators.h:370-389` only
emits Python dicts for two of the five variants of `metadata_transfer`:

```cpp
python::list metadata_transfers;
for (auto &&m : v.metadata_transfers) {
    python::dict transfer;
    if (auto p = std::get_if<xdp2gen::llvm::metadata_transfer>(&m.transfer)) {
        transfer.set("dst_off", static_cast<int>(p->dst_bit_offset));
        transfer.set("name", m.name);
        transfer.set("src_off", static_cast<int>(p->src_bit_offset));
        transfer.set("length", static_cast<int>(p->bit_size));
    } else if (auto p = std::get_if<xdp2gen::llvm::metadata_write_constant>(&m.transfer)) {
        transfer.set("value", static_cast<int>(p->value));
        transfer.set("name", m.name);
        transfer.set("dst_off", static_cast<int>(p->dst_bit_offset));
        transfer.set("length", static_cast<int>(p->bit_size));
    }
    metadata_transfers.append(std::move(transfer));
}
```

The 3 missing variants exist in `metadata_transfer::transfer`:

```cpp
std::variant<llvm::metadata_transfer,
             llvm::metadata_write_constant,
             llvm::metadata_write_header_offset,     // ← missing
             llvm::metadata_write_header_length,     // ← missing
             llvm::metadata_value_transfer>          // ← missing
    transfer;
```

For mono codegen these become:
- `metadata_write_header_offset` → emit `_meta->l3_off = hdr - pkt_start;` (or similar)
- `metadata_write_header_length` → emit `_meta->ip_hlen = hlen;`
- `metadata_value_transfer` → emit a value-level field assignment (e.g., the result of a small computation rather than a direct memcpy)

**Fix:** add `else if` branches in `make_python_object(graph_t graph,
vertex)` and tag each dict with a `kind` field
(`"copy"|"constant"|"hdr_off"|"hdr_len"|"value"`). Mono template
dispatches on `kind`.

## Gap 2 — `inline_shape` annotation

Today every parse node is emitted as a `static inline __unused() int
__@!parser_name!@_@!name!@_xdp2_parse(...)`. The compiler decides
whether to inline based on call-site heuristics; LTO with the current
graph shape leaves 12+ direct calls in the entry function (per R1
findings).

R3 needs the codegen to *force* the inlining at the source level by
emitting a `parse_<node>:` label inside the entry function and using
`goto parse_<next>:` for state transitions. For graphs that don't fit
the mono mold (post-handlers / exit nodes / TLVs / flag fields), the
fallback is the existing per-function emit.

The shape decision is per-node:
- `MONO_LABEL` — emit as label inside the entry function (~80%
  of nodes on typical flow_dissector graphs)
- `DIRECT_CALL` — emit as separate function called via direct call
  (used for tail nodes the IR can't fully flatten, e.g. TLV walks
  that depend on runtime length)
- `EXIT` — emit as direct call to an exit-node helper (okay/fail/
  atencap nodes, retained for R3.5 step)

This annotation can be derived from existing fields:
- `if (post_handler != "")` → not mono-eligible → DIRECT_CALL
- `if (len(tlv_nodes) > 0)` → DIRECT_CALL (or inline-loop, deferred
  to R3 phase 2)
- `if (encap)` → MONO_LABEL but with encap bookkeeping emitted
  inline
- otherwise → MONO_LABEL

**Fix:** add a derived `inline_shape` field on `vertex_property` and
expose it in the Python dict. Computed by walking the graph once
during graph construction.

## Gap 3 — Hot-edge ordering

The existing template emits `switch (type) { case A: ...; case B: ...; }`
arms in *declaration order* — whatever order the user wrote in
`XDP2_MAKE_PROTO_TABLE(...)`. gcc usually reorders the switch into a
balanced tree or jump table, so order doesn't *correctness*-matter,
but for branch-prediction-cost, the hot path (eth→ipv4→tcp/udp)
should be visited first.

S2 already addressed this in `parser_big.c` and `parser_simple_hash.c`
by hand-reordering the ipv6_table to put TCP/UDP first. R3's codegen
can do the same automatically.

Hot-edge data sources:
- **Static heuristic:** known common protocols (IPv4, IPv6, TCP, UDP,
  HTTPS, DNS) get ordered first
- **Workload-driven:** consume a chain-histogram JSON to drive
  ordering (deferred to R3 phase 2)

For R3 phase 1 a small static lookup table of "common protocol
values" (ETH_P_IP, ETH_P_IPV6, IPPROTO_TCP, IPPROTO_UDP, etc.) is
sufficient.

**Fix:** when emitting the `switch` block, sort the edges with the
static heuristic. Add a `hot_priority` integer per `edge_property`
(0 = unknown, higher = hotter), then sort descending before emit.

## R2.3 — Validator pass for fast-path eligibility

Parsers that satisfy ALL the following are mono-eligible:

| Check | Existing IR field |
|---|---|
| No post-handlers | `for v in vertices: v.post_handler == ""` |
| No okay/fail/atencap exit nodes | `!parser.okay_target_set && !parser.fail_target_set && !parser.atencap_target_set` |
| No counters | `parser.num_counters == 0` |
| No keys | `parser.num_keys == 0` |
| No frame-storage growth | `parser.max_frames <= 1` |
| Bounded graph depth | `vertice_leveler::max_level < CONFIG_MAX_MONO_DEPTH` (sensible default: 32) |

The first 5 checks already exist as IR fields. Only the graph-depth
limit is a new check, and `vertice_leveler` already computes the
needed max_level.

Validator runs in `main.cpp:430-580` between graph construction and
codegen. On failure: emit the generic codegen with a comment
explaining why mono was rejected. On success: emit both
`XDP2_PARSER_OPT` (status quo for testing) AND `XDP2_PARSER_MONO`.

## Files to touch in R2 (estimated)

| Sub-task | File | Lines |
|---|---|---:|
| R2.1: expose 3 missing transfer variants | `src/tools/compiler/include/xdp2gen/python_generators.h` ~370-389 | ~40 |
| R2.2: add `inline_shape` to vertex_property + computation | `src/tools/compiler/include/xdp2gen/graph.h` ~195 (struct), + a graph-walker function | ~60 |
| R2.2: expose `inline_shape` to Python | `python_generators.h` ~341 | ~5 |
| R2.2: hot-edge sort | `python_generators.h` (edge list emission helper) | ~30 |
| R2.3: validator pass | `src/tools/compiler/src/main.cpp` ~430 | ~80 |
| R2.4: update consumers (only xdp2-compiler itself) | n/a | 0 |
| **Total** | | **~215 LoC** |

## Conclusion

R2 is much smaller than the original plan estimated (~3 days). The IR
is already in great shape — the major content for monolithic codegen
is all there. The 3 small additions (Python binding for 3 transfer
variants, inline_shape per-vertex, hot-edge sort) are mechanical.

The validator pass (R2.3) is the most "design-decision" part — it
defines what counts as mono-eligible. Conservative defaults
(reject any graph with post-handlers / exit-nodes / counters / keys /
frame-growth / depth > 32) are the right starting point; R3 can
relax these as the template handles more cases.

**R2's main impact on the R3 plan**: nothing significant changes.
The mono template can be written as described in the R1-R8 plan,
consuming the IR as it stands plus the small additions above. The
Python dict shape needs no major redesign.
