# R7 — Per-parser tailored metadata struct (Plan)

## Context

R5 and R6 both delivered null perf results because gcc's
optimizer + Zen 1's store buffer + 8-way L1d absorbed every
template-level optimisation we threw at them. The 280 instr/pkt
gap to rust-mono on `vxlan-k8s-pure` is structural: **rust-mono
extracts fewer metadata fields per packet than c-xdp2-mono
does, and that's the entire 50 ns**. Layout changes can't fix
store count.

R7 closes the gap by making the codegen emit a **per-parser
metadata struct** containing ONLY the fields the parser's graph
actually writes. For `flow_dissector_l2` that would drop the
struct from 192 B → ~57 B and eliminate every write to the
unused tcp_options/arp/gre/mpls tail.

This is the audit's Option C (`perf-results/2026-05-19-r6-audit
/audit.md`). Per the R6 results doc, R7 is the only remaining
direction with real ns/pkt headroom.

## Pre-existing IR already has what we need

`src/tools/compiler/include/xdp2gen/llvm/metadata_pattern.h`:

```cpp
struct metadata_transfer {
    std::size_t src_bit_offset, dst_bit_offset, bit_size;
    bool is_frame = false;
    /* ... */
};

struct metadata_write_constant { /* dst_bit_offset, bit_size */ };
struct metadata_write_header_offset { /* dst_bit_offset, bit_size */ };
struct metadata_write_header_length { /* dst_bit_offset, bit_size */ };
struct metadata_value_transfer { /* similar */ };
```

The IR already knows every metadata write's `dst_bit_offset`
and `bit_size`. Per parser, the set of (offset, size) pairs
across all `metadata_transfer`s in all reachable nodes IS the
"used field set". **No new IR extraction needed.** The data is
sitting in `graph_consumer` already.

## Two strategies

### Strategy A — Per-parser narrow struct (codegen emits a new struct type)

For each parser, the codegen computes the used-field set and
emits:

```c
/* Generated for parser_xxx */
struct xxx_metadata {
    /* Only fields actually written by parser_xxx's graph */
    __u8 addr_type;
    __u8 eth_addrs[12];
    __be16 eth_proto;
    __u8 ip_proto;
    __be16 ports[2];
    union { __be32 v4_addrs[2]; struct in6_addr v6_addrs[2]; } addrs;
};

/* Generated extractor wrapping the original extract_metadata
 * but writing to xxx_metadata via the same dst_bit_offset
 * (which still works because new struct fields are at the
 * same offsets via __attribute__((packed)) + manual layout).
 */
```

The user code at the call site uses `struct xxx_metadata` for
the parser. Every other struct-pointer site needs updating.

**API impact**: large. Every `struct xdp2_metadata_all *` site
becomes `void *` or a parser-typed pointer. `frame_size = sizeof(...)`
in `xdp2_parser_def` already takes the struct size as a number,
so that adapts naturally.

**LoC estimate**: ~400 LoC across IR (field-set computation),
codegen (struct emit + extractor adapter), template, parser
configuration.

### Strategy B — Same struct, codegen elides cold writes

Keep `struct xdp2_metadata_all` 192 B as-is. The codegen, per
parser, knows which `dst_bit_offset`s are actually written by
the parser graph. For nodes whose `extract_metadata` IR
contains writes to fields the parser never reads downstream,
emit a NO-OP instead of the actual write.

Simpler — but the question is "which fields does the parser
read downstream?". The answer is: typically none, because
metadata is consumer-side. The parser writes; the application
reads. Without consumer-side IR analysis (which we don't have),
we don't know which fields the application cares about.

**However**: the `xdp2_parser_def` could declare its used field
set explicitly. The codegen would then ONLY emit writes to
those fields, even if the proto_def's extract_metadata function
writes more. This requires:

1. Adding `enum used_fields { ETH_PROTO=0x1, IP_PROTO=0x2, ... };`
2. Adding `__u64 used_fields_mask` to `xdp2_parser_def`
3. Codegen filters every metadata write against the mask

**API impact**: small. Each parser declares its used field mask
as part of its config. No struct type changes.

**LoC estimate**: ~150 LoC.

**Catch**: this doesn't shrink `sizeof(struct xdp2_metadata_all)`,
so per-frame cacheline cold-write pressure stays the same.
But the WRITE COUNT drops, which is what matters for instr/pkt.

### Recommendation

**Phase 1 — Strategy B** (mask-based write elision). Smaller
API surface, faster to implement, directly attacks the
instruction count. Measure on hp2/hp5.

**Phase 2 — Strategy A** (per-parser struct), only if Strategy
B's measured delta plateaus before closing the gap to
rust-mono. Strategy A buys the cacheline savings that Strategy
B leaves on the table.

## Phase table

| # | Phase | Scope | Files | LoC | Risk |
|---|---|---|---|---:|---|
| A | Parser-def field mask | Add `__u64 used_field_mask` to `xdp2_parser_def`; default = all-fields = backward-compatible | `src/include/xdp2/parser.h`, `src/include/xdp2/proto_defs.h` | 30 | Low |
| B | Codegen filter | In mono template + opt template, gate each `metadata_write_*` IR variant against the parser's mask. If field not in mask, emit no-op (or empty block). | `src/templates/xdp2/mono_def.template.c`, `src/templates/xdp2/c_def.template.c`, `src/tools/compiler/src/template.cpp` | 80 | Medium |
| C | flow-dissector-l2 declares its mask | Set `used_field_mask = ETH_PROTO|ETH_ADDRS|IP_PROTO|ADDR_TYPE|L3_OFF|L4_OFF|PORTS|ADDRS|FLOW_LABEL|VLAN|VLAN_COUNT|IS_FRAGMENT|FIRST_FRAG|ICMP` (basically everything except gre/gre_pptp/arp/tcp_options/mpls) | `samples/flow_dissector/flow_dissector_parsers.h` | 5 | Low |
| D | Verify + sweep | parity-gate, matrix, hp2/hp5 sweep on all 6 workloads | (no code) | 0 | Low |
| E (conditional) | Per-parser narrow struct (Strategy A) | Only if D shows <10 ns/pkt drop on hp5 vxlan | (large) | 400 | High |

**Total Phase A-D: ~115 LoC + verification.** Phase E only if
warranted.

## Phase A — Parser-def field mask

Add to `struct xdp2_parser_def`:

```c
enum xdp2_metadata_fields {
    XDP2_MD_ETH_PROTO    = 1ULL << 0,
    XDP2_MD_ETH_ADDRS    = 1ULL << 1,
    XDP2_MD_IP_PROTO     = 1ULL << 2,
    XDP2_MD_ADDR_TYPE    = 1ULL << 3,
    XDP2_MD_L2_OFF       = 1ULL << 4,
    XDP2_MD_L3_OFF       = 1ULL << 5,
    XDP2_MD_L4_OFF       = 1ULL << 6,
    XDP2_MD_PORTS        = 1ULL << 7,
    XDP2_MD_ADDRS        = 1ULL << 8,
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
    XDP2_MD_ALL          = ~0ULL,  /* default */
};

struct xdp2_parser_def {
    /* ... existing fields ... */
    __u64 used_field_mask;
};
```

Default = `XDP2_MD_ALL` keeps all existing parsers unchanged.

## Phase B — Codegen filter

In `mono_def.template.c`, the existing metadata-write blocks
(R3.3.4 inline `memcpy()` emit, R3.3.5 npi_simple, etc.) gate
each `metadata_transfer` IR variant on a parser-mask check at
template generation time.

The template preprocessing in `template.cpp` would map each
transfer's `dst_bit_offset` to its corresponding `XDP2_MD_*`
flag via a lookup table that mirrors the
`XDP2_METADATA_<name>` offsets in `parser_metadata.h`. The
mapping:

| dst_bit_offset (bits) | field | flag |
|---|---|---|
| 0 | addr_type | XDP2_MD_ADDR_TYPE |
| 8-9 | bitfields (is_fragment, first_frag, vlan_count) | corresponding flags |
| 16-111 | eth_addrs | XDP2_MD_ETH_ADDRS |
| 112-127 | l2/l3/l4_off | corresponding |
| 192-207 | eth_proto | XDP2_MD_ETH_PROTO |
| ... | ... | ... |

Generated once at codegen time as a static lookup.

For each metadata_transfer in the IR:
1. Look up the field flag from `dst_bit_offset`.
2. If `parser_def.used_field_mask & flag`, emit the write.
3. Else, emit nothing.

This requires the codegen to know the parser_def's
`used_field_mask` at compile time. Since the mask is in the
parser_def init list and the AST consumer already walks
parser_def init lists (per the R5.C work), we extend the
consumer to capture this field too.

## Phase C — flow-dissector-l2 declares its mask

```c
XDP2_MAKE_PARSER_PROGRAM(
    flow_dissector_l2_program,
    .root_node = &ether_node,
    .parser_type = XDP2_GENERIC_PARSER,
    .frame_size = sizeof(struct xdp2_metadata_all),
    .num_frames = 1,
    .used_field_mask = XDP2_MD_ETH_PROTO | XDP2_MD_ETH_ADDRS |
                       XDP2_MD_IP_PROTO | XDP2_MD_ADDR_TYPE |
                       XDP2_MD_L2_OFF | XDP2_MD_L3_OFF |
                       XDP2_MD_L4_OFF | XDP2_MD_PORTS |
                       XDP2_MD_ADDRS | XDP2_MD_FLOW_LABEL |
                       XDP2_MD_VLAN | XDP2_MD_VLAN_COUNT |
                       XDP2_MD_IS_FRAGMENT | XDP2_MD_FIRST_FRAG |
                       XDP2_MD_ICMP,
);
```

This drops `XDP2_MD_TCP_OPTIONS`, `XDP2_MD_ARP`, `XDP2_MD_GRE`,
`XDP2_MD_GRE_PPTP`, `XDP2_MD_MPLS`, `XDP2_MD_KEYID` — none of
which the flow-dissector consumer reads downstream.

Codegen now elides every TCP-options/ARP/GRE/PPTP/MPLS write
in the generated parser. Per-packet instruction count drops
by ~50-100 instructions on the rare TCP-with-options or
GRE/PPTP packet. **Net effect on https-web (no options):
likely no measurable delta** (TCP-with-options is a tiny
fraction). **Net effect on vxlan-k8s-pure**: also negligible
(vxlan doesn't trigger any of these elided writes either).

Hmm. **This is the key insight**: the workloads in the sweep
all parse plain TCP/UDP/VXLAN — none touch tcp_options, arp,
gre, gre_pptp, or mpls. So Strategy B's mask elision has
NOTHING to actually elide on our current sweep workloads.

**Strategy B is null on the workloads we measure.** Different
workloads (e.g., a TCP-options-heavy capture) would benefit,
but those aren't in the current sweep set.

## Re-evaluation — Strategy A needed for measurable delta

Going back to Strategy A: per-parser narrow struct. For
flow-dissector-l2, the narrow struct would be ~57 B vs the
current 192 B. Even though we don't WRITE the cold fields on
the current workloads (they're already write-cold post-R6),
the cold fields still occupy cachelines that the CPU may
prefetch / dirty / track in its store-buffer scoreboarding.

**But**: R6's null result already disproved that
"cacheline-touch count" maps to ns/pkt on Zen 1. So even
Strategy A may yield null on Zen 1.

The only thing that would measurably move ns/pkt is reducing
**store COUNT**. Per-packet on https-web, c-xdp2-mono writes:
- 1 addr_type
- 12 bytes eth_addrs (1-3 stores depending on inline width)
- 2 l3_off + 2 eth_proto + 1 ip_proto = 3-5 stores
- 4 ports
- 8 v4_addrs

Total ~10-15 stores. rust-mono probably has the same count or
similar. So the 280 instr/pkt gap isn't store-count on the
HOT path. It must be in:

1. **Goto-state dispatch arms** mono walks through that
   rust-mono's monomorphic match doesn't. (Switch-case
   ladder vs match-tree codegen difference.)
2. **TLV/flag_fields walker traversal** for GRE etc — even
   when there's no extracted field, the walker still
   iterates option lists.
3. **Per-node ops dispatch overhead** despite R5's NULL-ops
   trim — there are STILL devirtualised calls for non-NULL
   ops.len, ops.next_proto, etc.

## Revised recommendation

**R7 should NOT be Strategy A/B as originally planned.** The
audit's Option C predates the R5+R6 null results which showed
that struct-write count isn't the bottleneck.

The actual bottleneck on tunneled workloads is likely
**dispatch shape**: mono uses a flat goto-state machine
where rust-mono uses an enum-of-states match tree. The two
generate fundamentally different LLVM IR.

A more productive R7 would be:

- **R7-A**: profile the per-node instruction breakdown on
  c-xdp2-mono vxlan-k8s-pure via `perf record` + `perf annotate`,
  identify which generated functions/blocks consume the 280
  extra instructions.
- **R7-B**: based on R7-A findings, target the specific code
  shape that's bloated (likely the per-node `goto state_*`
  dispatch and the `proto_table` switch ladders).

This is investigation work, ~1-day effort, not a 500-LoC
codegen project.

## Phase table (revised R7)

| # | Phase | Scope | LoC | Risk |
|---|---|---|---:|---|
| A | perf-annotate sweep | `perf record` c-xdp2-mono on vxlan-k8s-pure (hp5), `perf annotate` per-function. Identify which generated code shapes consume the most instructions. | 0 (analysis) | Low |
| B | Targeted codegen fix | Based on A's findings, fix the bloated code shape — likely a template or codegen pattern change. | varies | Medium |
| C | Sweep | hp2/hp5 measurement | 0 | Low |

## Why this matters

The user has been doing this performance investigation
explicitly for Linux kernel team review. Honest reporting
matters more than chasing nominal wins:

- **R4 (TLV/flag_fields walkers)** was deferred. R7-A's
  perf-annotate might show flag_fields walker overhead is
  the actual gap, making R4 the right next phase.
- **R3.4.5 fast-path completion** captured the easy wins
  (TCP/UDP no-encap). The hard cases are tunneled traffic.
- **The kernel-team narrative is best served by**:
  c-xdp2-mono at 139 ns/pkt with full inner-5-tuple extraction
  on VXLAN, vs flowdis at 110 ns/pkt without it. That's a
  clear apples-vs-oranges story already; closing the 30 ns
  gap further is bonus.

R7 is "if we want to" not "we must to ship".

## Out of scope

- Anything that changes the user-facing API of
  `struct xdp2_metadata_all`. R6 already shipped the layout
  change; further changes to per-parser struct types would be
  a major break.
- Per-parser SIMD vectorisation. That's R8+.
- Changes to flow-dissector consumer code. The downstream
  ABI is stable.
