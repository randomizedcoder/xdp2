# R8-Option C phase 2-a.1 — mono template kind extension

Date: 2026-05-21. Extended the mono codegen template to emit
three new transfer kinds (`constant`, `hdr_off`, `hdr_len`) in
addition to the existing `copy` kind. Adjusted the `mt_all_copy`
gate in `template.cpp` to include the new kinds.

## TL;DR

- **Infrastructure shipped**: template now emits 4 transfer
  kinds inline. Adjusted the gate accordingly. Backward-compatible.
- **Zero new nodes unlocked today.** The bottleneck for the
  9 still-failing nodes is **count mismatches in the LLVM IR
  pattern matcher**, not kind support.
- Parity gate green, matrix 4914/4914 clean.

## What changed

### Template (`src/templates/xdp2/mono_def.template.c`)

The R3.3.4 inline metadata-transfer block now branches on
`t['kind']`:

- `copy` (unchanged): typed-store or memcpy for byte-aligned
  load + [bswap] + store sequences.
- `constant` (new): write a literal value
  (e.g. `frame->addr_type = XDP2_ADDR_TYPE_IPV4`).
  Emits `*(__uN *)(metadata + dst_off) = value`.
- `hdr_off` (new): write current parse offset, computed at
  emit time as `(hdr - ctrl->pkt.start)`.
- `hdr_len` (new): write current node's computed hlen.
- `value` (unchanged): falls back to indirect call (complex
  computations not inlineable today).

### Gate (`src/tools/compiler/src/template.cpp`)

```python
# Before:
mt_all_copy = len(mts) > 0 and all(t.get('kind') == 'copy' for t in mts)

# After:
_supported_kinds = ('copy', 'constant', 'hdr_off', 'hdr_len')
mt_all_copy = len(mts) > 0 and all(t.get('kind') in _supported_kinds for t in mts)
```

The variable name retained for backward compat with template
checks (`<!--(if graph[node]['mt_all_copy'])-->`).

## Diagnostic before/after

**Before phase 2-a.1** (post phase 1):
- 9 nodes with `mt_full_coverage=True`
- Nodes failing with `mt_all_copy=False` (kind issue): 2
  (ipv4_node 3/6, ipv6_node 3/4)
- Nodes failing with `mt_all_copy=True` (count issue): 7

**After phase 2-a.1**:
- 9 nodes with `mt_full_coverage=True` (unchanged)
- Nodes failing with `mt_all_copy=False`: **0** ✓
- Nodes failing with `mt_all_copy=True` (count issue): 9
  (was 7, now includes the 2 that flipped from kind-issue to
  count-issue)

The kind extension successfully resolved the kind-issue cases.
But those same nodes ALSO have count mismatches, so they
still don't qualify.

## The remaining 9 count-mismatch nodes

### Too-few transfers (matcher missed IR stores)

| node | transfers/stores | missing | notes |
|---|---|---|---|
| ipv4_node | 3/6 | 3 | is_fragment, first_frag bitfields, l3_off via hdr_offset |
| ipv6_node | 3/4 | 1 | likely flow_label's `ntohl(*be32) & 0x000FFFFF` |
| ipv6_frag_node | 1/3 | 2 | is_fragment + first_frag bitfields |
| mpls_node | 1/2 | 1 | likely the BSWAP+BIT_MANIP composite |
| tipc_node | 1/2 | 1 | likely the BSWAP+CONST_ADDR_TYPE composite |

### Too-many transfers (duplicate match)

| node | transfers/stores | excess | notes |
|---|---|---|---|
| icmpv4_node | 4/3 | 1 | icmp_has_id sentinel CONDITIONAL splits across IR variants |
| icmpv6_node | 4/3 | 1 | same |
| arp_node | 4/3 | 1 | likely STRUCT_FIELD writes matched by multiple patterns |
| rarp_node | 4/3 | 1 | same |

## What unlocking each would take

### Too-few cases — add new patterns

Each requires identifying the unmatched IR shape and adding a
pattern to `patterns.h` / `patterns.h2`:

- **bitfield writes** (is_fragment, first_frag, vlan_count):
  bitfield is read-modify-write in IR. Need a pattern that
  recognises the read+OR+store sequence as a single transfer.
  ~30-50 LoC. Unlocks ipv4_node, ipv6_frag_node, and several
  vlan-related nodes.

- **complex computed writes** (flow_label):
  `*be32 → ntohl → AND mask → store` is a bswap-then-AND
  sequence. Could add a `transfer_with_mask` pattern.
  ~40-60 LoC. Unlocks ipv6_node.

- **header-length offset writes** (l3_off):
  `frame->l3_off = xdp2_parse_hdr_offset(hdr, ctrl)` —
  function call. The `metadata_pattern_write_header_offset`
  exists but may not be matching all cases. Audit needed.

### Too-many (duplicate match) — deduplicate

The pattern matcher matches the same IR store via multiple
patterns. Options:

1. **Add disjoint constraints** to patterns so each IR store
   matches at most one pattern. Risky — could break existing
   matches.
2. **Post-match dedup** in graph.h: group matches by
   `(dst_off, length)` and pick one canonical match per group.
   Safer. ~20-30 LoC.

For icmpv4/icmpv6 specifically, the icmp_metadata source has:
```c
frame->icmp.type = ...;
frame->icmp.code = ...;
if (icmp_has_id(p[X]))
    frame->icmp.id = ...;
```

The `if` branch produces 2 IR variants (taken / not-taken),
each writing `frame->icmp.id`. The matcher matches BOTH
variants as separate transfers — but the source has only one
LOGICAL transfer (conditional). Cleanest fix: deduplicate by
destination offset.

## Decision

This session's work (~50 LoC template + 5 LoC gate) shipped
the kind-extension infrastructure. Forward-looking value:
when the IR matcher's count-mismatch issues are fixed (next
session's work), the kind extension will automatically pick
up `constant`/`hdr_off`/`hdr_len` transfers without further
template changes.

Phase 2-a.1 work split:
- ✅ **kind extension** (this commit): template + gate update, structural
- ⏳ **bitfield pattern** (next 1 session): unlocks ipv4_node, ipv6_frag_node
- ⏳ **flow_label mask pattern** (next 1 session): unlocks ipv6_node
- ⏳ **dedup logic** (next 1 session): unlocks icmpv4/icmpv6/arp/rarp

Total estimated remaining: 2-3 sessions for ~7 more nodes
unlock. Or commit to 2-a.5 (per-parser inline extractor codegen,
~3 days) for clean rewrite.

## Correctness

- Parity-gate: 32/32 OK
- Protocol-coverage-matrix: 4914 cells, 0 OK!N, 0 REJ-undeclared,
  0 REJ-unexpected
- Mono-perf ceiling: 0 violations

## Files changed (this commit)

- `src/templates/xdp2/mono_def.template.c` — extended R3.3.4
  inline emit block from 1 kind to 4 kinds (+58 LoC)
- `src/tools/compiler/src/template.cpp` — `mt_all_copy` gate
  relaxed to `mt_all_supported` (5 LoC)

## Reproducing the diagnostic

```sh
nix build .#flow-dissector-matrix-artifacts
DRV=$(nix path-info --derivation .#flow-dissector-matrix-artifacts | tail -1)
nix log "$DRV" 2>&1 | grep "mt_full_coverage=False" |
    grep "mt_all_copy=True" | head -20
```
