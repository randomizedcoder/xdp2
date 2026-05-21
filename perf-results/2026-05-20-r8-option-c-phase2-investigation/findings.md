# R8-Option C phase 2-a investigation

Date: 2026-05-20. Investigation to scope phase 2-a: extend
the R3.3.4 LLVM IR analysis to recognize more extractor
patterns, so more parse nodes hit `mt_full_coverage=true`
and benefit from phase 1's mask gating.

## Goal

Currently only 4 distinct field names qualify for inline
emission (eth_proto, ip_proto, keyid, ports). The other ~17
fields are written via per-protocol `ops.extract_metadata`
callbacks that the codegen calls indirectly. Phase 2-a would
extend coverage so more fields can be mask-gated.

## Idiom classification of all 30 `XDP2_METADATA_TEMP_*` macros

Extracted from `src/include/xdp2/parser_metadata.h` by AWK
scan looking for distinct C idioms in each macro body.

### By difficulty for LLVM pattern matching

| difficulty | count | macros | reason |
|---|---|---|---|
| **easy** (no special idiom) | 14 | `gre`, `gre_*` (8 variants), `vlan_8021AD`, `vlan_8021Q`, `ports`, `sack_1..4`, `tcp_option_window_scaling`, `l2tp_v3`, `ipv6_eh`, `ipv6_frag_noinfo`, `esp`, `ip_overlay` | Simple typed field writes; existing patterns should match |
| **memcpy** (existing pattern matches) | 10 | `ether`, `ether_off`, `ipv4`, `ipv4_addrs`, `ipv6`, `ipv6_addrs`, `arp_rarp`, `ether_off`, `ports_off`, `tcp_option_mss`, `tcp_option_timestamp` | `metadata_pattern_transfer_memcpy_lhs_gep_rhs_gep` exists; should work but may fail count match |
| **bswap** (existing pattern matches) | 6 | `tipc`, `tcp_option_mss`, `tcp_option_timestamp`, `ipv6_frag`, `ipv4`, `arp_rarp` | `metadata_pattern_transfer_lhs_bswap_load_gep_rhs_gep` exists |
| **header-offset** (existing pattern matches) | 3 | `ether_off`, `ports_off`, `ipv4`, `ipv6` | `metadata_pattern_write_header_offset` exists |
| **const-write** | 4 | `ipv4`, `ipv4_addrs`, `ipv6`, `ipv6_addrs`, `tipc` (CONST_ADDR_TYPE) | `metadata_pattern_write_constant` exists |
| **bitfield** (no current pattern) | 1 | `vlan_set_tpid` | Bitfield writes compile to read-modify-write in IR; needs new pattern |
| **conditional** (no current pattern) | 2 | `icmp`, `mpls` | `if (...)` arms produce branch IR; structural mismatch with straight-line patterns |
| **complex multi-step** | 1 | `ipv4` (HDR_OFFSET + CONST + SIMPLE_LOAD + MEMCPY + CONDITIONAL + BSWAP) | Combination of patterns + the `is_fragment` / `first_frag` conditionals |

### Key finding

**Most existing macros have pattern support, but
`mt_full_coverage` requires STRICT EQUALITY of `len(mts) ==
store_count`**. If the IR has even one store the matcher
misses (a debug assert, a TBAA marker, a sub-field write the
pattern doesn't capture), the whole macro falls back to
indirect call.

The 14 "easy" macros likely fail due to small mismatches
between the C source and the IR shape. Each one needs:
1. Identification of the specific IR store(s) the matcher
   misses
2. Either a new pattern OR a small refactor of the C source
   to produce IR the existing patterns match

### Difficulty of extending each pattern type

| extension | LoC | risk | expected unlock |
|---|---|---|---|
| **store-count audit + matcher fix per macro** | ~10-20 LoC × 14 macros = 140-280 LoC | low (each macro is independent) | 14 macros gain mt_full_coverage; ~10 new fields mask-gateable |
| **bitfield pattern** | 30-50 LoC | medium (read-modify-write is multi-op) | `vlan_set_tpid` (1 macro) |
| **conditional write pattern** | 80-150 LoC | high (branch-aware matching) | `icmp` and `mpls` (2 macros) |
| **per-parser inline extractor codegen** | 300-500 LoC | high (refactors extract_metadata calling convention) | All 30 macros gateable; clean architecture |

## Recommended phase 2-a path

**Iterative, smallest-first**:

### 2-a.1 (~1 session): store-count audit + minimal matcher additions

For each of the 14 "easy" macros that DON'T currently
mt_full_coverage:
1. Build with verbose IR diagnostic to see `metadata_transfers=N/M`
2. Identify the unmatched store(s)
3. Either add a small matcher extension or refactor the source

This is the highest-value-per-LoC work. Each macro is
independent. Can be done incrementally.

### 2-a.2 (~1 session): memcpy count-match audit

The 10 memcpy macros may already have `mt_full_coverage` if
each memcpy call produces exactly 1 transfer in the IR. If
gcc/clang unrolls memcpy into multiple stores, count
mismatches. Investigate per macro; if unroll happens, either
mark memcpy patterns as "1 transfer regardless of stores" or
disable memcpy unrolling for these calls.

### 2-a.3 (~1 day): bitfield pattern

Only one macro (`vlan_set_tpid`) needs it. Low impact unless
VLAN traffic is the target.

### 2-a.4 (~2 days): conditional pattern

`icmp` and `mpls` extractors. Higher value (icmp is per-pkt
on ICMP traffic; mpls on MPLS). Branch-aware pattern
matching is structurally different from current patterns;
substantial new code.

### 2-a.5 (~3 days): per-parser inline extractor codegen

The architecturally cleanest solution. Codegen emits the
metadata extractor INLINE in the per-node body, gated by the
parser's mask, instead of calling the per-protocol macro.
Bypasses the IR-matcher entirely.

Requires:
- A new declarative spec for what each per-protocol extractor
  does (field, src_offset, size, byte-swap, conditional)
- Mono template emits inline writes from the spec
- Backward compat: macros stay for non-mono parsers

Most work, highest leverage.

## Decision matrix

| path | session cost | expected unlock | risk |
|---|---|---|---|
| pause Option C at phase 1 | 0 | 0 (phase 1 ships) | low |
| 2-a.1 (audit + minor matcher) | 1 | ~10 fields | low |
| 2-a.1 + 2-a.2 | 2 | ~15 fields | low |
| 2-a.1 + 2-a.2 + 2-a.3 | 3 | ~16 fields | medium |
| 2-a.1 through 2-a.4 | 5 | ~18 fields (all but combinations) | high |
| 2-a.5 (clean rewrite) | 3 | all 30 fields | high |

## Recommendation

**2-a.5** (per-parser inline extractor codegen) IS the
cleanest long-term solution the user requested. Once built,
all 30 fields are gateable without per-macro investigation
work. The IR-matcher path becomes secondary (only needed for
parsers that explicitly opt out of the new codegen).

But 2-a.5 is ~3 days, not session-sized. Honest scope.

**2-a.1** (audit + minor matcher extensions) is session-sized
and unlocks ~10 fields. Lower architectural elegance but
higher LoC-per-perf ratio in the short term.

User to choose between:
- (A) ship phase 1, defer everything until a dedicated 2-a.5 day
- (B) do 2-a.1 in next session to unlock 10 more fields via
  patch-based work
- (C) commit to 2-a.5 multi-day project now

## What this investigation produced (no code change)

This doc itself is the deliverable. Code changes: none.

The investigation surfaced:
1. Memcpy pattern already exists in `patterns.h2:1266`
2. 14 macros are "easy" candidates (no special idiom)
3. Per-macro audit is the unblocking work
4. The cleanest 2-a.5 path is well-scoped and architecturally clean
