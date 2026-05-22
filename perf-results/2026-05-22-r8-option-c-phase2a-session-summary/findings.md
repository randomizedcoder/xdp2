# R8-Option C phase 2-a iteration session summary

Date: 2026-05-22. Continuation of "path 1: continue iteratively"
from the previous session's perf-next-steps decision matrix.

## Shipped this session

| sub-phase | what | LoC | result |
|---|---|---|---|
| 2-a.1 | template kind support (constant, hdr_off, hdr_len) | 70 | shipped (infra) |
| 2-a.2 | metadata_transfers dedup pass | 40 | shipped (correctness) |
| 2-a.3 | memcpy-counts-as-store fix | 25 attempted, reverted | exposed matcher inconsistency |

**Net node unlock**: 0 new `mt_full_coverage=True` nodes.
Still at 9 (unchanged from session start).

## What the iterative work has surfaced

Each session's incremental fix has exposed a deeper layer of
LLVM-matcher inconsistency:

### Session before this one
- Phase 1 mask infrastructure shipped
- Found: 9 nodes mt_full_coverage, 9 fail with various reasons

### This session
- **2-a.1** found: 2 nodes (ipv4, ipv6) had `mt_all_copy=False`
  because the template only emitted `copy` kind. Extending to
  4 kinds resolved the kind issue → both nodes now show
  `mt_all_copy=True` but STILL fail mt_full_coverage due to
  count mismatches (3/6, 3/4).
- **2-a.2** found: icmpv4/icmpv6 had duplicate matches (4/3).
  Dedup pass collapsed duplicates → 2/3, revealing the matcher
  MISSES the conditional id store entirely.
- **2-a.3** attempted: count memcpy intrinsics as stores. This
  REGRESSED ether_inner_node (1/1 → 1/2) because the matcher
  doesn't reliably catch every memcpy. Reverted.
- **arp investigation** (no commit): dumped LLVM IR for
  arp_metadata. 5 logical writes (3 Store + 2 memcpy). Matcher
  finds 4 — one memcpy is matched, one isn't. Root cause
  requires verbose-debug instrumentation of the matcher.

## The fundamental issue

The LLVM IR pattern matchers in `patterns.h2` have **uneven
coverage**:
- Some patterns match aggressively (catching the same store
  multiple times → over-count)
- Other patterns miss certain shapes (conditional stores,
  some memcpys, bitfields) → under-count
- The mismatch count varies per node depending on which
  patterns happen to fire on its specific IR shape

Each incremental fix (add a pattern, dedup, count-fix) shifts
the problem rather than solving it. The matcher infrastructure
has inconsistencies that compound.

## What each remaining failing node needs

| node | state | what would unlock it | risk |
|---|---|---|---|
| arp_node | 4/3 | identify the spurious 4th match + tighten its pattern constraint, OR fix the store_count to be consistent with matcher | medium |
| rarp_node | 4/3 | same as arp | medium |
| icmpv4_node | 2/3 | conditional store pattern | high |
| icmpv6_node | 2/3 | same | high |
| mpls_node | 1/2 | bitfield aggregate pattern (mpls struct write is 32-bit aggregated) | high |
| tipc_node | 1/2 | shift+mask+bswap pattern | medium |
| ipv4_node | 3/6 | bitfield pattern + hdr_offset audit + flow_label mask | high |
| ipv6_node | 3/4 | mask-AND pattern (flow_label) | medium |
| ipv6_frag_node | 1/3 | bitfield pattern + multiple stores audit | high |

Total estimated work for incremental coverage: 5-10 more
sessions. Most patterns are non-trivial cpp2 LLVM IR matchers.

## Path forward — honest reassessment

The iterative path (option 1) was meant to be session-sized
work yielding incremental unlocks. After 3 iterations
(2-a.1, 2-a.2, 2-a.3) we have shipped useful infrastructure
but no new nodes. Continuing this path means:

- **5-10 more sessions** to fully cover the failing nodes
- **Each session may discover yet-deeper matcher issues**
- The matcher patterns are written in cpp2 (Carbon-style C++)
  which adds learning curve

The cleaner alternative remains **2-a.7 (per-parser inline
extractor codegen)**:
- ~3 days focused work
- Bypasses the LLVM-IR-matcher entirely
- Per-parser codegen reads a declarative metadata spec and
  emits inline writes directly
- All 30 fields automatically supported without matcher work

The iterative path has shipped real value (kind extension +
dedup are correctness/infrastructure improvements that
benefit the cleaner rewrite too). But for actual
mt_full_coverage unlocks, the iterative path's marginal cost
is exceeding the marginal benefit.

## Recommendation

**Pause Option C phase 2-a iterative work here.** What's
shipped this session is forward-looking value:
- 2-a.1 kind extension: when the matcher is fixed (someday),
  these kinds will be automatically inlined
- 2-a.2 dedup: prevents duplicate writes from any future
  matcher work
- 2-a.3 investigation: documents the matcher inconsistency
  for future fixers

The 9-node `mt_full_coverage=True` state is the stable point
the existing matcher achieves cleanly. Further unlock requires
either (a) deep matcher audit work (multi-session, uncertain
yield), or (b) the 2-a.7 rewrite (multi-day, all nodes
unlocked).

User to choose:
1. **Stop here**: Option C ships at "phase 1 + 2-a.1 + 2-a.2";
   document in perf-next-steps and move to other options
2. **Continue iterating** with explicit acceptance of 5-10
   more sessions for incremental unlock
3. **Commit to 2-a.7 rewrite** as the next focused project
   (~3 days)
