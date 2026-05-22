# R8-Option C phase 2-a.2 — metadata-transfer dedup

Date: 2026-05-22. Added a deduplication pass over collected
`metadata_transfers` in `src/tools/compiler/src/main.cpp` after
the LLVM pattern matchers run. Dedup is keyed on
`(dst_bit_offset, bit_size)`; multiple pattern matches against
the same destination collapse to a single canonical transfer.

## TL;DR

- Dedup pass shipped (~35 LoC in main.cpp + 2-line `#include` add)
- **Reveals a second-order problem on icmpv4/icmpv6**:
  pre-dedup `4/3` (too many — duplicates) → post-dedup `2/3`
  (too few — pattern matcher MISSES the conditional id store)
- No new nodes mt_full_coverage today, but the dedup is a
  correctness improvement (removes erroneous duplicate writes
  that would have been silently emitted)
- All gates green: parity 32/32, matrix 4914/4914

## What changed

`src/tools/compiler/src/main.cpp` after line 2101: added a
dedup pass:

```cpp
std::set<std::pair<std::size_t, std::size_t>> seen;
auto new_end = std::remove_if(
    mts.begin(), mts.end(),
    [&](xdp2gen::metadata_transfer const &t) {
        auto key = dst_size_of(t);
        if (seen.count(key)) return true;
        seen.insert(key);
        return false;
    });
mts.erase(new_end, mts.end());
```

`dst_size_of` is a `std::visit` over the transfer variant
that extracts `(dst_bit_offset, bit_size)` for each variant
shape (copy/constant/hdr_off/hdr_len/value all carry these
fields).

The pass keeps the FIRST match per `(offset, size)` key. Any
subsequent match for the same destination is discarded. This
is safe because the destination write is unconditional from
the IR's perspective — multiple pattern matches just represent
different ways to recognize the same store.

## Before-and-after (diagnostic on flow-dissector)

Sample nodes that previously had duplicate-match issues:

| node | pre-2a.2 | post-2a.2 | what happened |
|---|---|---|---|
| icmpv4_node | 4/3 | 2/3 | 2 distinct (offset, size) duplicates removed |
| icmpv6_node | 4/3 | 2/3 | same |
| arp_node | 4/3 | 4/3 | no dedup needed — 4 distinct (offset, size) |
| rarp_node | 4/3 | 4/3 | same |
| (15 nodes total ran the dedup; only icmpv4/icmpv6 had key collisions) | | | |

The arp/rarp cases (still 4/3) have a different issue: 4
distinct destinations were matched, but only 3 stores exist
in IR. One of the 4 matches is spurious (a pattern matched
something that isn't actually a store of metadata) OR the
arp_metadata's memcpy calls are being counted by some
patterns. Investigation deferred.

## What dedup reveals about icmpv4/icmpv6

Before dedup: 4/3 = matcher matched 4 transfers, IR has 3 stores
After dedup: 2/3 = 2 unique (offset, size) destinations matched

For icmpv4:
- icmp_metadata source has 3 logical writes: type, code, id
  (id is conditional inside `if (icmp_has_id(...))`)
- IR has 3 stores (one per logical write)
- Pattern matchers found 4 transfers — must include 2 duplicates
- After dedup: 2 unique destinations

Conclusion: the matchers found 2 of 3 actual destinations
(type, code), each matched twice. The 3rd (id, conditional)
isn't matched by any current pattern — branch-aware pattern
needed.

## What this enables / doesn't enable

**Enables**: a future "conditional store pattern" addition
would have a clean 3/3 match for icmpv4/icmpv6, immediately
qualifying both for mt_full_coverage. The dedup pass means
adding that pattern won't push the count too high.

**Doesn't directly unlock**: icmpv4/icmpv6 still fail
mt_full_coverage today. arp/rarp's spurious 4th match is a
separate matcher-quality issue.

## Correctness

- **Parity-gate**: 32/32 OK
- **Protocol-coverage-matrix**: 4914 cells, 0 OK!N, 0
  REJ-undeclared, 0 REJ-unexpected
- **Mono-perf ceiling**: 0 violations

The dedup pass keeps the canonical write per destination, so
the emitted code does NOT write the same metadata field twice
(which would have been incorrect for any conditional/variant
sources).

## Files changed

- `src/tools/compiler/src/main.cpp` — dedup pass + `#include <algorithm>`, `#include <set>` (~40 LoC)

## Next steps (still iterating on phase 2-a)

The remaining roadmap:

| sub-phase | what | unlocks | LoC | sessions |
|---|---|---|---|---|
| 2-a.1 | template kind support (shipped) | infrastructure | 70 | 1 (done) |
| 2-a.2 | matcher dedup (THIS) | dedup only; correctness | 40 | 1 (done) |
| 2-a.3 | conditional store pattern | icmpv4/v6 if-arm writes | 80-150 | ~2 |
| 2-a.4 | bitfield write pattern | ipv4 fragmentation bits | 30-50 | ~1 |
| 2-a.5 | mask-AND pattern | ipv6 flow_label | 40-60 | ~1 |
| 2-a.6 | audit spurious matches | arp/rarp +1 phantom | varies | ~1 |
| 2-a.7 | per-parser inline extractor codegen | all 30 fields, clean | 300-500 | ~3 days |

Iteratively shipping 2-a.3 / 2-a.4 / 2-a.5 / 2-a.6 unlocks
the remaining 9 failing nodes incrementally. ~4 more sessions
of incremental work to fully cover, OR ~3 days for the
2-a.7 rewrite (cleaner long-term).

## Reproducing

```sh
nix build .#flow-dissector-matrix-artifacts
DRV=$(nix path-info --derivation .#flow-dissector-matrix-artifacts | tail -1)

# Before/after counts on the duplicate-match nodes
nix log "$DRV" 2>&1 | grep -E "icmpv4_node:|arp_node:" |
    grep "next_proto_info=4" | head -4

# Mt_full_coverage status across all nodes
nix log "$DRV" 2>&1 | grep -c "mt_full_coverage=True"
```
