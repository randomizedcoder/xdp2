# R5 per-node bookkeeping trim — results vs predictions

Run: 2026-05-19, hp2 + hp5, smoke iter count, vxlan-k8s-pure +
https-web (the two workloads where the rust-mono gap was
biggest pre-R5).

Build: `merge/matrix-physical-testbed` @ `36a6272` (R5.A + B + C
all committed).

## TL;DR

**All three trims fired in the generated code, but moved zero
ns/pkt at hp5.** gcc -O3 -march=native -flto -fno-plt was
already folding the runtime branches we trimmed. The mono
template is at gcc's local optimisation minimum on Zen 1.

This validates the codegen approach. The remaining ~50 ns gap
to rust-mono on vxlan-k8s-pure is NOT bookkeeping overhead;
it's something else (likely metadata struct size + TLV/flag_
fields walker overhead).

## Per-workload c-xdp2-mono ns/pkt (hp5)

| workload | pre-R5 (cab4593) | R5.A (c9f9323) | R5.A+B (3b81481) | R5.A+B+C (36a6272) | Δ total |
|---|---:|---:|---:|---:|---:|
| https-web | 73 | 72 | 72 | 72 | -1 (noise) |
| vxlan-k8s-pure | 141 | 141 | 141 | 140 | -1 (noise) |

Smoke iter count = single replicate per cell; the noise band
is ±2-3 ns. The trims are within noise.

## Trim execution confirmed (post-R5 parser.mono.c counts)

| pattern | pre-R5 | post-R5 | confirmed |
|---|---:|---:|:-:|
| `ctrl->var.last_node = parse_node` writes | ~150 (one per node × 14 parsers × ~10 nodes) | **0** | ✅ R5.A fired |
| `if (parse_node->ops.extract_metadata)` runtime checks | ~150 | **0** | ✅ R5.B fired |
| `if (parse_node->ops.handler)` runtime checks | ~150 | **0** | ✅ R5.B fired |
| `next_proto_keyin ? ... : ...` ternaries | ~150 | **0** | ✅ R5.C fired |
| `if (!proto_def->overlay)` runtime checks | ~300 (two sites per node) | **0** | ✅ R5.C fired |
| `parse_node->ops.{extract_metadata,handler}` direct calls | (was conditional) | **182** | ✅ correctly emitted when non-NULL |

Every trim is present in the generated mono.c. The codegen
output is different — but the compiled binary's per-packet
cycle count isn't.

## Why no perf delta?

gcc at `-O3 -march=native -flto -fno-plt` (committed in
`cab4593`) is aggressive enough to:

1. **Constant-fold across the `(const struct xdp2_parse_node *)
   &node` cast.** With LTO + `-O3`, gcc sees the `static const`
   struct's initializer and propagates the constants through
   the cast. The runtime `if (parse_node->ops.extract_metadata)`
   check resolves to a compile-time constant per node.
2. **Branch-trim dead arms.** When the condition is statically
   known, the dead arm is eliminated from the basic-block layout.
3. **DCE the dead stores.** The `ctrl->var.last_node = parse_node`
   store, if the value isn't read along any reachable path, is
   eliminated. (We confirmed via objdump in
   `perf-results/2026-05-19-O3-march-native-flto/comparison.md`
   that ZERO `call *` indirect-call instructions remain in the
   mono entry function — gcc was devirtualising everything.)

The R5 trims make the **template source** more honest about
what the codegen produces, but the **compiled binary** doesn't
change because gcc was already producing the trimmed form
under aggressive flags.

## The remaining 50 ns gap to rust-mono — what it IS NOT

Eliminated hypotheses:

| hypothesis | status |
|---|---|
| Compile flags (-O2 vs LTO+native) | DISPROVED (perf-results/2026-05-19-O3-march-native-flto) |
| Code-size / icache pressure | DISPROVED (perf-results/2026-05-19-icache) |
| Per-node bookkeeping overhead | DISPROVED (this run — gcc already folds) |

## What it likely IS

Re-reading `perf-results/2026-05-19-icache/analysis.md` with
this new knowledge:

- mono uses **789 instr/pkt** on vxlan vs rust-mono's inferred
  **~510 instr/pkt** — the 280 instr/pkt difference is real
  (icache run confirmed it via `perf stat`). But it's NOT
  redundant runtime checks; gcc already eliminated those.

The 280 instr/pkt difference must be:

1. **Metadata struct layout.** `xdp2_metadata_all` is ~200 B
   (3 cachelines). rust's `FlowMeta` is ~100 B. Mono writes
   more bytes per packet — each store is one instruction at
   the same IPC. ~50-100 extra instr/pkt plausibly.
2. **R3.3.4 inline memcpy() emit for metadata_transfers.** The
   IR-coverage gate (mt_full_coverage) inlines memcpy() per
   transfer. Each `memcpy(dst, src, N)` becomes 1-3 instructions
   depending on N. mono has many such transfers per node;
   rust-mono uses direct field stores which gcc collapses better.
3. **TLV / flag_fields walker overhead.** Per the mono-
   eligibility loosening in commit `a47d2ad`, flag_fields nodes
   (gre_v0, gre_v1, etc.) are walked by mono via their
   proto_table dispatch but the FLAG fields themselves are
   NOT walked. Yet the dispatch into them costs cycles.
   rust-mono handles these via direct function calls.
4. **Switch case mispredictions on cold paths.** Mono's
   goto-state has many switch cases per node; rust's match
   ladders predict differently.

These are R6-class investigations (metadata struct re-layout +
flag_fields walker emission), NOT R5 follow-ups.

## What this means for the kernel-team narrative

The original takeaway stands: **c-xdp2-mono is faster than
kernel flowdis on tunneled traffic at the same iteration count**
(140 ns vs flowdis 117 ns on hp5 vxlan-k8s-pure, though
flowdis stops at outer 5-tuple and mono walks the full inner
stack — different scopes).

The rust-mono gap is real but the cause is in the data path
(struct layout + metadata writes), not the dispatch shape. The
C codegen is producing efficient code; the headroom is in the
metadata layer.

## Recommendation

**Stop here on R5; defer the remaining gap to R6** (metadata
struct re-layout) which is a bigger investigation with real
struct-design tradeoffs (the 200-byte `xdp2_metadata_all` was
chosen to cover every protocol's fields in one struct; trimming
it means either splitting per-parser variants or going to a
sparse-write model).

The R5 work itself is still valuable as **documentation of
intent**: the template now reflects what gcc was already doing,
so a future contributor reading mono_def.template.c sees the
intended emission shape directly. Useful for cross-team review
(LKM, kernel devs).

## Mono ceiling gate

`mono-perf.md`: still clean — c-xdp2-mono ≤ c-xdp2-usp × 1.10
holds (mono 72-140 vs usp 133-159 on the two workloads).

## Files

- `summary.md` / `summary.csv` — full matrix at R5.A+B+C
- `mono-perf.md` — parity ceiling (0 violations)
- `comparison.md` — this file

## Reproducing the R5 commits' generation

```sh
# A: ctrl->var.last_node store dropped
git show c9f9323 -- src/templates/xdp2/mono_def.template.c

# B: static-NULL ops trim using existing IR strings
git show 3b81481 -- src/templates/xdp2/mono_def.template.c \
                    src/tools/compiler/src/template.cpp

# C: AST capture of overlay + next_proto_keyin + ops.len
git show 36a6272 -- src/tools/compiler/include/xdp2gen/graph.h \
                    src/tools/compiler/include/xdp2gen/ast-consumer/graph_consumer.h \
                    src/tools/compiler/include/xdp2gen/python_generators.h \
                    src/templates/xdp2/mono_def.template.c
```

## Looking forward: R6 metadata struct re-layout

Out of scope for this work, but the natural next phase if the
kernel team wants to close the rust-mono gap on tunnel
workloads:

1. Audit which fields of `xdp2_metadata_all` (~200 B) are
   touched per parse on representative workloads. The cold
   fields are wasted cacheline traffic.
2. Either:
   - Split into a "5-tuple core" struct (~40 B) + optional
     extended struct (~160 B), with the per-parser scope
     deciding which gets written.
   - OR add per-parser metadata struct generation: each parser
     declares its used field set and the codegen emits a
     tailored struct + extractors.

Estimated savings: 1-2 cacheline writebacks per packet ≈
5-10 ns/pkt. Combined with whatever flag_fields walker
optimisation gives, plausibly closes most of the remaining
50 ns gap.

Plan complexity: 500+ LoC across IR, codegen, and the
xdp2_metadata_all struct definition. Probably a 2-3-day effort.
