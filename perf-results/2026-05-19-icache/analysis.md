# Icache investigation — c-xdp2-mono vs rust-mono gap

Run: 2026-05-19, hp2 + hp5, modes M/O/S × workloads
{https-web, vxlan-k8s-pure}, 100 iterations × 20000 packets each.

Trigger: from `perf-results/2026-05-19-O3-march-native-flto/
comparison.md`, after disproving the compile-flag hypothesis,
the leading candidate for the remaining ~50 ns c-xdp2-mono vs
rust-mono gap was "code-size / icache pressure" — the L2 mono
entry function is 10,388 asm instructions ≈ 62KB, bigger than
Zen 1's 32KB L1i.

## Headline: icache hypothesis DISPROVED

Looking at hp5 vxlan-k8s-pure (where the mono-vs-rust gap is
biggest):

| mode | ns/pkt | icache-miss | branch-miss | instr | cycles | IPC | miss/Mi |
|---|---:|---:|---:|---:|---:|---:|---:|
| -M | 140 | 1,409,346 | 2,571,444 | 1.58 B | 3.41 B | 0.46 | 893 |
| -O | 160 | 1,418,035 | 2,897,796 | 2.13 B | 3.66 B | 0.58 | 667 |
| -S | 239 | 1,603,432 | 5,239,199 | 4.42 B | 4.80 B | 0.92 | 363 |

**Icache misses are similar across all three modes**
(1.4M-1.6M). Mono doesn't blow icache — it has the SAME miss
count as opt and slightly fewer than generic. The "62KB function
won't fit in 32KB L1i" worry was wrong: the *hot path* through
the function fits, and cold-path lines aren't touched.

## What the gap actually is: instructions per packet

Same vxlan-k8s-pure cells, derived per-packet metrics:

| mode | instr/pkt | cycles/pkt | ns/pkt | front-end stall % |
|---|---:|---:|---:|---:|
| -M | **789** | 1,705 | 140 | (1 - IPC × 5/clock) ≈ 91 % |
| -O | 1,063 | 1,830 | 160 | 88 % |
| -S | 2,208 | 2,400 | 239 | 82 % |

(2M parses = 100 iters × 20K pcap. front-end stall % is rough; Zen 1
peak IPC = 5 so stall fraction ≈ 1 - IPC/5).

Mono uses ~40 % fewer instructions than opt and ~64 % fewer than
generic. **The R3.4 codegen IS leaner** than the alternatives —
but rust-mono at 92 ns × 3.2 GHz ≈ 295 cycles/pkt is 1.7× tighter
than c-mono's 451 cycles/pkt on the same workload. With similar
IPC, rust uses **~35 % fewer instructions per packet** than
c-mono. The gap is instruction-count, not icache.

## Where the extra C-side instructions probably go

Each per-node body in the mono template emits roughly:

```c
ctrl->var.last_node = parse_node;                    // 1 store
ret = __mono_check_pkt_len(...);                     // inlined: ~3-5 instr
if (ret != XDP2_OKAY) return ret;                    // 1 cmp+branch
if (parse_node->ops.extract_metadata)                // 1 load+branch (even if NULL)
    parse_node->ops.extract_metadata(...);           // direct call when devirt'd
if (parse_node->ops.handler)                         // 1 load+branch (even if NULL)
    parse_node->ops.handler(...);
type = proto_def->ops.next_proto(hdr);               // direct call when devirt'd
if (!proto_def->overlay) {                           // 1 load+branch
    hdr = (char *)hdr + hlen;
    len -= hlen;
}
switch (type) { ... }                                // dispatch
```

On a 7-node vxlan walk, that's ~50-70 "bookkeeping" instructions
per packet that rust's monomorphic match-cascade simply doesn't
have. Multiply by 7 nodes ≈ ~350-490 instr/pkt of pure structural
overhead. That matches the observed gap.

## On https-web (TCP fast-path) — gap nearly closed

| host | mode | ns/pkt | instr/pkt | gap to rust |
|---|---|---:|---:|---:|
| hp5 | mono | 72 | 447 | mono 72 vs rust-mono 72 — **closed** |

When the R3.4 fast-path fires (TCP/IPv4), mono is single-block
straight-line code, no per-node bookkeeping. It matches rust-mono
exactly. **The 50 ns gap exists only on workloads where the
fast-path doesn't fire** — i.e., tunneled traffic where mono has
to walk the slow-path goto-state body.

## Recommendation

The next perf lever for tunnel workloads is NOT codegen-restructure
for icache. It's **trimming per-node bookkeeping in the slow-path
goto-state template** (`src/templates/xdp2/mono_def.template.c`),
gated on what the IR already knows:

| trim | when safe | est. savings |
|---|---|---:|
| skip `ctrl->var.last_node = parse_node` | when no consumer reads it (most paths) | ~7 instr × N nodes |
| skip `if (ops.extract_metadata)` null check | when IR proves the slot is NULL (the cast loses const, gcc can't see this) | ~3 instr × N |
| skip `if (ops.handler)` null check | same — IR knows | ~3 instr × N |
| skip `if (!proto_def->overlay)` | when statically known false | ~3 instr × N |
| inline `__mono_check_pkt_len` body, omit `ops.len` indirection | when proto_def has no `ops.len` | ~5 instr × N |

For a 7-node vxlan walk these total ~140 instructions per packet
trimmed. At IPC 0.46 that's ~70 cycles ≈ 22 ns. Combined that's
about half the rust-mono gap. The other half is presumably
metadata-write differences (rust extracts MORE fields but apparently
uses fewer writes per field — or the field layout is friendlier).

These trims are R5-class work (~150-250 LoC across the AST
consumer + python_generators + the template). They're the next
codegen item, gated on IR introspection of the proto_def static
const so the trimmed code is provably equivalent to the original.

## What this run also tells us

| observation | reading |
|---|---|
| Mono uses 40 % fewer instructions than opt | R3 codegen is winning. The default-flip in `c5cbaf4` is justified. |
| Mono's IPC (0.46) is LOWER than opt's (0.58) | Mono is more memory/branch-bound per cycle. Branch predictor hits more cold paths in mono's goto-state than in opt's switch-driven dispatch. |
| Branch misses HALVED on mono vs opt (2.6M vs 7.3M on https-web) | The R3.4 fast-path short-circuits the worst branch-prediction territory entirely. |
| iTLB misses are tiny everywhere (≤370) | Not a TLB issue. Confirms the per-packet path fits in a handful of pages. |
| hp2 vs hp5 deltas remain ≤ 3 % | Re-confirms compute-bound regime; the metadata-write path isn't yet at memory-bandwidth ceiling. |

## Reproducing

```
nix run .#flow-dissector-icache-sweep -- \
    --testbed testbeds/hp2-hp5-x710.toml \
    --workloads vxlan-k8s-pure,https-web \
    --modes M,O,S \
    --iters 100
```

Output: per-cell `.txt` (raw perf-stat) + `.json` (parsed) +
aggregate `icache-summary.md` (markdown table).

## Files

- `icache-summary.md` — aggregate table
- `hp2/icache/<workload>/{M,O,S}.{txt,json}` — per-cell raw +
  parsed counters
- `hp5/icache/<workload>/{M,O,S}.{txt,json}` — same for hp5
