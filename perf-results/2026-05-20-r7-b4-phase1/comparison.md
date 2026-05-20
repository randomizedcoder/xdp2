# R7-B4 phase 1 — AST fix + per-node inline length check

Date: 2026-05-20. Per-node `__mono_check_pkt_len` helper trimmed
when proto_def has no `ops.len`. Previously blocked by AST
miscapture of `proto_has_len_op`; this phase fixes the AST then
re-lands the template change.

## TL;DR

**Phase 1 ships correctness-clean.** AST fix corrects the IR
data; the template change emits the right code per-node based
on actual proto_def shape (helper for variable-length headers,
inline check for fixed-length). Matrix 4914/4914 cells clean.

**Perf is null** on hp5 (every cell ±2 ns of R7-B3 baseline);
some movement on hp2 (-5 ns on k8s-microservices) but within
hp2's historical noise band. gcc + `always_inline` was already
producing similar code shapes for both forms.

The real value of phase 1 is structural: future codegen work
that depends on `proto_has_len_op` (or similar IR flags
derived from `proto_def->ops`) is now unblocked.

## The fix — 1 line in `python_generators.h`

Before (broken, used graph_consumer.h's stale field):
```cpp
obj.set("proto_has_len_op", v.proto_has_len_op);
```

After (derive from working proto-nodes.h capture):
```cpp
obj.set("proto_has_len_op", v.proto_len.has_value());
```

The graph_consumer.h walker that R5.C added at line 745 sits
in `_handle_init_list_expr_parse_node`, which is called only
for parse_user_node init lists. It never reaches the proto_def
because `.proto_def = &xdp2_parse_X` is stored as just the
name string (UnaryOperator path, doesn't recurse into the
referenced VarDecl).

Meanwhile, `proto-nodes.h` has a SEPARATE consumer
`xdp2_proto_node_consumer` that walks `const struct xdp2_proto_def`
init lists directly. It correctly captures `.ops.len`,
`.ops.next_proto`, `.overlay`, etc. into a `proto_node_extract_data`
struct, which is then merged into the vertex_property via
`transfer_data_from_proto_node_data_to_vertex` (sets
`vertex.proto_len = proto_node_data.len`).

So `v.proto_len` is the reliable source of truth for "this
proto_def has ops.len". `v.proto_has_len_op` (R5.C-added) is
always false. The fix is to use the working capture.

## The template change — R7-B4 v1 reapplied

In `mono_def.template.c:361`, replace the unconditional helper
call:
```c
ret = __mono_check_pkt_len(hdr, proto_def, len, &hlen);
if (ret != XDP2_OKAY) return ret;
```

With per-node gated emit:
```c
<!--(if graph[node]['proto_has_len_op'])-->
/* Variable-length headers (IPv4 IHL, IPv6 EH, SRv6 etc.) */
ret = __mono_check_pkt_len(hdr, proto_def, len, &hlen);
if (ret != XDP2_OKAY) return ret;
<!--(else)-->
/* Fixed-length headers: inline check, no helper call */
hlen = proto_def->min_len;
if (__builtin_expect(len < (size_t)hlen, 0))
    return XDP2_STOP_LENGTH;
<!--(end)-->
```

Verified per-node emit in generated `parser.mono.c`:
- `ipv6_node` (no ops.len in `xdp2_parse_ipv6`) → emits inline
  check ✓
- `ipv6_eh_node` (has ops.len = `ipv6_eh_len`) → emits helper
  call ✓
- `srv6_node` (has ops.len = `ipv6_srv6_len`) → emits helper
  call ✓ (this was the parity-gate failure mode pre-fix; now
  correct)

## Perf delta vs R7-B3 baseline

### hp5 (canonical)

| workload | R7-B3 | R7-B4 phase 1 | Δ |
|---|---:|---:|---:|
| https-web | 72 | 72 | 0 |
| k8s-microservices | 131 | 133 | +2 (noise) |
| nfs-server | 70 | 69 | -1 |
| pppoe-isp | 74 | 72 | -2 |
| vlan-tcp-mix | 70 | 72 | +2 |
| vxlan-k8s-pure | 136 | 136 | 0 |

### hp2

| workload | R7-B3 | R7-B4 phase 1 | Δ |
|---|---:|---:|---:|
| https-web | 70 | 69 | -1 |
| k8s-microservices | 135 | 130 | **-5** |
| nfs-server | 70 | 71 | +1 |
| pppoe-isp | 75 | 73 | -2 |
| vlan-tcp-mix | 73 | 72 | -1 |
| vxlan-k8s-pure | 138 | 140 | +2 (noise) |

hp5 is null within ±2 ns noise band. hp2 has more movement (the
k8s-microservices -5 ns might be real, but hp2 has been noisier
across our sweeps).

## Why null on hp5?

The helper `__mono_check_pkt_len` is `always_inline`. gcc + LTO
sees the `pnode->ops.len` field is `static const`, so the
runtime check `if (pnode->ops.len)` is constant-folded at
compile time. The two emit shapes produce equivalent assembly
when the inline expansion settles.

The cycles attributable to per-node length check on tunneled
workloads (~7 nodes × ~3 cycles for the min_len comparison)
are mostly amortised into the rest of the per-node body's
work via Zen 1's out-of-order pipeline.

## Why phase 1 still matters

Even at null perf delta, phase 1 ships:

1. **AST fix unblocks future work.** Any codegen optimisation
   that depends on `proto_has_len_op` (e.g., a per-node
   specialised dispatcher, profile-guided inlining choices,
   etc.) can now rely on the IR being correct.
2. **Template honesty.** The generated `parser.mono.c` now
   makes its per-node intent explicit — reviewers see "this
   node has variable-length, hence helper call" vs "this node
   is fixed-length, inline check". Easier to audit.
3. **Pre-condition for B2** (per-protocol dispatch functions,
   phase 2): if we split each node into its own static inline
   function, having proto_has_len_op correct means we don't
   emit the helper call wrapper for fixed-length nodes —
   keeping per-node code smaller.

## Correctness

- **Parity gate**: 32/32 pcaps OK (including srv6-end-64.pcap
  which broke pre-fix).
- **Protocol-coverage matrix**: 4914 cells, 0 OK!N, 0
  REJ-undeclared, 0 REJ-unexpected.
- **Mono-perf ceiling**: 0 violations on 12 cells.

## What remains: phase 2

R7-B2 — per-protocol dispatch functions. ~150 LoC template
restructure mirroring rust-mono's per-function-per-node
approach. Speculative impact (could be 0 to 20 ns). The IR
data from phase 1 supports it.

## Files

- `comparison.md` — this file
- `sweep.md` — full hp2+hp5 6-workload matrix
- `mono-perf.md` — parity ceiling (0 violations)
- `matrix.md` — protocol-coverage matrix (4914 cells, 0/0/0)

## Reproducing

```sh
# Build + parity + matrix
nix build .#checks.x86_64-linux.parity-gate
nix run .#protocol-coverage-matrix -- --out /tmp/cov
grep -E "OK!N|REJ-unexpected" /tmp/cov/report/matrix.md

# Perf sweep
XDP2_RESULTS_ROOT=/tmp/r7-b4-final-sweep \
nix run .#flow-dissector-matrix-sweep -- \
    --testbed testbeds/hp2-hp5-x710.toml

# Verify per-node emit
nix build .#flow-dissector-matrix-artifacts
MC=$(readlink result)/lib/xdp2-flow-dissector-matrix/parser.mono.c
# Expect: ipv6_node has inline check, ipv6_eh_node has helper call
awk '/^label_ipv6_node:/,/^}/' "$MC" | grep "R7-B4 phase 1"
awk '/^label_ipv6_eh_node:/,/^}/' "$MC" | grep "R7-B4 phase 1"
```
