# R7-B4 — Two attempts, both reverted

Date: 2026-05-20. The R7-B4 idea: trim per-node
`__mono_check_pkt_len(hdr, proto_def, len, &hlen)` overhead.
Two variants attempted, both reverted.

## TL;DR

| variant | what | result |
|---|---|---|
| **B4 v1** | Inline length check per-node using `proto_has_len_op` IR flag | Reverted: parity-gate disagreement on `srv6-end-64.pcap`. Root cause: AST consumer misses nested designated initializers like `.ops.len = X` for `field_name == "len"` capture. |
| **B4 v2** | Change helper signature from `int(...,&hlen)` to `ssize_t(...)` returning hlen | Reverted: regression of 2-5 ns/pkt on tunnel workloads. gcc handled the pointer-out-param form better than return-by-value despite always_inline. |

## B4 v1 — IR-gated per-node inline (reverted)

Replaced:
```c
ret = __mono_check_pkt_len(hdr, proto_def, len, &hlen);
if (ret != XDP2_OKAY) return ret;
```

With:
```c
<!--(if graph[node]['proto_has_len_op'])-->
ret = __mono_check_pkt_len(hdr, proto_def, len, &hlen);
if (ret != XDP2_OKAY) return ret;
<!--(else)-->
hlen = proto_def->min_len;
if (__builtin_expect(len < (size_t)hlen, 0))
    return XDP2_STOP_LENGTH;
<!--(end)-->
```

Theory: for nodes without `ops.len`, skip the helper call entirely
and emit just the min_len check inline. ~5 cycles/node × ~5
nodes per VXLAN packet = ~25 cycles = ~6 ns/pkt expected.

**Reverted** after `parity-gate` failed on `srv6-end-64.pcap`:
c-xdp2-mono disagreed with c-flowdis-usp on `flow_label`,
`ip_proto`, `ipv6_src`, `ipv6_dst` (and similar IPv6 fields).

Root cause: `proto_has_len_op` is set to `false` for IPv6 even
though `proto_def->ops.len = ipv6_length_check` is present. The
AST consumer at `graph_consumer.h:745` checks
`field_name == "len"` but the in-tree proto_def init lists use
nested designated initializers (`.ops.len = X`) — the walker
sees the outer `ops` field, recurses, and inside the sub-init
sees `len` BUT only for parse_node_ops contexts (where `len`
doesn't exist). For proto_def's xdp2_parse_ops, the walker
isn't entering the substructure because `.proto_def = &xdp2_parse_X`
is stored as a string name (line 666) without walking into the
referenced VarDecl's init.

To enable B4 v1, the AST consumer needs to:
1. Track the proto_def VarDecl referenced by parse_node, then
2. Walk that VarDecl's initializer to find `.ops.len`

Roughly 50-100 LoC of careful AST work. Deferred.

## B4 v2 — Return-by-value helper (reverted)

Alternative approach: don't change the per-node template, just
rewrite the helper to return `hlen` directly. Eliminates the
`*hlen` pointer-to-stack indirection that may force gcc to spill
the length to memory.

```c
/* Before */
static inline int __mono_check_pkt_len(hdr, pnode, len, ssize_t *hlen);

/* After */
static inline ssize_t __mono_check_pkt_len(hdr, pnode, len);
/* Returns: hlen on success, -error on failure */
```

Call site:
```c
hlen = __mono_check_pkt_len(hdr, proto_def, len);
if (__builtin_expect(hlen < 0, 0))
    return (int)(-hlen);
```

Also added `__builtin_expect(... < 0, 0)` hints inside the helper.

**Result (hp5 c-xdp2-mono delta vs R7-B3 baseline)**:

| workload | R7-B3 | B4 v2 | Δ |
|---|---:|---:|---:|
| https-web | 72 | 72 | 0 |
| **k8s-microservices** | 131 | **135** | **+4** (regression) |
| nfs-server | 70 | 70 | 0 |
| pppoe-isp | 74 | 72 | -2 |
| vlan-tcp-mix | 70 | 69 | -1 |
| **vxlan-k8s-pure** | 136 | **138** | **+2** (regression) |

Tunneled workloads got SLOWER. The signature change must be
interacting badly with gcc's optimizer on Zen 1 despite
always_inline. Possible reasons:
- The `-XDP2_STOP_LENGTH` negation forces a `neg` instruction
  at the call site (cold path; should be invisible)
- The `if (hlen < 0)` check vs `if (ret != XDP2_OKAY)` produces
  slightly different branch patterns
- `__builtin_expect(... < 0, 0)` on three branches inside the
  helper changes how gcc reorders blocks during inlining

The 200 B / 192 B struct + ~10K-instruction inlined function is
big enough that small optimizer changes cascade unpredictably.

**Reverted** as a net regression.

## What this teaches

The R7-A perf-record finding that `__mono_check_pkt_len` is "hot"
was misleading. The hot lines (cmp, jb, leave, pop) in the
perf-annotate are SHARED across many node bodies because the
helper is always_inline. Each individual inlining is fine; the
TOTAL across 7+ node walks adds up to "this helper is hot" in
aggregate but isn't fixable by changing the helper itself.

The real cost is the underlying work: per-node length check
(unavoidable), per-node header advance (unavoidable),
per-node dispatch (B1 addressed). The helper signature is not
the bottleneck.

## Files

- `comparison.md` — this file
- `sweep-attempted-reverted.md` — full hp2+hp5 matrix for B4 v2
  (showing the regression). Kept for reproducibility, but the
  template change is NOT in the tree.
- `mono-perf.md` — mono-perf ceiling (still 0 violations even
  with the regression)

## State of R7-B after this session

| variant | status | impact |
|---|---|---|
| B1 (hot-edge shortcut) | **shipped** | **−4 ns/pkt on tunnels** |
| B3 (typed stores) | shipped | null perf, cleaner emit |
| B4 v1 (IR-gated inline) | reverted | needs AST fix in graph_consumer |
| B4 v2 (return-by-value) | reverted | +2-5 ns regression |
| B2 (per-protocol functions) | not attempted | ~150 LoC speculative |

Remaining headroom on tunneled c-xdp2-mono vs rust-mono: 43 ns
(vxlan), 47 ns (k8s-microservices). Closing this further
requires either the AST-fix path (for B4 v1) or the B2
structural refactor.

## Recommendation

Pause R7 unless the user wants the structural B2 work. B1's
4 ns win is already shipped and is the only clean optimisation
remaining in the dispatch/extraction layer for Zen 1 at the
template level. Deeper work (B2 or AST-fix-then-B4) is on the
order of days, not hours.
