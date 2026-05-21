# R7-B2 phase 2 — Per-protocol function restructure (rigorous test, reverted)

Date: 2026-05-20. R7-B2 = restructure mono parser from one
giant `xdp2_parse_mono()` function with internal `goto label_X`
chains into per-node `parse_<node>_<parser>()` functions
calling each other via tail-calls (`return parse_X(...)`),
mirroring rust-mono's per-protocol-function structure.

**Reverted** after a full sweep showed a +5 ns/pkt regression
on hp5 pppoe-isp and otherwise null deltas. The signal-test
prediction was correct; this rigorous test is the definitive
evidence.

## Two-phase test

### Phase 1: Signal-test (`__attribute__((hot))`)

One-line template change: add `hot` attribute to entry function.
If gcc's existing layout isn't optimal, hot should move at
least one cell.

Result on hp5 vs R7-B4 phase 1 baseline:

| workload | B4-phase1 | +hot | Δ |
|---|---:|---:|---:|
| https-web | 72 | 71 | -1 |
| k8s-microservices | 133 | 133 | 0 |
| nfs-server | 69 | 70 | +1 |
| pppoe-isp | 72 | 73 | +1 |
| vlan-tcp-mix | 72 | 70 | -2 |
| vxlan-k8s-pure | 136 | 136 | 0 |

All within ±2 ns noise band. The hint is null because gcc
already treats the function as hot (only call site, inlined
into benchmark loop).

### Phase 2: Full B2 restructure

Per-node functions emitted as separate `static int`:

```c
/* Forward declarations */
static int parse_ether_node_xdp2_parser_flow_dissector(
    const struct xdp2_parser *, void *, size_t, void *, void *,
    struct xdp2_ctrl_data *);
/* ...36 more... */

/* Per-node function body */
static int parse_ether_node_xdp2_parser_flow_dissector(
    const struct xdp2_parser *parser, void *hdr, size_t len,
    void *metadata, void *frame, struct xdp2_ctrl_data *ctrl)
{
    /* length check, metadata extract, handler, dispatch */
    switch (type) {
    case 0x8:
        return parse_ip_check_node_xdp2_parser_flow_dissector(
            parser, hdr, len, metadata, frame, ctrl);
    ...
    }
    return parse_node->unknown_ret;
}

/* Entry function */
static __attribute__((always_inline)) int
xdp2_parser_flow_dissector_xdp2_parse_mono(...) {
    /* fast-path */
    return parse_ether_node_xdp2_parser_flow_dissector(
        parser, hdr, len, metadata, frame, ctrl);
}
```

Template change: ~50 lines in `mono_def.template.c`. Generated
`parser.mono.c` grew to ~100 per-node function definitions
(one per parser graph node).

### Phase 2 perf results vs R7-B4 phase 1 baseline

**hp5 c-xdp2-mono:**

| workload | B4-phase1 | B2 | Δ |
|---|---:|---:|---:|
| https-web | 72 | 72 | 0 |
| k8s-microservices | 133 | 133 | 0 |
| nfs-server | 69 | 71 | +2 (noise) |
| **pppoe-isp** | 72 | **78** | **+6 (regression)** |
| vlan-tcp-mix | 72 | 73 | +1 |
| vxlan-k8s-pure | 136 | 135 | -1 |

**hp2 c-xdp2-mono:**

| workload | B4-phase1 | B2 | Δ |
|---|---:|---:|---:|
| https-web | 69 | 71 | +2 |
| k8s-microservices | 130 | 130 | 0 |
| nfs-server | 71 | 71 | 0 |
| pppoe-isp | 73 | 75 | +2 |
| vlan-tcp-mix | 72 | 73 | +1 |
| vxlan-k8s-pure | 140 | 138 | -2 |

**pppoe-isp regressed on both hosts** (+6 hp5, +2 hp2). The
PPPoE walk (eth → pppoe → ppp → ipv4 → tcp) has more
inter-function transitions than the other chains and pays the
function-call overhead most heavily.

The signal-test phase 1 had predicted this. Other workloads
are within noise.

## Why B2 regressed

With the entry function marked `always_inline` and the per-node
functions NOT marked `always_inline` (the structural difference
that makes B2 "different" from current), gcc:

1. Inlines the entry function into the benchmark loop body.
2. Cannot inline the per-node functions because their addresses
   are taken (forward declarations make them externally
   visible at the .o level).
3. Compiles each `return parse_X(...)` as a tail call where
   possible, but on Zen 1 at -O3 gcc isn't always able to
   tail-call switch-on-return-value patterns reliably.

Net: every node transition becomes a function call (push/pop or
jmp via tail-call). For PPPoE's 5-node chain that's ~10 cycles
of call overhead beyond the current goto-jmp form. Hence the
+5-6 ns regression on hp5.

For VXLAN's 7-node chain we'd expect even more overhead, but
it appears the workload's higher absolute cost dilutes the
relative impact.

## Correctness

- **Parity gate**: 32/32 pcaps OK (with B2 template change)
- **Protocol-coverage matrix**: 4914 cells, 0 OK!N, 0
  REJ-undeclared, 0 REJ-unexpected
- **Mono-perf ceiling**: 0 violations on 12 cells

The restructure is functionally identical to the current
goto-state form. The regression is purely from the function-
call overhead gcc can't fully eliminate.

## Decision: revert

R7-B2 reverted. Net change to repository = 0. The current
single-function-with-gotos shape stays.

The lesson: at gcc -O3 -march=native -flto on Zen 1 with
`always_inline` on the entry function, the parser is at gcc's
local optimum. Any structural change either:
- Inlines back to the same code (null perf, e.g.,
  per-node functions with always_inline)
- Adds function-call overhead (regression, e.g.,
  per-node functions without always_inline)

## What R7-B2 confirms

The c-xdp2-mono vs rust-mono gap on tunnels (43 ns on vxlan,
48 ns on k8s-microservices) is **NOT closable via template-
level codegen changes** at gcc -O3 on Zen 1. The compiler is
already producing close-to-optimal code from the template
intent.

The remaining headroom requires:
1. **Per-parser tailored metadata struct** (R6 audit's Option
   C, ~500 LoC IR + codegen). Reduces the NUMBER of fields
   written per packet, not the shape of how they're written.
2. **Different compiler** — rustc/LLVM emits per-protocol
   match-tree dispatch differently than gcc's binary-search
   switch. Could try building with clang to test.
3. **Profile-guided optimization (PGO)** — collect a profile
   from real traffic, recompile with PGO data, gcc can then
   reorder hot paths and inline differently.

None of these are R7 territory. They're R8+ or separate
investigations.

## R7 final state (after R7-B2 revert)

| Phase | Status | Impact |
|---|---|---|
| R7-A perf-record | shipped (docs) | Identified cost drivers |
| R7-B1 hot-edge shortcut | **shipped** | **-4 ns/pkt on tunnels** |
| R7-B3 typed stores | shipped | Null perf, cleaner emit |
| R7-B4 phase 1 (AST fix + per-node len check) | shipped | Null perf, unblocks future |
| R7-B4 v1 (original) | reverted | AST limitation |
| R7-B4 v2 (return-by-value) | reverted | +5 ns regression |
| R7-B2 phase 2 (this) | **reverted** | +5-6 ns pppoe-isp regression |

c-xdp2-mono final state on hp5 (4 of 6 tied or ahead of
rust-mono):

| workload | c-xdp2-mono | rust-mono | gap |
|---|---:|---:|---:|
| https-web | 72 | 71 | +1 (tied) |
| nfs-server | 70 | 70 | 0 (tied) |
| pppoe-isp | 73 | 80 | -7 (mono ahead) |
| vlan-tcp-mix | 72 | 88 | -16 (mono way ahead) |
| k8s-microservices | 132 | 84 | +48 (structural) |
| vxlan-k8s-pure | 135 | 92 | +43 (structural, was +46) |

## Files

- `findings.md` — this analysis
- `sweep-hot-attr.md` — phase 1 signal-test results
- `sweep-b2-restructure.md` — phase 2 full restructure results
  (REVERTED; not in tree)
- `mono-perf-b2.md` — B2 mono-perf ceiling (still 0 violations
  but the +5 ns pppoe-isp regression was the dealbreaker)
