# Dispatch-Architecture Cost: Why Generic Parse-Graphs Lose to Hand-Tuned Dissectors

## TL;DR

The XDP2 parser (both C `libxdp2` and Rust `xdp2-bench`) is a
**generic, extensible parse-graph engine**. Every protocol layer
goes through a dispatch step: function-pointer call to read the
next-protocol value, linear-table lookup of the next node,
function-pointer call to extract metadata, function-pointer call to
the handler. That generic dispatch is what makes XDP2 extensible —
adding a new protocol means dropping in a node definition; no
recompile of the engine.

It is also what makes XDP2 **~2× slower than kernel flowdis** on
full-protocol parses, even after every trivial optimisation has
landed (memset hoist, static-link, FlowMeta reset). The dispatch
tax is structural and built into the parser architecture.

This doc captures the disasm + perf evidence and lays out the shape
of the fix.

## Evidence (post-O1+O5 build, 2026-05-09)

Direct `objdump -d` comparison of the two userspace dissectors on
the same test workload:

```
__xdp2_parse                 (libxdp2.a, statically linked into benchmark)
  size:           494 lines of asm
  indirect calls: 9 (`call *%rax` / `call *%rdx`)
  loop body:      do { ... lookup_node(table, type); ... } while(...);
                  with ops.next_proto / ops.extract_metadata / ops.handler
                  invoked via function pointer per protocol layer.
```

```
__skb_flow_dissect_err       (libflowdis.so — userspace port of kernel C)
  size:           1540 lines of asm — 3× bigger
  total calls:    14 (visible in inner loop)
  indirect calls: 0 in the main parse path
                  (only direct calls to __skb_flow_get_ports,
                   __siphash_aligned, memcmp, rand, etc.)
```

Per-packet wall on hp5, https-web.pcap, 100 iter:

| Path | ns/pkt | Comment |
|---|---:|---|
| `c-bpf-fast` (kernel BPF JIT) | 18 | 7-chain hardcoded, JITed, no dispatch |
| `xdp2_eth_ipv4_l4_fast` (Phase O2 in benchmark.c) | 16 | Same shape; userspace inlined |
| `__skb_flow_dissect_err` (kernel C, full parse) | 25 | Hand-tuned, direct calls |
| `__xdp2_parse` (XDP2-C, full parse, post-O1+O5) | 52 | 6-9 indirect calls/pkt + linear lookup_node |

## Where the gap lives — three components

### 1. `lookup_node()` linear search

`src/lib/xdp2/parser.c:43-48`:

```c
static const struct xdp2_parse_node *lookup_node(
		int type, const struct xdp2_proto_table *proto_table)
{
	for (int i = 0; i < proto_table->num_ents; i++)
		if (type == proto_table->entries[i].type)
			return proto_table->entries[i].node;
	return NULL;
}
```

For every protocol layer, this is a linear walk of the proto table.
The IPv4 table has ~14 entries; on a TCP packet we walk from index
0 looking for protocol 6. Cache-friendly (the table is small) but
the BPU sees a variable-length loop with a data-dependent exit. That
adds 5-10 cycles per layer.

### 2. Indirect function-pointer dispatch

In the `__xdp2_parse` loop at `src/lib/xdp2/parser.c:703-814`:

```c
type = proto_def->ops.next_proto(hdr);   // call *%rax
parse_node->ops.extract_metadata(...);   // call *%rax
parse_node->ops.handler(...);             // call *%rax
```

For an eth+ipv4+tcp parse, that's **9 indirect calls per packet**.
Each indirect call:
- Costs 5-7 cycles when correctly predicted.
- Costs 16-20 cycles when mispredicted.
- Pollutes the BTB (branch target buffer) — different function
  pointers per protocol mean the predictor has to learn each one.

In a mixed-protocol workload, these are mispredict-heavy because
the same dispatch site sees different targets across packets.

### 3. Generic-graph callbacks add even when the protocol doesn't need them

`extract_metadata`, `handler`, `post_handler` callbacks are checked
for non-NULL on every layer. Even when they're absent, the check +
branch is in the hot path. For a parser that doesn't use any of
those for the common case, that's ~3 branches per layer × 3 layers
= 9 branches purely to test "are you wired?"

## Same story on the Rust side

The C-side gap above mirrors a Rust-side gap that's been documented
since `fast-path-dispatch.md`:

| Mode | ns/pkt (combo) | branch-miss% | Why |
|---|---:|---:|---|
| `rust-graph` (dyn-trait vtable) | 287 | 4.06% | Indirect call per layer, BPU loses track |
| `rust-graph-enum` (single match) | 17 | 2.28% | Static match, jump-table |
| `rust-compiled` (codegen + nested match) | 47 | 5.01% | 3-deep nested match per packet |
| `rust-mono` (hand-rolled) | 51 | 4.87% | Same nested match shape |

`graph-enum` closed the gap from 287 → 17 ns by collapsing the
dispatch from a vtable to a single switch on a `ParseNodeId` enum.
**The C-side equivalent doesn't exist yet.**

## What the fix looks like

There are three orthogonal improvements that compound:

### Fix A — generated jump-table per `parse_node`

Replace `lookup_node()`'s linear search with a generated jump-table
or perfect-hash lookup. The `xdp2-compiler` already understands the
parser graph at compile time; it can emit:

```c
/* Generated for ipv4_node — replaces lookup_node(IPv4_TABLE, type). */
static const struct xdp2_parse_node *ipv4_lookup(__u8 ip_proto) {
    switch (ip_proto) {
    case 6:   return &tcp_node;
    case 17:  return &udp_node;
    case 1:   return &icmp_node;
    case 47:  return &gre_node;
    /* ... full table inlined as a switch ... */
    default:  return NULL;
    }
}
```

Compiler chooses jump-table or branchy switch. **Removes the linear
search; gives BPU a predictable target per ip_proto value.**

### Fix B — inline `next_proto` / `extract_metadata` for the common protocols

The common eth/ipv4/ipv6/tcp/udp `proto_def->ops.next_proto()` is
a 1-2 line function (`return *(u16*)(hdr+12);` for eth ethertype).
There's no reason to dispatch through a function pointer — inline
the load directly at the call site.

Same for `extract_metadata`: the eth handler writes
`metadata->eth_proto` and `metadata->eth_addrs` from fixed offsets.
Inline that in `__xdp2_parse_eth_specialised`.

This is what xdp2-compiler already does for *generated* parsers (it
can emit a specialised entry point per parser graph). Today's
benchmark uses the *generic* `__xdp2_parse` engine — switching to a
generated specialised version would close most of this gap.

### Fix C — emit a specialised `parse_<graph>` per parser

Today, `xdp2-compiler` generates protocol code but routes
everything through the generic `__xdp2_parse` engine at the top
level. The structural fix: emit a fully-specialised entry point
where every dispatch is a switch and every `ops.X()` call is
inlined:

```c
/* Generated by xdp2-compiler for the flow_dissector_l2 graph. */
int flow_dissector_l2_parse(const void *hdr, size_t len,
                             struct xdp2_metadata_all *meta,
                             struct xdp2_ctrl_data *ctrl) {
    /* Eth */
    if (len < 14) return XDP2_STOP_LENGTH;
    __u16 etype = *(__be16 *)(hdr + 12);
    memcpy(meta->eth_addrs, hdr, 12);
    meta->eth_proto = etype;
    
    switch (etype) {
    case htons(ETH_P_IP):
        return flow_dissector_l2_parse_ipv4(hdr+14, len-14, meta, ctrl);
    case htons(ETH_P_IPV6):
        return flow_dissector_l2_parse_ipv6(hdr+14, len-14, meta, ctrl);
    case htons(ETH_P_8021Q):
        return flow_dissector_l2_parse_vlan(hdr+14, len-14, meta, ctrl);
    /* ... */
    default:
        return XDP2_STOP_UNKNOWN_PROTO;
    }
}
```

This is the **C-side analogue of `graph_compiled.rs`** — code that
the existing xdp2-rs-compiler generates for Rust today. The C-side
codegen path needs the same treatment.

## Cost / effort estimate

| Fix | LoC scope | Effort | Expected win |
|---|---:|---:|---:|
| A — generated jump-table per node | ~200 LoC in xdp2-compiler codegen | 1-2 days | 10-15 ns/pkt |
| B — inline common `ops.X()` | ~300 LoC + new template | 2-3 days | 15-20 ns/pkt |
| C — fully-specialised per-graph entry | ~500 LoC + template overhaul | 3-5 days | parity with kernel flowdis |

Cumulative target: **bring `__xdp2_parse` (full parse) from 52 ns
to ~25 ns on https-web** — kernel-flowdis parity. Stretch: 18 ns
(matching `c-bpf-fast` on workloads where the chain set covers
80%+ of traffic).

## What's already done that this builds on

- **Phase A1-A5** (commit `a156609`): asm + perf-counter pipeline.
  Re-runnable per build to validate any structural change lands.
- **Phase O1+O5** (commit `8e8c6f5`): trivial wins (-14 ns/pkt on
  c-xdp2-usp).
- **Phase O2** (commit `5883d4d` + correction `5b58c2d`):
  hardcoded fast-path proves the architecture. The "real" fix is
  to make the GENERATED parser look like the fast path for the
  common case.
- **Rust `graph-enum`** + `graph_compiled`: existing examples of
  what the static-dispatched form looks like in the Rust codebase.

## Phases S1–S3 — realised wins (2026-05-09, commits a6c37e0 / 30998d9 / 5ad9440)

The structural plan landed three of the four phases:

### S1 — switch C benchmark default to `_opt` variant (commit `a6c37e0`)

Verified the `_opt` variant produced by xdp2-compiler skips both
`lookup_node()` and the function-pointer dispatch via
`proto_def->ops.X`. Just had to flip the benchmark default:

  **Local Zen 1, https-web.pcap, 100 iter:**
  | Mode | Before (-S, generic) | After (default, _opt) | Δ |
  |---|---:|---:|---:|
  | `XDP2 parser` | 62 ns/pkt | **38 ns/pkt** | -24 (-39%) |
  | Kernel flowdis | 27-29 ns/pkt | 27-29 ns/pkt | unchanged |

The C-side gap to kernel flowdis dropped from ~2.3× to ~1.3×.
Existing codegen, single-line change. Parity gate green.

### S2 — reorder `ipv6_table` (commit `30998d9`)

`parser_big.c` and `parser_simple_hash.c` had their `ipv6_table`
with extension headers at indices 0-3, TCP/UDP at 4-5. The generic
`__xdp2_parse` engine's linear `lookup_node()` walk was hitting
TCP/UDP only after 4 EH iterations. Reordered TCP/UDP to indices
0/1.

`flow_dissector_tables.h` already had the optimal order, so the
matrix benchmark itself doesn't see this win. The change benefits
parsers that use the generic engine (parse_dump, simple_router,
sample tuple parsers) on IPv6/TCP traffic.

Estimate: 3-6 ns/pkt on IPv6-heavy generic-engine workloads.
Parity gate green.

### S3 — drop dport-leaf nested match in `graph_compiled` + `graph_mono` (commit `5ad9440`)

The original plan called for a full xdp2-compiler codegen rewrite
to a flat state machine. In practice, the codegen at
`xdp2-rs/crates/xdp2-compiler/src/codegen.rs:183` emits a different
shape than the checked-in `graph_compiled.rs` (no FlowMeta
extraction; signature mismatch). Regenerating from codegen would
have lost functionality.

Pivoted to a focused hand-edit targeting the ONLY true 2-level
nesting in the file: the dport leaf-only match inside the TCP arm
(35 leaf arms) and inside the UDP arm (30+ leaf arms). Kept all
encapsulation arms (vxlan/geneve/gtpu).

  **Local Zen 1, combo.pcap, 50 iter (500K pkts):**
  | Mode | Before | After | Δ |
  |---|---:|---:|---:|
  | `rust-compiled` | 47 ns/pkt | **33 ns/pkt** | -14 (-30%) |
  | `rust-mono` | 51 ns/pkt | **36 ns/pkt** | -15 (-29%) |
  | `rust-graph-enum` (target) | 17 ns/pkt | 17 ns/pkt | (unchanged, the comparison) |

Closes the gap from 2.7-3× to 1.9-2.1× vs graph-enum. Doesn't reach
full parity because graph-enum has a fundamentally smaller
protocol surface (5 nodes vs 28+ ethertypes + 13 IP protos).

What's preserved: all extracted flow info (src/dst ports, ip_proto,
addrs, tcp_flags, addr_type, l3_off, l4_off) and tunnel
encapsulation parsing.

What's removed: per-app-protocol minimum-length stubs that did
length-only checks without populating metadata. Application
identification was always the consumer's job, not the
graph-walker's. Parity gate green.

### Summary table — full optimisation campaign cumulative wins

(Local Zen 1; numbers from each commit's smoke test on the same
machine. https-web.pcap unless noted.)

| Mode | Original baseline (combo) | Post-O1+O5 (https-web) | Post-S1+S3 (mixed) | Total Δ |
|---|---:|---:|---:|---:|
| `c-xdp2-usp` | 232 ns | 181 (https-web) | **38** (https-web, _opt) | **-194 ns / 84%** |
| `rust-compiled` | 47 ns | 47 (no change from O1+O5) | **33** (combo, S3) | **-14 ns / 30%** |
| `rust-mono` | 51 ns | 51 | **36** (combo, S3) | **-15 ns / 29%** |
| `rust-graph-enum` | 17 ns | 17 | 17 | unchanged (was already optimal) |
| `c-bpf-fast` | 18 ns | 18 | 18 | unchanged (kernel BPF JIT) |

**Honest framing:** the 84% win on `c-xdp2-usp` is mostly the
pre-existing `_opt` codegen finally being used by default. The
real new engineering was S2 + S3. The Rust 30% wins are
material. None of this closes the gap to kernel flowdis on full
parses — that's a deeper engineering effort (per the "fix shape
A/B/C" section above).

### What's still pending (deferred)

- **Full xdp2-compiler codegen rewrite** to emit graph_compiled
  from a structured IR (with FlowMeta extraction). The current
  codegen lacks that surface. Real engineering: ~1-2 weeks.
- **Closing the kernel-flowdis gap on full parses** (38 → 25 ns).
  Would require either inlining `_opt`'s per-node helpers (LTO
  may already do this — verify with disasm) or a fundamental
  change to the per-node-call boundary.
- **hp5 hardware re-measure** of S1+S2+S3 cumulative numbers via
  the matrix campaign. Local Zen 1 numbers are equivalent enough
  for the trend; canonical hp5 numbers are a small follow-up.

## See also

- `xdp2-rs/docs/fast-path-dispatch.md` — Rust dyn-vs-enum dispatch story
- `xdp2-rs/docs/deep-performance-analysis.md` — TMA + Zen 1 per-loop counters
- `xdp2-rs/docs/performance-next-steps.md` — pre-existing perf follow-up list
- `perf-results/asm/2026-05-08/asm-comparison-baseline.md` — per-impl
  ns/pkt + IPC + branch-miss data this analysis is built on
