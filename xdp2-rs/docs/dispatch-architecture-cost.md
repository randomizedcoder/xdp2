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

## See also

- `xdp2-rs/docs/fast-path-dispatch.md` — Rust dyn-vs-enum dispatch story
- `xdp2-rs/docs/deep-performance-analysis.md` — TMA + Zen 1 per-loop counters
- `xdp2-rs/docs/performance-next-steps.md` — pre-existing perf follow-up list
- `perf-results/asm/2026-05-08/asm-comparison-baseline.md` — per-impl
  ns/pkt + IPC + branch-miss data this analysis is built on
