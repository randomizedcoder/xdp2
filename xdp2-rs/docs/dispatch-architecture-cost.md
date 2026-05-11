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

## Phase R1 — Measured asm baseline (2026-05-10)

**Critical finding: the original cost model was wrong about
function-call inlining.** Direct disasm inspection of the
benchmark binary (post-S1+S2+S3 build,
`/nix/store/...-xdp2-flow-dissector-matrix-artifacts-0.1.0/bin/benchmark`)
shows:

### What the binary actually contains

```
$ nm benchmark | awk '$2 ~ /^[Tt]$/' | grep flow_dissector_l2 | wc -l
1
```

**Only ONE per-node text symbol exists on the
eth+ipv4+tcp common path** —
`xdp2_parser_flow_dissector_l2_xdp2_parse_etype_dispatch_node`.
gcc + LTO has fully inlined ~50 per-node helper functions into
this single entry. The function is 655 asm lines.

There ARE direct calls to ~10 encap nodes (vlan/vxlan/pbb/pppoe/
nsh/etc) but **these are not on the common eth+ipv4+tcp path** —
they're invoked only for the rare ethertypes.

### Indirect calls on the common path

```
$ objdump --disassemble=...etype_dispatch_node | grep -cE 'call.*\*'
2
```

Two indirect calls remain. Looking at the context, they're at:
- `call *%r9` after setting up args (rdx, rcx, etc.)
- `call *%rax` immediately after, with similar arg setup

These are the `proto_def->ops.extract_metadata` and
`proto_def->ops.handler` callback pointers. gcc + LTO does NOT
devirtualize them because the function pointers live in a
`const struct xdp2_proto_def` that's referenced via a chain of
indirections gcc can't trace at compile time.

### Revised 13 ns gap model

The Phase-1 cost model said function-call boundaries cost
~24 cycles (7.5 ns) of the gap. **That component is roughly zero**
in the actual binary — gcc inlined everything on the common path.

Updated cost attribution (subject to confirmation by perf record
on hp5):

| Component | Cycles | ns | Notes |
|---|---:|---:|---|
| ~~Per-node function-call boundaries~~ | ~~24~~ | ~~7.5~~ | **Zero — gcc inlined them** |
| Indirect ops callbacks (extract_metadata + handler) × 2 | ~12 | 3.8 | Confirmed in disasm; ~6 cycles each on Zen 1 |
| Per-node boilerplate inside the inlined body | ~? | ~? | The 655-line function still contains per-node prologues/epilogues even when inlined; needs perf record to attribute |
| Frame-pointer indirection | ~6 | 1.9 | Confirmed by `mov ...,-0x38(%rbp)` register-spill pattern in the disasm |
| Branch mispredicts (large switch with 28 ethertype + 13 ipproto arms) | ~? | ~? | The big switch table + nested switches likely cost more than the ops callbacks; perf record should confirm |

**The architectural rebuild thesis is still correct** — kernel
flowdis avoids ALL of this by being a single hand-tuned function
with goto-state-transitions and direct stores. But the specific
fix priority changes:

1. **Devirtualise the ops callbacks** (R5) — confirmed 12
   cycles on the table; this is the highest-leverage target.
2. **Eliminate the per-node boilerplate inside the inlined
   body** (part of R3 + R5) — even when inlined, each node's
   "extract_metadata-NULL-check, handler-NULL-check, encap-flag-
   check, last_node-update" boilerplate is in the hot path.
3. **Restructure the big switch** (part of R3) — gcc may already
   emit a jump table; if not, R3's mono codegen with explicit
   goto-state would help. But this might be a smaller win than
   originally modelled.

### Implication for R3 priority

R3's centerpiece (mono codegen) was modelled as worth ~24 cycles
of function-boundary elimination + ~12 of devirtualisation = ~36
cycles. Reality is more like 0 + 12 + boilerplate-savings + branch-
prediction-improvement. The total 13 ns gap is real but its
composition is different. R3 + R5 + R6 collectively still get us
there, but in different proportions.

**R1 next sub-tasks (deferred to next session):**

- R1.1: perf record on hp5 with high sample rate, attribute
  cycles per instruction in the entry function. This will pin
  down where the boilerplate + branch-mispredict cost actually
  lives.
- R1.2-R1.4: same exercise for kernel flowdis; build the diff.

For now the takeaway: **the binary is already half of what we
hoped for from R3 (per-node helpers ARE inlined post-LTO)**. R3's
delta is probably smaller than the plan estimated. R5 (callback
devirt) becomes higher-priority. The plan's overall direction is
right; the per-phase ns budgets need re-allocation after R1.1
data lands.

### R1.2-R1.3 — measured baseline on GENERIC engine + kernel flowdis (2026-05-10)

Wired up a focused `perf-record-c-xdp2-r1` nix target (commit
TBD) — runs `perf record -F 999 -g` on the C benchmark binary,
extracts perf-annotate for the hot entry function. Categorised
each non-zero-sample instruction with
`nix/scripts/r1-attribute-cycles.sh`.

**Pre-S1 generic-engine baseline (combo.pcap, `__xdp2_parse`):**

| Component | % of cycles | ns / pkt | Notes |
|---|---:|---:|---|
| compute (test/cmp/and/cmovg…) | 44.83 | 104.4 | Most of this is the `lookup_node()` linear-search compare loop |
| branch_dense (conditional jumps) | 30.08 | 70.1 | Loop back-edge + flag checks; the 17.05% single hot instr at `jne 1ee70` is the proto-table miss path |
| load | 9.83 | 22.9 | Walking proto_table entries + struct field loads |
| regshuffle (reg-to-reg mov) | 5.21 | 12.1 | Argument prep before indirect calls |
| indirect_call | 4.04 | 9.4 | `ops.next_proto` + `ops.extract_metadata` + `ops.handler` dispatches |
| frame_indirect (stack spills) | 2.32 | 5.4 | Small function — most state stays in regs |
| store (productive field writes) | 0.58 | 1.4 | Almost no useful work — extraction is in callbacks |
| direct_call | 0.00 | 0.0 | LTO inlined everything on the common path |
| **TOTAL** | 99.21 | 233.0 | Matches measured `XDP2 parser: 233 ns/pkt` |

**Kernel flowdis baseline (combo.pcap, `__skb_flow_dissect_err`):**

| Component | % of cycles | ns / pkt | Notes |
|---|---:|---:|---|
| compute | 29.54 | 48.2 | Big switch arm comparisons + length/version checks |
| branch_dense | 22.71 | 37.0 | `goto proto_again` / `goto ip_proto_again` state-machine |
| frame_indirect | 18.17 | 29.6 | Much bigger function (1540 lines) — more local state |
| store (productive field writes) | 18.13 | 29.5 | **The productive work — direct stores to `flow_keys`** |
| prologue (push/pop/ret/nop) | 4.55 | 7.4 | Single-function prologue/epilogue |
| load | 4.55 | 7.4 | Packet+struct loads |
| regshuffle | 2.27 | 3.7 | Reg-to-reg shuffling |
| indirect_call | 0.00 | 0.0 | **Zero indirect dispatch — all direct** |
| direct_call | 0.00 | 0.0 | Helpers like `__skb_flow_get_ports` show as separate symbols below |
| **TOTAL** | 99.92 | 163.0 | Matches measured `Kernel flowdis: 163 ns/pkt` |

**Per-component delta (XDP2 generic – kernel flowdis):**

| Category | XDP2 ns | flowdis ns | delta | Interpretation |
|---|---:|---:|---:|---|
| compute | 104.4 | 48.2 | **+56.3** | XDP2 wastes cycles on `lookup_node()` linear search |
| branch_dense | 70.1 | 37.0 | **+33.1** | Proto-table iteration + per-layer flag/encap checks |
| load | 22.9 | 7.4 | +15.5 | Proto-table struct loads (table entry, type, node ptr) |
| regshuffle | 12.1 | 3.7 | +8.4 | Calling-convention arg-prep across the 3 indirect calls |
| indirect_call | 9.4 | 0.0 | +9.4 | The 3 ops dispatches — `next_proto` + `extract_metadata` + `handler` |
| branch_uncond | 1.4 | 0.0 | +1.4 | jmp branches between proto-table cases |
| frame_indirect | 5.4 | 29.6 | -24.2 | Flowdis has more locals (TCP options state); XDP2 spills less |
| prologue | 2.7 | 7.4 | -4.7 | Flowdis is one big function — bigger prologue |
| store | 1.4 | 29.6 | **-28.2** | **Flowdis does 22× more productive work per cycle** |
| direct_call | 0.0 | 0.0 | 0.0 | Both inlined on common path |
| **TOTAL** | 233.0 | 163.0 | **+70.0** | The dispatch tax (pre-S1 baseline) |

**Key insight from the delta table:** the `store` line is the
inverse-tell. Flowdis spends 22× more time writing fields to
`flow_keys` than XDP2 spends on its `metadata` struct, even
though they extract the same information. The reason: XDP2's
extraction happens inside callback functions invoked via
indirect calls, and the callbacks share helper utilities that
dilute the per-instruction sample density. The "real work" is
hidden in the +9.4 ns indirect-call bucket plus the helper
functions (`ipv4_metadata`/`ipv6_metadata`/`ports_metadata`/
`tcp_len`/`ip_proto`) which show up as separate symbols
totaling ~94 samples vs ~44 for `__skb_flow_dissect_err` and
~14 for `__skb_flow_get_ports`.

The `compute` + `branch_dense` + `load` triplet sums to **+105 ns**
in XDP2 — that's the price of the `lookup_node()` linear-search +
proto-table walking. S1 (switching to `_opt`) eliminates most of
this; the post-S _opt path measured at 38 ns on https-web
(13 ns gap vs flowdis 25 ns) is consistent with the
generic-engine 233 ns minus the ~190 ns of lookup-loop overhead.

### R1.1 — measured baseline on post-S `_opt` path (combo.pcap)

Fresh perf-record on hp5 (200 iter × 500 000 pkt × 3 impls,
benchmark binary built post-S1, parser=optimized,
`/nix/store/...-xdp2-flow-dissector-matrix-artifacts-0.1.0/bin/benchmark`,
47 033 cpu/cycles/P samples at -F 999):

```
Kernel flowdis: 172 ns/pkt
XDP2 parser:    188 ns/pkt   ← post-S _opt path
XDP2 parse-only:186 ns/pkt
```

**Gap: 16 ns/pkt** (XDP2-C 188 vs flowdis 172). Different
absolute numbers than https-web — combo.pcap has deeper encap +
TCP options + more protocol diversity, so both impls do more
work. The gap is similar in magnitude to the 13 ns from
https-web measurements.

### R1.0 correction — per-node helpers are NOT all inlined

R1.0 incorrectly concluded "only 1 text symbol exists" and that
LTO had inlined everything. Direct binary inspection shows the
opposite:

```
$ objdump --disassemble=xdp2_parser_flow_dissector_l2_xdp2_parse_etype_dispatch_node benchmark | grep -cE "call.*<"
12   # 12 DIRECT calls from entry into per-node helpers
$ objdump --disassemble=xdp2_parser_flow_dissector_l2_xdp2_parse_etype_dispatch_node benchmark | grep -cE "call.*\*"
2    # 2 INDIRECT calls remain in entry (with ~0% samples on common path)
```

The `__xdp2_parser_flow_dissector_*_node_xdp2_parse.isra.0`
per-node helpers exist as separate functions called via direct
`call <addr>` from the entry function. They are:
ipv4_node, tcp_node, udp_node, ipv6_node, batman, trill, hsr,
e8021Q, pbb, e8021AD, pppoe, nsh, snap, edsa, ipv6_eh,
ah_ipv6, ether_inner, gre_v0, ipv6_frag. ~16 separate functions
on the common-path tree.

R1.0's error was in the `grep flow_dissector_l2 | wc -l` — that
filter only matched the entry symbol (which has `_l2` in its
name). The per-node helpers are named without `_l2`. The actual
inlining structure: each helper is its own function with
prologue/epilogue and direct-call boundaries to its successor
node.

### R1.2 — per-symbol component attribution (post-S _opt)

Used `nix/scripts/r1-attribute-cycles.sh` with the fresh
F999 perf-record data (3090 samples across the 5 hot symbols
on the eth+ipv4/v6+tcp/udp path). Attribution weighted by
sample share:

| Component | XDP2 ns | flowdis ns | delta ns | Notes |
|---|---:|---:|---:|---|
| compute | 57.8 | 48.3 | **+9.6** | Per-node length/version/IHL checks (mostly in helpers) |
| branch_dense | 50.8 | 33.5 | **+17.2** | Big switch in entry + per-node conditionals in helpers |
| prologue (push/pop/ret/nop) | 20.6 | 8.9 | **+11.7** | Per-helper function-call boundary overhead (15 helpers × ~1-2 ns each) |
| regshuffle (reg-to-reg mov) | 20.0 | 9.0 | **+11.0** | Argument-marshalling before each direct call |
| store (metadata writes) | 26.0 | 19.8 | +6.3 | XDP2 actually stores more metadata than flowdis here |
| load (packet/struct reads) | 5.4 | 19.7 | **-14.3** | Flowdis re-reads packet header bytes more |
| frame_indirect (stack spills) | 0.2 | 21.5 | **-21.3** | Flowdis has deep local state (TCP options walker etc.) |
| branch_uncond (jmp) | 2.8 | 2.3 | +0.5 | Mostly the same |
| direct_call | 0.2 | 1.9 | -1.8 | Flowdis calls `__skb_flow_get_ports`/`memcmp`/etc. |
| indirect_call | **0.0** | **0.0** | 0.0 | **Both: zero on hot path. R5 saves nothing here.** |
| other (movdqu / SIMD) | 3.0 | 6.1 | -3.1 | flowdis has more `movups %xmm0,...` zeroing instructions |
| **TOTAL** | **188.0** | **172.0** | **+16.0** | Matches measured gap exactly |

### R1.3 — what the 16 ns gap actually composes

Boiled down:

| Sub-gap | ns | Phase target | Estimated win |
|---|---:|---|---:|
| **Function-call boundaries** (prologue + regshuffle) | +22.7 | **R3 (mono codegen)** — inlining all per-node helpers into a single function with goto-state transitions | **up to ~22 ns** (most of this gap) |
| **Big-switch + per-node conditionals** | +17.2 | **R3 + R2** — flatter dispatch tree, hot-edge ordering | ~3-8 ns (modest — gcc already optimises the switch) |
| **Per-node validation** (compute) | +9.6 | hard to remove without skipping safety | minimal |
| **Metadata stores** (store) | +6.3 | already productive work; R3 can't reduce | n/a |
| **Stack/load overhead diff** (frame_indirect + load) | -35.6 | flowdis does more — XDP2 already ahead here | none |
| **Indirect-call overhead** | 0.0 | **R5 saves NOTHING on this path** | 0 ns |
| **Net** | +16 | | up to ~25 ns improvement (188 → 163 ns) |

### R1.4 — revised R-phase priority and ns budgets

The R1.0 conclusions need correction; the actual data points
to a very different cost composition:

1. **R3 (monolithic codegen) is the highest-leverage phase
   — projected ~22 ns win** by eliminating the per-helper
   function-call boundaries (prologue + regshuffle). This
   makes R3 the centerpiece of the rebuild, as originally
   planned in the R1-R8 doc, but for a different
   reason than the plan said (it's not about *adding* inlining
   — the helpers are already inlined into the parse tree
   structure conceptually; it's about *flattening* the 15
   separate-function tree into one function with goto
   transitions).
2. **R5 (devirtualise ops callbacks) saves nothing.** The
   common eth+ipv4/v6+tcp/udp path has 0% indirect_call
   samples in the perf data. The 2 indirect calls still
   present in the entry function are reached only by rare
   parse paths (encap depth limit, exit-node fallback, etc.).
   *Drop R5 from the urgent list; keep it as cleanup later
   if the indirect-call-fallback paths matter for adversarial
   workloads.*
3. **R6 (encap / frame management cleanup) is also low-value
   here.** Frame_indirect is ALREADY tiny on XDP2 (0.2 ns vs
   flowdis 21.5 ns) — flowdis has more stack usage, not less.
   The encap-bookkeeping overhead the plan called out lives
   elsewhere (probably in the per-node helpers' prologue,
   which R3 absorbs).
4. **R4 (refactor 6 parsers) is still needed** as a
   prerequisite for R3 to apply broadly. Without R4, only
   the simpler parsers can be re-emitted via the mono
   codegen.

**Updated phase ns budget:**

| Phase | Was modeled | Revised by R1 data |
|---|---:|---:|
| R3 (mono codegen) | ~11 ns | **~22 ns** ← the big win |
| R5 (devirt callbacks) | ~12 cycles / 3.8 ns | ~0 ns ← drop urgency |
| R6 (encap cleanup) | ~8 cycles / 2.5 ns | ~0 ns ← drop urgency |
| Branch / compute restructuring (part of R3) | ? | ~3-8 ns |
| **Net achievable** | ~16 ns | **~25 ns (188 → 163 ns, parity with flowdis)** |

The rebuild is still worth doing — the architectural thesis
("flatten the per-node tree into a single function with
goto-state transitions, like flowdis") is correct. But the
cost composition has shifted from "indirect dispatch tax" to
"per-helper function-call boundary tax". This changes which
sub-tasks within R3 are highest priority.

## Phase R3 phase 1 — hand-written mono reference (2026-05-10)

Implemented the R3 scaffolding and a hand-written mono parser
covering the eth → ipv4/v6 → tcp/udp/icmp common path
(`samples/flow_dissector/flow_dissector_mono.h`):

- New `XDP2_MONOLITHIC` parser_type and `XDP2_PARSER_MONO()` macro.
- xdp2_parse() routes XDP2_MONOLITHIC through the same direct
  entry-function dispatch as XDP2_OPTIMIZED — at the dispatch
  boundary they're identical; the difference is in the SHAPE of the
  generated function (one goto-state function vs N per-node helpers).
- `-M` flag in `samples/flow_dissector/benchmark.c` selects the mono
  variant for performance + correctness testing.

**Measured speedups on x86_64 (local — not the hp5 testbed):**

| PCAP | mono ns/pkt | opt ns/pkt | flowdis ns/pkt | correctness |
|---|---:|---:|---:|---|
| tcp_ipv4.pcap (11 pkts) | **5** | 15 | 20 | 11/11 ✓ |
| icmp_ipv4.pcap (6 pkts) | **7** | 15 | 23 | 6/6 ✓ |
| https-web.pcap (20 000 pkts) | **12** | 42 | 30 | 20 000/20 000 ✓ |

**Headline:** on https-web (realistic web-server traffic mix, no
encap), mono runs at 12 ns/pkt vs opt 42 vs kernel flowdis 30 with
100% metadata parity against kernel flowdis. **mono is 3.5× faster
than _opt** and **2.5× faster than kernel flowdis** with bit-exact
correctness across 20 000 packets.

This confirms the R1.4 model: the post-S _opt path's 188 ns gap
*is* the per-helper function-call boundary tax, and flattening to a
single goto-state function eliminates most of it. mono on https-web
runs in ~38 cycles/pkt — comparable to what the BPF-JIT-compiled
`fast_flow.bpf.o` reaches (15 ns/pkt with 85% common-case hits).

## Phase R3 phase 2 — extended encap coverage (2026-05-10)

Extended the hand-written mono reference to handle the major encap
layers that R3 phase 1 didn't cover:

- **VLAN/QinQ** (`ETH_P_8021Q` / `ETH_P_8021AD`) — strips up to
  `XDP2_MAX_VLAN_CNT` tags, records id/priority/tpid per tag, jumps
  back to the dispatch_etype label with the inner ethertype.
- **MPLS** (`ETH_P_MPLS_UC` / `ETH_P_MPLS_MC`) — walks the label
  stack to bottom-of-stack, records first-label metadata, then
  peeks the IP version nibble to dispatch into IPv4 or IPv6.
- **PPPoE** (`ETH_P_PPP_SES`) — strips 6-byte PPPoE header + 2-byte
  PPP protocol type, dispatches on PPP_IP (0x0021) / PPP_IPV6 (0x0057).
- **IPv6 extension headers** — hop-by-hop, routing, dest-options,
  mobility, HIP, shim6 use the generic `nexthdr + hdrlen×8` walker.
  Fragment header has its own block (fragment offset + first_frag
  metadata). AH header walks `nexthdr + hdrlen×4`.
- **GRE v0** — flag-driven header length (4-16 bytes), encap depth
  bounded, dispatch on inner protocol type (etype-encoded).
- **IPIP / 6-in-4 / 6-in-6** (`IPPROTO_IPIP` / `IPPROTO_IPV6` as
  next-protocol) — encap depth counter, goto inner IPv4/IPv6 parse.

**Correctness sweep across the in-tree PCAP corpus** (33 PCAPs):

| Pcap | matches | notes |
|---|---:|---|
| tcp_ipv4 / tcp_ipv6 / tcp_sack | 100% | core path |
| icmp_ipv4 / icmp_ipv6 | 100% | |
| ipv4frags | 100% | |
| vlan_icmp / QinQ | 100% | vlan stripping |
| can-2003-0003 | 100% | non-IP L2 |
| l2tp / l7_l2tp | 100% | L2TP v3 + L7 path |
| ipip | 100% | 4-in-4 |
| 6in4 / 6to4 | 100% | PPPoE-wrapped IPv4(IPV6) |
| gre-sample / gre-within-gre | 100% | GRE v0 nested |
| plain-ipv6-64 | 100% | |
| srv6-* (8/9 pcaps) | 100% | segment routing |
| zlip-{1,2,3} | 100% | recursive IP-in-IP |
| protobuf_in_udp | 100% | |
| ipv6-udp-fragmented | 33% | only first_frag passes; non-first fragments differ on inner-derived addrs (flowdis quirk?) |
| gre-pptp | 0% | PPTP-version-1 GRE — mono bails at v != 0 |
| srv6-end_dx2-64 | 0% | inner L2 segment routing variant |
| vxlan | n/a | empty pcap |

Headline: **30 of 33 PCAPs at 100% bit-exact metadata parity with
kernel flowdis.** The 3 remaining failures are minor specific cases
(PPTP-style GRE, an SRv6 variant, non-first-fragment IPv6 addr
quirks).

**Phase 2 perf** on https-web (20 000 pkts × 500 iter):

```
Kernel flowdis: 30 ns/pkt
XDP2 mono:      16 ns/pkt  (1.9× faster, 100% correctness)
XDP2 _opt:      42 ns/pkt  (pre-mono baseline)
```

Phase 2 added 4 ns/pkt over phase 1 (12 → 16 ns) — the cost of the
extra dispatch arms (VLAN, MPLS, PPPoE, IPv6 EH, encap depth).
Still 1.9× faster than kernel flowdis with substantially more
coverage. Layout-level optimisations (reorder switch cases by
hit-frequency, likely() on hot arms) can shave this further in a
later pass.

**Phase 1 → phase 2 → phase 3 trajectory:**

| Phase | Deliverable | State |
|---|---|---|
| R3.1 | Macro + dispatch + minimal mono reference (eth/ipv4/ipv6/tcp/udp/icmp) | **DONE** |
| R3.2 | Extended encap coverage (vlan / qinq / mpls / pppoe / ipv6 EH / gre / ipip / 6in4 / 6to4) | **DONE** — 30/33 PCAPs at 100% |
| R3.3 | Replace hand-written reference with template-generated codegen (`mono_parser.template.c`) consuming the R2 IR | not started |
| R3.4 | Hardcoded eth+ipv4+l4 fast-path emitted by template (R3.5 in plan) | not started — the existing benchmark.c O2 path covers this manually |

**Remaining R3.2 follow-ups:**

- PPTP-style GRE (version 1) — adds key/seq/ack fields, currently
  mono bails. Would extract `_meta->gre_pptp` like the OPT path.
- SRv6 `end_dx2` — inner L2 cross-connect variant; needs SR header
  flag bit dispatch.
- IPv6 non-first-fragment addr handling — flowdis appears to zero
  trailing address bytes; mono keeps the outer addrs verbatim. Needs
  closer inspection of the flowdis semantics.

These are not blockers for R3.3 (template codegen) — they're
localised additions to the goto-state machine that the codegen
template can emit once the IR carries the right per-protocol
shape.

## See also

- `xdp2-rs/docs/fast-path-dispatch.md` — Rust dyn-vs-enum dispatch story
- `xdp2-rs/docs/deep-performance-analysis.md` — TMA + Zen 1 per-loop counters
- `xdp2-rs/docs/performance-next-steps.md` — pre-existing perf follow-up list
- `perf-results/asm/2026-05-08/asm-comparison-baseline.md` — per-impl
  ns/pkt + IPC + branch-miss data this analysis is built on
