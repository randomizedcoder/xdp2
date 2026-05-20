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
| R3.3 | Replace hand-written reference with template-generated codegen consuming the R2 IR | **DONE** — see §R3.3 below |
| R3.4 | Hardcoded eth+ipv4+l4 fast-path emitted by template (R3.5 in plan) | not started — the existing benchmark.c O2 path covers this manually |

**Remaining R3.2 follow-ups (inherited by R3.3 codegen):**

- PPTP-style GRE (version 1) — adds key/seq/ack fields, currently
  mono bails. Would extract `_meta->gre_pptp` like the OPT path.
- SRv6 `end_dx2` — inner L2 cross-connect variant; needs SR header
  flag bit dispatch.
- IPv6 non-first-fragment addr handling — flowdis appears to zero
  trailing address bytes; mono keeps the outer addrs verbatim. Needs
  closer inspection of the flowdis semantics.

## Phase R3.3 — compiler-driven mono codegen (2026-05-17)

R3.3 took mono from a hand-written reference to a compiler-emitted
parser shipped as the canonical `c-xdp2-mono` implementation. Eight
shippable commits on `merge/matrix-physical-testbed`:

| Commit | Sub-phase | Scope |
|---|---|---|
| `1d818f2` | R3.3.1 | Fix pyratemp `TemplateSyntaxError` in `mono_def.template.c` — nested `<!--(if)-->` block tags at the same tab indent as the outer `<!--(for)-->` parsed as siblings. Indent fix; xdp2-compiler now emits 2.4 MB of valid C. |
| `5bb82e5` | R3.3.2 | Wire `check_mono_eligibility()` per-root in `main.cpp`; drop TLV/flag_fields gates (scaffold template skips those walks anyway, matching the hand-written reference). 15/15 flow_dissector roots pass eligibility. |
| `523fade` | R3.3.3 | Add `parser.mono.c` Makefile rule; introduce `xdp2-compiler -D` flag (forwards to clang as `--extra-arg=-D`); `USE_GENERATED_MONO=1` build flag swaps the c-xdp2-mono binding. |
| `20a60dc` | R3.3.4 | Template: inline `memcpy` per `metadata_transfer` (gated on `mt_all_copy`). Shipped with latent parity bug — IR analysis can miss fields. |
| `2f9e7c6` | R3.3.5 | Template: inline `next_proto` load (gated on `npi_simple`). Same latent bug. |
| `be2df7e` | R3.3.6 | Nix derivation passes `USE_GENERATED_MONO=1`; introduce `XDP2_PARSERS_SKIP` guard in `src/include/xdp2/parser.h` so the dual-TU build (`parser.p.c` + `parser.mono.c` both `#include "parser.c"`) doesn't collide on the base `xdp2_parser_X` globals; R3.3.4/.5 inline emits temporarily disabled to restore parity. |
| `65bae62` | R3.3.4b | IR-coverage gate: `mt_full_coverage = mt_all_copy AND transfers >= leaf_fields`. Compares LLVM-IR-derived transfer count against the metadata_record's declared leaf field count; only inline-emit when the IR pass captured every field the C extract_metadata function writes. Restores R3.3.4 inline emit safely. |
| `fb586f1` | R3.3.5b | Re-enable R3.3.5 inline `next_proto`. The `npi_simple` gate (byte-aligned full-mask 8/16/32-bit load, no scaled offset) is structurally sufficient — no separate coverage check needed. |
| `5135e3e` | (tooling) | `flow-dissector-matrix-unified` runs the benchmark twice (`-O` and `-M`); aggregator recognises `c-xdp2-mono`. First end-to-end matrix-sprint row for the generated parser. |
| (this commit) | R3.3.7 | Delete `flow_dissector_mono.h` (460 lines). Generator is canonical. |

### The IR-coverage bug

R3.3.4 originally landed unconditional inline emit and shipped with
a parity failure that compile-only verification didn't catch: the
LLVM IR analysis underlying `metadata_transfers` can emit FEWER
transfers than the C `extract_metadata` function actually writes.
E.g. `ipv4_metadata` writes 6 fields (`is_fragment`, `first_frag`,
`l3_off`, `addr_type`, `ip_proto`, `addrs.v4_addrs`) but the IR
analysis captured only 2 simple copies. Replacing the indirect
call with inline emit alone silently dropped the 4 IR-invisible
fields — 0/11 matches on tcp_ipv4 against kernel flowdis.

R3.3.4b's fix: precompute a per-vertex `mt_full_coverage` flag in
the template Python preprocessing as `mt_all_copy AND len(transfers)
>= metadata_record_field_count AND field_count > 0`. The leaf-field
count comes from a C++-side recursive walk over the vertex's
`metadata_record` (`python_generators.h`, R3.3.4b commit), exposed
to the Python preprocessor as a single int. When the gate fails,
fall back to the indirect call — correctness preserved.

The lesson: **compile-only verification is the failure mode**.
Every future template-edit phase should run `nix build
.#checks.parity-gate` as part of its verification, not just `gcc -c`.

### Headline perf — first matrix-sprint with generated mono

`perf-results/2026-05-17-r3.3-mono-v3/summary.md`, hp2-hp5-x710
testbed, `https-web.pcap`, 100 iter, single replicate:

| Mode | hp2 ns/pkt | hp5 ns/pkt |
|---|---:|---:|
| `c-bpf-fast` | 23 | 23 |
| `rust-simd` | 40 | 40 |
| `rust-template` | 68 | 68 |
| `rust-compiled` | 72 | 73 |
| `rust-mono` (hand-written) | 77 | 72 |
| `rust-mono-x4` | 83 | 83 |
| `rust-graph-enum` | 104 | 105 |
| `c-bpf-flowdis` | 113 | 114 |
| **`c-xdp2-mono`** | **115** | **114** |
| `c-flowdis-usp` | 116 | 117 |
| `c-xdp2-usp` (_opt) | 131 | 134 |
| `c-xdp2-parse-only` | 131 | 138 |
| `rust-graph` (dyn) | 267 | 272 |

**The R3 architectural-rebuild target is met**: an extensible
parse-graph parser (XDP2-C with mono codegen) now matches a
hand-tuned monolithic parser (kernel flowdis) on realistic mixed
traffic, while remaining graph-extensible.

c-xdp2-mono lands at kernel-flowdis parity on full https-web —
~15% faster than the c-xdp2-usp function-pointer-tree variant,
statistically indistinguishable from c-flowdis-usp and
c-bpf-flowdis. The gap to `c-bpf-fast` (23 ns) is the "no dispatch
at all" tax of running a parse graph; the gap to `rust-simd`
(40 ns) is what SIMD ntuple matching buys vs. a goto-state machine.

The win is smaller on https-web (~15%) than on simple synthetic
pcaps because https-web exercises many nodes whose
`extract_metadata` is not IR-decomposable (R3.3.4b's coverage gate
falls back to indirect for those), so the bulk of packets still
hit some indirect-call cost. Simple-pcap snapshot (local dev box,
artifact from R3.3.5b/R3.3.7, auto-scaled iter so each measurement
spans ≥100 K total parses):

| pcap | pkts | iter | c-xdp2-mono | c-xdp2-usp | mono delta |
|---|---:|---:|---:|---:|---:|
| tcp_ipv4 | 11 | 9 090 | 9 ns | 14 ns | −36% |
| tcp_ipv6 | 12 | 8 333 | 9 ns | 14 ns | −36% |
| icmp_ipv4 | 6 | 16 666 | 8 ns | 11 ns | −27% |
| vlan_icmp | 1 | 100 000 | 9 ns | 12 ns | −25% |
| QinQ | 2 | 50 000 | 8 ns | 9 ns | −11% |
| 6in4 | 20 | 5 000 | 6 ns | 20 ns | −70% |
| gre-sample | 40 | 2 500 | 10 ns | 23 ns | −57% |
| srv6-end-64 | 1 | 100 000 | 12 ns | 20 ns | −40% |

Mono wins on every probed pcap; range −11% (QinQ) to −70% (6in4).

A previous snapshot of this table at `-n 100` on the same pcaps
suggested a +10% vlan_icmp "regression"; that was measurement noise
— vlan_icmp.pcap is a single packet, so `-n 100` totals ~10 µs of
wall-time per cell, dominated by `clock_gettime` overhead and
one-time JIT/branch-predictor warm-up costs. At ≥100 K total parses
the picture is clean. Lesson: per-pcap perf snapshots need
iteration counts auto-scaled to packet count.

### R3.3 deviations from plan

1. **R3.3.1 "segfault"** was actually a pyratemp `TemplateSyntaxError`
   from sibling-indent block tags. The CLI segfault the R3.3 phase 0
   commit message referenced was a separate pre-existing issue —
   missing `XDP2_*_INCLUDE_PATH` env vars outside Nix.
2. **R3.3.2 loosening** dropped TLV / flag_fields gates entirely
   (plan called for a "per-vertex descendant walk Option A"). The
   scaffold template doesn't emit walkers for those anyway.
3. **`XDP2_PARSERS_SKIP` guard** (added in R3.3.6) was not in the
   plan. The dual-TU duplicate-symbol issue the plan called
   "acceptable rodata duplication" turned out to be a hard link
   error.
4. **R3.3.4 / R3.3.5 latent parity bug** forced an R3.3.4b/.5b
   split. Future template-edit phases should run the parity gate
   in their verification.
5. **Hot-edge ordering** (R2 gap #3, planned as part of R3.3.5)
   deferred. The structural inline-load win is the bigger of the
   two.

### What R3.3 leaves open

- **Perf-ceiling guard in parity-gate** (planned for R3.3.7): not
  shipped this commit. Needs benchmark JSON ingestion +
  `c-xdp2-mono` ns/pkt threshold vs `c-bpf-fast`. Reasonable
  follow-up (~30 LoC in `nix/checks/parity-gate.nix`).
- **R3.4 fast-path emit** from the template (vs. the manual
  `xdp2_eth_ipv4_l4_fast()` in benchmark.c). Optional.

## Phase R3.5.2 — wider IR coverage (2026-05-17, commit `594f0cb`)

Pushed three coupled changes to extend the R3.3.4b inline
`extract_metadata` emit beyond its initial coverage:

1. **New pattern `metadata_pattern_const_no_gep`** matches
   `store iN <const>, ptr %3` (offset-0 direct constant store, no
   intermediate GEP — LLVM's shape for `_meta->addr_type = X` and
   similar). Adds 3 transfers across the parser graph.
2. **Fixed the R3.3.4b coverage gate** that had been silently
   disabling the inline emit since `65bae62`. The gate compared
   per-vertex transfer-count to `metadata_record_field_count` —
   computed from `v.metadata_record`, which holds the FULL 64-leaf
   `xdp2_metadata_all` struct for every vertex. The threshold was
   always 64; transfers rarely reached that; the gate rejected
   everything; `c-xdp2-mono` ran entirely on indirect calls.
3. **Tightened the gate from `>=` to `==`** so duplicate-match
   cases (e.g. `icmp_metadata`'s conditional `icmp.id` write that
   the IR analysis splits into multiple variants) don't fire
   inline-emit with mismatched sources.

After the fix:

  Per-node coverage (in `samples/flow_dissector/parser.c`):
    9 nodes mt_full_coverage=True (was 0)
      tcp, udp, ports, ether_inner, ipv6_eh, l2tp, esp,
      ah_ipv4, ah_ipv6

  Per-parser-root × vertex inline emissions in parser.mono.c:
    R3.3.4 inline memcpy:       154 (was 0)
    R3.3.5 inline next_proto:   378 (unchanged)

  Parity: 22/22 ok on the standing corpus.

### Surprising perf result — the inline emit doesn't move the headline

hp5 `https-web.pcap` matrix sprint
(`perf-results/2026-05-17-r3.5.2/summary.md`):

| Mode | pre-R3.5.2 hp5 | R3.5.2 hp5 |
|---|---:|---:|
| `c-xdp2-mono` | 114 ns | 116 ns |
| `c-xdp2-usp` | 134 ns | 130 ns |
| `c-flowdis-usp` | 117 ns | 119 ns |

The `c-xdp2-mono` headline barely moves (114 → 116 within
single-replicate noise). The 9 inline-emit nodes ARE on the
https-web hot path (especially `tcp_node`, `udp_node`,
`ports_node`), but the perf is unchanged.

**Why**: gcc + LTO was already inlining the `extract_metadata`
function-pointer call effectively at -O2. The R3.3 win (15% vs
`_opt`) came almost entirely from the goto-state body shape
(eliminating per-node function-call boundaries) and from
R3.3.5's inline `next_proto` (which devirtualises a call that
LTO genuinely couldn't inline because the function pointer
crosses the parse-graph dispatcher). R3.3.4's inline emit, even
when working, just re-produces what LTO was already doing.

This shifts the priority of the remaining R3 follow-ups:

- **R3.4 (hardcoded fast-path emit)** moves up. It sidesteps the
  parse graph entirely for the eth+ipv4+l4 chain, which would
  give the mono parser the `c-bpf-fast` (23 ns) floor on
  workloads where ≥80% of packets fit the chain. This is the
  remaining-large headroom.
- **R3.5 (wider IR coverage)** moves down. The infrastructure
  works (R3.5.2 proves it) but further coverage gives at most
  marginal perf wins on top of LTO's existing inlining. Still
  useful as a correctness foundation for a future BPF-target
  mono codegen (where LTO doesn't apply).
- **Hot-edge ordering** (R2 gap #3) is still on the table —
  reordering switch arms by hit-frequency affects branch
  prediction, which LTO doesn't influence. Likely the second-best
  perf knob after R3.4.

R3.5 pattern follow-ups deferred to that future-BPF-target
audience:
- hdr_off pattern variant for ptr-diff-derived offsets (l3_off
  in ipv4/ipv6_metadata).
- Conditional-bit-op decomposition (is_fragment / first_frag).
- Multi-store deduplication for icmp_id-style conditional writes
  (would let the gate accept some `transfers > stores` cases).

## Phase R3.4.1 — template fast-path lands (2026-05-17, commit `0f7668e`)

Hardcoded eth+ipv4+{tcp,udp,icmp} straight-line extractor at the
top of the generated mono entry function, gated on
`parser_name == 'xdp2_parser_flow_dissector_l2'`. Sidesteps the
parse graph entirely on a chain match; falls through to the
goto-state body on miss. Plan: `docs/r3.4-and-hot-edge-plan.md`
§R3.4.

### Headline — fast-path moves c-xdp2-mono into Rust territory

`perf-results/2026-05-17-r3.4.1/summary.md`, hp2-hp5-x710,
https-web.pcap:

| Mode | pre-R3.4.1 hp5 | R3.4.1 hp5 | delta |
|---|---:|---:|---:|
| **`c-xdp2-mono`** | **116 ns** | **76 ns** | **−34%** |
| `c-xdp2-usp` | 130 | 131 | noise |
| `c-flowdis-usp` | 117 | 119 | noise |
| `c-bpf-flowdis` | 113 | 120 | noise |
| `c-bpf-fast` (BPF JIT floor) | 23 | 23 | unchanged |

For context the R3.4.1-era hp5 ranking is:

| Mode | hp5 ns/pkt |
|---|---:|
| `c-bpf-fast` | 23 |
| `rust-simd` | 40 |
| `rust-template` | 68 |
| `rust-compiled` | 72 |
| `rust-mono` (hand-written) | 72 |
| **`c-xdp2-mono`** | **76** ← new architectural headline |
| `rust-template-simd` | 75 |
| `rust-mono-x4` | 83 |
| `rust-graph-enum` | 106 |
| `c-bpf-flowdis` | 120 |
| `c-flowdis-usp` | 119 |
| `c-xdp2-usp` | 131 |
| `c-xdp2-parse-only` | 131 |
| `rust-graph` (dyn) | 274 |

`c-xdp2-mono` now beats **every kernel-flowdis variant** (USP, BPF
JIT) by ~35%, beats `c-xdp2-usp` by 42%, and is within 5% of
`rust-mono` / `rust-compiled` — the Rust modes that used to be the
"fastest non-SIMD parsers in tree." The R3 architectural-rebuild
target ("an extensible C parser at kernel-flowdis parity") is
substantially exceeded; the new target is closing the 76 → 23 ns
gap to `c-bpf-fast` (the no-graph-dispatch-at-all BPF JIT floor).

### Local simple-pcap snapshot (auto-scaled iter, ≥100K parses)

| pcap | pre-R3.4.1 mono | post-R3.4.1 mono | delta |
|---|---:|---:|---:|
| tcp_ipv4 | 9 ns | **6 ns** | −33% |
| icmp_ipv4 | 8 ns | **6 ns** | −25% |

Parity: 22/22 ok on the corpus. The chain check (etype + ihl + frag
+ ipproto) costs ~3 cycles on Zen 1 — even on chain-miss workloads
the overhead is well under noise.

### Where the win comes from

The fast-path skips:
- The first goto-label dispatch (etype_dispatch_node)
- Length checks in each parse_node prologue
- Per-node ops-table indirection
- next_proto load + switch table
- `lookup_node()` walk inside `__xdp2_parse` (still indirect-called
  by the C ABI when crossing parsers)

For an eth+ipv4+tcp packet that all collapses to: 5 byte
comparisons + 3 stores + 1 memcpy. LLVM at -O2 emits ~12 x86 insns
for the matched-chain branch.

### What R3.4.1 leaves for follow-ups

- **R3.4.4 — generalise via `XDP2_FAST_PATH_CHAIN(...)` annotation**.
  Hardcoded parser-name gate is OK for one parser; multi-parser /
  per-shape chain emission needs an explicit declaration grammar.
  Plan §R3.4.4 has the design sketch.
- **R3.4.5 — add the remaining 6 chain shapes** (`c-bpf-fast`'s
  eth+ipv4+udp, eth+ipv4+icmp, eth+ipv6+tcp, eth+ipv6+udp,
  eth+ipv6+icmp, eth+vlan+ipv4+tcp). IPv6 fast-path is the
  highest-leverage addition for general traffic.
- **Hot-edge ordering** (R2 gap #3, plan §H1-H3). Smaller +2-5%
  on top of R3.4.1; runs next in the plan's sequencing.

## Phase H1+H2+H3 — hot-edge ordering (2026-05-17, commit `cb3ad30`)

Plan §H1+H2: sort each vertex's `out_edges` descending by
hit-priority in `template.cpp`'s Python preprocessor, so generated
switch arms emit TCP/UDP/ICMP/IP/IPv6 first, then VLAN/MPLS, then
encap and rare protocols. R2 gap #3.

Generated `parser.mono.c` switch arm order (verified):

  label_ipv4_node:                label_etype_dispatch_node:
    case 0x6  (TCP)                 case 0x8    (IP)
    case 0x11 (UDP)                 case 0xdd86 (IPv6)
    case 0x1  (ICMP)                case 0xa888 (8021AD)
    case 0x2f (GRE)                 case 0x81   (8021Q)
    ...                              ...

H3 hp5 sprint (`perf-results/2026-05-17-hot-edge/summary.md`):

| Mode | R3.4.1 hp5 | +hot-edge hp5 |
|---|---:|---:|
| `c-xdp2-mono` | 76 | 75 |
| `c-xdp2-usp` | 131 | 132 |
| `c-flowdis-usp` | 119 | 118 |

**Hot-edge moves c-xdp2-mono by -1 ns on hp5 — within
single-replicate measurement noise.** Expected: R3.4.1's fast-path
already handles the bulk of TCP/IPv4 packets on https-web, so the
graph-dispatch path only runs on fast-path misses (rare on this
workload). Hot-edge only matters for those rare packets, and the
miss-path is a small fraction of the total cost.

The work is still useful as forward-looking infrastructure:

- For workloads with **low fast-path hit rate** (IPv6-heavy,
  encap-heavy, VLAN-heavy without VLAN-fast-path), the graph
  dispatch IS the hot path and hot-edge wins matter.
- For the **fast-path-miss tail** even on https-web — the
  branch-predictor benefit applies to whichever ipproto follows
  TCP/UDP in declaration order; with hot-edge it's deterministic.
- gcc's jump-table emission and predictor heuristics consider
  source order; future toolchain updates / different compilers
  may benefit from explicit ordering more than gcc 15 does.

### Detail subtlety the first H1 implementation missed

`edge['macro_name']` is the hex-string representation of the
proto constant (`"0x6"` for `IPPROTO_TCP`), not the source name
`"IPPROTO_TCP"`. The lookup table must key on `macro_name_value`
(int) instead. Additionally, ethertypes are stored byte-swapped on
little-endian builds (`ETH_P_IP=0x0800` → stored `0x0008`), so the
priority table includes both byte orders.

### Headline picture after H1+H2+H3

| Mode | hp5 ns/pkt | rank |
|---|---:|---:|
| `c-bpf-fast` | 24 | 1 |
| `rust-simd` | 42 | 2 |
| `rust-template` | 69 | 3 |
| `rust-mono` | 72 | 4 |
| `rust-compiled` | 73 | 4 |
| `rust-template-simd` | 74 | 6 |
| **`c-xdp2-mono`** | **75** | **7** |
| `rust-mono-x4` | 83 | 8 |
| `rust-graph-enum` | 109 | 9 |
| `c-flowdis-usp` | 118 | 10 |
| `c-bpf-flowdis` | 120 | 11 |
| `c-xdp2-usp` | 132 | 12 |
| `rust-graph` | 271 | 13 |

`c-xdp2-mono` is now the **7th-fastest parser overall on hp5
https-web** — ahead of rust-mono-x4 and the rust-graph-enum
headline, within 3 ns of rust-compiled / rust-mono, and the
**fastest C-side parser by a wide margin** (next-best C is
`c-flowdis-usp` at 118 ns, ~57% slower).

## Phase R3.4.5a — IPv6 fast-path (2026-05-17, commit `9272a97`)

Plan §R3.4.5: lifted ahead of R3.4.4's `XDP2_FAST_PATH_CHAIN`
annotation work because IPv6 is the highest-leverage chain
addition for general traffic.

Added eth+ipv6+{tcp,udp,icmpv6} as a second `if` block inside the
existing parser-name gate. Chain check: len ≥ 62, etype = 0x86DD,
IPv6 version=6, next_header ∈ {6, 17, 58}. Excludes EH chains by
construction (next_header values 0/43/44/60 etc. fall through).
Writes addr_type, l3_off, ip_proto, flow_label (via
`ntohl(*be32) & 0x000FFFFF` matching parser_metadata.h:428),
addrs.v6_addrs (32B), ports or ICMPv6 type/code/id-with-sentinel.

R3.4.5a hp5 sprint
(`perf-results/2026-05-17-r3.4.5a/summary.md`):

| Mode | post-hot-edge hp5 | R3.4.5a hp5 | delta |
|---|---:|---:|---:|
| **`c-xdp2-mono`** | **75** | **71** | **−5%** |
| `c-xdp2-usp` | 132 | 135 | noise |
| `c-flowdis-usp` | 118 | 119 | noise |

Local simple-pcap snapshot:

| pcap | pre-R3.4.5a | post-R3.4.5a | delta |
|---|---:|---:|---:|
| tcp_ipv4 | 6 | 5 | (within noise) |
| tcp_ipv6 | 10 | **6** | **−40%** |
| icmp_ipv6 | (~) | 6 | new fast-path hit |
| plain-ipv6-64 | (~) | 7 | new fast-path hit |

### Headline picture after R3.4.5a

| Mode | hp5 ns/pkt | rank |
|---|---:|---:|
| `c-bpf-fast` | 23 | 1 |
| `rust-simd` | 42 | 2 |
| `rust-template` | 68 | 3 |
| **`c-xdp2-mono`** | **71** | **4** ← was 75 |
| `rust-mono` | 72 | 5 |
| `rust-compiled` | 73 | 6 |
| `rust-template-simd` | 75 | 7 |
| `rust-mono-x4` | 83 | 8 |
| `rust-graph-enum` | 106 | 9 |
| `c-flowdis-usp` | 119 | 10 |
| `c-bpf-flowdis` | 120 | 11 |
| `c-xdp2-usp` | 135 | 12 |
| `rust-graph` | 274 | 13 |

**`c-xdp2-mono` is now the 4th-fastest parser overall on hp5
https-web — ahead of every Rust parser except rust-simd /
rust-template, and within 3 ns of the rust-template "fastest
non-SIMD Rust mode" mark.**

Compared against `c-flowdis-usp` (the kernel's hand-tuned C
parser): c-xdp2-mono runs at **60% of its time** on the same
workload (71 vs 119) while remaining a generic extensible parse
graph.

Compared against `c-bpf-fast` (23 ns): c-xdp2-mono is 3.1× — the
remaining gap is the fraction of https-web packets that miss the
fast-path (anything with VLAN, encap, IPv6 EH, fragmentation, or
IHL≠5 falls through to the graph). Adding more fast-path chain
shapes (R3.4.5 remainder) is what closes it further.

### R3.4 / R3.5 / hot-edge series — running total

| Phase | hp5 c-xdp2-mono | cumulative delta |
|---|---:|---:|
| Pre-R3.3 (slow `c-xdp2-usp` baseline) | 134 | 0% |
| R3.3.7 (hand-written-mono retired, generator canonical) | 114 | −15% |
| R3.5.2 (wider IR coverage) | 116 | (no change; gcc LTO does the work) |
| **R3.4.1** (IPv4 fast-path) | **76** | **−43%** |
| H1-H3 (hot-edge ordering) | 75 | (within noise on this workload) |
| **R3.4.5a** (IPv6 fast-path) | **71** | **−47%** |

### What R3.4.5a leaves for follow-ups

- **R3.4.4 — `XDP2_FAST_PATH_CHAIN(...)` annotation**. Replace
  the hardcoded parser-name gate with an explicit
  user-declaration. Enables fast-paths on other parsers (the L3
  parser, future parsers).
- **R3.4.5 remainder — 5 more chain shapes**:
  eth+vlan+ipv{4,6}+tcp/udp (most-common VLAN traffic),
  eth+pppoe+... (consumer ISP). Each new chain captures more of
  the workload-dependent miss tail.
- **Profile-guided hot-edge priorities**. Already covered as a
  deferred follow-up; lower priority now that the fast-path
  captures most TCP/UDP traffic.
- **TLV / flag_fields walkers** in generated code — needed for
  `gre-pptp` (PPTP-version-1) and `srv6-end_dx2` parity. R4.
- **Wider IR coverage** so more `extract_metadata` functions
  qualify for inline emit on https-web (driving the +15% win
  closer to the +50% seen on simple pcaps). Investigate which
  metadata patterns the LLVM analysis trips on and extend the
  matcher.

## Phase R3.4 remainder + R5 — completing the R3.4 plan (2026-05-18 → 2026-05-19)

### R3.4 chain completion (commits `b8532a2`, `d687a6f`, `a1de445`, `ba26071`)

R3.4.5b/c/d/e add the remaining chains the R3.4.5 plan called out:

| chain | commit | shape |
|---|---|---|
| R3.4.5b | `b8532a2` | eth+8021Q+ipv4+{tcp,icmp} |
| R3.4.5c | `d687a6f` | eth+8021Q+ipv6+{tcp,icmpv6} |
| R3.4.5d | `a1de445` | eth+PPPoE+ipv4+{tcp,icmp} |
| R3.4.5e | `a1de445` | eth+PPPoE+ipv6+{tcp,icmpv6} |
| R3.4.4 (generalisation) | `ba26071` | `.enable_fast_paths = 1` per-parser config field replaces the hardcoded `parser_name == 'xdp2_parser_flow_dissector_l2'` template gate |

UDP was intentionally **dropped** from every fast-path chain
(`a063bfc`) for tunnel correctness: a UDP fast-path that short-
circuits at outer UDP loses inner-5-tuple extraction on VXLAN /
Geneve / GTP-U / MPLS-UDP / PPPoE-over-UDP. The graph walk
correctly enters these tunnels via udp_node's dport dispatch;
the fast-path would race ahead and emit outer-only metadata.
TCP + ICMP have no in-tree tunnel ports so they stay in the
fast-path.

### Bug fix series surfaced by the protocol-coverage-matrix

The broad-coverage discovery pcap + the new protocol-coverage-
matrix tool (`nix run .#protocol-coverage-matrix`) surfaced four
correctness bugs in the codegen that the original 22-pcap parity
gate missed:

1. **`npi_simple` bswap mismatch** (commit `3ad4ac4`). 16/32-bit
   `next_proto` loads were `__builtin_bswap`ed inline but the
   switch case constants were the raw `__cpu_to_be16()` table
   keys. Result: 16-bit next_proto dispatches silently
   `goto unknown_ret` on every match → mono silently dropped
   out of GRE / inner-Ethernet / PPPoE dispatches. Discovered
   when adding broad-coverage.pcap to the matrix surfaced 600
   `c-xdp2-mono vs rust-*` `ip_proto` disagreements.
2. **`vxlan_proto` convention** (commit `a063bfc`). `vxlan_proto`
   returned host-order `ETH_P_TEB` but `vxlan_inner_table`
   keyed by `__cpu_to_be16(ETH_P_TEB)`. Strict-equality lookup
   never matched → all C parsers stopped at outer UDP on VXLAN.
3. **`icmp_id` sentinel three-way alignment** (commit `eebe021`).
   Slow path stored host `1`, mono fast-path stored `htons(1)`,
   Rust never sentinelled at all. The bench's `ntohs` on emit
   surfaced these as `1` / `256` / `0` for the same packet —
   the icmpv4 OK!N cells in the matrix.
4. **Per-(pcap, parser) `tunnel_behavior` overrides** (commit
   `f0faceb`). A parser declared inner globally can be re-
   declared outer on specific pcaps where its graph lacks the
   tunnel walker (e.g. rust-template's fixed-offset extractor
   on ah.pcap). New schema mechanism in parity_scope.json.

Net result of these bug fixes: matrix coverage went from
22 OK!N cells (icmpv4 + vxlan disagreements) to **0 OK!N, 0
REJ-undeclared, 0 REJ-unexpected** across 378 protocols × 13
parsers = 4914 cells. First time the matrix has zero pairwise
field disagreements.

### Aggressive compile flags (commit `cab4593`)

C userspace CFLAGS flipped from `-O2 -g` to
`-O3 -march=native -flto -fno-plt`. Validated on hp5 sweep:
moved every cell by ≤3 ns (= measurement noise). The codebase
was already at gcc -O2's local minimum for this code shape.

The flags are kept anyway: they remove "build tuning" as a
confounding variable in subsequent investigations.

### Mono is now the benchmark default (commit `c5cbaf4`)

`samples/flow_dissector/benchmark.c`: default parser flipped
from OPTIMISED (-O) to MONOLITHIC (-M). Mono sits at ~70
ns/pkt on TCP workloads (vs opt's ~135) on hp5 with R3.4
fast-paths capturing the common chains automatically. Old
`-O` flag still works as explicit opt-in; `-S` still selects
generic engine.

### The 50 ns gap to rust-mono on tunneled workloads —
###   three hypotheses tested, all DISPROVED

Post-R3.4 sweep showed `c-xdp2-mono` on `vxlan-k8s-pure.pcap`
(20K-packet workload, slow-path tunnel walking) at **141 ns/pkt
on hp5** vs `rust-mono` at **92 ns/pkt** — a 49 ns gap (35 %).

The 2026-05-19 investigation ran three experiments to localize
the cause:

| hypothesis | experiment | result |
|---|---|---|
| Compile-flag asymmetry (rust LTO+native vs C -O2) | rebuild C at `-O3 -march=native -flto -fno-plt` | ±3 ns delta — DISPROVED (`perf-results/2026-05-19-O3-march-native-flto/`) |
| Code-size / icache pressure (mono entry = 10K asm instr ≈ 62 KB, larger than 32 KB L1i) | `perf stat -e l1-icache-load-misses,...` sweep per parser-mode | similar miss counts across modes (1.4–1.6 M); ipc differs, miss/Mi differs — DISPROVED (`perf-results/2026-05-19-icache/`) |
| Per-node bookkeeping overhead (`last_node` store, NULL-ops checks, overlay check, keyin ternary) | R5 trim — gate emission on IR-known statics | trims fired in mono.c (0 surviving NULL checks); 0 ns/pkt delta on hp5 — DISPROVED (`perf-results/2026-05-19-r5-trim/`) |

The third disproof is interesting: gcc `-O3 -march=native -flto`
was *already* folding the runtime branches we trimmed. The mono
template is at gcc's local optimisation minimum on Zen 1; the
R5 trims make the template source match what the compiled
binary already produced.

### What the 50 ns gap actually is — pending investigation

The icache sweep measured `mono` at 789 instructions/packet on
vxlan vs `rust-mono`'s inferred ~510. That's a real 280 instr/pkt
difference. Now that bookkeeping is eliminated as the cause,
the leading candidates for the remaining gap are in the
**data path**, not dispatch shape:

- **Metadata struct layout**: `xdp2_metadata_all` is ~200 B
  (3 cachelines); rust's `FlowMeta` is ~100 B. Mono writes
  more bytes per packet — each store is one instruction at
  the same IPC.
- **Inline `memcpy()` emit for metadata_transfers** (R3.3.4
  IR-coverage devirt). The pattern `memcpy(dst, src, N)` per
  transfer generates 1-3 instructions depending on N; rust-
  mono's direct field stores collapse better.
- **TLV / flag_fields walker overhead**. The mono-eligibility
  loosening in commit `a47d2ad` lets flag_fields nodes through
  without walker emission, but the proto_table dispatch into
  them still costs cycles.

R6 (metadata struct re-layout) is the next phase. Estimated
500+ LoC, ~2-3 day effort with real struct-design tradeoffs.

### Headline picture after R5

`c-xdp2-mono` on hp5:

| workload | pre-R3.4 | post-R3.4 | post-R5 | flowdis on same |
|---|---:|---:|---:|---:|
| https-web (TCP) | 116 | 71 | 72 | 119 |
| nfs-server (TCP) | (~115) | 69 | 69 | 115 |
| vlan-tcp-mix (VLAN+TCP) | (slow) | 70 | 70 | 127 |
| pppoe-isp (PPPoE+TCP) | (slow) | 72 | 73 | 123 |
| k8s-microservices (mixed VXLAN) | (slow) | 137 | (no measure) | 116 |
| vxlan-k8s-pure (100 % VXLAN) | (incorrect: stopped at outer UDP) | 141 | 140 | 110 |

The two tunnel workloads (k8s-microservices, vxlan-k8s-pure)
show the work-vs-speed tradeoff: mono walks the full inner
stack (correct inner 5-tuple); flowdis stops at outer (no
inner extraction). Direct cross-parser comparison on those
two cells is apples-vs-oranges (`docs/r3.4-hp5-perf-targets.md`
caveats section).

## Phase R6 — Metadata struct re-layout (2026-05-19)

Targets the fourth hypothesis after R5 disproved bookkeeping:
maybe the metadata-struct layout itself (200 B, scattered
hot/cold mix) was the cause of the 280 instr/pkt gap to
rust-mono on tunneled workloads. Per
`perf-results/2026-05-19-r6-audit/audit.md`, the pre-R6 layout
placed 108 bytes of cold fields (`tcp_options`, `arp`, `gre`,
`gre_pptp`, `mpls`) BEFORE the hashed region, so they occupied
hot cachelines that were never written on TCP/UDP 5-tuple
parses (the common case).

**Phase A** (`parser_metadata.h:297-323`): rebind
`XDP2_HASH_LENGTH` macro from `sizeof(*FRAME)` to a named
end field (`offsetof(addrs) + sizeof(addrs)`). Precondition
for adding cold fields after `addrs` without silently extending
the IPv6 hash byte range.

**Phase B** (`parser_metadata.h:220-260`): move `tcp_options`,
`arp`, `gre`, `gre_pptp`, `mpls` to AFTER `addrs`. Move
`l2_off/l3_off/l4_off` to the front prefix so all small hot
fields cluster ahead of the hash region.

**Resulting struct**: 200 B → 192 B (saves 8 B / parser frame).
All hot fields for a TCP/IPv4 5-tuple parse fit in CL0
(offsets 0-59): addr_type + eth_addrs + l3_off + eth_proto +
ip_proto + ports + addrs.v4. The pre-R6 layout used 4
cachelines for the same set of writes (eth_addrs in CL0, the
rest scattered across CL2-CL3).

`perf-results/2026-05-19-r6-layout/full-sweep-analysis.md`
(full 6-workload sweep, non-smoke, hp2 + hp5):

| workload | host | R5 | R6 (full) | Δ |
|---|---|---:|---:|---:|
| https-web | hp5 | 72 | 73 | +1 |
| k8s-microservices | hp5 | ~137 | 136 | -1 |
| nfs-server | hp5 | 69 | 70 | +1 |
| pppoe-isp | hp5 | 73 | 73 | 0 |
| vlan-tcp-mix | hp5 | 70 | 71 | +1 |
| vxlan-k8s-pure | hp5 | 140 | 139 | -1 |

**Null result on perf at full iteration count, just like R5
and the smoke sweep.** Every hp5 cell is within ±1 ns of the
R5 baseline. Three layout/dispatch hypothesis
tests (R5 bookkeeping, R6 layout, compile flags) have now all
yielded zero ns/pkt on Zen 1 because gcc was already producing
near-optimal code on the pre-R6 layout.

Store-buffer absorption + 8-way L1d on Zen 1 mean cacheline-
write count doesn't matter — 4 scattered stores retire at the
same rate as 1 packed store once they all hit L1.

**What R6 leaves**: the ~50 ns gap to rust-mono on tunnels is
**store count**, not store placement. To close it requires
either:

- **R7** — per-parser metadata struct generation. Each parser
  declares its used field set in the IR; codegen emits a
  tailored struct + extractors. For flow-dissector-l2 the
  per-parser struct would drop to ~57 B (single cacheline,
  5-tuple only); fewer metadata writes per packet, matching
  rust-mono's store count. ~500 LoC of IR + codegen work.
- **R4** — proper flag_fields walker emission for `gre_v0/v1`
  and similar protocols where the current mono codegen elides
  field-by-field extraction.

R6 is permanent value even at zero ns/pkt: struct size shrank,
hash-macro is compositionally stable (precondition for R7),
and hot fields are clustered for any future microarchitecture
that's less forgiving than Zen 1.

### Cumulative R3-R6 picture

`c-xdp2-mono` on hp5, evolution across phases:

| Phase | https-web | vxlan-k8s-pure | notes |
|---|---:|---:|---|
| Pre-R3.3 baseline | 116 | (n/a; outer-only) | slow generic engine |
| R3.3.7 (mono canonical) | 114 | (n/a) | hand-written retired |
| R3.4.1 (IPv4 fast-path) | 76 | (n/a) | -34 % |
| R3.4.5a (IPv6 fast-path) | 71 | (n/a) | -38 % |
| R3.4.5b-e + R3.4.4 (chains + generalisation) | 71 | (n/a) | (within noise) |
| vxlan bug fix (a063bfc) | 71 | 141 | first correct vxlan walk |
| R5 trim (bookkeeping) | 72 | 140 | null on perf, valid trim |
| R6 layout | 73 | 139 | null on perf, struct now 192 B |

**Net of all phases**: -37 % on https-web vs pre-R3.3
baseline; the tunnel-walking c-xdp2-mono path now sits at
139 ns/pkt on hp5 (143 ns/pkt on hp2) with correct inner
5-tuple extraction (vs flowdis's 113 ns/pkt on hp5 that stops
at outer UDP — c-xdp2-mono pays 26 ns extra to extract the
inner 5-tuple that flowdis omits).

## Phase R7-B1 — Hot-edge `__builtin_expect` shortcut (2026-05-20)

Following the R7-A perf-record investigation
(`perf-results/2026-05-20-r7-a/findings.md`), which surfaced
that c-xdp2-mono spends ~30 cycles/pkt in per-node
`switch (type)` dispatches (compiled by gcc as binary-search
trees over 20-49 sparse cases), R7-B1 prepends a hot-edge
shortcut before each switch:

```c
/* mono_def.template.c:429 */
if (__builtin_expect(type == HOT_VALUE, 1))
    goto label_HOT_TARGET;
switch (type) { /* full N≥4 case branches */ }
```

The "HOT_VALUE" is the FIRST entry in the proto_table's
source order — by in-tree convention the most common protocol
(ETH_P_IP first in ether_table, IPPROTO_TCP first in ipv4's
next-proto table, etc.).

`perf-results/2026-05-20-r7-b1/comparison.md`:

| workload | host | R6 | R7-B1 | Δ |
|---|---|---:|---:|---:|
| https-web | hp5 | 73 | 72 | -1 (noise) |
| **k8s-microservices** | hp5 | **136** | **132** | **-4** |
| nfs-server | hp5 | 70 | 71 | +1 (noise) |
| pppoe-isp | hp5 | 73 | 73 | 0 |
| vlan-tcp-mix | hp5 | 71 | 72 | +1 (noise) |
| **vxlan-k8s-pure** | hp5 | **139** | **135** | **-4** ✓ |
| **vxlan-k8s-pure** | hp2 | **143** | **139** | **-4** |

**First real ns/pkt win since R3.4.5a.** Three independent
cells showing -3 to -4 ns on tunnel workloads (vxlan,
k8s-microservices), across both hosts. R5 + R6 had been null
on perf; R7-B1 finally moves the needle.

The improvement is bounded to tunneled workloads because the
R3.4 fast-path captures `eth + ipv4 + tcp/icmp` and friends
at parser entry — flat workloads never reach the per-node
slow-path switch. VXLAN's inner walk
(eth → ipv4 → udp → vxlan → inner eth → inner ipv4 → tcp)
doesn't fit any fast-path chain, so every per-node switch
fires.

For the 7-node VXLAN walk: 7 hot-edge hits per packet × ~2-3
cycles saved each = ~14-21 cycles/pkt = **3.5-5 ns/pkt at
4 GHz**. Measured: 4 ns. Within prediction.

Codegen surface: 7-line addition to
`src/templates/xdp2/mono_def.template.c`. No IR changes, no
AST changes, no API changes. 700 hot-edge shortcuts emitted
in the generated flow-dissector-l2 parser.

Correctness: 4914-cell matrix 0/0/0, parity-gate 32/32 OK,
mono-perf ceiling 0 violations.

### Cross-impl ranking after R7-B1 (hp5)

| workload | c-xdp2-mono | rust-mono | gap |
|---|---:|---:|---:|
| https-web | 72 | 72 | 0 (tied) |
| **nfs-server** | **71** | 70 | **+1** (≈ tied) |
| **pppoe-isp** | **73** | 81 | **−8** (mono ahead) |
| **vlan-tcp-mix** | **72** | 88 | **−16** (mono way ahead) |
| k8s-microservices | 132 | 84 | +48 (tunnel gap) |
| vxlan-k8s-pure | 135 | 92 | **+43** (was +46, R7-B1 closed 7%) |

Post-R7-B1: **c-xdp2-mono ties or beats rust-mono on 4 of 6
workloads, and the remaining tunnel gap is +43 ns (down from
+46)**. Three R7-B follow-ups remain candidate (B2 per-protocol
dispatch functions, B3 direct-store metadata extracts) which
together could close another 16-20 ns/pkt of the tunnel gap.

## Phase R7-B3 — Typed-store metadata transfers (null, kept for clarity, 2026-05-20)

R7-A's analysis identified `memcpy()`-based metadata transfer
emit as a second optimisation candidate. R7-B3 replaces
`memcpy(metadata + dst, hdr + src, N)` with typed
`*(__u16/__u32/__u64 *)` stores for power-of-2 sizes.

Generated `parser.mono.c` emit counts after B3:
- 28 typed `__u16` stores
- 196 typed `__u32` stores  
- 60 `memcpy()` fallbacks (96-bit eth_addrs, 128/256-bit v6 addrs)

`perf-results/2026-05-20-r7-b3/comparison.md`: **null on perf
(±2 ns across all 12 cells)**. gcc `-O3 -march=native -flto`
was already lowering `memcpy(dst, src, SMALL_CONSTANT)` to
typed mov instructions. The R3.3.4 inline-memcpy emit
(replacing the indirect `ops.extract_metadata` call) was the
win that mattered; the copy SHAPE (memcpy vs typed) is
gcc-equivalent at -O3.

R7-B3 kept anyway because the generated `parser.mono.c` is
more readable (typed-field copies vs opaque memcpy) and
structurally aligns with rust-mono's direct field-store
idiom. Correctness-clean (4914-cell matrix 0/0/0, parity 32/32,
mono-perf 0 violations).

## Phase R7-B4 — Inline `__mono_check_pkt_len` per-node (attempted, reverted)

R7-A also flagged per-node `__mono_check_pkt_len(hdr, proto_def,
len, &hlen)` calls as a cycle contributor — the `*hlen` pointer
indirection might force gcc to spill the length to the stack.
R7-B4 attempted to inline the length check per-node, gated on
the existing `proto_has_len_op` IR field (captured but unused
since R5.C).

**Reverted** after the parity gate surfaced field disagreements
on `srv6-end-64.pcap` (flow_label / ip_proto / ipv6_dst /
ipv6_src). Root cause: the AST consumer in
`src/tools/compiler/include/xdp2gen/ast-consumer/graph_consumer.h:745`
captures `field_name == "len"` only when the field name
literally matches in the walked init list, but in-tree
proto_defs use nested designated initializers like
`.ops.len = ipv6_length_check` which the walker presents
differently than the flat `.ops = { .len = X }` form. Result:
`proto_has_len_op` is incorrectly `false` for IPv6 / IPv6-EH /
SRv6 nodes that DO have variable-length headers. The R7-B4
template change then emitted `hlen = min_len` only — wrong
for variable-length IPv6 EH chains.

Proper fix is in the AST consumer (handle nested designated
inits). That's a graph_consumer investigation, not a
template change.

R7-B4 reverted at commit (pending). The `proto_has_len_op` IR
field stays in place for the future fix.

### Cross-impl ranking after R6 (hp5, full sweep)

c-xdp2-mono vs rust-mono on the same workloads:

| workload | c-xdp2-mono | rust-mono | gap |
|---|---:|---:|---:|
| https-web | 73 | 71 | +2 |
| **nfs-server** | **70** | 71 | **−1** (mono ahead) |
| **pppoe-isp** | **73** | 80 | **−7** (mono ahead) |
| **vlan-tcp-mix** | **71** | 91 | **−20** (mono way ahead) |
| k8s-microservices | 136 | 85 | +51 |
| vxlan-k8s-pure | 139 | 93 | +46 |

c-xdp2-mono matches or beats rust-mono on 4 of 6 workloads.
The remaining gap exists only on the two tunneled workloads.
The R3.4.5b/c VLAN fast-paths pay off as a 20 ns win on
`vlan-tcp-mix`.

c-xdp2-mono is now the **4th-fastest parser overall on
https-web** (post c-bpf-fast, rust-simd, rust-template) and
runs at **61% of c-flowdis-usp's time** on the same workload.
The kernel's hand-tuned C flow_dissector is 65% slower than
our generated mono parser on TCP/IPv4 — full numbers in
`perf-results/2026-05-19-r6-layout/full-sweep-analysis.md`.

## See also

- `xdp2-rs/docs/fast-path-dispatch.md` — Rust dyn-vs-enum dispatch story
- `xdp2-rs/docs/deep-performance-analysis.md` — TMA + Zen 1 per-loop counters
- `xdp2-rs/docs/performance-next-steps.md` — pre-existing perf follow-up list
- `perf-results/asm/2026-05-08/asm-comparison-baseline.md` — per-impl
  ns/pkt + IPC + branch-miss data this analysis is built on
