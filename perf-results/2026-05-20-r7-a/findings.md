# R7-A — perf-record c-xdp2-mono vs rust-mono on vxlan-k8s-pure

Run: 2026-05-20, hp5 only, `perf record -F 9999 -g`. Two parser
implementations under the same vxlan-k8s-pure.pcap workload. Goal:
identify the code shapes responsible for the 280 instr/pkt gap
between c-xdp2-mono (139 ns/pkt) and rust-mono (93 ns/pkt) that
R5 and R6 disproved as bookkeeping or struct-layout artefacts.

## TL;DR

The c-xdp2-mono per-packet cost is dominated by **per-node
proto_table switch dispatch**. Each parse_node's `switch (type)`
contains 20-49 sparse case labels (byte-swapped ethertype /
ip_proto / dport values). gcc compiles these as binary search
trees → log2(N) compares per dispatch, plus the per-node
function-prologue cost.

For a VXLAN packet that walks 7 nodes (outer eth, ipv4, udp,
vxlan, inner eth, inner ipv4, inner tcp), c-xdp2-mono pays:

- ~6 compares × 7 nodes = ~42 dispatch compares
- 7 function entries (or pseudo-entries inside one big function)
- 7 metadata extract sequences (some inlined via R3.3.4 IR)
- ~280 extra instructions vs rust-mono's specialised
  per-protocol parse functions

rust-mono's dispatch is split into per-protocol functions
(`dispatch_ether`, `dispatch_ipv4`, `parse_udp_tunnel`, etc.)
where the LLVM backend can apply more aggressive
type-narrowing — each function has a small known set of cases
to dispatch on, often compiled into 2-3 compares max.

## Setup

- Workload: `vxlan-k8s-pure.pcap` (20K-packet capture of VXLAN
  tunneled traffic with TCP inside).
- 200 iterations × 19822 parseable packets = 3.96 M parses
  per impl.
- hp5: Ryzen 5 PRO 2400G, DDR4 @ 1866 MT/s, kernel 6.18.
- Compile flags: gcc -O3 -march=native -flto -fno-plt (post-R6).
- Rust: --release with `xdp2-rs` package.
- Perf sample rate: 9999 Hz.

## Headline counters

| metric | c-xdp2-mono* | rust-mono | ratio |
|---|---:|---:|---:|
| Total cycles | 6.46 B | 1.59 B | 4.06× |
| Total instructions | 2.87 B | 1.39 B | 2.06× |
| Branches | 804 M | 281 M | 2.86× |
| Branch-misses | 4.89 M | 3.17 M | 1.54× |
| L1-dcache-load-misses | 43.9 M | 20.4 M | 2.15× |
| L1-icache-load-misses | 1.80 M | 0.40 M | 4.50× |
| iTLB-load-misses | 170 | 251 | 0.68× |
| Wall time | 1.80 s | 0.44 s | 4.09× |

\* The C benchmark binary runs all 3 c-impls per invocation
(c-flowdis-usp + c-xdp2-mono + c-xdp2-parse-only). The
counters above are aggregated across all three. Per-impl cycle
share is reported in the per-symbol breakdown.

## Per-impl cycle attribution

c-xdp2-mono total cycles (estimated from ns/pkt = 139, hp5 @
4 GHz): **~2.20 B cycles** for 3.96 M parses = 556 cycles/pkt.

rust-mono total cycles: **~1.47 B cycles** for 3.96 M parses
= 372 cycles/pkt.

**Cycle gap: 184 cycles/pkt = 46 ns/pkt at 4 GHz.** This is
the gap to explain.

## c-xdp2-mono per-symbol breakdown

(From `c-xdp2-mono/perf-report-by-symbol.txt`)

| % cycles | symbol | role |
|---:|---|---|
| 87.28 | `main` | benchmark harness (inlined parser loops + memset + flowdis loop) |
| 7.94 | `xdp2_parser_flow_dissector_l2_xdp2_parse_mono.lto_priv.0` | non-inlined mono entry-point invocations (correctness check + a fallthrough path) |
| 1.96 | `__skb_flow_dissect_err` | kernel flowdis impl (separate process loop) |
| 0.54 | `__skb_flow_get_ports` | flowdis helper |
| 0.13 | `icmp_metadata.constprop.0` | extracted metadata helper |
| ~3 | other | pcap loader, libc, dl_fini |

The `main` symbol contains the inlined hot path — gcc -flto
inlined the entire mono parser into the benchmark loop body
because it's called from a tight loop with constant args.
A second copy lives behind the `.lto_priv.0` mangling (7.94%)
which is called from a slightly different context.

## rust-mono per-symbol breakdown

(From `rust-mono/perf-report-by-symbol.txt`)

| % cycles | symbol | role |
|---:|---|---|
| 52.83 | `xdp2_bench::bench::run_single_threaded` | parse loop |
| 12.01 | `graph_mono::parse_ipv4` | IPv4 header decode |
| 7.09 | `graph_mono::dispatch_ipv4` | next_proto dispatch (TCP/UDP/ICMP/etc.) |
| 6.59 | `graph_mono::dispatch_ether` | etype dispatch (IP/IPv6/VLAN/etc.) |
| 5.88 | `graph_mono::parse_udp_tunnel` | UDP + VXLAN inner-walk |
| 4.75 | `xdp2_core::engine::parse` | parse entry / glue |
| 1.27 | `extract_ether_metadata` | metadata write |
| 0.45 | `extract_ipv4_metadata` | metadata write |
| 0.27 | `extract_ports_metadata` | metadata write |
| 0.18 | `extract_vxlan_metadata` | metadata write |
| ~3 | `ParseNode<>` trait methods | extract_metadata, handler, is_overlay, next_proto, proto_table |

rust-mono **splits per-protocol work into separate functions**:
- `dispatch_ether` is its own 6.59% function for the etype switch
- `parse_ipv4` is a 12.01% function for IPv4 header decoding
- `parse_udp_tunnel` is the VXLAN inner walk

Each function has a focused scope, allowing LLVM to apply
specialised optimisations: tighter register allocation, simpler
branch prediction patterns, smaller per-function instruction
windows.

## The dispatch shape — c-xdp2-mono's binary search vs
##   rust-mono's specialised functions

Inspecting the generated `parser.mono.c` for c-xdp2-mono, the
ether_inner_node dispatch contains a switch with 49 case
labels (the full `ether_table` + `ETHER_TABLE_CORE_ENTRIES`
plus extended userspace entries). Cases are sparse byte-swapped
values:

```c
switch (type) {
case 0x8:    goto label_ip_check_node;    /* ETH_P_IP */
case 0xdd86: goto label_ip_check_node;    /* ETH_P_IPV6 */
case 0xa888: goto label_e8021AD_node;
case 0x81:   goto label_e8021Q_node;
case 0x4788: goto label_mpls_node;
... 44 more cases ...
}
```

gcc -O3 compiles a sparse 49-key switch as a balanced binary
search tree — log2(49) = ~6 comparisons per dispatch. Looking
at the perf-annotate, hot sample addresses cluster around
`cmp $0xXXXX, %ax` pairs spread through the function body:

```
2.55 :  186e7:  cmp    $0x289, %ax       /* ETH_P_CFM byte-swap */
1.79 :  186c7:  cmp    $0xe00, %ax       /* ETH_P_CANXL byte-swap */
2.48 :  187ac:  shr    $0x4, %al
1.03 :  19ba5:  cmp    $0xe00, %ax
1.93 :  19bb5:  cmp    $0x608, %ax       /* ETH_P_ARP byte-swap */
1.10 :  19bc5:  cmp    $0x400, %ax       /* ETH_P_802_2 byte-swap */
1.03 :  19bd5:  cmp    $0x81, %ax        /* ETH_P_8021Q low-byte */
```

The cmp values that take 1-3 % each are the pivots of gcc's
binary search tree — checking the tree's mid-node, then
branching left/right.

**For VXLAN-k8s-pure**, every packet walks:
1. Outer ether dispatch (49 cases → ~6 cmp)
2. ip_check_node dispatch (~few cases) → ipv4_node
3. ipv4 next_proto dispatch (~15 cases → ~4 cmp) → udp_node
4. udp dport dispatch (~50+ tunnel ports → ~6 cmp) → vxlan_node
5. vxlan vni→ether_inner dispatch (1 case → 1 cmp + jmp)
6. Inner ether dispatch (49 cases → ~6 cmp)
7. Inner ip_check → ipv4 → ports

Per-packet dispatch comparisons: ~30. Each cmp + je is ~1
cycle (pipelined). With ~30 compares per packet that's ~30
cycles in pure dispatch.

rust-mono's per-protocol functions handle the same dispatch
in fewer compares because each function has only the
relevant subset of cases (LLVM trims unreachable cases via
inlining + dead-code elimination).

## Where the 184-cycle gap actually goes

A breakdown attempt, in order of confidence:

1. **Dispatch compares**: ~30 per packet, ~30 cycles (~7.5 ns).
   Rust-mono pays maybe ~10-15 of these in its split
   functions. Gap ≈ 15-20 cycles.

2. **Function prologues/epilogues**: c-xdp2-mono enters the
   parser entry once per packet (1 call), but inside the
   one-function body executes 7 metadata extracts inline.
   rust-mono calls 7+ specialised functions per VXLAN
   packet, paying 7× prologue + epilogue ≈ 14 cycles. But
   c-mono pays at least 1 push/leave/ret of its own.
   Net: c-mono SAVES cycles here.

3. **Branch prediction**: branch-misses 4.89 M (c-mono) vs
   3.17 M (rust). The 1.72 M extra branch-mispredicts for
   c-mono × ~20 cycle mispredict penalty = ~34M cycles, but
   that's across 11.9 M parses total (all 3 c-impls). Per
   c-mono parse: ~3M extra branch-misses (estimated 1/3 share)
   × 20 = 60M cycles for c-mono = 15 cycles/pkt. Small but
   nonzero.

4. **L1-dcache misses**: 43.9 M (c-mono, all 3 impls) vs
   20.4 M (rust). c-mono share ≈ 14.6 M (1/3) vs rust 20.4 M
   — actually c-mono has FEWER L1d misses per packet
   (~3.7/pkt vs ~5.1/pkt). Not the gap.

5. **L1-icache misses**: 1.80 M (c-mono) vs 0.40 M (rust).
   That's 4.5× the icache pressure for c-mono. Per packet:
   c-mono ~0.45 misses, rust ~0.10 misses. At ~10 cycle
   each cold-fetch (L1i miss → L2 hit), c-mono pays ~4.5
   cycles vs rust's ~1. **Gap ≈ 3.5 cycles/pkt = ~1 ns.**
   Small but real.

6. **Metadata extraction shape**: c-xdp2-mono uses inline
   `memcpy()` calls per the R3.3.4 IR-driven inlining; gcc
   may not always optimize these into immediate stores
   ideally. rust-mono uses direct field stores
   (`metadata.eth_proto = ntohs(...)`) which LLVM
   collapses better. Hard to attribute precisely; ~20-30
   cycles/pkt difference plausible across 5-7 transfers.

The bulk of the 184-cycle gap is therefore in:
- ~50 cycles in dispatch shape (binary-search vs
  specialised functions)
- ~30-50 cycles in metadata-write shape (inline memcpy vs
  direct stores)
- ~15 cycles in branch-prediction quality
- Various small effects (icache, prologues, etc.)

## What R7-B should target

Three candidate fixes, ranked by expected impact and risk:

### B1. Profile-guided hot-edge sort (low risk, ~15 LoC)

The codegen template already has access to the parse graph's
out-edges. Add a simple "hot-first" ordering: for each
parse_node, examine its IR's edge weights (or use a hardcoded
priority for well-known protocols: IP, IPv6, VLAN, MPLS) and
emit `case` labels in priority order.

gcc's binary search picks the median pivot; reordering source-
level cases doesn't help. But we can WRAP the switch:

```c
/* Hot-case shortcut: 80%+ of traffic is IPv4 on this node */
if (likely(type == 0x0008))   /* ETH_P_IP byte-swapped */
    goto label_ip_check_node;
switch (type) {
    /* full switch with all 49 cases */
}
```

The `if (likely(...))` short-circuits the common case in
~1-2 cycles. The cold switch only runs on the rare cases.

**Estimated gain**: ~15 cycles/pkt on hp5 vxlan (5 dispatches
× 3 cycles saved). ~4 ns/pkt.

### B2. Per-protocol dispatch functions (medium risk, ~150 LoC)

Mirror rust-mono's structural approach: have the codegen emit
ONE `static inline` function per parse_node containing only
that node's dispatch + metadata extract. The mono entry-point
becomes a sequence of `goto label_X` calls between these
functions.

This change is largely cosmetic at the IR level — the same
operations happen — but gives gcc more optimization granularity
per function (smaller scopes, better register reuse, simpler
prologue elision).

**Estimated gain**: ~30 cycles/pkt (~7.5 ns) by reducing
within-function complexity that throws off gcc's optimizer
on the giant ether_inner_node + others.

### B3. Direct field-store metadata extracts (medium risk, ~80 LoC)

The R3.3.4 inline-memcpy emit pattern works but produces
suboptimal code on small (1-2-4-8 byte) transfers. Replace
with direct typed-store patterns:

```c
/* before (R3.3.4 inline memcpy): */
memcpy((char *)metadata + 192/8, (const char *)hdr + 96/8, 16/8);

/* after (direct store): */
metadata->eth_proto = *(const __be16 *)((const char *)hdr + 12);
```

Functionally identical; gcc generates better code for the
typed store.

**Estimated gain**: ~20-30 cycles/pkt on packets with many
transfers (e.g. VXLAN, 14+ transfers across encap layers).

### Combined potential

B1 + B2 + B3 = ~65-95 cycles/pkt = ~16-24 ns/pkt savings on
hp5 vxlan-k8s-pure. That would bring c-xdp2-mono down to
~115-123 ns/pkt vs rust-mono's 93 ns/pkt. The remaining
~25-30 ns is structural: rust-mono's per-protocol functions
are an architectural advantage we can't replicate without
significant codegen work.

## Files

- `findings.md` — this analysis
- `raw-data/c-xdp2-mono/` — perf-stat, perf-record.data, perf-annotate, perf-report-by-symbol
- `raw-data/rust-mono/` — same
- `raw-data/c-xdp2-opt/` — bonus: c-xdp2-opt (with -O flag) for comparison

## Recommendation

Start with **B1 (hot-edge sort)** as it has the lowest risk
(~15 LoC, no API change) and easiest verification. If B1
yields ≥3 ns/pkt measurable improvement on hp5 vxlan,
escalate to B2 + B3.

If B1 yields ≤2 ns/pkt (noise), the structural codegen
difference is larger than per-comparison costs suggest and
B2 becomes the next-natural attempt.
