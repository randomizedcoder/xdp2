# Optimal metadata layout — kernel-usage analysis plan

Branch: `flow-keys-compat-reorder`.
Companion to: `docs/flow-keys-compat-reorder-plan.md` and
`docs/flow-keys-vs-xdp2-metadata.md`.

## Question

What is the **most efficient** memory layout for flow-dissection
metadata, given how the Linux kernel actually consumes it?

Currently we have two layouts on the table:
1. Kernel `flow_keys` (~80 B) — designed in 2014-era kernel,
   evolved organically
2. XDP2 `xdp2_metadata_all_v2` (~208 B, proposed) — flow_keys
   prefix + XDP2 extras at tail

Neither was designed from first principles around modern
read/write patterns. The optimal layout would be informed by:
- **Read access patterns** from kernel consumers (RFS, RPS,
  RSS, cls_flow, conntrack, etc.)
- **Write patterns** from the parser (per R6 audit, ~30 B
  written per packet on TCP/IPv4; most struct cold)
- **Hash region performance** (siphash over a contiguous span)
- **Cacheline boundaries** on multiple microarchitectures
  (Zen 1 has large store buffer; in-order ARM does not)

## Preliminary data gathered (this session)

### Field access frequency across kernel `net/*` + `include/net/*`

Rough grep counts (single-line accesses; doesn't capture
context):

| field | grep hits | category |
|---|---:|---|
| `ports` | 177 | **HOT (read+write)** |
| `vlan` | 155 | hot |
| `addrs` | 153 | **HOT (read+write+hash)** |
| `icmp` | 93 | medium |
| `basic.ip_proto` | 59 | hot |
| `basic.n_proto` | 55 | hot |
| `control.flags` | 52 | medium |
| `control.addr_type` | 51 | **HOT (hash dispatch)** |
| `keyid` | 26 | medium |
| `cvlan` | 22 | cold |
| `tags.flow_label` | 13 | cold |
| `control.thoff` | 2 | **VERY COLD** |

### Hash computation pattern

From `net/core/flow_dissector.c:1764-1816`:
- `flow_keys_hash_start = &flow->basic` (offset 8)
- `flow_keys_hash_length` covers basic..end-of-addrs
  (variable based on addr_type: v4 = 40 B, v6 = 64 B)
- `__flow_hash_consistentify` reads:
  - `control.addr_type` (dispatch)
  - `addrs.v4addrs.src/dst` OR `addrs.v6addrs.src/dst`
  - `ports.src/dst`
  - Sorts addrs and ports for bidirectional consistency
- `__flow_hash_from_keys` then runs siphash over the
  hash region

### Top consuming files

```
net/sched/sch_cake.c       — CAKE qdisc (high-perf shaper)
net/sched/sch_choke.c      — CHOKE qdisc
net/sched/cls_flow.c       — TC flow classifier
net/ipv6/route.c           — IPv6 routing decisions
net/ipv4/route.c           — IPv4 routing decisions
net/ipv4/fib_frontend.c    — FIB lookups
net/ipv6/netfilter.c       — IPv6 netfilter hooks
net/ipv4/netfilter.c       — IPv4 netfilter hooks
net/core/flow_dissector.c  — the dissector itself
```

These are the "hot" consumers. The actual fields each touches
differs per use-case.

## Analysis plan — phases

### Phase 1 — Per-consumer field-touch matrix (~1 session)

For each of the top consuming files, enumerate which
flow_keys fields it reads. Produces a matrix:

| consumer | addrs | ports | basic | vlan | cvlan | keyid | icmp | flow_label | flags | thoff | addr_type |
|---|---|---|---|---|---|---|---|---|---|---|---|
| sch_cake | ✓ | ✓ | ✓ | ✓ | | | | ✓ | | | |
| sch_choke | ✓ | ✓ | ✓ | | | | | | | | |
| cls_flow | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | | ✓ |
| ipv6/route | ✓ | ✓ | ✓ | | | | | ✓ | | | |
| ipv4/route | ✓ | ✓ | ✓ | | | | | | | | |
| (rest) | ... | | | | | | | | | | |

Then weight by **invocation frequency**:
- RPS path: per packet on the RX path (very hot)
- RFS lookup: per flow setup
- TC flow filter: per packet on packets matched by filter
- ipv4/ipv6 route: per packet that needs L3 routing
- conntrack: per packet on the netfilter chain

The aggregate "touch weight" per field tells us which fields
should be in CL0 vs cold tail.

Method: grep + manual inspection of context. Each file is
~500-2000 lines; ~30-60 min per file × 9 files = 4-9 hours
for the full matrix.

### Phase 2 — Write-pattern audit (~few hours)

Already partially done by the R6 audit. The XDP2 parser writes:
- always: addr_type, l3_off, eth_proto, ip_proto, addrs, ports
  (~30 B for TCP/IPv4)
- sometimes (per protocol): icmp, flow_label, vlan_set,
  keyid, tcp_options, mpls, arp, gre, gre_pptp

The hot WRITE set is roughly the same as the hot READ set:
basic 5-tuple + L3 offset. Confirms the existing optimization
intuition.

### Phase 3 — Hash performance analysis (~few hours)

The siphash over the hash region is the bottleneck for
consumers that need the hash. Measure:
- Current `flow_hash_from_keys` cycles (kernel benchmark, or
  port to userspace)
- How much of the hash time is siphash itself vs the
  setup/consistentify
- Whether a smaller hash region (e.g. just the 5-tuple) would
  give acceptable distribution properties for RSS/RFS

If the hash region could shrink without bias loss, the
metadata struct could too.

### Phase 4 — Microarchitecture sensitivity (~1 session per CPU)

For each available testbed:
- Measure read-path cost: cycles to read addrs + ports +
  basic (the "5-tuple inspection" path)
- Measure consistentify + hash cost on the full hash region
- Compare current flow_keys layout vs the proposed
  xdp2_metadata_all_v2 layout vs hypothetical "optimal"
  layouts

hp5 (Zen 1) has the harness already. Other CPUs need testbed
setup first.

### Phase 5 — Propose layouts + benchmark (~1 session)

Based on phases 1-4, propose 2-3 candidate "optimal" layouts:

**Layout A — Hash-first (compact)**:
- CL0: addr_type + addrs + ports + basic + flags (~56 B)
- CL1+: vlan + icmp + extras

**Layout B — Read-frequency-sorted**:
- CL0: top-N most-read fields based on phase-1 weighted matrix
- CL1+: rest by descending frequency

**Layout C — Read/write co-located**:
- CL0: union of hot-read + hot-write sets
- Optimizes for the case where parser and consumer touch
  same cachelines

Bench each on hp5 vs current flow_keys layout. Pick the
winner.

## Expected findings (hypothesis)

Based on the preliminary data, the most efficient layout
probably:

1. **Puts the 5-tuple (addrs + ports + basic) in CL0** —
   read by every hash consumer, written by every parser
2. **Puts the hash region contiguous in CL0+CL1** — siphash
   benefits from sequential memory access
3. **Moves icmp, flow_label, vlan, cvlan, keyid to CL1 or
   tail** — read by fewer consumers
4. **Moves XDP2 extras (eth_addrs, tcp_options, arp, gre,
   mpls) to bytes 128+** — only read by specialized
   consumers
5. **Reduces struct size** if some fields can be removed
   for parsers that don't need them (per Option C work)

Estimated size: **64-96 B** for the "common consumer" set,
vs current `flow_keys` 80 B and proposed v2 ~208 B.

## What the analysis would feed into

This analysis informs:

- **Whether xdp2_metadata_all_v2 should match current
  flow_keys exactly (compatibility-first)** OR
- **Whether to propose a new flow_keys layout to the kernel
  (efficiency-first)** OR
- **Whether per-parser tailored structs (Option C phase 2-a.7)
  is the right long-term direction**

The analysis is also a contribution in its own right: a
"current state of flow_keys consumption in Linux" writeup that
would be valuable to maintainers regardless of XDP2 outcomes.

## Cost / sequencing

| phase | cost | dependency |
|---|---|---|
| 1 — Per-consumer field-touch matrix | 4-9 hours | none |
| 2 — Write-pattern audit | 2-3 hours | (largely done) |
| 3 — Hash performance analysis | 2-3 hours | none |
| 4 — Microarchitecture sensitivity | 1 session per CPU | testbed availability |
| 5 — Propose + benchmark | 1 session | phases 1-4 |

**Total**: ~2-3 focused sessions for the full analysis,
extensible per CPU testbed.

## Suggested first move

**Do phase 1 first** (field-touch matrix). Smallest
self-contained piece that gives concrete data. Without it,
"optimal layout" is speculation.

Phase 1 produces a clear artifact:
`perf-results/<date>-flow-keys-consumer-audit/findings.md`
with the matrix + per-consumer summary.

Once we have that, the rest of the analysis becomes
data-driven rather than hypothesis-driven.

## Risks

| risk | severity | mitigation |
|---|---|---|
| Field-touch matrix doesn't show clear winner | medium | The data itself is still valuable; layout proposal becomes more nuanced |
| Different consumers want different layouts | medium | Confirms that per-parser tailored structs (Option C 2-a.7) is the right direction |
| Optimal layout breaks ABI compat | high | Document tradeoff; could propose layout as a new struct alongside flow_keys, not a replacement |
| Hash performance dominates and layout doesn't matter | low | Phase 3 would reveal this; outcome would be "layout doesn't matter much" which is also actionable |

## Out of scope (deferred)

- Actually re-laying out kernel `flow_keys` (would require
  netdev maintainer buy-in)
- Per-consumer tailored structs in the kernel (would require
  major refactor of every consumer)
- BPF flow_dissector ABI changes
- Userspace cls_flow tooling changes

The analysis informs design decisions but doesn't commit to
upstream layout changes.
