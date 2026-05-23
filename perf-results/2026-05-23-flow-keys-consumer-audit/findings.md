# flow_keys consumer audit — Phase 1 + Phase 2 findings

**Date**: 2026-05-23
**Branch**: `flow-keys-compat-reorder`
**Plan**: `docs/optimal-metadata-layout-analysis-plan.md`
**Companion**: `docs/flow-keys-compat-reorder-plan.md`,
  `docs/flow-keys-vs-xdp2-metadata.md`

This audit replaces the analysis-plan's "Quick reference"
flat grep counts with per-consumer evidence. Kernel source
read at `/home/das/Downloads/linux/`.

## TL;DR

**CL0 candidates** — touched by direct read in 3+ buckets AND
written by the XDP2 parser on the TCP/IPv4 hot path:

1. `addrs` (32 B union)
2. `ports` (4 B)
3. `control.addr_type` (2 B; dispatch field)
4. `basic.ip_proto` (1 B)

**CL1 candidates** — touched by direct read in 1-2 buckets, or
hash-region-only:

- `control.flags` — read by route.c (ECMP encap dispatch);
  not written by the XDP2 parser (kernel-only semantic)
- `tags.flow_label` — read by route.c (IPv6 only); written
  by the XDP2 parser for IPv6
- `basic.n_proto` — hash-region only; written by every L2
  parser
- `vlan`, `cvlan`, `keyid`, `icmp` — hash-region only

**Cold tail** — read in only one consumer or not at all:

- `control.thoff` — not read by any of the nine audited
  consumers (matches the analysis-plan's "VERY COLD" call-out)

**Hypothesis validation**: the analysis-plan's prediction
that the 5-tuple set (addrs + ports + basic + control.addr_type)
is the CL0 winner is **confirmed by the per-consumer evidence**.
The prediction that `control.thoff` is very cold is **also
confirmed**. The prediction about vlan/cvlan/keyid/icmp being
cold is **partially confirmed**: they are not directly read,
but they ARE in the siphash region, so they're touched on
every hash computation. A layout that pulls them out of the
hash region would shrink hash time but require dissector and
consumer changes that are out of scope here.

**Discrepancy with the preliminary grep counts**: the
analysis-plan TL;DR listed `vlan` as "hot" (155 hits) and
`icmp` as "medium" (93 hits). The per-consumer audit shows
neither is directly read in the nine kernel consumers — those
grep hits land in (a) the dissector itself writing those
fields, (b) the kernel's bpf-flow_dissector ABI, (c) unrelated
symbols (e.g., `vlan_tag` on skb). The grep counts in the
analysis plan should be treated as upper bounds; the actual
read-frequency by hot consumers is much lower for those fields.

## Consumer bucket assignment

| consumer | bucket | rationale |
|---|---|---|
| `net/sched/sch_cake.c` | RX-hot | qdisc, per-packet on enqueue path on busy queues; CAKE is the modern high-performance shaper |
| `net/sched/sch_choke.c` | RX-hot | qdisc, per-packet on enqueue; CHOose-and-Keep flow drop |
| `net/sched/cls_flow.c` | TC-hot | tc classifier; per-packet only when filter chain matches |
| `net/ipv4/route.c` | Route-hot | per-routed-packet; ECMP multipath hash dispatch |
| `net/ipv6/route.c` | Route-hot | per-routed-packet; ECMP multipath hash dispatch for v6 |
| `net/ipv4/fib_frontend.c` | Setup-only | RPF/source-validate; only runs when `fib_rules_require_fldissect` is set |
| `net/ipv4/netfilter.c` | Setup-only | `ip_route_me_harder`; iptable_nat/mangle hook reroute |
| `net/ipv6/netfilter.c` | Setup-only | `ip6_route_me_harder`; v6 reroute |
| `net/core/flow_dissector.c` | Writer | the dissector itself — excluded from the read aggregate |

Coarse quantitative weights (indicative-only; real call-site
frequency would need kernel benchmarks):

| bucket | weight |
|---|---:|
| RX-hot | 100 |
| Route-hot | 30 |
| TC-hot | 10 |
| Setup-only | 1 |

## Phase 1.C — per-consumer × per-field matrix

Cell legend:
- **R** = direct field read in the consumer's logic
- **H** = in the hash region; read implicitly by
  `flow_hash_from_keys()` / `__flow_hash_consistentify()`
- **W** = written to a synthesized stack-local `hash_keys`
  (consumer constructs its own hash input)
- blank = not touched

Hash-region membership (per
`include/net/flow_dissector.h:405-417` and
`net/core/flow_dissector.c:1705-1729`): the hashed bytes span
`basic` through end-of-`addrs`. `control` is BEFORE the hash
region; `addrs` is the LAST field and its hash length varies
by `addr_type`.

| consumer | bucket | control.addr_type | control.flags | control.thoff | basic.n_proto | basic.ip_proto | tags.flow_label | vlan | cvlan | keyid | ports | icmp | addrs |
|---|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| sch_cake | RX-hot | R | | | H | R/W | H/W | H | H | H/W | R/W | H | R/W |
| sch_choke | RX-hot | H | | | H | H | H | H | H | H | H | H | H |
| cls_flow | TC-hot | R | | | | R | | | | | R | | R |
| ipv4/route | Route-hot | R | R | | | R | R | | | | R | | R |
| ipv6/route | Route-hot | R | R | | | R | R | | | | R | | R |
| ipv4/fib_frontend | Setup-only | | | | | R | | | | | R | | |
| ipv4/netfilter | Setup-only | | | | | R | | | | | R | | |
| ipv6/netfilter | Setup-only | | | | | R | | | | | R | | |

**Notes**:
- `sch_cake` does a struct assignment `host_keys = keys` at
  `sch_cake.c:741` which technically touches every byte of
  `keys` for cache purposes. The matrix shows only the
  explicit logic-relevant reads. The fields that cake then
  zeros (`ports`, `basic.ip_proto`, `keyid.keyid`,
  `tags.flow_label` at lines 742-745) are marked as `H` /
  `H/W` since cake's *logic* doesn't depend on their value
  — it deliberately blanks them before hashing.
- `sch_choke` uses `make_flow_keys_digest()`
  (`sch_choke.c:159`), which is equivalent to hashing the
  full struct. So every hash-region field is `H`.
- `cls_flow` reads via `flow_get_u32_src/dst()`
  (`flow_dissector.c:1731-1759`) which internally switches
  on `control.addr_type` — that's the `R` for addr_type.
  Other field accesses are direct (`flow->basic.ip_proto`,
  `flow->ports.ports`).
- `ipv4/route` and `ipv6/route` both construct a synthesized
  `hash_keys` (a stack-local `flow_keys`) and call
  `flow_hash_from_keys()` on it. Those writes are not
  reflected in the matrix because they don't read from the
  dissector-populated `keys` — they're writes to a fresh
  buffer.
- The Setup-only consumers (`fib_frontend`, `ipv4/netfilter`,
  `ipv6/netfilter`) only touch `basic.ip_proto`, `ports.src`,
  `ports.dst` — via the inline helpers
  `fib4_rules_early_flow_dissect()` (`ip_fib.h:418-437`)
  and `fib6_rules_early_flow_dissect()`
  (`ip6_fib.h:688-707`). They never dereference `addrs`
  through `flkeys`; they read `addrs` from `iph` / `ipv6hdr`
  on the skb directly.

## Phase 1.D — aggregate touch-weight per field

Method: for each field, sum the bucket weight of every
consumer that has `R` in that field. (Hash-region-only `H`
cells are tracked separately because they don't drive layout
decisions — every consumer that calls
`flow_hash_from_keys()` touches the full hash region by
definition.)

### Qualitative (primary — drives layout decisions)

| field | direct-read buckets | hash-region-read buckets | category |
|---|---|---|---|
| `addrs` | RX-hot + TC-hot + Route-hot×2 | RX-hot×2 | **CL0 hot** |
| `ports` | RX-hot + TC-hot + Route-hot×2 + Setup-only×3 | RX-hot×2 | **CL0 hot** |
| `control.addr_type` | RX-hot + TC-hot + Route-hot×2 | RX-hot | **CL0 hot** |
| `basic.ip_proto` | TC-hot + Route-hot×2 + Setup-only×3 | RX-hot×2 | **CL0 hot** |
| `control.flags` | Route-hot×2 | — | CL1 medium |
| `tags.flow_label` | Route-hot×2 | RX-hot×2 | CL1 medium |
| `basic.n_proto` | — | RX-hot×2 | hash-only / cold-direct |
| `vlan` | — | RX-hot×2 | hash-only / cold-direct |
| `cvlan` | — | RX-hot×2 | hash-only / cold-direct |
| `keyid` | — | RX-hot×2 | hash-only / cold-direct |
| `icmp` | — | RX-hot×2 | hash-only / cold-direct |
| `control.thoff` | — | — | **VERY COLD** (no reads at all) |

### Quantitative (appendix — indicative only)

Direct-read score = Σ(bucket weight) for `R` cells. The score
is meaningful only for ranking, not as an absolute frequency.
Hash-region-only (`H`) is not counted because the hash
region is read atomically — adding `vlan` and removing it
doesn't change the per-field score.

| field | score | computation |
|---|---:|---|
| `ports` | **173** | 100 + 10 + 30 + 30 + 1 + 1 + 1 |
| `addrs` | **170** | 100 + 10 + 30 + 30 |
| `control.addr_type` | **170** | 100 + 10 + 30 + 30 |
| `basic.ip_proto` | **103** | 10 + 30 + 30 + 1 + 1 + 1 + (sch_cake H/W = 30, attribution ambiguous; conservatively excluded) |
| `tags.flow_label` | 60 | 30 + 30 |
| `control.flags` | 60 | 30 + 30 |
| `basic.n_proto` | 0 | (hash-region only) |
| `vlan`, `cvlan`, `keyid`, `icmp` | 0 | (hash-region only) |
| `control.thoff` | 0 | (no reads anywhere) |

The ranking matches the qualitative buckets. The
analysis-plan's preliminary grep counts overstated `vlan`
(155) and `icmp` (93) because those counts included writer
code paths, the bpf-flow_dissector dispatch tables, and
unrelated symbols.

## Phase 2 — write-pattern cross-reference

XDP2 parser write set, from
`src/include/xdp2/parser_metadata.h:231-261` and the
`XDP2_METADATA_TEMP_*` macros (lines 412-979). Mapped onto
kernel `flow_keys` fields per
`docs/flow-keys-vs-xdp2-metadata.md` lines 109-122.

| kernel field | XDP2 write origin | always written? | kernel read |
|---|---|---|---|
| `control.addr_type` | `XDP2_METADATA_addr_type` (ipv4/ipv6 macros) | **always for L3** | **hot** |
| `control.flags` | — (XDP2 doesn't emit `FLOW_DIS_ENCAPSULATION` etc.) | **never** | medium (route only) |
| `control.thoff` | partially via `l4_off` (different semantic) | — | not read |
| `basic.n_proto` | `XDP2_METADATA_eth_proto` (ether macros) | **always for L2** | hash-only |
| `basic.ip_proto` | `XDP2_METADATA_ip_proto` (ipv4/ipv6 macros) | **always for L3** | **hot** |
| `tags.flow_label` | `XDP2_METADATA_flow_label` (ipv6 macro line 507) | IPv6 only | medium (route only) |
| `vlan` / `cvlan` | `XDP2_METADATA_TEMP_vlan_*` (lines 747-767) | per-VLAN tag | hash-only |
| `keyid` | `XDP2_METADATA_TEMP_gre_keyid` (line 913) | GRE only | hash-only |
| `ports` | `XDP2_METADATA_TEMP_ports*` (lines 541-553) | **TCP/UDP/SCTP** | **hot** |
| `icmp` | `XDP2_METADATA_TEMP_icmp` (line 772) | ICMP only | hash-only |
| `addrs` | `XDP2_METADATA_TEMP_ipv{4,6}_addrs` (lines 490, 525) | **always for L3** | **hot** |

### Hot intersection — fields both write-hot AND read-hot

| field | written | read |
|---|---|---|
| **`addrs`** | always for L3 (every IP packet) | RX + TC + Route |
| **`ports`** | always for L4 (TCP/UDP/SCTP) | RX + TC + Route + Setup |
| **`control.addr_type`** | always for L3 | RX + TC + Route |
| **`basic.ip_proto`** | always for L3 | TC + Route + Setup (RX uses zero) |

These four are the **CL0 winners**: the parser writes them
on the common TCP/IPv4 hot path, and the kernel reads them
in the hot consumers. They should be co-located in the first
cacheline of any optimized layout.

### Write-hot but read-cold

- `basic.n_proto` (eth_proto): written by every L2 parser
  but only read via the hash. Layout consequence: it must
  stay in the hash region for compatibility, but it doesn't
  need to be in CL0 for direct-read locality.
- `tags.flow_label`: written for IPv6 only; read by route.c
  only. A CL1 candidate.

### Read-hot but write-cold

- (none in the surveyed set — every read-hot field is also
  written on the common path)

### Cold both directions

- `control.thoff` — written by neither side, read by no
  consumer. Cold-tail candidate.
- `vlan`, `cvlan`, `keyid`, `icmp` — written per protocol,
  read via hash only. Hash-region members; remain there for
  ABI but don't drive CL0 layout.

## Open questions for Phases 3-5

Concrete questions the data above raises but Phase 1+2 does
not answer:

1. **Hash region performance** (Phase 3): the CL0 candidates
   (addrs, ports, basic, control.addr_type) total ~40 B. If
   the siphash region could be shrunk to just those four
   fields, what's the cycle savings vs the bias loss for
   RSS/RFS distribution? Worth measuring.
2. **`control.flags` semantics** (Phase 5 design question):
   the route.c consumers read `FLOW_DIS_ENCAPSULATION` to
   decide whether to do inner-flow-keys hashing. XDP2's
   parser doesn't emit `flow_keys`-style flags today — for
   the v2 reorder, we need to decide whether to synthesize
   `control.flags = FLOW_DIS_ENCAPSULATION` based on XDP2's
   `ctrl->var.encaps` tracking, or accept that route.c will
   never see encap-aware hashing through an
   xdp2_metadata_all_v2 cast.
3. **`control.thoff` semantics** (Phase 5 design question):
   not read by any audited consumer, but the `flow_keys`
   ABI has it. Should v2 emit a meaningful value (XDP2's
   `l4_off`) for forward-compat with future consumers, or
   leave it zero?
4. **Microarchitecture sensitivity** (Phase 4): Zen 1 (hp5)
   absorbs scatter writes; smaller cores don't. The CL0
   layout matters more on in-order or small-store-buffer
   cores. Needs a testbed.

## Followups

- The analysis-plan's TL;DR (`docs/optimal-metadata-layout-analysis-plan.md`
  lines 7-41) lists `vlan` and `icmp` as "hot" / "medium"
  based on flat grep counts. After Phase 1 evidence, those
  fields are **direct-read cold** (only touched via the hash
  region in the surveyed consumers). Worth a one-line
  amendment to the plan TL;DR pointing at this findings doc.
- The Phase 1 hypothesis is data-confirmed. Phase 3 (hash
  performance) is the next-most-informative phase and is
  independent of testbed availability — it can run on hp5.
- Phase 4 (μarch sensitivity) requires a non-Zen testbed.
  Park until one is available.
- The v2 reorder plan (`docs/flow-keys-compat-reorder-plan.md`)
  is unaffected by these findings — the v2 layout is
  flow_keys-byte-exact, so it carries forward the existing
  kernel layout regardless of what an "optimal" layout
  would be. The two efforts are decoupled.

## Verification spot-checks

Five (consumer, field, line) tuples checked against kernel
source:

1. `sch_cake.c:747` — `host_keys.control.addr_type` switch → confirms `control.addr_type` R for sch_cake ✓
2. `cls_flow.c:90` — `return flow->basic.ip_proto;` → confirms `basic.ip_proto` R for cls_flow ✓
3. `ipv4/route.c:1971` — `*p_has_inner = !!(keys.control.flags & FLOW_DIS_ENCAPSULATION);` → confirms `control.flags` R for ipv4/route ✓
4. `ipv6/route.c:2422` — `hash_keys.tags.flow_label = keys.tags.flow_label;` → confirms `tags.flow_label` R for ipv6/route ✓
5. `ip_fib.h:434` — `fl4->flowi4_proto = flkeys->basic.ip_proto;` → confirms `basic.ip_proto` R for the Setup-only group ✓

Aggregate ranking is directionally consistent with the
analysis-plan's preliminary grep counts at the top
(ports/addrs lead, thoff at zero); diverges in the middle
where vlan/icmp were overstated by the flat grep. See "TL;DR
→ Discrepancy" above.
