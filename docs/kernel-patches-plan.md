# Kernel patches plan — flow_keys analysis derived

**Date**: 2026-05-23
**Branch**: `flow-keys-compat-reorder`
**Companion analysis**: `perf-results/2026-05-23-flow-keys-consumer-audit/`
**Companion docs**: `docs/upstream-options.md` (paths 1-5 +
  tooling-barrier addendum), `docs/flow-keys-compat-reorder-plan.md`
  (XDP2-side v2 implementation)

## What this plan IS

A concrete proposal for **upstream Linux kernel patches** that
the Phase 1-5 analysis on this branch enables. These are
**Goal A** patches (per `upstream-options.md` addendum) — they
don't require any XDP2 tooling to enter the kernel tree; they
stand on their own as kernel-side changes justified by the
analysis evidence.

## What this plan ISN'T

- The PPPoE BPF patch (covered by `upstream-options.md` path 1;
  independent of Phase 1-5 work; ship separately)
- The R3.4 fast-paths technique backport
  (`upstream-options.md` path 3; needs a separate multi-week
  kernel-module benchmark effort)
- XDP2 framework upstream (`upstream-options.md` path 4;
  needs the tooling story resolved per the addendum)
- XDP2-side `xdp2_metadata_all_v2` work
  (`flow-keys-compat-reorder-plan.md` — this lands in XDP2's
  own tree, not upstream Linux)

## The patch series

Three patches, smallest to largest. Each is independently
justifiable, but they're better as a series because the
docs patch sets the context for the code patches.

### Patch 1/3 — `Documentation/networking: document flow_keys consumer touch matrix`

**File**: `Documentation/networking/flow_dissector.rst`
(extend existing file)
**Size**: ~150 LoC of RST
**Controversy**: lowest — pure docs

Adds a new section to the existing `flow_dissector.rst`
documenting which kernel subsystems read which `flow_keys`
fields. Content derives directly from
`perf-results/2026-05-23-flow-keys-consumer-audit/findings.md`
(Phase 1+2 per-consumer matrix). Includes the bucket
assignment (RX-hot / Route-hot / TC-hot / Setup-only) with
file:line citations.

**Why this lands first**: it provides the evidence base
that patches 2 and 3 cite. Maintainers reviewing patch 2
will want to know "where does this 50% claim come from?"
and the docs patch is the answer.

**Suggested subject**:
```
Documentation/networking: document struct flow_keys consumer touch matrix
```

**Commit message points**:
- Result of auditing 9 kernel consumers
- Provides ground truth for future layout discussions
- Per-consumer evidence with line citations

**CC**: `netdev@vger.kernel.org`,
  `linux-doc@vger.kernel.org`,
  `Jakub Kicinski <kuba@kernel.org>`,
  `Paolo Abeni <pabeni@redhat.com>`,
  `Eric Dumazet <edumazet@google.com>`,
  `Jonathan Corbet <corbet@lwn.net>` (docs)

### Patch 2/3 — `net: flow_dissector: add flow_hash_from_keys_small()`

**File**: `net/core/flow_dissector.c` +
  `include/net/flow_dissector.h`
**Size**: ~80 LoC (decl + impl + comment block)
**Controversy**: medium — new API, requires justification
  evidence but doesn't touch existing code paths

Adds a companion function to `flow_hash_from_keys()` that
hashes only the 5-tuple region (`basic.ip_proto + ports +
addrs`), ~16 B. The existing `flow_hash_from_keys()`
remains unchanged.

**Justification** (from Phase 3 + Phase 3-followup):

- Phase 3 cycle measurement: full hash ~80 cyc v4 / ~120
  cyc v6; 5-tuple-only hash ~40 cyc. ~50% saving for v4,
  ~67% for v6.
- Phase 3-followup chi-squared on 100k synthetic flows:
  full region chi²=242.5 (df=255), small region
  chi²=260.6 — statistically equivalent. K=4096 buckets
  also equivalent.
- Conclusion: smaller region is RSS/RFS-distribution-safe;
  cycle saving is genuine.

**Implementation sketch** (kernel coding style):

```c
/* In include/net/flow_dissector.h */
u32 flow_hash_from_keys_small(struct flow_keys *keys);

/* In net/core/flow_dissector.c */
/*
 * 5-tuple-only hash variant: hashes basic.ip_proto + ports +
 * addrs only, skipping tags/vlan/cvlan/keyid/icmp. ~50%
 * faster than flow_hash_from_keys() with statistically
 * equivalent distribution for RSS/RFS purposes.
 *
 * Suitable for callers that don't need bit-exact hash
 * compatibility with skb_get_hash()/RSS, e.g.
 * sch_cake's host accounting hashes.
 */
u32 flow_hash_from_keys_small(struct flow_keys *keys)
{
    /* siphash directly over a contiguous 5-tuple buffer */
    __flow_hash_secret_init();
    __flow_hash_consistentify(keys);
    /* ... hash basic + ports + addrs only ... */
}
EXPORT_SYMBOL(flow_hash_from_keys_small);
```

**Suggested subject**:
```
net: flow_dissector: add flow_hash_from_keys_small() 5-tuple helper
```

**Commit message points**:
- Cite Phase 3 cycle data (Zen 2 Threadripper measurement)
- Cite Phase 3-followup chi-squared distribution test
- Explicit "not bit-exact with flow_hash_from_keys()" warning
- Reference the consumer-touch-matrix doc (patch 1)

**CC**: `netdev@vger.kernel.org`,
  `bpf@vger.kernel.org` (BPF flow_dissector callers),
  `Jakub Kicinski`, `Paolo Abeni`, `Eric Dumazet`,
  `Alexei Starovoitov <ast@kernel.org>` (BPF)

**Open design questions** to resolve before posting:

1. **v6 in the small variant**: 5-tuple = 16 B works for
   v4 (8 B src+dst). For v6 (32 B src+dst), the function
   needs to either hash a reduced v6 representation
   (low-64-bits per address?) or hash the full v6 addrs.
   Hashing full v6 makes the "small" name less accurate.
   Recommend: hash full v6 addrs; rename function variant
   if confusing. Decide before patch posting.
2. **Naming**: `flow_hash_from_keys_small()` vs
   `flow_hash_5tuple()` vs `flow_hash_compact()`. Pick one;
   bikeshed-prone.
3. **`flow_hash_from_keys_seed_small()` variant**: parallel
   to existing `flow_hash_from_keys_seed()`. Probably yes
   for API symmetry, small extra effort.

### Patch 3/3 — `net: sched: sch_cake: use flow_hash_from_keys_small() for host accounting`

**File**: `net/sched/sch_cake.c`
**Size**: ~20 LoC change
**Controversy**: low if patch 2 lands — uses the new API
  in exactly the kind of place it's designed for

`sch_cake.c:750-763` calls `flow_hash_from_keys(&host_keys)`
twice per packet for `dsthost_hash` and `srchost_hash` —
the host-accounting hashes (separate from the main flow
hash at line 775). These two hashes are used purely for
sch_cake's internal host-load accounting — they don't need
bit-exact compatibility with the RSS hash.

**Switch the two host_keys hashes to the small variant.**
Keep the main flow_hash unchanged (it's compared against
skb->hash, so bit-exact compat matters there).

**Expected saving** (per Phase 3 modeling):
- 2 hashes/packet × ~40 cyc saved = ~80 cyc/packet
- At 3 GHz: ~25 ns/packet on every flow_mode != NONE path
- sch_cake on a busy 10G+ link processes millions of
  packets/sec — small per-packet wins compound

**Suggested subject**:
```
net: sched: sch_cake: use flow_hash_from_keys_small() for host accounting
```

**Commit message points**:
- Cite patch 2 for the API + justification
- Note that the main flow_hash is unchanged (compat
  preserved for skb_get_hash comparisons)
- Per-packet cycle saving estimate
- Reference: host_keys are sch_cake-internal accounting,
  not exposed to other RSS/RFS paths

**CC**: `Toke Høiland-Jørgensen <toke@toke.dk>` (cake
  maintainer), `Dave Täht <dave.taht@gmail.com>` (cake
  contributor / origin), `Jamal Hadi Salim <jhs@mojatatu.com>`
  (TC), `netdev@vger.kernel.org`

## Sequencing

**Bundle as a 3-patch series** posted to netdev with
patch 1 as the docs/evidence base.

Order:
1. Patch 1 (docs) — establishes evidence
2. Patch 2 (new API) — cites patch 1
3. Patch 3 (cake user) — cites patch 2

**Posting cadence**:
- Pre-post sanity: run on a recent net-next tip; rebuild;
  smoke-test the cake selftest if there is one
- Cover letter explaining: this is research-derived, links
  to the analysis branch artifacts (the perf-results/
  directory of this branch is the supporting evidence)
- Single revision sent to netdev; expect iteration on
  patch 2's API naming and v6 handling

## What we don't have yet (pre-post checklist)

These are needed before this patch series is ready to send:

- [ ] **hp5 (Zen 1) re-validation of the Phase 3 numbers.**
  All cycle measurements were on Zen 2 Threadripper. Need
  to compile + run `hash_bench.c` on hp5 to confirm the
  trend. The relative trends should hold, but having hp5
  numbers in the commit messages is much stronger than
  "Zen 2 Threadripper says."
- [ ] **Real-traffic chi-squared.** Synthetic uniform flows
  passed; running the same test against tuples extracted
  from a real pcap (one of `data/pcaps/*` or a captured
  trace) before posting forecloses the "but what about
  heavy-tailed real traffic?" reviewer question.
- [ ] **sch_cake selftest exists?** Check
  `tools/testing/selftests/net/forwarding/` for a cake
  test; if there is one, run it locally before posting
  patch 3.
- [ ] **Patch 2 naming + v6 design** resolved (see "Open
  design questions" above).
- [ ] **Tom Herbert ack/comment** before posting, since
  he's been driving XDP2 upstream work — courtesy alignment.

## More-ambitious follow-up series (do NOT include in series 1)

Once series 1 lands (or stalls clearly), these are the
plausible follow-ups:

### Series 2 — `flow_keys` reorder for CL0 hot fields

Move `addrs` from the end of `struct flow_keys` to the
front, alongside `ports`, `basic.ip_proto`, and
`control.addr_type`. Justified by Phase 1+2 evidence that
these four are the CL0 winners.

**Why higher controversy**: kernel comment in
`include/net/flow_dissector.h:415` explicitly says
`/* 'addrs' must be the last member */` — the hash-length
calculation in `flow_keys_hash_length()` depends on it.
Reordering means rewriting that function. Plus every
caller that does sizeof-arithmetic on the struct needs
review. Not session-scale.

**Defer until series 1 lands** and there's evidence of
maintainer interest in layout changes.

### Series 3 — IPv4/IPv6 route ECMP small-hash adoption

Apply the patch 3 pattern (switch to
`flow_hash_from_keys_small()`) to `net/ipv4/route.c`
and `net/ipv6/route.c` ECMP multipath hashes. Higher
review burden because routing-hash bit-exact properties
matter for ECMP path-affinity.

**Defer until series 1 lands** and there's evidence the
small-hash approach is acceptable to route maintainers
specifically.

## Risks

| risk | likelihood | mitigation |
|---|---|---|
| Patch 2 API name bikeshed cycles | high | Pre-circulate name on netdev IRC / mailing list before posting |
| Patch 2 v6 distribution concern | medium | Run real-traffic chi-squared on v6 before posting |
| Patch 3 cake regression on weird workloads | low | hp5 re-validate; rely on cake's own self-test if present |
| Maintainer: "why not just BPF-based?" | medium | Phase 3 measurement is the answer; cite the cycle delta |
| Maintainer: "show benchmarks on real workloads, not microbench" | medium | Defer to follow-up if asked; this is opt-in API, doesn't break anyone |
| Tom Herbert prefers a different patch direction | medium | Pre-align before posting |

## What success looks like

- **Patch 1 lands** → kernel docs gain the consumer-touch
  matrix as a reference artifact; useful regardless of
  future patches.
- **Patch 2 lands** → new helper API in the kernel; future
  hash-cost-sensitive callers have an option.
- **Patch 3 lands** → sch_cake gets a measurable per-
  packet win at high pps; concrete proof-point for the
  helper API's value.

If all three land, the Phase 1-5 analysis has produced
**real upstream kernel changes** without requiring any
XDP2 tooling to ship in-tree. That's the Goal A outcome.

If only patch 1 lands, the analysis still has an upstream
artifact (the docs patch) — useful for any future
flow_keys-layout discussion.

## What's still parked

- **hp5 testbed access** — needed for re-validation
  before posting (pre-post checklist)
- **Phase 4 (μarch sensitivity)** — needed to expand the
  patch 2 commit message to cover non-Zen cores; not a
  blocker for posting
- **XDP2-side v2 implementation** — separate work, runs
  in parallel; lives in
  `docs/flow-keys-compat-reorder-plan.md`
- **Layout B (v3) on XDP2 side** — depends on v2 landing
  first
