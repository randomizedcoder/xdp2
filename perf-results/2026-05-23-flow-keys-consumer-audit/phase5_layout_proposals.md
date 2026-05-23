# Phase 5 — concrete layout proposals + modeled cycle cost

**Date**: 2026-05-23
**Branch**: `flow-keys-compat-reorder`
**Companion**: `findings.md` (Phase 1+2), `phase3_hash_perf.md`,
  `phase3_hash_bias.md`
**Companion implementation plan**:
  `docs/flow-keys-compat-reorder-plan.md` (the
  byte-exact `xdp2_metadata_all_v2` proposal)

## TL;DR

Three candidate "optimal" layouts, each backed by Phase 1-3 data:

| layout | hot-write CL0? | hot-read CL0? | hash region | ABI compat | est. cycle saving |
|---|---|---|---|---|---|
| **A — flow_keys-exact** (`v2` from companion plan) | partial | yes | 40 B (v4) / 64 B (v6) | **kernel cast works** | 0 (baseline) |
| **B — 5-tuple-first compact** | **yes** | **yes** | 16 B small + 40 B compat | kernel cast works only for full hash | **~40 cyc/hash** |
| **C — per-parser-tailored** | configurable | configurable | configurable | none guaranteed | **~40-80 cyc/hash** (workload-dependent) |

**Recommendation**: ship Layout A as the v2 (companion plan
already does this). **Add Layout B as v3** opt-in: same
prefix-compat byte layout, but with a smaller second hash
entry point exposed for callers that don't need byte-exact
kernel parity. Defer Layout C until Option C
phase 2-a.7 work reaches the "metadata struct as a
configurable codegen output" stage.

This recommendation is data-armed but not benchmark-validated
on hp5. The cycle-saving numbers below are *modeled* from
Phase 3 measurements on Zen 2. **hp5 (Zen 1) re-validation
remains a parked next-session item.**

## Inputs (data review)

From Phase 1+2 (`findings.md`):

- **CL0 winners** (read-hot AND write-hot on TCP/IPv4):
  `addrs`, `ports`, `control.addr_type`, `basic.ip_proto`
- **CL1 winners** (read-medium): `control.flags`,
  `tags.flow_label`
- **Hash-region-only** (read via siphash, no direct logic):
  `basic.n_proto`, `vlan`, `cvlan`, `keyid`, `icmp`
- **Cold tail** (no reads at all): `control.thoff`

From Phase 3 cycle measurements (`phase3_hash_perf.md`):

- `__flow_hash_consistentify` ≈ 0-40 cyc (free)
- siphash 16-24 B ≈ 40 cyc real work
- siphash 40-56 B ≈ 80 cyc real work
- siphash 64-72 B ≈ 80-120 cyc real work
- v4 (40 B) full hash ≈ 80 cyc; v6 (64 B) ≈ 120 cyc

From Phase 3 follow-on (`phase3_hash_bias.md`):

- 16 B 5-tuple region gives statistically equivalent
  distribution to 40 B full region — no RSS/RFS quality
  penalty for shrinking.

## Layout A — `xdp2_metadata_all_v2` (flow_keys byte-exact)

**Already documented in
`docs/flow-keys-compat-reorder-plan.md`. Repeated here for
side-by-side comparison.**

```c
struct xdp2_metadata_all_v2 {
    /* === bytes 0-79: byte-exact match with kernel struct flow_keys === */
    /* control (8 B) */
    __u16  thoff;                  /*   0 */
    __u16  addr_type_be16;         /*   2 */
    __u32  flags;                  /*   4 */
    /* basic (4 B + 4 B pad to siphash align) */
    __be16 n_proto __aligned(8);   /*   8 */
    __u8   ip_proto;               /*  10 */
    __u8   basic_pad;              /*  11 */
    /* tags (4 B) */
    __u32  flow_label;             /*  16 */
    /* vlan + cvlan (8 + 8 B) */
    struct fk_vlan vlan;           /*  20 */
    struct fk_vlan cvlan;          /*  28 */
    /* keyid (4 B) */
    __be32 keyid;                  /*  36 */
    /* ports (4 B) */
    __be32 ports;                  /*  40 */
    /* icmp (4 B) */
    struct fk_icmp icmp;           /*  44 */
    /* addrs (32 B) — last */
    union fk_addrs addrs;          /*  48 */

    /* === bytes 80+: XDP2-specific extras (invisible to kernel) === */
    __u8   eth_addrs[12];          /*  80 */
    __u16  l2_off;                 /*  92 */
    __u16  l3_off;                 /*  94 */
    __u16  l4_off;                 /*  96 */
    /* ... tcp_options, arp, gre, gre_pptp, mpls ... */
};
/* total ~208 B */
```

**Properties** (per companion plan + Phase 1-3 data):

- **Cacheline distribution** (v4 hot-write path): `addrs`
  lands at bytes 48-55 (CL0 if struct is CL-aligned). `ports`
  at 40-43 (CL0). `basic.ip_proto` at 10 (CL0). `addr_type` at
  2-3 (CL0). All four CL0 winners are in the same cacheline.
  ✓ matches Phase 1+2 finding.
- **Hash region**: 40 B v4 / 64 B v6 (same as kernel). Hash
  cost: ~80 cyc v4, ~120 cyc v6. Same as kernel.
- **ABI compat**: `(struct flow_keys *)xdp2_meta_v2` is a
  valid kernel-side cast. Zero translation cost.
- **Cycle saving vs kernel today**: zero. This is a
  *compatibility* layout, not an *optimization* layout.

## Layout B — `xdp2_metadata_all_v3` (5-tuple-first compact)

**New proposal. Same byte-0-79 prefix as Layout A for ABI
compat with kernel callers**, plus an **additional 16-B
small-hash region** at the tail and a second hash function
exposed.

```c
struct xdp2_metadata_all_v3 {
    /* === bytes 0-79: byte-exact match with kernel flow_keys (same as v2) === */
    /* (identical layout to xdp2_metadata_all_v2) */
    /* ... */

    /* === bytes 80-95: 5-tuple small-hash region (16 B) === */
    __u8   sh_ip_proto;            /*  80 — duplicate of basic.ip_proto */
    __u8   sh_pad[3];              /*  81 */
    __be16 sh_sport;               /*  84 — duplicate of ports.src */
    __be16 sh_dport;               /*  86 */
    __be32 sh_saddr;               /*  88 — duplicate of addrs.v4.src (or hashed v6) */
    __be32 sh_daddr;               /*  92 */

    /* === bytes 96+: XDP2-specific extras (same as v2) === */
    __u8   eth_addrs[12];          /*  96 */
    /* ... tcp_options, arp, gre, gre_pptp, mpls ... */
};
/* total ~224 B (+16 B over v2) */
```

**Two hash entry points exposed**:

```c
/* Full kernel-equivalent hash — uses bytes 0-79 hash region */
u32 xdp2_flow_hash_full(struct xdp2_metadata_all_v3 *m);

/* Compact 5-tuple hash — uses bytes 80-95 sh_* region; ~40 cyc */
u32 xdp2_flow_hash_small(struct xdp2_metadata_all_v3 *m);
```

**Properties**:

- **Cacheline distribution** (v4 hot-write path): same as
  v2 (the CL0 winners are still at offsets ≤55). The new
  sh_* fields are at CL1 (offsets 80-95) — they're **write-
  duplicates** of fields already written in CL0.
- **Extra write cost**: writing the sh_* duplicates adds
  4 store ops per packet on the TCP/IPv4 hot path. On Zen 1
  store buffer absorbs these; on smaller cores the cost is
  more visible. Modeled cost: ~2-4 cycles/packet.
- **Hash cost**:
  - `xdp2_flow_hash_full`: ~80 cyc v4 / ~120 cyc v6 (same
    as v2)
  - `xdp2_flow_hash_small`: ~40 cyc (per Phase 3) for v4
    and v6 (the 16-B region holds a hashed-down v4 OR the
    hash of v6 addrs — needs design decision below)
- **Cycle saving vs Layout A**: ~40 cyc/hash for callers
  that use the small variant. In sch_cake-style consumers
  that hash 3×/packet, that's **~120 cyc/packet ≈ 40 ns/pkt
  at 3 GHz**.
- **ABI compat**: bytes 0-79 unchanged → kernel cast still
  works. Kernel callers ignore bytes 80+. Only the new
  `xdp2_flow_hash_small` is XDP2-specific.

### Open design questions for Layout B

1. **v6 in the small region**: 16 B holds v4 addrs (8 B)
   directly. For v6 (32 B src+dst), the small region would
   need to hold a *reduced representation* — e.g., the
   low 32 bits of each v6 address, or a pre-hash digest.
   Affects distribution quality on v6 only (RFC 4291
   suggests low-64-bits is well-randomized for global
   addrs); Phase 3-followup tested only v4. Re-validate
   with v6 traffic if v6 hash-bias matters.
2. **sh_* field writes**: should these be emitted by the
   parser unconditionally, or gated on a per-parser
   `use_small_hash_region = 1` config? Conditional writes
   would let v2-only consumers avoid the cost; uniform
   writes simplify codegen. Recommend: gate on parser
   config field, default off (matches the
   `.use_flow_keys_layout` pattern in the companion plan).
3. **Naming**: `sh_*` vs `small_*` vs `compact_*`. Pick
   one consistently if shipping.

## Layout C — Per-parser-tailored (Option C 2-a.7)

**Not a single layout; a *codegen direction*.** Each parser
declares a `.metadata_layout = { fields_used: BITMASK,
hash_region: HOT/FULL, alignment: CL/PACK }` and the
xdp2-compiler emits a struct tailored to that parser.

Example tailored structs the codegen might emit:

```c
/* For a parser that only needs 5-tuple hashing
 * (e.g., a simple L4 load-balancer parser) */
struct __packed metadata_tcp_5tuple {
    __u8   ip_proto;               /*  0 */
    __u8   _pad[3];                /*  1 */
    __be16 sport, dport;           /*  4 */
    __be32 saddr, daddr;           /*  8 */
};                                 /* 16 B total */

/* For a parser that needs eth_addrs + l2_off + 5-tuple
 * (e.g., a switch fastpath) */
struct __packed metadata_switch {
    __u8   eth_addrs[12];          /*  0 */
    __u16  l2_off;                 /* 12 */
    __be16 eth_proto;              /* 14 */
    __u8   ip_proto;               /* 16 */
    __u8   _pad[3];                /* 17 */
    __be16 sport, dport;           /* 20 */
    __be32 saddr, daddr;           /* 24 */
};                                 /* 32 B total */
```

**Properties**:

- **Cacheline distribution**: optimal per-parser (smallest
  struct = smallest CL footprint).
- **Hash cost**: ~40 cyc with siphash over the whole
  tailored struct (16-32 B typical).
- **ABI compat**: **none** by design. Each parser's output
  is bespoke. Kernel-style cast doesn't work.
- **Cycle saving**: largest of the three layouts —
  potentially **80+ cyc/packet** vs Layout A for simple
  parsers (smaller struct = smaller write set + smaller
  hash region).
- **Complexity**: highest. Requires codegen IR to track
  per-parser layouts, mask used fields, emit per-parser
  hash functions. Already partially explored in the
  R8-Option C phase 2-a series.

## Modeled cycle cost summary

For an sch_cake-style consumer that calls
`flow_hash_from_keys` 3× per packet on TCP/IPv4:

| layout | per-hash cyc | per-packet cyc (3 hashes) | ns/pkt at 3 GHz |
|---|---:|---:|---:|
| Layout A (v2) | 80 | 240 | ~80 ns |
| Layout B (v3, small hash) | 40 | 120 | ~40 ns |
| Layout C (16-B tailored) | 40 | 120 | ~40 ns |

For an ipv4/route consumer that calls
`flow_hash_from_keys` 1× per packet:

| layout | per-hash cyc | per-packet cyc | ns/pkt at 3 GHz |
|---|---:|---:|---:|
| Layout A | 80 | 80 | ~27 ns |
| Layout B (small) | 40 | 40 | ~13 ns |
| Layout C (tailored) | 40 | 40 | ~13 ns |

For a Setup-only consumer (fib/netfilter — only basic +
ports read, no hash compute):

| layout | per-call cost | notes |
|---|---|---|
| All three | identical | hash never computed; layout doesn't matter |

## Recommendation

**Ship Layout A (companion plan's v2) first.** The
compatibility win (zero-translation kernel cast) is concrete
and ABI-stable. It's the lowest-risk path to upstream
relevance.

**Then ship Layout B as v3 opt-in.** It's a strict
superset of v2 (same prefix; adds a 16-B tail), so it
inherits v2's compat properties while exposing the
cycle-saving small-hash path for XDP2-aware consumers.
This is the data-supported "what would optimal look like"
answer to the analysis-plan's question.

**Defer Layout C (per-parser tailored) until Option C
phase 2-a.7 work matures.** The codegen complexity is
substantial; the cycle savings are real but only payoff
for consumers that don't need any ABI compat. Most XDP2
upstream-relevance arguments hinge on the Layout A cast
demo, so per-parser tailoring is downstream of that.

### Sequencing

1. **Implement Layout A** (companion plan phases 1-5)
2. **Re-test on hp5** per `flow-keys-compat-reorder-plan.md`
   §"Quick-reference re-test protocol"
3. **If Layout A regresses on hp5 by >3 ns**: investigate
   per the playbook before adding Layout B
4. **If Layout A is null on hp5**: design Layout B in a
   follow-up branch; ship in a separate PR
5. **Park Layout C** with a pointer-doc; revisit when
   Option C 2-a.7 reaches steady state

## Re-test protocol for any of the proposals

Same as the companion plan's quick-reference table:

| gate | requirement | wall time |
|---|---|---|
| Parity gate | 32/32 OK | ~3 min |
| Protocol-coverage matrix | 4914 cells, 0 OK!N / 0 REJ-* | ~5 min |
| Mono-perf ceiling | 0 violations on 12 cells | bundled in sweep |
| hp2-hp5 sweep | cells within ±2 ns of baseline (`e970334`) | ~30 min |

Layout B additionally needs:

| extra gate | rationale |
|---|---|
| hash distribution sanity check on `xdp2_flow_hash_small` | confirm Phase 3-followup result holds on the implemented version |
| sh_* duplicate-write validation | every TCP/IPv4 packet should populate sh_* identically to ports/addrs/ip_proto |

## What this DOESN'T deliver

- **Actual hp5 measurements of any layout.** All cycle
  numbers above are *modeled* from Phase 3 microbench on
  Zen 2 Threadripper. The companion plan's re-test
  protocol is what produces the real numbers, and that
  requires hp5 access.
- **Layout B v6-addr design**: the question of how to fit
  v6 addrs (32 B) into a 16-B small-hash region is left
  open above (pre-hash digest? low-64-bits? both for two
  variants?). Resolve when Layout B is being implemented,
  not before.
- **A complete upstream-pitch document.** Layout A is the
  upstream-relevance lever; Layouts B/C are XDP2-internal
  optimizations. The upstream pitch lives in
  `docs/flow-keys-vs-xdp2-metadata.md` and the
  Path-5-drop-in writeup, not here.

## Followups

- Update analysis-plan TL;DR with the Phase 5 outcome:
  hypothesis confirmed; recommended approach is "ship the
  compat layout first, add the optimized variant as opt-in
  later." Done at next plan-update commit.
- Phase 4 (μarch sensitivity) still parked on hp5.
- Real-traffic hash-bias re-validation (use `data/pcaps/*`)
  for Layout B's v6 design question. Cheap; ~1 hour.
- Layout B v3 implementation branch (separate from the
  v2 work).
