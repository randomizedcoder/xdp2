# Risk audit — flow_hash_from_keys_small() patch series

**Date**: 2026-05-23
**Branch**: `flow-keys-compat-reorder`
**Tree audited**: net-next at `c0aa5f13826d`
**Companion**:
  - `docs/kernel-patches-plan.md` (the patch series)
  - `kernel-patches/series1-flow-hash-small/v1/` (the patches)
  - `perf-results/2026-05-23-flow-keys-consumer-audit/findings.md` (the original 9-consumer audit)

## Why this doc exists

After the Phase 1-5 analysis and the patch series draft, the
question came up:

> If this is such a clear win, how come nobody else has
> noticed? What else uses `struct flow_keys`?

That's the right question to ask before posting. This doc is
the exhaustive audit that answers it.

## The original Phase 1 audit was too narrow

The Phase 1+2 audit (`findings.md`) covered **nine** "hot
consumer" files. A full audit of net-next finds **many more**
touch points. Most are unaffected by our patch, but the broader
picture is worth having in writing.

### Exhaustive flow_keys touch inventory

Grouped by what they DO with flow_keys:

**Hash-emit (call `flow_hash_from_keys{,_seed}()`)** — our
patch is opt-in for these; they keep working unchanged unless
they actively switch over:

- `net/core/flow_dissector.c:1811` `flow_hash_from_keys()`
- `net/core/flow_dissector.c:1818` `flow_hash_from_keys_seed()`
- `net/core/flow_dissector.c:1992-2005` `__skb_get_hash_net()`
  — **THE skb->hash populator**. Calls `__flow_hash_from_keys()`
  internally; output lands in `skb->hash`.
- `net/sched/sch_cake.c:756,759,765,769` — the two
  `host_keys` hash calls (our patch 3 switches these)
- `net/sched/sch_cake.c:781` — the main `flow_hash` call (we
  leave unchanged because it interacts with skb->hash below)
- `net/ipv4/route.c` — **5 distinct call sites** of
  `fib_multipath_hash_from_keys()`
  (lines 1972, 2021, 2083, 2120, 2151), all wrapping
  `flow_hash_from_keys_seed()` for ECMP path selection
- `net/ipv6/route.c` — **6 distinct call sites** of the
  same multipath helper (lines 2433, 2482, 2525, 2547, 2582,
  2619)

**Hash-comparison (depends on bit-stability with skb->hash)**:

- `net/core/dev.c:5108` `get_rps_cpu()` — uses `skb_get_hash(skb)`
  which returns `skb->hash`. RPS steering MUST match what the
  NIC's RSS hash produced, otherwise flows re-steer and lose
  CPU affinity.
- `net/sched/sch_cake.c:786-787` — `use_skbhash` shortcut
  compares the cake-computed flow_hash against `skb->hash`.
  This is why patch 3 leaves the main flow_hash on the full
  function.

**Hash-compute via independent path (different siphash region)**:

- `net/core/flow_dissector.c:1968` `__skb_get_hash_symmetric_net()`
  — uses a separate `flow_keys_dissector_symmetric` that
  populates only proto+addrs+ports; remaining fields stay
  zero, then siphash hashes the full region (so the zero
  bytes contribute zero entropy). **Important precedent** —
  see "What this tells us" below.
- `net/sched/sch_choke.c:158-170` — uses
  `make_flow_keys_digest()` and a direct `memcmp()` on the
  16-B digest. Independent of `flow_hash_from_keys`.

**Field-readers (don't hash; read individual fields)**:

- `net/sched/cls_flow.c` — calls `flow_get_u32_src/dst()` and
  reads `basic.ip_proto`, `ports`. Unaffected by our patch.
- `net/sched/cls_flower.c` — calls `skb_flow_dissect_*`;
  reads fields for filter matching. Unaffected.
- `net/ethernet/eth.c:136` — `skb_flow_dissect_flow_keys_basic`
  for basic ethertype parsing. Unaffected.

**Driver ARFS (Accelerated Receive Flow Steering)** — extract
flow info from packets to program hardware filter tables. All
read flow_keys *fields*; none call `flow_hash_from_keys()`:

- `drivers/net/ethernet/broadcom/bnxt/bnxt.c:15776`
- `drivers/net/ethernet/cisco/enic/enic_clsf.c:181`
- `drivers/net/ethernet/intel/ice/ice_arfs.c:463`
- `drivers/net/ethernet/mellanox/mlx5/core/en_arfs.c:740`
- `drivers/net/ethernet/sfc/rx_common.c:921`
- `drivers/net/ethernet/sfc/falcon/rx.c:853`
- `drivers/net/ethernet/sfc/siena/rx_common.c:912`
- `drivers/net/ethernet/hisilicon/hns3/hns3_enet.c:2968`
- `drivers/net/ethernet/mellanox/mlx5/core/en_rx.c:1525` (GRO)
- `drivers/net/bonding/bond_main.c:4220-4221` (uses
  `flow_get_u32_src/dst`)
- `drivers/net/xen-netback/hash.c:182`

**BPF surface**:

- `BPF_PROG_TYPE_FLOW_DISSECTOR` hook — BPF programs that
  parse packets and write into flow_keys. They consume the
  same struct definition as the kernel, so any layout change
  is an ABI break. Our patch does NOT change the layout.
  BPF programs that hash flow_keys themselves get the same
  result they get today.

## Impact of our patch on each category

| category | call sites | impact |
|---|---|---|
| `flow_hash_from_keys()` callers — opt-in | many | unchanged unless they switch. Patch 3 switches sch_cake's 4 host_keys calls only. |
| `__skb_get_hash_net` → `skb->hash` | 1 (kernel-wide) | **unchanged**. skb->hash continues to use the full algorithm; RPS/RFS/RSS bit-stability preserved. |
| Multipath routing (ipv{4,6}/route.c) — 11 call sites | many | **unchanged**. We don't propose switching these. Route hash bit-stability matters for ECMP path-affinity in long-lived flows; needs a separate, careful discussion. |
| sch_cake main flow_hash | 1 | **unchanged**. Compared against `skb->hash`; needs bit-stability. |
| sch_cake host_keys hashes | 4 | **switched** to small variant (patch 3). These are cake-internal accounting; never compared with skb->hash or any other externally-derived hash. |
| `__skb_get_hash_symmetric_net` | 1 | **unchanged**. Has a different purpose (PACKET_FANOUT symmetric hashing); already uses its own narrow region via separate dissector. |
| `sch_choke` digest+memcmp | 1 | **unchanged**. Uses `flow_keys_digest`, independent path. |
| Field-readers (cls_flow, cls_flower, eth.c) | many | **unchanged**. Don't call hash function at all. |
| NIC ARFS drivers (11 drivers) | 11+ | **unchanged**. Read flow_keys fields to program hardware; don't call kernel hash function. |
| BPF flow_dissector hook | many | **unchanged**. Struct layout unchanged. |

**The patch surface is narrower than the Phase 1 audit suggested.**
Only sch_cake's host_keys hashes (4 call sites) actually
switch. Everything else stays on the full function.

## What this tells us — and how it answers the user's concern

### "If this is such a clear win, how come nobody has done it?"

Honest answer, in three parts:

**1. The kernel already accepts "hash a subset of flow_keys"
as a valid operation.** `__skb_get_hash_symmetric_net()` has
done this since 2016 (David Miller, commit for
PACKET_FANOUT_FLAG_DEFRAG / symmetric hashing). It uses a
*separate dissector* (`flow_keys_dissector_symmetric`) that
populates only proto+addrs+ports, then hashes the full
flow_keys region (with zeros for the cold fields).

Our patch is conceptually similar but more direct: instead of
populating-then-hashing-the-zeros, we hash a smaller buffer
that only contains the populated bytes. **Same effective
entropy, fewer siphash rounds.** The precedent for "the
5-tuple is enough" already exists.

**2. The siphash switch in 2019 didn't reconsider the region
size.** When `flow_hash_from_keys()` was converted from jhash
to siphash (commit `55667441c84f`, Eric Dumazet, Oct 2019),
the motivation was security — the Klein/Pinkas/Berger UDP
IPv6 flowlabel attack. The conversion was a drop-in over the
same `flow_keys_hash_start()` / `FLOW_KEYS_HASH_OFFSET`
region. **The region size was not discussed and was not
considered as an optimization knob.** It's not that the idea
was rejected — it just never came up.

**3. The PANDA / dissector-replacement effort took the
oxygen.** Tom Herbert + Pedro Tammela presented "Replacing
Flow Dissector with PANDA Parser" at Netdev 0x15 (2021) and
followed up at 0x16. The plan was a wholesale replacement of
the flow dissector, not incremental improvements. PANDA
didn't merge upstream. Meanwhile, no one bothered with smaller
incremental wins because the replacement was supposedly
coming. Now that PANDA has stalled, the incremental wins are
on the table.

**No prior proposal for `flow_hash_from_keys_small()` or
equivalent was found on lore.kernel.org, LWN, or LKML
archives.** This is genuinely unexplored upstream territory,
not a previously-rejected idea.

### "What else uses the struct?"

A lot. But:
- Most uses are *field-readers* (drivers, classifiers,
  netfilter) that don't call the hash function.
- The hash-function callers are mostly multipath routing and
  RPS/RFS, all of which need bit-stable hashing.
- Our patch adds a *parallel* function and switches exactly
  one consumer (sch_cake's host_keys accounting) — a consumer
  that owns both endpoints of the hash comparison.

The narrow blast radius is the patch's strongest feature.

## Remaining risks (not addressed by the audit)

These are things the audit can't fully settle:

1. **Maintainer pushback on "yet another hash function".**
   Reviewers may prefer to deprecate hash variants rather
   than add them. A counter-argument: `__skb_get_hash_symmetric_net()`
   already exists as a parallel variant, so the precedent
   for "we have multiple hash functions for different
   purposes" is already established.

2. **The opt-in adoption pattern is uncommon.** Most kernel
   APIs are either used widely or not at all. A helper used
   by exactly one caller (sch_cake) may be questioned.
   Counter: showing the helper's use case is concrete (cake's
   3-hashes-per-packet hot path) and inviting future adopters
   (route ECMP, possibly cls_flow internals) makes the case
   that this is a building block, not a one-off.

3. **The "small" name suggests it's a partial / inferior
   hash.** A reviewer might prefer
   `flow_hash_from_keys_5tuple()` or
   `flow_hash_from_keys_fast()`. Worth bike-shedding on
   netdev before settling.

4. **Sch_cake author opinion is uncertain.** Toke
   Høiland-Jørgensen / Dave Täht maintain cake; their take
   on whether the host_keys hashes are worth optimizing
   matters. **Should reach out before posting.**

5. **The cycle data is from AMD Zen 1 and Zen 2 only.** Intel
   results could be different. The trend should hold (siphash
   is well-pipelined on all modern OoO cores), but maintainers
   may ask for Intel numbers. We don't have an Intel testbed
   today.

6. **`__skb_get_hash_symmetric` may be the right place for
   this, not a new function.** A reviewer might propose:
   "if you want a small-region hash, make `flow_keys_dissector_symmetric`
   exposed and let people use it." The counter is that
   our small variant skips the dissection cost entirely
   (since the caller already has a populated flow_keys),
   whereas `__skb_get_hash_symmetric_net()` re-runs the
   dissector. **Worth pre-empting in the cover letter.**

## What this means for the patch series

**The patch is defensible.** The exhaustive audit shows:

- No prior rejection of this idea
- A direct precedent for "hash a subset" exists (symmetric)
- The blast radius is narrow (one consumer, internal accounting)
- The cycle data is honest about uarch dependence
- The distribution data is solid (chi² + real-traffic)

**Recommendations for the cover letter** (to add):

1. A "prior art" paragraph citing
   `__skb_get_hash_symmetric_net()` as the existing precedent
   for "hash a subset of flow_keys."
2. A "blast radius" paragraph noting that the patch series
   touches exactly one consumer (sch_cake host_keys, 4 call
   sites) and leaves all hash-stability paths (RPS/RFS, skb->hash,
   multipath routing, sch_cake main flow_hash) unchanged.
3. A "why not just use `__skb_get_hash_symmetric`" pre-emption
   noting the cost difference (we skip the re-dissect; they
   re-run it).

**Recommended pre-post action**:
- **Reach out to Toke H. and/or Dave Täht** before non-RFC
  posting to get sch_cake-maintainer alignment on whether
  the host_keys hash optimization is worth their review time.
  Patch 3 is the consumer-side patch; their opinion is the
  one that matters most for its acceptance.

## What's still unknown

- Intel cycle behaviour (no testbed)
- BPF-flow_dissector-program interactions specifically with
  hash-output dependencies (the BPF prog can read flow_keys
  fields, but does any program hash them and depend on
  bit-stability with `flow_hash_from_keys`?)
- Whether any out-of-tree consumer (DPDK / VPP / commercial
  network stacks) has its own bit-stability dependency on
  `flow_hash_from_keys()` output. Probably not — those stacks
  do their own hashing — but worth flagging if asked.

## Bottom line for the user's concern

We're not overlooking something fundamental. We ARE making
a narrowly-scoped change that:

- Has clear prior art (`__skb_get_hash_symmetric_net`)
- Has measurable wins on every uarch tested (no regression
  anywhere)
- Doesn't break any existing bit-stability path
- Hasn't been proposed-and-rejected before

The reason no one has done this incremental win is most
plausibly:
1. PANDA was going to replace the whole thing
2. The siphash conversion in 2019 didn't reconsider region
   size — it was security-driven, not perf-driven
3. The cycle savings (~36-80 cyc/call) are real but small —
   below the threshold most kernel developers would chase
   without a specific motivating consumer
4. Adding kernel APIs is conservative work; people don't add
   them unless there's a strong use case. sch_cake's
   3-hashes-per-packet hot path on busy queues is that use
   case.

The patch is still worth posting. The risks are tractable
and the prior-art picture supports the framing.
