# LWN article plan — flow_keys analysis + small-region hash

**Date**: 2026-05-23
**Branch**: `flow-keys-compat-reorder`
**Target outlet**: LWN.net (primary). Possible secondary:
  Linux Plumbers Conference proceedings, LSF/MM talk.
**Companion docs**:
  - `docs/upstream-options.md` (path 2 — LWN article is one
    of the upstream paths)
  - `docs/kernel-patches-plan.md` (the patch series the
    article will introduce)
  - `perf-results/2026-05-23-flow-keys-consumer-audit/` (all
    the data the article will cite)

## Why an LWN article

LWN articles do several things at once that fit this work:

1. They reach kernel maintainers and senior developers in
   the audience that matters for the patch series — netdev,
   BPF, qdisc folks.
2. They build *context* before the patches arrive on the
   list. By the time the patches show up on netdev, reviewers
   have already seen the analysis and don't need the cover
   letter to do all the heavy lifting.
3. They invite *broader discussion* — a layout question
   like "what should flow_keys look like in 2026?" benefits
   from voices beyond just the patch submitter.
4. They influence direction even when patches don't get
   accepted as-is. XDP started this way (Brouer/Borkmann
   LSF/MM talks before code landed).

## Target audience

Three concentric circles, written for the innermost:

1. **Innermost** — netdev/BPF maintainers who will review the
   patches (Jakub Kicinski, Paolo Abeni, Eric Dumazet, Alexei
   Starovoitov, Toke Høiland-Jørgensen). They want:
   technical depth, struct layouts, cycle measurements, honest
   discussion of trade-offs and uarch dependence.
2. **Middle** — kernel developers in other subsystems who
   read LWN to track networking developments. They want:
   enough context to understand why the change matters
   without needing to be flow_dissector experts.
3. **Outermost** — sysadmins / SREs / sufficiently-technical
   product engineers who read LWN to understand kernel
   trends. They want: the headline, the magnitude of the win,
   what it means for them.

Optimise for the innermost circle; the outer two can skim.

## Article structure (per user's prescription)

Three acts:

```
Act 1 — How it works today (with history)
Act 2 — The challenges
Act 3 — The proposed changes
```

Plus a closing section pointing at future work / open
questions.

Target length: **3000-4000 words**. Long enough for technical
depth, short enough to fit a single LWN feature.

## Section-by-section outline

### 1. Title + lede (150 words)

Working title: **"Faster flow hashing in the Linux kernel:
a five-tuple shortcut"**.

Alternates:
- "Slimming down struct flow_keys hashes"
- "A 16-byte path through flow_dissector"
- "Auditing how the kernel reads flow_keys"

Lede:
- One paragraph framing — kernel hashing on the hot path,
  why it matters, what the proposed change does in one
  sentence.
- Drop the headline number: "~36-80 cycles saved per call,
  depending on microarchitecture and address family."
- Single forward-pointer: "This article walks through how
  flow_keys came to look the way it does, what the audit of
  its consumers revealed, and the small patch series that
  follows from the data."

### 2. How it works today — flow_dissector + flow_keys (700 words)

Open with history:

- **2011**: Eric Dumazet introduces `skb_flow_dissect()` to
  unify the kernel's existing flow-dissection helpers
  (commit `0744dd00c1b1`). Before this, RPS / RFS and a
  handful of other consumers each had their own
  packet-header parser. Quote from the commit: "We use at
  least two flow dissectors in network stack, with known
  limitations and code duplication."
- **2013**: `thoff` added to flow_keys for later use
  (commit `8ed781668dd4` — note this is the field the
  Phase 1 audit found nobody reads today).
- **2014**: refactored to accept raw buffers (not just
  skbs), making the dissector usable from BPF and beyond.
- **2015**: file renamed `flow_keys.h` → `flow_dissector.h`
  (commit `1bd758eb1cab`).
- **Since 2015**: organic growth. New consumers
  (`sch_cake.c`, multipath ECMP in `ipv{4,6}/route.c`, etc.)
  attached themselves to the dissector; new fields
  (`flow_label`, `vlan`, `cvlan`, `keyid`, `icmp`) were
  added to flow_keys to support specific consumer needs.

Then describe the present state:

- **struct flow_keys today** — show the C definition (see
  Diagram 1 below). Note the comment
  `/* 'addrs' must be the last member */` and explain why
  (variable hash length per address type).
- **The hash region** — bytes from `basic` through end-of-
  `addrs`, hashed by `flow_hash_from_keys()` via
  `__flow_hash_consistentify()` + `siphash()`. Variable
  length: 40 B for IPv4, 64 B for IPv6.
- **The consumers** — list nine principal consumers across
  qdiscs, route lookups, classifiers, netfilter. Note that
  flow_keys is also the output of the BPF flow_dissector
  hook (ABI-affecting).

### 3. The challenges (700 words)

Frame two questions the patch series tries to answer:

**Question 1: which fields does the kernel actually read?**

This is the consumer-touch matrix from
`perf-results/.../findings.md`. Show it as Diagram 2.

Key observations:
- The "5-tuple" set (`addrs + ports + control.addr_type +
  basic.ip_proto`) is read by every category of consumer.
- `tags.flow_label`, `vlan`, `cvlan`, `keyid`, `icmp` are
  written by the dissector but read by no consumer's logic
  — they contribute to the hash output but not to any
  consumer's branching or arithmetic.
- `control.thoff` is read by *no consumer at all* among the
  nine audited.

**Question 2: how much does the hash actually cost?**

Userspace microbench using the kernel's own siphash
(via XDP2's port). Measured on three hosts (two Zen 1, one
Zen 2). Show as Table 1 — see `phase3_hash_perf.md` for
the data.

Key observations:
- `flow_hash_from_keys()` is dominated by siphash, not by
  the consistentify pass.
- SipHash2-4 cycle cost scales in ~16-byte bands (one band
  per 8 bytes processed).
- The current 40-B v4 region sits one siphash band above
  the would-be 16-B 5-tuple region — savings are real but
  uarch-dependent at median.

Then the layout-versus-API trade-off:

- Reordering `struct flow_keys` to optimise for the
  consumer-touch matrix would break ABI (BPF dissector hook
  contract). Probably not worth the controversy.
- Adding a *parallel hash helper* for the 5-tuple case
  doesn't touch the struct at all and gives callers a
  choice. Much easier sell.

Lead into Act 3 by foreshadowing: "There's a small patch
series that does exactly this."

### 4. The proposed changes (1000 words)

Three patches. Per-patch ~300 words.

**Patch 1: Documentation/networking/flow_dissector.rst**

- New file in kernel docs documenting the consumer matrix.
- Doesn't change code; gives reviewers and future contributors
  a reference for "who reads which field."
- Includes the per-bucket rationale (RX-hot / Route-hot /
  TC-hot / Setup-only).

**Patch 2: net: flow_dissector: add flow_hash_from_keys_small()**

- ~100 LoC; new opt-in API.
- Hashes `basic.ip_proto + ports + addrs` only — 16 B for
  IPv4, 40 B for IPv6.
- Distribution properties: bitwise identical chi² to the full
  region across 100k synthetic flows; corroborated on a
  small real-traffic capture.
- Cycle saving: ~40 cyc on Zen 2 IPv4 at p50; ~36 cyc on
  Zen 1 IPv4 at p10 (masked at p50 by rdtsc fence floor);
  ~36-40 cyc on IPv6 across both uarches.
- Show the new C definition (Diagram 3).

**Patch 3: net: sched: sch_cake — use the small variant**

- ~8-line change. Switches sch_cake's two `host_keys`
  hashes (used for dual-host fair queueing) to the new
  helper. Keeps the main flow_hash unchanged because it
  can compare against `skb->hash`.
- Saves ~80 cyc/packet on busy queues (2 hashes × ~40 cyc).
- Show the diff (Diagram 4).
- **cake_mq angle**: the newly merged `cake_mq` qdisc
  (Toke Høiland-Jørgensen, merged net-next early 2026)
  auto-installs an `sch_cake` per HW TX queue and routes
  every per-queue instance through the same `cake_hash()`
  code. Patch 3 is therefore picked up by every per-queue
  cake under `cake_mq` for free — the saving scales
  linearly with NIC queue count. Worth a short paragraph
  in this section since cake_mq is the deployment target
  most readers will care about.
- Note: this is a *demonstration consumer*; the helper is
  general-purpose.

### 5. Honest trade-offs (400 words)

Things the article should acknowledge openly:

- The "50% faster" headline is uarch-dependent. On Zen 1
  v4 at median, the saving disappears below the rdtsc
  resolution. The cycle delta is still real (visible at p10
  and p99) but the *median* on Zen 1 is unchanged.
- The new helper is *not* bit-exact with
  `flow_hash_from_keys()`. Callers that compare against
  `skb->hash` or need RSS-path agreement must continue
  using the existing function.
- IPv6 saving is smaller in absolute terms (~36 cyc) but
  applies across both audited uarches.
- The patch doesn't address the deeper layout question. A
  full reorder of `struct flow_keys` would have larger
  potential wins (consumer-touch matrix says CL0 should
  hold addrs+ports+basic+addr_type) but breaks the BPF
  dissector ABI.

### 6. What's next (300 words)

Future directions the article can flag:

- **Other consumers**: `ipv4/route.c` and `ipv6/route.c`
  ECMP multipath hashes could adopt the small variant.
  Higher review burden because routing-hash bit-stability
  matters for path-affinity.
- **A reordered flow_keys**: would require maintainer
  buy-in and a much larger discussion. The audit data
  arms the conversation; the article ends with "should the
  next layout iteration revisit the struct ordering?"
- **XDP2 angle (brief mention only)**: a 5-tuple-shaped
  output struct in XDP2 is being explored as a way to
  produce flow_keys-compatible parser output. Reference the
  XDP2 work in passing; don't make the article about XDP2.

### 7. Closing (150 words)

- Patch series link (LKML archive URL once posted).
- Brief author bio: "Dave Seddon contributes to XDP2 (the
  codegen-based flow-dissection project led by Tom Herbert,
  formerly known as PANDA) and is the author of the patch
  series discussed here. This is his first kernel patch
  contribution. The XDP2-vs-kernel comparison work that led
  to this audit lives at
  https://github.com/randomizedcoder/xdp2."
- Acknowledgments:
  - Tom Herbert (XDP2 lead) for the wider flow-dissection
    work this analysis builds on.
  - Toke Høiland-Jørgensen (current cake maintainer) for
    the cake_mq design and the wider QoS work that makes
    the patch-3 consumer relevant in the first place.
  - Eric Dumazet for the original `skb_flow_dissect()` in
    2011 that this work extends.
  - **Remembering Dave Täht** (1965-2025): cake co-author
    and a foundational voice in the Linux bufferbloat
    effort. Patch 3 touches code he helped create; his
    name remains in the `sch_cake.c` copyright header
    where it belongs. The bufferbloat community's
    tribute lives at LWN
    (https://lwn.net/Articles/1016109/) and on Toke's
    blog.

## Diagrams / structs / tables to include

| # | Type | Content | Source |
|---|---|---|---|
| 1 | Code block | `struct flow_keys` from `include/net/flow_dissector.h` with byte-offset annotations | `flow-keys-vs-xdp2-metadata.md` |
| 2 | Table | Consumer × field touch matrix (R / H / blank) | `findings.md` |
| 3 | Code block | `flow_hash_from_keys_small()` source | `kernel-patches/.../v1/0002-*.patch` |
| 4 | Diff | sch_cake before/after (4 host_keys hash calls) | `kernel-patches/.../v1/0003-*.patch` |
| T1 | Table | Microbench cycle table — Zen 1 vs Zen 2, region size sweep | `phase3_hash_perf.md` |
| T2 | Table | Chi² distribution test results | `phase3_hash_bias.md` |
| 5 | ASCII bar chart (optional) | Cycle cost: full v4 vs full v6 vs small, both uarches | `phase3_hash_perf.md` |

For LWN's format: code blocks render fine; tables are
acceptable for ≤10 columns; ASCII diagrams for layout
illustrations work well.

## Source-material references

Everything the article will cite, in one place:

| section | source doc / artifact |
|---|---|
| History | `git log` on `include/net/flow_keys.h` then `flow_dissector.h` (commits 0744dd00c1b1, 8ed781668dd4, 1bd758eb1cab) |
| struct flow_keys layout | `include/net/flow_dissector.h:405-417` in net-next at `c0aa5f13826d` |
| Hash region helpers | `net/core/flow_dissector.c:1705-1816` |
| Consumer audit | `findings.md` |
| Cycle measurements | `phase3_hash_perf.md`, `hash_bench_run.txt`, `hash_bench_hp{2,5}.txt` |
| Bias test | `phase3_hash_bias.md`, `hash_bias_run.txt`, `hash_bias_pcap_run.txt` |
| Patches | `kernel-patches/series1-flow-hash-small/v1/*.patch` |
| Wider context | `upstream-options.md`, `optimal-metadata-layout-analysis-plan.md` |

All of these are public on the `flow-keys-compat-reorder`
branch; once pushed the article can link to specific commits.

## Submission notes

**Timing**: post-RFC-on-netdev, pre-non-RFC-on-netdev. The
article works best as the "here's what's coming" pitch that
arrives a few days before or alongside the non-RFC patch
series. This lets reviewers read the article first, then
the patches, with full context.

**Approach**: contact LWN editor (Jonathan Corbet,
`corbet@lwn.net`) with a pitch:
- Subject: "Article pitch: small-region hash helper for
  flow_keys"
- Body: 2-3 paragraph summary + link to this plan + offer
  to draft. Corbet typically responds within a few days
  with go/no-go.

**Author**: Dave Seddon (matches the patch series SoB).

**Word budget**: 3000-4000. Long enough for the technical
depth this audience expects. Adjust per Corbet's feedback.

**Lead time**: LWN typically wants 1-2 weeks from acceptance
to publication. Draft should be ready before the non-RFC
submission so the timing lines up.

**Licence**: LWN holds article copyright; that's standard.

**Conflict-of-interest disclosure**: article author is the
patch author. State this up front; LWN editors expect it.

## What this plan does NOT settle

- **Whether** to write the article. The plan is "if we
  write it, this is what it looks like." Decision: write
  it after RFC v1 gets feedback on netdev and we have at
  least one round of revision; that way the article
  reflects something closer to the final shape.
- **Whether to include XDP2 framing** prominently. Current
  recommendation: keep XDP2 in a single paragraph as the
  analytical source. Making the article *about* XDP2 risks
  losing the audience that doesn't yet know what XDP2 is
  and isn't here for that conversation.
- **Whether to split into two articles**. Could be: (1)
  "the analysis" — covers Phase 1-3 with the
  consumer-touch matrix and hash-cost data, no patches;
  (2) "the patches" — the 3-patch series specifically.
  Decision: try single-article first. Split only if Corbet
  asks for shorter pieces.
- **Diagrams: hand-drawn vs ASCII vs SVG**. LWN accepts
  all three. Default to ASCII for layout/data tables; ask
  Corbet if SVG would be welcomed for the touch-matrix.

## Followups

- Push `flow-keys-compat-reorder` to origin so the article
  can link to specific commits.
- Once RFC posted: capture the message-id / lore.kernel.org
  URL for citation in the article.
- Once article published: link from
  `docs/upstream-options.md` (path 2) and from
  `kernel-patches-plan.md`.
