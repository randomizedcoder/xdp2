# series4-flowdis-fastpath — status

## Readability-polish round (2026-07-07, evening)

A dedicated clean-code review pass over the final series, then the small
mechanical items applied (still 15 patches, branch `series4-final-v3`
rewritten in place; pre-polish tip kept as `series4-final-v3-prepolish`):

- **Suite hygiene (patch 14):** `fd_descent_gates[]` array + `fd_all_gates_off()`
  — suite init/exit now clears the five descent gates too, so a failing test
  can never leak an enabled gate into its successors (previously
  correct-by-ordering only).
- **Accessor prototypes (patch 14):** the two test-only accessor prototypes
  moved from the test .c into `include/net/flow_dissector.h` under
  `#if IS_ENABLED(CONFIG_FLOW_DISSECTOR_KUNIT_TEST)` — kills the checkpatch
  "externs in .c" warning legitimately (now 3 benign warnings total).
- **Kernel polish:** `FLOW_DIS_IPV4_VIHL_NOOPT` named constant for the 0x45
  version+IHL byte (patch 02; anchored next to the fast-helper forward
  declarations — NOT next to MAX_FLOW_DISSECT_HDRS, which patch 10 moves);
  GTP-U slow path pre-extracts ver/pt/low3 to match the fast path (patch 12);
  a where-each-shape-is-counted comment above the counter helpers (patch 08);
  a @num_hdrs-threading doc paragraph on the forward declarations (patch 09).

Deliberately NOT done (recorded as the prepared answer if a reviewer asks):
shared tunnel-header classification helpers used by both fast and slow paths
— would make byte-identity structural instead of by-parallel-editing and
shrink flow_dissect_fast_ipv4; deferred as it restructures patches 10-13.

Verified: KUnit 61/61 on the polished tree; per-commit compile ×15;
checkpatch 0 errors / 3 benign warnings; W=1 + sparse clean on
flow_dissector.o and flow_dissector_test.o. Replay gotcha for future rounds:
anchor early-patch insertions on series-owned text that later patches don't
move (the MAX_FLOW_DISSECT_HDRS block moves in patch 10; the counters block
lands adjacent in patch 08).

## Pre-submission hardening round (2026-07-07, later)

Full adversarial review from the net-next-reviewer perspective, then fixes.
The series is now **15 patches** (branch net-next `series4-final-v3`, base
b73bc9ca3686 unchanged), regenerated in this directory.

**Restructure.** netdev's process doc caps a series at 15 patches; 16 would
bounce. Folded old patches 03+04 (VLAN + QinQ) into one (~+201/−18, smaller
than patch 02; they were the most intertwined pair — QinQ edits the proc
handler VLAN introduces, and the vlan/qinq sysctl auto-toggle coupling is now
explained in one message). New numbering: 01 prelude, 02 eth_ip, 03 vlan+qinq,
04 pppoe, 05 mpls, 06 ipip, 07 gre, 08 counters, 09 bound, 10–13 descents
(vxlan/geneve/gtpu/fou-gue), 14 KUnit, 15 docs.

**Code fixes distributed into their originating commits:**
- **static_branch hints (02–05):** dispatcher gates used
  `static_branch_likely` on DEFINE_STATIC_KEY_FALSE keys (default-off case
  compiled as a taken jump, contradicting the "off = not-taken JMP" claim;
  07–13 already used `unlikely`). All now `static_branch_unlikely`.
- **VXLAN header validation (10):** neither path checked the RFC 7348 I flag
  before descending — GBP/GPE/nonconforming frames to port 4789 were parsed
  as plain VXLAN. Both paths now require `vx_flags == VXLAN_HF_VNI` (byte-
  identity preserved). Negative control proven: with the check knocked out,
  the new KUnit case fails 6 expectations.
- **Geneve OAM (11):** OAM control frames (RFC 8926 §3.1) now defer on both
  paths.
- **Reverse-xmas-tree:** declaration ordering fixed across the series (the
  eth_ip key blocks, vlan tci pair, gue block, and the test file) — netdev
  enforces it and checkpatch doesn't catch it.
- **Test-builder bug found:** `put_vxlanhdr()` wrote
  `htonl(VXLAN_HF_VNI)` — a double byte-swap (VXLAN_HF_VNI is already
  cpu_to_be32). Latent while nothing read vx_flags; became live with the
  I-flag check. Fixed; also converted all be-typed KUNIT_EXPECT_EQs to
  host-order compares (sparse-clean).

**KUnit 53 → 61 tests** (still one patch, 14): STOP_AT/BEFORE_ENCAP contract
(descent gate on, callers keep outer tuple); gates-off negative over the whole
corpus observed via a new fast-hits test accessor + positive control;
`flow_hash_from_keys()` equality asserted in every equivalence check; new
corpus shapes (mid-stream fragment ±1st-frag flag, GRE CSUM|KEY and
CSUM|KEY|SEQ, priority-tagged VID 0, IPv6 routing header); descent-validation
negatives (VXLAN I=0 and GBP bits, Geneve OAM, GTP-U S flag) with
assert-outer helpers.

**AI attribution (user decision):** every commit carries
`Assisted-by: Claude:claude-fable-5 sparse` per the in-tree
Documentation/process/coding-assistants.rst format (checkpatch validates it);
the cover letter has an explicit "On tooling" section (Shutsemau-style, per
LWN 2026-07-02). Authorship/Signed-off-by remain Dave Seddon (DCO).

**Cover letter:** renumbered; the two eth_ip measurement contexts are now
labelled (allshapes vs isolated A/B — they read as contradictory before);
restored "Why not just optimise the existing loop"; added header-validation +
STOP-flag + tc-flower-ENC-keys paragraph (verified: enc keys come from tunnel
metadata via skb_flow_dissect_tunnel_info(), untouched by the descents);
added global-vs-per-netns gates rationale; "about half the instructions"
re-anchored to the measured 47–55%; checkpatch-clean (underlines switched
to `=`; `---` underlines read as commit separators).

**Verification of this round:** KUnit 61/61 on the exact final tree, plus a
KASAN+UBSAN run (truncation sweep + fuzzer under KASAN); per-commit compile
of flow_dissector.o (+ fou_core.o, net_namespace.o where touched) across all
15 commits; checkpatch --strict **0 errors** on all 15 + cover (remaining
warnings, all benign: ctl_table-const false positive ×1, MAINTAINERS
new-file notices ×2 — there is no flow_dissector MAINTAINERS section,
net/core is NETWORKING [GENERAL] —, test-accessor extern ×1); W=1 (gcc),
sparse and smatch clean on all touched objects (smatch's only output is a
container_of parser quirk in include/net/neighbour.h, not ours).
Build-env notes: kernel builds need the elfutils pkg-config fix AND the
x86-64 elfutils store path (aarch64 twins exist); KUnit runs from the
`/home/das/Downloads/net-next-kunit` worktree to avoid mrproper-ing the
in-tree build.

Branches: `series4-final-v3` (send this), scratch `series4-hardening-wip`
(byte-identical tree, kept for reference). **The RFC auto thread
(`series4-rfc-tail-v2`) still needs rebasing onto v3 before it is sent.**
Remaining before `git send-email`: full-build + boot smoke on real hardware,
gates-on soak (syzbot never exercises default-off gates), BPF flow-dissector
selftests on a booted kernel, get_maintainer Cc list, check net-next is open.

## Documentation round (2026-07-07)

Added **patch 16**: `Documentation: networking: add flow_dissector overview
and fast-path guide`. The kernel had no general flow_dissector doc — only
`Documentation/bpf/prog_flow_dissector.rst` (BPF override only, and itself
orphaned from every toctree). New `Documentation/networking/flow_dissector.rst`:
overview (what the dissector is, struct flow_keys, the skb->hash consumers),
the dissection path, the BPF-override relationship, the opt-in fast paths, the
tunnel inner-flow descents, and the when-to-enable break-even model + auto
controller. Indexed in `networking/index.rst`; also indexes the orphaned
`prog_flow_dissector.rst` and cross-links the two. Per-knob reference stays in
`admin-guide/sysctl/net.rst` (the doc links to it, no duplication). Verified:
`make htmldocs` builds `flow_dissector.html` with **0 warnings on the new/edited
files**, all `:doc:` cross-refs resolve, orphan warning gone. Main series now
**16 patches** (net-next `series4-final-v2`, tip 55d5547); RFC auto rebased onto
it (`series4-rfc-tail-v2`). No kernel/code change — Documentation only.

## Byte-identical descent + promote-to-landable round (2026-07-06)

The tunnel descents (vxlan/geneve/gtpu/fou/gue) are no longer RFC. The
slow path now grows the **same** descent as the fast path
(`__skb_flow_dissect_udp_encap()` mirrors `flow_dissect_fast_udp_inner()`),
so fast == slow holds and the descents become byte-identical, opt-in
features. They moved into the **main [PATCH net-next] series**, which is
now **15 patches**: prelude, 7 shapes, counters, bound-recursion, then
vxlan/geneve/gtpu/fou-gue (11-14), then the KUnit suite (15, extended to
cover the descents). The RFC thread is now **1 patch** (the adaptive
auto controller only) in `../series4-rfc-auto/`.

Two real bugs surfaced and were fixed as part of this (both folded into
the descent patches, both caught by the now-extended KUnit suite):
- **ENCAP dead-store:** vxlan/geneve/gtpu fast descents stamped
  FLOW_DIS_ENCAPSULATION *before* the inner leaf, which unconditionally
  zeroes `key_control->flags` — so those three never actually set ENCAP
  (and were miscounted as SHAPE_ETH_IP). Fixed by routing all five
  descents through the shared `flow_dissect_fast_udp_inner()` tail, which
  stamps ENCAP after the inner returns.
- **Missing recursion cap:** none of the five UDP-tunnel fast descents
  bounded num_hdrs (only ipip/gre did) — a stack-exhaustion DoS once a
  gate is on, and a depth divergence from the now-descending slow path.
  The shared tail carries the MAX_FLOW_DISSECT_HDRS cap; the slow path is
  bounded by the loop's skb_flow_dissect_allowed().

KUnit: **53/53** (5 new descent-equivalence cases: pin the descent gate
on, toggle the entry gates so one pass descends via fast and the other
via slow, memcmp; corpus includes inner UDP, fou/gue IPv6-outer/IPv4-
inner residue, inner ICMP / out-of-subset deferral, and a 16-level VXLAN
nest at the cap). Both negative controls proven (wrong slow offset ->
vxlan case fails; cap disabled -> nest case fails). Per-commit compile +
checkpatch --strict 0 errors on the 4 descent patches. The slow descent
honours STOP_BEFORE/AT_ENCAP (RPS/RFS/tc callers keep the outer tuple).

Branches: net-next `series4-final-v2` (15, base b73bc9ca), branch
`series4-rfc-tail-v2` (+ auto). Work branch `series4-descent-wip` holds
the verified monolithic tree.

## FOU/GUE inner descent round (2026-07-05, later)

Added an RFC descent for Tom Herbert's UDP encapsulations (he is a likely
reviewer, having authored FOU/GUE and much of the flow dissector). RFC
thread is now **5 patches** (fou/gue is patch 5, after auto).

- **New RFC patch: "descend into FOU/GUE inner flow"** (gates
  `net.flow_dissector.gue_inner` + `fou_inner`). The crux vs
  vxlan/geneve/gtpu: FOU/GUE have **no well-known UDP port**, so the
  packet can't be identified from the wire — the dissector consults the
  per-netns fou table via a registered `struct flow_dissector_fou_ops`
  (fou is tristate, so a hook not a direct call). GUE is self-describing
  (guehdr->proto_ctype = inner proto); direct FOU is bare (inner proto is
  per-tunnel config, so dissection is stateful). Bounded by num_hdrs;
  stamps ENCAP. fou_core: fou_list add/del -> _rcu for the lockless
  data-path walk. KUnit: mock fou-ops + dummy netdev, GUE+FOU descent
  tests assert the inner 5-tuple (48/48 total). checkpatch 0/0.
- Implemented as ONE patch (not two): FOU and GUE share the whole
  mechanism (hook, lookup, dispatcher, call sites), so splitting would
  have both patches editing the same lines. Both gates/features are
  delivered.
- The RFC cover has a "Patch 4: FOU/GUE inner descent (Tom Herbert's UDP
  encapsulations)" section raising the design questions (per-packet
  fou-table walk cost; is stateful direct-FOU dissection in scope; exact
  port match vs the others' hardcoded ports).

## Test-hardening + security round (2026-07-05, later)

An adversarial/coverage audit of the KUnit suite and the fast-path helpers
found one real security bug and expanded the tests substantially:

- **Security (fixed, new patch 10 "bound fast-path tunnel recursion").** The
  fast tunnel helpers (flow_dissect_fast_{ipv4,ipv6,ipip_inner,gre_inner})
  recursed on nested IPIP/GRE with **no MAX_FLOW_DISSECT_HDRS cap** — a crafted
  deeply nested tunnel frame drove one C stack frame per ~20 bytes of linear
  header (hlen = skb_headlen), a kernel-stack-exhaustion DoS once the ipip/gre
  gate is on, plus a >15-header output divergence from the slow path. Fixed by
  threading a num_hdrs counter and deferring to the slow path past the cap
  (byte-identical: <=cap both descend, >cap fast defers to the slow result).
  Series is now **11 patches** (bound is 10, KUnit tests 11).
- **Test expansion (patch 11).** 32 -> 46 tests: every case now runs against
  BOTH eligible dissectors (added a test-only accessor for the file-static
  flow_keys_dissector_symmetric — different used_keys, exercises the
  no-VLAN/no-flow-label branches); a deep-nest IPIP/GRE regression across the
  cap boundary (guards the fix — fails at 16 levels without it); a non-linear
  /frag skb fallback case; corner protocols (GRE SEQ/KEY/version/TEB, IPv6
  ext-header chains, VLAN 8021Q->8021AD, larger IPv4 options, PPPoE PFC); more
  skb-mode shapes; an ineligible-dissector-defers negative; and a seeded
  deterministic fuzzer (4000 iters x 2 dissectors, fixed seed).
- **Byte-identity nit (folded into patch 2).** _ipv4/_ipv6 now clamp thoff with
  min_t like the slow path and the MPLS helper (was a plain (u16) truncation).
- **Negative controls run:** removing the cap makes the deep-nest test fail at
  16 levels; injecting a ports bug makes the fuzzer fail. Both restored.
- **Design note:** the MPLS/PPPoE/CVLAN/num_of_vlans key-write branches are
  unreachable by design (neither eligible dissector requests those keys) —
  defensive dead code, not test-coverable.
- Branches: series4-final (11, base b73bc9ca3686), series4-rfc-tail (4, onto it;
  descents thread num_hdrs too). KUnit 46/46; per-commit compile clean;
  checkpatch --strict 0 errors.


Unified, definitive submission of the flow_dissector opt-in fast-path work.
Supersedes the earlier iterations (v1 umbrella-knob; v2 inline; v3 namespace
eth_ip/vlan/qinq; v4 pppoe/mpls/ipip/gre + descent RFCs). Nothing from those was
ever emailed to netdev or merged — the "in net-next as <hash>" language in the v3
and v4 cover letters described an imagined future and does not apply.

## De-risking round (2026-07-05) — split send + BPF narrative + in-tree test

The single 12-patch posting was restructured into **two sends** after a
pre-submission review of anticipated pushback (eBPF flow dissector not
mentioned anywhere; maintenance-burden/"two paths" concern unaddressed;
byte-identical verification out-of-tree only):

1. **Main series `[PATCH net-next v1 00-10/10]`** (this directory,
   `v1-00*.patch`, branch `series4-final`, base `b73bc9ca3686`):
   - **NEW patch 01** — prelude: static-key gate
     (`netns_bpf_flow_dissector_enabled`) skipping the rcu_read_lock + two
     rcu_dereference netns-BPF run_array loads on every dissect when no BPF
     flow dissector program is attached anywhere. Mirrors
     `bpf_sk_lookup_enabled`; also covers the legacy BPF_PROG_ATTACH paths
     the sk_lookup sibling doesn't have. The honest "we improved the
     existing path too" patch.
   - patches 02-08 — the seven byte-identical fast paths (unchanged
     content except the two bug fixes below).
   - patch 09 — per-shape counters + `/proc/net/flow_dissector_stats`.
     Commit message now documents that BPF-handled dissects are
     deliberately not counted (the increment sits after the BPF early
     return — correct denominator for the fast-hit-rate signal).
   - **NEW patch 10** — KUnit fast/slow equivalence suite
     (`net/core/flow_dissector_test.c`, `CONFIG_FLOW_DISSECTOR_KUNIT_TEST`).
     32 tests: eligible shapes, deliberate misses, truncation sweep at
     every byte boundary, skb-mode (hwaccel VLAN) cases. Run:
     `./tools/testing/kunit/kunit.py run --arch=x86_64 --kconfig_add
     CONFIG_NET=y --kconfig_add CONFIG_FLOW_DISSECTOR_KUNIT_TEST=y
     flow_dissector_fastpath`
   - Cover letter gained "Relationship to the BPF flow dissector",
     "Maintenance burden: why two paths won't diverge", and "Why not just
     optimise the existing loop" sections; patch 02's message now states
     the BPF-hook ordering (fast path runs after it; attached programs
     always win — verified in code at the flow_dissect_fast call site).

2. **RFC thread `[RFC net-next v1 0-4/4]`**
   (`../series4-rfc-descent-auto/`, branch `series4-rfc-tail`, applies on
   the main series): vxlan/geneve/gtpu inner descent + adaptive
   auto-enable. Subjects normalized to plain `net: flow_dissector:` (the
   RFC marker lives in the email prefix). The operator-problem
   flow-distribution story and the open questions moved from the main
   cover into this thread's cover.

**The KUnit suite caught two real byte-identical violations** the
out-of-tree A/B harness had missed; both fixed in place (folded into the
patches that introduced them, each intermediate commit still
compile-verified, final tree byte-identical to the KUnit-green tree):

- **MPLS (patch 06)**: the fast helper skipped the slow path's `out_good`
  terminal writes. For the standard flow_keys dissectors (no MPLS key
  requested) the slow path returns OUT_GOOD after the first LSE with
  nhoff advanced, so `thoff`, `n_proto` (the MPLS ethertype) and
  `ip_proto` (0) still get written at the exit label. Fast helper now
  mirrors that (and takes `proto` as a parameter).
- **4in6 / v6-outer descent (patch 07)**: the slow path writes the outer
  IPv6 addresses (32 B into the flow_keys addrs union) and outer flow
  label before descending; an inner IPv4 then overwrites only the first
  8 B, leaving outer-v6 residue that the fast path (which skipped outer
  writes) did not reproduce. Functionally benign (the hash only covers
  v4addrs when addr_type is IPv4) but a byte-identical violation. The
  v6-outer descent now mirrors the slow path's outer writes; corpus
  gained 4in6_flowlabel, 6in6 and gre6_ipv4 cases.

Signed-off-by added to the counters and auto commits (was missing);
the auto commit's Co-Authored-By trailer (a GitHub convention checkpatch
rejects) was dropped during normalization — re-add AI attribution in
whatever form is preferred before sending, if desired.

Verification status of this round: all 14 commits checkpatch --strict
**0 errors** (remaining warnings: the ctl_table-const false positive —
`register_net_sysctl_sz` takes non-const in this tree; the KUnit
MAINTAINERS notice; one >75-col commit-message table line in the auto
RFC). `net/core/flow_dissector.o` compiles at every edited intermediate
commit and at both branch tips. KUnit 32/32 at the main-series tip.

## The series (historical 2026-07-05 numbering — see the top section for the current 15-patch layout; all gates under /proc/sys/net/flow_dissector/, default 0)

| # | patch | sysctl | tier | verified |
|---|---|---|---|---|
| 01 | netns-BPF lookup static key (prelude) | (none) | existing-path optimisation | compile-clean; no-prog case skips the lookup |
| 02 | eth + IPv{4,6} + {TCP,UDP} | `eth_ip` | byte-identical (base gate) | KUnit + output == slow path |
| 03 | single Eth+VLAN | `vlan` | byte-identical | KUnit + output == slow path |
| 04 | QinQ (depth-2) | `qinq` | byte-identical | KUnit + output == slow path |
| 05 | PPPoE session | `pppoe` | byte-identical | KUnit + output == slow path |
| 06 | single-label MPLS | `mpls` | byte-identical | KUnit (bug found+fixed) |
| 07 | IP-in-IP family (IPIP/4in6/6in4) | `ipip` | byte-identical | KUnit (4in6 bug found+fixed) |
| 08 | plain GRE (no flags) | `gre` | byte-identical | KUnit + output == slow path |
| 09 | per-shape counters + `/proc/net/flow_dissector_stats` | (none) | mechanism-only | compile-clean; counting validated via test_parser (docs/COUNTERS-VALIDATION.md) |
| 10 | KUnit fast/slow equivalence suite | (none) | test | 32/32 pass; divergence = CI failure |

RFC thread (`../series4-rfc-descent-auto/`):

| # | patch | sysctl | tier |
|---|---|---|---|
| 1 | VXLAN inner descent | `vxlan_inner` | RFC (behaviour change) |
| 2 | Geneve inner descent | `geneve_inner` | RFC (behaviour change) |
| 3 | GTP-U inner descent | `gtpu_inner` | RFC (behaviour change) |
| 4 | adaptive auto-enable (`auto` + `auto_window_packets`) | `auto` | RFC (policy loop) |

`vlan`/`qinq` carry the dependency auto-toggle (`proc_set_vlan_key` /
`proc_set_qinq_key`); `eth_ip` is the parent gate.

## Provenance + verification (updated 2026-07-07)

These `v1-0000..v1-0015` are **real `git format-patch` output** from the
local net-next tree (`/home/das/Downloads/net-next`):

- main: `git format-patch --subject-prefix='PATCH net-next' -v1
  --cover-letter --base=b73bc9ca3686 b73bc9ca3686..series4-final-v3`
- The cover body is maintained in `/tmp/s4msgs/cover-letter-body.txt`
  during a round and hand-inserted after regeneration (format-patch
  emits a blank blurb); the commit-message sources for the round live
  in `/tmp/s4msgs/*.txt` (regenerate them from the branch if lost —
  git is the source of truth).

Historical (2026-07-05) provenance:

- main: `git format-patch --subject-prefix='PATCH net-next' -v1
  --cover-letter --base=b73bc9ca3686 b73bc9ca3686..series4-final`
- RFC: `git format-patch --subject-prefix='RFC net-next' -v1
  --cover-letter series4-final..series4-rfc-tail`
- Cover-letter bodies are maintained in the two `v1-0000-*` files (hand
  restored after regeneration; format-patch emits a blank blurb).
- The old 12-patch branch `series4-send` (9efb44752a0c) is kept for
  history and because l2's netnext-kernel.nix pins it by rev; the new
  canonical branches are `series4-final` (main) + `series4-rfc-tail`.

Remaining before `git send-email`: the author's usual net-next full-build
+ boot smoke on real hardware, then send the main series; send the RFC
thread referencing the main series' lore link.

## Docs
- `docs/RECOMMENDATIONS.md` — **definitive per-feature enablement guide**: which
  gate to turn on for which traffic pattern (all 10 shapes), byte-identical vs
  behaviour-changing, and the honest caveats. The go-to "when to enable" reference.
- `docs/deployment.md`, `docs/packet-flow-context.md` — deployment recipe +
  stack-placement architecture (carried from series3; namespace-aware).
- `PERFORMANCE.md`, `TESTING.md` — full data + method catalogue.
