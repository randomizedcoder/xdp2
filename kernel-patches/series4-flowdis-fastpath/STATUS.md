# series4-flowdis-fastpath — status

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

## The series (all gates under /proc/sys/net/flow_dissector/, default 0)

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

## Provenance + verification (updated 2026-07-05)

These `v1-0000..v1-0010` (and `../series4-rfc-descent-auto/v1-0000..v1-0004`)
are **real `git format-patch` output** from the local net-next tree
(`/home/das/Downloads/net-next`):

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
