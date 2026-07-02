# series4-flowdis-fastpath — status

Unified, definitive submission of the flow_dissector opt-in fast-path work.
Supersedes the earlier iterations (v1 umbrella-knob; v2 inline; v3 namespace
eth_ip/vlan/qinq; v4 pppoe/mpls/ipip/gre + descent RFCs). Nothing from those was
ever emailed to netdev or merged — the "in net-next as <hash>" language in the v3
and v4 cover letters described an imagined future and does not apply.

## The series (all gates under /proc/sys/net/flow_dissector/, default 0)

| # | patch | sysctl | tier | verified |
|---|---|---|---|---|
| 01 | eth + IPv{4,6} + {TCP,UDP} | `eth_ip` | byte-identical (base gate) | output == slow path |
| 02 | single Eth+VLAN | `vlan` | byte-identical | output == slow path |
| 03 | QinQ (depth-2) | `qinq` | byte-identical | output == slow path |
| 04 | PPPoE session | `pppoe` | byte-identical | output == slow path |
| 05 | single-label MPLS | `mpls` | byte-identical | output == slow path |
| 06 | IP-in-IP family (IPIP/4in6/6in4) | `ipip` | byte-identical | output == slow path |
| 07 | plain GRE (no flags) | `gre` | byte-identical | output == slow path |
| 08 | VXLAN inner descent | `vxlan_inner` | **RFC EXPERIMENT** | behaviour change; flow-distribution measured |
| 09 | Geneve inner descent | `geneve_inner` | **RFC EXPERIMENT** | behaviour change; flow-distribution measured |
| 10 | GTP-U inner descent | `gtpu_inner` | **RFC EXPERIMENT** | behaviour change; flow-distribution measured |

`vlan`/`qinq` carry the dependency auto-toggle (`proc_set_vlan_key` /
`proc_set_qinq_key`); `eth_ip` is the parent gate.

## Landable core vs RFC tail

Patches 1-7 are byte-identical and proposed for merge. Patches 8-10 change
behaviour (inner vs outer keys) and are posted RFC EXPERIMENT for design
discussion (see the cover letter's open questions), backed by the new
flow-distribution data (`perf-results/2026-07-01-encap-flow-distribution/`).

**Fallback if a maintainer objects to mixing landable + RFC in one posting:**
drop patches 8-10 to a follow-up RFC series and post 1-7 as `[PATCH net-next]`.
Do not split preemptively — the whole point of series4 is to show the full
intent, with the encapsulation value proposition front and centre.

## Assembly note (IMPORTANT — regenerate before sending)

These .patch files were **assembled** from the v3/v4 bodies (namespace scheme;
v1/v2 umbrella-knob code is subsumed by v3's namespaced eth_ip) and had only
their `Subject:` prefixes normalised to a contiguous `[PATCH net-next v1 N/10]`.
They are NOT yet a clean git history. Before `git send-email`:

1. Apply/rebase all ten onto a current net-next checkout as one contiguous
   series (resolve any context overlap — patches 8/1 (vxlan) and 4-7 all touch
   `flow_dissect_fast_ipv4` in `net/core/flow_dissector.c`; original ordering had
   vxlan_inner independent of the v4 byte-identical shapes).
2. `git format-patch --cover-letter -v1 --base=<net-next hash>` to fill
   From/Date/base and produce a real diffstat (the cover letter's diffstat is
   approximate: ~830 insertions across the same 3 files as v3+v4 combined).
3. Verify each patch applies and the tree builds; run the byte-identical checks.
4. Reconcile the RFC-EXPERIMENT subject wording (patch 8 vs 9/10 place the tag
   slightly differently).

## Docs
`docs/deployment.md`, `docs/packet-flow-context.md` (carried from series3;
already namespace-aware). See `PERFORMANCE.md` and `TESTING.md`.
