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

## Provenance + verification (2026-07-01)

These `0001..0010` are **real `git format-patch -v1` output** generated against
net-next **`d6e815297491`** (base-commit line present in each). They were built
by cherry-picking the actual commits from the `flow-dissector-namespace-v3/v4`
branches onto current net-next and reordering vxlan_inner from the middle to the
RFC tail so the byte-identical core (1-7) is independently landable. The
reordering conflicts were purely in the registration lists (static keys, sysctl
table, header externs, docs) — the fast-path *code* applied without conflict.

**Verified** (a full kernel build was blocked by a local host-toolchain issue —
nix binutils vs libelf ABI in objtool — unrelated to the patches):
- order-independent line comparison of the final `net/core/flow_dissector.c`
  and `include/net/flow_dissector.h` against the already-tested
  `flow-dissector-namespace-v4` branch: **flow_dissector.h identical; the only
  flow_dissector.c delta is net-next's own eth_addrs refactor between the two
  bases — no flowdis fast-path line, static key, or sysctl entry differs.** So
  the series is line-equivalent to the tested branch, just reordered.
- all 10 `net.flow_dissector.*` sysctl entries present and well-formed; no
  conflict markers.

Remaining before `git send-email`: a clean-tree kernel build on a working
toolchain (the author's usual net-next setup), then send. Optionally reconcile
the RFC-EXPERIMENT subject wording (patch 8 vs 9/10 place the tag slightly
differently).

## Docs
- `docs/RECOMMENDATIONS.md` — **definitive per-feature enablement guide**: which
  gate to turn on for which traffic pattern (all 10 shapes), byte-identical vs
  behaviour-changing, and the honest caveats. The go-to "when to enable" reference.
- `docs/deployment.md`, `docs/packet-flow-context.md` — deployment recipe +
  stack-placement architecture (carried from series3; namespace-aware).
- `PERFORMANCE.md`, `TESTING.md` — full data + method catalogue.
