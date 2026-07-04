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
| 08 | per-shape counters + `/proc/net/flow_dissector_stats` | (none) | mechanism-only (no dissection change) | compile-clean; counting validated via test_parser (docs/COUNTERS-VALIDATION.md) |
| 09 | VXLAN inner descent | `vxlan_inner` | **RFC EXPERIMENT** | behaviour change; flow-distribution measured |
| 10 | Geneve inner descent | `geneve_inner` | **RFC EXPERIMENT** | behaviour change; flow-distribution measured |
| 11 | GTP-U inner descent | `gtpu_inner` | **RFC EXPERIMENT** | behaviour change; flow-distribution measured |
| 12 | adaptive auto-enable (`auto` + `auto_window_packets`) | `auto` | **RFC** (policy loop) | compile-clean; policy core unit-tested (userspace agent, 8 tests) |

`vlan`/`qinq` carry the dependency auto-toggle (`proc_set_vlan_key` /
`proc_set_qinq_key`); `eth_ip` is the parent gate.

## Landable core vs RFC tail

Patches 1-8 are proposed for merge: 1-7 byte-identical (fast == slow or
fall-through), and 8 mechanism-only (per-cpu counters + a read-only proc file;
does not change dissection). Patches 9-11 change behaviour (inner vs outer keys)
and are posted RFC EXPERIMENT for design discussion (see the cover letter's open
questions), backed by the flow-distribution data
(`perf-results/2026-07-01-encap-flow-distribution/`). Patch 12 (adaptive
auto-enable) is an RFC policy loop on top of the counters (docs/AUTO-DESIGN.md);
the same policy also ships as a userspace reference agent
(`xdp2-rs/crates/xdp2-fastpath-control`, both homes share identical thresholds).

**Fallback if a maintainer objects to mixing landable + RFC in one posting:**
drop patches 9-12 to a follow-up RFC series and post 1-8 as `[PATCH net-next]`.
Do not split preemptively — the whole point of series4 is to show the full
intent, with the encapsulation value proposition front and centre.

## Provenance + verification (updated 2026-07-03)

These `0001..0012` are **real `git format-patch -v1` output** generated against
net-next **`d6e815297491`** (base-commit line present in each), in order:
byte-identical (1-7), counters (8), descent RFC (9-11), auto RFC (12).

**Verified — the series now compiles.** The earlier host-toolchain blocker
(objtool failing on `gelf_getsymshndx` because the nix shell's ancient
libelf-0.8.13 shadowed elfutils via pkg-config) is resolved by pointing
`PKG_CONFIG_PATH` at elfutils-0.194-dev:

- `make net/core/flow_dissector.o` builds **objtool-clean** at the series tip
  (all 12 commits applied) — the counters and auto code are real-compile-verified,
  not just line-compared.
- Counters (patch 8) counting logic validated end-to-end via the userspace mirror
  in `test_parser` on ground-truthed pcaps — see `docs/COUNTERS-VALIDATION.md`
  (eth_ip top-level gate, vlan/qinq first/second tag, all seven shapes).
- Auto (patch 12) policy core unit-tested in the userspace reference agent
  (8 tests: dwell, hysteresis, disable, mpls-exclusion, rate-cap, window-gate,
  parse) — `xdp2-rs/crates/xdp2-fastpath-control`.
- all `net.flow_dissector.*` sysctl entries (10 gates + `auto` +
  `auto_window_packets`) present and well-formed; no conflict markers.

Remaining before `git send-email`: the author's usual net-next full-build + boot
smoke on real hardware, then send. Minor polish options: reconcile the
RFC-EXPERIMENT subject-tag placement across 9/10/11, and (optional) move the
`/proc/net/flow_dissector_stats` net.rst paragraph from patch 12 into patch 8
so the doc lands with the mechanism it describes.

## Docs
- `docs/RECOMMENDATIONS.md` — **definitive per-feature enablement guide**: which
  gate to turn on for which traffic pattern (all 10 shapes), byte-identical vs
  behaviour-changing, and the honest caveats. The go-to "when to enable" reference.
- `docs/deployment.md`, `docs/packet-flow-context.md` — deployment recipe +
  stack-placement architecture (carried from series3; namespace-aware).
- `PERFORMANCE.md`, `TESTING.md` — full data + method catalogue.
