# Kernel patch series 2 — bpf_flow.c PPPoE handling

**Date**: 2026-05-23
**Branch**: `flow-keys-compat-reorder`
**Target tree**: `net-next`
**Net-next branch**: `bpf-flow-dissector-pppoe-rfc` (separate from
  series 1's `flow-hash-small-rfc`)
**Patches go here**: `kernel-patches/series2-bpf-pppoe/v1/`
**Discovery write-up**:
  `perf-results/2026-05-20-bpf-pppoe-investigation/findings.md`
**Companion**: `docs/kernel-patches-plan.md` (series 1)

## What this series is

A single-patch RFC that adds `ETH_P_PPP_SES` (PPPoE
session) handling to `tools/testing/selftests/bpf/progs/bpf_flow.c`,
the in-tree BPF flow_dissector reference program. Closes
a gap the C kernel flow dissector doesn't have:
PPPoE-wrapped packets currently get dropped at the entry
switch in the BPF reference because there's no case for
their ethertype.

## Why a separate series from series 1

| dimension | series 1 (flow_hash_small) | series 2 (bpf PPPoE) |
|---|---|---|
| target file | `net/core/flow_dissector.c`, `net/sched/sch_cake.c` | `tools/testing/selftests/bpf/progs/bpf_flow.c` |
| maintainers | netdev / sched | BPF / netdev |
| test surface | bench microbench + chi-squared | BPF verifier + selftest harness |
| review thread audience | network performance folks | BPF folks |

Bundling them would overload both review threads. Each
stands on its own merit.

## Cover letter framing

Two key framings, both already in the v1 cover letter:

1. **Same XDP2 comparison work**. Mention this is a
   follow-up to the series 1 RFC and that both came from
   the same XDP2-vs-kernel comparison work done with
   Tom Herbert. Reviewers from the BPF side may not have
   seen series 1; tell them.

2. **First-kernel-PR friendliness**. Same humility-and-
   context tone as series 1. Explicitly RFC.

## The patch

Single commit:
`selftests/bpf: bpf_flow: handle PPPoE session packets`

~63 LoC change to `bpf_flow.c`:
- `PPPOE = 6` constant
- `MAX_PROG = 7` (bumped from 6)
- `PPP_IP` / `PPP_IPV6` defines (local; matches the
  pattern used for vlan_hdr/gre_hdr/frag_hdr)
- `struct pppoe_ses_hdr` (PPPoE header + 2-byte PPP
  protocol field; 8 bytes total = PPPOE_SES_HLEN)
- `case bpf_htons(ETH_P_PPP_SES):` in `parse_eth_proto`
- `PROG(PPPOE)` handler that validates, advances offsets,
  switches on PPP protocol, and tail-calls IP/IPV6/DROP

The userspace loader at `flow_dissector_load.h` iterates
programs in source order and populates jmp_table indices
automatically — no loader change needed.

## CC list

- `Alexei Starovoitov <ast@kernel.org>` (BPF)
- `Daniel Borkmann <daniel@iogearbox.net>` (BPF)
- `Andrii Nakryiko <andrii@kernel.org>` (BPF)
- `Stanislav Fomichev <sdf@fomichev.me>` (BPF flow_dissector
  selftests)
- `Eric Dumazet <edumazet@google.com>` (flow_dissector
  semantics; cited for the C-side PPPoE handling pattern)
- `Jakub Kicinski <kuba@kernel.org>`, `Paolo Abeni <pabeni@redhat.com>`
  (netdev)
- `bpf@vger.kernel.org`, `netdev@vger.kernel.org`

## Pre-post checklist

- [x] checkpatch.pl --strict — clean
- [x] BPF compile (clang 18.1.8 -target bpf with
  NIX_HARDENING_ENABLE="" workaround) — clean
- [x] Verified `flow_dissector_6` (new PROG(PPPOE))
  present in the compiled BPF object alongside the
  existing 0-5
- [ ] Run `tools/testing/selftests/bpf/test_progs -t
  flow_dissector` — needs root + selftest build env
- [ ] Decide whether to add a PPPoE pcap test fixture
  alongside the patch (probably yes, but small; could
  be a follow-up patch in the same series — bumps the
  series from 1 patch to 2)
- [ ] Courtesy alignment with Tom Herbert on the framing
- [ ] Decide whether to mention/defer the session_id
  UAPI exposure as a follow-up
- [ ] Decide whether to extend the patch to handle
  PPP_MPLS_UC / PPP_MPLS_MC (the C dissector does)

## Open design questions for reviewer feedback

1. **PPPoE pcap fixture**: should we add one to
   `tools/testing/selftests/bpf/` along with the
   handler, or land the handler alone and add a fixture
   in a follow-up? Argument for together: complete review
   in one go. Argument for separate: keeps the diff
   focused.

2. **session_id exposure**: `bpf_flow_keys` has no slot
   for the PPPoE session_id; the C dissector exposes it
   via `FLOW_DISSECTOR_KEY_PPPOE`. Adding a slot is a
   UAPI extension that needs its own discussion.
   Recommend: defer; the cover letter flags it as a
   possible follow-up.

3. **MPLS-over-PPP**: trivial to add (`PPP_MPLS_UC` →
   tail-call MPLS). The C dissector does it. Including
   it makes the handler more complete; excluding it
   keeps the diff minimal. Recommend: include in v2 if
   reviewers ask, exclude from v1.

4. **Handler name**: `PROG(PPPOE)` — short and consistent
   with `PROG(MPLS)` / `PROG(VLAN)`. No bike-shed
   anticipated.

## Sequencing relative to series 1

Series 1 (flow_hash_small) goes first. It's the more
substantive contribution and the "main" cover letter
introduces the author + the XDP2 context.

Series 2 (bpf PPPoE) follows once series 1 is on the
list. The series 2 cover letter explicitly refers back
to series 1 ("same XDP2 comparison work as my other
RFC") to give the BPF reviewers context without
re-explaining everything.

If posting both within the same few days: post series 1
first, wait 24-48h for the cover letter to circulate,
then post series 2. This avoids the "both pop up at
once and look like a campaign" optics.

## Risks

| risk | mitigation |
|---|---|
| BPF verifier rejection on some kernel version | We compile-tested; verifier check happens at load. Selftest run will catch it. Pre-post item. |
| Reviewer asks "why not in the production C path?" | Already there — see `__skb_flow_dissect()` ETH_P_PPP_SES arm. Pre-emptive paragraph in cover letter. |
| Patch overlaps with concurrent BPF flow_dissector work | Check lore for active threads before posting. Easy to rebase if needed. |
| MPLS-over-PPP gets flagged as missing | Honest "out of scope for minimal diff" framing; offer to add in v2. |
| session_id UAPI question derails review | Defer cleanly in cover letter as "separate UAPI conversation"; don't engage. |

## Followups (out of scope this series)

- Add PPPoE pcap fixture (could be patch 2 in this series)
- session_id UAPI extension for `bpf_flow_keys`
- PPP_MPLS_UC / PPP_MPLS_MC dispatch
- Document the BPF flow_dissector reference in
  Documentation/networking/ (series 1 starts a new
  flow_dissector.rst; could extend with a "BPF reference"
  section after both series land)
