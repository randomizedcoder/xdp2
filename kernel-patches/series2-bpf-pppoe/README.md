# Series 2 — bpf_flow.c PPPoE handling

**Target tree**: `net-next`
  (`git://git.kernel.org/pub/scm/linux/kernel/git/netdev/net-next.git`)
**Net-next branch**: `bpf-flow-dissector-pppoe-rfc`
  (separate from series 1's `flow-hash-small-rfc`)

**Plan doc**: `../../docs/kernel-patches-series2-bpf-pppoe-plan.md`
**Discovery write-up**:
  `../../perf-results/2026-05-20-bpf-pppoe-investigation/findings.md`

## What this is

A single-patch RFC adding PPPoE session-packet handling
(`ETH_P_PPP_SES` / 0x8864) to the in-tree BPF
flow_dissector reference at
`tools/testing/selftests/bpf/progs/bpf_flow.c`.

The C kernel flow dissector handles PPPoE properly; the
BPF reference has no case for it and drops PPPoE packets
at the entry switch. This patch adds the missing
`PROG(PPPOE)` handler following the same pattern as the
existing `PROG(VLAN)` / `PROG(MPLS)` handlers.

## Why a separate series from series1

Different file, different maintainers (BPF folks rather
than netdev/sched), different test surface, and the
discovery is independently useful. Bundling them would
overload both review threads.

The shared origin (XDP2-vs-kernel comparison work with
Tom Herbert) is mentioned in both cover letters so
reviewers see the analytical context.

## Status

- [x] v1 patch drafted; preserved in `v1/`.
- [x] checkpatch.pl --strict clean.
- [x] BPF object compiles clean (clang 18.1.8 -target bpf).
- [x] Resulting object exposes `flow_dissector_6` (the
  new PPPOE program) alongside the existing 0-5.
- [ ] Not yet posted to netdev / bpf list. Pre-post
  checklist (below) needs to clear first.

## v1 summary

```
$ git log --oneline origin/main..bpf-flow-dissector-pppoe-rfc
edfca32c3a01 selftests/bpf: bpf_flow: handle PPPoE session packets
```

Single commit, 1 file changed, 63 insertions(+), 1 deletion(-).
Subject for cover letter:
`[PATCH RFC 0/1] selftests/bpf: bpf_flow: handle PPPoE session packets`

## Pre-post checklist

- [x] checkpatch.pl --strict passes
- [x] BPF compile verified
- [ ] **Run BPF flow_dissector selftests** —
  `tools/testing/selftests/bpf/test_progs -t flow_dissector`.
  Needs root and a configured kernel build environment.
- [ ] **Add a PPPoE pcap test case** to the existing
  flow_dissector tests. The current fixtures don't
  include PPPoE; we'd want one to demonstrate the new
  handler works on real packets through the BPF
  verifier + execution path.
- [ ] **Courtesy alignment with Tom Herbert** on the
  framing (same as series 1 — this patch comes from the
  same XDP2 comparison work).
- [ ] **Decide on UAPI session_id exposure**: the C
  dissector surfaces PPPoE session_id via
  `FLOW_DISSECTOR_KEY_PPPOE` but `bpf_flow_keys` has no
  corresponding field. Adding one is a separate UAPI
  conversation; the RFC asks reviewers whether that
  should be a follow-up.

## Build workaround

Same nix-shell libelf issue as series 1. To build
`bpf_flow.bpf.o` locally:

```bash
cd /home/das/Downloads/net-next
nix develop /home/das/Downloads/xdp2 --command bash -c '
  export NIX_HARDENING_ENABLE=""
  clang -target bpf -O2 -g -Wall \
    -I tools/testing/selftests/bpf \
    -I tools/testing/selftests/bpf/tools/include \
    -I tools/include \
    -I tools/include/uapi \
    -c tools/testing/selftests/bpf/progs/bpf_flow.c \
    -o /tmp/bpf_flow.bpf.o
  llvm-objdump -d --triple=bpf /tmp/bpf_flow.bpf.o | \
    grep "^[0-9a-f].*<flow_dissector"
'
```

Expected output: `flow_dissector_0` through
`flow_dissector_6`. The `flow_dissector_6` is the new
PROG(PPPOE).

The `NIX_HARDENING_ENABLE=""` unset is required because
the nix-wrapped clang otherwise injects
`-fzero-call-used-regs=used-gpr` which is not supported
for `-target bpf`.

## Revisions

- `v1/` — initial RFC, not yet posted
- (future: `v2/`, `v3/` based on review feedback)

## Future work signaled in the RFC

- MPLS-over-PPP support (PPP_MPLS_UC / PPP_MPLS_MC →
  tail-call MPLS handler). Easy follow-up if requested
  by reviewers.
- session_id UAPI exposure via a new bpf_flow_keys
  field. Separate conversation.
- PPPoE pcap fixture for the BPF selftest harness.
