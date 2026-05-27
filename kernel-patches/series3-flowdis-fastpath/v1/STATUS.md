# Series 3: kernel flow_dissector fast-path — RFC v1 (draft complete)

**Date**: 2026-05-27
**Status**: 3-patch v1 RFC drafted. Awaits build + boot + test
  before submission to netdev. Test plan below.
**Plan**: `docs/kernel-flowdis-fastpath-plan.md` in the xdp2 repo.
**Base**: net-next `c0aa5f13826dcb035bec3d6b252e6b2020fa5f88`
  (same base as series 1 + 2).
**Branch in net-next**: `flowdis-fastpath-rfc`,
  HEAD `28bc2795d2fe`.

## Series shape (v1)

| # | patch | LoC | status |
|---:|---|---:|---|
| 1 | flow_dissector: add fast-path entry-point skeleton | 96 | drafted |
| 2 | flow_dissector: add eth+IPv4+{TCP,UDP} fast-path | 88 | drafted |
| 3 | flow_dissector: add eth+IPv6+{TCP,UDP} fast-path | 101 | drafted |

Total: 276 LoC, all in net/core/flow_dissector.c. Cover letter at
`0000-cover-letter.patch`.

Held for v2 follow-up:
- VLAN dispatch + 4 VLAN variants (~150 LoC)
- Kernel selftest for byte-exact verification
- A toggle mechanism (CONFIG / static_key / sysctl) for the
  selftest

## Decision notes from drafting

**Combined TCP+UDP per address family** rather than separate
patches. The dispatching logic and key writes are identical
between TCP and UDP (both have src/dst u16 ports at L4 offset
0); the only difference is the `iph->protocol` / `iph->nexthdr`
test. Keeping them in one function per family matches kernel
"one logical change per patch" convention and avoids
mostly-duplicated diffs across two patches.

**Byte-exact output** vs the "skip cold slot writes" alternative.
The plan doc considered both. Final decision: byte-exact, because:
- Saving from skipping is ~3 ns/pkt — small vs the ~30 ns/pkt
  fast-path win
- Forward-compat risk if a future consumer reads a "cold" slot
- The cover letter explicitly invites maintainer feedback on
  this choice; if reviewers prefer the skip-cold variant, we
  can change in v2

**Dissector-identity check** restricts the fast-path to
`flow_keys_dissector` and `flow_keys_dissector_symmetric`. Custom
dissectors (e.g. tc cls_flow with bespoke key sets) defer. The
cover letter invites maintainer feedback on whether a broader
policy (any dissector requesting a subset of what the fast-path
writes) would be better.

**Flow label deferral** in the IPv6 fast-path. The slow path
writes `key_tags->flow_label` when the dissector requests
FLOW_DISSECTOR_KEY_FLOW_LABEL AND the packet's label is non-zero.
The fast-path doesn't write key_tags->flow_label, so for
byte-exactness we defer when both conditions hold. The common
case (label == 0 on most internet traffic) takes the fast-path.

## Compile-time gates (per patch)

| patch | W=1 build | checkpatch --strict |
|---:|---|---|
| 1 | clean | 0 errors, 0 warnings, 0 checks |
| 2 | clean | 0 errors, 0 warnings, 0 checks |
| 3 | clean | 0 errors, 0 warnings, 0 checks |

## Pending tests (before non-RFC submission)

Per `docs/kernel-flowdis-fastpath-plan.md` §3:

### Patch 1 architectural gate (the hybrid-cadence checkpoint)

Skipped on user direction (Option B chosen: write all, then
test the lot at the end). If patch 1's dispatch site is wrong,
patches 2-3 inherit the bug. Risk accepted.

### Batched test of the 3-patch series

1. **Build**: Patched kernel via NixOS flake. Pattern: modify
   `/home/das/nixos/hp/hp3/test-kernel/default.nix` to point at
   `/home/das/Downloads/net-next` branch `flowdis-fastpath-rfc`
   (HEAD 28bc2795d2fe). Rebuild via `nixos-rebuild build` from
   hp3's config OR `nix build .#xdp2-test-kernel` if there's a
   flake target.
2. **Boot**: nix-copy-closure to hp1, hp2, hp3, hp5. Reboot each.
   Verify `uname -r` matches expected build, `dmesg | grep -i
   WARN` is clean.
3. **Correctness (manual byte-exact spot check)**: Run iperf3
   through cake on hp1<->hp3. Verify `tc -s qdisc show cake`
   shows non-zero `Sent`, no `dropped`. The cake host_keys hash
   uses fields the fast-path writes; if those fields are wrong,
   cake class population breaks visibly.
4. **Microbench**: Run
   `nix run .#flow-dissector-matrix-unified -- --pcap data/pcaps/
   https-web.pcap` on hp5 with patched kernel. Compare ns/pkt
   for `c-flowdis-usp` (the kernel C path) to the same metric
   on the unpatched hp5 baseline (last measured 116-119 ns/pkt
   on the post-R8 sweep). Expected: ~85-90 ns/pkt patched. Run
   on the 4 flat workloads (https-web, nfs-server, vlan-tcp-mix
   for the IPv4 fast-path stats; nfs-server may include IPv6).
5. **Macrobench**: iperf3 -P 16 -t 60 hp1->hp3 through cake.
   Throughput in the 16 Gbit/s range, matching B.1 baseline.
   No regression.
6. **Short sustained**: 30-min iperf3 through cake on the
   patched kernel. dmesg clean, no memory growth, no drop
   accumulation.
7. **BPF compat**: Load
   `tools/testing/selftests/bpf/progs/bpf_flow.bpf.o` via
   `flow_dissector_load.c`. Verify the BPF dissector runs (not
   the C fast-path) when loaded. Unload, verify fast-path
   resumes via timing comparison.
8. **24h soak (final, before non-RFC)**: 24h iperf3 + 24h iperf2
   soak per the B.1 pattern.

## Next sessions

When picking this back up:
1. Confirm `/home/das/Downloads/net-next` branch
   `flowdis-fastpath-rfc` is still at HEAD `28bc2795d2fe`. If
   not, fetch from the previous session's state.
2. Modify the NixOS test-kernel derivation to point at this
   branch.
3. Run the batched test plan above. Iterate on any failures.
4. Once green, update cover letter with the actual measured
   numbers (replacing the "~85-90 ns/pkt expected" claim with
   measured values).
5. Send to netdev with cc to relevant maintainers (Jakub
   Kicinski, Paolo Abeni, Eric Dumazet — same list as series 1).
