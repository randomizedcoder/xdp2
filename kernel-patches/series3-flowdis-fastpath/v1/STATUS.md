# Series 3: kernel flow_dissector fast-path — RFC v1 (draft, awaiting test)

**Date**: 2026-05-27
**Status**: 3-patch v1 RFC drafted with simplified English + bullet
  style. Awaits build + boot + test before submission to netdev.
**Plan**: `docs/kernel-flowdis-fastpath-plan.md` in the xdp2 repo.
**Test plan**: `docs/kernel-flowdis-fastpath-test-plan.md`.
**Base**: net-next `c0aa5f13826dcb035bec3d6b252e6b2020fa5f88`
  (same base as series 1 + 2).
**Branch in net-next**: `flowdis-fastpath-rfc`, HEAD `ad885e48f1d4`.

## Series shape (v1)

| # | patch | net-next commit | LoC | status |
|---:|---|---|---:|---|
| 1 | flow_dissector: add fast-path entry-point skeleton | `1ddc620812be` | 57 | drafted |
| 2 | flow_dissector: add eth+IPv4+{TCP,UDP} fast-path | `0a45d17e954e` | 66 | drafted |
| 3 | flow_dissector: add eth+IPv6+{TCP,UDP} fast-path | `ad885e48f1d4` | 72 | drafted |

Total: 195 LoC, all in net/core/flow_dissector.c. Cover letter at
`0000-cover-letter.patch`.

LoC dropped 30% from the first draft (276 -> 195) after a comment
pruning pass: kernel norm is "code speaks for itself" with comments
only on non-obvious bits. See the parallel helpers
`__skb_flow_dissect_ipv4`, `__skb_flow_dissect_icmp`,
`__skb_flow_dissect_l2tpv3` in the same file -- all zero comments.
We kept comments only on:

- The dispatcher's contract (3-line block above `flow_dissect_fast`)
- The IPv4 0x45 magic (version + IHL packed in one byte)
- The IPv6 flow-label deferral logic (non-obvious why we defer)

Held for v2 follow-up:

- VLAN dispatch + 4 VLAN variants (~150 LoC)
- Kernel selftest for byte-exact verification
- A toggle mechanism (CONFIG / static_key / sysctl) for the
  selftest

## Style audit applied (2026-05-27 evening)

Rewrote all three commit messages and the cover letter:

- Simplified English: short sentences, common words, active voice
- Favour bullets over prose
- Plain ASCII (no smart quotes, no em-dashes)
- Per-patch body around 25-35 lines (down from 45-55)
- Cover letter around 150 lines (down from 250+)
- Removed marketing phrases ("the largest single optimisation",
  "captures the win", etc.)
- Kept all technical content: dispatch shape, byte-exact rule,
  fall-through cost, prior art, design questions for reviewers

Style reference: looked at recent flow_dissector commits (Eric
Dumazet, Asbjørn Sloth Tønnesen, Ratheesh Kannoth, Pablo Neira)
to match kernel norms. Typical accepted commit message body is
3-15 lines; ours are larger because the framework patch
documents an architectural commitment.

## Compile-time gates (per patch)

| patch | W=1 build | checkpatch --strict |
|---:|---|---|
| 1 | clean | 0 errors, 0 warnings, 0 checks |
| 2 | clean | 0 errors, 0 warnings, 0 checks |
| 3 | clean | 0 errors, 0 warnings, 0 checks |

## Static analysis (whole series)

| tool | result |
|---|---|
| `scripts/checkpatch.pl --strict` | 0/0/0 per patch |
| `make W=1` (gcc warnings) | clean |
| `make coccicheck M=net/core/` | no findings introduced |
| `clang-tidy bugprone-* performance-* clang-analyzer-*` | only `easily-swappable-parameters` warnings, matching the existing `__skb_flow_dissect` API shape (kernel idiom) |
| sparse | (skipped: sparse 0.6.4 in nixpkgs does not understand `__typeof_unqual__` used by recent kernels; need master-branch sparse) |

The `xdp2` flake has clang-tidy, cppcheck, flawfinder, semgrep, etc.
under `.#analysis-*`, but those are wired to the xdp2 C codebase
and would need an adapter to run against kernel source. The
kernel-native tools above are the relevant ones.

## CC list when posting (from `scripts/get_maintainer.pl net/core/flow_dissector.c`)

```
To: netdev@vger.kernel.org

Cc: David S. Miller <davem@davemloft.net>
Cc: Eric Dumazet <edumazet@google.com>
Cc: Jakub Kicinski <kuba@kernel.org>
Cc: Paolo Abeni <pabeni@redhat.com>
Cc: Simon Horman <horms@kernel.org>
Cc: Qingfang Deng <qingfang.deng@linux.dev>
Cc: linux-kernel@vger.kernel.org
```

Probably ALSO add (interested parties from XDP2 work):

```
Cc: Tom Herbert <tom@quantonium.net>   # XDP2/PANDA lead, related prior art
```

Verify CC list with `scripts/get_maintainer.pl` again at posting
time in case maintainers change.

## Posting checklist when ready

1. Run `git send-email --to=netdev@vger.kernel.org --cc=... 0000-*.patch 0001-*.patch 0002-*.patch 0003-*.patch`.
2. Verify the message-id of the cover letter from the lore archive.
3. Update STATUS.md with the lore.kernel.org URL once posted.
4. Capture any reviewer feedback over the next 1-2 weeks.
5. Plan v2 in a new directory: `v2/`.

## Decision notes from drafting

**Combined TCP+UDP per address family** rather than separate
patches. The dispatching logic and key writes are identical
between TCP and UDP. Two patches that differ only in protocol
value would have nearly identical diffs.

**Byte-exact output** vs the "skip cold slot writes" alternative.
The plan doc considered both. Final decision: byte-exact, because:

- Saving from skipping is ~3 ns/pkt; small versus the ~30 ns/pkt
  fast-path win.
- Forward-compat risk if a future consumer reads a "cold" slot.
- The cover letter explicitly invites maintainer feedback on
  this choice. If reviewers prefer the skip-cold variant we can
  change in v2.

**Dissector-identity check** restricts the fast-path to
`flow_keys_dissector` and `flow_keys_dissector_symmetric`. Custom
dissectors (e.g. tc cls_flow with bespoke key sets) defer. The
cover letter invites feedback on whether a broader policy (any
dissector requesting a subset of what the fast-path writes) would
be better.

**Flow label deferral** in the IPv6 fast-path. The slow path
writes `key_tags->flow_label` when the dissector requests
FLOW_DISSECTOR_KEY_FLOW_LABEL AND the packet's label is non-zero.
The fast-path does not write key_tags->flow_label, so for
byte-exactness we defer when both conditions hold. The common
case (label == 0 on most internet traffic) takes the fast-path.

## Pending tests (before non-RFC submission)

Per `docs/kernel-flowdis-fastpath-test-plan.md`:

- Phase 1: deploy and boot patched kernel on hp1, hp2, hp3, hp5
- Phase 2: functional smoke (ping, brief iperf3, cake works)
- Phase 3: microbench (flow-dissector-matrix-unified on hp5 + hp3)
- Phase 4: macro short (16 cells: iperf3 + iperf2 × IPv4/IPv6 ×
  TCP/UDP × two pairs)
- Phase 5: 30-min sustained per pair (iperf3 round, iperf2 round)
- Phase 6: 24h soak (i40e pair iperf3, mlx5 pair iperf2 in parallel)
- Phase 7: analysis + cover-letter update with measured numbers

Phase 0 (kernel build on the four hosts) is in flight at the time
of writing.

## Next sessions

When picking this back up:

1. Confirm `/home/das/Downloads/net-next` branch
   `flowdis-fastpath-rfc` is still at HEAD `bd25b1631c7d`. If
   not, fetch from the previous session's state.
2. Confirm `kernel-patches/series3-flowdis-fastpath/v1/` matches
   that branch (regenerate via `git format-patch` if not).
3. Run the test plan. Iterate on any failures.
4. Once green, update cover letter with the measured numbers
   from Phases 3-6.
5. Send to netdev with the CC list above.
