# Series 3: kernel flow_dissector fast-path — RFC v1 (draft, awaiting test)

**Date**: 2026-05-27
**Status**: 3-patch v1 RFC drafted with simplified English + bullet
  style. Awaits build + boot + test before submission to netdev.
**Plan**: `docs/kernel-flowdis-fastpath-plan.md` in the xdp2 repo.
**Test plan**: `docs/kernel-flowdis-fastpath-test-plan.md`.
**Base**: net-next `c0aa5f13826dcb035bec3d6b252e6b2020fa5f88`
  (same base as series 1 + 2).
**Branch in net-next**: `flowdis-fastpath-rfc`, HEAD `eeca3eb493b8`.

## Series shape (v1)

| # | patch | net-next commit | LoC | status |
|---:|---|---|---:|---|
| 1 | flow_dissector: add fast-path entry-point skeleton | `1ddc620812be` | 57 | drafted |
| 2 | flow_dissector: add eth+IPv4+{TCP,UDP} fast-path | `080196491134` | 73 | drafted |
| 3 | flow_dissector: add eth+IPv6+{TCP,UDP} fast-path | `eeca3eb493b8` | 78 | drafted |

Total: 207 LoC, all in net/core/flow_dissector.c.

LoC trajectory:
- First draft: 276 lines (with verbose comments)
- After comment pruning: 195 lines
- After C11 modernization (+static_assert, +unlikely): 207 lines

Kept comments only on:
- The dispatcher's contract (3-line block above `flow_dissect_fast`)
- The IPv4 0x45 magic (version + IHL packed in one byte)
- The IPv6 flow-label deferral logic (non-obvious why we defer)
- The static_assert blocks (explain the compile-time invariant)

## C11 idioms used (kernel uses -std=gnu11 since 5.18)

- `static_assert(sizeof(struct iphdr) == 20)` — patch 2. Holds the
  compile-time invariant the fast-path depends on. If struct iphdr
  ever grew (unlikely, ABI-affecting), build would fail with a clear
  message instead of silent misbehaviour.
- `static_assert(sizeof(struct ipv6hdr) == 40)` — patch 3.
- `unlikely(...)` hints on the bail-out branches. Tells the branch
  predictor that fast-path bail-outs (length too short, wrong
  version, unsupported protocol, etc.) are the cold path. Saves
  a small amount on the hit-path code layout.

Reference: `Documentation/process/programming-language.rst` documents
the kernel C standard:

  "the kernel is typically compiled with gcc under -std=gnu11: the
   GNU dialect of ISO C11"

C11 was adopted by the kernel in commit e8c07082a810 (May 2022,
5.18-rc1).

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
| `sparse` (master, post 0.6.4) | clean — no findings in flow_dissector.c |
| `smatch` (Dan Carpenter, 1.74) | clean — no findings in flow_dissector.c |

### Running these locally

Three new flake outputs (added to xdp2's `flake.nix`, see
`nix/kernel-static-analysis.nix`):

```bash
# Build sparse from upstream master (nixpkgs 0.6.4 is too old)
nix build .#sparse-master

# Wrap smatch with same UX
nix build .#kernel-smatch

# Run both against a kernel tree's .o target
nix run .#kernel-check -- /home/das/Downloads/net-next \
                          net/core/flow_dissector.o
```

The wrapper takes a kernel source tree path and a target .o; runs
sparse-master and smatch as `CHECK=`, filters results to only
findings in the source file (drops included-header noise), prints
"(clean)" when no findings.

The `xdp2` flake's `.#analysis-*` tools (clang-tidy, cppcheck,
flawfinder, semgrep, sanitizers) target xdp2's own C codebase, not
kernel source. The `sparse-master` + `kernel-smatch` + `kernel-check`
outputs are the kernel-source equivalents.

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
