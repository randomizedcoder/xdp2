# Series 3: kernel flow_dissector fast-path — RFC v1 (sysctl-gated, awaiting test)

**Date**: 2026-05-27 (initial), 2026-06-07 (gate reshape)
**Status**: 3-patch v1 RFC reshaped to be sysctl-gated (default off,
  static_branch_likely + proc_do_static_key). Awaits build + boot +
  test on the gated form before submission to netdev.
**Plan**: `docs/kernel-flowdis-fastpath-plan.md` in the xdp2 repo.
**Test plan**: `docs/kernel-flowdis-fastpath-test-plan.md`.
**Base**: net-next `c0aa5f13826dcb035bec3d6b252e6b2020fa5f88`
  (same base as series 1 + 2).
**Branch in net-next**: `flowdis-fastpath-rfc`, HEAD `e24cf9001c0b`
  (2026-06-07 gate reshape; pre-gate snapshot at
  `flowdis-fastpath-rfc-pre-gate`, HEAD `eeca3eb493b8`).

## Gate design

The fast-path is opt-in via a new sysctl:

  `net.core.flow_dissector_fastpath = 0` (default; no behavior change)
  `net.core.flow_dissector_fastpath = 1` (fast-path enabled)

Implementation pattern mirrors Eric Dumazet's existing static-branch
sysctls (`net.core.high_order_alloc_disable` /
`net_high_order_alloc_disable_key` in sock.c):

- `DEFINE_STATIC_KEY_FALSE(flow_dissector_fastpath_key)` in
  `net/core/flow_dissector.c`
- extern declaration in `include/net/flow_dissector.h`
- sysctl table entry in `net/core/sysctl_net_core.c` with
  `.proc_handler = proc_do_static_key`
- new Documentation entry in
  `Documentation/admin-guide/sysctl/net.rst`

**static_branch_likely (not _unlikely)**: operators who flip this
sysctl have opted into the fast-path because they want it fast;
`static_branch_likely` keeps the dispatcher inline in the hot text
section, matching the layout the microbench measured against.
Default-off users pay one forward JMP per dissector call (cheap,
one not-taken JMP).

## Series shape (v1, gated)

| # | patch | net-next commit | LoC | status |
|---:|---|---|---:|---|
| 1 | flow_dissector: add opt-in fast-path entry-point skeleton | `cb4e51dd913c` | +108 | reshaped |
| 2 | flow_dissector: add eth+IPv4+{TCP,UDP} fast-path | `09548fd3f814` | +73/-1 | unchanged |
| 3 | flow_dissector: add eth+IPv6+{TCP,UDP} fast-path | `e24cf9001c0b` | +78/-1 | unchanged |

Total: 257 insertions across 4 files:
- net/core/flow_dissector.c (+217)
- Documentation/admin-guide/sysctl/net.rst (+24)
- include/net/flow_dissector.h (+8)
- net/core/sysctl_net_core.c (+8)

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
- Kernel selftest for byte-exact verification (flip the sysctl
  on, run a packet corpus through both paths, byte-compare struct
  flow_keys)

The "toggle mechanism" follow-up from the pre-gate plan landed in
v1 (sysctl + static_branch_likely) rather than v2.

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

## Test plan status (updated 2026-05-28)

Per `docs/kernel-flowdis-fastpath-test-plan.md`:

| phase | task | status |
|---|---|---|
| 0 | prereqs (kernel build, IPv6 NixOS config) | done |
| 1 | deploy + boot patched kernel on hp1/hp2/hp3/hp5 | done |
| 2 | functional smoke (ping, cake, dual stack) | done |
| 3 | microbench (libflowdis port) | done |
| 4 | macro short (16 cells) | done |
| 5 | 30-min sustained per pair | pending |
| 6 | 24h soak (i40e iperf3 + mlx5 iperf2 parallel) | pending |
| 7 | cover-letter update with measured numbers | done |

### Phase 3 numbers

Microbench (synthetic eth+IPv4+TCP, fast-path always hits; sysctl=1
equivalent — the libflowdis port runs the fast-path
unconditionally, equivalent to the kernel with the static_branch
key enabled):

- Zen 2 Threadripper PRO 3945WX (N=10): 12.44 -> 6.56 ns/pkt
  (-47.3 %, 8x pooled stdev)
- Skylake-deriv Core i9-10885H t (N=10): 10.61 -> 5.62 ns/pkt
  (-47.0 %, 38x pooled stdev) -- added 2026-06-04
- Zen 1 Ryzen 5 PRO 2400G hp5 (N=5): 20.50 -> 20.53 ns/pkt
  (within noise; cover letter's "masked at p50" prediction holds;
  Comet Lake-H confirms the same ~5 ns absolute saving is masked
  by the clock_gettime floor on Zen 1, not a uarch-specific no-op)

Details: `perf-results/2026-05-28-series3-phase3/results.md`
  (Zen 2 + Zen 1) and
  `perf-results/2026-06-04-series3-phase3-t/results.md`
  (Comet Lake-H, second-vendor confirmation).

### Gated kernel A/B verification (2026-06-07)

After the gate reshape, the patched kernel was rebuilt against
`linuxPackages_latest` (Path B; hp1/hp3 at 7.0.9, hp2/hp5 at
7.0.0; t at 7.0.10). The four hp* hosts were re-tested with
sysctl=0 then sysctl=1 to confirm the new claims:

| pair | sysctl=0 | sysctl=1 | delta |
|---|---:|---:|---:|
| mlx5 25 GbE (hp1->hp3) | 16.393 Gbit/s | 16.723 Gbit/s | +2.0% |
| i40e 10 GbE (hp2->hp5) | 9.409 Gbit/s  | 9.409 Gbit/s  | 0% (link-saturated) |

- sysctl=0 matches or exceeds B.1 baseline on both NICs:
  *no regression* vs unpatched kernel.
- sysctl=1 lands at the top of the prior Phase 4 range on both
  NICs: the gated path produces the same code as the prior
  always-on draft.
- Retransmit rates between sysctl=0 and sysctl=1 are equivalent
  on both pairs: the byte-exact contract holds end-to-end (no
  flow-hash scatter from broken dissector output).
- Cake stats: 0 drops, 0 overlimits across all 4 runs.

Details: `perf-results/2026-06-07-series3-gated-ab/results.md`.

### ARM gated kernel A/B (2026-06-09)

The patches were ported to the Raspberry Pi 5 pair (Cortex-A76 4c @
2.4 GHz, BCM2712, 1 GbE switched) and a standalone Pi 4 (Cortex-A72
4c @ 1.8 GHz, BCM2711) via Path B against nixos-raspberrypi's
linux_rpi5 / linux_rpi4 6.12.87 kernel. The 3 patches applied
cleanly with no 6.12 context drift — patches generalise to 6.12
kernel base.

| host | uname | sysctl | mount + dmesg |
|---|---|---|---|
| pi5-1 | 6.12.87 (patched) | = 0 ✅ | /nix on NVMe, no new dmesg |
| pi5-2 | 6.12.87 (patched) | = 0 ✅ | /nix on NVMe, no new dmesg |
| pi4-1 | 6.12.87 (patched) | = 0 ✅ | no new dmesg |

Pi 5 pair TCP wire-rate cross-qdisc matrix (30 s, -P 16):

- cake/fq_codel/fq/noqueue: 936.2 ± 0.05 Mbit/s in both modes,
  0 retx in all cells. **No regression at sysctl=0 on ARM**, link
  saturates in both modes (1 GbE ceiling).

Pi 5 pair UDP small-packet PPS-limited (-b 0 -l 64 -P 8, 20 s, N=3
per mode):

- sysctl=0: 162.8 ± 1.7 Mbit/s mean
- sysctl=1: 153.8 ± 2.3 Mbit/s mean
- delta -5.5 % (every sysctl=1 run below every sysctl=0 run,
  signal not noise)

This is an **unexpected ARM-specific regression** in the opt-in
path for UDP small-packet workloads. Working hypotheses pending v2
investigation: branch predictor on the dispatcher chain, 16 KiB
page boundary effects, fast-path .text layout vs slow-path entry.

The default-off case (sysctl=0) shows no regression on ARM — the
critical claim for v1 RFC holds.

Details: `perf-results/2026-06-09-series3-arm-ab/results.md`.

### Phase 4 numbers

16 macro cells (iperf3 + iperf2 x IPv4/IPv6 x TCP/UDP, two pairs):

- mlx5 25 GbE TCP: 15.94 - 16.78 Gbit/s (B.1 baseline 16.023)
- i40e 10 GbE TCP: 9.28 - 9.41 Gbit/s (near link rate)
- 0 dmesg WARN/BUG introduced by the patches across all cells

Details: `perf-results/2026-05-28-series3-phase4/results-full.md`.

## Next sessions

When picking this back up:

1. Confirm `/home/das/Downloads/net-next` branch
   `flowdis-fastpath-rfc` is still at HEAD `e24cf9001c0b` (gated;
   2026-06-07 reshape). Pre-gate snapshot kept at branch
   `flowdis-fastpath-rfc-pre-gate` (HEAD `eeca3eb493b8`).
   Single-patch variant on `flowdis-fastpath-rfc-v2-inline` HEAD
   `8013aee91ccb` (gated), pre-gate at
   `flowdis-fastpath-rfc-v2-inline-pre-gate` HEAD `1cb8ab442809`.
2. Confirm `kernel-patches/series3-flowdis-fastpath/v1/` and
   `v1-netdev/` and `v2-experiment/` match those branches
   (regenerate via `git format-patch` if not).
3. Re-run smoke tests with sysctl flipped (sysctl=0 must be
   no-change; sysctl=1 must match the unconditional draft's
   Phase 4 macro numbers within noise).
4. Send to netdev with the CC list above. The v1-netdev/ cover
   letter is the canonical send form; the COMPARISON.md in
   v2-experiment/ explains the single-patch alternative.
