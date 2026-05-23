# Series 1 — flow_hash_from_keys_small() + docs + sch_cake user

**Target tree**: `net-next`
  (`git://git.kernel.org/pub/scm/linux/kernel/git/netdev/net-next.git`)

**Plan doc**: `../../docs/kernel-patches-plan.md`
**Analysis backing**:
  `../../perf-results/2026-05-23-flow-keys-consumer-audit/`

## What this is

A 3-patch series for upstream Linux kernel networking,
derived from the Phase 1-5 analysis on the
`flow-keys-compat-reorder` branch of XDP2:

1. **Documentation/networking: document flow_keys consumer
   touch matrix** — new doc file, ~150 LoC RST.
2. **net: flow_dissector: add `flow_hash_from_keys_small()`
   5-tuple helper** — new kernel function, ~80 LoC.
3. **net: sched: sch_cake: use `flow_hash_from_keys_small()`
   for host accounting** — switch sch_cake's two host_keys
   hashes to the new variant, ~20 LoC change.

## Why this exists in the XDP2 repo

XDP2's `kernel-patches/` directory **preserves the generated
`*.patch` files** as artifacts of work done in the
net-next clone. The patches themselves are developed in
the net-next tree (`/home/das/Downloads/net-next/`), not
here. The files in `v1/`, `v2/` etc. are
`git format-patch` outputs, kept for:

- Historical record across review iterations
- Cross-referencing from XDP2 docs without needing to
  re-checkout the net-next branch
- Sharing with collaborators who don't have the
  net-next branch handy

## Workflow

```bash
# Develop in the net-next clone:
cd /home/das/Downloads/net-next
git checkout -b flow-hash-small-rfc origin/main
# ... make commits ...

# Generate patches:
git format-patch -3 --cover-letter --base=origin/main \
    -o /tmp/series1-v1/

# Edit the cover letter to summarise the series.

# Preserve in this repo:
cp /tmp/series1-v1/*.patch \
   ~/Downloads/xdp2/kernel-patches/series1-flow-hash-small/v1/

# Send for review (DO NOT run until pre-post checklist passes):
cd /home/das/Downloads/net-next
git send-email --to=netdev@vger.kernel.org \
    --cc='<see plan doc per-patch CC list>' \
    /tmp/series1-v1/*.patch
```

## Status

- [ ] v1 patches not yet written. This README is the
  scaffolding; the `v1/` directory will be populated
  after development in net-next.

## Pre-post checklist (gates `git send-email`)

Per `../../docs/kernel-patches-plan.md`:

- [ ] hp5 (Zen 1) re-validation of Phase 3 cycle numbers
- [ ] Real-traffic chi-squared on a pcap-derived flow set
- [ ] sch_cake selftest run (check
      `tools/testing/selftests/net/forwarding/` in net-next
      for an existing cake test)
- [ ] Patch 2 v6-addr handling design decision resolved
- [ ] Patch 2 function name finalized
      (`flow_hash_from_keys_small()` vs alternatives)
- [ ] Tom Herbert courtesy alignment

## Revisions

- `v1/` — initial RFC, not yet posted
- (future: `v2/`, `v3/` based on review feedback)
