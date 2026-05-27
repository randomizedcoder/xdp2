# Series 3: kernel flow_dissector fast-path — RFC v1 (in flight)

**Date**: 2026-05-27
**Status**: Patch 1 of 5-6 drafted; awaiting patch-1 architectural-gate
  smoke test on hp5 before writing patches 2-5.
**Plan**: see `docs/kernel-flowdis-fastpath-plan.md` in the xdp2 repo.
**Base**: net-next commit `c0aa5f13826dcb035bec3d6b252e6b2020fa5f88`
  (same base as series 1 + 2).
**Branch in net-next**: `flowdis-fastpath-rfc`.

## Series goal (recap)

Backport XDP2's R3.4 fast-path technique into the in-tree
`__skb_flow_dissect()`. The technique alone captures ~95% of XDP2's
flat-workload speedup and is portable straight-line C — no codegen,
no new tooling, no new ABI.

Expected on-the-wire result: 117 -> ~85-90 ns/pkt on https-web
(~25-30% faster vs vanilla).

## Patch series shape

| # | patch | status |
|---:|---|---|
| 1 | flow_dissector: add fast-path entry-point skeleton | **drafted** |
| 2 | flow_dissector: add eth+IPv4+TCP fast-path | pending patch-1 smoke |
| 3 | flow_dissector: add eth+IPv4+UDP fast-path | pending |
| 4 | flow_dissector: add eth+IPv6+TCP fast-path | pending |
| 5 | flow_dissector: add eth+IPv6+UDP fast-path | pending |
| 6 | (optional) flow_dissector: add VLAN dispatch + variants | TBD |

## Patch 1 — drafted state

- `0001-net-flow_dissector-add-fast-path-entry-point-skelet.patch`
  - 96 insertions, 0 deletions
  - checkpatch.pl --strict: 0 errors, 0 warnings, 0 checks
  - Compiles clean at W=1
  - Forward-declares `flow_keys_dissector_symmetric` near the new
    code (it's defined later in the same file)
  - Adds `flow_dissect_fast()` dispatcher with:
    - dissector-identity check (only the two standard dissectors)
    - flag-rejection (only accepts the empty flag set or
      `FLOW_DISSECTOR_F_PARSE_1ST_FRAG`)
    - ethertype switch (IPv4 / IPv6 / default)
  - Adds `flow_dissect_fast_ipv4()` and `flow_dissect_fast_ipv6()`
    stubs (both return false)
  - Adds the call site in `__skb_flow_dissect()` after the BPF
    override block (`rcu_read_unlock()`) and before the slow-path
    `FLOW_DISSECTOR_KEY_ETH_ADDRS` write
  - No behaviour change: all stubs return false, every packet
    still reaches the slow path

## Next step

Per the hybrid testing cadence in `docs/kernel-flowdis-fastpath-plan.md`,
patch 1 is the architectural commitment and gets independent
validation before patches 2-5 are written:

1. Build patched kernel via NixOS flake (same pattern as
   `kernel-patches/test-kernel/`, but pointing at the new branch
   `flowdis-fastpath-rfc`).
2. Boot on hp5.
3. Verify the dispatch site behaves correctly (every packet still
   reaches slow path; flow_keys output is unchanged).
4. Measure fall-through cost on a flat workload via the matrix
   benchmark (`nix run .#flow-dissector-matrix-unified`).
   - Expected: ≤2 ns/pkt added vs vanilla baseline (one ethertype
     switch in the fast-path framework).
   - If higher: investigate; framework design issue.
5. Confirm no kernel WARN/BUG in dmesg.

If patch 1 validates, proceed to patches 2-5 in a batched workflow.
If patch 1 reveals a design issue, fix in place before continuing.

## Notes for future-me

- Branch `flowdis-fastpath-rfc` in `/home/das/Downloads/net-next/` is
  the working tree.
- HEAD on that branch is patch 1; rebase on net-next when starting
  patch 2.
- Don't rename the patch file; the kernel-patch convention is
  one `.patch` per commit, exported via `git format-patch`.
