# v1 vs v2-experiment: shape comparison

This directory holds a SINGLE-PATCH experiment for the same series 3
work. Same C semantics, same byte-exact contract, same measured
performance. Different SOURCE LAYOUT — everything inlined directly
into `__skb_flow_dissect()` rather than factored into three new
static helper functions.

## At a glance

| | v1 (current) | v2-experiment |
|---|---:|---:|
| patches | 3 | 1 |
| total +insertions | 206 | 151 |
| total -deletions | 2 | 0 |
| new functions | 3 (flow_dissect_fast, flow_dissect_fast_ipv4, flow_dissect_fast_ipv6) | 0 |
| static_asserts | 2 | 2 |
| W=1 compile clean | yes | yes |
| checkpatch --strict | 0/0/0 | 0/0/0 |
| disassembly bytes | (gcc inlines static funcs from one call site, so identical) | (no inlining required; bytes already inline) |
| measured Zen 2 -47 % | yes | yes (same code emitted) |

## What v1 looks like (control)

Series of 3 commits in net-next branch `flowdis-fastpath-rfc`:

  1ddc620812be net: flow_dissector: add fast-path entry-point skeleton
                +57 lines — adds the dispatcher + IPv4/IPv6 stubs
  080196491134 net: flow_dissector: add eth+IPv4+{TCP,UDP} fast-path
                +73/-1 lines — plugs the IPv4 stub body
  eeca3eb493b8 net: flow_dissector: add eth+IPv6+{TCP,UDP} fast-path
                +78/-1 lines — plugs the IPv6 stub body

`__skb_flow_dissect()` itself grows by 7 lines (the call site). The
heavy lifting lives in three new static helpers above the function.

## What v2-experiment looks like

A single commit in net-next branch `flowdis-fastpath-rfc-v2-inline`:

  net: flow_dissector: add fast-path for eth + IPv{4,6} + {TCP,UDP}
                +151 lines, all in one commit

`__skb_flow_dissect()` grows by ~135 lines (the entire fast-path
block inline, plus the forward declaration of
`flow_keys_dissector_symmetric` and the two static_asserts at
file scope).

No new functions. Bail-outs use `goto slow_path;` to a label just
above the existing slow-path entry — same idiom the existing
function already uses for `goto out_good;` / `goto out_bad;`.

## Pros of v2 (single patch)

- **Smaller diff**: 151 vs 206 lines added.
- **One commit to review**: reviewer sees the whole change at once,
  doesn't have to track 3 commits and the call site they wire
  together.
- **No function-call overhead concern at all**: the code is
  literally inline. Same machine code as v1 (because gcc inlines
  v1's static helpers from a single call site), but in v2 it's
  source-level inline too.
- **Easier to see the byte-exact contract**: the fast-path writes
  sit in the same function as the slow-path writes, side-by-side.
  Reviewer can scan both to confirm they match.

## Pros of v1 (3 patches)

- **__skb_flow_dissect() stays focused**: the slow-path graph
  walk reads cleanly without 135 lines of fast-path code
  occupying the function's lexical scope.
- **Easier bisection**: each patch is one logical change.
  Catches regressions caused by IPv4 vs IPv6 vs framework
  independently.
- **Maintainable extension**: adding patch 4 (VLAN), patch 5
  (PPPoE), etc. for v2 of the series is mechanically clean —
  one more static helper, one more arm in the dispatcher. v2
  would require ever-deeper inlining into __skb_flow_dissect.
- **Reviewer can accept a subset**: if maintainers like the
  framework + IPv4 but not IPv6 yet, v1 can land 1+2 and hold
  3. v2 is all-or-nothing.
- **Each patch independently testable**: v1 patch 1 (framework
  only, all stubs return false) is verifiable on its own as
  a no-op. v2 is one big change.

## My recommendation

Keep v1 as the structure for the netdev submission. Reasons in
order of weight:

1. **Convention**: net-next maintainers expect one-logical-change-
   per-patch. The framework patch + per-shape patches structure is
   the conventional split.
2. **Bisectability**: if a future change breaks something, `git
   bisect` lands on a specific shape (v4 vs v6) rather than the
   whole fast-path.
3. **Future shapes**: VLAN, PPPoE, encap variants will each be a
   patch in v2 of the series. v1's structure scales; v2's
   inlining doesn't.
4. **Reviewer accept-subset flexibility**: maintainers can accept
   the framework + one shape and ask for the rest separately.

That said — **the v2 experiment IS useful as a reading aid for the
reviewer**, because seeing the whole thing inline makes the
byte-exact contract self-evident. Could include it as a link in
the cover letter ("if you find the 3-patch split harder to read,
the equivalent single-patch view is at the v2-experiment branch
on the same xdp2 repo"). Reviewer reads whichever they prefer.

## Files

- `0001-net-flow_dissector-add-fast-path-for-eth-IPv-4-6-TCP.patch`
  — the v2-experiment single patch
- `COMPARISON.md` (this file)

The v2 experiment is on net-next branch
`flowdis-fastpath-rfc-v2-inline` (HEAD around commit
`1cb8ab442809`). The v1 patches remain canonical on
`flowdis-fastpath-rfc` (HEAD `eeca3eb493b8`).
