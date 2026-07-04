# Adaptive fast-path enablement — design (packet-window controller)

Builds on the per-shape counters (patch 08/11). Mechanism there; **policy** here.
Goal: let the kernel enable/disable the byte-identical fast-path gates on its own
as traffic composition changes, so operators don't hand-tune ten knobs — and make
*how fast it adapts* a single, intuitive knob.

## Core idea: decide every N packets, not every N milliseconds

Adaptation is driven by a **packet-count window**, not a wall-clock tick. Every
`auto_window_packets` dissects, the controller re-evaluates each shape and flips
its gate if warranted. This is traffic-proportional: a busy link adapts in
milliseconds, an idle link doesn't churn. (Prior art: `lib/dim/` — Dynamic
Interrupt Moderation — samples traffic epochs and damps transitions; same shape.)

The signal is already produced by the counters patch: `dissects` (denominator),
and per shape `occurrences` (slow) + `fast_hits` (fast). Per shape the
gate-invariant eligible fraction is `(occurrences + fast_hits) / dissects`.

## Two correctness requirements

**1. Window deltas, not cumulative.** Threshold the eligible fraction over the
**last window only** — snapshot the counters at each decision and diff. Cumulative
(since-boot) ratios asymptotically freeze and the controller stops adapting after
uptime grows. Deltas are what make "pattern changed → gate flips."

```
Δdissects   = dissects        - dissects_prev
Δtotal[s]   = (occ[s]+fast[s]) - total_prev[s]
frac[s]     = Δtotal[s] / Δdissects        (this window's eligible fraction)
```

**2. Sample on the hot path, flip in process context.** `static_branch_enable()`
→ `text_poke()` takes a mutex and can sleep — illegal from `__skb_flow_dissect`
(softirq/RCU). Split:

- **hot path:** the existing per-cpu `dissects` inc, plus a branch-predictable
  check "did this cpu's local dissects cross `auto_window_packets / num_online_cpus`?"
  → if so `schedule_work(&flow_dissector_auto_work)`. No new locks, no atomics on
  the common path.
- **worker (process context):** sum the per-cpu counters, compute the window
  deltas above, run the policy core, apply `static_branch_enable/disable`.

(The per-cpu-local threshold makes the trigger approximate — a window is ~N
packets, not exactly N — which is fine; the window is a smoothing parameter, not
a deadline.)

## Policy core (identical in-kernel and in the userspace agent)

For each **byte-identical** shape `s` (eth_ip, vlan, qinq, pppoe, mpls, ipip, gre):

```
p_be[s]  = C[s] / (S[s] + C[s])        # measured break-even for this uarch class
                                       # (perf-results/2026-07-02-fastpath-breakeven)
enable  when frac[s] > p_be[s] + MARGIN_HI  for DWELL consecutive windows
disable when frac[s] < p_be[s] - MARGIN_LO  for DWELL consecutive windows
```

- **Hysteresis** (`MARGIN_HI` > `MARGIN_LO` band around `p_be`) prevents flapping
  at the threshold.
- **Dwell** (`DWELL` consecutive windows, default ~3) prevents a single anomalous
  window from flipping a gate.
- **Flip rate cap** — a global minimum interval between flips (across all shapes)
  bounds `text_poke` cost and defeats crafted rare-shape bursts trying to force
  patch storms.
- **Per-shape overrides:** never auto-enable `mpls` on in-order cores (S < C, no
  break-even). **Descent shapes (vxlan/geneve/gtpu) are never auto-managed** —
  they change hashing behaviour, so enabling them must stay a deliberate operator
  action.
- **vlan/qinq coupling** respected (reuse the existing sibling enable logic).

Because `p_be` is larger on in-order cores (C is ~10-30x larger there), the same
formula yields correctly higher thresholds without a separate policy — the table
carries the uarch difference.

## Knobs

| sysctl | meaning | default |
|---|---|---|
| `net.flow_dissector.auto` | mode: 0 off (manual per-shape knobs apply) / 1 on | 0 |
| `net.flow_dissector.auto_window_packets` | decision window (adaptation speed) | 1000000 |

Larger window = smoother/slower adaptation; smaller = faster/twitchier. `DWELL`,
the hysteresis margins, and the flip-rate cap are compile-time constants derived
conservatively from the break-even table (not exposed as knobs — they are policy
the operator shouldn't have to reason about). The break-even table itself is the
per-uarch threshold basis.

## Two policy homes (RFC presents both; list decides)

- **Home A — userspace reference agent.** *(implemented)* Kernel stays
  mechanism-only (counters + the manual sysctls). The agent samples
  `/proc/net/flow_dissector_stats`, runs the identical policy core, writes the
  per-shape sysctls. Tunable without kernel review; "mechanism not policy."
  Shipped as `xdp2-rs/crates/xdp2-fastpath-control/src/flowdis_auto.rs` (pure
  `Policy::decide` core + parser + sysctl writer, 8 unit tests) with a runnable
  `examples/flowdis-auto-agent.rs` poll/decide/apply loop.
- **Home B — in-kernel `auto` knob.** *(implemented, RFC patch)* The
  packet-window worker above lives in `net/core/flow_dissector.c`
  (`net.flow_dissector.auto` + `auto_window_packets`). Ten knobs collapse to one;
  no userspace dependency. Cost: the adaptive loop lives in the kernel (the
  maintainer tradeoff). Compile-verified (objtool-clean).

Both homes use **byte-for-byte the same** policy constants (break-even table,
`DWELL=3`, `+10pp`/`-5pp` margins, ≥1s flip cap, mpls/descent exclusions), so
they make the same decision on the same input.

The counters (patch 08/11) are the common, uncontroversial foundation for either.

## Per-netns

v1 is global (`init_net`), matching the current global gates and the global
counters. Per-netns counters + per-netns `auto` is a noted follow-up (ties to the
existing open per-netns-gate question).

## Validation

- **Policy core unit tests** (mirror `reconciler.rs`): feed a `frac[]` time series
  that crosses `p_be ± margin`, assert flips happen only after `DWELL` windows and
  respect the rate cap; assert `mpls`/descent are never auto-flipped.
- **Window-delta correctness:** confirm cumulative counters do not freeze the
  decision — a long steady run followed by a composition change still flips.
- **Hot-path cost:** the per-cpu threshold check adds a compare+branch to the
  already-hot path; confirm within the pktgen cyc/pkt noise floor.
