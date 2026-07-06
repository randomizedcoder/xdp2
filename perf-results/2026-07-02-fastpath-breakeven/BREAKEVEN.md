# Fast-path break-even: when auto-enable pays off (from measured costs)

We can compute the exact traffic fraction at which enabling a per-shape fast-path
becomes a net win, because we measured **both** halves of the per-packet cost
model — not a heuristic guess:

- **S — per-match saving.** The straight-line fast body vs the generic parser, per
  shape per microarchitecture (`../2026-06-25-series3-allshapes-microbench/`).
- **C — hot-path miss cost.** The penalty a *non-matching* packet pays when a
  gate is on and it falls through to the slow path — measured directly
  (`../2026-06-10-series3-pi3-pcap-microbench/`): **+6.7 ns/pkt on in-order
  Cortex-A53**, ~0.2–0.9 ns on out-of-order x86/ARM. (When a gate is off it is a
  free NOP, so C is only paid while enabled.)

When a shape's gate is on, each packet either matches (fraction `p`, saves `S`)
or misses (`1-p`, costs `C`). Enabling is net-positive exactly when

```
        p·S > (1-p)·C     ⇔     p > C / (S + C)   ≡  p_be
```

So the break-even matching fraction `p_be` is a **derived, measured number** per
shape per uarch. (Use the exact `C/(S+C)`, not the `C/S` approximation — they
diverge when C approaches S, e.g. MPLS on in-order cores.)

## Break-even table  (`compute_breakeven.py` → enable a shape above its p_be)

```
uarch (C ns)         eth_ip    vlan    qinq   pppoe    mpls    ipip
-------------------------------------------------------------------
Zen2   (x86 OoO)  0.2     7.9%    3.1%    2.7%    6.0%   29.0%    2.6%
Skylake(x86 OoO)  0.2     6.2%    5.6%    6.4%    7.3%   27.8%    2.9%
Zen1   (x86 OoO)  0.2    22.2%    4.9%    4.8%   12.3%   22.2%    2.0%
A76    (ARM OoO)  0.6    12.1%    7.1%    4.4%   10.2%   32.4%    3.5%
A72    (ARM OoO)  0.6     6.3%    3.4%    2.3%    4.9%   21.7%    1.7%
A53  (ARM in-ord) 6.7    19.2%   11.2%    8.4%   17.8%   69.5%    7.8%
X60 (RV in-ord)   6.7    17.8%   12.9%   11.0%   18.4%   61.2%    8.0%
```

(X60's C was not separately measured — assumed A53-like, so its row is the
in-order estimate. Zen1 eth_ip S≈0.7 is at the microbench's noise floor, so its
22% is unreliable — but Zen1 still wins clearly on vlan/qinq/ipip.)

## What this means for auto-enablement

- **Mainstream byte-identical shapes (ipip, qinq, vlan, pppoe, eth_ip) break even
  low** — 2–12% on OoO cores, 8–19% on in-order. If more than ~1-in-5 of your
  packets are that shape, enabling wins. The controller's default hysteresis band
  (enable a margin above `p_be`, disable below) sits comfortably here.
- **MPLS is the high-bar shape** — 22–32% on OoO, **60–70% on in-order** (its
  saving is barely above the miss cost there). Auto should not enable MPLS unless
  it is a large majority of traffic; on constrained in-order hosts, leave it to
  manual. This is why the controller carries a per-shape MPLS override.
- **In-order cores raise every break-even** (C is ~10–30× larger), and the table
  captures that automatically — the same `p_be` formula yields the right, higher
  thresholds without a separate policy.

## Precision / residual

- The break-even is *derived from two measured costs*, so its location is known
  per shape/uarch — no controlled eligible-fraction sweep is needed to find it.
- Residual: C was measured mainly on early-bail misses (wrong ethertype). A
  *deep-bail* miss (right ethertype, wrong L4 — e.g. ICMP under eth_ip) may cost a
  little more, widening the band slightly. An optional kernel-level sweep at
  fixed eligible fractions would confirm the model end-to-end, but does not change
  where the threshold is.

Reproduce: `python3 compute_breakeven.py`.
