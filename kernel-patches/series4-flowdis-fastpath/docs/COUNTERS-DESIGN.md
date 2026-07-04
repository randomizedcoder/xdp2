# Per-shape counters — implementation design (resolved)

The observability counters that feed both operator visibility and the adaptive
controller. Mechanism only; they do not change dissection. This resolves the
placement subtleties so the patch can be written and verified directly.

## State

`enum flow_dissector_shape` (include/net/flow_dissector.h) — the **byte-identical
shapes only** (the ones the controller may auto-manage; descent is never
auto-managed so it is not counted here):

```
ETH_IP, VLAN, QINQ, PPPOE, MPLS, IPIP, GRE, __MAX
```

Per-cpu, summed on read (net/core/flow_dissector.c):

```c
struct flow_dissector_stats {
	u64 occurrences[FLOW_DISSECTOR_SHAPE__MAX]; /* handled by SLOW path */
	u64 fast_hits[FLOW_DISSECTOR_SHAPE__MAX];   /* fast body ran */
	u64 dissects;                               /* denominator */
};
static DEFINE_PER_CPU(struct flow_dissector_stats, flow_dissector_pcpu_stats);
```

`occurrences[]` is counted on the **slow** path, so — measured while a shape's
gate is off — it is the eligible-fraction signal for auto-enable. `fast_hits[]`
confirms the fast body is engaging (the auto-disable signal once enabled).

## Increment placement (resolved — the subtle part)

- **`dissects`** — one `this_cpu_inc` at the top of `__skb_flow_dissect()`, just
  before the `flow_dissect_fast()` call. *(done)*
- **`occurrences[ETH_IP]`** — at the top-level `ETH_P_IP`/`ETH_P_IPV6` slow case,
  **gated on being the first header** (capture the entry `nhoff` in a local; count
  only when this case's `nhoff` equals it). This correctly counts packets whose
  *outermost* header is eth+IP — including a tunnel's outer eth+IP+UDP, which the
  eth_ip fast path *does* handle — while excluding post-tag inner IP (those are
  VLAN/PPPoE/MPLS packets, counted under their own shape). Without the
  first-header gate, a `VLAN+IP` packet would be double-counted as both vlan and
  eth_ip.
- **`occurrences[VLAN]` / `[QINQ]`** — in the `ETH_P_8021Q/8021AD` slow case:
  first tag (`dissector_vlan == FLOW_DISSECTOR_KEY_MAX`) → VLAN; second tag → QINQ.
- **`occurrences[PPPOE]`** — in the `ETH_P_PPP_SES` case (place after its leading
  declaration block to avoid declaration-after-statement).
- **`occurrences[MPLS]`** — in the `ETH_P_MPLS_UC/MC` case (statement-first, clean).
- **`occurrences[IPIP]`** — in the `IPPROTO_IPIP` case (statement-first, clean).
- **`occurrences[GRE]`** — in the `IPPROTO_GRE` case (statement-first, clean).
- **`fast_hits[shape]`** — count at the fast-path terminal per shape. The
  dispatcher `flow_dissect_fast()` knows the top-level L2 shape
  (VLAN/ETH_IP/PPPOE/MPLS) on a `true` return → count there. Because the shared
  `flow_dissect_fast_ipv4/ipv6` helpers may descend, count `IPIP`/`GRE` fast_hits
  inside `flow_dissect_fast_ipip_inner`/`_gre_inner` on success, and count
  `QINQ` inside `flow_dissect_fast_vlan` when it consumes a second tag; the
  dispatcher's `ETH_IP` count is then plain eth_ip only (descents already counted
  under ipip/gre).

## Readout

`/proc/net/flow_dissector_stats` (seq_file registered in
`flow_dissector_sysctl_init`, `proc_create_net_single`). One line per shape:

```
shape        occurrences   fast_hits   eligible%   gate
eth_ip          12345678      9012345      74.1%     on
vlan             2345678       120000      14.1%     off
...
dissects: 16600000
```

`eligible% = 100 * (occurrences + fast_hits) / dissects` — what the controller
thresholds against the break-even table (`perf-results/2026-07-02-fastpath-breakeven/`).

## Cost / verification

- One `this_cpu_inc` per dissect on the already-hot classification path; per-cpu,
  summed on read — negligible, and confirmed to stay within the pktgen cyc/pkt
  noise floor.
- Validate composition on known pcaps (the classifier in
  `perf-results/2026-07-02-fastpath-breakeven/classify_shapes.py` shows the
  method; the kernel counters reproduce it): pump a known mix via pktgen, read
  `/proc/net/flow_dissector_stats`, confirm per-shape `eligible%` matches.

## Status

**Done.** The full patch — enum, per-cpu struct/helpers, `dissects`, all seven
`occurrences[]` increments, the `fast_hits[]` set (per the resolved placement
above), and the `/proc/net/flow_dissector_stats` seq_file — is implemented in
`net/core/flow_dissector.c` + `include/net/flow_dissector.h` and **compile-
verified against net-next** (`make net/core/flow_dissector.o`, objtool-clean;
the objtool/libelf build blocker was fixed by pointing `PKG_CONFIG_PATH` at
elfutils-0.194). It sits in the series as patch **08/11** (between the
byte-identical fast-paths and the RFC descent tail); the `.patch` files are
regenerated under `kernel-patches/series4-flowdis-fastpath/`.

`fast_hits[]` semantics note: each shape is counted only on the fast path's
*success* return (a fall-through to slow is counted there instead), so
`occurrences + fast_hits` is a gate-invariant per-shape total. eth_ip is counted
in the dispatcher gated on `!encap`, so ipip/gre descents count under their own
shape; the one documented interaction is that manually enabling an RFC overlay
descent (vxlan/geneve/gtpu) moves that outer packet out of the eth_ip count
(descent sets ENCAP) — descent shapes are manual/separate and not auto-managed.

Remaining (later tasks): userspace mirror counters for `test_parser` unit-testing
(Part 1 tail), the adaptive controller RFC (Part 2), and cover-letter/docs
integration (Part 3).
