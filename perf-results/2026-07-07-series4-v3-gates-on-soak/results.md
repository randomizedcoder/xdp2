# series4 v3 all-gates-on soak — hp2 → hp5, 2026-07-07

**PASS: 78 rounds / 2 h, 4,184,496,105 dissects, 2,105,572,919 eth_ip
fast-path hits, 0 kernel warnings.**

First-ever soak with the fast path actually engaged on the standard receive
path — run on the flag-fixed v3 kernel (`series4-rfc-tail-v3` @ 86974579,
which admits `FLOW_DISSECTOR_F_STOP_AT_FLOW_LABEL` from `skb_get_hash()`).
Every prior in-kernel run had an inert fast path (see STATUS.md "THE flag
bug").

## Setup
- DUT hp5 (Zen 1, X710 10 GbE, `enp1s0f0np0`, rxhash off so RPS dissects in
  software), generator hp2, back-to-back DAC.
- All 12 shape/descent gates on (`auto` off); consumers: RPS (all CPUs),
  RFS (32768/2048), cake 9Gbit triple-isolate, flower ingress filter.
- Traffic per ~95 s round: iperf3 TCP ×4 (plain) + TCP over a real VXLAN
  overlay + UDP 500M over a real Geneve overlay (kernel encap on the
  generator, wire-real tunnel frames at the DUT), then 3×10 s UDP 1G blasts.
- Watchdogs each round: dmesg severity scan (flow/dissect/BUG/WARNING/stack),
  dissects + fast_hits monotonicity. All 78 rounds clean.

## Mid-soak BPF precedence test (also PASS)
`bpf_flow.bpf.o` (the in-tree selftests program) attached via a minimal
libbpf loader on the DUT while the soak flowed:
- attached: `dissects` froze for 10 s (463,303,607 → 463,303,607) — every
  dissect fully handled by the BPF program before the fast path or counters,
  exactly the cover letter's precedence claim;
- detached: dissects and fast_hits resumed immediately.
Also exercised patch 1's netns-BPF static key attach/detach under live 10G
traffic.

## Notes
- Final counters: eth_ip occurrences 1,614,092 (all pre-soak gate-off
  smoke) vs fast_hits 2.1B — with the gate on, eligible plain traffic went
  100% fast path. Tunnel-descent dissects count only in the denominator
  (per-shape counting deliberately excludes descents).
- Artifacts: soak.log (per-round), stats-start/end.txt, dmesg-end.txt.
- This is a robustness soak, not an A/B: the Phase F/G perf re-measurement
  on the fixed kernel is still pending (required before send — the old
  in-kernel numbers were taken with the fast path inert).
