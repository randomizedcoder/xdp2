# Local perf snapshot — 2026-05-18, post-VXLAN-fix series

Measured on the dev workstation (NOT hp5), so absolutes will differ
on the testbed. The relative deltas are the meaningful signal.

This snapshot captures perf after the following commits in
`merge/matrix-physical-testbed`:
- `3ad4ac4` mono npi_simple bswap fix
- `a063bfc` VXLAN proto convention + UDP fast-path drop
- `eebe021` icmp_id sentinel alignment
- `2e52423` rust-bench dump-meta-only filter bypass
- `f0faceb` per-(pcap, parser) tunnel_behavior overrides

## Numbers (`benchmark -p -n 100000`)

| pcap | flowdis | xdp2-opt | xdp2-mono | mono Mpps | mono vs flowdis |
|---|---:|---:|---:|---:|---:|
| tcp_ipv4 | 20 ns | 15 ns | **5 ns** | 200 | 4.0× |
| tcp_ipv6 | 20 ns | 14 ns | **6 ns** | 166 | 3.3× |
| vxlan    | 19 ns | 21 ns | **16 ns** | 62 | 1.2× |

## What moved vs the pre-fix state

- **tcp_ipv4/tcp_ipv6**: unchanged. The TCP fast-path was kept in
  mono; only UDP was dropped. Headline perf on TCP-dominant
  workloads (https-web, etc.) should be unchanged from R3.4.5a's
  baseline.
- **vxlan**: mono now walks the full stack (post-fix-correctness)
  instead of short-circuiting at outer UDP via the old fast-path.
  The 16 ns/pkt is the cost of that walk; before the fix mono
  would have been ~5-6 ns/pkt at outer UDP but produced INCORRECT
  outer-only metadata. The 10 ns regression buys correctness on
  the entire VXLAN/Geneve/GTP-U/MPLS-UDP tunnel family.
- **Mono still beats opt on vxlan** (16 vs 21 ns) — the codegen
  win persists even on the full slow-path walk.

## Headline

**c-xdp2-mono on tcp_ipv4 is 4× faster than kernel flowdis** on
this workstation (5 ns vs 20 ns). The R3.4 fast-path series
landed in a state where:
- 5-tuple-dominant workloads get sub-graph-walk perf via
  the TCP/ICMP fast-paths
- Tunnel correctness is preserved via the full graph walk on UDP
- The matrix has 0 cross-parser disagreements (4914/4914)

Need a real hp5 run to confirm hp5-specific numbers; this
workstation's perf characteristics aren't a substitute for the
testbed's Zen 1 + isolated cores.
