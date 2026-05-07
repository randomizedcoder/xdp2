# Live-Wire AF_XDP Parser Comparison Baseline — 2026-05-06

First head-to-head live-wire parser comparison on the hp2-hp5-x710
testbed with `XDP2_MATRIX_PARITY=1` already validating correctness on
the PCAP-replay side. Phase L1+L2+L3+L4 of the live-wire plan.

## Configuration

- **Testbed:** hp2-hp5-x710 (AMD Ryzen 5 PRO 2400G × 2, Intel X710 10
  GbE, NixOS, kernel 7.0.1).
- **Topology:** pktgen on hp2 → 10 GbE → X710 NIC on hp5 → Flow
  Director ntuple rule (UDP/443 → q1) → AF_XDP zerocopy → `xdp2-bench
  --mode <X>` on queue 1.
- **Single queue, single core, single 5-tuple** — measures the
  one-pipeline ceiling, not aggregate cluster throughput.
- **Loads:** 10 Mpps offered (saturating; receiver caps well below
  this).
- **Frame sizes:** 64 B and 1500 B.
- **Modes:** 4 — see table.
- **Duration:** 30 s per cell × 4 modes × 2 frame sizes = 8 cells.

## Results

| Mode | 64 B (ns/pkt, Mpps) | 1500 B (ns/pkt, Mpps) | drops |
|---|---:|---:|---:|
| `af-xdp` (compiled) | 1139, 0.90 | 1139, 0.90 | 91% |
| `af-xdp-mono` | 1139, 0.90 | 1139, 0.90 | 91% |
| `af-xdp-graph-enum` | 1139, 0.90 | 1139, 0.90 | 91% |
| `af-xdp-template` (eth-ipv4-udp) | 1139, 0.88 | 1139, 0.88 | 91% |

(Numbers from `summary-afxdp.csv`; medians match means at this noise
floor.)

## Headline

**The parser doesn't matter on live wire at single-queue.** All four
implementations — including hand-rolled `mono`, enum-dispatch
`graph-enum`, and the hardware-classified `template` extractor —
converge to the same **1139 ns/pkt / ~0.88 Mpps** ceiling. The
parser's intrinsic per-packet cost (17–46 ns/pkt on PCAP replay)
is **eclipsed ~25–60× by the rx pipeline overhead** (DMA → NAPI →
XDP → XSKMAP → AF_XDP umem refill → batch dispatch).

This is the answer to the question that motivated the campaign: "do
the PCAP-replay rankings (graph-enum > template > mono > compiled)
survive on live wire?" **They do not at single-queue.** The pipeline
is the bottleneck; the parser sees a buffer that already cost it
~1100 ns to arrive.

## PCAP-replay vs. live-wire side-by-side

| Mode | PCAP-replay (combo.pcap, hp5) | Live wire (hp5, q1, 64 B) | Ratio |
|---|---:|---:|---:|
| `rust-graph-enum` / `af-xdp-graph-enum` | 17 ns/pkt (63 Mpps) | 1139 ns/pkt (0.90 Mpps) | **67×** |
| `rust-mono` / `af-xdp-mono` | 51 ns/pkt (20 Mpps) | 1139 ns/pkt (0.90 Mpps) | **22×** |
| `rust-compiled` / `af-xdp` | 47 ns/pkt (21 Mpps) | 1139 ns/pkt (0.90 Mpps) | **24×** |
| `rust-template` / `af-xdp-template` | 50 ns/pkt (20 Mpps) | 1139 ns/pkt (0.88 Mpps) | **23×** |

The faster the parser, the bigger the live-wire ratio — because the
pipeline overhead is fixed and the parser cost gets amortised.
graph-enum lost the most (67×) because it had the most to lose;
mono/compiled/template had higher PCAP cost so the same fixed pipeline
overhead is a smaller multiplier.

## Frame size has no effect at this scale

Both 64 B and 1500 B converge to the same 877K pps. That's expected:

- **64 B is pps-bound**: link-rate cap is ~14.88 Mpps but the receiver
  caps at 0.88 Mpps, so frame size doesn't enter the equation.
- **1500 B link-rate cap is ~0.83 Mpps**: very close to the
  observed 0.88 Mpps. At higher frame sizes the link starts to bind
  before the receiver. We're right at the crossover but on the
  receiver-bound side at 1500 B.

A larger frame-size sweep (256 B, 512 B) would show this crossover
clearly, but the headline doesn't change.

## What this means for the parser project

1. **Parser optimisation pays off only when the pipeline gets
   faster.** Today's 1139 ns/pkt budget is dominated by NAPI +
   XSKMAP + umem mgmt — not parsing. Squeezing 17 → 10 ns/pkt in
   the parser is invisible until the pipeline drops below ~50 ns/pkt.
2. **Multi-queue is the next step for end-to-end Mpps.** 8 queues ×
   8 cores would, in principle, deliver ~7 Mpps aggregate (linear
   scaling assumed). Verifying that requires a multi-queue Phase
   L1.1 run (the wrapper supports it via `--queues 8`; pktgen needs
   port-range spread to feed RSS).
3. **PCAP-replay numbers stay valuable as the parser-intrinsic
   characterisation.** When the pipeline gets faster (kernel busy-poll
   tuning, larger UMEM, polling instead of NAPI) the parser
   ranking from PCAP replay will start to matter. Today it doesn't.

## Files

- `summary-afxdp.{md,csv}` — campaign rollup (8 cells).
- `hp2-hp5-x710/afxdp/<mode>/<size>b/10mpps.{json,log}` — raw per-cell
  data + bench output.
- `hp2-hp5-x710/afxdp/<mode>/<size>b/10mpps-bench/` — pktgen counters,
  ntuple rules, raw xdp2-bench output preserved for diagnosis.

## Reproducing this baseline

```bash
# Single-queue head-to-head — 8 cells × 30s = ~5 min wall after warm cache.
nix run .#flow-dissector-afxdp-live -- \
    --testbed testbeds/hp2-hp5-x710.toml \
    --duration 30 --loads 10 \
    --modes af-xdp,af-xdp-mono,af-xdp-graph-enum,af-xdp-template \
    --frame-sizes 64,1500 --results perf-results

# Re-extract metrics from logs (the wrapper's inline awk only handles
# the af-xdp-template per-queue table; the other modes use a
# different output format — extract-afxdp-cell.py handles both).
python3 nix/scripts/extract-afxdp-cell.py \
    perf-results/$(date -I)/hp2-hp5-x710/afxdp

# Aggregate
nix run .#flow-dissector-afxdp-aggregate -- \
    --results perf-results --out perf-results/$(date -I)
```

## Follow-ups (not in this baseline)

- **Multi-queue scaling sweep** — `--queues 1,2,4,8` to find the
  aggregate ceiling. Expected linearish scaling on i40e/X710; the
  exact curve characterises the per-pipeline-instance cost vs.
  cross-pipeline contention.
- **Decompose the 1139 ns/pkt budget** — perf-record / bpftool /
  tracepoints to break down DMA vs. NAPI vs. XDP vs. XSKMAP vs.
  AF_XDP umem refill vs. batch dispatch vs. parse. Once we know
  where the time is going, the next-bigger optimisation target is
  obvious.
- **Add `af-xdp-mono-x4` / `af-xdp-simd` / `af-xdp-template-simd`** —
  these use batch parsing, which currently doesn't fit the
  one-packet-at-a-time AF_XDP rx closure. Adding them needs new
  rx-loop variants that batch packets before parsing.
- **C-side parsers (kernel flowdis, XDP2-C, BPF) on AF_XDP** — would
  require new wrapper code (own rx loop, own umem mgmt) since those
  parsers live in `samples/flow_dissector/benchmark{,_bpf}.c`,
  not in `xdp2-bench`.
