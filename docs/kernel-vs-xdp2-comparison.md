# Kernel-vs-XDP2 perf comparison

Last updated: 2026-05-20 (post-R8).

Direct head-to-head ns/pkt comparison between the in-tree kernel
flow_dissector parsers and XDP2's generated parsers, on the
hp2-hp5-x710 physical testbed (Ryzen 5 PRO 2400G, Zen 1).

## Setup

- Workloads: 6 representative pcaps (https-web, nfs-server,
  pppoe-isp, vlan-tcp-mix, k8s-microservices, vxlan-k8s-pure).
- Testbed: hp2-hp5-x710, hp5 results below (hp2 within ±2 ns).
- Build: gcc -O3 -march=native -flto -fno-plt; XDP2 main branch
  post-R8 (commit `7e36da7`).
- Parsers compared:
  - `c-flowdis-usp` — Linux kernel `__skb_flow_dissect_err`
    (userspace harness driving the in-tree dissector).
  - `c-bpf-flowdis` — Linux in-tree `bpf_flow.kern.o`
    (BPF_PROG_TEST_RUN harness).
  - `c-xdp2-mono` — XDP2 generated monolithic C parser.
  - `rust-mono` — XDP2 generated Rust monolithic parser.

## Methodology

### Benchmark harness

Two harness binaries in `samples/flow_dissector/`:

1. **`benchmark`** (`benchmark.c`) — drives the three C parsers
   (`c-flowdis-usp`, `c-xdp2-usp`, `c-xdp2-mono`) in a single
   process. Each parser gets its own perf loop:
   ```c
   for (int r = 0; r < repeat; r++) {
       for (int i = 0; i < npkts; i++) {
           __skb_flow_dissect_err(...);  /* or xdp2_parse() */
       }
   }
   ```
   Wallclock measured via `clock_gettime(CLOCK_MONOTONIC_RAW)`
   bracketing each loop. ns/pkt = total_ns / (repeat × npkts).

2. **`benchmark_bpf`** (`benchmark_bpf.c`) — drives BPF parsers
   via `BPF_PROG_TEST_RUN`. The kernel-side `bpf_prog_test_run`
   ioctl provides a built-in `repeat` parameter and returns
   `duration_ns` directly. We use repeat=1000.

Both harnesses run the parser against the same filtered pcap
(only packets a given parser can handle are included, to avoid
fairness penalties from parser-specific rejections).

### Iteration counts

- **Smoke mode** (`--smoke`): default repeat=100. Fast (~3 sec
  per cell per host) but ±2-3 ns noise band.
- **Full mode** (no flag): repeat=200 + BPF repeat=1000.
  Slower (~10 sec per cell) but ±1 ns noise band.

All numbers in the headline table are from full-mode sweeps.

### What ns/pkt represents

For c-flowdis-usp / c-xdp2-* (userspace): time from entering
the parser function to returning, divided by packet count.
Excludes pcap loading, harness setup, accumulator resets (per
O1.A 2026-05-08, only the parse-relevant accumulators are
reset per packet, not the full metadata struct).

For c-bpf-flowdis / c-bpf-xdp2 (BPF_PROG_TEST_RUN): kernel's
own measurement of the BPF program's execution time, including
the kernel→BPF dispatch overhead. This is structurally ~65 ns
of floor cost on Zen 1 that the userspace parsers don't have.

### What ns/pkt does NOT include

- Driver RX cost (NIC → skb)
- Skb allocation / freeing
- L1d cache miss on the first packet byte (the bench warms
  caches with a 100-iteration warmup pass)
- Userspace ↔ kernel context switches (the harness is fully
  userspace; only BPF cells cross into kernel)

### Output verification

Every cell is correctness-checked against the parity-gate
(32 pcaps × N parsers, all-fields comparison) and the
protocol-coverage-matrix (4914 cells × N parsers, per-field
pairwise). A cell with non-zero `OK!N`, `REJ-undeclared`, or
`REJ-unexpected` would fail the run; the post-R8 sweeps show
0/0/0 across the board.

### Hardware control

- CPU pinning: `taskset -c 3` (isolate the bench from the
  scheduler's other cores).
- Idle prevention: the perf loop runs at 100% CPU so frequency
  governor stays at boost.
- Thermal: the bench takes <30 sec per cell; no thermal
  throttling observed in any run.

hp5 is the canonical testbed; hp2 results are sanity checks
because hp2 has historically shown ~5-10% more inter-run
variance (likely DDR4 timing differences — hp2 at 2133 MT/s,
hp5 at 1866 MT/s).

### Noise band

Smoke-iteration band: ±2-3 ns (single replicate per cell).
Full-iteration band: ±1 ns (averaged over 200 replicates).
Cell-to-cell variation within one run: typically ±1 ns on
hp5, ±2-3 ns on hp2.

A claim of "X ns/pkt improvement" requires the delta to
exceed the noise band on the canonical testbed (hp5) and to
not regress beyond the noise band on the secondary (hp2).
The R7-B1 (-4 ns), R7-B4 v1 (reverted), R7-B2 (reverted), and
R8 (-8 ns) decisions all applied this rule.

## Headline numbers (hp5)

| workload | kernel C (flowdis-usp) | kernel BPF (bpf-flowdis) | **XDP2 mono** (c-xdp2-mono) | rust-mono |
|---|---:|---:|---:|---:|
| https-web | 117 | 115 | **72** | 72 |
| nfs-server | 114 | 121 | **70** | 71 |
| pppoe-isp | 127 | 65‡ | **74** | 80 |
| vlan-tcp-mix | 121 | 125 | **70** | 89 |
| k8s-microservices | 120† | 115† | 127 | 85 |
| vxlan-k8s-pure | 111† | 120† | 128 | 92 |

† Kernel parsers stop at OUTER 5-tuple on tunneled traffic;
XDP2 walks FULL INNER 5-tuple. These cells are
apples-vs-oranges (different scopes of work).

‡ **c-bpf-flowdis does NOT parse PPPoE.** The in-tree BPF
flow_dissector at
`samples/flow_dissector/kern_bpf/bpf_flow.c:147-150` returns
`BPF_DROP` for any etype other than IP / IPv6 / MPLS / 802.1Q /
802.1AD. The 65 ns/pkt is the BPF_PROG_TEST_RUN entry+exit
overhead with the program immediately rejecting at the entry
dispatch — no actual parsing happens. The "fast" number is a
measurement artifact, not parser speed. Full analysis:
`perf-results/2026-05-20-bpf-pppoe-investigation/findings.md`.

## Headline finding

**Flat workloads** (TCP/UDP/ICMP, with or without VLAN/PPPoE):
c-xdp2-mono runs at **60-65 % of c-flowdis-usp's time** — i.e.
~40 % faster than the kernel's hand-tuned C flow_dissector on
the same hardware, on the same workload, while supporting a
strict superset of the kernel's protocol coverage.

**Tunneled workloads** (VXLAN, k8s-microservices): the kernel
stops at the outer 5-tuple. XDP2 walks the full inner stack
and emits inner 5-tuple metadata. The 17-ns gap to kernel C
(111 → 128 on vxlan-k8s-pure) reflects extra work XDP2 does,
not slower codegen. If c-xdp2-mono were artificially limited
to outer-only (matching kernel scope), the flat-workload
pattern predicts ~70-90 ns/pkt.

## Why c-xdp2-mono is faster than the kernel's hand-tuned C

The XDP2 generated mono parser benefits from three optimisations
not available to the kernel's flow_dissector:

1. **No `ops_*` indirect calls.** The kernel
   `__skb_flow_dissect_err` walks a series of function pointers
   (one per dissector). XDP2's R3.3 IR-coverage devirtualisation
   pass replaces every `ops.extract_metadata` indirect call with
   inline `memcpy` stores (R3.3.4) or typed stores (R7-B3).

2. **Fast-path chains at parser entry** (R3.4, R8). On matching
   packet shapes c-xdp2-mono completes the parse without
   entering the per-node body at all. The kernel flow_dissector
   has no fast-path framework — every packet enters the
   dissector state machine.

3. **gcc -O3 -march=native -flto + `always_inline`** on the
   entry function. The parser becomes one ~10K-instruction
   block inlined into the caller's loop. No function-call
   overhead, full constant-folding of `static const` proto_def
   fields.

The kernel can't easily adopt these because:
- The flow_dissector serves many callers (not specialised per
  use site).
- It has to remain BPF-translatable for the eBPF dissector
  variant.
- It doesn't do per-parser graph generation — adding it would
  be an XDP2-style codegen project from scratch.

## The `c-bpf-flowdis` outlier on pppoe-isp

c-bpf-flowdis is unusually fast on `pppoe-isp.pcap`
(65 ns/pkt vs 115-125 ns on every other workload). Root cause:
the kernel's in-tree BPF flow_dissector does not support
PPPoE. It rejects every PPPoE packet at the entry dispatch
without doing any parsing. The 65 ns is the
BPF_PROG_TEST_RUN entry+exit overhead, not parser cost. Full
analysis: `perf-results/2026-05-20-bpf-pppoe-investigation/findings.md`.

The honest framing for the kernel-team narrative:
> On a PPPoE-heavy workload, c-bpf-flowdis rejects every
> packet at the entry dispatch in ~65 ns. The 65 ns/pkt is the
> floor cost of BPF_PROG_TEST_RUN, not the cost of parsing.
> c-xdp2-mono at 74 ns/pkt parses every packet and emits the
> full L2+L3+L4 metadata — strictly more work, ~9 ns extra.

## Reproducing

```sh
# Single-host smoke run
nix run .#flow-dissector-matrix-unified -- --pcap data/pcaps/https-web.pcap

# Full hp2-hp5 sweep across all 6 workloads
XDP2_RESULTS_ROOT=/tmp/kernel-vs-xdp2 \
nix run .#flow-dissector-matrix-sweep -- \
    --testbed testbeds/hp2-hp5-x710.toml
```

## See also

- `xdp2-rs/docs/dispatch-architecture-cost.md` — full R3-R8
  optimisation history with mechanism analysis
- `perf-results/2026-05-20-r8/comparison.md` — R8 VXLAN
  fast-path landing
- `samples/flow_dissector/docs/benchmarks.md` — benchmark
  harness mechanics
