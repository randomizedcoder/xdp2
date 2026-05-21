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
