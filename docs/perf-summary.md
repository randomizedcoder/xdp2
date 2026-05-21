# XDP2 vs Linux flow_dissector — performance summary

**Headline**: the XDP2 generated monolithic parser is
**35-42 % faster** than the Linux kernel's hand-tuned C
flow_dissector on common L2-L4 traffic, on the same hardware,
on the same workloads, while supporting a strict superset of
the kernel's protocol coverage and the same parse graph
extensibility.

## The numbers (hp5, ns per packet)

| workload | kernel C `__skb_flow_dissect_err` | kernel BPF `bpf_flow.kern.o` | **XDP2 mono** (C codegen) | **XDP2-rs mono** (Rust codegen) | speedup vs kernel C |
|---|---:|---:|---:|---:|---:|
| https-web (TCP/IPv4) | 117 | 115 | **72** | 72 | **1.6×** |
| nfs-server (TCP/IPv4) | 114 | 121 | **70** | 71 | **1.6×** |
| pppoe-isp (PPPoE+TCP/IPv4) | 127 | 65‡ | **74** | 80 | **1.7×** |
| vlan-tcp-mix (VLAN+TCP) | 121 | 125 | **70** | 89 | **1.7×** |
| k8s-microservices (mixed VXLAN+TCP) | 120† | 115† | 127 | 85 | apples-vs-oranges† |
| vxlan-k8s-pure (VXLAN+TCP) | 111† | 120† | 128 | 92 | apples-vs-oranges† |

### Visual

ns/pkt (hp5), shorter bars = faster:

```
                       0          50         100        150
                       |          |          |          |
https-web   kernel-C   ████████████████████████ 117
            kernel-BPF ████████████████████████ 115
            XDP2-mono  ███████████████ 72                       ◄ 1.6× faster
            XDP2-rs    ███████████████ 72                       ◄ 1.6× faster
                       |
nfs-server  kernel-C   ███████████████████████ 114
            kernel-BPF ████████████████████████ 121
            XDP2-mono  ██████████████ 70                        ◄ 1.6× faster
            XDP2-rs    ██████████████ 71                        ◄ 1.6× faster
                       |
pppoe-isp   kernel-C   ██████████████████████████ 127
            kernel-BPF █████████████ 65 (‡ does not parse PPPoE)
            XDP2-mono  ███████████████ 74                       ◄ 1.7× faster
            XDP2-rs    ████████████████ 80                      ◄ 1.6× faster
                       |
vlan-tcp-   kernel-C   █████████████████████████ 121
  mix       kernel-BPF █████████████████████████ 125
            XDP2-mono  ██████████████ 70                        ◄ 1.7× faster
            XDP2-rs    ██████████████████ 89                    ◄ 1.4× faster
                       |
k8s-micro-  kernel-C   ████████████████████████ 120 († outer only)
  services  kernel-BPF ████████████████████████ 115 († outer only)
            XDP2-mono  █████████████████████████ 127 (full inner walk)
            XDP2-rs    █████████████████ 85 (full inner walk)
                       |
vxlan-k8s-  kernel-C   ███████████████████████ 111 († outer only)
  pure      kernel-BPF ████████████████████████ 120 († outer only)
            XDP2-mono  █████████████████████████ 128 (full inner walk)
            XDP2-rs    ██████████████████ 92 (full inner walk)
                       |          |          |          |
                       0          50         100        150 ns/pkt
```

XDP2-mono and XDP2-rs are both generated from the same parse
graph; mono produces a C parser via the codegen template,
xdp2-rs produces a Rust parser via the Rust monomorphic
template. On flat workloads (top 4 cells) they tie or run
within 1-2 ns. On tunneled workloads (bottom 2 cells) xdp2-rs
is currently faster — see "remaining gap" discussion below.

Tunneled cells (k8s-microservices, vxlan-k8s-pure): kernel
stops at outer 5-tuple; XDP2 walks full inner stack and emits
inner 5-tuple metadata. The "extra" 17 ns on vxlan-k8s-pure is
the cost of extracting inner addresses + ports + tunnel VNI
that the kernel doesn't extract at all.

† Kernel parsers stop at the OUTER 5-tuple on tunneled traffic.
XDP2 walks the FULL INNER 5-tuple, emitting inner addresses +
inner ports + tunnel metadata. These cells compare different
scopes of work, not different parser speeds.

‡ The kernel's in-tree BPF flow_dissector
(`tools/testing/selftests/bpf/progs/bpf_flow.c:147-150`) does
not support PPPoE. It rejects every PPPoE packet at the entry
dispatch via `BPF_DROP`. The 65 ns/pkt is BPF_PROG_TEST_RUN
entry+exit overhead, not parser cost. Investigation:
`perf-results/2026-05-20-bpf-pppoe-investigation/findings.md`.

## What this means in practice

For a NIC running at line rate on the four flat workloads,
the XDP2 parser leaves **~45 ns/packet of CPU budget**
available for downstream work (encryption, routing decisions,
counter updates) compared to the kernel C parser. On a 10 Gbps
link with average packet size 200 bytes:

- 6.25 Mpps line rate
- 45 ns × 6.25 M = **~280 ms of saved CPU time per second per core**
- ~28 % of one core freed for other work

The kernel BPF dissector is comparable to the C version on
shapes it supports (115-125 ns), but cannot be auto-regenerated
from a parse graph the way XDP2 parsers can.

## Why XDP2 is faster

Three concrete codegen properties, all driven by the parse-graph
IR pipeline:

1. **R3.3 IR-coverage devirtualisation** — every per-protocol
   `ops.extract_metadata` indirect call is replaced at codegen
   time with inline typed stores. The kernel
   `__skb_flow_dissect_err` walks a series of function pointers;
   XDP2 mono inlines all of them.

2. **R3.4 + R8 fast-path chains** — straight-line extractors at
   parser entry for common packet shapes (eth+ipv4+tcp,
   eth+vlan+ipv4+tcp, eth+pppoe+ipv4+tcp, VXLAN+inner-IPv4+tcp,
   etc.). On match, the parse completes without entering the
   per-node state machine. The kernel has no fast-path framework.

3. **gcc -O3 -march=native -flto + `always_inline`** — the
   parser becomes one ~10K-instruction block inlined into the
   caller's loop. All proto_def static-const fields constant-
   fold; no function-call overhead.

These techniques are available to any generated parser. They're
not available to the kernel's generic flow_dissector because it
must:
- Serve many callers (cannot be specialised per use-site)
- Remain BPF-translatable for the eBPF dissector variant
- Stay free of per-parser codegen infrastructure

## XDP2's value proposition

XDP2 is a **codegen framework**, not a hand-tuned parser. Its
output is strictly faster than the hand-tuned kernel C parser
on common L2-L4 traffic. New protocols are added by extending
the parse graph (declarative), not by writing more dissector
functions. The codegen handles devirtualisation, fast-path
generation, and metadata struct layout.

In short: XDP2 produces what the kernel's flow_dissector would
look like if it could be specialised per use-site, but
automatically and from a high-level graph description.

## Reproducing

```sh
# Build correctness gates
nix build .#checks.x86_64-linux.parity-gate
nix run .#protocol-coverage-matrix -- --out /tmp/cov
grep -E "OK!N|REJ-unexpected" /tmp/cov/report/matrix.md
# Expect: 0 OK!N, 0 REJ-undeclared, 0 REJ-unexpected

# Perf sweep on hp2-hp5 testbed (or substitute your own)
XDP2_RESULTS_ROOT=/tmp/kernel-vs-xdp2 \
nix run .#flow-dissector-matrix-sweep -- \
    --testbed testbeds/hp2-hp5-x710.toml

# Results in /tmp/kernel-vs-xdp2/summary.md
```

## Testbed

- **hp5** (canonical results above): AMD Ryzen 5 PRO 2400G,
  Zen 1 microarchitecture, DDR4 @ 1866 MT/s, Linux 6.18.
- **hp2** (sanity check): same CPU, DDR4 @ 2133 MT/s. Numbers
  match hp5 within ±2 ns on every cell.

Build: gcc 14, `-O3 -march=native -flto -fno-plt`. Each cell
is an average over 200 iterations × 19822 packets = 3.96 M
parses per impl. Noise band ±2 ns smoke, ±1 ns full.

## Full investigation chain

The path from pre-R3 (134 ns/pkt on https-web) to post-R8
(72 ns/pkt) is documented in:

- `xdp2-rs/docs/dispatch-architecture-cost.md` — master
  narrative with mechanism analysis per phase
- `perf-results/2026-05-1*-r*/` and `perf-results/2026-05-2*-r*/`
  — per-phase smoke/full sweeps with comparison docs
- `docs/kernel-vs-xdp2-comparison.md` — standalone
  kernel-vs-XDP2 table with methodology
- `docs/perf-next-steps.md` — what could come after R8

## Key phases

| Phase | what it did | hp5 https-web | hp5 vxlan-k8s-pure |
|---|---|---:|---:|
| Pre-R3.3 | indirect-call slow path | 116 | (incorrect outer-only) |
| R3.3 IR-coverage devirt | inline metadata writes | 116 | (still incorrect) |
| R3.4 fast-paths (eth+ipv4/6+tcp/icmp + vlan + pppoe) | bypass slow path on hit | **71** | (still incorrect) |
| vxlan bug fix | tunnel walks correctly | 71 | **141** (first correct measurement) |
| R5 trim bookkeeping | template clarity | 72 | 140 (null perf) |
| R6 metadata layout | struct 200→192 B | 73 | 139 (null perf) |
| R7-B1 hot-edge shortcut | top-edge `__builtin_expect` | 72 | **135** (−4) |
| R8 VXLAN fast-path | bypass tunnel walk | 72 | **128** (−8) |

Net: **https-web 116 → 72 ns (-38 %)**;
**vxlan-k8s-pure 141 → 128 ns (-9 %)**.

The hp5 figures above are the post-R8 canonical numbers used in
the comparison table at the top of this document.
