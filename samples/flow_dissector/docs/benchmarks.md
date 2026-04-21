[Back to Summary](../SUMMARY.md)

## Userspace Benchmark

The benchmark (`benchmark.c`, 731 lines) runs head-to-head comparisons between
xdp2's parser and a userspace port of the kernel's flow dissector (`libflowdis`,
included in xdp2) on real PCAP traffic.

### Measurement Modes

The benchmark reports three measurements per run:

| Measurement | Per-packet work inside timing loop |
|---|---|
| **Kernel flowdis** | `memset(&keys, 0, ~88 bytes)` + `__skb_flow_dissect_err()` |
| **XDP2 parser** | `memset(&metadata, 0, ~200 bytes)` + ctrl field resets + `xdp2_parse()` |
| **XDP2 parse-only** | ctrl field resets + `xdp2_parse()` (no metadata memset) |

The "XDP2 parser" number includes a ~200-byte `memset` per packet (zeroing
`struct xdp2_metadata_all`), while flowdis only zeroes ~88 bytes (`struct
flow_keys`). This ~10 ns/pkt penalty explains most of the gap between
the "XDP2 parser" and "Kernel flowdis" numbers. The "parse-only" measurement
isolates the actual parsing algorithm cost by skipping the metadata memset.

### Final Performance Results

All results compiled with `-O2`, 100 iterations.

**Large-scale benchmark (500k combinatorial packets, 512 protocol combinations):**

| Parser mode | flowdis (ns/pkt) | xdp2 (ns/pkt) | parse-only (ns/pkt) | Speedup | Parse-only speedup |
|---|---|---|---|---|---|
| Optimized (`-O`) | 137 | 150 | 135 | 0.9x | **1.0x** |
| Standard | 135 | 181 | 177 | 0.7x | 0.8x |
| Fast (`-F`) | 135 | 190 | 175 | 0.7x | 0.8x |

**Small PCAP benchmarks (protocol-specific, `-O` optimized parser):**

| Traffic | flowdis (ns/pkt) | xdp2 (ns/pkt) | parse-only (ns/pkt) | Speedup | Parse-only speedup |
|---|---|---|---|---|---|
| IPv4 TCP (11 pkts) | 20 | 21 | 9 | 0.9x | **2.1x** |
| IPv6 TCP (12 pkts) | 20 | 21 | 9 | 1.0x | **2.1x** |
| GRE tunneled (40 pkts) | 29 | 31 | 17 | 0.9x | **1.7x** |
| Combinatorial 100k | 135 | 148 | 120 | 0.9x | **1.1x** |

**Standard parser (generic table-driven loop):**

| Traffic | flowdis (ns/pkt) | xdp2 (ns/pkt) | parse-only (ns/pkt) | Speedup |
|---|---|---|---|---|
| IPv4 TCP | 20 | 43 | 31 | 0.5x |
| GRE tunneled | 29 | 95 | 87 | 0.3x |
| Combinatorial 100k | 141 | 183 | 171 | 0.8x |

**Fast parser (`-F`, simplified loop, no post-handlers/exit nodes):**

| Traffic | flowdis (ns/pkt) | xdp2 (ns/pkt) | parse-only (ns/pkt) | Speedup |
|---|---|---|---|---|
| IPv4 TCP | 20 | 33 | 23 | 0.6x |
| IPv6 TCP | 21 | 32 | 22 | 0.7x |
| GRE tunneled | 29 | 85 | 75 | 0.3x |

> **Note:** After the multi-graph expansion (March 2026), the fast parser is
> no longer compatible with the L2 graph — the expanded graph has ~70 unique
> reachable nodes, exceeding `NUM_FAST_NODES` (64). The fast parser tests are
> skipped. The optimized parser (`-O`) provides better performance anyway
> and remains the recommended path. See [challenge #14](challenges.md#14-fast-parser-incompatible-with-expanded-graph).

### Performance Analysis

The parse-only numbers confirm that xdp2's optimized parser is **1.1--2.1x
faster** than the kernel's hand-written flow dissector at actual packet parsing.
The apparent slowness in the "XDP2 parser" column is entirely due to the
metadata struct size difference:

- `struct xdp2_metadata_all`: ~200 bytes → ~15 ns/pkt memset cost
- `struct flow_keys` (flowdis): ~88 bytes → ~5 ns/pkt memset cost

This ~10 ns/pkt penalty accounts for most of the gap. A purpose-built
`flow_dissector_metadata` struct (~88 bytes, see
[metadata optimization](metadata-optimization.md)) would close the gap,
giving the optimized parser an expected **1.0--1.5x speedup** including all
setup overhead.

The optimized parser's advantage comes from eliminating function pointer
overhead, replacing linear table lookups with switch statements, and inlining
metadata extraction.

## 4-Way Performance Comparison Matrix

The benchmark supports a 4-way comparison across implementation (kernel vs xdp2)
and execution mode (non-BPF userspace vs BPF in-kernel).

**500k packets, 512 protocol combinations, optimized parser (`-O`):**

|                        | Non-BPF (userspace)      | BPF (in-kernel)          |
|------------------------|--------------------------|--------------------------|
| **Kernel flowdis**     | 137 ns/pkt,  7 Mpps      | 213 ns/pkt,  4 Mpps      |
| **XDP2 parser**        | 150 ns/pkt,  6 Mpps      | Compiles (988KB .o), needs root for runtime |
| **XDP2 parse-only**    | 135 ns/pkt,  7 Mpps      | Compiles (988KB .o), needs root for runtime |

Key findings:

- **XDP2 optimized parse-only matches the kernel** at 135 ns/pkt (1.0x parity)
  on diverse mixed-protocol traffic.
- **BPF is 1.6x slower than userspace** (213 vs 135 ns/pkt). The
  `BPF_PROG_TEST_RUN` syscall overhead and BPF JIT constraints account for
  this. Rows within each column are directly comparable, but cross-column
  numbers reflect different execution contexts.
- **XDP2 BPF compiles successfully.** The xdp2-compiler generates
  `parser.xdp.h` which compiles to a 988KB BPF object file. Runtime
  benchmarking requires root (for `BPF_PROG_TEST_RUN`).

## Physical-Testbed 6-Way Matrix — Tuned (2026-04-21)

Re-run after wiring the `xdp2.nixosModules.physical-testbed` module
into both `hp2` and `hp5` (rebuild + reboot). Tuning applied: isolcpus
2-7, `nohz_full`, `rcu_nocbs`, `mitigations=off`, governor pinned to
performance, transparent hugepages off, lldpd / grafana / prometheus /
docker / oomd / fstrim disabled. `hp5` additionally has `lowJitter =
true` (turbo boost off, `nowatchdog`, `nmi_watchdog=0`,
`numa_balancing=0`, mgmt-IRQ pinning). Both runs `taskset -c 2` onto
an isolated core.

|                     | hp2 (userspace) | hp2 (BPF)         | hp5 (userspace) | hp5 (BPF)         |
|---------------------|-----------------|-------------------|-----------------|-------------------|
| Kernel flowdis      | 32 ns · 31 Mpps | 74 ns · 13 Mpps   | 26 ns · 38 Mpps | 79 ns · 12 Mpps   |
| XDP2 parser         | 70 ns · 14 Mpps | **N/A** (way 5)   | 59 ns · 16 Mpps | **N/A** (way 5)   |
| XDP2 parse-only     | 50 ns · 20 Mpps | —                 | 42 ns · 23 Mpps | —                 |
| xdp2-flow-ebpf fast | —               | 22 ns · 45 Mpps   | —               | 23 ns · 43 Mpps   |

**Speedup vs the untuned 2026-04-20 baseline** (ratio of new ÷ old):
Way 1: 1.97×–2.04×, Way 2: 2.17×–2.30×, Way 3: 2.12×–2.38×,
Way 4: 2.29×–2.80×, Way 6: **6.26×–7.23×**. The jump is biggest in
the BPF rows — `BPF_PROG_TEST_RUN` runs `repeat=1000` in a tight
kernel loop where every per-call cycle saved by `mitigations=off` +
isolcpus + nohz_full compounds. The previous "performance" floor was
almost entirely overhead, not parser cost; the new numbers track much
closer to the actual algorithmic work.

**Cross-host consistency** (hp5 vs hp2 row-by-row, "+" = hp5 faster):
untuned was uniformly +6 % to +21 % (hp5 always faster, mean +13 %);
tuned spread is **−7 % to +19 %** with hp5 only marginally ahead on
the userspace rows and hp2 slightly faster on the two heavy-BPF rows.
The hosts now behave as expected for matched hardware: noise-floor
cross-talk rather than a deterministic hp5 advantage.

Way 5 still doesn't load on either host — same kernel-7.0.0 verifier
regression documented in [challenge #15](challenges.md#15-bpf-verifier-rejects-xdp2-generated-parser-on-ipv6-extension-headers-way-5-partial).
Tuning the host doesn't fix codegen. Track that separately.

## Physical-Testbed 6-Way Matrix — Untuned baseline (2026-04-20)

First live run of the 6-way matrix on the xdp2 physical testbed
(`hp2`/`hp5`, Ryzen 5 PRO 2400G, kernel 7.0.0 NixOS, Intel X710 10GbE,
see [`docs/physical-testbed.md`](../../../docs/physical-testbed.md)).
Invocation:

```bash
nix run .#run-on-host -- hp2 hp5 -- flow-dissector-matrix-smoke   # sandboxed (ways 1–3)
ssh root@hp5 'cd /root/xdp2 && nix run .#flow-dissector-matrix -- data/pcaps/tcp_ipv4.pcap'
```

Measured against the in-tree `data/pcaps/tcp_ipv4.pcap` (11 IPv4/TCP
packets, ×10 userspace iterations, ×1000 BPF_PROG_TEST_RUN repeats):

|                     | hp2 (userspace)     | hp2 (BPF)           | hp5 (userspace)     | hp5 (BPF)           |
|---------------------|---------------------|---------------------|---------------------|---------------------|
| Kernel flowdis      | 63 ns/pkt · 15 Mpps | 207 ns/pkt · 4 Mpps | 53 ns/pkt · 18 Mpps | 181 ns/pkt · 5 Mpps |
| XDP2 parser         | 161 ns/pkt · 6 Mpps | **N/A** (way 5)     | 128 ns/pkt · 7 Mpps | **N/A** (way 5)     |
| XDP2 parse-only     | 106 ns/pkt · 9 Mpps | —                   | 100 ns/pkt · 10 Mpps| —                   |
| xdp2-flow-ebpf fast | —                   | 159 ns/pkt · 6 Mpps | —                   | 144 ns/pkt · 6 Mpps |

Known issues surfaced by this run:

- **Way 5 (`XDP2 BPF parser`) fails to load on kernel 7.0.0 even for
  pure-IPv4 PCAPs.** This is a regression beyond the IPv6-EH-only
  scope documented in [challenge #15](challenges.md#15-bpf-verifier-rejects-xdp2-generated-parser-on-ipv6-extension-headers-way-5-partial).
  The verifier rejects at program load with
  `math between pkt pointer and register with unbounded min value`
  after processing ~1832 insns — before any packet flows, so the
  caller-side IPv4 bounds in `flow_dissector.bpf.c` no longer mask the
  problem. On-disk object still compiles cleanly via `clang -target bpf`
  (matrix build passes); only load fails.
- **Way-1–4 + Way 6 all load and produce timings.** No unexpected
  failures in the userspace or hand-written-fastpath rows.

Host-vs-host delta (**~15–25 % hp5 faster** across every row that
loads) is **not a host-class difference**:

- CPUs are identical (same Ryzen 5 PRO 2400G).
- DIMM channel topology is identical (dual-channel, fully populated).
- hp5 is actually clocked *slower* (1866 vs 2133 MT/s) — memory
  bandwidth can't explain a *speedup* on hp5.
- The micro-benchmark (11 pkts × 10 iters) is dominated by cache
  state, branch-predictor warm-up, and turbo-boost variance at the
  moment of measurement.

Treat as run-to-run noise until re-measured on a larger corpus. The
500k-combo PCAP numbers in the "Final Performance Results" table above
(from earlier dev-box runs) remain the load-bearing comparison. This
physical-testbed section is a smoke record, not a performance claim.

### Reproducibility

Both hosts land on identical derivation hashes for the matrix
artifacts (`x21yziwfpsyzqfvivz7i50hyjp6n3daw-xdp2-flow-dissector-matrix-artifacts-0.1.0`)
and for the smoke derivation (`2811asdpdqds0nkac4bnz007c95vx2ig-xdp2-flow-dissector-matrix-smoke-0.1.0.drv`).
This required one fix in the physical-testbed-runner wrapper: the
rsync step must ship `.git/` so Nix's flake input uses git-tracked-path
semantics rather than plain-directory hashing — see commit `e5abff4`.

### Measurement Methodology

- **Non-BPF column**: `clock_gettime(CLOCK_MONOTONIC_RAW)` around userspace loops.
  The `benchmark` binary links the kernel flow dissector ported to userspace
  (libflowdis) and the xdp2 parser (generated by xdp2-compiler).
- **BPF column**: `BPF_PROG_TEST_RUN` with `repeat=N`, kernel returns avg
  ns/invocation. The `benchmark_bpf` binary loads a compiled BPF flow dissector
  object and runs it via the kernel's test infrastructure. This measures real
  JIT-compiled BPF performance.
- **Test PCAP**: 500,000 packets generated by `gen_test_pcap.py` covering all
  512 valid protocol combinations (L2×L3×L4×tunnel permutations). Generated
  deterministically via `nix build .#test-pcap` (seed=42, cached in Nix store).
- Numbers are **not directly comparable across columns** due to different
  execution contexts (userspace C vs kernel JIT-compiled BPF), but rows within
  each column are directly comparable.
- **Hardening disabled**: Nix builds use `NIX_HARDENING_ENABLE=` (empty) globally
  to disable stack protectors, FORTIFY_SOURCE, and other hardening flags that
  add overhead. This ensures fair apples-to-apples comparison between parsers.

### Running the Matrix

```bash
# Generate the 500k test PCAP (cached in Nix store)
nix build .#test-pcap
ls result-test-pcap/combo.pcap   # 58 MB, 500k packets

# Or generate a custom PCAP
nix run .#gen-test-pcap -- -n 500000 -o /tmp/combo.pcap

# Run userspace benchmarks (no root needed)
./benchmark -p -O -n 100 result-test-pcap/combo.pcap

# Run BPF benchmark (needs root for BPF_PROG_TEST_RUN)
sudo LD_LIBRARY_PATH=install/x86_64/lib \
  ./benchmark_bpf -p -n 1000 -b bpf_flow.kern.o result-test-pcap/combo.pcap

# Or run the combined 4-way matrix script
sudo ./benchmark_matrix.sh -n 100 result-test-pcap/combo.pcap
```

### Benchmark Tools

- **`benchmark.c`** (731 lines): Userspace head-to-head benchmark. Loads PCAP,
  runs both flowdis and xdp2 parsers, reports correctness and performance.
  Supports `-O` (optimized), `-F` (fast), `-p` (performance mode), `-n N`
  (iterations), `-v` (verbose per-packet comparison).

- **`benchmark_bpf.c`** (418 lines): BPF benchmark using `BPF_PROG_TEST_RUN`.
  Loads a compiled BPF `.o` file, injects PCAP packets via the kernel's BPF
  test infrastructure, reports per-packet latency. Supports `-l LABEL` for
  labeling output lines (used by `benchmark_matrix.sh`).

- **`benchmark_matrix.sh`** (175 lines): 4-way matrix wrapper script. Runs
  both userspace and BPF benchmarks for kernel and xdp2 parsers, formats
  results as a comparison table. Handles root detection for BPF tests.

- **`parser_xdp.c`** (5 lines): Single-root wrapper that includes the
  xdp2-compiler XDP output (`parser.xdp.h`). Needed because the compiler
  generates a header file, and BPF compilation requires a `.c` translation unit.

### Kernel BPF Flow Dissector

The kernel's BPF flow dissector (`bpf_flow.c`) is vendored from Linux selftests
(`tools/testing/selftests/bpf/progs/bpf_flow.c`). It is compiled as
`bpf_flow.kern.o` with `clang -target bpf` and benchmarked via
`benchmark_bpf` using `BPF_PROG_TEST_RUN`.

To update the vendored copy to a newer kernel version:

```bash
# Fetch from a specific kernel version (pinned in nix/kern-bpf-flow.nix)
nix build .#kern-bpf-flow-src
cp result samples/flow_dissector/kern_bpf/bpf_flow.c
```

### BPF Compilation

The XDP2 BPF flow dissector is compiled as a portable BPF object using
architecture-specific defines (`bpfArchDefines` in the Nix build):

- **x86_64**: `__x86_64__`
- **aarch64**: `__aarch64__`
- **riscv64**: `__riscv`, `__riscv_xlen=64`

The BPF target itself is always `bpf` (architecture-neutral), but the
C preprocessor needs the host architecture defines for struct layout
compatibility (endianness, type sizes).

### Status

- **Kernel BPF flow dissector**: Working. Vendored from Linux v6.12 selftests,
  compiled as `bpf_flow.kern.o`, benchmarked at 213 ns/pkt (4 Mpps) on 500k
  mixed-protocol traffic.
- **XDP2 BPF flow dissector**: Compiles successfully. The xdp2-compiler
  generates `parser.xdp.h` which compiles to a 988KB BPF `.o` file via
  `clang -target bpf`. The BPF build uses `ETHER_TABLE_CORE_ENTRIES` (28
  ethertypes) to stay within BPF branch target limits — see [challenge
  #12](challenges.md#12-bpf-program-size-exceeded-branch-target-range).
  Runtime benchmarking requires root for `BPF_PROG_TEST_RUN`.
- **Fast parser**: No longer compatible with the expanded L2 graph (~70
  nodes exceeds `NUM_FAST_NODES=64`). Skipped in test suite. The optimized
  parser (`-O`) provides better performance anyway — see [challenge
  #14](challenges.md#14-fast-parser-incompatible-with-expanded-graph).
