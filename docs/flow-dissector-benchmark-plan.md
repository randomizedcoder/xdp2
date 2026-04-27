# Authoritative Flow Dissector Benchmark: hp2/hp5 Cross-Implementation Comparison

This document specifies how to run a unified benchmark of all XDP2 flow
dissector implementations on the dedicated hp2/hp5 testbed, producing a
single authoritative comparison across kernel native, kernel eBPF, C/C++
XDP2, and Rust xdp2-rs parsers.

---

## Table of contents

1. [Motivation and gap analysis](#1-motivation-and-gap-analysis)
2. [Hardware and tuning pre-flight](#2-hardware-and-tuning-pre-flight)
3. [PCAP selection matrix](#3-pcap-selection-matrix)
4. [The 10-row authoritative table](#4-the-10-row-authoritative-table)
5. [Experiment phases](#5-experiment-phases)
6. [Hypotheses (predictions before running)](#6-hypotheses-predictions-before-running)
7. [Methodology notes](#7-methodology-notes)
8. [Known issues and mitigations](#8-known-issues-and-mitigations)
9. [Deliverables](#9-deliverables)
10. [Execution checklist](#10-execution-checklist)

---

## 1. Motivation and gap analysis

We have two benchmark worlds that have never been unified on the same hardware:

| Benchmark | Hardware | PCAP | Key results |
|-----------|----------|------|-------------|
| C matrix (ways 1-6) | hp2/hp5 (Ryzen 5 PRO 2400G, Zen 1) | `tcp_ipv4.pcap` (11 pkts) | kernel flowdis 26-32 ns, xdp2 C parse-only 42-50 ns, fast BPF 22-23 ns (tuned) |
| Rust perf-sweep | "l" (Threadripper 3945WX, Zen 2) | `combo.pcap` (445K pkts) | graph 174 ns, mono 38 ns, compiled 36 ns, template 39 ns |

**These numbers cannot be compared** because they differ on three axes:

1. **PCAP:** 11-packet single-chain vs 445K diverse-protocol — cache behaviour,
   branch prediction training, and protocol mix all differ fundamentally.
2. **Hardware:** Zen 1 (4c/8t, 2133 MT/s DDR4) vs Zen 2 (12c/24t, quad-channel).
   Different IPC, cache sizes, branch predictor generations.
3. **Tuning:** hp2/hp5 have `isolcpus`, `nohz_full`, `mitigations=off`;
   Threadripper measurements used only `taskset` pinning.

**Goal:** Run every implementation on the SAME pcap, SAME hardware, SAME
tuning, producing one table where every cell is directly comparable.

**Existing tooling:** The `flow-dissector-matrix-unified` Nix target
(`nix/xdp2-rs-matrix.nix`) already wires the 6-way C matrix and 4 Rust
modes into a single run against a pre-filtered PCAP. It has never been
executed on hp2/hp5.

### References

- C matrix tuned results: `perf-results/hp2/matrix-tuned-20260421T161443Z.txt`
- Rust platform results: `xdp2-rs/docs/performance-by-platform.md`
- Testbed setup: `docs/physical-testbed.md`

---

## 2. Hardware and tuning pre-flight

Before any experiment run, verify the testbed is in known-good state.

### 2.1 Host specifications

| Field | hp2 | hp5 |
|-------|-----|-----|
| CPU | AMD Ryzen 5 PRO 2400G (Zen 1, 4c/8t) | identical |
| RAM | 30 GB DDR4 @ 2133 MT/s | 61 GB DDR4 @ 1866 MT/s |
| NIC | Intel X710 10 GbE SFP+ (i40e) | identical |
| OS | NixOS, kernel 6.18.x | identical |

### 2.2 Pre-flight checklist

Run on each host before starting experiments:

```bash
# 1. Verify CPU isolation
grep -oP 'isolcpus=\S+' /proc/cmdline        # expect: isolcpus=2,3,4,5,6,7
grep -oP 'nohz_full=\S+' /proc/cmdline       # expect: nohz_full=2-7
grep -oP 'rcu_nocbs=\S+' /proc/cmdline       # expect: rcu_nocbs=2-7
grep -oP 'mitigations=\S+' /proc/cmdline     # expect: mitigations=off

# 2. Verify CPU governor
cat /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor | sort -u
# expect: performance

# 3. Verify THP disabled
cat /sys/kernel/mm/transparent_hugepage/enabled
# expect: always madvise [never]

# 4. Verify NIC tuning applied
ethtool -g enp1s0f0np0 | head -10            # expect: RX 4096, TX 4096
ethtool -l enp1s0f0np0                       # expect: Combined = isolcpu count
ethtool -k enp1s0f0np0 | grep -E 'gro|lro|tso|gso'  # expect: all off

# 5. Verify BPF JIT
sysctl net.core.bpf_jit_enable               # expect: 1

# 6. Check for noisy services
systemctl is-active docker lldpd avahi-daemon 2>/dev/null
# expect: all inactive or not found
```

### 2.3 lowJitter modes

The testbed module supports two jitter configurations. Run experiments under
both to quantify sensitivity:

| Config | Turbo boost | NMI watchdog | Use case |
|--------|-------------|--------------|----------|
| `lowJitter=false` (default) | ON | ON | Standard tuned — representative of production |
| `lowJitter=true` | OFF | OFF | Minimum jitter — isolates algorithmic cost |

---

## 3. PCAP selection matrix

Four PCAPs, each targeting a different measurement purpose:

| PCAP | Packets | Purpose | Nix target | Template match rate (expected) |
|------|---------|---------|------------|-------------------------------|
| `tcp_ipv4.pcap` | 11 | HFT ceiling: single-chain, icache-hot, branch-predictor-trained | in-tree `data/pcaps/` | ~100% |
| `https-web.pcap` | ~20K | Production-like: 80% TCP/443, 15% TCP/80, 5% DNS/ICMP | `.#workload-pcap-https-web` | >80% |
| `combo.pcap` | 500K | DPI stress: 512 protocol combinations, max diversity | `.#test-pcap` | ~29% |
| `mixed-real.pcap` | ~871 | Real captures: tunnels, fragments, SRv6, L2TP, VXLAN | `.#perf-mixed-pcap` | ~40-60% |

**Why these four:**

- `tcp_ipv4` establishes the **best-case ceiling** — tiny working set,
  perfectly predicted branches, hot icache. This is the HFT scenario.
- `https-web` represents **production traffic** where template mode should
  dominate (>80% match rate). Most real deployments look like this.
- `combo` is the **adversarial DPI workload** — 512 protocol combinations
  stress every parser path. Template match rate drops to ~29%, forcing
  fallback to compiled parsing. This tests worst-case diversity.
- `mixed-real` adds **real-world edge cases** (tunnels, fragments, extension
  headers) that synthetic PCAPs miss.

---

## 4. The 10-row authoritative table

The primary deliverable. All 10 rows measured on the same pre-filtered PCAP:

| Row | Implementation | Family | Execution context |
|-----|---------------|--------|-------------------|
| 1 | Kernel flow dissector (libflowdis) | C | userspace, `CLOCK_MONOTONIC_RAW` |
| 2 | XDP2 parser (full, with 200B memset) | C | userspace, `CLOCK_MONOTONIC_RAW` |
| 3 | XDP2 parse-only (no memset) | C | userspace, `CLOCK_MONOTONIC_RAW` |
| 4 | Kernel BPF flow dissector (selftest) | eBPF | `BPF_PROG_TEST_RUN` (kernel-reported) |
| 5 | XDP2 BPF parser (compiler-generated) | eBPF | `BPF_PROG_TEST_RUN` (**N/A — verifier failure**) |
| 6 | xdp2-flow-ebpf fast (hand-written) | eBPF | `BPF_PROG_TEST_RUN` (kernel-reported) |
| 7 | Rust graph (dynamic dispatch) | Rust | userspace, rdtsc-derived ns |
| 8 | Rust mono (monomorphized) | Rust | userspace, rdtsc-derived ns |
| 9 | Rust compiled (LTO + inline) | Rust | userspace, rdtsc-derived ns |
| 10 | Rust template (classify + fixed-offset extract) | Rust | userspace, rdtsc-derived ns |

**Columns per PCAP:** ns/pkt (mean +/- 95% CI), Mpps, IPC, ins/pkt, branch-miss%

**Sub-tables:**

| Table | Purpose |
|-------|---------|
| T1: Main comparison | 10 rows x 4 PCAPs, mean +/- 95% CI |
| T2: Cross-host reproducibility | hp2 vs hp5 delta per cell (expect <5%) |
| T3: Tuned vs untuned sensitivity | lowJitter=true vs false per row |
| T4: Statistical summary | stddev, min, max, 95% CI from 5 runs per config |
| T5: TMA microarchitecture | IPC, retiring%, FE-bound%, BE-bound%, bad-spec% |

### PCAP filtering

The unified matrix pre-filters every PCAP through `xdp2-bench --output-pcap`
so both the C matrix and Rust modes measure the **exact same packet set**.
The filter pass rate varies by PCAP and must be recorded:

| PCAP | Expected pass rate | Reason for filtering |
|------|-------------------|---------------------|
| `tcp_ipv4.pcap` | ~100% | All 11 packets are Ethernet/IPv4/TCP |
| `https-web.pcap` | >95% | May filter rare edge protocols |
| `combo.pcap` | ~89% (445K/500K) | Rust parser rejects ~11% of combinations |
| `mixed-real.pcap` | ~80-90% | Real captures may hit unhandled protocols |

---

## 5. Experiment phases

### Phase A: Smoke test (15 minutes)

Verify all tooling works before committing to long runs.

```bash
# 1. C matrix smoke (ways 1-3 only, no root needed)
nix run .#run-on-host -- hp5 -- flow-dissector-matrix-smoke

# 2. Quick xdp2-bench sanity
ssh hp5 'cd ~/xdp2 && nix develop --command \
  cargo run -p xdp2-bench --release -- \
    --pcap data/pcaps/tcp_ipv4.pcap --iterations 10 --mode both'
```

**Exit criteria:** Both commands produce valid ns/pkt numbers. Way 5 shows
N/A (expected). All Rust modes (graph, mono, compiled, template) report.

### Phase B: Unified matrix (4-6 hours)

The core experiment. Run `flow-dissector-matrix-unified` for each PCAP,
5 runs each, on both hosts.

```bash
# Build PCAPs locally first
nix build .#workload-pcap-https-web -o pcap-https-web
nix build .#test-pcap -o pcap-combo
nix build .#perf-mixed-pcap -o pcap-mixed-real

# Run unified matrix: 5 runs x 4 PCAPs x 2 hosts = 40 runs
# (automated via run-on-host; each run ~3-5 minutes)
for pcap in data/pcaps/tcp_ipv4.pcap \
            pcap-https-web/https-web.pcap \
            pcap-combo/combo.pcap \
            pcap-mixed-real/mixed-real.pcap; do
  for run in 1 2 3 4 5; do
    nix run .#run-on-host -- hp2 hp5 -- \
      flow-dissector-matrix-unified -- -n 500 -N 1000 -c 3 "$pcap"
  done
done
```

**Output:** 10-row unified table per run, collected in
`perf-results/{hp2,hp5}/flow-dissector-matrix-unified-<timestamp>/`.

### Phase C: Rust perf-sweep with hardware counters (3 hours)

Run `perf-sweep.sh` on hp2/hp5 to collect IPC, branch-miss%, cache-miss%,
and TMA breakdown for Zen 1. This data currently only exists for Zen 2.

```bash
# On each host, for each PCAP:
nix run .#run-on-host -- hp2 hp5 -- perf-sweep-tcp
nix run .#run-on-host -- hp2 hp5 -- perf-sweep-combo
nix run .#run-on-host -- hp2 hp5 -- perf-sweep-mixed
```

Captures all 4 perf passes: basic, stalls, detail, zen.

**Key comparison:** Zen 1 (hp2/hp5) TMA vs Zen 2 (Threadripper "l") TMA —
are the bottlenecks the same?

### Phase D: Tuned vs untuned sensitivity (1 hour)

Repeat a subset of Phase B under both lowJitter configurations:

```bash
# With lowJitter=false (turbo ON) — already the default
nix run .#run-on-host -- hp5 -- flow-dissector-matrix-unified -- \
  -n 500 -N 1000 -c 3 data/pcaps/combo.pcap

# Toggle lowJitter=true on hp5 (requires NixOS rebuild)
# Then re-run the same command
```

**Key question:** Does Rust's larger code footprint (compiled mode: ~160
instructions/pkt vs C kernel flowdis: ~88 bytes metadata) make it more
sensitive to turbo boost / frequency scaling?

### Phase E: AF_XDP + ntuple template (2 hours)

The real-traffic measurement. Uses both hosts simultaneously (hp2 sends,
hp5 receives).

```bash
# Pre-requisite: Flow Director rules installed on hp5
ethtool -n enp1s0f0np0    # verify ntuple rules

# Run with pktgen burst=32 + queue_map (proven to reach line rate)
nix run .#run-on-host -- hp5 -- flow-dissector-ntuple-template-bench
```

**Context:** Existing D1 experiments already showed:
- Baseline: 1.37 Mpps at 64B (pktgen TX-bound)
- burst=32: 4.14 Mpps (3.02x lift)
- burst=32 + queue_map: 7.34 Mpps RX (14.39 Mpps TX = line rate, 49% drop)

This phase contextualizes the AF_XDP real-NIC numbers alongside the
parse-only numbers from Phase B.

---

## 6. Hypotheses (predictions before running)

Record these predictions before execution, then validate against results:

| # | Hypothesis | Basis | Expected result |
|---|-----------|-------|-----------------|
| H1 | Rust compiled ~40-50 ns on combo.pcap | Zen 1 is slower than Zen 2 (36 ns on Threadripper); combo.pcap exercises more protocol paths than tcp_ipv4 | 40-50 ns/pkt on hp2/hp5 |
| H2 | Rust template wins on https-web.pcap | >80% template match rate on production-like traffic eliminates software classification cost | 15-25 ns/pkt, beating compiled |
| H3 | xdp2-flow-ebpf fast remains BPF champion | Hand-written fixed-offset BPF with no loops or switches | ~22-25 ns across all PCAPs |
| H4 | Kernel BPF flowdis is slowest | `BPF_PROG_TEST_RUN` overhead + general-purpose parsing | ~70-80 ns on tcp_ipv4, worse on combo |
| H5 | Rust graph ~4-5x slower than compiled | vtable dispatch overhead is architectural, not hardware-specific | 160-220 ns on combo.pcap |
| H6 | Cross-host variance <5% | Identical CPUs; remaining delta is run-to-run noise | All cells within 5% between hp2 and hp5 |
| H7 | Rust compiled beats C XDP2 parse-only | Rust's LTO + monomorphization produces tighter code than C table-driven | Compiled < parse-only on all PCAPs |
| H8 | C kernel flowdis beats Rust graph | Hand-written sequential C vs dynamic dispatch overhead | kernel flowdis ~26-32 ns < graph ~160 ns |

---

## 7. Methodology notes

### 7.1 Timing domains

Three distinct timing mechanisms are used. Results within each domain are
comparable; cross-domain ranking requires care:

| Domain | Mechanism | Overhead | Used by |
|--------|-----------|----------|---------|
| C userspace | `clock_gettime(CLOCK_MONOTONIC_RAW)` around loops | ~20 ns/call (amortized over 500 iterations) | Rows 1-3 |
| BPF | `BPF_PROG_TEST_RUN` kernel-reported ns | Includes syscall entry/exit overhead per repeat batch | Rows 4-6 |
| Rust userspace | rdtsc-derived nanoseconds | ~1 ns/call | Rows 7-10 |

**Rule:** Compare within domains (row 1 vs 3, row 7 vs 9) freely. Compare
across domains (row 1 vs row 9) with the caveat that timing overhead differs.

### 7.2 Iteration counts

- Userspace: **500 iterations** (each iterates over all packets in the PCAP)
- BPF: **1000 repeats** per `BPF_PROG_TEST_RUN` invocation
- These match the unified matrix defaults (`-n 500 -N 1000`)

### 7.3 Core pinning

All measurements pinned to **core 3** (`-c 3`), which is in the isolated
set (2-7). This ensures: no scheduler migration, no timer tick interrupts
(`nohz_full`), no RCU callbacks (`rcu_nocbs`).

### 7.4 Statistical rigor

- **5 runs per configuration** (PCAP x host x tuning combination)
- Report: mean, stddev, min, max, 95% confidence interval
- Discard runs with >3-sigma deviation from mean (indicates transient
  system interference)
- **Total runs for Phase B:** 5 runs x 4 PCAPs x 2 hosts = 40

### 7.5 PCAP pre-filtering

The unified matrix script (`xdp2_rs_matrix.sh`) pre-filters the input PCAP
through `xdp2-bench --output-pcap` so both C and Rust measure the **exact
same packet set**. This is critical: without filtering, the C matrix
includes packets the Rust parser rejects, inflating C throughput relative
to Rust.

Record the filter pass rate for each PCAP in results.

---

## 8. Known issues and mitigations

| Issue | Impact | Mitigation |
|-------|--------|------------|
| **Way 5 verifier failure** — XDP2 BPF parser (`flow_dissector.bpf.o`) rejected by kernel verifier on 7.0.0+ with `math between pkt pointer and register with unbounded min value` | Row 5 is N/A in all tables | Document as N/A. Fix requires compiler codegen changes (tracked separately). The other 9 rows are unaffected. |
| **Metadata struct size** — C XDP2 parser memsets ~200 bytes vs kernel's ~88 bytes (~10-15 ns penalty) | Row 2 (XDP2 parser full) appears slower than it should | Always include row 3 (parse-only) which isolates parser algorithm cost without memset overhead. |
| **BPF vs userspace timing incomparability** — `BPF_PROG_TEST_RUN` includes per-batch syscall overhead that userspace loops don't have | BPF rows (4-6) appear slower than equivalent userspace implementations | Label timing domains clearly in all tables. Don't rank BPF rows against userspace rows. |
| **Zen 1 PMU limitations** — Ryzen 2400G may lack `stalled-cycles-backend` and some TMA Level 2 events | TMA analysis may be incomplete vs Zen 2 Threadripper | The perf-sweep script handles missing counters gracefully. Document which events are unavailable. |
| **NixOS channel divergence** — hp2 on `nixos-25.11` (stable), hp5 on `nixos-unstable` | Kernel and toolchain versions may differ slightly | Document exact kernel and libbpf versions per host. For ns-scale work, converge channels before Phase B if possible. |
| **Fat LTO memory** — Rust fat LTO builds require significant RAM; hp2 has only 30 GB | Build may OOM on hp2 | Build on hp5 (61 GB) or pre-build on dev box and rsync binaries. The `run-on-host` script transfers the flake and builds remotely. |

---

## 9. Deliverables

| # | Deliverable | Description |
|---|------------|-------------|
| D1 | **Authoritative 10-row table** | T1 from Section 4: all implementations, all 4 PCAPs, with 95% CIs |
| D2 | **Cross-host reproducibility** | T2: hp2 vs hp5 delta per cell, validating <5% variance |
| D3 | **Tuned sensitivity analysis** | T3: lowJitter=true vs false, per implementation |
| D4 | **TMA microarchitecture profiles** | T5: Zen 1 (hp2/hp5) vs Zen 2 (Threadripper) comparison |
| D5 | **Updated performance-by-platform.md** | Add "AMD Ryzen 5 PRO 2400G (Zen 1)" section to `xdp2-rs/docs/performance-by-platform.md` |
| D6 | **Raw JSON results** | All perf-sweep JSON files committed to `perf-results/hp2/` and `perf-results/hp5/` |
| D7 | **Hypothesis validation** | Section 6 table updated with actual results and pass/fail verdicts |

---

## 10. Execution checklist

Step-by-step commands. Estimated total wall time: 12-16 hours (plan for
overnight Phase B + C).

### 10.1 Pre-flight (both hosts)

```bash
# Verify testbed state
nix run .#run-on-host -- hp2 hp5 -- flow-dissector-matrix-smoke

# Check kernel parameters on each host
for host in hp2 hp5; do
  echo "=== $host ==="
  ssh root@$host 'cat /proc/cmdline'
  ssh root@$host 'cat /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor | sort -u'
  ssh root@$host 'sysctl net.core.bpf_jit_enable'
  ssh root@$host 'uname -r'
done
```

### 10.2 Phase A: Smoke (15 min)

```bash
nix run .#run-on-host -- hp5 -- flow-dissector-matrix-smoke
```

Verify: all 3 userspace ways produce numbers, BPF ways 4+6 produce numbers,
way 5 shows N/A, Rust modes all report.

### 10.3 Phase B: Unified matrix (4-6 hours)

```bash
# Build PCAPs (once)
nix build .#workload-pcap-https-web -o pcap-https-web
nix build .#test-pcap -o pcap-combo
nix build .#perf-mixed-pcap -o pcap-mixed-real

# Run the full matrix
for pcap in \
    data/pcaps/tcp_ipv4.pcap \
    pcap-https-web/https-web.pcap \
    pcap-combo/combo.pcap \
    pcap-mixed-real/mixed-real.pcap; do
  for run in $(seq 1 5); do
    echo "=== Run $run: $(basename $pcap) ==="
    nix run .#run-on-host -- hp2 hp5 -- \
      flow-dissector-matrix-unified -- -n 500 -N 1000 -c 3 "$pcap"
  done
done
```

### 10.4 Phase C: Perf-sweep (3 hours)

```bash
nix run .#run-on-host -- hp2 hp5 -- perf-sweep-tcp
nix run .#run-on-host -- hp2 hp5 -- perf-sweep-combo
nix run .#run-on-host -- hp2 hp5 -- perf-sweep-mixed
```

### 10.5 Phase D: Tuned sensitivity (1 hour)

```bash
# Run with default tuning (lowJitter=false)
nix run .#run-on-host -- hp5 -- flow-dissector-matrix-unified -- \
  -n 500 -N 1000 -c 3 pcap-combo/combo.pcap

# Toggle lowJitter=true on hp5, rebuild NixOS, re-run
# (NixOS rebuild is out of scope for this doc — see physical-testbed.md)
nix run .#run-on-host -- hp5 -- flow-dissector-matrix-unified -- \
  -n 500 -N 1000 -c 3 pcap-combo/combo.pcap
```

### 10.6 Phase E: AF_XDP + ntuple (2 hours)

```bash
# Verify ntuple rules on hp5
ssh root@hp5 'ethtool -n enp1s0f0np0'

# Run pktgen → AF_XDP template benchmark
nix run .#run-on-host -- hp5 -- flow-dissector-ntuple-template-bench
```

### 10.7 Post-processing

```bash
# Collect all results
rsync -az hp2:~/xdp2/perf-results/ ./perf-results/hp2/
rsync -az hp5:~/xdp2/perf-results/ ./perf-results/hp5/

# Update INDEX.json
# (run-on-host does this automatically)

# Populate the authoritative table from collected results
# (manual aggregation of 40 unified-matrix runs into T1-T5)
```

---

## Appendix A: implementation-to-row mapping

For clarity, here is how the existing benchmark binaries map to the 10 rows:

| Row | Binary | Flag / mode | BPF object |
|-----|--------|-------------|------------|
| 1 | `benchmark` | `-I kernel` | — |
| 2 | `benchmark` | `-I xdp2` | — |
| 3 | `benchmark` | `-I xdp2 -P` (parse-only) | — |
| 4 | `benchmark_bpf` | `-b bpf_flow.kern.o` | `bpf_flow.kern.o` |
| 5 | `benchmark_bpf` | `-b flow_dissector.bpf.o` | `flow_dissector.bpf.o` |
| 6 | `benchmark_bpf` | `-b fast_flow.bpf.o` | `fast_flow.bpf.o` |
| 7 | `xdp2-bench` | `--mode graph` | — |
| 8 | `xdp2-bench` | `--mode mono` | — |
| 9 | `xdp2-bench` | `--mode compiled` | — |
| 10 | `xdp2-bench` | `--mode template` | — |

The `xdp2_rs_matrix.sh` / `flow-dissector-matrix-unified` Nix target
orchestrates all 10 rows automatically.

## Appendix B: what this document does NOT cover

- **Way 5 fix** — the verifier failure requires compiler codegen changes
  and is tracked separately.
- **C++ backport** — `xdp2-rs/docs/cpp-backport-plan.md` describes a
  potential C++ reimplementation; this benchmark focuses on existing code.
- **Multi-threaded scaling** — the unified matrix is single-threaded.
  Multi-threaded measurements exist in `performance-by-platform.md` and
  can be re-run on hp2/hp5 as a follow-up.
- **Production deployment benchmarks** — AF_XDP + ntuple (Phase E) is
  the closest proxy, but true production benchmarks require realistic
  traffic generators (DPDK T-Rex, etc.), which are future work (D2 experiments).
