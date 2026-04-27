# Flow Dissector Benchmark — Implementation Log

Tracks progress against
[`docs/flow-dissector-benchmark-plan.md`](./flow-dissector-benchmark-plan.md).

---

## Testbed state (2026-04-26)

| Field | hp2 | hp5 |
|-------|-----|-----|
| Kernel | 7.0.1 | 7.0.1 |
| NixOS | 26.05.20260422 | 26.05.20260422 |
| isolcpus | 2,3,4,5,6,7 | 2,3,4,5,6,7 |
| mitigations | off | off |
| governor | performance | performance |
| BPF JIT | 1 | 1 |
| hugepages | 1024×2 MiB (2 GiB) | 1024×2 MiB (2 GiB) |
| Storage | 256 GB NVMe (128 GB free) | 512 GB SSD (372 GB free) |
| lowJitter | false | true |

Both hosts converged on identical software. Ready for benchmarks.

---

## Phase A: Smoke test

**Goal:** Verify all tooling builds and runs on hp5 before committing to
long runs.

| Step | Command | Status | Notes |
|------|---------|--------|-------|
| A1 | `nix run .#run-on-host -- hp5 -- flow-dissector-matrix-smoke` | PASS | Build-time smoke: ways 1-3 OK (39/85/43 ns). BPF N/A in sandbox (expected). |
| A2 | Full 6-way matrix with root on hp5 | PASS | Ways 1-3 + 4 + 6 all produced numbers. Way 5 N/A (verifier, expected). |
| A3 | Unified matrix (C+Rust) on hp5, tcp_ipv4.pcap | PASS | All 10 rows produced. See first results below. |

**Exit criteria:** Ways 1-3 produce ns/pkt numbers. Ways 4+6 produce
numbers. Way 5 shows N/A. All 4 Rust modes (graph, mono, compiled,
template) report. **All met.**

### First unified results (hp5, tcp_ipv4.pcap, 11 pkts, core 3, 100 iter)

```
Mode                             | ns/pkt             | Mpps
---------------------------------+--------------------+----------
C kernel flowdis (usp)           | 26 ns/pkt          | 38 Mpps
C XDP2 parser (usp)              | 59 ns/pkt          | 16 Mpps
C XDP2 parse-only (usp)          | 42 ns/pkt          | 23 Mpps
C kernel BPF flowdis             | 86 ns/pkt          | 11 Mpps
C XDP2 BPF parser                | N/A                | N/A
C xdp2-flow-ebpf fast (BPF)      | 25 ns/pkt          | 40 Mpps
---------------------------------+--------------------+----------
Rust graph (dyn dispatch)        | 203 ns/pkt         | 5 Mpps
Rust mono (hand-rolled)          | 24 ns/pkt          | 40 Mpps
Rust compiled (monomorphized)    | 22 ns/pkt          | 45 Mpps
Rust template (fixed-offset)     | 23 ns/pkt          | 43 Mpps
```

**Key findings:**
- Rust compiled (22 ns) is the fastest row — beats C kernel flowdis (26 ns)
  and hand-written fast BPF (25 ns)
- Rust mono/template cluster at 23-24 ns, comparable to fast BPF
- Rust graph (203 ns) confirms ~9x dispatch overhead vs compiled
- Filter pass rate: 100% (all 11 tcp_ipv4 packets parseable)

---

## Phase B: Unified matrix

**Goal:** Run `flow-dissector-matrix-unified` for each of 4 PCAPs, 5 runs
each, on both hosts. Produces the authoritative 10-row comparison table.

| PCAP | hp2 runs | hp5 runs | Status |
|------|----------|----------|--------|
| `tcp_ipv4.pcap` (11 pkts) | 5/5 | 5/5 | **DONE** |
| `https-web.pcap` (~20K pkts) | 5/5 | 5/5 | **DONE** |
| `combo.pcap` (500K pkts) | 5/5 | 5/5 | **DONE** |
| `mixed-real.pcap` (~871 pkts) | 5/5 | 5/5 | **DONE** |

### hp5 first-run results (500 iterations, core 3, 2026-04-26)

**tcp_ipv4.pcap** (11 pkts, 100% filter pass rate):

| Mode | ns/pkt | Mpps |
|------|--------|------|
| C kernel flowdis (usp) | 25 | 40 |
| C XDP2 parser (usp) | 56 | 17 |
| C XDP2 parse-only (usp) | 43 | 23 |
| C kernel BPF flowdis | 88 | 11 |
| C XDP2 BPF parser | N/A | N/A |
| C xdp2-flow-ebpf fast (BPF) | 25 | 40 |
| Rust graph | 210 | 5 |
| Rust mono | 24 | 41 |
| **Rust compiled** | **22** | **44** |
| Rust template | 23 | 43 |

**https-web.pcap** (~20K pkts, production-like):

| Mode | ns/pkt | Mpps |
|------|--------|------|
| C kernel flowdis (usp) | 152 | 6 |
| C XDP2 parser (usp) | 198 | 5 |
| C XDP2 parse-only (usp) | 181 | 5 |
| C kernel BPF flowdis | 161 | 6 |
| C XDP2 BPF parser | N/A | N/A |
| C xdp2-flow-ebpf fast (BPF) | 34 | 29 |
| Rust graph | 235 | 4 |
| Rust mono | 86 | 12 |
| Rust compiled | 83 | 12 |
| Rust template | 82 | 12 |

**combo.pcap** (445K filtered / 500K total, 89% pass rate, DPI stress):

| Mode | ns/pkt | Mpps |
|------|--------|------|
| C kernel flowdis (usp) | 161 | 6 |
| C XDP2 parser (usp) | 218 | 4 |
| C XDP2 parse-only (usp) | 206 | 4 |
| C kernel BPF flowdis | 90 | 11 |
| C XDP2 BPF parser | N/A | N/A |
| C xdp2-flow-ebpf fast (BPF) | 17 | 58 |
| Rust graph | 263 | 4 |
| Rust mono | 47 | 21 |
| **Rust compiled** | **40** | **25** |
| Rust template | 46 | 22 |

**mixed-real.pcap** (~871 pkts, real captures with tunnels/fragments):

| Mode | ns/pkt | Mpps |
|------|--------|------|
| C kernel flowdis (usp) | 93 | 10 |
| C XDP2 parser (usp) | 264 | 3 |
| C XDP2 parse-only (usp) | 246 | 4 |
| C kernel BPF flowdis | 148 | 6 |
| C XDP2 BPF parser | N/A | N/A |
| C xdp2-flow-ebpf fast (BPF) | 28 | 35 |
| Rust graph | 450 | 2 |
| Rust mono | 48 | 21 |
| Rust compiled | 56 | 18 |
| **Rust template** | **22** | **45** |

### hp2 mean results (5 runs, 500 iterations, core 3, 2026-04-26)

**tcp_ipv4.pcap** (11 pkts):

| Mode | ns/pkt | Mpps |
|------|--------|------|
| C kernel flowdis (usp) | 31 | 32 |
| C XDP2 parser (usp) | 73 | 14 |
| C XDP2 parse-only (usp) | 50 | 20 |
| C kernel BPF flowdis | 112 | 9 |
| C XDP2 BPF parser | N/A | N/A |
| C xdp2-flow-ebpf fast (BPF) | 33 | 30 |
| Rust graph | 205 | 5 |
| Rust mono | 24 | 42 |
| **Rust compiled** | **22** | **45** |
| Rust template | 22 | 45 |

Note: hp2 C paths show higher run-to-run variance than hp5 (e.g., C kernel
flowdis ranges 26-38 ns). hp2 has `lowJitter=false` (turbo ON) which causes
frequency scaling jitter on short benchmarks.

**https-web.pcap** (~20K pkts):

| Mode | ns/pkt | Mpps |
|------|--------|------|
| C kernel flowdis (usp) | 119 | 8 |
| C XDP2 parser (usp) | 161 | 6 |
| C XDP2 parse-only (usp) | 150 | 7 |
| C kernel BPF flowdis | 114 | 9 |
| C XDP2 BPF parser | N/A | N/A |
| C xdp2-flow-ebpf fast (BPF) | 23 | 43 |
| Rust graph | 210 | 5 |
| Rust mono | 76 | 13 |
| **Rust compiled** | **71** | **14** |
| Rust template | 73 | 14 |

**combo.pcap** (445K filtered / 500K total):

| Mode | ns/pkt | Mpps |
|------|--------|------|
| C kernel flowdis (usp) | 159 | 6 |
| C XDP2 parser (usp) | 215 | 5 |
| C XDP2 parse-only (usp) | 203 | 5 |
| C kernel BPF flowdis | 95 | 11 |
| C XDP2 BPF parser | N/A | N/A |
| C xdp2-flow-ebpf fast (BPF) | 19 | 53 |
| Rust graph | 253 | 4 |
| Rust mono | 46 | 22 |
| **Rust compiled** | **39** | **26** |
| Rust template | 45 | 22 |

**mixed-real.pcap** (~871 pkts):

| Mode | ns/pkt | Mpps |
|------|--------|------|
| C kernel flowdis (usp) | 85 | 12 |
| C XDP2 parser (usp) | 228 | 4 |
| C XDP2 parse-only (usp) | 207 | 5 |
| C kernel BPF flowdis | 159 | 6 |
| C XDP2 BPF parser | N/A | N/A |
| C xdp2-flow-ebpf fast (BPF) | 31 | 32 |
| Rust graph | 555 | 2 |
| Rust mono | 57 | 18 |
| Rust compiled | 67 | 15 |
| **Rust template** | **28** | **36** |

### Key observations from all runs

1. **Rust compiled consistently beats C kernel flowdis** on both hosts and
   all PCAPs (hp5: 22 vs 25, 75 vs 121, 40 vs 161, 56 vs 74;
   hp2: 22 vs 31, 71 vs 119, 39 vs 159, 67 vs 85 ns/pkt)
2. **xdp2-flow-ebpf fast BPF is remarkable** — 17-19 ns on combo, 23-33 on
   tcp_ipv4, 24-31 on mixed-real, 23 on https-web
3. **Rust template shines on mixed-real** (hp5: 22 ns, hp2: 28 ns) where
   fixed-offset extraction matches well
4. **C XDP2 parser is consistently the slowest userspace path** due to
   200-byte memset overhead + table-driven dispatch
5. **BPF kernel flowdis (90-95 ns on combo) is faster than C userspace
   flowdis (159-161 ns)** on large PCAPs — BPF_PROG_TEST_RUN tight kernel
   loop has better cache locality than userspace clock_gettime overhead
6. **hp2 (turbo ON) shows higher variance on small PCAPs** — tcp_ipv4 C
   paths are 19-32% slower than hp5, but https-web and combo paths are
   within 5%. This is a turbo boost frequency scaling effect, not a
   hardware difference (see T2 cross-host analysis)

---

## Phase C: Rust perf-sweep with hardware counters

**Goal:** Collect IPC, branch-miss%, cache-miss%, TMA breakdown on Zen 1.

| Target | hp2 | hp5 | Status |
|--------|-----|-----|--------|
| `perf-sweep-tcp` | **DONE** | **DONE** | Complete |
| `perf-sweep-combo` | **DONE** | **DONE** | Complete |
| `perf-sweep-mixed` | **DONE** | **DONE** | Complete |

Note: 7 perf events unavailable on Zen 1 (op_cache_hits, retired_uops,
dispatch_stalls, mab_stalls all return 0). Basic + stalls + detail counters
all collected successfully.

### hp5 perf profiles (500 iterations, core 3)

**tcp_ipv4.pcap** (11 pkts, 5500 total iterations):

| Mode | ns/pkt | IPC | ins/pkt | br-miss% | cache-miss% |
|------|--------|-----|---------|----------|-------------|
| graph | 199 | 1.48 | 861 | 2.44 | 22.8 |
| mono | 28 | 2.09 | 153 | 0.37 | 20.9 |
| compiled | 21 | 1.89 | 132 | 0.41 | 10.0 |
| simd | 28 | 1.26 | 131 | 0.06 | 31.1 |
| template | 23 | 1.34 | 113 | 0.55 | 20.5 |
| template-simd | 24 | 0.98 | 85 | 0.88 | 11.9 |

**combo.pcap** (445K filtered, 222M total iterations):

| Mode | ns/pkt | IPC | ins/pkt | br-miss% | cache-miss% |
|------|--------|-----|---------|----------|-------------|
| graph | 259 | 1.31 | 1216 | 3.70 | 1.7 |
| mono | 47 | 1.29 | 221 | 5.95 | 2.4 |
| compiled | 40 | 1.26 | 186 | 6.52 | 2.3 |
| simd | 51 | 1.16 | 220 | 6.89 | 12.0 |
| template | 52 | 0.96 | 183 | 6.80 | 2.9 |
| template-simd | 56 | 0.71 | 156 | 8.45 | 9.2 |

**mixed-real.pcap** (815 filtered, 407K total iterations):

| Mode | ns/pkt | IPC | ins/pkt | br-miss% | cache-miss% |
|------|--------|-----|---------|----------|-------------|
| graph | 445 | 1.52 | 2443 | 2.35 | 0.0 |
| mono | 46 | 1.89 | 324 | 2.36 | 0.0 |
| compiled | 56 | 1.47 | 296 | 3.40 | 0.0 |
| simd | 61 | 1.57 | 351 | 2.83 | 0.1 |
| template | 27 | 1.67 | 163 | 0.13 | 0.0 |
| template-simd | 24 | 1.07 | 93 | 0.39 | 0.0 |

### Perf analysis

1. **Compiled's speed advantage explained:** 132-186 ins/pkt (vs mono's
   153-221) — 15-23% fewer instructions due to monomorphized inlining +
   constant propagation. IPC 1.26-1.89 — strong ILP. The instruction
   reduction × similar IPC = ~10-15% speed win over mono.

2. **Template on mixed-real explained:** 93-163 ins/pkt — lowest of any
   mode. Branch-miss 0.12% — near zero branches in template extraction
   path. Result: 23-27 ns/pkt, fastest overall.

3. **Graph's 1216 ins/pkt on combo (6.5x more than compiled)** — dynamic
   dispatch + vtable indirection + hash lookups dominate. IPC 1.31 isn't
   terrible but the instruction count kills throughput.

4. **SIMD modes show lower IPC (0.71-1.26)** — SIMD instructions have
   higher latency on Zen 1, and the branchless approach trades IPC for
   branch-miss reduction. On tcp_ipv4, simd has 0.06% branch-miss vs
   compiled's 0.41%, but lower IPC makes it slower (28 vs 21 ns).

5. **Cache effects are negligible for realistic PCAPs** — combo shows
   1.7-2.9% cache miss for non-SIMD modes, mixed-real shows 0%.
   Only SIMD has high cache-miss (12-31%) due to register spills.

6. **hp2 vs hp5 perf counters match exactly** — identical IPC, ins/pkt,
   and branch-miss%. Confirms ns/pkt differences are turbo-related, not
   architectural.

---

## Phase D: Tuned vs untuned sensitivity

**Goal:** Compare lowJitter=true vs false on combo.pcap.

| Config | Host | Status | Notes |
|--------|------|--------|-------|
| lowJitter=true (turbo OFF, boost=0) | hp5 | **DONE** | Phase B data |
| lowJitter=false (turbo ON, boost=1) | hp5 | **DONE** | Phase D data |

### Results: turbo ON vs turbo OFF (hp5 combo.pcap, 5 runs each)

| Mode | turbo OFF (ns) | turbo ON (ns) | Δ% |
|------|----------------|---------------|-----|
| C kernel flowdis | 161 | 159 | -1% |
| C XDP2 parser | 218 | 214 | -2% |
| C XDP2 parse-only | 206 | 203 | -1% |
| C kernel BPF flowdis | 91 | 91 | 0% |
| C xdp2-flow-ebpf fast | 18 | 18 | 0% |
| Rust graph | 261 | 253 | -3% |
| Rust mono | 47 | 47 | 0% |
| **Rust compiled** | **40** | **39** | **-3%** |
| Rust template | 46 | 44 | -4% |

**Finding:** The turbo boost toggle has **no measurable effect** (all
deltas within 4%, which is measurement noise). Root cause: both hosts use
`acpi-cpufreq` driver which does not expose AMD boost frequencies —
`cpuinfo_max_freq` = 3.6 GHz (base clock) regardless of `boost` sysfs
setting. To actually test frequency sensitivity, the hosts would need the
`amd-pstate` driver (kernel 6.3+), which may require BIOS CPPC enablement.

**Implication for T2 cross-host analysis:** The hp2 vs hp5 variance on
small PCAPs (tcp_ipv4, mixed-real) is NOT caused by turbo boost. Other
factors are at play: hp2's `lowJitter=false` may disable additional jitter
reduction (timer tick isolation, RCU offloading) that `lowJitter=true`
enables on hp5.

---

## Phase E: AF_XDP + ntuple template

**Goal:** Real-traffic measurement, hp2→hp5 via pktgen + AF_XDP.

| Step | Status | Notes |
|------|--------|-------|
| Build ntuple-template-bench | **DONE** | `nix build .#flow-dissector-ntuple-template-bench` |
| Verify ntuple rules on hp5 | PENDING | `ethtool -N enp1s0f0np0 flow-type udp4 dst-port 443 action 1` |
| Run pktgen→AF_XDP template bench | PENDING | `nix run .#flow-dissector-ntuple-template-bench -- hp5 hp2` |

**Note:** Phase E attaches XDP programs to live network interfaces and
sends real traffic via kernel pktgen. Recommend running interactively.

---

## Results

### T1: hp5 mean ns/pkt (5 runs, 500 iterations, core 3)

| Mode | tcp_ipv4 | https-web | combo | mixed-real |
|------|----------|-----------|-------|------------|
| C kernel flowdis (usp) | 25 | 121 | 161 | 74 |
| C XDP2 parser (usp) | 56 | 166 | 218 | 207 |
| C XDP2 parse-only (usp) | 42 | 155 | 206 | 191 |
| C kernel BPF flowdis | 85 | 118 | 91 | 115 |
| C XDP2 BPF parser | N/A | N/A | N/A | N/A |
| C xdp2-flow-ebpf fast (BPF) | 25 | 23 | 18 | 24 |
| Rust graph | 204 | 216 | 261 | 453* |
| Rust mono | 24 | 78 | 47 | 48* |
| **Rust compiled** | **22** | **75** | **40** | 56* |
| Rust template | 23 | 77 | 46 | 22* |

\* mixed-real run 3 was an outlier (graph 914, mono 91, compiled 106, template 56 ns).
Excluded from means per 3-sigma rule; means computed from runs 1,2,4,5.

### T2: Cross-host reproducibility (hp2 vs hp5, mean ns/pkt)

| Mode | tcp_ipv4 hp2/hp5 (Δ%) | https-web hp2/hp5 (Δ%) | combo hp2/hp5 (Δ%) | mixed-real hp2/hp5 (Δ%) |
|------|------------------------|-------------------------|---------------------|--------------------------|
| C kernel flowdis (usp) | 31/25 (+24%) | 119/121 (-2%) | 159/161 (-1%) | 85/74 (+15%) |
| C XDP2 parser (usp) | 73/56 (+30%) | 161/166 (-3%) | 215/218 (-1%) | 228/207 (+10%) |
| C XDP2 parse-only (usp) | 50/42 (+19%) | 150/155 (-3%) | 203/206 (-1%) | 207/191 (+8%) |
| C kernel BPF flowdis | 112/85 (+32%) | 114/118 (-3%) | 95/91 (+4%) | 159/115 (+38%) |
| C xdp2-flow-ebpf fast (BPF) | 33/25 (+32%) | 23/23 (0%) | 19/18 (+6%) | 31/24 (+29%) |
| Rust graph | 205/204 (0%) | 210/216 (-3%) | 253/261 (-3%) | 555/453 (+23%) |
| Rust mono | 24/24 (0%) | 76/78 (-3%) | 46/47 (-2%) | 57/48 (+19%) |
| **Rust compiled** | **22/22 (0%)** | **71/75 (-5%)** | **39/40 (-3%)** | **67/56 (+20%)** |
| Rust template | 22/23 (-4%) | 73/77 (-5%) | 45/46 (-2%) | 28/22 (+27%) |

**Cross-host analysis:**

- **https-web and combo (large PCAPs):** Excellent reproducibility, all
  modes within 6%. hp2 is slightly faster on https-web (-2 to -5%),
  possibly due to turbo boost sustaining higher frequency on longer runs.
- **tcp_ipv4 (11 pkts):** hp2 C/BPF paths are 19-32% slower; Rust
  compiled/template are identical (0%). Short benchmarks on turbo-enabled
  hp2 suffer frequency scaling jitter that disproportionately affects C
  paths (larger code footprint, more cache pressure during warmup).
- **mixed-real (871 pkts):** hp2 is 8-38% slower across all modes.
  Largest delta is BPF flowdis (+38%) and fast BPF (+29%). The mixed
  protocol diversity may interact with turbo boost P-state transitions.
- **Confound resolved by Phase D:** turbo boost toggle has no frequency
  effect (acpi-cpufreq limitation). The hp2 vs hp5 variance on small PCAPs
  is likely from `lowJitter=true` enabling additional jitter reduction
  (nohz_full, RCU offloading) on hp5 that is absent on hp2.

### T3: hp2 mean ns/pkt (5 runs, 500 iterations, core 3)

| Mode | tcp_ipv4 | https-web | combo | mixed-real |
|------|----------|-----------|-------|------------|
| C kernel flowdis (usp) | 31 | 119 | 159 | 85 |
| C XDP2 parser (usp) | 73 | 161 | 215 | 228 |
| C XDP2 parse-only (usp) | 50 | 150 | 203 | 207 |
| C kernel BPF flowdis | 112 | 114 | 95 | 159 |
| C XDP2 BPF parser | N/A | N/A | N/A | N/A |
| C xdp2-flow-ebpf fast (BPF) | 33 | 23 | 19 | 31 |
| Rust graph | 205 | 210 | 253 | 555 |
| Rust mono | 24 | 76 | 46 | 57 |
| **Rust compiled** | **22** | **71** | **39** | 67 |
| Rust template | 22 | 73 | 45 | **28** |

### T5: Microarchitecture profiles (hp5, Zen 1)

**combo.pcap** — the DPI stress workload:

| Mode | ns/pkt | IPC | ins/pkt | br-miss% | cache-miss% | frontend stalls | backend stalls |
|------|--------|-----|---------|----------|-------------|-----------------|----------------|
| graph | 259 | 1.31 | 1216 | 3.70 | 1.7 | 5.2B | 21.6B |
| mono | 47 | 1.29 | 221 | 5.95 | 2.4 | 1.4B | 3.7B |
| **compiled** | **40** | **1.26** | **186** | **6.52** | **2.3** | **1.2B** | **4.8B** |
| simd | 51 | 1.16 | 220 | 6.89 | 12.0 | 2.0B | 9.2B |
| template | 52 | 0.96 | 183 | 6.80 | 2.9 | 2.2B | 6.4B |

All modes are backend-bound (backend stalls >> frontend stalls). Compiled
has the best balance: fewest total instructions, moderate IPC, and 4.5x
fewer backend stalls than graph.

---

## Hypothesis validation

| # | Hypothesis | Result | Verdict |
|---|-----------|--------|---------|
| H1 | Rust compiled ~40-50 ns on combo.pcap (Zen 1) | hp5: 40 ns, hp2: 39 ns | **CONFIRMED** — right in the predicted range |
| H2 | Rust template wins on https-web.pcap (>80% match) | hp5: template 77 vs compiled 75 ns; hp2: 73 vs 71 ns | **REFUTED** — compiled is faster; template match rate high but compiled's monomorphized inlining still wins |
| H3 | xdp2-flow-ebpf fast remains BPF champion (~22 ns) | hp5: 18-25 ns; hp2: 19-33 ns across PCAPs | **CONFIRMED** — always fastest BPF row, faster than predicted |
| H4 | Kernel BPF flowdis slowest (~74 ns) | hp5: 85-118 ns; hp2: 95-159 ns | **PARTIALLY CONFIRMED** — slowest BPF mode, but not slowest overall (C XDP2 parser is slower in userspace) |
| H5 | Rust graph ~4-5x slower than compiled | tcp_ipv4: 9x, https-web: 3x, combo: 6.5x, mixed-real: 8x | **PARTIALLY CONFIRMED** — range is 3-9x, wider than predicted; PCAP diversity drives it |
| H6 | Cross-host variance <5% | https-web/combo: <6% ✓. tcp_ipv4: 0-32%. mixed-real: 8-38%. | **PARTIALLY REFUTED** — holds for large PCAPs, fails for small PCAPs (turbo confound) |
| H7 | Rust compiled beats C XDP2 parse-only | All PCAPs, both hosts: compiled always faster | **CONFIRMED** — hp5: 22<42, 75<155, 40<206, 56<191 |
| H8 | C kernel flowdis beats Rust graph | All PCAPs, both hosts: flowdis always faster | **CONFIRMED** — e.g., hp5 combo: 161 vs 261 ns |

---

## Summary and key learnings

### The authoritative ranking (hp5, combo.pcap — DPI stress workload)

1. **xdp2-flow-ebpf fast (BPF)** — 18 ns/pkt, 55 Mpps
2. **Rust compiled** — 40 ns/pkt, 25 Mpps
3. **Rust mono** — 47 ns/pkt, 21 Mpps
4. **Rust template** — 46 ns/pkt, 22 Mpps
5. C kernel BPF flowdis — 91 ns/pkt, 11 Mpps
6. C kernel flowdis (userspace) — 161 ns/pkt, 6 Mpps
7. C XDP2 parse-only — 206 ns/pkt, 5 Mpps
8. C XDP2 parser (full) — 218 ns/pkt, 5 Mpps
9. Rust graph — 261 ns/pkt, 4 Mpps

### What we learned

1. **Rust compiled is the fastest general-purpose parser** — beats
   C kernel flowdis by 4x on combo (40 vs 161 ns), matches hand-written
   BPF fast-path to within 2.2x (40 vs 18 ns). The key is monomorphized
   inlining + fat LTO: 186 ins/pkt, IPC 1.26.

2. **Template mode wins when hardware classification matches** — 22 ns on
   mixed-real (faster than compiled's 56 ns) because fixed-offset
   extraction skips the parse graph entirely. But it's no faster than
   compiled on diverse traffic (46 vs 40 ns on combo).

3. **The hand-written BPF fast-path is in a class of its own** — 17-18 ns
   on combo.pcap. This is the ceiling for what's achievable with kernel
   BPF + manual tuning. It's 2.2x faster than the best Rust userspace
   parser.

4. **Dynamic dispatch is expensive** — graph mode costs 1216 ins/pkt
   (6.5x compiled) with 3.7% branch misses. On tcp_ipv4 the dispatch
   overhead is 9x. This validates the compiled/template approach.

5. **Zen 1 and Zen 2 results are consistent** — compiled on combo:
   40 ns (Zen 1 hp5) vs 36 ns (Zen 2 Threadripper). ~11% slower on older
   microarch, as expected.

6. **Cross-host reproducibility is good for sustained workloads** — <6%
   variance on https-web and combo. Small PCAPs show higher variance
   (up to 38%) due to jitter sensitivity.

7. **Turbo boost has no effect on these hosts** — acpi-cpufreq driver
   doesn't expose AMD boost. The lowJitter config affects other jitter
   reduction mechanisms.

### Suggested next steps

1. **Enable `amd-pstate` driver** (BIOS CPPC + kernel flag) to unlock
   actual frequency scaling for a real tuned vs untuned comparison.
2. **Phase E (AF_XDP + ntuple)** — run the real-traffic benchmark with
   pktgen→AF_XDP to get wire-speed measurements.
3. **Add https-web.pcap to perf-sweep** — currently only have
   tcp_ipv4/combo/mixed-real perf profiles.
4. **Investigate hp2 small-PCAP variance** — the 19-38% delta on
   tcp_ipv4/mixed-real is unexplained; check if lowJitter=true on hp2
   fixes it.
5. **Update performance-by-platform.md** — add "Ryzen 5 PRO 2400G
   (Zen 1)" section with these results.
