# Adversarial Benchmark Suite — Stress-Testing the 4x Claim

## Context

Phase A-D benchmarks (see [`flow-dissector-benchmark-implementation.md`](./flow-dissector-benchmark-implementation.md))
show the Rust compiled parser at **40 ns/pkt** vs the C kernel flow
dissector at **161 ns/pkt** on combo.pcap — a 4x speedup on identical
Zen 1 hardware (hp2/hp5, AMD Ryzen 5 PRO 2400G).

This is a bold claim. Before presenting it to the kernel community, we
need to find and document every weakness, bias, and fairness gap in the
comparison. The goal is not to inflate the numbers but to produce
results a skeptical kernel reviewer would accept.

### What a kernel reviewer will challenge

- "Your benchmark PCAP excludes packets my parser handles."
- "You're comparing different amounts of work per packet."
- "What about protocol X that we support and you don't?"
- "4x seems unrealistic — what are you NOT measuring?"
- "What happens with real production traffic, not synthetic?"
- "What's the worst-case per-packet latency?"

Each experiment below is designed to preemptively answer one of these.

---

## Known fairness problems in the current comparison

| # | Problem | Impact |
|---|---------|--------|
| 1 | **Pre-filter bias** — 11% of combo.pcap excluded because Rust can't parse them. C benchmark only sees the "easy" set. | Flatters both sides, but hides Rust's coverage gaps. |
| 2 | **Metadata work gap** — C benchmark registers only 9 of 27 dissector keys. Rust doesn't extract TCP flags, IP TTL/TOS, or separate outer/inner tunnel keys. Both sides doing less work than production. | Comparison is "4x faster at partial extraction" not "4x faster at full flow dissection." |
| 3 | **MPLS correctness gap** — Rust reads first label and stops (`graph_compiled.rs:680-691`). Kernel walks the entire label stack to find inner IP headers. Rust is "faster" because it does less. | Invalid comparison for MPLS traffic. |
| 4 | **Tunnel depth safety** — Compiled mode resets depth to 0 on VXLAN/Geneve entry (`graph_compiled.rs:467/484/546/606`), creating unbounded recursion. Graph mode correctly bounds via `max_encaps`. | Safety bug in compiled mode; mode divergence. |
| 5 | **Synthetic traffic distribution** — combo.pcap has uniform protocol distribution across 1371 unique stacks. Real traffic is Zipfian — 80%+ is TCP/IPv4. Kernel code paths are optimized for common traffic. | Combo.pcap may exaggerate Rust's advantage on rare protocols. |
| 6 | **No tail latency data** — Only mean ns/pkt reported. No P99, P99.9, or per-packet distribution. | Hides bimodal behavior (simple vs complex packets). |

---

## Experiments

### E1: Pre-filter bias quantification

**Priority**: P0 (must-do before any claims)
**Effort**: 0.5 day
**Challenge answered**: "Your PCAP excludes packets I handle."

**Goal**: What protocols does the 11% excluded set contain? Does the
kernel handle them?

**Method**:
1. Generate complement PCAP: packets in combo.pcap NOT in the filtered
   output that `xdp2_rs_matrix.sh` produces
2. Run `xdp2-bench --chain-histogram` on the complement to classify
   rejected packets by protocol chain
3. Run C kernel flowdis benchmark on the complement alone
4. Report: what percentage does C successfully parse that Rust rejects?
5. For each chain where C succeeds and Rust rejects: document as a
   coverage gap with protocol name and packet count

**Expected outcome**: Most rejected packets are L2-leaf protocols
(LLDP, PTP, CFM, EtherCAT, MACsec) that the kernel flow dissector also
fails on (no `FLOW_DISSECTOR_KEY_BASIC` match). Some may reveal real
gaps — protocols the kernel handles but Rust treats as `UnknownProto`.

**Files**:
- `samples/flow_dissector/xdp2_rs_matrix.sh` (pre-filter at lines
  102-107)
- `samples/flow_dissector/gen_test_pcap.py` (combo generation logic)

---

### E2: Metadata completeness audit

**Priority**: P0
**Effort**: 1 day
**Challenge answered**: "You're comparing different amounts of work."

**Goal**: Document exactly what each parser extracts per packet, and
measure performance when both do equivalent work.

**Method**:

1. Enumerate all 27 `FLOW_DISSECTOR_KEY_*` types the kernel supports.
2. Map each to the corresponding Rust `FlowMeta` field
   (`xdp2-rs/crates/xdp2-bench/src/flow_meta.rs`).
3. Produce the equivalence table:

| Kernel key | Rust FlowMeta field | Present? |
|------------|-------------------|----------|
| CONTROL | addr_type, is_fragment, first_frag, l2/l3/l4_off | Yes |
| BASIC | eth_proto, ip_proto | Yes |
| IPV4_ADDRS | addrs.v4_src/v4_dst | Yes |
| IPV6_ADDRS | addrs.v6_src/v6_dst | Yes |
| PORTS | ports.src_port/dst_port | Yes |
| FLOW_LABEL | flow_label | Yes |
| ARP | arp.* | Yes |
| TIPC | addrs.tipc_key | Yes |
| GRE_KEYID | keyid | Yes |
| VLAN | vlan[0] | Yes |
| CVLAN | vlan[1] | Partial |
| MPLS | mpls.* (first label only) | Partial |
| TCP (flags) | — | **No** |
| IP (tos, ttl) | — | **No** |
| ICMP | icmp.* | Yes |
| ETH_ADDRS | eth_addrs | Yes |
| ENC_KEYID | keyid (overwritten by inner) | **Partial** |
| ENC_IPV4_ADDRS | — (overwritten) | **No** |
| ENC_IPV6_ADDRS | — (overwritten) | **No** |
| ENC_CONTROL | — | **No** |
| ENC_PORTS | — (overwritten) | **No** |
| ENC_IP | — | **No** |

4. Add missing keys to C benchmark
   (`samples/flow_dissector/benchmark.c` lines 85-93): VLAN, CVLAN,
   MPLS, TCP, IP, ICMP, ETH_ADDRS, all ENC_*.
5. Re-run unified matrix with full key set vs minimal key set.
6. Report the delta: how much does enabling full keys slow the kernel?

**Deliverable**: "The kernel with 9 keys: X ns. With 27 keys: Y ns.
Rust extracts Z equivalent fields. The fair comparison is Rust (Z
fields) vs kernel (Z-equivalent keys): N× speedup."

---

### E3: MPLS and tunnel correctness gap

**Priority**: P0
**Effort**: 0.5 day
**Challenge answered**: "Your parser doesn't even extract inner headers
for MPLS."

**Goal**: Quantify where the Rust parser does strictly less work than the
kernel, making any performance comparison invalid for those protocols.

**Method**:
1. **MPLS**: Generate Eth/MPLS(N labels)/IPv4/TCP packets for
   N = 1, 2, 4, 8, 16, 32. Compare outputs:
   - Kernel: walks stack, extracts inner src/dst IP + ports
   - Rust compiled (`graph_compiled.rs:680-691`): reads first label
     metadata, stops. Inner headers not extracted.
   - Document: "Rust is O(1), kernel is O(N), but Rust extracts less."
2. **VXLAN nesting**: Generate packets with 1, 2, 4, 8, 12, 16 layers
   of VXLAN nesting.
   - Compiled mode: resets depth to 0 each layer (line 467), will
     recurse all layers regardless of `MAX_DEPTH`.
   - Graph mode: respects `max_encaps`, stops at configured limit.
   - Document the divergence depth and whether compiled mode can
     stack-overflow (estimate: 16 layers × ~100B stack frame = 1.6KB,
     safe; but 128 layers = 12.8KB, still under 8MB default).
   - Flag as **safety issue**: compiled mode should respect depth.
3. **Inner vs outer keys**: For VXLAN(Eth/IPv4/TCP) packets, compare:
   - Kernel: extracts outer src/dst IP in `ENC_IPV4_ADDRS`, inner in
     `IPV4_ADDRS`, both ports.
   - Rust: overwrites outer with inner (single `FlowMeta.addrs`).

**Deliverable**: Correctness equivalence matrix per protocol showing
what each parser returns.

---

### E4: Adversarial PCAP suite

**Priority**: P1
**Effort**: 2 days
**Challenge answered**: "What about edge cases?"

**Goal**: Find traffic patterns where C kernel flowdis beats Rust
compiled mode, or where the difference is minimal.

Generate 100K packets per scenario. Benchmark all implementations via
unified matrix.

| Scenario | What it stresses | Where Rust might lose |
|----------|-----------------|----------------------|
| **Max IPv4 options** (IHL=15, 40B options + TCP) | Variable header length | Cache line split on 60B IP header, bounds check cost |
| **Deep IPv6 EH chains** (1/2/4/8 extensions) | Per-EH dispatch loop | `match` overhead per extension in compiled mode |
| **MPLS 32-label stack** | Stack walk depth | N/A — Rust does O(1), invalid perf comparison |
| **VXLAN 8-16 layers** | Recursion depth, code footprint | Unbounded recursion in compiled; graph stops at max_encaps |
| **Branch-miss maximizer** (alternating 6 protocol types) | BTB pollution | Compiled's large monomorphized match tables |
| **ARP flood** (100% ARP) | Minimal parse work | `FlowMeta::default()` ~220B memset dominates at <10ns parse |
| **Unknown ethertype** (0xDEAD) | Early-stop fast path | Both fast; measures bail-out overhead |
| **14-byte minimum Ethernet** | Edge-case bounds checking | Rust copies 12B MAC + reads ethertype even for unknown |

**Key hypothesis**: ARP flood and minimum Ethernet are candidates where
C wins — when parse work is trivial (~5 ns), Rust's larger `FlowMeta`
memset (~220B vs C's ~200B `flowdis_all_keys`) becomes the bottleneck.

**Implementation**: Extend `gen_test_pcap.py` with `--adversarial`
flag and per-scenario generators. Add Nix targets for each scenario
PCAP.

---

### E5: Production-realistic workloads at scale

**Priority**: P1
**Effort**: 2 days
**Challenge answered**: "Real traffic isn't uniform. What happens with
Zipfian distributions?"

**Goal**: Test with realistic traffic mixes at 1M+ packet scale.

**Method**:
1. Generate 1M-packet versions of existing workload profiles
   (`gen_workload_pcap.py`):
   - **https-web**: 80% TCP/443 + 10% TCP/80 + 5% DNS + 5%
     ARP/ICMP/other
   - **k8s-microservices**: 40% VXLAN-encapsulated gRPC + 30%
     direct TCP + 20% IPIP + 10% other
   - **nfs-server**: 55% TCP/2049 + 30% client TCP + 15% DNS/other
2. Run `xdp2-bench --chain-histogram` to verify Zipfian shape
3. Run unified matrix on each workload, both hosts, 5 runs
4. Compare with combo.pcap results to quantify distribution effect

**Expected**:
- **https-web** (homogeneous TCP/IPv4): Both parsers benefit from
  branch prediction. Rust advantage shrinks to ~2-3x because kernel's
  TCP/IPv4 hot path is well-optimized and cache-warm.
- **k8s-microservices** (tunnel-heavy): Rust advantage grows because
  kernel tunnel handling (STOP_AT_ENCAP flag, outer+inner key
  separation) is expensive.
- **nfs-server** (port-concentrated): Similar to https-web.

---

### E6: Tail latency distribution

**Priority**: P1
**Effort**: 2 days
**Challenge answered**: "What's the worst-case per-packet time?"

**Goal**: Report P50, P90, P95, P99, P99.9, P99.99, and max latency per
packet for both parsers.

**Method**:
1. Add per-packet `rdtsc` timing to xdp2-bench:
   - Use fenced `rdtscp` (~2 cycles overhead per measurement)
   - Store delta-cycles per packet in pre-allocated `Vec<u32>`
   - Post-process: convert to nanoseconds using TSC frequency
2. Correlate worst-case packets with protocol chain (which protocols
   trigger the longest parse path?)
3. Run on combo.pcap (diverse) and https-web (homogeneous)
4. Instrument C benchmark with equivalent per-packet rdtscp timing
5. Plot latency CDF for both parsers on same chart

**Deliverable**: Percentile table + CDF chart. List of protocol chains
that dominate P99+ tail.

---

### E7: Sustained workload (1-hour run)

**Priority**: P2
**Effort**: 1 day
**Challenge answered**: "Does performance hold up over time?"

**Goal**: Detect cache/TLB degradation or thermal effects over sustained
operation.

**Method**:
1. Run `xdp2-bench --iterations 1000000` on combo.pcap
   (~1 hour wall time with 445K packets × 1M iterations)
2. Use `perf stat -I 10000` to sample cache/TLB miss rates every
   10 seconds throughout the run
3. Compare first-minute vs last-minute ns/pkt
4. Run with a cache-polluting co-tenant on an adjacent core
   (streaming read of 100MB buffer) to simulate multi-tenant contention

**Expected**: No degradation for isolated runs — working set fits in
L2. With contention, compiled mode's ~20KB hot path should suffer less
L1i eviction than graph mode's ~200KB.

---

### E8: Multi-threaded scaling

**Priority**: P2
**Effort**: 1 day
**Challenge answered**: "Does it scale?"

**Goal**: Verify linear scaling for both parsers (1-8 threads on 4c/8t).

**Method**:
1. `xdp2-bench --threads 1,2,4,8` with core pinning to isolated set
   (cores 2-7)
2. Measure per-thread ns/pkt and aggregate Mpps
3. Check for false sharing via `perf c2c` if available on Zen 1
4. For C benchmark: run multiple instances on disjoint packet slices
   via `taskset`

**Expected**: Linear scaling for both — flow dissection is
embarrassingly parallel with no shared state. Rust's advantage should
remain constant across thread counts.

---

### E9: memset cost isolation

**Priority**: P2
**Effort**: 0.5 day
**Challenge answered**: "How much of the time is just zeroing memory?"

**Goal**: Quantify per-packet metadata zeroing cost.

**Method**:
1. Print `std::mem::size_of::<FlowMeta>()` in Rust and
   `sizeof(struct flowdis_all_keys)` in C
2. Add a "no-memset" mode: reuse metadata struct without re-zeroing
3. Benchmark with and without memset on tcp_ipv4.pcap (where parse time
   is lowest and memset fraction is highest)
4. Report memset contribution as percentage of total ns/pkt

**Expected**: At 22 ns/pkt (tcp_ipv4), a 220B memset costs ~5-8 ns
(23-36% of total). This is a structural cost that matters most for
simple packets.

---

### E10: Timing infrastructure validation

**Priority**: P2
**Effort**: 0.5 day
**Challenge answered**: "Are you sure your clocks are equivalent?"

**Goal**: Confirm C and Rust use equivalent timing mechanisms.

**Method**:
1. Verify: C uses `clock_gettime(CLOCK_MONOTONIC_RAW)`, Rust uses
   `std::time::Instant::now()` → `clock_gettime(CLOCK_MONOTONIC)`
2. Measure per-call overhead: tight loop, 1M iterations, both clocks
3. If material difference (>5 ns), add `CLOCK_MONOTONIC_RAW` option to
   Rust runner (`xdp2-rs/crates/xdp2-bench/src/runners.rs`)

**Expected**: Both use VDSO fast path on Linux x86_64. Per-call cost
~20-25 ns. Difference negligible relative to 40-161 ns parse times. But
`CLOCK_MONOTONIC_RAW` avoids NTP skew — matters for 1-hour sustained
runs (E7).

---

## Execution schedule

### Week 1 — Fairness audit (P0)

| Day | Experiment | Goal |
|-----|-----------|------|
| 1 | E1: Pre-filter bias | Quantify excluded packets |
| 1-2 | E2: Metadata audit | Equalize work comparison |
| 2 | E3: Correctness gaps | MPLS + tunnel equivalence |

### Week 2 — Adversarial + production (P1)

| Day | Experiment | Goal |
|-----|-----------|------|
| 3-4 | E4: Adversarial PCAPs | Find crossover points |
| 5-6 | E5: Production workloads | Zipfian traffic validation |
| 6-7 | E6: Tail latency | Per-packet distribution |

### Week 3 — Depth (P2)

| Day | Experiment | Goal |
|-----|-----------|------|
| 8 | E7: Sustained run | 1-hour stability |
| 9 | E8: Multi-threaded | Scaling validation |
| 9 | E9: memset cost | Structural overhead |
| 10 | E10: Timing validation | Clock equivalence |

---

## Deliverables

1. **Fairness report**: Pre-filter bias %, metadata equivalence table,
   correctness gap matrix (MPLS, tunnels, ENC_* keys)
2. **Adversarial results**: 8-scenario table showing where each parser
   wins, loses, or ties
3. **Production workload results**: 3 Zipfian workloads at 1M packets
   with chain-histogram verification
4. **Tail latency CDFs**: P50-P99.99 for both parsers on
   representative traffic
5. **Sustained/scaling results**: 1-hour stability, 1-8 thread scaling
   curves
6. **Honest claims table**: "Rust compiled is Nx faster than C kernel
   flowdis for [specific conditions with specific caveats]"

---

## Critical files

| File | Role |
|------|------|
| `xdp2-rs/crates/xdp2-bench/src/graph_compiled.rs` | Tunnel depth reset (467/484/546/606), MPLS leaf (680-691) |
| `xdp2-rs/crates/xdp2-bench/src/flow_meta.rs` | FlowMeta struct (122 lines) — metadata completeness audit target |
| `xdp2-rs/crates/xdp2-bench/src/runners.rs` | Timing infrastructure, thread pool |
| `samples/flow_dissector/benchmark.c` | C benchmark, key registration (lines 85-93) |
| `samples/flow_dissector/gen_test_pcap.py` | Combinatorial PCAP generator — extend for adversarial scenarios |
| `samples/flow_dissector/gen_workload_pcap.py` | Workload profiles — scale to 1M packets |
| `samples/flow_dissector/xdp2_rs_matrix.sh` | Unified matrix — pre-filter logic (lines 102-107) |
| `docs/flow-dissector-benchmark-implementation.md` | Results tracking document |

---

## Preliminary findings (E1 partial — pre-filter analysis)

### combo.pcap rejection breakdown

Full combo.pcap has 500,000 packets. The Rust parser's pre-filter
keeps 445,178 (89.0%) and rejects 54,822 (11.0%).

**Rejected packets by outer ethertype:**

| Ethertype | Full | Filtered | Rejected | Protocol | Why rejected |
|-----------|------|----------|----------|----------|-------------|
| 0x8100 | 250,007 | 222,112 | **27,895** | VLAN | Inner protocol not parseable |
| 0x88a8 | 113,458 | 100,955 | **12,503** | QinQ (802.1ad) | Inner protocol not parseable |
| 0x86dd | 34,624 | 29,814 | **4,810** | IPv6 | Unknown next-header protocol |
| 0x8864 | 14,430 | 12,506 | **1,924** | PPPoE | Inner protocol not parseable |
| 0x0800 | 31,728 | 29,804 | **1,924** | IPv4 | Unknown IP protocol number |
| (none) | 3,844 | 1,922 | **1,922** | Truncated/LLC | Too short or LLC framing |
| 0x4305 | 2,883 | 0 | **2,883** | Unknown (STP inner?) | Ethertype not in Rust dispatch table |
| 0x8035 | 961 | 0 | **961** | RARP | Not implemented in Rust |
| **Total** | **500,000** | **445,178** | **54,822** | | |

**Key observation**: The rejected packets are NOT exotic leaf protocols.
The leaf protocols (LLDP, PTP, CFM, LACP, etc.) are actually KEPT by
the Rust parser — they appear as `eth/eth-0xNNNN` chains in the
histogram. The rejected 54,822 packets are primarily:

1. **VLAN/QinQ/PPPoE wrappers around unsupported inner protocols**
   (42,322 packets, 77% of rejected) — the Rust parser enters the
   VLAN/QinQ/PPPoE envelope correctly but fails when the inner
   ethertype or IP protocol number doesn't match any dispatch entry.

2. **IPv4/IPv6 with unsupported transport protocols** (6,734 packets,
   12%) — e.g., IPv6 next-header values that aren't TCP/UDP/ICMP/
   SCTP/ESP/AH/L2TP/GRE.

3. **Ethertype 0x4305** (2,883 packets, 5%) — not in Rust's ethertype
   dispatch table at all.

4. **RARP (0x8035)** (961 packets, 2%) — Rust handles ARP (0x0806)
   but not RARP.

### Mode divergence finding

During the pre-filter step, one additional finding emerged:

```
Correctness: graph ok=445178/445178, mono ok=445178/445178,
             compiled ok=445177/445178, template ok=128859/445178
```

- **Compiled mode fails on 1 packet** that graph/mono handle
  successfully. This is a mode divergence bug.
- **Template mode matches 128,859/445,178** (28.9%) — the remaining
  71.1% fall back to compiled. This means template's fast path only
  applies to ~29% of combo.pcap's diverse traffic.

### What the kernel does with the rejected set

**Not yet measured.** Next step: run C kernel flowdis on the 54,822
rejected packets and report:
- How many does the kernel successfully parse?
- For which protocol chains does the kernel extract useful flow keys
  that Rust cannot?

---

## Gap analysis summary

### G1: Protocol coverage gaps (Rust parser)

| Gap | Impact | Packets affected (combo.pcap) | Fix complexity |
|-----|--------|-------------------------------|----------------|
| **RARP (0x8035)** | Coverage | 961 (0.2%) | Low — mirror ARP handler |
| **Ethertype 0x4305** | Coverage | 2,883 (0.6%) | Low — add dispatch entry |
| **VLAN/QinQ inner ethertypes** | Coverage | ~40K (8%) | Medium — identify which inners fail, add dispatch entries |
| **IPv6 unknown next-headers** | Coverage | ~4,800 (1%) | Medium — identify which NH values fail |
| **IPv4 unknown IP protocols** | Coverage | ~1,900 (0.4%) | Medium — identify which proto values fail |

### G2: Correctness gaps (less work than kernel)

| Gap | Impact | Where in code | Fix complexity |
|-----|--------|---------------|----------------|
| **MPLS first-label-only** | Correctness | `graph_compiled.rs:680-691` | High — need stack walk + inner IP dispatch |
| **Tunnel outer keys overwritten** | Correctness | `graph_compiled.rs:467` (VXLAN), 484 (Geneve) | High — need separate `ENC_*` fields in FlowMeta |
| **TCP flags not extracted** | Metadata | `flow_meta.rs` missing field | Low — add field + extractor |
| **IP TTL/TOS not extracted** | Metadata | `flow_meta.rs` missing field | Low — add field + extractor |

### G3: Safety issues

| Issue | Severity | Where in code | Fix complexity |
|-------|----------|---------------|----------------|
| **Compiled mode tunnel depth unbounded** | Medium | `graph_compiled.rs:467/484/546/606` — depth reset to 0 | Medium — propagate depth instead of resetting |
| **Compiled mode diverges from graph** on 1 packet | Low | Unknown packet — need to identify | Low — once identified |

### G4: Benchmark methodology gaps

| Gap | Impact | Fix complexity |
|-----|--------|----------------|
| **C benchmark registers 9/27 keys** | Kernel does less work than production | Low — add more `__FDK()` entries to `benchmark.c` |
| **Pre-filter excludes 11% of combo.pcap** | Comparison uses Rust-friendly subset | Medium — run C on both sets, report separately |
| **No tail latency (P99/P99.9)** | Hides worst-case per-packet behavior | Medium — add per-packet rdtsc timing |
| **No production traffic profiles** | Synthetic ≠ real Zipfian distributions | Medium — generate + run 1M-pkt workloads |
| **Single-threaded only** | Doesn't validate scaling claims | Low — xdp2-bench already supports `--threads` |
| **No sustained (1-hour) runs** | Can't rule out cache/thermal degradation | Low — just run longer |
| **Timing clock mismatch** | C: CLOCK_MONOTONIC_RAW, Rust: CLOCK_MONOTONIC | Low — verify VDSO overhead equivalence |

---

## Next steps (ordered)

### Immediate (no code changes needed)

1. **Run C kernel flowdis on full unfiltered combo.pcap** on hp5 to
   measure what the kernel extracts from the 54,822 rejected packets.
   Compare parse success rate vs the 445,178 filtered set.

2. **Identify the 1 compiled-mode divergence packet** — run xdp2-bench
   with debug output to find which packet in combo.pcap causes compiled
   mode to fail while graph succeeds.

3. **Measure `sizeof(FlowMeta)` and `sizeof(flowdis_all_keys)`** — print
   from code to quantify the memset cost difference.

4. **Run unified matrix on https-web.pcap (20K) at 1M scale** — the
   `gen_workload_pcap.py` script already supports this; just generate a
   larger PCAP and run.

### Code changes required (fix before next benchmark round)

5. **Add RARP (0x8035) support** — mirror the ARP handler in Rust
   dispatch table.

6. **Add missing FlowMeta fields** — `tcp_flags: u8`, `ip_tos: u8`,
   `ip_ttl: u8` with extractors in the TCP and IPv4 parse paths.

7. **Fix compiled mode tunnel depth** — propagate `depth` parameter
   through VXLAN/Geneve entry instead of resetting to 0.

8. **Add full key set to C benchmark** — register VLAN, CVLAN, MPLS,
   TCP, IP, ICMP, ETH_ADDRS, and ENC_* keys in `benchmark.c`.

### New infrastructure needed

9. **Adversarial PCAP generator** — extend `gen_test_pcap.py` with
   `--adversarial` mode for: max IPv4 options, deep IPv6 EH chains,
   MPLS stacks, deep VXLAN nesting, branch-miss maximizer, ARP flood.

10. **Per-packet latency mode** — add `--per-packet-timing` to
    xdp2-bench using rdtscp, output percentile table.

11. **Complement PCAP extractor** — tool to output packets that
    xdp2-bench rejects (complement of `--output-pcap`).

---

## Verification

After each experiment:
1. Raw data saved to `perf-results/adversarial/` with JSON reports
2. Results added to `docs/flow-dissector-benchmark-implementation.md`
3. Each finding tagged as one of:
   - **confirmed advantage** — Rust genuinely faster at equivalent work
   - **fairness correction needed** — comparison was unequal; corrected
     number is X
   - **coverage gap** — Rust doesn't handle this protocol/feature
   - **safety issue** — bug that needs fixing regardless of performance
