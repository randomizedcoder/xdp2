# Performance Next Steps — Post-Flamegraph Roadmap

Flamegraph-driven roadmap for the next round of optimization work. Companion
to [performance-optimization.md](./performance-optimization.md),
[performance-maximization-plan.md](./performance-maximization-plan.md), and
[deep-performance-analysis.md](./deep-performance-analysis.md).

Generated from the `mixed-real.pcap` run (828 pkts, 815 parseable — typical
Linux-box protocol mix: TCP/UDP/ICMP over IPv4/IPv6, VLAN/QinQ, GRE nested,
VXLAN, L2TP, IP-in-IP, 6in4, SRv6, fragments). Flamegraphs captured on core 3,
`perf -F 10000`, 5000 iterations.

Raw data: [`perf-results/flamegraphs-mixed/`](../../perf-results/flamegraphs-mixed/)
(SVGs + `hotfns.txt`).

---

## Current state (mixed-real.pcap, 815 parseable packets)

| Mode | ns/pkt | Mpps | Top hotspots |
|------|--------|------|--------------|
| graph | 300 | 3.3 | `engine::parse` 56% + dyn trait calls ~20% |
| compiled | 23 | 43 | `parse_ip_check` 15%, `dispatch_ipv4` 14%, `parse_gre` 12% |
| template | 17 | 58 | 99% inlined into `main`; `extract_gre2_ipv4_icmp` 7%, `classify_ipv4` 6% |

**Key insight:** compiled and template are no longer dominated by framework
overhead — they're dominated by actual protocol parsing work. Further
improvements need to attack the parsing work itself, not the dispatch
mechanism.

---

## TMA findings (collected 2026-04-17)

**Root cause for the earlier sweep failure:** Zen 2 exposes
`stalled-cycles-frontend` but *not* `stalled-cycles-backend`, and its generic
last-level-cache event is also missing. The `PerfCounters` setup was
all-or-nothing, so one missing counter aborted the whole pass. Fixed by
building counters individually and reporting missing ones as zero — see
`xdp2-rs/crates/xdp2-bench/src/perf.rs`.

Full 4-pass TMA results are saved at
[`perf-results/tma-mixed/full-4pass.txt`](../../perf-results/tma-mixed/full-4pass.txt).

| Mode | ns/pkt | IPC | Instructions/pkt | Branches/pkt | Branch-miss % | L1D miss/pkt | L1I miss/pkt | Retiring | Bad Spec | FE Bound | BE Bound |
|------|--------|-----|------------------|--------------|----------------|--------------|---------------|----------|----------|----------|----------|
| graph    | 274 | 1.84 | 2028 | 514 | 0.23 | 3.34 | 0.018 | **85.4%** | 3.0% | 11.6% | 0.0%* |
| compiled |  40 | 1.53 |  242 |  56 | 0.09 | 3.26 | 0.002 | **95.6%** | 1.2% |  3.2% | 0.0%* |
| template |  22 | 1.62 |  126 |  28 | 0.10 | 3.37 | 0.001 | **94.8%** | 1.3% |  3.9% | 0.0%* |

<sub>*Backend Bound reports 0% because `stalled-cycles-backend` is not exposed
on Zen 2. The true BE bound value is hidden inside the retirement number.</sub>

**What TMA tells us — this reshuffles priorities dramatically:**

1. **All three modes are retirement-bound, not stall-bound.** Frontend
   stalls are 1-6% of cycles; branch misses are <0.25%. There is almost
   no stall time to win back via icache, branch prediction, or TLB
   optimizations.
2. **Graph's 6.9× slowdown vs compiled is pure instruction count**:
   2028 vs 242 instructions/pkt, at roughly similar IPC. The dyn-dispatch
   vtable costs real uops, not stalls. BOLT and icache optimizations
   will do very little here — the win must come from eliminating
   instructions (enum dispatch, inlining vtable methods).
3. **Compiled at 95% retiring is already near its ceiling at this IPC.**
   Further gains require either fewer instructions per packet or more
   ILP. Branch-prediction improvements are out of scope (0.09% miss rate).
4. **IPC of 1.5-1.6 on compiled/template vs Zen 2's theoretical peak
   (~4-5)** suggests serial dependency chains in the hot loop. Restructuring
   to expose more ILP (load decoupling, independent parallel accumulators)
   is a candidate area.

This refines the roadmap below: **deprioritize BOLT and branchless tricks,
prioritize instruction-count reduction and ILP exposure.**

---

## Ranked next steps (after TMA)

### Tier 1 — instruction-count reduction (biggest expected payoff)

1. **`parse_ip_check` audit** (15% of compiled samples). If this is IP
   header checksum computation, it's pure uops we don't need in most
   production deployments (NIC offloads handle it). Add a
   `--trust-csum` / `--skip-ip-check` flag, measure the delta. Expected
   shave: 10-15% off compiled. **Start here** — highest confidence.

2. **Graph-mode dyn-dispatch elimination** (was Tier 3). At 2028
   instructions/pkt vs 242 for compiled, the win here is not 5-10% — it
   could be 5-6×. Replace `&dyn ParseNodeDyn` with an enum dispatch and
   measure. If the graph engine is still needed for runtime flexibility
   (proto_audit, experimentation), this is the biggest single-pass lever
   for that mode.

3. **`parse_gre` bit-manipulation** (12% of compiled). The GRE header
   flag-fields expansion uses byte-by-byte conditionals. `popcnt` +
   `pdep` (BMI2) collapses flag processing to a handful of instructions.
   Zen 2 supports both.

4. **`classify_ipv4` / `classify_gre2`** in template (6% + 3%). Sequential
   conditional chains deciding which template to use. A small LUT or SIMD
   byte-compare on the first 16 bytes can collapse these.

### Tier 2 — ILP improvement

5. **Decouple load chains in the hot loop.** IPC is 1.5-1.6 vs Zen 2's
   ~4-5 theoretical. Almost certainly serial dependency chains: load a
   header field → compute offset → load next field. Where safe, hoist
   loads to start before their result is needed. Needs assembly audit
   (`cargo-show-asm`) on the compiled-mode inner loop.

6. **Prefetch next packet.** `_mm_prefetch` on `pkt[i+1]` while parsing
   `pkt[i]`. Benchmark loops should see improvement; real gains depend on
   NIC rx-ring layout. Defer measurement until X710 is available.

### Tier 3 — deprioritized by TMA (may still be worth a try, later)

7. **BOLT on top of PGO.** Previously expected +5-10%. TMA shows
   frontend stalls are 1-6% of cycles and L1I misses are ~0.002/pkt on
   compiled — almost no icache pressure. BOLT's main lever is
   code-layout / icache, so the ceiling is probably closer to +1-3%.
   Keep on the list but not urgent.

8. **`dispatch_ipv4` LUT.** Previously flagged as a win, but branch miss
   rate is 0.09% — the predictor already nails it. A LUT adds a load
   without saving a stall. Skip unless the assembly audit shows a long
   cmov chain on the critical path.

### Tier 4 — defer until X710 hardware is available

9. **Batched parsing API.** Interleave N packets in the outer loop with
   prefetch. Only pays off at DPDK/AF_XDP batch sizes — the benchmark
   doesn't exercise this.
10. Per-protocol criterion micro-benchmarks.
11. NIC-side offloads (RSS, ntuple filters, checksum offload).
12. AF_XDP zero-copy rx path.

---

## Execution order

1. ✅ Collect TMA data (stalls/detail counter fix + 4-pass run on mixed PCAP).
2. ✅ **Tier 1 item 1 — `parse_ip_check` audit.** Result: **red herring.**
   The function is a 3-line IP-version dispatcher, not a checksum. Marking it
   `#[inline(always)]` did inline it (vanished from the flamegraph) but its
   samples just redistributed into `parse_ipv4` and `parse_gre` —
   throughput unchanged (23-28 ns/pkt compiled, within run-to-run noise).
   **Lesson: flamegraph attribution for small functions is unreliable.**
   The `#[inline(always)]` is kept as a cleanup.
3. ✅ Baseline for typical Linux traffic: ran flamegraph on pure TCP/IPv4
   (`tcp_ipv4.pcap`): compiled **13 ns/pkt / 73 Mpps**, template **14 ns/pkt**,
   graph **118 ns/pkt**. Hot functions for compiled mode are just
   `parse_ipv4` (10%) + `dispatch_ipv4` (7%) + `dispatch_ether` (3%) — this
   is already close to the instruction-count floor for the header fields we
   extract. Saved to `perf-results/tcp-only/`.
4. **Open decision:** Where to invest next? Three realistic options given
   the data:

   - **(a) Graph enum dispatch** — graph is 118 ns/pkt TCP-only vs 13 ns/pkt
     compiled, a 9× gap that's pure dyn-dispatch instruction overhead. If
     graph mode is on the production path (e.g. proto_audit, future dynamic
     parsers), this is by far the biggest absolute-cycles win available.
     **Highest payoff, most engineering effort.**
   - **(b) `parse_gre` BMI2/popcnt** — helps GRE-heavy workloads (DPI,
     overlay networks). Does nothing for the TCP/IPv4 baseline, which is
     already fast.
   - **(c) Template classifier LUT/SIMD** — template is already the fastest
     mode. Marginal gains for already-small numbers.

5. Tier 2 item 5 (ILP audit via `cargo-show-asm`) — always useful; IPC of 1.6
   suggests serial dependency chains somewhere, but targeted optimizations
   probably need to wait until we pick (a)/(b)/(c).
6. Re-evaluate Tier 3 (BOLT, LUT dispatch) only after above gains are booked
   or invalidated.

---

## How to reproduce the data backing this plan

```bash
nix run .#perf-flamegraph -- \
  $(nix build --no-link --print-out-paths .#perf-mixed-pcap)/mixed-real.pcap \
  5000 \
  perf-results/flamegraphs-mixed
```

See [deep-performance-analysis.md](./deep-performance-analysis.md) for the
full set of Nix perf targets.
