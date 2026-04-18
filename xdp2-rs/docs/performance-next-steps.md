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

## Missing data (collect before Tier 2+)

The `perf-sweep-tcp` run only gathered `basic` + `zen` counters. `stalls` and
`detail` passes failed with "No such file or directory" on the Zen 2 desktop.
Before picking optimizations blindly, we need **TMA Level 1**
(frontend-bound vs backend-bound vs bad-speculation vs retiring) to know
*why* the hot functions are slow.

Options:
1. Fix the stalls/detail sweep — investigate `perf_event_paranoid`, Zen 2 PMU
   event name differences, or xdp2-bench perf-pass implementation.
2. Add a dedicated TMA collection step: `perf stat -M TopdownL1 -- xdp2-bench …`

Without TMA, we're guessing. With it we'll know whether to chase icache
misses, branch mispredicts, load-latency, or port contention.

---

## Ranked next steps

### Tier 1 — cheap, high-confidence wins

1. **BOLT on top of PGO.** PGO already delivered +14-30%. BOLT (post-link
   binary layout optimization) typically adds another +5-10% on tight code
   paths. Requires building with a recent LLVM; add `nix/bolt-build.nix`
   target and plumb through.

2. **Prefetch next packet.** `_mm_prefetch` on `pkt[i+1]` while parsing
   `pkt[i]`. Benchmark-only loops should see big wins; real gains depend on
   NIC ring layout (relevant when X710 arrives).

3. **Collect stalls/detail/TMA data.** See "Missing data" above.

### Tier 2 — targeted micro-opts on the visible hotspots

4. **`parse_ip_check`** (15% of compiled) — if this is IP header checksum
   computation, most production deployments get this from NIC offload. Add
   a `--trust-csum` / `--skip-ip-check` flag and measure. Could shave
   10-15% off compiled immediately.

5. **`dispatch_ipv4`** (14%) — look at the assembly: is the `match proto`
   a cmov chain or jump table? A 256-entry LUT keyed on the 8-bit proto
   is branch-free; may or may not be faster depending on icache footprint
   vs branch prediction success.

6. **`parse_gre`** (12%) — GRE flag-field expansion is bit-manipulation
   heavy; check for `popcnt`/`pdep` (BMI2) opportunities.

7. **`classify_ipv4` / `classify_gre2`** in template — these are mini
   protocol classifiers. SIMD byte-compare on the first 16-32 bytes can
   collapse multiple sequential branches.

### Tier 3 — architectural bets (bigger effort)

8. **Batched parsing API.** Process N packets in an outer loop with
   interleaved prefetch. Only pays off at DPDK/AF_XDP batch sizes, but
   that's the direction we're heading.

9. **Graph-mode specialization.** The 13× gap graph→compiled is the
   dyn-dispatch tax. If any production use case needs the graph mode's
   flexibility, an `enum`-dispatched variant (not `dyn Trait`) would
   close most of the gap without giving up runtime composition.

10. **Per-protocol criterion micro-benchmarks.** Isolate each protocol
    parser so regressions show up per-parser, not only in the aggregate
    sweep.

### Tier 4 — defer until X710 hardware is available (~mid-April 2026)

11. NIC-side offloads (RSS, ntuple filters, checksum offload) change the
    baseline completely.
12. AF_XDP zero-copy changes the memory access pattern.
13. Cache behavior on a real rx ring is different from a hot pcap buffer
    in L1.

---

## Execution order

1. **Tier 1 item 3** (collect TMA data) — always run analysis before optimization.
2. **Tier 2 item 4** (`parse_ip_check` audit) — highest-confidence single change
   based purely on the flamegraph.
3. **Tier 1 item 1** (BOLT) — infrastructure work, amortizes over everything
   after it.
4. Whichever of items 5-7 the TMA data prioritizes.
5. Defer items 8-13 for now.

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
