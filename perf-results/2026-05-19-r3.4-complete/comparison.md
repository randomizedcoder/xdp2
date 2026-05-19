# 2026-05-19 hp2/hp5 sweep — post-R3.4 results vs predictions

Run: 2026-05-19, smoke iteration count (100), 6 workloads across
hp2 + hp5, all 14 parsers per workload.

Build context: `merge/matrix-physical-testbed` @ `cd285b9`. The 14
commits since the 2026-05-17 R3.4.5a hp5 baseline are detailed in
`docs/r3.4-hp5-perf-targets.md`.

**Apples-to-apples caveat applies — read
`docs/r3.4-hp5-perf-targets.md#%EF%B8%8F-this-is-not-apples-to-apples`
before interpreting any single ns/pkt number across parser
families.** Different parsers populate different field sets and
walk to different depths. The numbers are useful as ceiling
indicators within a parser family, and the hp2/hp5 Δ is a valid
memory-bound vs compute-bound diagnostic — but cross-family ratios
mix efficiency with work.

## Prediction check (`docs/r3.4-hp5-perf-targets.md` predictions vs measured)

### https-web (predicted: c-xdp2-mono ≤ 75 ns/pkt; no regression)

✅ **PASS**: mono hp5 = 73 ns/pkt (baseline 71, predicted ≤75).

Within run-to-run noise — none of the 14 commits since 2026-05-17
regressed the TCP fast-path on the baseline workload.

### hp2 vs hp5 memory-speed delta (predicted: ≤3 % on TCP, 5–10 % on tunnel)

| workload | mono hp2 | mono hp5 | Δ (hp2-hp5)/hp5 | predicted | reading |
|---|---:|---:|---:|---:|---|
| https-web | 72 | 73 | -1 % | ≤3 % | ✅ compute-bound |
| nfs-server | 68 | 69 | -1 % | ≤3 % | ✅ compute-bound |
| k8s-microservices | 134 | 137 | -2 % | ≤3 % | ✅ compute-bound |
| vlan-tcp-mix | 70 | 70 | 0 % | ≤3 % | ✅ compute-bound |
| pppoe-isp | 76 | 72 | **+5 %** | ≤3 % | hp2 SLOWER — likely smoke-noise / NIC variance |
| vxlan-k8s-pure | 145 | 141 | **+3 %** | 5–10 % | hp2 SLOWER — still compute-bound, NOT memory-bound as predicted |

**Headline**: the parse loop stays firmly compute-bound across
every workload, including the deep tunnel walks. The Phase R6
metadata-write trimming the targets doc flagged as a possible
follow-up is **not yet justified** — there's no memory-bandwidth
ceiling to trim into.

The two cases where hp2 was *slower* than hp5 (PPPoE and VXLAN)
are within smoke-iteration noise (single replicate, 100
iterations). A full run with more replicates would tighten the
confidence intervals.

### New workloads (vlan-tcp-mix, pppoe-isp, vxlan-k8s-pure)

| workload | predicted mono hp5 | measured mono hp5 | reading |
|---|---:|---:|---|
| vlan-tcp-mix | 8–12 ns/pkt | **70 ns/pkt** | ❌ wildly off — see below |
| pppoe-isp | 10–14 ns/pkt | **72 ns/pkt** | ❌ wildly off |
| vxlan-k8s-pure | 20–30 ns/pkt | **141 ns/pkt** | ❌ wildly off |

**The prediction was wrong**, but for an interesting reason. The
local-workstation snapshot (`benchmark -M -n 100000` on a
100-packet pcap) showed mono at 6–7 ns/pkt because:

1. The 100-packet pcap fits entirely in L1 cache — every byte
   load is cache-hit.
2. 100K iterations × 100 packets = 10M parses with the same data,
   so branch predictors are fully warm.
3. The `benchmark` binary's loop has lower per-iteration overhead
   than the matrix runner's `xdp2-bench`.

On hp5 with the 20000-packet workload pcap × 100 iterations:
- The pcap data doesn't fit in L1 / mostly fits in L2
- Branch predictors warm up but not to the same degree
- xdp2-bench has additional bookkeeping per packet (timing,
  parity records, etc.)

Real perf is in the 70 ns/pkt range, NOT 7 ns/pkt. The targets
doc's local-snapshot extrapolation was off by ~10×. **The hp5
numbers are the authoritative reading.**

## What this run DOES tell us

### Mono fast-path effectiveness (TCP/IPv4 + chain variants)

| workload | mono hp5 | parse-only hp5 | mono speedup vs slow-path |
|---|---:|---:|---:|
| https-web | 73 | 131 | 1.8× |
| nfs-server | 69 | 126 | 1.8× |
| vlan-tcp-mix | 70 | 129 | 1.8× |
| pppoe-isp | 72 | 130 | 1.8× |

R3.4 fast-paths cut mono from ~130 ns/pkt (slow path) to ~70 ns/pkt
(fast path) — a consistent 1.8× speedup across all eth + L2-tag +
L3 + L4 chain shapes. The new R3.4.5b/c/d/e chains
(`vlan-tcp-mix`, `pppoe-isp`) match the original R3.4.1
(`https-web`) within 3 ns. **The chain set generalises.**

### Mono on tunneled workloads (correctness vs speed tradeoff)

| workload | mono hp5 | flowdis hp5 | mono - flowdis |
|---|---:|---:|---:|
| k8s-microservices (mixed) | 137 | 116 | **+21 ns slower** |
| vxlan-k8s-pure (pure tunnel) | 141 | 111 | **+30 ns slower** |

This is the cost of the bug fixes that landed in this branch. Pre-
fix, mono short-circuited at outer UDP via the (buggy) R3.4.1
fast-path and *appeared* faster than flowdis on tunneled traffic
— while emitting wrong inner metadata. After the fix:

- Mono walks the full inner stack (correct inner 5-tuple)
- flowdis stops at outer UDP (no inner extraction)
- Mono does measurably more work and is correctly measured as
  slower

**This is exactly the "Mode A vs Mode B" decomposition the
targets doc flagged as future work.** Kernel-team readers can't
fairly compare 141 ns (mono extracting inner) vs 111 ns (flowdis
extracting outer only). The equal-work bench is the right
follow-up.

### Other observations

- **rust-graph-enum looks artificially fast on non-IPv4 workloads**:
  28 ns/pkt on pppoe-isp, 29 ns/pkt on vlan-tcp-mix. These aren't
  efficient parsing — they're *fast rejections* (the parser
  doesn't support PPPoE / VLAN-ethertype so it returns at the
  first dispatch). The bench harness sees a sub-graph that handles
  100 % of these packets in ≤30 ns by NOT parsing them.

- **rust-mono / rust-compiled stay competitive with c-xdp2-mono**
  on most workloads (within 5–10 ns). On vxlan-k8s-pure, rust-mono
  93 vs c-xdp2-mono 141 — rust is faster on the full tunnel walk.
  Worth investigating: is rust's tunnel-walking implementation
  more efficient than the C generic engine's, or is rust extracting
  less inner-metadata?

- **c-bpf-fast at 17–24 ns/pkt** is the universal ceiling and
  represents the NIC-classified fast-path with hardware queue
  dispatch — the speed-of-light reference.

- **rust-graph at 263–462 ns/pkt** is the slowest by far. Dyn-
  dispatch overhead. Useful as a sanity baseline (R1.0 era), not
  as a competitive parser.

## Cross-comparison vs 2026-05-17 baseline

Same metric, hp5 column, https-web only (only workload covered
by the baseline):

| Mode | 2026-05-17 baseline | 2026-05-19 actual | Δ |
|---|---:|---:|---:|
| c-flowdis-usp | 119 | 117 | -2 |
| c-xdp2-usp | 135 | 133 | -2 |
| c-xdp2-parse-only | 135 | 131 | -4 |
| **c-xdp2-mono** | **71** | **73** | **+2 (noise)** |
| c-bpf-flowdis | 120 | 114 | -6 |
| c-bpf-fast | 23 | 23 | 0 |
| rust-graph | 274 | 263 | -11 |
| rust-graph-enum | 106 | 105 | -1 |
| rust-mono | 72 | 72 | 0 |
| rust-mono-x4 | 83 | 82 | -1 |
| rust-compiled | 73 | 72 | -1 |
| rust-simd | 42 | 41 | -1 |
| rust-template | 68 | 69 | +1 |
| rust-template-simd | 75 | 75 | 0 |

Most parsers shifted ±2 ns (noise). Two notable trends:

- **c-xdp2-parse-only: -4 ns** (135 → 131). Possibly the icmp_id
  sentinel alignment or the npi_simple bswap fix shaving a few
  cycles off the generic engine. Or noise. Hard to say with one
  replicate.
- **rust-graph: -11 ns** (274 → 263). Largest single delta. Likely
  noise but worth re-checking with more replicates.

No regressions worth flagging.

## Mono perf-ceiling gate

`mono-perf.md`: **0 violations** across 12 cells compared
(c-xdp2-mono ≤ c-xdp2-usp × 1.10). Mono is faster than the
generic engine on every workload, including tunneled.

## Next steps

1. **Run a non-smoke (full iteration count) hp2/hp5 sweep** to
   tighten the confidence intervals on the hp2 vs hp5 deltas.
   Smoke uses 100 iterations; the full run uses more replicates
   and the matrix aggregator reports ci95.

2. **Plan and build the equal-work + extras-cost bench** (Mode A
   / Mode B per the targets doc's "Future work" section). The
   tunneled workloads in this run (k8s-microservices,
   vxlan-k8s-pure) show the work-vs-speed tradeoff clearly — the
   equal-work bench would tell us "is mono more efficient than
   flowdis at the same depth?" cleanly.

3. **Investigate rust-mono's tunnel performance** vs c-xdp2-mono
   (93 vs 141 on vxlan-k8s-pure). If rust really is doing
   equivalent work faster, there's a C-side optimisation to
   borrow.

4. **Update the targets doc**: replace the predicted
   `vlan-tcp-mix 8–12 ns/pkt` numbers (extrapolated from the
   local snapshot) with the actual ~70 ns/pkt hp5 numbers, and
   note the L1-cache artefact in the local snapshot.
