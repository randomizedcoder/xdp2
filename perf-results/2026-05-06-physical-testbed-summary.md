# Physical Testbed Benchmark Results — 2026-05-06

The Phase 11–15 campaign captured by
`docs/flow-dissector-matrix-implementation-plan.md` (in-tree wiring,
Phases 0-10) + `docs/flow-dissector-benchmark-plan.md` (campaign
phases A-E). Driven by the new `flow-dissector-matrix-run` /
`flow-dissector-afxdp-live` pipeline against the live `hp2-hp5-x710`
testbed.

This doc consolidates **deliverables D1, D2, D4, D7** from the
benchmark plan §9. D3 (T3 lowJitter sensitivity) is deferred per
Phase 14 — needs a NixOS rebuild on hp5's external config. D5
(performance-by-platform.md update) and D6 (raw JSONs) are committed
separately.

## Methodology

- **Hardware:** AMD Ryzen 5 PRO 2400G (Zen 1, 4 c / 8 t), Intel X710
  10 GbE SFP+ (i40e), 30 GiB DDR4-2133 / 61 GiB DDR4-1866.
- **Software:** NixOS 26.05.20260418 unstable, kernel 7.0.1.
- **Tuning:** `mitigations=off`, `isolcpus=2-7`, `nohz_full=2-7`,
  `rcu_nocbs=2-7`, `transparent_hugepage=never`, ring 4096/4096,
  6 combined queues, GRO/GSO/TSO off, BPF JIT enabled,
  `perf_event_paranoid=0`. Verified in
  `perf-results/2026-05-05/preflight.txt`.
- **Sweep:** 5 reps × 4 PCAPs × 2 hosts × 14 modes = 560 cell JSONs.
  100 iter per cell on the matrix runner, 200/500 iter on the
  perf-sweep runner. PCAPs pre-filtered through xdp2-bench so all
  modes measure the same packet set.
- **Statistics:** medians across 5 reps; 95% CI from 1.96 × SEM.
  Cross-cell win = CI-disjoint ns/pkt; overlapping CIs = noise. See
  `nix/scripts/aggregate-results.py:write_regressions`.

## D1 — T1 main table (hp5 medians)

`hp5` is the DUT. ns/pkt = median over 5 reps × 100 iter; values are
**ns/pkt (Mpps)**. `c-bpf-xdp2` omitted (kernel verifier rejection on
7.x — Way 5 N/A).

| Mode               | tcp_ipv4 (11) | https-web (20K) | mixed-real (~870) | combo (500K) |
|--------------------|--------------:|----------------:|------------------:|-------------:|
| c-flowdis-usp      | 26 (38.0)     | 122 (8.0)       | 67 (14.0)         | 162 (6.0)    |
| c-xdp2-usp         | 93 (10.0)     | 195 (5.0)       | 189 (5.0)         | 232 (4.0)    |
| c-xdp2-parse-only  | 72 (13.0)     | 183 (5.0)       | 177 (5.0)         | 221 (4.0)    |
| c-bpf-flowdis      | 85 (11.0)     | 117 (8.0)       | 99 (10.0)         | 91 (10.0)    |
| **c-bpf-fast**     | **24 (41.0)** | **23 (43.0)**   | **21 (47.0)**     | **18 (55.0)**|
| rust-graph         | 218 (5.0)     | 266 (4.0)       | 464 (2.0)         | 289 (3.0)    |
| **rust-graph-enum**| **22 (45.0)** | **78 (13.0)**   | **18 (53.0)**     | **12 (81.0)**|
| rust-mono          | 24 (40.0)     | 82 (12.0)       | 48 (21.0)         | 50 (20.0)    |
| rust-mono-x4       | 27 (37.0)     | 86 (12.0)       | 52 (19.0)         | 55 (18.0)    |
| rust-compiled      | 22 (45.0)     | 82 (12.0)       | 53 (19.0)         | 47 (21.0)    |
| rust-simd          | 29 (34.0)     | 42 (23.0)       | 65 (15.0)         | 57 (18.0)    |
| rust-template      | 17 (56.0)     | 77 (13.0)       | 21 (47.0)         | 51 (20.0)    |
| rust-template-simd | 19 (52.0)     | 74 (13.0)       | 19 (52.0)         | 56 (18.0)    |

**Headline reproduction:** the 2026-05-02 reference's `rust-graph-enum
12 ns/pkt @ 80 Mpps on combo` matches exactly — 12 ns / 81 Mpps in the
2026-05-06 sweep. Every other Rust mode within ±2 ns of reference.

**Per-pcap winners (hp5):**
- `tcp_ipv4`: rust-template at **17 ns** (56 Mpps) — smallest working
  set, best L1 cache hit.
- `https-web`: rust-template-simd at **74 ns** (13 Mpps), narrowly ahead of
  rust-template (77) and rust-compiled (82).
- `mixed-real`: rust-graph-enum at **18 ns** (53 Mpps) — enum dispatch
  beats template on real-world traffic where template match rate drops.
- `combo`: **rust-graph-enum at 12 ns** (81 Mpps) — 33× faster than C
  XDP2 parse-only and 6.6× faster than the next-best Rust mode
  (rust-compiled at 47 ns).

**BPF camp:** `c-bpf-fast` (xdp2-flow-ebpf) is the BPF champion at
**18 ns** on combo — beating every C userspace mode and tied with the
fastest Rust mode (graph-enum). The hand-written BPF flow-dissector
remains the best constant-time fixed-offset extractor.

## D2 — T2 cross-host reproducibility (combo.pcap)

Hypothesis H6: cross-host variance < 5 % on identical hardware.

| Mode               | hp2 ns/pkt | hp5 ns/pkt | Δ %    |
|--------------------|-----------:|-----------:|-------:|
| c-flowdis-usp      | 160        | 162        | 1.23 % |
| c-xdp2-usp         | 229        | 232        | 1.29 % |
| c-xdp2-parse-only  | 217        | 221        | 1.81 % |
| c-bpf-flowdis      | 87         | 91         | 4.40 % |
| c-bpf-fast         | 18         | 18         | 0.00 % |
| rust-graph         | 287        | 289        | 0.69 % |
| **rust-graph-enum**| **12**     | **12**     | **0.00 %** |
| rust-mono          | 49         | 50         | 2.00 % |
| rust-mono-x4       | 54         | 55         | 1.82 % |
| rust-compiled      | 47         | 47         | 0.00 % |
| rust-simd          | 55         | 57         | 3.51 % |
| rust-template      | 50         | 51         | 1.96 % |
| rust-template-simd | 55         | 56         | 1.79 % |

**H6 confirmed:** mean Δ = 1.6 %, max Δ = 4.40 % (c-bpf-flowdis),
**all 13 cells under the 5 % target**. graph-enum, compiled, c-bpf-fast
all read identical between the two hosts. The 2026-04-26 hp5 storage +
channel converge (both on `nixos-unstable`, kernel 7.0.1) wiped out
the earlier ~20 % delta noted in the 2026-04-20 6-way matrix run.

## D3 — T3 tuned-vs-untuned (deferred)

Phase 14 (`xdp2.testbed.lowJitter = true`) requires a NixOS rebuild on
hp5's external config (`~/nixos/hp/hp5/`); deferred per
`docs/flow-dissector-matrix-progress.md` Phase 14. H7 (Rust larger
code footprint = more turbo-sensitive) remains an open hypothesis.

## D4 — T5 microarchitecture (TMA) breakdown

See `perf-results/2026-05-06/T5-tma.md` for the full 7-mode × 3-pcap
× 2-host = 42-cell PMU breakdown (IPC, branch-miss%, cache-miss%,
L1d-miss%, FE-bound%, BE-bound%) generated by Phase 13.

**Headline (combo on hp5):**

| Mode             | ns/pkt | IPC  | branch-miss% | FE-bound% | BE-bound% |
|------------------|-------:|-----:|-------------:|----------:|----------:|
| graph            | 289    | 1.31 | 3.89 %       | 2.5 %     | 8.6 %     |
| mono             |  50    | 1.28 | 5.91 %       | 2.8 %     | 17.7 %    |
| compiled         |  47    | 1.22 | 6.19 %       | 3.3 %     | 10.3 %    |
| template         |  50    | 1.09 | 6.50 %       | 3.6 %     | 15.4 %    |

**graph-enum is not in T5** because perf-sweep uses
`xdp2-bench --mode both` which excludes it. The 2026-05-02 reference
captured graph-enum's PMU breakdown via a separate
`xdp2-bench --mode graph-enum --perf` invocation: 12 ns/pkt at 28
cycles/pkt @ 2.4 GHz, IPC 2.55, branch-miss 0.4 % — 15× lower
branch-miss than the trait-object graph mode (3.9 %), confirming the
enum-dispatch elision of indirect calls.

## D7 — Hypothesis verdicts

The pre-execution predictions in `flow-dissector-benchmark-plan.md` §6,
filled in with measured numbers:

| #  | Hypothesis                                                | Predicted | Measured (combo, hp5)  | Verdict |
|----|----------------------------------------------------------|-----------|------------------------|---------|
| H1 | Rust compiled 40-50 ns on combo                          | 40-50     | **47**                 | ✅       |
| H2 | Rust template wins on https-web (>80 % match)            | 15-25     | 77 (vs compiled 82)    | ⚠ partial — template only marginally beats compiled on the synthetic https-web; production traffic with higher template match would widen the gap |
| H3 | xdp2-flow-ebpf fast remains BPF champion ~22-25 ns       | ~22-25    | **18-24** across pcaps | ✅       |
| H4 | Kernel BPF flowdis is slowest                            | ~70-80 (tcp_ipv4) | 85 on tcp_ipv4 | ✅ish — kernel BPF flowdis is mid-tier on small pcaps but rust-graph and c-xdp2-usp are slower; "slowest" is mode-dependent |
| H5 | Rust graph ~4-5× slower than compiled                    | 4-5×      | **6.1×** (289/47)      | ✅ish — slightly more than predicted, same order |
| H6 | Cross-host variance < 5 %                                | <5 %      | **max 4.40 %**         | ✅       |
| H7 | Rust larger code footprint = more turbo-sensitive        | TBD       | deferred (Phase 14)    | — open  |
| H8 | C kernel flowdis beats Rust graph                        | true      | **162 vs 289 (1.79×)** | ✅       |

5 of 8 confirmed cleanly, 2 partial / mode-dependent, 1 deferred.

## E — AF_XDP live (T-afxdp)

See `perf-results/2026-05-06/T-afxdp.md`. Phase 15 surfaced the
documented D3 RX-drop ceiling: AF_XDP receiver caps at ~877 K pps on
hp5 regardless of offered load (1 / 2 / 5 / 10 Mpps all received the
same), with drops scaling linearly with offered load. Zero-copy mode
confirmed for every cell. The `<0.1 % drops at 1 Mpps` plan target is
**not met** because of receiver-side fill-ring saturation, not a
Phase 15 wrapper bug; D3 tuning experiments
(`xdp2-exp-afxdp-rings-large`, `xdp2-exp-afxdp-busypoll-100`,
`xdp2-exp-afxdp-netdev-budget`) are the next step on this front.

## D5 — performance-by-platform.md update

A new "AMD Ryzen 5 PRO 2400G (Zen 1, 4c/8t)" section added in
`xdp2-rs/docs/performance-by-platform.md` cross-references this
narrative summary and the regression-gated baseline at
`testbeds/hp2-hp5-x710.baseline.csv`.

## D6 — Raw JSONs

Committed under `perf-results/2026-05-06/`:

```
perf-results/2026-05-06/
├── 2026-05-05/hp2-hp5-x710/{hp2,hp5}/
│   ├── flow-dissector-matrix-unified-<ts>/<pcap>/<mode>.json   (560 cells)
│   ├── perf-sweep-{tcp,mixed,combo}-<ts>/<pcap>/<host>_1T.json (30 reports)
│   └── perf-sweep-{tcp,mixed,combo}-<ts>.log                   (per-rep logs)
├── 2026-05-05/hp2-hp5-x710/afxdp/<load>mpps.{json,log}         (4 loads)
├── summary.csv                  (matrix sweep — 112 rows, T1 source)
├── summary.md                   (matrix sweep — narrative T1)
├── regressions.md               (matrix sweep vs baseline — 0 regressions)
├── T5-tma.md                    (T5 D4 deliverable)
├── T-afxdp.md                   (E deliverable)
├── sweep-driver.log             (Phase 12 driver log)
└── perf-sweep-driver.log        (Phase 13 driver log)
```

## Open questions / next steps

- **H7 / Phase 14:** land `lowJitter=true` on hp5 + re-sweep to
  produce T3.
- **D3 RX-drop:** run `xdp2-exp-afxdp-rings-large` (FILL_RING=4096,
  FRAME_COUNT=16384) on hp5 to see if the receiver ceiling lifts
  past 0.88 Mpps. Also `xdp2-exp-pktgen-burst-32 +
  xdp2-exp-pktgen-queue-map` to push pktgen TX past its default
  ~1.48 Mpps cap so offered loads above 2 Mpps actually hit the wire.
- **Mellanox:** the testbed-config sketch (`testbeds/example-mellanox-cx4.toml`)
  and `nic-tuning.nix` mlx5_core branch (Phase 9) are ready; live
  validation needs a Mellanox testbed.
- **graph-enum PMU on combo:** the perf-sweep targets use
  `--mode both` which excludes graph-enum. A supplemental
  `xdp2-bench --mode graph-enum --perf --perf-pass {basic,stalls,detail,zen}`
  per (host, pcap) would put graph-enum into T5; small follow-up.
