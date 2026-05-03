# Flow-Dissector Matrix on Physical Testbed — Design

Status: design proposal
Author: xdp2 perf team
Date: 2026-05-02

## 1. Goals & Non-Goals

### Goals

- A **repeatable, configurable** cross-implementation flow-parser
  benchmark that runs on real physical hardware. The 10-row matrix
  covers the kernel flow dissector, the kernel eBPF flow dissector,
  the XDP2 (C) parsers (user-space and BPF), `xdp2-flow-ebpf`, and
  the multiple `xdp2-rs` modes (graph, graph-enum, mono, mono-x4,
  compiled, template, template-simd, simd).
- Surface IPC, branch-miss rate, L1d/LLC-miss rate, and
  microarchitecture-specific stalls alongside `ns/pkt` and `Mpps`,
  so a parser's lead can be explained, not just observed.
- **Portability across hardware.** A user with a different host pair
  (different CPU, different NIC, different driver) substitutes a
  config file; no scripts, Nix code, or NixOS modules are edited to
  change hardware.
- **Flake-first.** Every step is a `flake.nix` output. The user's
  surface is `nix run .#flow-dissector-matrix-run`,
  `... -aggregate`, `... -check`, etc. Internals live in modular
  `nix/*.nix` files and `nix/modules/`.

### Non-Goals

- Synthetic micro-benchmarks (covered elsewhere).
- Container or VM runs — performance numbers are only meaningful
  on bare metal.
- Cross-OS support — Linux only, NixOS recommended.

## 2. Naming Conventions

This document distinguishes three implementations carefully:

| Name in this doc          | What it refers to                                      |
|---------------------------|--------------------------------------------------------|
| **`xdp2-rs`**             | The Rust implementation. Always written with the `-rs` suffix to disambiguate from the C parser. |
| **`XDP2 (C)`** / `XDP2 C/C++` | The original C/C++ XDP2 parser (user-space and kernel BPF variants). |
| **`xdp2-flow-ebpf`**      | The standalone fast eBPF flow-dissector artifact built from the C parser. |
| **kernel flow dissector** | Linux's in-tree flow dissector, both user-space (via `flowdis`) and BPF variants. |

Implementations should always be referred to with the labels above to
avoid ambiguity in tables, plots, and result files.

## 3. Hardware Abstraction Layer — `testbed-config`

A small, portable config file captures everything host- and
NIC-specific. It is the *only* surface a user touches when porting
the benchmark to new hardware.

The reference instantiation is `testbeds/hp2-hp5-x710.toml` (sketch
in §13). A second sketch, `testbeds/example-mellanox-cx4.toml`,
demonstrates portability for a Mellanox ConnectX-4 host pair.

```toml
# testbeds/<name>.toml — schema

[testbed]
name        = "hp2-hp5-x710"   # used in result paths and report titles
description = "AMD Ryzen 5 PRO 2400G (Zen 1), Intel X710 10GbE"

[[hosts]]
role           = "dut"          # device under test (parser runs here)
hostname       = "hp5"
arch           = "x86_64-linux"
cpu_vendor     = "amd"          # amd | intel | arm
cpu_uarch      = "zen1"         # zen1, zen3, skylake, icx, neoverse-n1, ...
isolated_cpus  = "2-7"          # → kernel cmdline isolcpus= and nohz_full=
hugepage_count = 1024
governor       = "performance"
mitigations    = "off"          # honest-perf benchmark; clearly labeled

[[hosts]]
role          = "generator"     # traffic source for Phase E only
hostname      = "hp2"
arch          = "x86_64-linux"
cpu_vendor    = "amd"
cpu_uarch     = "zen1"
isolated_cpus = "2-7"

[nic]
driver          = "i40e"        # i40e | ice | mlx5_core | bnxt_en | ...
model           = "Intel X710"
dut_iface       = "enp1s0f0"
gen_iface       = "enp1s0f1"
link_speed_gbps = 10
queues          = 8
zerocopy_afxdp  = true
flow_director   = "ethtool"     # ethtool | tc-flower | devlink
rss_config      = "default"

[run]
iterations_combo     = 200
iterations_tcp_ipv4  = 500
iterations_mixed     = 200
afxdp_duration_s     = 30
```

### Why TOML, not pure Nix

The config is consumed both by Nix (for system-level NixOS module
configuration) **and** by runtime tooling (the orchestrator, the
aggregator). TOML is comfortable in both worlds; Nix can `fromTOML`
it, and the runtime tools parse it directly.

## 4. Modular Nix Architecture

All new and modified surface lives in modular `nix/` files exposed
through `flake.nix`:

| File                                   | Role                                                                                  | New / Existing |
|----------------------------------------|---------------------------------------------------------------------------------------|----------------|
| `nix/testbed-config.nix`               | Loader/validator: TOML → Nix attrset, used by both NixOS modules and runtime targets. | **New**        |
| `nix/modules/physical-testbed.nix`     | NixOS module — reads `testbed-config` (no hardcoded constants). Sets isolcpus, nohz_full, hugepages, governor, mitigations, IRQ pinning. | **Modify** |
| `nix/modules/nic-tuning.nix`           | NixOS module — NIC-driver-specific tuning. Branches on `[nic].driver` to emit ethtool / tc-flower / devlink commands; sets RSS, ring sizes, IRQ affinity, AF_XDP zerocopy where supported. | **New** |
| `nix/flow-dissector-matrix-runner.nix` | Per-host matrix run. Refactor of the existing `flow-dissector-matrix-unified` to be config-driven (PCAPs, iterations, modes from config). Emits per-mode JSON. | **Refactor** |
| `nix/perf-bench.nix`                   | Per-mode hardware-counter sweep. Already present. **Modify**: select PMU passes by `cpu_uarch` (Zen passes for AMD, Skylake/icelake passes for Intel, ARM PMU set for Neoverse). Invoke `xdp2-bench --perf` directly (the documented quirk). | **Modify** |
| `nix/physical-testbed-runner.nix`      | Multi-host orchestrator (rsync + ssh + nix run + result pull). **Modify**: accept testbed-config, drop hardcoded `hp2`/`hp5`, fan out by role. | **Modify** |
| `nix/aggregate-results.nix`            | JSON tree → markdown + CSV aggregator. Computes mean/median/p95/95% CI per (host, pcap, mode) cell. | **New** |
| `flake.nix`                            | Expose new outputs (see below). Compose existing primitives into testbed-config-driven targets. | **Modify** |

### Public flake outputs (the user surface)

| Output                                  | Purpose                                                              |
|-----------------------------------------|----------------------------------------------------------------------|
| `flow-dissector-matrix-run`             | Run full Phase B + C sweep across the testbed.                       |
| `flow-dissector-matrix-aggregate`       | Walk results, emit `summary.{md,csv}` and `regressions.md`.          |
| `flow-dissector-matrix-check`           | 1-iteration smoke + regression gate; CI-suitable.                    |
| `flow-dissector-afxdp-live`             | Phase E live-traffic run (DUT + generator coordination).             |
| `nixosModules.physicalTestbed`          | NixOS module for the DUT/generator host configs.                     |
| `nixosModules.nicTuning`                | NixOS module for NIC-driver-specific tuning.                         |

Typical usage:

```bash
# Run full matrix on the reference testbed
nix run .#flow-dissector-matrix-run -- --testbed testbeds/hp2-hp5-x710.toml

# Aggregate latest run into a markdown report + CSV
nix run .#flow-dissector-matrix-aggregate -- \
  --results perf-results/2026-05-02 \
  --testbed testbeds/hp2-hp5-x710.toml

# CI smoke
nix run .#flow-dissector-matrix-check -- \
  --testbed testbeds/hp2-hp5-x710.toml

# Phase E live AF_XDP
nix run .#flow-dissector-afxdp-live -- \
  --testbed testbeds/hp2-hp5-x710.toml --duration 30
```

## 5. Parser Matrix (10 rows)

| Row | Implementation                                | Invocation                                              |
|-----|-----------------------------------------------|---------------------------------------------------------|
| 1   | Kernel flow dissector (user-space)            | `flow-dissector-bench --parser standard`                |
| 2   | XDP2 (C) parser, user-space                   | `flow-dissector-bench --parser xdp2`                    |
| 3   | XDP2 (C) parse-only, user-space               | `flow-dissector-bench --parser xdp2 --parse-only`       |
| 4   | Kernel flow dissector (BPF)                   | `xdp2-flow-bpf-bench` (kernel BPF flowdis)              |
| 5   | XDP2 (C) BPF parser                           | `xdp2-flow-bpf-bench --xdp2` (verifier status recorded) |
| 6   | `xdp2-flow-ebpf` fast                         | `fast_flow.bpf.o` via BPF_PROG_TEST_RUN                 |
| 7   | `xdp2-rs` graph (vtable)                      | `xdp2-bench --mode graph`                               |
| 8   | `xdp2-rs` graph-enum                          | `xdp2-bench --mode graph-enum`                          |
| 9   | `xdp2-rs` mono / mono-x4 / compiled           | `xdp2-bench --mode {mono,mono-x4,compiled}`             |
| 10  | `xdp2-rs` template / template-simd / simd     | `xdp2-bench --mode {template,template-simd,simd}`       |

Row 9 and Row 10 each expand into 3 sub-rows in the result tables; they
are grouped in this matrix because they share family/dispatch style.

## 6. PCAP Corpus

The corpus is parameterized in `[run]`; each entry maps a logical name
to a Nix-store path produced by an existing or new derivation.

| Logical name | Source                                              | Purpose                                          |
|--------------|-----------------------------------------------------|--------------------------------------------------|
| `tcp_ipv4`   | `data/pcaps/tcp_ipv4.pcap`                          | Homogeneous traffic — `template-simd`'s strong case |
| `https_web`  | (existing https/web capture)                        | Web-like distribution of TLS/HTTP                |
| `combo`      | `flake.nix` `test-pcap` (500k generated)            | Heterogeneous — `xdp2-rs` graph-enum's strong case |
| `mixed_real` | (Internet capture; sentinel for regressions)        | Real-world fuzz, regression sentinel             |

Adding/removing a PCAP is a config-only change.

## 7. Run Plan — Phase B (parser matrix)

`flow-dissector-matrix-run` reads `testbed-config`, then via
`physical-testbed-runner.nix`:

1. **rsync** the working tree to each host listed in config.
2. On each host **in parallel**, invoke `flow-dissector-matrix-runner`
   with the same config plus the host's role.
3. Inside the runner: for each `(pcap, mode)` cell, run sequentially
   on a single isolated CPU (`taskset -c <isolated_cpus[0]>`), one
   warm-up iteration discarded, then `[run].iterations_<pcap>`
   timed iterations.
4. Each cell emits a JSON record with: `ns_per_pkt`, `mpps`, packet
   count, iteration count, build hash, NIC firmware/driver, kernel
   version.
5. Result files are pulled back to
   `perf-results/<date>/<testbed.name>/<host>/<pcap>/<mode>.json`.

Hosts run in parallel; modes within a host are sequential to avoid
counter contention.

## 8. Run Plan — Phase C (perf counters)

For four headline modes — `xdp2-rs` graph-enum, `xdp2-rs` compiled,
`xdp2-rs` template, `xdp2-rs` graph — invoke
`xdp2-bench --perf --perf-pass <pass>` directly (not through the
sweep wrapper; see "Documented Quirks").

PMU passes selected by `cpu_uarch` from config:

| `cpu_uarch`   | Passes                                                |
|---------------|-------------------------------------------------------|
| `zen1`/`zen3` | `basic`, `cache`, `branch`, `zen-fe`, `zen-be`        |
| `skylake`/`icx` | `basic`, `cache`, `branch`, `intel-fe`, `intel-be`  |
| `neoverse-n1` | `basic`, `cache`, `branch`, `arm-pmu`                 |

Captured per pass: `cycles/pkt`, `instructions/pkt`, `IPC`,
`branch-miss%`, `L1d-miss%`, `LLC-miss%`, plus uarch-specific
frontend and backend stalls.

## 9. Run Plan — Phase E (AF_XDP live, included)

Reuses two existing primitives:

- `samples/flow_dissector/run_ntuple_template_bench.sh` — DUT side.
- `samples/flow_dissector/pktgen_ntuple_template.sh` (kernel) **or**
  `samples/flow_dissector/pktgen_dpdk_ntuple_template.sh` (DPDK) —
  generator side.

Wrapped as the flake output `flow-dissector-afxdp-live`:

1. Resolve `dut` and `generator` hosts and interfaces from
   `testbed-config`.
2. On the generator: run pktgen at incrementing offered loads
   (1, 2, 5, 10 Mpps; capped at `[nic].link_speed_gbps`).
3. On the DUT: run `xdp2-bench --mode af-xdp --interface
   <[nic].dut_iface> --queue 0 --duration <[run].afxdp_duration_s>`,
   then a per-queue variant
   `xdp2-bench --mode af-xdp-template ...` using flow-director
   rules emitted by the `nicTuning` NixOS module.
4. Emit one JSON per offered load: pps received, drops, rx-queue
   utilization, AF_XDP zerocopy mode reported by the kernel.

### NIC-driver-specific flow-director generation

`nic-tuning.nix` branches on `[nic].driver` and `[nic].flow_director`:

- **i40e + ethtool** (Intel X710 reference): `ethtool -N`/`-K`
  ntuple rules.
- **mlx5_core + tc-flower** (Mellanox ConnectX-4/5): `tc qdisc` +
  `tc filter add dev ... protocol ip parent ffff: flower ...`.
- **ice + devlink** (Intel E810): `devlink dev region` /
  `devlink-resource` for shared blocks.
- **bnxt_en + ethtool** (Broadcom NetXtreme): ethtool ntuple with
  the driver's documented quirks.

A user adding a new NIC family adds a new branch in `nic-tuning.nix`
and a new value for `[nic].driver` — nothing else.

## 10. Result Aggregation

`flow-dissector-matrix-aggregate` walks
`perf-results/<date>/<testbed.name>/**.json` and emits:

- **`summary.md`** — markdown tables grouped by PCAP. Columns:
  per-host ns/pkt with 95% CI. Hosts identified by `[testbed].name`
  and the `dut`/`generator` role, not hardcoded names.
- **`summary.csv`** — flat CSV: `(testbed, host, role, pcap, mode,
  ns_per_pkt_mean, ns_per_pkt_median, ns_per_pkt_p95, ci_lo, ci_hi,
  mpps, iterations, build_hash)`.
- **`regressions.md`** — diff vs the previous date's `summary.csv`
  for the same testbed, flagging cells whose 95% CIs do not overlap
  and whose median moved by ≥ 5%.

Statistics methodology: a "win" is **CI-disjoint** ns/pkt;
overlapping CIs are reported as "noise" regardless of point estimate
delta. This avoids overclaiming on small jitter.

## 11. Regression Gate

`flow-dissector-matrix-check` is a CI-suitable smoke run:

- 1 warm-up + 5 timed iterations per cell on the `combo` PCAP only.
- Single host (the testbed's `dut`).
- Compares mode means against `testbeds/<name>.baseline.csv`
  (one baseline per testbed).
- Fails the build if any mode regresses > 10% on `combo` versus its
  baseline.

A `-loose` variant uses 25% threshold for early-stage hardware that
has not yet been characterized.

## 12. Reproducibility Checklist

Captured into every `summary.md` header:

- Kernel version + cmdline (`isolcpus`, `nohz_full`, `mitigations`).
- CPU governor + turbo state.
- IRQ affinities.
- RSS configuration / queue count.
- Hugepages allocated.
- NIC firmware version + driver version.
- Nix store path (build hash) of `xdp2-bench`,
  `flow-dissector-bench`, `xdp2-flow-bpf-bench`, and the
  `xdp2-flow-ebpf` artifact.
- `testbed-config` SHA256.

## 13. Worked Examples

### 13.1 Reference instantiation — `testbeds/hp2-hp5-x710.toml`

```toml
[testbed]
name        = "hp2-hp5-x710"
description = "AMD Ryzen 5 PRO 2400G (Zen 1) × 2, Intel X710 10GbE, NixOS"

[[hosts]]
role           = "dut"
hostname       = "hp5"
arch           = "x86_64-linux"
cpu_vendor     = "amd"
cpu_uarch      = "zen1"
isolated_cpus  = "2-7"
hugepage_count = 1024
governor       = "performance"
mitigations    = "off"

[[hosts]]
role          = "generator"
hostname      = "hp2"
arch          = "x86_64-linux"
cpu_vendor    = "amd"
cpu_uarch     = "zen1"
isolated_cpus = "2-7"

[nic]
driver          = "i40e"
model           = "Intel X710"
dut_iface       = "enp1s0f0"
gen_iface       = "enp1s0f1"
link_speed_gbps = 10
queues          = 8
zerocopy_afxdp  = true
flow_director   = "ethtool"
rss_config      = "default"

[run]
iterations_combo    = 200
iterations_tcp_ipv4 = 500
iterations_mixed    = 200
afxdp_duration_s    = 30
```

This file reproduces the 2026-05-02 setup whose results are in
`perf-results/2026-05-02-physical-testbed-summary.md`.

### 13.2 Alternative — `testbeds/example-mellanox-cx4.toml` (sketch)

```toml
[testbed]
name        = "tr-pair-cx4"
description = "AMD Threadripper 3970X × 2, Mellanox ConnectX-4 25GbE"

[[hosts]]
role           = "dut"
hostname       = "tr1"
arch           = "x86_64-linux"
cpu_vendor     = "amd"
cpu_uarch      = "zen2"
isolated_cpus  = "8-31"
hugepage_count = 4096
governor       = "performance"
mitigations    = "off"

[[hosts]]
role          = "generator"
hostname      = "tr2"
arch          = "x86_64-linux"
cpu_vendor    = "amd"
cpu_uarch     = "zen2"
isolated_cpus = "8-31"

[nic]
driver          = "mlx5_core"
model           = "Mellanox ConnectX-4 Lx"
dut_iface       = "enp1s0f0np0"
gen_iface       = "enp1s0f0np0"
link_speed_gbps = 25
queues          = 16
zerocopy_afxdp  = true
flow_director   = "tc-flower"
rss_config      = "default"

[run]
iterations_combo    = 500
iterations_tcp_ipv4 = 1000
iterations_mixed    = 500
afxdp_duration_s    = 60
```

This sketch demonstrates portability: a different CPU family
(Zen 2 → different PMU passes), a different NIC driver
(`mlx5_core` → `tc-flower` for flow steering), a different link
speed (25 GbE → AF_XDP offered-load curve goes higher), and more
isolated CPUs (24 cores) — all expressed in config, with no
script edits.

## 14. References to Existing Primitives

| Primitive                          | Path                                                                | Reused for           |
|------------------------------------|---------------------------------------------------------------------|----------------------|
| Unified matrix script              | `samples/flow_dissector/xdp2_rs_matrix.sh`                          | Phase B              |
| C-only matrix                      | `samples/flow_dissector/benchmark_matrix.sh`                        | Phase B rows 1-6     |
| AF_XDP driver                      | `samples/flow_dissector/run_ntuple_template_bench.sh`               | Phase E              |
| pktgen (kernel)                    | `samples/flow_dissector/pktgen_ntuple_template.sh`                  | Phase E              |
| pktgen (DPDK)                      | `samples/flow_dissector/pktgen_dpdk_ntuple_template.sh`             | Phase E              |
| Matrix flake target (`xdp2-rs`)    | `nix/xdp2-rs-matrix.nix`                                            | Phase B              |
| C matrix flake target              | `nix/flow-dissector-matrix.nix`                                     | Phase B              |
| Matrix smoke flake target          | `nix/flow-dissector-matrix-smoke.nix`                               | Regression gate      |
| Host orchestrator                  | `nix/physical-testbed-runner.nix`                                   | All phases           |
| NixOS tuning module (existing)     | `nix/modules/physical-testbed.nix`                                  | DUT/gen tuning       |
| Perf bench                         | `nix/perf-bench.nix`                                                | Phase C              |
| Perf analysis (existing sweeps)    | `nix/perf-analysis.nix`                                             | Phase C              |
| ntuple-template flake target       | `nix/ntuple-template-bench.nix`                                     | Phase E              |
| DPDK ntuple-template flake target  | `nix/dpdk-ntuple-template-bench.nix`                                | Phase E              |
| `xdp2-flow-ebpf` artifacts         | `nix/xdp2-flow-ebpf.nix`, `nix/xdp2-flow-ebpf-image.nix`             | Row 6                |
| `test-pcap` derivation             | inline in `flake.nix` (`gen-test-pcap`, `test-pcap`)                | PCAP corpus          |
| Existing testbed doc               | `docs/physical-testbed.md`                                          | Hardware section     |
| Existing benchmark plan            | `docs/flow-dissector-benchmark-plan.md`                             | Phase structure      |
| Latest results                     | `perf-results/2026-05-02-physical-testbed-summary.md`               | Reference numbers    |

## 15. Documented Quirks

These were observed during the 2026-05-02 reference run and must be
codified in the implementation:

- **`perf-sweep` wrapper masked counters.** Direct
  `xdp2-bench --perf --perf-pass <pass>` invocation works; the
  wrapper does not. Phase C must invoke directly.
- **XDP2 (C) BPF parser fails the verifier** on this build —
  recorded as N/A, with the verifier log archived next to the
  results so the regression is traceable rather than silent.
- **`writeShellApplication` flake outputs require `nix run`,**
  not `nix build`. The orchestrator uses `nix run` accordingly.
- **`mitigations=off`** is honest-perf only; the summary header
  marks every result as such so it cannot be misread as a
  production claim.

## 16. Open Questions

- Result-tree publication: keep `perf-results/` git-tracked, or
  push to a Grafana / Prometheus pushgateway?
- Smoke CI host: dedicated build farm, or only the physical
  testbed (which means CI is offline whenever the testbed is in
  use for live runs)?
- Should `testbeds/*.toml` live in this repo, or in a sibling
  private repo with site-specific configs (some sites' hostnames
  and IPs may be sensitive)?

## 17. Implementation Order

When this design is implemented, the recommended order is:

1. `nix/testbed-config.nix` — schema + loader (smallest unit, easiest
   to test).
2. Refactor `nix/modules/physical-testbed.nix` to consume it (no
   behavior change for the reference instantiation).
3. `nix/modules/nic-tuning.nix` — start with the i40e branch only.
4. Refactor `nix/physical-testbed-runner.nix` to consume the config.
5. Refactor `nix/flow-dissector-matrix-runner.nix` (from
   `xdp2-rs-matrix.nix` + `flow-dissector-matrix.nix`) to consume the
   config.
6. `nix/aggregate-results.nix` — JSON → `summary.{md,csv}`.
7. Wire up `flake.nix` outputs (`flow-dissector-matrix-{run,aggregate,check}`).
8. Phase E wiring (`flow-dissector-afxdp-live`).
9. Add the second NIC branch in `nic-tuning.nix` (Mellanox / mlx5_core
   via tc-flower) to validate portability against a real second
   testbed.
