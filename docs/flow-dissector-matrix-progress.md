# Flow-Dissector Matrix on Physical Testbed — Implementation Progress

Status tracker for the work specified in:
- Design: [`flow-dissector-matrix-physical-testbed.md`](flow-dissector-matrix-physical-testbed.md)
- Plan:   [`flow-dissector-matrix-implementation-plan.md`](flow-dissector-matrix-implementation-plan.md)

This document is **updated after each commit**. Status values:
`not started`, `in progress`, `done`, `deferred`.

Naming hygiene applies: `xdp2-rs` (Rust), `XDP2 (C)` (C/C++ parser),
`xdp2-flow-ebpf` (eBPF artifact), "kernel flow dissector".

## Phase Ladder

| Phase | Name                                                     | Status         | Started     | Completed   | Commit(s) |
|-------|----------------------------------------------------------|----------------|-------------|-------------|-----------|
| 0     | Pre-flight                                               | done           | 2026-05-02  | 2026-05-02  | `ecd2642` |
| 1     | `testbed-config` schema + loader                         | done           | 2026-05-02  | 2026-05-02  | `9c6caa1` |
| 2     | `testbed-config`-to-module adapter                       | done           | 2026-05-03  | 2026-05-03  | `ca7739f` |
| 3     | `nic-tuning` NixOS module (i40e)                         | done           | 2026-05-03  | 2026-05-03  | `c5b2ce4` |
| 4     | Refactor `physical-testbed-runner`                       | done           | 2026-05-03  | 2026-05-03  | `7f63a36` |
| 5     | Refactor `flow-dissector-matrix-runner`                  | done           | 2026-05-04  | 2026-05-04  | `94a36f2` |
| 6     | `aggregate-results`                                      | done           | 2026-05-04  | 2026-05-04  | `aec1037` |
| 7     | `flake.nix` outputs + regression gate                    | not started    | —           | —           | —         |
| 8     | AF_XDP live (Phase E)                                    | not started    | —           | —           | —         |
| 9     | Second NIC branch (mlx5_core / tc-flower)                | not started    | —           | —           | —         |

## Branch

Working branch: `merge/matrix-physical-testbed`, cut off `proto-audit`.

## Phase 0 — Pre-flight

**Status:** done

**Activities:**
- Branch `merge/matrix-physical-testbed` cut off `proto-audit` HEAD.
- Progress doc skeleton (this file) created.

**Deviations from plan:**
- The plan's Phase 0 calls for re-running the 2026-05-02 reference
  matrix on `hp5` to confirm the baseline. This step is **deferred**
  to a future session with guaranteed live-hardware access. The
  existing `perf-results/2026-05-02-physical-testbed-summary.md`
  remains the de-facto baseline.
- The plan's "schema sketch sign-off" is rolled into Phase 1 — the
  schema is implemented directly rather than reviewed on paper first.

**Verification:**

```bash
$ git rev-parse --abbrev-ref HEAD
merge/matrix-physical-testbed
```

## Phase 1 — `testbed-config` schema + loader

**Status:** done

**Files landed:**
- `nix/testbed-config.nix` — pure-Nix TOML loader + validator.
  Exposes `loadTestbedConfig`, `loadAll`, plus the supported sets
  for uarch, driver, and flow-director styles.
- `testbeds/hp2-hp5-x710.toml` — reference testbed (Intel X710 / i40e
  / AMD Zen 1).
- `testbeds/example-mellanox-cx4.toml` — Mellanox sketch
  (mlx5_core / tc-flower / AMD Zen 2 / 25 GbE) for portability
  validation.
- `flake.nix` — exposes `testbedConfigs.<name>` (system-independent
  output) loaded via `loadAll ./testbeds`, and `lib.loadTestbedConfig`
  / `lib.loadAll` helpers for downstream consumers.

**Validation invariants enforced:**
- `cpu_uarch` must be in `{zen1..zen4, skylake, icelake, icx,
  sapphirerapids, neoverse-n1, neoverse-v1}`.
- `nic.driver` must be in `{i40e, ice, mlx5_core, bnxt_en}`.
- `nic.flow_director` must be in `{ethtool, tc-flower, devlink}`.
- Exactly one host with `role = "dut"`; at most one with
  `role = "generator"`.

**Verification (all four DoD criteria — actual output):**

```bash
$ nix eval --raw .#testbedConfigs.hp2-hp5-x710.nic.driver
i40e

$ nix eval --raw .#testbedConfigs.example-mellanox-cx4.nic.driver
mlx5_core

$ nix eval --raw .#testbedConfigs.hp2-hp5-x710.hosts.dut.hostname
hp5

$ nix eval --raw .#testbedConfigs.hp2-hp5-x710.hosts.generator.hostname
hp2

# Bad config (two duts) rejected with clear message:
$ nix eval --impure --expr 'let lib = import <nixpkgs/lib>; \
  tlib = import /home/das/Downloads/xdp2/nix/testbed-config.nix \
    { inherit lib; }; \
  in (tlib.loadTestbedConfig /tmp/bad-two-duts.toml).testbed.name'
error: testbed-config: exactly one host must have role='dut', got 2
```

**Notes:**
- `nix flake check` not run as a final gate this phase: the working
  tree currently contains many untracked `result-*` symlinks and a
  pre-existing `xdp2-test-riscv64.sock` socket file that blocks flake
  imports unrelated to this work. Direct attribute eval succeeds,
  proving the loader is sound; full flake check can be re-validated
  once the working tree is cleaned in a future session.

## Phase 2 — `testbed-config`-to-module adapter

**Status:** done

**Files landed:**
- `nix/modules/testbed-config-adapter.nix` — pure helper. Provides
  `testbedConfigToModule { config; role; }` that returns the
  `xdp2.testbed.*` config values for a given host role, plus a
  `parseCpuRange` utility (Linux-style `"2-7"` / `"2,4-6"` strings
  → integer list) and a `tests` attrset of pure-Nix unit tests.
- `flake.nix` — exposes `lib.testbedConfigToModule`,
  `lib.parseCpuRange`, and `lib.testbedConfigAdapterTests`.

**Mappings implemented:**

| testbed-config field                        | xdp2.testbed.* output       |
|---------------------------------------------|-----------------------------|
| `hosts.<role>.isolated_cpus`                | `isolatedCpus` (list of int, range-parsed) |
| `hosts.<role>.hugepage_count`               | `hugepages2M`               |
| `nic.dut_iface` / `nic.gen_iface`           | `peerInterfaces` (one entry, role-selected) |
| `hosts.<role>.governor` + `mitigations`     | `lowJitter` (true if perf + off) |
| `hosts.<role>.mitigations`                  | `disableMitigations`        |
| (always)                                    | `enable = true`             |

The existing `physical-testbed.nix` module is **not modified** —
the adapter speaks its option language as-is.

**Verification (all DoD criteria — actual output):**

```bash
# Adapter unit tests (CPU-range parser round-trips)
$ nix eval .#lib.testbedConfigAdapterTests.ok
true

# DUT role on the reference x710 testbed
$ nix eval --impure --json --expr '
    let lib = import <nixpkgs/lib>;
        tlib = import ./nix/testbed-config.nix { inherit lib; };
        adapter = import ./nix/modules/testbed-config-adapter.nix { inherit lib; };
        cfg = tlib.loadTestbedConfig ./testbeds/hp2-hp5-x710.toml;
    in adapter.testbedConfigToModule { config = cfg; role = "dut"; }'
{"xdp2":{"testbed":{"disableMitigations":true,"enable":true,
  "hugepages2M":1024,"isolatedCpus":[2,3,4,5,6,7],
  "lowJitter":true,"peerInterfaces":["enp1s0f0"]}}}

# Generator role picks gen_iface
... role = "generator"; }
peerInterfaces = ["enp1s0f1"]

# Mellanox sketch parses 24-CPU isolation + 4096 hugepages
... ./testbeds/example-mellanox-cx4.toml ... role = "dut"; }
isolatedCpus = [8..31] (24 entries), hugepages2M = 4096,
peerInterfaces = ["enp1s0f0np0"]
```

**Notes:**
- `nix eval .#lib.testbedConfigToModule ...` via the flake hits the
  same untracked-socket-file impurity as Phase 1; direct module
  imports remain the working verification path. Cleanup of the
  working tree (untracked `result-*` symlinks, `.sock` files) is
  out of scope for this session.

## Phase 3 — `nic-tuning` NixOS module (i40e), refactor/extract

**Status:** done

**Files landed:**
- `nix/modules/nic-tuning.nix` — new NixOS module owning all
  driver-specific data-plane tuning. Options:
  `xdp2.nicTuning.{enable, driver, peerInterfaces, isolatedCpus,
  jumbo, gro, flowDirectorRules}`. Driver dispatch: `i40e` is
  fully implemented (per-NIC ethtool tune service + IRQ affinity
  service, both lifted verbatim from the historic
  `physical-testbed.nix` body); `mlx5_core` / `ice` / `bnxt_en`
  are accepted by the enum but produce no activation services
  and a top-level warning until Phase 9 lands.
- `nix/modules/physical-testbed.nix` — refactored to import
  `./nic-tuning.nix` and forward `peerInterfaces`,
  `isolatedCpus`, `jumbo`, `gro`, `flowDirectorRules` to the new
  module's options. The two helper functions
  (`mkNicTuneService`, `mkNicAffinityService`) and the
  `cpuMaskCount` helper are removed; CPU isolation, hugepages,
  kernel cmdline, sysctls, addressing, real-services bench, and
  the lowJitter / mgmt-affinity services remain.
- `nix/modules/testbed-config-adapter.nix` — extended so the
  returned attrset also populates
  `xdp2.nicTuning.driver = config.nic.driver`, overriding the
  `lib.mkDefault "i40e"` set by physical-testbed.
- `nix/modules/tests/nic-tuning-eval-test.nix` — synthetic NixOS
  evaluation test that builds the module twice (once with
  `i40e`, once with `mlx5_core`) and asserts the expected unit
  names + warnings. Returns a `runCommand` derivation whose name
  encodes the result; throws on failure with a clear message.
- `flake.nix` — exposes
  `nixosModules.nicTuning = ./nix/modules/nic-tuning.nix` and
  wires `checks.<system>.nic-tuning-eval` into the per-system
  block.

**Deviations from plan:**
- The plan called for verifying via
  `nix build .#nixosConfigurations.hp5`. `hp5` NixOS host config
  is external to this repo (per `docs/physical-testbed.md`), so
  the byte-identical-cmdline DoD line is **deferred**. Phase 3
  verification rests on the synthetic eval test, which evaluates
  the same module pipeline against an inline configuration.

**Verification (all DoD criteria — actual output):**

```bash
$ nix eval --impure --json --expr '
    let pkgs = import <nixpkgs> {}; lib = pkgs.lib;
        test = import ./nix/modules/tests/nic-tuning-eval-test.nix { inherit pkgs lib; };
    in test.name'
"nic-tuning-eval-ok"

$ nix eval --impure --json --expr '
    let lib = (import <nixpkgs> {}).lib;
        tlib = import ./nix/testbed-config.nix { inherit lib; };
        a = import ./nix/modules/testbed-config-adapter.nix { inherit lib; };
        cfg = tlib.loadTestbedConfig ./testbeds/hp2-hp5-x710.toml;
    in (a.testbedConfigToModule { config = cfg; role = "dut"; }).xdp2.nicTuning.driver'
"i40e"

$ nix eval --impure --json --expr '
    ...example-mellanox-cx4.toml ... .xdp2.nicTuning.driver'
"mlx5_core"

# Full physical-testbed eval (synthetic) produces both expected services:
$ nix eval --impure --json --expr '
    ... eval-config with xdp2.testbed.enable = true,
        peerInterfaces = ["enp1s0f0"] ...
    builtins.attrNames eval.config.systemd.services'
# Includes: "xdp2-nic-tune-enp1s0f0", "xdp2-nic-affinity-enp1s0f0"

# No NIC-tuning logic remains in physical-testbed.nix
$ grep -nE 'mkNicTuneService|mkNicAffinityService|cpuMaskCount|TxRx-' \
    nix/modules/physical-testbed.nix
# (no matches)
```

**Notes:**
- physical-testbed.nix sets `xdp2.nicTuning.driver = lib.mkDefault
  "i40e"` so existing consumers (those who don't go through the
  testbed-config adapter) get unchanged behavior. The adapter
  overrides this default with the testbed-config's `[nic].driver`.

## Phase 4 — `physical-testbed-runner` consumes `--testbed <toml>`

**Status:** done

**Files landed:**
- `nix/physical-testbed-runner.nix` — extended with two coexisting
  invocation forms:
  - **New** `--testbed PATH -- TARGET [TARGET...]`: loads a
    testbed-config TOML, derives DUT and (optional) generator
    hostnames, and writes results under
    `perf-results/<date>/<testbed.name>/<host>/...`.
  - **Legacy** `HOST [HOST...] -- TARGET [TARGET...]`: byte-identical
    to pre-Phase-4 behavior; results stay at `perf-results/<host>/...`.
- A small inlined `parse_testbed_toml()` awk function extracts
  `testbed.name`, the DUT hostname, and the (optional) generator
  hostname from the config. Awk was chosen over `dasel` (CLI changed
  in v3) and `python3` to keep the script self-contained and avoid
  growing `runtimeInputs`.

**Mutual-exclusion guarantees:**
- `--testbed PATH extra-host -- TARGET` is rejected with a clear
  message ("positional hosts not allowed with --testbed").
- A missing TOML file fails before any ssh side effects.
- A TOML missing either `testbed.name` or the DUT host fails fast.

**Deviations from plan:**
- Plan suggested `dasel` for TOML parsing; switched to gawk because
  `dasel` 3.x has an incompatible CLI (no `-f` flag) and the
  testbed-config schema is small and stylized — a 12-line awk parser
  is sufficient and ships with `gawk` (already in `runtimeInputs`).
- Phase 4 result-tree layout uses `<date>/<testbed.name>/<host>/` per
  plan; the existing `INDEX.json` file remains at the top of
  `RESULTS_ROOT` so a single index covers all testbed runs.

**Verification (parse-only smoke; ssh fails as expected without
live hosts):**

```bash
$ XDP2_RESULTS_ROOT=/tmp/run-out-phase4 nix run .#run-on-host -- \
    --testbed testbeds/hp2-hp5-x710.toml -- echo
[testbed] hp2-hp5-x710: dut=hp5 gen=hp2
[hp5] rsync -> root@hp5:~/xdp2/
[hp2] rsync -> root@hp2:~/xdp2/
[hp2] -> echo  (log: /tmp/run-out-phase4/2026-05-03/hp2-hp5-x710/hp2/echo-...log)
[hp5] -> echo  (log: /tmp/run-out-phase4/2026-05-03/hp2-hp5-x710/hp5/echo-...log)
# Path computation observable: /tmp/run-out-phase4/<date>/hp2-hp5-x710/<host>/

# Mutual exclusion:
$ nix run .#run-on-host -- --testbed testbeds/hp2-hp5-x710.toml extra -- echo
xdp2-run-on-host: positional hosts not allowed with --testbed (got 'extra')

# Legacy positional form unchanged:
$ XDP2_RESULTS_ROOT=/tmp/legacy nix run .#run-on-host -- example.invalid -- echo
[example.invalid] rsync -> root@example.invalid:~/xdp2/
# (results would land at /tmp/legacy/example.invalid/echo-<ts>/)
```

**Notes:**
- Live multi-host fan-out + result rsync-back are validated in a
  future session with `hp2`/`hp5` access. The path-computation and
  arg-parse changes are local-side and fully witnessed above.

## Phase 5 — `flow-dissector-matrix-runner` per-cell JSON

**Status:** done

**Files landed:**
- `nix/xdp2-rs-matrix.nix` — added `-j <dir>` flag. When set, an
  `emit_cell_json` helper writes `<dir>/<pcap-basename>/<mode>.json`
  after every measured cell. Modes: `c-flowdis-usp`, `c-xdp2-usp`,
  `c-xdp2-parse-only`, `c-bpf-flowdis`, `c-bpf-xdp2`, `c-bpf-fast`,
  `rust-graph`, `rust-mono`, `rust-compiled`, `rust-template`.
- `samples/flow_dissector/xdp2_rs_matrix.sh` — same flag (`-j <dir>`),
  same helper, same mode names. Standalone (non-Nix) callers stay in
  parity with the Nix wrapper.
- `nix/checks/matrix-runner-json-shape.nix` (new) — pure-Nix
  regression gate. Synthesizes one cell record using the agreed
  printf template, validates with `jq -e` that all expected keys are
  present, and greps both source files to confirm they carry the
  same key set. Tripping condition: anyone removes or renames a
  field in either source's printf template.
- `flake.nix` — wired `checks.<system>.matrix-runner-json-shape` so
  the gate runs as part of `nix flake check`.

**JSON schema (one record per `(pcap, mode)` cell):**

```json
{
  "mode":         "rust-graph",
  "pcap":         "combo.pcap",
  "ns_per_pkt":   12,
  "mpps":         80,
  "iterations":   100,
  "build_hash":   "<truncated absolute path to xdp2-bench>",
  "kernel":       "6.18.22",
  "nic_driver":   "i40e",
  "nic_firmware": "9.30"
}
```

`nic_driver` / `nic_firmware` are populated from `XDP2_NIC_DRIVER`
and `XDP2_NIC_FIRMWARE` environment variables (empty by default).
`build_hash` is the resolved path to `xdp2-bench` (truncated to
80 chars), which uniquely identifies the binary in the Nix store.
`ns_per_pkt` and `mpps` fall back to JSON `null` when the cell did
not produce a numeric measurement (e.g. a BPF run failing without
CAP_BPF).

**Deviations from plan:**
- Plan specified `--json-out` long form; used short form `-j`
  because both runners use `getopts` (no `--long-flag` support).
  Functionality is identical.
- Plan suggested running the actual matrix runner inside the
  flake check on the smallest test-pcap fixture. That requires
  `CAP_BPF` (BPF_PROG_TEST_RUN) which Nix sandbox builds do not
  grant — moved to a synthetic-data approach that exercises the
  exact printf template and grep-witnesses both sources for the
  same key set. Live end-to-end verification is deferred to the
  same session that runs Phase 4 on hp2/hp5.
- Plan listed mode names as `graph`/`mono`/etc.; chose
  `rust-graph` / `c-bpf-fast` / etc. so the JSON is unambiguous
  when aggregated across all 10 cells (which Phase 6 will do).

**Verification:**

```bash
$ nix build --no-link --print-out-paths .#checks.x86_64-linux.matrix-runner-json-shape
/nix/store/<hash>-matrix-runner-json-shape

$ cat /nix/store/<hash>-matrix-runner-json-shape
ok

$ /nix/store/<hash>-xdp2-flow-dissector-matrix-unified/bin/xdp2-flow-dissector-matrix-unified -h
Usage: xdp2-flow-dissector-matrix-unified [OPTIONS] [pcap_file]
  ...
  -j <dir>    Per-cell JSON output directory        (default: unset)
              When set, writes <dir>/<pcap>/<mode>.json for every
              measured (pcap, mode) cell. The text table on stdout
              is unchanged.
```

**Notes:**
- Live end-to-end (`nix run .#flow-dissector-matrix-unified -- -j /tmp/cells`)
  requires xdp2-bench + CAP_BPF on a real host; the schema is
  validated locally via the synthetic check.
- Phase 6 (`aggregate-results`) will consume these per-cell JSONs.

## Phase 6 — `aggregate-results` (Python)

**Status:** done

**Files landed:**
- `nix/scripts/aggregate-results.py` — single-file Python stdlib-only
  aggregator (~330 LoC). Walks
  `<results>/<date>/<testbed>/<host>/<target-ts>/<pcap>/<mode>.json`,
  groups by `(testbed, host, pcap, mode)`, computes mean/median/p95
  and 95% CI (Normal-approx via `1.96 × SEM`), and emits
  `summary.md`, `summary.csv`, and (with `--baseline`)
  `regressions.md`. CLI flags: `--results`, `--out`, `--baseline`,
  `--threshold-pct` (default 10), `--min-iterations` (default 30),
  `--fail-on-regression`.
- `nix/aggregate-results.nix` — `pkgs.writeShellApplication` wrapper
  that execs python3 against the script, with `mainProgram` set so
  `nix run .#flow-dissector-matrix-aggregate` works directly.
- `nix/checks/aggregate-results-test.nix` — pure-Nix
  `runCommand` that synthesizes a 5-cell Phase-5 fixture
  (`hp2`+`hp5` × `combo.pcap`+`tcp_ipv4.pcap` × multiple modes),
  runs the aggregator, validates `summary.csv` parses with
  `csv.DictReader` (5 rows, expected hosts + modes), greps
  `summary.md` for testbed/pcap/mode names, and exercises
  `--baseline` in three modes:
  1. baseline that disagrees on `hp2/rust-graph` produces a
     regression row for that cell **and** does **not** flag
     `hp5/rust-graph` (which matches baseline).
  2. baseline with non-numeric median (`?`) fails with
     "baseline incomplete" in stderr.
  3. `--fail-on-regression` propagates a non-zero exit when
     regressions exist.
- `flake.nix` — exposes
  `packages.<system>.flow-dissector-matrix-aggregate` and wires
  `checks.<system>.aggregate-results`.

**Schema delivered:**

`summary.csv` columns: `testbed, host, pcap, mode, n_iter,
n_replicates, ns_per_pkt_mean, ns_per_pkt_median, ns_per_pkt_p95,
ns_per_pkt_ci95_lo, ns_per_pkt_ci95_hi, mpps_median, build_hash,
kernel, nic_driver, nic_firmware`.

`summary.md`: one section per `(testbed, pcap)`, rows = mode in
canonical order (`c-flowdis-usp`, `c-xdp2-usp`,
`c-xdp2-parse-only`, `c-bpf-flowdis`, `c-bpf-xdp2`, `c-bpf-fast`,
`rust-graph`, `rust-mono`, `rust-compiled`, `rust-template`),
columns = host. Cell content: `<median> ns/pkt (<mpps> Mpps)`
with optional `(low-N)` annotation when
`iterations < --min-iterations`.

`regressions.md`: dual-gate detection — a cell regresses iff
**both** the median delta exceeds `--threshold-pct` (default
10%) **and** new CI95-lo > baseline CI95-hi (CI-disjoint). This
follows the design's §15 guidance ("Win = CI-disjoint;
otherwise = noise") and avoids small-N false positives.

**Deviations from plan:**
- Used `1.96 × SEM` Normal approximation rather than the
  Student-t for CI95. Stdlib lacks t-quantiles and the
  difference is immaterial for the regression-detection
  purpose (the dual-gate's CI-disjoint condition is robust to
  the approximation). Documented inline.
- Skipped `pkgs.jq` from `runtimeInputs` — the Python
  implementation reads JSON directly via `json.loads`, so jq
  is unused.
- Path-inference is forgiving: a malformed tree warns once
  and falls back to `host="unknown"`, `testbed="unknown"`
  rather than failing, so partial result trees still produce
  useful output.

**Verification (all DoD criteria — actual output):**

```bash
$ nix build --no-link --print-out-paths .#flow-dissector-matrix-aggregate
/nix/store/<hash>-flow-dissector-matrix-aggregate

$ nix build --no-link --print-out-paths .#checks.x86_64-linux.aggregate-results
/nix/store/<hash>-aggregate-results-test
$ cat /nix/store/<hash>-aggregate-results-test
ok

# Synthetic single-cell smoke:
$ TMP=$(mktemp -d) && \
  D=$TMP/results/2026-05-04/hp2-hp5-x710/hp5/run-001/combo.pcap && \
  mkdir -p "$D" && \
  printf '{"mode":"rust-graph","pcap":"combo.pcap","ns_per_pkt":12,"mpps":80,"iterations":100,"build_hash":"x","kernel":"6.18.22","nic_driver":"i40e","nic_firmware":""}\n' > "$D/rust-graph.json" && \
  nix run .#flow-dissector-matrix-aggregate -- --results "$TMP/results"
$ cat "$TMP/results/summary.md"
## hp2-hp5-x710 — `combo.pcap`
| Mode | hp5 |
|---|---|
| rust-graph | 12 ns/pkt (80 Mpps) |
$ cat "$TMP/results/summary.csv"
testbed,host,pcap,mode,n_iter,n_replicates,...
hp2-hp5-x710,hp5,combo.pcap,rust-graph,100,1,12,12,12,—,—,80,x,6.18.22,i40e,
```

**Notes:**
- Live end-to-end (against a real Phase-5 result tree from
  `hp2`/`hp5`) is exercised in Phase 7's composed
  `flow-dissector-matrix-run` wrapper.
- The `regressions.md` dual-gate aligns with the design's
  noise-rejection guidance and is unit-tested both for the
  positive (hp2 disagreement → flagged) and negative
  (hp5 agreement → not flagged) cases.

## Phases 7–9

These phases require either:
- Multi-host orchestration with live ssh access (Phases 7, 8),
- Live hardware to verify (Phase 8 — AF_XDP), or
- A second NIC family on a real testbed (Phase 9 — mlx5_core).

Details remain in
[`flow-dissector-matrix-implementation-plan.md`](flow-dissector-matrix-implementation-plan.md).

## Cross-Phase Notes

- All result trees emitted by future phases will live under
  `perf-results/<date>/<testbed.name>/` so multiple testbeds (e.g.
  `hp2-hp5-x710` and a future Mellanox testbed) coexist without
  clobbering each other.
- The 2026-05-02 reference numbers in
  `perf-results/2026-05-02-physical-testbed-summary.md` are the
  baseline that the final implementation must reproduce within 95%
  CI (specifically: `xdp2-rs graph-enum` at ~12 ns/pkt on combo.pcap).
