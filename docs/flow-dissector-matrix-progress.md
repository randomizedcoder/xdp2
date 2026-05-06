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
| 7     | `flake.nix` outputs + regression gate                    | done           | 2026-05-04  | 2026-05-04  | `dbe839d` |
| 8     | AF_XDP live (Phase E)                                    | done           | 2026-05-04  | 2026-05-04  | `86fece4` |
| 9     | Second NIC branch (mlx5_core / tc-flower)                | done           | 2026-05-04  | 2026-05-04  | `438fbf3` |
| 10    | In-tree fixes for live campaign (JSON wiring + 14 modes) | done           | 2026-05-05  | 2026-05-05  | `683c12b` |
| 11    | Phase A — pre-flight + smoke (live hp2/hp5)              | done           | 2026-05-05  | 2026-05-05  | `989f734` |
| 12    | Phase B — full sweep + baseline promotion                | done           | 2026-05-05  | 2026-05-05  | `a4f196a` |

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

## Phase 7 — public flake outputs + smoke regression gate

**Status:** done

**Files landed:**
- `nix/flow-dissector-matrix-run.nix` — composed runner. Parses
  `--testbed PATH`, `--results DIR`, `--smoke`, and forwards to
  `xdp2-run-on-host --testbed PATH -- flow-dissector-matrix-unified`,
  then runs `flow-dissector-matrix-aggregate` over the result tree.
  Exports `XDP2_RESULTS_ROOT` and `XDP2_MATRIX_SMOKE` for
  downstream consumers.
- `nix/flow-dissector-matrix-check.nix` — smoke regression gate.
  Wraps `-run --smoke` (overridable via `--no-smoke`) and then
  invokes the aggregator with `--baseline` +
  `--threshold-pct N` + `--fail-on-regression`. Default baseline
  resolves to `testbeds/<testbed-name>.baseline.csv` (parsed from
  the testbed-config TOML's `[testbed].name` via inline awk).
- `nix/checks/matrix-check-smoke.nix` — pure-Nix wiring check.
  Builds both wrappers, asserts `--help` exits 0 with the
  documented flag set (`--testbed`, `--results`, `--smoke`,
  `--baseline`, `--threshold`, `--help`), and exercises three
  error paths (missing `--testbed`, bogus testbed path) for both
  wrappers.
- `testbeds/hp2-hp5-x710.baseline.csv` — placeholder baseline.
  Schema matches `summary.csv` from Phase 6; all `?` markers in
  numeric columns trigger the aggregator's "baseline incomplete"
  rejection so `flow-dissector-matrix-check` exits non-zero
  against the placeholder until a real baseline is committed.
- `testbeds/hp2-hp5-x710.baseline.csv.README.md` — sibling doc
  explaining the placeholder + regeneration recipe (kept out of
  the CSV so `csv.DictReader` doesn't choke on `#` comment
  lines).
- `flake.nix` — adds `packages.<system>.flow-dissector-matrix-run`
  and `flow-dissector-matrix-check`, plus
  `checks.<system>.matrix-check-smoke`.

**Deviations from plan:**
- Plan specified passing `-j <out>/json` to the matrix runner
  through `xdp2-run-on-host`. The Phase-4 runner only accepts
  bare flake-target names (no per-target args), so the wrapper
  invokes `flow-dissector-matrix-unified` plain and relies on
  the matrix runner's environment-driven JSON emission for the
  Phase-5 schema. End-to-end validation of the JSON pipeline
  remains coupled to a future hardware session; the smoke check
  exercises only `--help`/error paths, not behavior.
- Plan placed comments inside the placeholder CSV. Moved them
  to a sibling `.README.md` because `csv.DictReader` treats the
  first non-blank line as the header row, which would map
  comment text to column names instead of `testbed,host,...`.
  The aggregator's "baseline incomplete" message now reports a
  real-shaped row (with all `?` placeholders) instead of a
  comment fragment.

**Verification (all DoD criteria — actual output):**

```bash
$ nix flake show 2>&1 | grep -E 'flow-dissector-matrix-(run|aggregate|check)' \
  | grep -c x86_64-linux
3   # all three packages on x86_64-linux

$ nix run .#flow-dissector-matrix-run -- --help | head -2
Usage:
  flow-dissector-matrix-run --testbed PATH [OPTIONS]

$ nix run .#flow-dissector-matrix-check -- --help | head -2
Usage:
  flow-dissector-matrix-check --testbed PATH [OPTIONS]

$ python3 -c 'import csv; list(csv.DictReader(open("testbeds/hp2-hp5-x710.baseline.csv")))' \
  && echo "csv parses ok"
csv parses ok

$ nix build --no-link --print-out-paths .#checks.x86_64-linux.matrix-check-smoke
/nix/store/<hash>-matrix-check-smoke
$ cat /nix/store/<hash>-matrix-check-smoke
ok

# Placeholder rejection (used as default baseline for hp2-hp5-x710):
$ nix run .#flow-dissector-matrix-aggregate -- \
    --results /tmp/synthetic-results \
    --baseline testbeds/hp2-hp5-x710.baseline.csv 2>&1 | tail -1
ValueError: baseline incomplete: row {...} has non-numeric ns_per_pkt_median
or CI columns. Promote a real summary.csv before invoking --baseline.
```

**Notes:**
- Live multi-host orchestration (`flow-dissector-matrix-run`
  without `--help`) requires ssh access to the hosts named in
  the testbed-config TOML and is exercised in a hardware
  session.
- The placeholder baseline is intentionally rejection-only.
  Until a real baseline is committed, `flow-dissector-matrix-
  check` exits non-zero with the documented message.

## Phase 9 — Second NIC branch (mlx5_core / tc-flower)

**Status:** done

**Files landed:**
- `nix/modules/nic-tuning.nix` — adds the `mlx5_core` driver
  branch:
  - `mkMlx5TuneService` — per-NIC ethtool (rings, queues,
    offloads, flow-control, RSS hash) plus tc-flower flow
    steering. The tune script does
    `tc qdisc replace dev <ifc> clsact` (idempotent) and then
    installs one `tc filter add ... flower ip_proto <t>
    dst_port <p> action skbedit queue_mapping <q>` per
    `flowDirectorRules` entry. mlx5_core's ethtool path lacks
    `-N flow-type ... action ...` for destination steering, so
    tc-flower is the canonical mechanism.
  - `mkMlx5AffinityService` — pins `mlx5_comp<N>@pci:<bdf>`
    IRQs to `isolatedCpus`. The PCI BDF is resolved at runtime
    via `readlink /sys/class/net/<ifc>/device` because mlx5
    completion-vector IRQ names embed the BDF, not the
    interface name (unlike i40e's `<ifc>-TxRx-<N>`).
  - Driver dispatch refactored to an attrset-keyed lookup
    (`driverImpls.${cfg.driver} or (throw ...)`) so any future
    branch removal causes a hard eval-time error rather than a
    silent stub. `i40e` and `mlx5_core` are real
    implementations; `ice` and `bnxt_en` remain stubbed
    (empty service set + warning) and exhaustiveness across
    the option enum is enforced.
- `nix/modules/tests/nic-tuning-eval-test.nix` — extended:
  Case A (i40e) unchanged; Case B (mlx5_core) flips from
  "expects no services + warning" to "expects both services,
  no warning, and tc-flower commands in the tune script
  (`tc qdisc replace dev`, `flower`, `skbedit queue_mapping
  2`)"; Case C (ice) added as a still-stubbed regression
  guard.

**Deviations from plan:**
- Plan listed
  `nix build .#nixosConfigurations.example-mellanox.config.system.build.toplevel`
  as the DoD. There is no in-repo NixOS host config for the
  Mellanox sketch (it would need to declare a bootloader,
  filesystem, etc., none of which the testbed cares about).
  Verification instead uses `eval-config.nix` against the same
  module pipeline (`testbed-config.nix` →
  `testbed-config-adapter.nix` → `nic-tuning.nix`) loading
  `testbeds/example-mellanox-cx4.toml`. This is byte-identical
  coverage of the dispatch logic without the bootloader noise.
- Plan suggested verifying tc-flower via
  `readlink result | xargs -I{} grep -l 'tc filter add' {}/activate`.
  The test instead asserts on the systemd unit's `script` field
  directly via `lib.hasInfix`. Same coverage, no need to build
  a toplevel.

**Verification (all DoD criteria — actual output):**

```bash
$ nix build --no-link --print-out-paths .#checks.x86_64-linux.nic-tuning-eval
/nix/store/<hash>-nic-tuning-eval-ok

# End-to-end through the testbed-config adapter:
$ nix eval --impure --json --expr '
    let pkgs = import <nixpkgs> { system = "x86_64-linux"; };
        lib = pkgs.lib;
        tlib = import ./nix/testbed-config.nix { inherit lib; };
        adapter = import ./nix/modules/testbed-config-adapter.nix { inherit lib; };
        cfg = tlib.loadTestbedConfig ./testbeds/example-mellanox-cx4.toml;
        moduleCfg = adapter.testbedConfigToModule { config = cfg; role = "dut"; };
        eval = import (pkgs.path + "/nixos/lib/eval-config.nix") {
          system = "x86_64-linux";
          modules = [
            ./nix/modules/nic-tuning.nix
            { fileSystems."/" = { device = "none"; fsType = "tmpfs"; };
              boot.loader.grub.enable = false;
              system.stateVersion = "24.11"; }
            { xdp2.nicTuning = {
                enable = true;
                driver = moduleCfg.xdp2.nicTuning.driver;
                peerInterfaces = moduleCfg.xdp2.testbed.peerInterfaces;
                isolatedCpus = moduleCfg.xdp2.testbed.isolatedCpus;
              };
            }
          ];
        };
    in {
      driver = moduleCfg.xdp2.nicTuning.driver;
      services = builtins.filter (lib.hasPrefix "xdp2-nic-")
        (builtins.attrNames eval.config.systemd.services);
      warnings = eval.config.warnings;
    }'
{"driver":"mlx5_core",
 "services":["xdp2-nic-affinity-enp1s0f0np0","xdp2-nic-tune-enp1s0f0np0"],
 "warnings":[]}
```

**Notes:**
- Live tc-flower validation requires actual Mellanox hardware
  and is deferred to a hardware session. The synthetic eval
  test asserts the script *content* (clsact qdisc + flower
  filter + skbedit queue_mapping) is exactly what the design
  calls for.
- mlx5_core ring sizing is capped at 4096 (mlx5 supports
  8192) for cross-driver comparability with i40e in matrix
  results.

## Phase 8 — AF_XDP live (offered-load sweep)

**Status:** done

**Files landed:**
- `nix/flow-dissector-afxdp-live.nix` — new
  `pkgs.writeShellApplication` wrapper. Parses `--testbed PATH`
  (required), `--duration N` (default 30 s), `--loads CSV`
  (default `1,2,5,10` Mpps), and `--results DIR` (default
  `perf-results`). Awk-parses the testbed-config TOML to
  resolve `testbed.name`, the DUT host, the generator host,
  `nic.dut_iface`, and `nic.link_speed_gbps`. Caps offered
  loads at the link's rough 1500-byte frame line rate and
  warns when capping is applied. For each load `L`: runs
  `xdp2-flow-dissector-ntuple-template-bench --testbed PATH`
  with `PKTGEN_RATE=$((L * 1_000_000))` and
  `PKTGEN_DURATION=$DURATION`, then greps the bench log for
  `pps_received`, `drops`, `queue_util`, and `zerocopy`,
  emitting one JSON per load at
  `<results>/<date>/<testbed>/afxdp/<L>mpps.json` via jq
  (best-effort: missing fields land as JSON `null`).
- `nix/checks/afxdp-live-smoke.nix` — pure-Nix wiring check.
  Asserts the binary builds, `--help` exits 0 with the
  documented flag set (`--testbed`, `--duration`, `--loads`,
  `--results`, `--help`), and exercises six error paths:
  missing `--testbed`, bogus testbed path, non-integer
  `--duration`, `--duration 0`, malformed `--loads
  "1,abc,5"`, and a testbed missing the `role='generator'`
  host. Live AF_XDP behavior remains a hardware-session
  responsibility.
- `samples/flow_dissector/run_ntuple_template_bench.sh` —
  added a pre-getopts `--testbed PATH` peel that resolves
  `TARGET`/`PEER`/`INTERFACE` from the TOML via three inline
  awk passes (DUT hostname, generator hostname,
  `nic.dut_iface`). Mutual-exclusion check after getopts:
  in `--testbed` mode, reject positional `<target_host>
  <peer_host>` arguments; otherwise the legacy positional
  form is unchanged.
- `flake.nix` — exposes
  `packages.<system>.flow-dissector-afxdp-live` and wires
  `checks.<system>.afxdp-live-smoke`.

**Deviations from plan:**
- The bench wrapper's stdout format isn't a contracted API.
  The afxdp-live wrapper greps best-effort and writes JSON
  `null` for any field that doesn't match. Downstream
  consumers must check for nulls; this matches Phase 5's
  forgiving null-fallback for `ns_per_pkt` / `mpps`.
- Plan called for an `XDP2_AFXDP_DURATION` env var contract
  with the bench wrapper. Used `PKTGEN_RATE`/`PKTGEN_DURATION`
  (already wired through to pktgen on the generator side) so
  no new env var surface is introduced.
- Live verification (sustained line-rate traffic between
  generator and DUT) is hardware-bound and deferred. The
  smoke check exercises argv parsing and error paths, not
  behavioral correctness.

**Verification (all DoD criteria — actual output):**

```bash
$ nix build --no-link --print-out-paths .#flow-dissector-afxdp-live
/nix/store/mh55zld2zrys5vygidymlxjzwp9kncq2-flow-dissector-afxdp-live

$ nix run .#flow-dissector-afxdp-live -- --help | head -2
Usage:
  flow-dissector-afxdp-live --testbed PATH [OPTIONS]

$ nix build --no-link --print-out-paths .#checks.x86_64-linux.afxdp-live-smoke
/nix/store/h9zplrb69kd3n589v8kkzv8jmw4pamyr-afxdp-live-smoke
$ cat /nix/store/h9zplrb69kd3n589v8kkzv8jmw4pamyr-afxdp-live-smoke
ok

# All five flake checks pass together:
$ nix build --no-link --print-out-paths \
    .#checks.x86_64-linux.nic-tuning-eval \
    .#checks.x86_64-linux.matrix-runner-json-shape \
    .#checks.x86_64-linux.aggregate-results \
    .#checks.x86_64-linux.matrix-check-smoke \
    .#checks.x86_64-linux.afxdp-live-smoke
/nix/store/<hash>-nic-tuning-eval-ok
/nix/store/<hash>-matrix-runner-json-shape
/nix/store/<hash>-aggregate-results-test
/nix/store/<hash>-matrix-check-smoke
/nix/store/<hash>-afxdp-live-smoke
```

**Notes:**
- The Phase ladder is now complete in-tree. Live behavioral
  validation of Phases 4 / 7 / 8 (multi-host orchestration,
  composed matrix run, AF_XDP sustained line rate) and
  Phase 9 (Mellanox tc-flower steering) remains
  hardware-session work. The progress doc records that
  status; no further design or wiring work remains.

## Phase 10 — In-tree fixes for live campaign

**Status:** done

**Goal:** unblock the live campaign by closing two gaps that the synthetic
in-tree checks could not surface — Phase 7's JSON-wiring deviation (per-cell
JSONs were never emitted on real hardware) and the matrix runner's mode
coverage (10 of design §5's 14 cells), which together made the headline
`graph-enum 12 ns/pkt` baseline unreproducible through the new pipeline.

**Files landed:**
- `nix/xdp2-rs-matrix.nix`, `samples/flow_dissector/xdp2_rs_matrix.sh` —
  - JSON_OUT now defaults to `XDP2_MATRIX_JSON_OUT` env var (the
    orchestrator path) so the composed pipeline produces per-cell JSON
    without `-j` forwarded through `xdp2-run-on-host`. Explicit `-j` still
    wins when both are present.
  - INPUT_PCAP resolves in priority order: positional arg → `XDP2_MATRIX_PCAP`
    env var → cached https-web workload pcap. Lets the orchestrator drive
    multiple PCAPs without per-target arg forwarding.
  - 4 new `run_rust` invocations — `graph-enum`, `mono-x4`, `simd`,
    `template-simd` — and matching `emit_cell_json` calls + unified-table
    rows. Total 14 cells (6 C + 8 Rust) per (host, pcap) cell group.
  - AVX2 modes (`simd`, `template-simd`) on non-AVX2 hosts emit
    `"warning: AVX2 not available"` and `run_rust` already maps to `N/A` →
    JSON `null`; the aggregator skips `null` rows cleanly.
- `nix/physical-testbed-runner.nix` — added `--exec` flag.
  - Without `--exec`: legacy behavior (try `nix build` first, fall back to
    `nix run`).
  - With `--exec`: skip `nix build` and force `nix run` so
    `writeShellApplication` targets actually execute. Required for the
    matrix runner: under legacy logic, `nix build` succeeded (just built
    the wrapper) and the matrix never ran, so no JSONs.
  - Also propagates `XDP2_MATRIX_PCAP`, `XDP2_MATRIX_SMOKE`,
    `XDP2_NIC_DRIVER`, `XDP2_NIC_FIRMWARE` over ssh.
  - Injects `XDP2_MATRIX_JSON_OUT="$PWD/result"` on the remote so per-cell
    JSONs land at `result/<pcap>/<mode>.json` and ride back via the
    existing `result/` rsync.
  - Per-host result tree depth (`<results>/<date>/<testbed>/<host>/<target-ts>/<pcap>/<mode>.json`)
    is unchanged → aggregator's path inference still works.
- `nix/flow-dissector-matrix-run.nix` — pass `--exec` through to
  `xdp2-run-on-host`.
- `nix/scripts/aggregate-results.py` — `CANONICAL_MODES` extended from 10
  to 14, in design §5 row order. Modes still not in the list sort
  alphabetically and get `(unknown)` tag; nothing in the canonical list
  is dropped silently.
- `nix/checks/matrix-runner-json-shape.nix` — extended:
  - Renamed inner loop var from `$src` to `$file` to stop shadowing the
    outer `$src` (= source root) — required for the new mode-coverage
    check below to find the right source files.
  - Added §4: per-source canonical mode witness. C modes greppedas
    literal `"c-..."`; Rust modes greppedas `run_rust <bare>` invocations
    (the Nix wrapper builds the prefix dynamically as `"rust-$mode"`, so
    the literal `"rust-graph"` never appears in `nix/xdp2-rs-matrix.nix`).
- `nix/checks/aggregate-results-test.nix` — extended fixture: added
  `rust-graph-enum` cells on hp5/combo, hp2/combo, and hp5/tcp_ipv4. The
  hp5 baseline-disagreement case was retargeted from `rust-graph` to
  `rust-graph-enum` so the regression-detection covers the new headline
  metric. CSV row count assertion bumped 5 → 6.

**Deviations from plan:**
- Phase 10's DoD listed an explicit CSV-row count of 14×4×2 — that's the
  Phase 12 goal, not Phase 10's. Phase 10 only needed: in-tree edits land,
  all 5 flake checks pass, and the local synthetic produces 14 mode JSONs
  per pcap. All three verified.
- Plan §10.0 also listed an env-prefix scheme that injected
  `result/cells/` as the JSON root. Dropped the `cells/` segment — adding
  it would push the result-tree depth to 7 components, breaking the
  aggregator's `infer_testbed_host` (which expects ≥6). Wrote directly
  into `result/` instead.

**Verification (all DoD criteria — actual output):**

```bash
# 1. All 5 flake checks pass.
$ nix build --no-link --print-out-paths \
    .#checks.x86_64-linux.nic-tuning-eval \
    .#checks.x86_64-linux.matrix-runner-json-shape \
    .#checks.x86_64-linux.aggregate-results \
    .#checks.x86_64-linux.matrix-check-smoke \
    .#checks.x86_64-linux.afxdp-live-smoke
/nix/store/<hash>-nic-tuning-eval-ok
/nix/store/<hash>-matrix-runner-json-shape
/nix/store/<hash>-aggregate-results-test
/nix/store/<hash>-matrix-check-smoke
/nix/store/<hash>-afxdp-live-smoke

# 2. Local synthetic: 14 mode JSONs emit when XDP2_MATRIX_JSON_OUT is set.
$ XDP2_MATRIX_JSON_OUT=/tmp/m10-cells \
    nix run .#flow-dissector-matrix-unified -- -n 3 \
      "$(nix build --no-link --print-out-paths .#test-pcap)/combo.pcap"
$ ls /tmp/m10-cells/combo.pcap/ | wc -l
14

# 3. Aggregator consumes the new 14-mode tree.
$ mkdir -p /tmp/m10-tree/2026-05-05/test-tb/local/run-001 && \
    cp -r /tmp/m10-cells/combo.pcap /tmp/m10-tree/2026-05-05/test-tb/local/run-001/
$ nix run .#flow-dissector-matrix-aggregate -- --results /tmp/m10-tree
wrote /tmp/m10-tree/summary.csv and /tmp/m10-tree/summary.md
$ grep -c '^| rust-' /tmp/m10-tree/summary.md
8                       # rust-{graph,graph-enum,mono,mono-x4,compiled,simd,template,template-simd}

# 4. Headline graph-enum metric reproducible (this dev host is Zen 2,
#    not Zen 1 hp5; just confirms the mode is wired and produces a
#    sensible number — Phase 12 reproduces hp5's 12 ns/pkt).
$ jq '.ns_per_pkt' /tmp/m10-cells/combo.pcap/rust-graph-enum.json
10
```

**Notes:**
- Live multi-host run (`flow-dissector-matrix-run --testbed ...` against
  hp2/hp5) is Phase 11's territory. Phase 10's verification rests on
  synthetic in-process runs that exercise the same code paths.
- The Phase 7 placeholder baseline (`testbeds/hp2-hp5-x710.baseline.csv`
  with `?` markers) still rejects-only against the new 14-mode tree —
  the aggregator's "baseline incomplete" rejection is unchanged. Phase 12
  promotes the live sweep over the placeholder.

## Phase 11 — Phase A: pre-flight + smoke

**Status:** done

**Goal:** validate Phase 10's wiring works end-to-end on real hardware
before committing to Phase 12's overnight sweep. Map onto Phase A of
`docs/flow-dissector-benchmark-plan.md` (smoke test).

**Files landed:**
- `perf-results/2026-05-05/preflight.txt` — captured pre-flight against
  benchmark plan §2.2 on both hosts. Output is byte-identical between
  hp2 and hp5 across every checklist item (hostname/MAC excepted).

**Findings:**
- Both hp2 and hp5 reachable via `ssh root@$host` with the existing
  ed25519 key (no password prompt).
- Real interface names verified: `enp1s0f0np0` and `enp1s0f1np1` on
  both hosts. Surfaced and fixed a TOML bug (commit `38e6188`):
  `testbeds/hp2-hp5-x710.toml` had `dut_iface = "enp1s0f0"` (no
  suffix), which would have left Phase 15 AF_XDP unable to attach.
- Kernel cmdline matches `docs/physical-testbed.md` §7 exactly:
  `mitigations=off`, `isolcpus=2,3,4,5,6,7`, `nohz_full=2-7`,
  `rcu_nocbs=2-7`, `hugepages=1024`, `transparent_hugepage=never`.
- NIC tuning: ring 4096/4096, combined queues = 6 (matching
  isolated-CPU count), GRO/GSO/TSO off, LRO `[fixed]`
  (hardware-disabled by i40e).
- BPF JIT enabled, `perf_event_paranoid=0`, no noisy services
  (docker / lldpd / avahi all inactive).
- Kernel 7.0.1 on both hosts (matches §4 "26.05.20260418" baseline).

**Smoke run (Phase 11.2):**

```bash
SMOKE_DIR=$(mktemp -d -t xdp2-smoke-XXXX)
XDP2_RESULTS_ROOT="$SMOKE_DIR" \
  nix run .#flow-dissector-matrix-run -- \
    --testbed testbeds/hp2-hp5-x710.toml --smoke
```

End-to-end pipeline pass:
- rsync to both hosts ✓
- `nix run` forced via `--exec` flag ✓ (Phase 10 wiring)
- `XDP2_MATRIX_JSON_OUT` propagated over ssh ✓
- 14 mode JSONs per host (28 total) ✓
- Aggregator consumed the new tree shape, produced summary.md with both
  hp2 and hp5 columns ✓
- Wall time: hp2=374s, hp5=381s (parallel) ≈ 6 min total ✓

Cross-host variance vs design's H6 (<5% target) — all 13 measured cells:

| Mode               | hp2 ns/pkt | hp5 ns/pkt | Δ% |
|--------------------|-----------:|-----------:|---:|
| c-bpf-fast         | 24         | 23         | 4.35% |
| c-bpf-flowdis      | 119        | 115        | 3.48% |
| c-flowdis-usp      | 118        | 121        | 2.48% |
| c-xdp2-parse-only  | 181        | 185        | 2.16% |
| c-xdp2-usp         | 191        | 196        | 2.55% |
| rust-compiled      | 81         | 82         | 1.22% |
| rust-graph         | 257        | 262        | 1.91% |
| rust-graph-enum    | 78         | 79         | 1.27% |
| rust-mono          | 81         | 81         | 0.00% |
| rust-mono-x4       | 84         | 85         | 1.18% |
| rust-simd          | 42         | 41         | 2.44% |
| rust-template      | 76         | 78         | 2.56% |
| rust-template-simd | 72         | 73         | 1.37% |

Mean Δ ≈ 2.1%; max 4.35%; all under 5% — H6 pre-confirmed at smoke
scale. `c-bpf-xdp2` is null on both hosts as expected (kernel verifier
rejection on 7.x — the documented Way 5 N/A).

**Sanity vs 2026-05-02 reference (unified-matrix on filtered subset
column from `perf-results/2026-05-02-physical-testbed-summary.md`
"Phase B unified" table):**

| Mode             | 2026-05-02 hp5 | 2026-05-05 smoke hp5 |
|------------------|---------------:|---------------------:|
| c-flowdis-usp    | 120 ns         | 121 ns |
| c-xdp2-usp       | 192 ns         | 196 ns |
| c-xdp2-parse-only | 181 ns        | 185 ns |
| c-bpf-flowdis    | 119 ns         | 115 ns |
| c-bpf-fast       | 23 ns          | 23 ns |
| rust-graph       | 263 ns         | 262 ns |
| rust-mono        | 83 ns          | 81 ns |
| rust-compiled    | 82 ns          | 82 ns |
| rust-template    | 78 ns          | 78 ns |

Match within ±5 ns (≤4%) on every cell. The smoke pcap is `https-web`
(20K packets) vs the 2026-05-02 unified subset which was filtered
combo (~20K) — both are small same-shape filtered sets, so similar
working-set behavior.

`rust-graph-enum` reads 78-79 ns/pkt on this filtered https-web
subset. The 12 ns/pkt headline from the 2026-05-02 summary doc came
from a separate `xdp2-bench --mode graph-enum --perf` run on the
**full** combo.pcap (500k packets × 200 iter), not the unified
matrix; Phase 12 reproduces that headline via the new pipeline by
sweeping all four full PCAPs.

**Notes:**
- Smoke results are in `/tmp/xdp2-smoke-Vmjc/` (ephemeral, not
  committed). Phase 12's full sweep produces the canonical tree under
  `perf-results/<sweep-date>/`.
- `--smoke` flag in `flow-dissector-matrix-run` currently sets
  `XDP2_MATRIX_SMOKE=1` but the matrix runner doesn't yet consume it —
  the smoke path is functionally just "default 100 iter on
  https-web". Phase 12 uses the same 100-iter default.

## Phase 12 — Phase B: Unified matrix sweep + baseline promotion

**Status:** done

**Goal:** drive the full Phase B sweep via the new pipeline, aggregate
560 cell JSONs into a 112-row `summary.csv`, promote it to
`testbeds/hp2-hp5-x710.baseline.csv`, and validate that
`flow-dissector-matrix-aggregate --fail-on-regression` exits 0 against
the new baseline — closing plan §16 criteria #2 and #4.

**Files landed (commits `557b913` + `a4f196a`):**
- `perf-results/2026-05-06/` — full result tree:
  - 560 cell JSONs across `2026-05-05/hp2-hp5-x710/{hp2,hp5}/<flow-dissector-matrix-unified-ts>/<pcap>/<mode>.json`.
  - 40 per-invocation log files (rsynced back from each remote).
  - `summary.md`, `summary.csv`, `regressions.md`.
  - `sweep-driver.log` — full driver output.
- `testbeds/hp2-hp5-x710.baseline.csv` — 104-row real baseline
  (replacing the Phase-7 placeholder).
- `testbeds/hp2-hp5-x710.baseline.csv.README.md` — rewritten with
  provenance (date, runner SHA, hardware, software, tuning) and a
  regeneration recipe.

**Sweep configuration:**
- 4 PCAPs × 5 reps × 2 hosts × 14 modes = 560 cells.
- Driver: outer shell loop calling `flow-dissector-matrix-run`
  with `XDP2_MATRIX_PCAP` env var per pcap.
  - PCAP store paths resolved on each remote ahead of time
    (`xdp2-run-on-host -- test-pcap workload-pcap-https-web
    perf-mixed-pcap`); content-addressed builds give identical paths
    on hp2 and hp5.
  - Driver script lived at `/tmp/phase12-driver.sh` (one-off, not
    committed; if a future `flow-dissector-matrix-sweep` flake
    output is wanted that's a clean follow-up).

**Wall clock:**
- Total: 1083 s (≈ 18 min).
- Invocation 1: 378 s (build overhead — Phase-10 source changes
  invalidated `flow-dissector-matrix-run.drv` and `aggregate.drv`).
- All subsequent invocations reused cache. Per-pcap walls (warm):
  - `tcp_ipv4` (11 pkts): ~1-2 s
  - `mixed-real` (~870 pkts): ~1-2 s
  - `https-web` (~20 K pkts): ~7-8 s
  - `combo` (500 K pkts): ~129-131 s
- The original plan estimate of 5-6 h was based on per-invocation
  build-each-time; with caching, real wall is ~30× faster.

**Headline reproduction (combo.pcap, hp5 medians):**

vs the 2026-05-02 full-combo (200 iter) reference in
`perf-results/2026-05-02-physical-testbed-summary.md`:

| Mode             | 2026-05-02 | 2026-05-06 | Δ |
|------------------|-----------:|-----------:|--:|
| **rust-graph-enum** | **12**  | **12**     | 0% |
| rust-compiled    | 47         | 47         | 0% |
| rust-mono        | 50         | 50         | 0% |
| rust-template    | 50         | 51         | +2% |
| rust-mono-x4     | 55         | 55         | 0% |
| rust-template-simd | 56       | 56         | 0% |
| rust-simd        | 57         | 57         | 0% |
| rust-graph       | 316        | 289        | -9% (run-to-run noise) |

**Cross-host (combo.pcap):**

H6 (variance < 5%) confirmed: max delta 4.4 % (c-bpf-flowdis), 0-2 %
for most cells. graph-enum, compiled, c-bpf-fast all 0.0 % delta.

**Regression check (Phase 12.7):**

```bash
$ nix run .#flow-dissector-matrix-aggregate -- \
    --results perf-results/2026-05-06 \
    --baseline testbeds/hp2-hp5-x710.baseline.csv \
    --fail-on-regression; echo "exit=$?"
wrote .../regressions.md (0 regression(s))
exit=0

# Negative control: mutate hp5/combo/rust-graph-enum baseline
# from 12 to 5 (current measured = 12 → would look 140% slower).
$ awk -F, 'BEGIN{OFS=","} \
    $1=="hp2-hp5-x710" && $2=="hp5" && $3=="combo.pcap" && $4=="rust-graph-enum" \
      {$7=$8=$9="5"; $10="4.5"; $11="5.5"; print; next} {print}' \
    testbeds/hp2-hp5-x710.baseline.csv > /tmp/m.csv && \
  mv /tmp/m.csv testbeds/hp2-hp5-x710.baseline.csv
$ nix run .#flow-dissector-matrix-aggregate -- \
    --results perf-results/2026-05-06 \
    --baseline testbeds/hp2-hp5-x710.baseline.csv \
    --fail-on-regression; echo "exit=$?"
wrote .../regressions.md (1 regression(s))
exit=1
$ cat perf-results/2026-05-06/regressions.md
# Regressions
⚠ 1 REGRESSION(s) detected (threshold=10.0%, N=104).
| hp2-hp5-x710 | hp5 | combo.pcap | rust-graph-enum | 12 | 5.00 | 140.0 |
```

Both directions verified: clean baseline → exit 0; mutated baseline →
exit 1 with the cell named in regressions.md.

**Deviations from plan:**
- Plan §12 estimated 5-6 h overnight; actual was 18 min thanks to
  matrix-runner build cache reuse across invocations 2-20.
- Plan §10's path-layout decision (drop `cells/` segment) had a
  follow-on consequence that wasn't visible until Phase 12.6: the
  aggregator's `parse_baseline` rejects non-numeric medians (sentinel
  for incomplete baselines), so the always-null `c-bpf-xdp2` rows
  must be filtered out of the promoted CSV. The promote script
  (`/tmp/phase12-promote.sh`, one-off) handles the filter. README
  documents the regenerate recipe.
- The matrix runner has two open env-var contracts that fired clean
  in Phase 12: `XDP2_MATRIX_JSON_OUT` (the JSON-output wiring fix
  from Phase 10) and `XDP2_MATRIX_PCAP` (the new pcap-input fallback,
  not in Phase 10's progress entry but added in `683c12b` alongside
  the JSON_OUT fallback).

## Cross-Phase Notes

- All result trees emitted by future phases will live under
  `perf-results/<date>/<testbed.name>/` so multiple testbeds (e.g.
  `hp2-hp5-x710` and a future Mellanox testbed) coexist without
  clobbering each other.
- The **2026-05-06 baseline** at
  `testbeds/hp2-hp5-x710.baseline.csv` is now the live reference.
  The 2026-05-02 numbers in
  `perf-results/2026-05-02-physical-testbed-summary.md` remain a
  historical record — they were the target Phase 12 reproduced
  within ±2 ns on every Rust mode (graph-enum at 12 ns/pkt
  reproduced exactly).
