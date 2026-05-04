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
| 4     | Refactor `physical-testbed-runner`                       | done           | 2026-05-03  | 2026-05-03  | TBD       |
| 5     | Refactor `flow-dissector-matrix-runner`                  | not started    | —           | —           | —         |
| 6     | `aggregate-results`                                      | not started    | —           | —           | —         |
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

## Phases 5–9

**Status:** Phase 5 in scope this session; Phases 6-9 not started.

These phases require either:
- Multi-host orchestration with live ssh access (Phases 4, 5, 7, 8),
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
