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
| 0     | Pre-flight                                               | done           | 2026-05-02  | 2026-05-02  | (this commit) |
| 1     | `testbed-config` schema + loader                         | not started    | —           | —           | —         |
| 2     | `testbed-config`-to-module adapter                       | not started    | —           | —           | —         |
| 3     | `nic-tuning` NixOS module (i40e)                         | not started    | —           | —           | —         |
| 4     | Refactor `physical-testbed-runner`                       | not started    | —           | —           | —         |
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

**Status:** not started

Pending implementation. Will produce:
- `nix/testbed-config.nix` — TOML loader + validator.
- `testbeds/hp2-hp5-x710.toml` — reference testbed (Intel X710 / i40e).
- `testbeds/example-mellanox-cx4.toml` — Mellanox sketch
  (mlx5_core / tc-flower) for portability validation.
- `flake.nix` — expose `testbedConfigs.<name>`.

**Definition of Done (from plan):**
- `nix eval .#testbedConfigs.hp2-hp5-x710.nic.driver` → `"i40e"`
- `nix eval .#testbedConfigs.example-mellanox-cx4.nic.driver` →
  `"mlx5_core"`
- `nix eval .#testbedConfigs.hp2-hp5-x710.hosts.dut.hostname` →
  `"hp5"`
- TOML with two `dut` roles fails evaluation with a clear message.

## Phase 2 — `testbed-config`-to-module adapter

**Status:** not started

Pending implementation. Will produce:
- `nix/modules/testbed-config-adapter.nix` — pure helper mapping
  testbed-config attrset onto the existing
  `xdp2.testbed.*` options exposed by
  `nix/modules/physical-testbed.nix`.
- `flake.nix` — expose `lib.testbedConfigToModule`.

**Note:** Plan originally called this a "refactor" of
`physical-testbed.nix`. Investigation showed the module is already
fully option-driven (nothing hardcoded to `hp2`/`hp5`); a
**non-invasive adapter** is the correct shape. The module itself is
not modified in this work.

**Definition of Done (from plan):**
- `nix eval .#lib.testbedConfigToModule .#testbedConfigs.hp2-hp5-x710 "dut"`
  produces an attrset with
  `xdp2.testbed.isolatedCpus = [ 2 3 4 5 6 7 ]`,
  `hugepages2M = 1024`.
- CPU-range parser handles `"2-7"` → `[ 2 3 4 5 6 7 ]` and
  `"2,4-6"` → `[ 2 4 5 6 ]`.

## Phases 3–9

**Status:** not started.

These phases require either:
- Multi-host orchestration with live ssh access (Phases 4, 5, 7, 8),
- Live hardware to verify (Phase 8 — AF_XDP), or
- A second NIC family on a real testbed (Phase 9 — mlx5_core).

They will be tackled in subsequent sessions; details remain in
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
