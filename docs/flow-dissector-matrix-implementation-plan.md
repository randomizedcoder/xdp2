# Flow-Dissector Matrix on Physical Testbed — Implementation Plan

Status: implementation plan
Companion to: [`flow-dissector-matrix-physical-testbed.md`](flow-dissector-matrix-physical-testbed.md)
Date: 2026-05-02

## 1. Intro

This document is the **execution plan** for the design captured in
[`docs/flow-dissector-matrix-physical-testbed.md`](flow-dissector-matrix-physical-testbed.md).
It breaks the design's §17 implementation order into ten ordered
phases (Phase 0 pre-flight + Phases 1-9), each with a goal, the
exact files touched, an approach, an observable definition of done,
copy-pasteable verification commands with expected output, and a
rollback note.

### Audience

The engineer(s) who will land this work. Each phase is sized to ship
as one or two PRs, in order, with the verification of phase **N**
completing before phase **N+1** begins.

### Working assumptions

- Hosts are NixOS bare-metal, configured with the
  `physicalTestbed` and `nicTuning` NixOS modules. No containers,
  no VMs.
- The flake is the public surface. Implementation hides inside
  modular `nix/*.nix` files; users interact through `flake.nix`
  outputs.
- Reference bring-up testbed is `hp2-hp5-x710` (AMD Zen 1 + Intel
  X710 + i40e). The 2026-05-02 reference numbers in
  `perf-results/2026-05-02-physical-testbed-summary.md` are the
  baseline that the final implementation must reproduce within 95%
  CI.

### Naming hygiene (apply throughout PRs, scripts, and reports)

| Term            | Meaning                                                          |
|-----------------|------------------------------------------------------------------|
| `xdp2-rs`       | The Rust implementation. Always with the `-rs` suffix.           |
| `XDP2 (C)`      | The C/C++ XDP2 parser (user-space and kernel BPF variants).      |
| `xdp2-flow-ebpf`| Standalone fast eBPF flow-dissector artifact.                    |
| kernel flow dissector | Linux's in-tree dissector (user-space `flowdis` and BPF).  |

### How to use this doc

1. Read the [design](flow-dissector-matrix-physical-testbed.md) first;
   this plan assumes you have.
2. Walk the phases in order. Each phase's verification block must
   pass before opening the next phase's PR.
3. Section [§14 Summary](#14-summary) tracks phase status; check
   off entries as you go.

## 2. Table of Contents

1. [Intro](#1-intro)
2. [Table of Contents](#2-table-of-contents)
3. [Phase Template](#3-phase-template)
4. [Phase 0 — Pre-flight](#4-phase-0--pre-flight)
5. [Phase 1 — `testbed-config` schema + loader](#5-phase-1--testbed-config-schema--loader)
6. [Phase 2 — Refactor `physical-testbed` NixOS module](#6-phase-2--refactor-physical-testbed-nixos-module)
7. [Phase 3 — `nic-tuning` NixOS module (i40e)](#7-phase-3--nic-tuning-nixos-module-i40e)
8. [Phase 4 — Refactor `physical-testbed-runner`](#8-phase-4--refactor-physical-testbed-runner)
9. [Phase 5 — Refactor `flow-dissector-matrix-runner`](#9-phase-5--refactor-flow-dissector-matrix-runner)
10. [Phase 6 — `aggregate-results`](#10-phase-6--aggregate-results)
11. [Phase 7 — `flake.nix` outputs + regression gate](#11-phase-7--flakenix-outputs--regression-gate)
12. [Phase 8 — AF_XDP live (Phase E)](#12-phase-8--af_xdp-live-phase-e)
13. [Phase 9 — Second NIC branch (mlx5_core / tc-flower)](#13-phase-9--second-nic-branch-mlx5_core--tc-flower)
14. [Verification — Standing Commands](#14-verification--standing-commands)
15. [Cross-Phase Concerns](#15-cross-phase-concerns)
16. [Summary](#16-summary)

## 3. Phase Template

Every phase below follows this structure:

- **Goal** — one sentence.
- **Files touched** — exact paths.
- **Approach** — bullet list of what changes.
- **Definition of Done (DoD)** — observable criteria.
- **Verification** — copy-pasteable commands + expected outputs.
- **Risks & rollback** — what to do if the phase breaks something.

## 4. Phase 0 — Pre-flight

### Goal

Establish the working branch, capture a fresh reference baseline on
the live testbed, and lock in the `testbed-config` schema before any
file is created.

### Files touched

- (none yet — branch + spec sign-off)

### Approach

- Cut a long-lived integration branch, e.g.
  `merge/matrix-physical-testbed`, off `main`.
- Re-run the 2026-05-02 reference matrix on `hp5` to confirm the
  baseline numbers still hold; archive a fresh
  `perf-results/<today>/hp5/baseline.json`.
- Write the `testbed-config` schema (§3 of the design) on paper /
  in a draft TOML and circulate for sign-off — the schema is the
  contract every later phase depends on, so changes here are cheap
  and changes after Phase 1 are not.

### Definition of Done

- [ ] Branch `merge/matrix-physical-testbed` exists and is pushed.
- [ ] Fresh baseline JSON archived under
      `perf-results/<today>/hp5-baseline/`.
- [ ] Schema draft reviewed; no field renames expected after this
      point.

### Verification

```bash
# Branch exists and is pushed
git rev-parse --abbrev-ref HEAD
# Expected: merge/matrix-physical-testbed

git ls-remote --heads origin merge/matrix-physical-testbed | wc -l
# Expected: 1

# Baseline run reproduces 2026-05-02 graph-enum number within 10%
nix run .#flow-dissector-matrix-unified -- \
  --pcap "$(nix build --no-link --print-out-paths .#test-pcap)/combo.pcap" \
  --iterations 200 --mode graph-enum
# Expected: ns/pkt within 12 ± 1.2 (i.e. 10.8–13.2)
```

### Risks & rollback

- Schema oversight (e.g. missing field for a future NIC) is cheap to
  fix here, expensive after Phase 1. Spend the time.
- If the baseline drifts > 10% from 2026-05-02, **stop** and
  investigate before proceeding — the rest of the plan assumes the
  baseline is stable.

## 5. Phase 1 — `testbed-config` schema + loader

### Goal

Land a Nix loader that parses `testbeds/<name>.toml` into a validated
attrset, plus the reference TOML and a Mellanox sketch.

### Files touched

- **New:** `nix/testbed-config.nix`
- **New:** `testbeds/hp2-hp5-x710.toml` (lifted from design §13.1)
- **New:** `testbeds/example-mellanox-cx4.toml` (lifted from design §13.2)
- **Modify:** `flake.nix` — expose `testbedConfig` attrset.

### Approach

- `nix/testbed-config.nix` defines the schema (host roles, NIC
  fields, run knobs) and uses `builtins.fromTOML` to load
  `testbeds/<name>.toml`. Returns an attrset with `testbed`,
  `hosts` (split by role), `nic`, `run`.
- Validation: assert each host has a unique `role`, exactly one is
  `dut`; `cpu_uarch` is in the supported set; `nic.driver` is in
  `[i40e, ice, mlx5_core, bnxt_en]` (extensible).
- `flake.nix` exposes `testbedConfig.<name>` (one attr per file in
  `testbeds/`).

### Definition of Done

- [ ] `nix eval .#testbedConfig.hp2-hp5-x710.nic.driver` returns
      `"i40e"`.
- [ ] `nix eval .#testbedConfig.example-mellanox-cx4.nic.driver`
      returns `"mlx5_core"`.
- [ ] `nix eval .#testbedConfig.hp2-hp5-x710.hosts.dut.hostname`
      returns `"hp5"`.
- [ ] Adding a TOML with two `dut` roles fails evaluation with a
      clear error.
- [ ] `nix flake check` passes.

### Verification

```bash
# Both reference configs evaluate cleanly
nix eval --raw .#testbedConfig.hp2-hp5-x710.nic.driver
# Expected stdout: i40e
nix eval --raw .#testbedConfig.example-mellanox-cx4.nic.driver
# Expected stdout: mlx5_core
nix eval --raw .#testbedConfig.hp2-hp5-x710.hosts.dut.hostname
# Expected stdout: hp5

# Validation rejects bad config
cp testbeds/hp2-hp5-x710.toml /tmp/bad.toml
sed -i 's/role = "generator"/role = "dut"/' /tmp/bad.toml
nix eval --impure --expr 'import ./nix/testbed-config.nix { configFile = "/tmp/bad.toml"; }'
# Expected: evaluation error mentioning "exactly one dut"

nix flake check
# Expected exit 0
```

### Risks & rollback

- **Risk:** schema gap discovered later. **Mitigation:** keep the
  loader strict (assert on unknown keys) so silent drift is not
  possible.
- **Rollback:** revert the new files; no other code yet depends on
  the loader.

## 6. Phase 2 — Refactor `physical-testbed` NixOS module

### Goal

Make `nix/modules/physical-testbed.nix` consume `testbed-config`
output instead of hardcoded constants, with **no observable change**
on the reference testbed.

### Files touched

- **Modify:** `nix/modules/physical-testbed.nix`
- **Modify:** the NixOS configuration(s) that import it (read the
  testbed-config and pass it in).

### Approach

- Add a top-level option `services.physicalTestbed.config` (an
  attrset) accepting the result of `testbed-config.nix`.
- Replace hardcoded `isolcpus`, `nohz_full`, `hugepages`, governor,
  mitigations, IRQ pinning with values derived from the option.
- Provide sensible defaults so the module is usable without a
  testbed-config (back-compat for any non-testbed consumers).

### Definition of Done

- [ ] Building the existing NixOS configuration for `hp5` produces
      an identical `system.build.toplevel` store path as before
      (or a diff that is provably semantics-preserving — boot
      params expanded from config but yielding identical
      `cmdline`).
- [ ] `nixos-option services.physicalTestbed.config.nic.driver`
      reports `"i40e"` after wiring the testbed-config in.

### Verification

```bash
# Build hp5 toplevel before and after; cmdline must be identical
nix build .#nixosConfigurations.hp5.config.system.build.toplevel
readlink result | xargs -I{} cat {}/kernel-params
# Expected: includes 'isolcpus=2-7 nohz_full=2-7 mitigations=off ...'
# Diff vs pre-refactor output: empty or whitespace-only.

# Module option visible at the right value
nixos-option -I nixpkgs=$(nix eval --raw .#inputs.nixpkgs) \
  --config $(nix eval --raw .#nixosConfigurations.hp5._module.args.modulesPath) \
  services.physicalTestbed.config.nic.driver
# Expected: "i40e"
```

### Risks & rollback

- **Risk:** subtle change to kernel cmdline (e.g. ordering)
  invalidates current bootloader entry on `hp5`/`hp2`.
- **Mitigation:** verify `kernel-params` byte-for-byte.
- **Rollback:** the module is local; `git revert` and rebuild.

## 7. Phase 3 — `nic-tuning` NixOS module (i40e)

### Goal

New NixOS module that emits the right NIC tuning commands for the
reference NIC (Intel X710 / i40e), driven by `testbed-config`.

### Files touched

- **New:** `nix/modules/nic-tuning.nix`
- **Modify:** `flake.nix` — expose `nixosModules.nicTuning`.
- **Modify:** `hp2`/`hp5` NixOS configs — import the module.

### Approach

- Accept `services.nicTuning.config = <testbed-config>` as input.
- Branch on `[nic].driver`:
  - `i40e` (Phase 3 scope): `ethtool -K <iface> ntuple on`, RSS
    indirection, ring sizes, IRQ affinity to `hosts.dut.isolated_cpus`.
- Other drivers: emit a no-op + warning ("not yet implemented");
  Phase 9 lands the mlx5_core branch.
- Module activation: `system.activationScripts.nicTuning` so it
  re-runs on `nixos-rebuild switch`.

### Definition of Done

- [ ] `nix build .#nixosConfigurations.hp5.config.system.build.toplevel`
      succeeds with the new module imported.
- [ ] After `nixos-rebuild switch` on `hp5`, `ethtool -k <iface>`
      reports ntuple-rx-flow-hash on; `ethtool -n <iface>`
      reflects expected rule count.
- [ ] An unsupported driver value produces a build-time warning,
      not a hard error.

### Verification

```bash
# Module composes
nix build .#nixosConfigurations.hp5.config.system.build.toplevel
# Expected exit 0

# Activation script is present in toplevel
grep -l 'nicTuning' "$(readlink result)/etc/systemd/system/multi-user.target.wants/"* \
  || readlink result | xargs -I{} grep -r 'nicTuning' {}/activate
# Expected: at least one match

# After deploy on hp5 (out of scope for nix build, but documented):
ssh root@hp5 'ethtool -k enp1s0f0 | grep ntuple'
# Expected: 'ntuple-filters: on'
ssh root@hp5 'ethtool -n enp1s0f0 | head -1'
# Expected: 'X total RX rules' where X matches config
```

### Risks & rollback

- **Risk:** wrong queue count or RSS hash misconfigures the NIC at
  switch time, breaking ssh.
- **Mitigation:** the module is gated by `services.nicTuning.enable`;
  default `false`. Enable explicitly per-host.
- **Rollback:** `nixos-rebuild switch` to the previous generation.

## 8. Phase 4 — Refactor `physical-testbed-runner`

### Goal

Make the multi-host orchestrator (`nix/physical-testbed-runner.nix`)
consume `testbed-config` and fan out by host role, dropping any
hardcoded `hp2`/`hp5` references.

### Files touched

- **Modify:** `nix/physical-testbed-runner.nix`
- **Modify:** `flake.nix` — expose updated `run-on-host` flake
  output that takes `--testbed`.

### Approach

- Add CLI flag `--testbed <path>` to the runner.
- Resolve `dut` and (optionally) `generator` hostnames from the
  loaded config.
- Parallel rsync to all hosts; per-host `nix run` with role-aware
  arguments.
- Pull results back into
  `perf-results/<date>/<testbed.name>/<host>/...`.

### Definition of Done

- [ ] `nix run .#run-on-host -- --testbed testbeds/hp2-hp5-x710.toml --target echo --args "hello"`
      runs `echo hello` on **both** hosts in parallel, producing
      a per-host log under `perf-results/<date>/<testbed.name>/<host>/`.
- [ ] No string `"hp2"` or `"hp5"` remains in
      `nix/physical-testbed-runner.nix` (verify with `grep`).

### Verification

```bash
# No hardcoded hostnames
grep -nE 'hp[0-9]' nix/physical-testbed-runner.nix
# Expected: no matches (exit 1)

# Smoke run
nix run .#run-on-host -- \
  --testbed testbeds/hp2-hp5-x710.toml \
  --target echo --args "hello-from-runner"
# Expected: per-host directory created, both contain "hello-from-runner"

ls perf-results/$(date -I)/hp2-hp5-x710/
# Expected output:
# hp2/
# hp5/
```

### Risks & rollback

- **Risk:** ssh connectivity quirks (host keys, passwordless sudo)
  break automation.
- **Mitigation:** runner exits non-zero with a clear "ssh to
  <host> failed" message; CI users see the cause immediately.
- **Rollback:** revert; no downstream depends on this yet.

## 9. Phase 5 — Refactor `flow-dissector-matrix-runner`

### Goal

Per-host matrix runner emits one JSON per `(pcap, mode)` cell,
driven entirely by `testbed-config`.

### Files touched

- **New (refactor):** `nix/flow-dissector-matrix-runner.nix`
  (consolidates `nix/flow-dissector-matrix.nix` and
  `nix/xdp2-rs-matrix.nix` for the C and `xdp2-rs` rows respectively).
- **Modify:** `samples/flow_dissector/xdp2_rs_matrix.sh` — emit
  per-cell JSON if `--json-out <dir>` is supplied (back-compat:
  default behavior unchanged).

### Approach

- Loop: for each `pcap` in `[run]`, for each `mode` in the matrix
  (rows 1-10 from design §5), pin to
  `taskset -c "$(echo $isolated_cpus | cut -d- -f1)"` and run the
  per-mode invocation.
- One JSON per cell:
  `perf-results/<date>/<testbed.name>/<host>/<pcap>/<mode>.json`.
- JSON record shape:
  ```json
  {
    "testbed": "hp2-hp5-x710",
    "host": "hp5",
    "pcap": "combo",
    "mode": "graph-enum",
    "ns_per_pkt": 12.0,
    "mpps": 80.0,
    "packets": 499995,
    "iterations": 200,
    "build_hash": "/nix/store/...",
    "kernel": "6.6.x",
    "nic_driver": "i40e",
    "nic_firmware": "9.20"
  }
  ```

### Definition of Done

- [ ] Running the runner end-to-end on `hp5` produces 4 PCAP × 12
      mode files = 48 JSONs (10 matrix rows, with rows 9/10
      expanded into 6 sub-modes total).
- [ ] Each JSON validates against the documented schema (key set
      and types).
- [ ] `xdp2-rs` graph-enum reproduces the 2026-05-02 baseline ±10%.

### Verification

```bash
# Drive a single host directly (assumes phase 4 wiring done)
nix run .#flow-dissector-matrix-runner -- \
  --testbed testbeds/hp2-hp5-x710.toml \
  --host hp5 \
  --out perf-results/$(date -I)/hp2-hp5-x710/hp5

# Cell count
find perf-results/$(date -I)/hp2-hp5-x710/hp5 -name '*.json' | wc -l
# Expected: 48 (4 pcaps × 12 modes)

# Schema sanity on one cell
nix shell nixpkgs#jq --command \
  jq -e 'has("ns_per_pkt") and has("mode") and has("build_hash")' \
  perf-results/$(date -I)/hp2-hp5-x710/hp5/combo/graph-enum.json
# Expected: true (exit 0)

# Reference number reproduction
nix shell nixpkgs#jq --command \
  jq '.ns_per_pkt' \
  perf-results/$(date -I)/hp2-hp5-x710/hp5/combo/graph-enum.json
# Expected: 12.0 ± 1.2
```

### Risks & rollback

- **Risk:** existing scripts (`xdp2_rs_matrix.sh`) consumed by other
  callers break when `--json-out` is added.
- **Mitigation:** flag is opt-in; default behavior preserved.
- **Rollback:** the new runner is additive; the old matrix flake
  outputs continue to work.

## 10. Phase 6 — `aggregate-results`

### Goal

Walk a results tree and emit `summary.md`, `summary.csv`, and
`regressions.md`.

### Files touched

- **New:** `nix/aggregate-results.nix`

### Approach

- A `writeShellApplication` (Python or Rust + `jq`) that:
  1. Reads every JSON under `--results <dir>`.
  2. Groups by `(testbed, host, pcap, mode)`; computes
     mean/median/p95/95% CI of `ns_per_pkt`.
  3. Emits `summary.md` (markdown tables grouped by PCAP, columns
     by host), `summary.csv` (flat), `regressions.md` (diff vs
     `--baseline <csv>`).
- Methodology section in `summary.md` header: "win = CI-disjoint
  ns/pkt; otherwise = noise."

### Definition of Done

- [ ] Running the aggregator on the Phase-5 output produces three
      files in the same directory.
- [ ] `summary.md` opens cleanly in `grip` / VS Code preview;
      tables render.
- [ ] `summary.csv` is parseable by `csvkit` (`csvstat`).
- [ ] Running with `--baseline` against the 2026-05-02 baseline
      produces a `regressions.md` flagging 0 regressions.

### Verification

```bash
nix run .#flow-dissector-matrix-aggregate -- \
  --results perf-results/$(date -I)/hp2-hp5-x710 \
  --baseline perf-results/2026-05-02/hp2-hp5-x710/summary.csv

ls perf-results/$(date -I)/hp2-hp5-x710/
# Expected: summary.md  summary.csv  regressions.md

nix shell nixpkgs#csvkit --command \
  csvstat perf-results/$(date -I)/hp2-hp5-x710/summary.csv | head -5
# Expected: csvkit prints column types without error

grep -c 'REGRESSION' perf-results/$(date -I)/hp2-hp5-x710/regressions.md
# Expected: 0
```

### Risks & rollback

- **Risk:** small-N iteration counts produce noisy CIs flagged as
  false-positive regressions.
- **Mitigation:** require `--min-iterations 30` in the aggregator;
  warn if any cell has fewer.
- **Rollback:** standalone target, easy to revert.

## 11. Phase 7 — `flake.nix` outputs + regression gate

### Goal

Expose the public flake API (`-run`, `-aggregate`, `-check`) and
wire the smoke regression gate.

### Files touched

- **Modify:** `flake.nix`
- **New (smoke):** small wrapper around Phase 5 runner that runs 1
  warm-up + 5 timed iterations on `combo` only, single host.

### Approach

- `flow-dissector-matrix-run`: composes Phase 4 (orchestrator) +
  Phase 5 (per-host runner) under the testbed-config.
- `flow-dissector-matrix-aggregate`: thin alias for Phase 6.
- `flow-dissector-matrix-check`: smoke version, exits non-zero on
  any cell regressing > 10% versus `testbeds/<name>.baseline.csv`.

### Definition of Done

- [ ] `nix flake show` lists all four new outputs.
- [ ] `nix run .#flow-dissector-matrix-check -- --testbed testbeds/hp2-hp5-x710.toml`
      exits 0 against the matching baseline.
- [ ] Mutating the baseline to claim `combo/graph-enum = 1 ns/pkt`
      causes the check to exit non-zero.

### Verification

```bash
nix flake show 2>&1 | grep -E 'flow-dissector-matrix-(run|aggregate|check)'
# Expected: 3 lines

nix run .#flow-dissector-matrix-check -- \
  --testbed testbeds/hp2-hp5-x710.toml
# Expected exit 0

# Mutate baseline; check fails
sed -i 's/graph-enum,12/graph-enum,1/' testbeds/hp2-hp5-x710.baseline.csv
nix run .#flow-dissector-matrix-check -- \
  --testbed testbeds/hp2-hp5-x710.toml
# Expected exit non-zero, message names the regressed cell

git checkout testbeds/hp2-hp5-x710.baseline.csv
```

### Risks & rollback

- **Risk:** check is too strict, blocking unrelated PRs on noise.
- **Mitigation:** ship a `--threshold` flag (default 10%); document
  using `--threshold 25` for early NIC bring-up.
- **Rollback:** the gate is opt-in; no PR is required to run it
  until CI explicitly enables it.

## 12. Phase 8 — AF_XDP live (Phase E)

### Goal

Add `flow-dissector-afxdp-live` flake output that drives a Phase E
live-traffic run across DUT and generator.

### Files touched

- **Modify:** `flake.nix` — new output.
- **Modify (light):** `samples/flow_dissector/run_ntuple_template_bench.sh`
  — accept `--testbed` and resolve hosts/interfaces from the config.

### Approach

- New flake output composes:
  - On `generator` host: `pktgen_ntuple_template.sh` (kernel) or
    `pktgen_dpdk_ntuple_template.sh` (DPDK).
  - On `dut` host: `xdp2-bench --mode af-xdp` and the per-queue
    `--mode af-xdp-template` variants.
- Sweep offered loads `[1, 2, 5, 10] Mpps` (capped at
  `[nic].link_speed_gbps / packet_overhead`).
- Emit per-load JSON with: pps received, drops, queue utilization,
  AF_XDP zerocopy mode.

### Definition of Done

- [ ] `nix run .#flow-dissector-afxdp-live -- --testbed testbeds/hp2-hp5-x710.toml --duration 30`
      completes without error.
- [ ] Result tree contains 4 JSONs (one per offered load).
- [ ] At 1 Mpps offered load on the reference testbed, drops < 0.1%.

### Verification

```bash
nix run .#flow-dissector-afxdp-live -- \
  --testbed testbeds/hp2-hp5-x710.toml \
  --duration 30

ls perf-results/$(date -I)/hp2-hp5-x710/afxdp/
# Expected: 1mpps.json  2mpps.json  5mpps.json  10mpps.json

nix shell nixpkgs#jq --command \
  jq '.drops_pct' \
  perf-results/$(date -I)/hp2-hp5-x710/afxdp/1mpps.json
# Expected: < 0.1
```

### Risks & rollback

- **Risk:** generator NIC requires offline config (e.g. flow-director
  rules) that aren't applied at boot.
- **Mitigation:** fail fast with a message pointing at the `nicTuning`
  module section to enable.
- **Rollback:** the output is additive.

## 13. Phase 9 — Second NIC branch (mlx5_core / tc-flower)

### Goal

Validate hardware portability by adding the Mellanox ConnectX-4
branch to `nic-tuning.nix`.

### Files touched

- **Modify:** `nix/modules/nic-tuning.nix` — add `mlx5_core`
  branch using `tc-flower` for flow steering.
- **Verify:** `testbeds/example-mellanox-cx4.toml` evaluates and
  the module composes.

### Approach

- Implement the mlx5_core branch:
  - `ethtool -L <iface> combined <queues>` for queue count.
  - `tc qdisc add dev <iface> ingress` and per-flow `tc filter`
    rules for steering.
  - AF_XDP zerocopy detection via `bpftool feature probe`.
- Live testing requires actual hardware; in-tree CI verifies
  evaluation + module composition only.

### Definition of Done

- [ ] `nix build .#nixosConfigurations.example-mellanox.config.system.build.toplevel`
      builds (using a synthetic NixOS config that imports the
      module with the Mellanox testbed-config).
- [ ] Driver dispatch in `nic-tuning.nix` is exhaustive: removing
      a branch causes evaluation to fail with a clear error.

### Verification

```bash
# Module composes for the Mellanox sketch
nix build .#nixosConfigurations.example-mellanox.config.system.build.toplevel
# Expected exit 0

# Activation script contains tc-flower commands
readlink result | xargs -I{} grep -l 'tc filter add' {}/activate
# Expected: at least one match

# Exhaustiveness check — temporarily remove i40e branch, expect failure
git apply tests/nic-tuning-remove-i40e.patch
nix build .#nixosConfigurations.hp5.config.system.build.toplevel 2>&1 \
  | grep -i 'unhandled.*driver'
# Expected: at least one line
git apply -R tests/nic-tuning-remove-i40e.patch
```

### Risks & rollback

- **Risk:** mlx5_core flow-steering syntax drift between kernel
  versions.
- **Mitigation:** pin to the kernel version in `[host].arch` /
  document tested versions.
- **Rollback:** revert the new branch; reference testbed unaffected.

## 14. Verification — Standing Commands

These commands appear repeatedly across phases; documented once:

| Command                                                                        | Purpose                  |
|--------------------------------------------------------------------------------|--------------------------|
| `nix flake check`                                                              | Post-refactor sanity     |
| `nix flake show`                                                               | Confirm public outputs   |
| `nix eval .#testbedConfig.<name>.<path>`                                       | Inspect loaded config    |
| `nix build .#nixosConfigurations.<host>.config.system.build.toplevel`          | NixOS module sanity      |
| `nix run .#flow-dissector-matrix-check -- --testbed <cfg>`                     | Smoke regression gate    |
| `nix run .#flow-dissector-matrix-run -- --testbed <cfg>`                       | Full sweep               |
| `nix run .#flow-dissector-matrix-aggregate -- --results <dir>`                 | Build report             |
| `nix run .#flow-dissector-afxdp-live -- --testbed <cfg> --duration 30`         | Phase E live             |

## 15. Cross-Phase Concerns

### Statistics methodology

A "win" is a **CI-disjoint** ns/pkt difference; overlapping CIs are
"noise" regardless of point estimates. The aggregator (Phase 6) and
check gate (Phase 7) both apply this. See design §10.

### Documented quirks

- **`perf-sweep` wrapper masks PMU counters.** Phase C invokes
  `xdp2-bench --perf` directly. (Design §15.)
- **`writeShellApplication` flake outputs require `nix run`,**
  not `nix build`.
- **`mitigations=off`** is honest-perf only; the
  `physical-testbed.nix` activation banner labels every booted
  host accordingly so result files cannot be misread as production
  claims.

### Naming hygiene (PR + result files)

- Every PR title and description references `xdp2-rs`, `XDP2 (C)`,
  `xdp2-flow-ebpf`, or "kernel flow dissector" — never bare "Rust"
  or "C parser" without context.
- Result files (`summary.md`, `regressions.md`) follow the same
  convention.

## 16. Summary

### Phase ladder

| Phase | Name                                                     | Primary artifact                                       | Status        |
|-------|----------------------------------------------------------|--------------------------------------------------------|---------------|
| 0     | Pre-flight                                               | `merge/matrix-physical-testbed` branch + baseline      | not started   |
| 1     | `testbed-config` schema + loader                         | `nix/testbed-config.nix`, `testbeds/*.toml`            | not started   |
| 2     | Refactor `physical-testbed` NixOS module                 | Config-driven `nix/modules/physical-testbed.nix`       | not started   |
| 3     | `nic-tuning` NixOS module (i40e)                         | `nix/modules/nic-tuning.nix`                           | not started   |
| 4     | Refactor `physical-testbed-runner`                       | Config-driven multi-host orchestrator                  | not started   |
| 5     | Refactor `flow-dissector-matrix-runner`                  | Per-cell JSON output                                   | not started   |
| 6     | `aggregate-results`                                      | `summary.{md,csv}` + `regressions.md`                  | not started   |
| 7     | `flake.nix` outputs + regression gate                    | Public API: `-run`, `-aggregate`, `-check`             | not started   |
| 8     | AF_XDP live (Phase E)                                    | `flow-dissector-afxdp-live`                            | not started   |
| 9     | Second NIC branch (mlx5_core / tc-flower)                | Portability validated                                  | not started   |

### When you can declare done

All of:
- Every phase's verification block passes.
- The reference testbed `hp2-hp5-x710.toml` reproduces the
  2026-05-02 numbers within 95% CI on the `combo`, `tcp_ipv4`,
  and `mixed_real` PCAPs.
- The Mellanox sketch (`example-mellanox-cx4.toml`) at minimum
  *builds*, even if no live hardware is available to run it.
- `nix run .#flow-dissector-matrix-check -- --testbed
  testbeds/hp2-hp5-x710.toml` exits 0 in CI.

### Forward pointers

The design's §16 open questions are **explicitly out of scope**
for these 9 phases and become follow-up tickets after Phase 9:

- Result-tree publication (Grafana / Prometheus pushgateway vs
  git-tracked `perf-results/`).
- Smoke CI host (build farm vs physical testbed only).
- Whether `testbeds/*.toml` lives in this repo or in a sibling
  private repo for site-specific configs.
