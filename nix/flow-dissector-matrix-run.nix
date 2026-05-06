# SPDX-License-Identifier: BSD-2-Clause-FreeBSD
#
# flow-dissector-matrix-run — Phase 7 of the matrix plan
# (docs/flow-dissector-matrix-implementation-plan.md §10).
#
# Composes Phase 4 (`xdp2-run-on-host --testbed`) with Phase 6
# (`flow-dissector-matrix-aggregate`) into a single user-facing
# command:
#
#   nix run .#flow-dissector-matrix-run -- \
#       --testbed testbeds/<name>.toml \
#       [--results <dir>] [--smoke]
#
# What it does:
#   1. Resolves `--results` to either the flag value, the
#      `XDP2_RESULTS_ROOT` env var, or `./perf-results`.
#   2. Invokes `xdp2-run-on-host --testbed PATH --
#      flow-dissector-matrix-unified` so each DUT/generator
#      builds and runs the unified matrix runner. Phase 4
#      handles the rsync-back into the result tree.
#   3. Runs `flow-dissector-matrix-aggregate --results <root>`
#      over the now-populated tree to emit summary.{md,csv}.
#
# Live multi-host orchestration requires ssh access to the hosts
# named in the testbed-config TOML. `--help` works without any
# hardware so the wiring can be smoke-tested in `nix flake check`.

{ pkgs, runOnHost, aggregate }:

pkgs.writeShellApplication {
  name = "flow-dissector-matrix-run";

  runtimeInputs = [
    runOnHost
    aggregate
    pkgs.coreutils
  ];

  text = ''
    set -eu

    usage() {
      cat <<'USAGE'
    Usage:
      flow-dissector-matrix-run --testbed PATH [OPTIONS]

    Options:
      --testbed PATH     testbed-config TOML (required; schema:
                         nix/testbed-config.nix).
      --results DIR      Result tree root. Default: $XDP2_RESULTS_ROOT
                         or ./perf-results.
      --smoke            Smoke-mode: pass through XDP2_MATRIX_SMOKE=1
                         so per-cell runs use the smaller iteration
                         count (1 warm + 5 timed).
      -h, --help         Show this help.

    Environment:
      XDP2_RESULTS_ROOT  Default for --results.
      XDP2_NIC_DRIVER    Forwarded to flow-dissector-matrix-unified.
      XDP2_NIC_FIRMWARE  Forwarded to flow-dissector-matrix-unified.

    What this command does:
      1. Calls xdp2-run-on-host --testbed PATH --
         flow-dissector-matrix-unified to fan out across the
         testbed's DUT and generator hosts. Phase 4's runner
         rsyncs result/ back to <results>/<date>/<testbed>/<host>/.
      2. Runs flow-dissector-matrix-aggregate over the result
         tree to emit summary.md and summary.csv.

    Live multi-host orchestration requires ssh access to the
    hosts named in the testbed-config TOML.
    USAGE
    }

    TESTBED=""
    RESULTS=""
    SMOKE=0

    while [ $# -gt 0 ]; do
      case "$1" in
        -h|--help) usage; exit 0 ;;
        --testbed)
          [ $# -ge 2 ] || { echo "flow-dissector-matrix-run: --testbed requires PATH" >&2; exit 2; }
          TESTBED="$2"; shift 2 ;;
        --results)
          [ $# -ge 2 ] || { echo "flow-dissector-matrix-run: --results requires DIR" >&2; exit 2; }
          RESULTS="$2"; shift 2 ;;
        --smoke) SMOKE=1; shift ;;
        --) shift; break ;;
        *) echo "flow-dissector-matrix-run: unknown argument '$1'" >&2; usage >&2; exit 2 ;;
      esac
    done

    if [ -z "$TESTBED" ]; then
      echo "flow-dissector-matrix-run: --testbed is required" >&2
      usage >&2
      exit 2
    fi
    if [ ! -f "$TESTBED" ]; then
      echo "flow-dissector-matrix-run: testbed file not found: $TESTBED" >&2
      exit 2
    fi

    if [ -z "$RESULTS" ]; then
      RESULTS="''${XDP2_RESULTS_ROOT:-$PWD/perf-results}"
    fi
    mkdir -p "$RESULTS"
    export XDP2_RESULTS_ROOT="$RESULTS"

    if [ "$SMOKE" -eq 1 ]; then
      export XDP2_MATRIX_SMOKE=1
    fi

    echo "[matrix-run] testbed=$TESTBED results=$RESULTS smoke=$SMOKE" >&2
    # --exec is required: flow-dissector-matrix-unified is a
    # writeShellApplication. Without --exec, xdp2-run-on-host's default
    # `nix build` first-pass succeeds (it just builds the wrapper) and
    # the matrix runner is never executed, so no per-cell JSONs are
    # emitted. With --exec, xdp2-run-on-host forces `nix run` and
    # propagates XDP2_MATRIX_PCAP / XDP2_MATRIX_SMOKE / XDP2_NIC_*
    # over ssh, plus injects XDP2_MATRIX_JSON_OUT=$PWD/result/cells/.
    xdp2-run-on-host --exec --testbed "$TESTBED" -- flow-dissector-matrix-unified

    echo "[matrix-run] aggregating $RESULTS" >&2
    flow-dissector-matrix-aggregate --results "$RESULTS"

    echo "[matrix-run] done. summary at $RESULTS/summary.md" >&2
  '';

  meta = {
    description = "Composed runner: orchestrate matrix on a testbed and aggregate results";
    mainProgram = "flow-dissector-matrix-run";
  };
}
