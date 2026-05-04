# SPDX-License-Identifier: BSD-2-Clause-FreeBSD
#
# flow-dissector-matrix-check — Phase 7 smoke regression gate.
#
# Composes flow-dissector-matrix-run --smoke with Phase 6's
# aggregator in --baseline / --fail-on-regression mode. Exits
# non-zero on any cell regression, intended for CI.
#
#   nix run .#flow-dissector-matrix-check -- \
#       --testbed testbeds/<name>.toml \
#       [--baseline testbeds/<name>.baseline.csv] \
#       [--threshold 10] [--results <dir>]
#
# Default baseline path: testbeds/<testbed-name>.baseline.csv
# (resolved at invocation time from the testbed-config's
# [testbed].name field).

{ pkgs, runOnHost, aggregate, matrixRun }:

pkgs.writeShellApplication {
  name = "flow-dissector-matrix-check";

  runtimeInputs = [
    runOnHost
    aggregate
    matrixRun
    pkgs.coreutils
    pkgs.gawk
  ];

  text = ''
    set -eu

    usage() {
      cat <<'USAGE'
    Usage:
      flow-dissector-matrix-check --testbed PATH [OPTIONS]

    Options:
      --testbed PATH     testbed-config TOML (required).
      --baseline PATH    Baseline CSV. Default:
                         testbeds/<testbed-name>.baseline.csv.
      --threshold N      Regression threshold percent (default 10).
      --results DIR      Result tree root. Default:
                         $XDP2_RESULTS_ROOT or ./perf-results.
      --smoke            Forwarded to matrix-run (default: ON).
                         Use --no-smoke for full iterations.
      --no-smoke         Run full iteration count (100 warm/timed).
      -h, --help         Show this help.

    Behavior:
      Runs flow-dissector-matrix-run, then invokes the aggregator
      with --baseline + --fail-on-regression so the wrapper exits
      non-zero on any regression. Designed for CI.

    Baseline-incomplete handling:
      A baseline CSV with non-numeric ns_per_pkt_median values
      (the placeholder marker '?') triggers a hard failure with
      "baseline incomplete" in stderr. Regenerate the baseline
      from a clean summary.csv before re-running.
    USAGE
    }

    TESTBED=""
    BASELINE=""
    THRESHOLD=10
    RESULTS=""
    SMOKE=1

    while [ $# -gt 0 ]; do
      case "$1" in
        -h|--help) usage; exit 0 ;;
        --testbed)
          [ $# -ge 2 ] || { echo "flow-dissector-matrix-check: --testbed requires PATH" >&2; exit 2; }
          TESTBED="$2"; shift 2 ;;
        --baseline)
          [ $# -ge 2 ] || { echo "flow-dissector-matrix-check: --baseline requires PATH" >&2; exit 2; }
          BASELINE="$2"; shift 2 ;;
        --threshold)
          [ $# -ge 2 ] || { echo "flow-dissector-matrix-check: --threshold requires N" >&2; exit 2; }
          THRESHOLD="$2"; shift 2 ;;
        --results)
          [ $# -ge 2 ] || { echo "flow-dissector-matrix-check: --results requires DIR" >&2; exit 2; }
          RESULTS="$2"; shift 2 ;;
        --smoke) SMOKE=1; shift ;;
        --no-smoke) SMOKE=0; shift ;;
        --) shift; break ;;
        *) echo "flow-dissector-matrix-check: unknown argument '$1'" >&2; usage >&2; exit 2 ;;
      esac
    done

    if [ -z "$TESTBED" ]; then
      echo "flow-dissector-matrix-check: --testbed is required" >&2
      usage >&2
      exit 2
    fi
    if [ ! -f "$TESTBED" ]; then
      echo "flow-dissector-matrix-check: testbed file not found: $TESTBED" >&2
      exit 2
    fi

    if [ -z "$RESULTS" ]; then
      RESULTS="''${XDP2_RESULTS_ROOT:-$PWD/perf-results}"
    fi

    # Default baseline: testbeds/<testbed-name>.baseline.csv
    if [ -z "$BASELINE" ]; then
      tname=$(awk -F'=' '
        /^\s*\[testbed\]/ { sec=1; next }
        /^\s*\[/          { sec=0 }
        sec && /^\s*name\s*=/ {
          gsub(/[" \t]/, "", $2); print $2; exit
        }' "$TESTBED")
      if [ -z "$tname" ]; then
        echo "flow-dissector-matrix-check: could not infer testbed name from $TESTBED" >&2
        exit 2
      fi
      BASELINE="testbeds/$tname.baseline.csv"
    fi
    if [ ! -f "$BASELINE" ]; then
      echo "flow-dissector-matrix-check: baseline not found: $BASELINE" >&2
      exit 2
    fi

    SMOKE_FLAG=""
    if [ "$SMOKE" -eq 1 ]; then SMOKE_FLAG="--smoke"; fi

    echo "[matrix-check] testbed=$TESTBED baseline=$BASELINE threshold=$THRESHOLD smoke=$SMOKE" >&2

    # shellcheck disable=SC2086
    flow-dissector-matrix-run --testbed "$TESTBED" --results "$RESULTS" $SMOKE_FLAG

    flow-dissector-matrix-aggregate \
      --results "$RESULTS" \
      --baseline "$BASELINE" \
      --threshold-pct "$THRESHOLD" \
      --fail-on-regression
  '';

  meta = {
    description = "Smoke regression gate: matrix-run + aggregate --fail-on-regression";
    mainProgram = "flow-dissector-matrix-check";
  };
}
