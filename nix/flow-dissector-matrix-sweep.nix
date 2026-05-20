# SPDX-License-Identifier: BSD-2-Clause-FreeBSD
#
# flow-dissector-matrix-sweep — multi-workload orchestrator wrapping
# flow-dissector-matrix-run. Reproducibility harness for the
# 2026-05-19 post-R3.4 perf sweep (docs/r3.4-hp5-perf-targets.md).
#
# What it does:
#   1. Resolves each workload name to its cached workload-pcap-* Nix
#      derivation (https-web, nfs-server, k8s-microservices,
#      vlan-tcp-mix, pppoe-isp, vxlan-k8s-pure).
#   2. For each workload, scp's the pcap to every host in the
#      testbed TOML to a known /tmp path.
#   3. Loops calling flow-dissector-matrix-run with
#      XDP2_MATRIX_PCAP=/tmp/<name>.pcap. Result tree accumulates
#      under $XDP2_RESULTS_ROOT/<date>/<testbed>/<host>/
#      flow-dissector-matrix-unified-<timestamp>/<pcap>/<parser>.json.
#   4. Runs flow-dissector-matrix-aggregate at the end to produce
#      summary.md + summary.csv + mono-perf.md covering all
#      workloads × hosts.
#
# Usage:
#   nix run .#flow-dissector-matrix-sweep -- \
#       --testbed testbeds/hp2-hp5-x710.toml [--smoke] \
#       [--workloads https-web,nfs-server,k8s-microservices,vlan-tcp-mix,pppoe-isp,vxlan-k8s-pure] \
#       [--results /path/to/perf-results]
#
# Default workloads is all 6. --smoke passes through to matrix-run.
#
# Result tree shape matches the existing matrix-run output so
# perf-results/<date>-r3.4-complete/-style snapshots remain
# diff-able across sweeps.

{ pkgs
, matrixRun
, matrixAggregate
, workloadPcaps        # attrset { name = derivation }
, lib
}:

let
  defaultWorkloadList = builtins.attrNames workloadPcaps;
  defaultWorkloads = lib.concatStringsSep "," defaultWorkloadList;
  defaultWorkloadsSpaced = lib.concatStringsSep " " defaultWorkloadList;

  # Emit shell associative-array entries mapping workload name → pcap path.
  pcapMapEntries = lib.concatStringsSep "\n" (lib.mapAttrsToList
    (name: drv: ''    PCAP_OF["${name}"]="${drv}/${name}.pcap"'')
    workloadPcaps);
in
pkgs.writeShellApplication {
  name = "flow-dissector-matrix-sweep";

  runtimeInputs = [
    matrixRun
    matrixAggregate
    pkgs.coreutils
    pkgs.openssh
  ];

  text = ''
    set -euo pipefail

    usage() {
      cat <<'USAGE'
Usage:
  flow-dissector-matrix-sweep --testbed PATH [OPTIONS]

Sweeps the post-R3.4 perf matrix across a list of workloads.
For each workload, scp's its cached pcap to every host in the
testbed, runs flow-dissector-matrix-run, and aggregates at the
end.

Options:
  --testbed PATH       testbed-config TOML (required).
  --results DIR        Result tree root. Default: $XDP2_RESULTS_ROOT
                       or ./perf-results.
  --workloads CSV      Comma-separated workload names. Default:
                       every workload-pcap-* in the flake.
  --smoke              Pass-through to flow-dissector-matrix-run
                       (smaller iteration count).
  -h, --help           This help.

Available workloads:
USAGE
      for w in ${defaultWorkloadsSpaced}; do
        echo "  - $w"
      done
    }

    TESTBED=""
    RESULTS=""
    WORKLOADS="${defaultWorkloads}"
    SMOKE=""

    while [ $# -gt 0 ]; do
      case "$1" in
        -h|--help) usage; exit 0 ;;
        --testbed) TESTBED="$2"; shift 2 ;;
        --results) RESULTS="$2"; shift 2 ;;
        --workloads) WORKLOADS="$2"; shift 2 ;;
        --smoke) SMOKE="--smoke"; shift ;;
        *) echo "matrix-sweep: unknown arg '$1'" >&2; usage >&2; exit 2 ;;
      esac
    done

    if [ -z "$TESTBED" ]; then
      echo "matrix-sweep: --testbed required" >&2
      exit 2
    fi
    if [ ! -f "$TESTBED" ]; then
      echo "matrix-sweep: testbed not found: $TESTBED" >&2
      exit 2
    fi

    if [ -z "$RESULTS" ]; then
      RESULTS="''${XDP2_RESULTS_ROOT:-$PWD/perf-results}"
    fi
    mkdir -p "$RESULTS"
    export XDP2_RESULTS_ROOT="$RESULTS"

    # workload → store-path/pcap map, baked at build time.
    declare -A PCAP_OF
${pcapMapEntries}

    # Extract hostnames from the testbed TOML (simple grep — the
    # config schema is documented in nix/testbed-config.nix).
    mapfile -t HOSTS < <(grep -E '^\s*hostname\s*=' "$TESTBED" \
                          | sed -E 's/.*"([^"]+)".*/\1/')
    if [ ''${#HOSTS[@]} -eq 0 ]; then
      echo "matrix-sweep: no hostnames in $TESTBED" >&2
      exit 2
    fi
    echo "[sweep] testbed=$TESTBED hosts=''${HOSTS[*]} results=$RESULTS"
    echo "[sweep] workloads=$WORKLOADS smoke=''${SMOKE:-no}"

    # Pre-stage every workload pcap on every host. scp is invoked
    # once per (host, workload) — small files (<1MB each).
    IFS=',' read -ra WLIST <<< "$WORKLOADS"
    echo "[sweep] pre-staging ''${#WLIST[@]} pcap(s) to ''${#HOSTS[@]} host(s)"
    for w in "''${WLIST[@]}"; do
      src="''${PCAP_OF[$w]:-}"
      if [ -z "$src" ]; then
        echo "matrix-sweep: unknown workload '$w' (no workload-pcap-$w derivation)" >&2
        exit 2
      fi
      for h in "''${HOSTS[@]}"; do
        echo "[stage] $w → root@$h:/tmp/$w.pcap"
        scp -q -o BatchMode=yes "$src" "root@$h:/tmp/$w.pcap"
      done
    done

    # Loop the per-workload matrix-run invocations.
    for w in "''${WLIST[@]}"; do
      echo
      echo "================================================================"
      echo "[sweep] $(date -Is) starting $w"
      echo "================================================================"
      XDP2_MATRIX_PCAP="/tmp/$w.pcap" \
        flow-dissector-matrix-run --testbed "$TESTBED" $SMOKE
      echo "[sweep] $(date -Is) done $w"
    done

    # Single aggregate at the end — picks up every JSON dropped by
    # the per-workload matrix-runs.
    echo
    echo "[sweep] aggregating $RESULTS"
    flow-dissector-matrix-aggregate --results "$RESULTS"

    echo
    echo "[sweep] complete. summary at $RESULTS/summary.md"
  '';

  meta = {
    description = "Multi-workload sweep: pre-stages pcaps, calls matrix-run per workload, aggregates";
    mainProgram = "flow-dissector-matrix-sweep";
  };
}
