# nix/series3-extensions-soak-10h.nix
#
# 10-hour soak wrapper around series3-extensions-soak.
#
# Wall-clock budget per cell: ~10h * 3600 s / 60 cells ≈ 600s. Use
# DUR=600 to fill the budget. 60 cells = 3 pairs * 5 scenarios * 4 cells
# (PPPoE excluded until the testbed-infrastructure issue documented in
# perf-results/2026-06-16-pppoe-investigation.md is resolved).
#
# Outputs land in perf-results/<YYYY-MM-DD>-v4-soak-10h/ with the same
# per-cell artifacts the smoke runs produce (iperf3.json, mpstat.log,
# scenario.env) and a single matrix.csv with mpstat-derived
# recv_sys_pct + recv_soft_pct columns.
#
# Goal: pin down the run-to-run variance of the recv_soft delta. The
# DUR=60 runs showed signal direction-consistent across pairs but
# magnitudes wobbled 0.1-1.5pp. DUR=600 gives ~10x more samples per
# cell, which should drop the noise floor by ~sqrt(10) ≈ 3x — enough
# to nail the MPLS UDP -1pp signal to ±0.3pp confidence.
#
# Usage:
#   nix run .#series3-extensions-soak-10h
#
# Override knobs (all default-correct for the standard fleet):
#   PAIRS=pi5-pair,hp1-hp3,hp2-hp5      pairs to run
#   SCENARIOS=vlan,qinq,vxlan,mpls,ipip scenarios (omit pppoe; see above)
#   DUR=600                             per-cell test seconds
#   OUT=perf-results/<date>-v4-soak-10h output dir

{ pkgs }:

let
  inner = import ./series3-extensions-soak.nix { inherit pkgs; };
in
pkgs.writeShellApplication {
  name = "series3-extensions-soak-10h";
  runtimeInputs = with pkgs; [ inner coreutils ];
  text = ''
    today=$(date +%Y-%m-%d)
    export PAIRS=''${PAIRS:-pi5-pair,hp1-hp3,hp2-hp5}
    export SCENARIOS=''${SCENARIOS:-vlan,qinq,vxlan,mpls,ipip}
    export DUR=''${DUR:-600}
    export OUT=''${OUT:-perf-results/$today-v4-soak-10h}
    echo "[series3-extensions-soak-10h] PAIRS=$PAIRS  SCENARIOS=$SCENARIOS  DUR=$DUR  OUT=$OUT"
    echo "[series3-extensions-soak-10h] expected wall-clock ≈ $(( (DUR + 8) * 60 / 60 )) min × 60 cells = $(( (DUR + 8) * 60 / 3600 ))h"
    exec ${inner}/bin/series3-extensions-soak
  '';
}
