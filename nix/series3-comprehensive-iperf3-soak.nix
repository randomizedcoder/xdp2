# nix/series3-comprehensive-iperf3-soak.nix
#
# Phase H wrapper around series3-extensions-soak with comprehensive
# defaults: every sysctl-controlled fast-path scenario (eth_ip through
# geneve_inner), all 3 healthy testbed pairs, REPLICATES=3 for
# confidence intervals, CONSUMER_ALL=1 to load the receiver.
#
# Wall-clock budget per cell ≈ 70s. Cells: 3 pairs × 8 scenarios ×
# 2 protos × 2 sysctl × 3 reps = 288 cells × 70s ≈ 5.6 h.
#
# Defaults match the overnight comprehensive run picked in the Phase H
# plan (user choice 2026-06-19: DUR=60 N=3). Every default is
# overridable for narrower investigations.
#
# Usage:
#   nix run .#series3-comprehensive-iperf3-soak
#   PAIRS=hp1-hp3 nix run .#series3-comprehensive-iperf3-soak
#   DUR=120 REPLICATES=5 nix run .#series3-comprehensive-iperf3-soak

{ pkgs }:

let
  inner = import ./series3-extensions-soak.nix { inherit pkgs; };
in
pkgs.writeShellApplication {
  name = "series3-comprehensive-iperf3-soak";
  runtimeInputs = with pkgs; [ inner coreutils ];
  text = ''
    today=$(date +%Y-%m-%d)
    export PAIRS=''${PAIRS:-pi5-pair,hp1-hp3,hp2-hp5}
    export SCENARIOS=''${SCENARIOS:-eth_ip,vlan,qinq,vxlan,mpls,ipip,gre,geneve}
    export DUR=''${DUR:-60}
    export REPLICATES=''${REPLICATES:-3}
    export CONSUMER_ALL=''${CONSUMER_ALL:-1}
    export OUT=''${OUT:-perf-results/$today-phase-h-iperf3}
    echo "[series3-comprehensive-iperf3-soak]"
    echo "  PAIRS=$PAIRS  SCENARIOS=$SCENARIOS"
    echo "  DUR=$DUR REPLICATES=$REPLICATES CONSUMER_ALL=$CONSUMER_ALL"
    echo "  OUT=$OUT"
    # Each row roughly DUR + COOLDOWN + scenario-up/down amortized;
    # estimate ~70s per cell at DUR=60.
    n_pairs=$(echo "$PAIRS" | tr ',' ' ' | wc -w)
    n_scen=$(echo "$SCENARIOS" | tr ',' ' ' | wc -w)
    n_cells=$(( n_pairs * n_scen * 2 * 2 * REPLICATES ))  # 2 protos, 2 sysctl
    eta_s=$(( n_cells * (DUR + 10) ))
    echo "  estimated wall-clock: $n_cells cells * ~$(( DUR + 10 ))s = $(( eta_s / 60 ))min ($(( eta_s / 3600 ))h)"
    exec ${inner}/bin/series3-extensions-soak
  '';
}
