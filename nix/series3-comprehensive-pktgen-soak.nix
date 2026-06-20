# nix/series3-comprehensive-pktgen-soak.nix
#
# Phase H wrapper around series3-cpu-bound-soak with comprehensive
# defaults: every sysctl-controlled fast-path scenario (eth_ip through
# geneve_inner), all 3 healthy testbed pairs, REPLICATES=3 for
# confidence intervals. Runs after series3-comprehensive-iperf3-soak
# in the overnight pipeline.
#
# Wall-clock per cell ≈ 70s. Cells: 3 pairs × 8 scenarios × 2 sysctl
# × 3 reps = 144 cells × 70s ≈ 2.8 h.
#
# vxlan + geneve cells emit status=overlay-unsupported (the kernel
# pktgen driver doesn't accept add_device against vxlan/geneve
# netdevs); the summary-report tool filters those rows out of the
# headline table automatically.
#
# Usage:
#   nix run .#series3-comprehensive-pktgen-soak

{ pkgs }:

let
  inner = import ./series3-cpu-bound-soak.nix { inherit pkgs; };
in
pkgs.writeShellApplication {
  name = "series3-comprehensive-pktgen-soak";
  runtimeInputs = with pkgs; [ inner coreutils ];
  text = ''
    today=$(date +%Y-%m-%d)
    export PAIRS=''${PAIRS:-pi5-pair,hp1-hp3,hp2-hp5}
    export SCENARIOS=''${SCENARIOS:-eth_ip,vlan,qinq,vxlan,mpls,ipip,gre,geneve}
    export DUR=''${DUR:-60}
    export REPLICATES=''${REPLICATES:-3}
    export OUT=''${OUT:-perf-results/$today-phase-h-pktgen}
    echo "[series3-comprehensive-pktgen-soak]"
    echo "  PAIRS=$PAIRS  SCENARIOS=$SCENARIOS"
    echo "  DUR=$DUR REPLICATES=$REPLICATES"
    echo "  OUT=$OUT"
    n_pairs=$(echo "$PAIRS" | tr ',' ' ' | wc -w)
    n_scen=$(echo "$SCENARIOS" | tr ',' ' ' | wc -w)
    n_cells=$(( n_pairs * n_scen * 2 * REPLICATES ))  # 2 sysctl, pktgen UDP only
    eta_s=$(( n_cells * (DUR + 10) ))
    echo "  estimated wall-clock: $n_cells cells * ~$(( DUR + 10 ))s = $(( eta_s / 60 ))min ($(( eta_s / 3600 ))h)"
    exec ${inner}/bin/series3-cpu-bound-soak
  '';
}
