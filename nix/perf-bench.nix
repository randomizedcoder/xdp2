# nix/perf-bench.nix
#
# Reproducible Rust parser benchmark targets.
#
# Targets:
#   nix run .#perf-bench              — standard benchmark (all modes, 500 iters, perf counters)
#   nix run .#perf-bench -- <args>    — custom args passed to xdp2-bench
#   nix run .#perf-sweep              — full performance sweep (all thread counts, JSON output)
#   nix run .#perf-sweep -- <args>    — custom args to perf-sweep.sh
#
# Both targets build xdp2-bench with fat LTO and target-cpu=native for
# maximum optimization, then run against the standard test PCAP.
#

{ pkgs, xdp2Rs }:

let
  pcapPath = ../data/pcaps/tcp_ipv4.pcap;
  sweepScript = ../xdp2-rs/scripts/perf-sweep.sh;
in
{
  # ── Standard benchmark: all modes, perf counters ──────────────────
  #
  # Usage:
  #   nix run .#perf-bench
  #   nix run .#perf-bench -- --mode compiled --iterations 1000
  #   nix run .#perf-bench -- --pcap /path/to/custom.pcap --mode both
  bench = pkgs.writeShellApplication {
    name = "xdp2-perf-bench";
    runtimeInputs = [ xdp2Rs.build pkgs.coreutils ];
    text = ''
      set -euo pipefail

      PCAP="${pcapPath}"
      DEFAULT_ARGS=(--pcap "$PCAP" --iterations 500 --mode both --perf)

      if [ $# -gt 0 ]; then
        # Custom args — user overrides everything
        exec xdp2-bench "$@"
      else
        echo "=== XDP2 Rust Parser Benchmark ==="
        echo "PCAP: $PCAP"
        echo "Args: ''${DEFAULT_ARGS[*]}"
        echo ""
        exec xdp2-bench "''${DEFAULT_ARGS[@]}"
      fi
    '';
  };

  # ── Full performance sweep: all thread counts, JSON output ────────
  #
  # Usage:
  #   nix run .#perf-sweep
  #   nix run .#perf-sweep -- /path/to/custom.pcap 1000 ./results/
  sweep = pkgs.writeShellApplication {
    name = "xdp2-perf-sweep";
    runtimeInputs = [ xdp2Rs.build pkgs.coreutils pkgs.gnugrep ];
    text = ''
      set -euo pipefail

      PCAP="''${1:-${pcapPath}}"
      ITERATIONS="''${2:-500}"
      OUTDIR="''${3:-perf-results}"

      # Override BENCH so perf-sweep.sh uses the Nix-built binary
      export BENCH="xdp2-bench"
      exec ${sweepScript} "$PCAP" "$ITERATIONS" "$OUTDIR"
    '';
  };
}
