# nix/perf-analysis.nix
#
# Deep performance analysis targets — reproducible across machines.
#
# Targets:
#   nix run  .#perf-sweep-tcp          — sweep tcp_ipv4.pcap (baseline, fast)
#   nix run  .#perf-sweep-mixed        — sweep merged real-protocol PCAP (~871 pkts)
#   nix run  .#perf-sweep-combo        — sweep 500K-packet combo.pcap (full-scale)
#   nix run  .#perf-flamegraph         — flamegraphs for graph/compiled/template
#   nix run  .#perf-annotate           — perf annotate for hot functions
#   nix run  .#perf-analysis-all       — run all sweeps + flamegraph + annotate
#   nix build .#perf-mixed-pcap        — generate merged mixed-protocol PCAP
#
# All nix run targets write results to ./perf-results/ (or user-specified dir).
# Set CORE_PIN=N to pin benchmarks to a specific core for reduced jitter.
#
# Prerequisites:
#   - kernel.perf_event_paranoid <= 2 (for perf counters)
#   - cargo install inferno (for flamegraph generation)
#

{ pkgs, xdp2Rs, test-pcap }:

let
  sweepScript = ../xdp2-rs/scripts/perf-sweep.sh;

  # ── Cached: merged mixed-protocol PCAP from real captures ──────────
  mixed-pcap = pkgs.runCommand "xdp2-mixed-pcap" {
    nativeBuildInputs = [ pkgs.wireshark-cli ];
  } ''
    mkdir -p $out
    # -F pcap forces legacy pcap format (xdp2-bench does not support pcapng)
    mergecap -F pcap -w $out/mixed-real.pcap \
      ${../data/pcaps/tcp_ipv4.pcap} \
      ${../data/pcaps/tcp_ipv6.pcap} \
      ${../data/pcaps/tcp_sack.pcap} \
      ${../data/pcaps/gre-within-gre.pcap} \
      ${../data/pcaps/gre-sample.pcap} \
      ${../data/pcaps/vxlan.pcap} \
      ${../data/pcaps/l2tp.pcap} \
      ${../data/pcaps/ipip.pcap} \
      ${../data/pcaps/6in4.pcap} \
      ${../data/pcaps/QinQ.pcap} \
      ${../data/pcaps/vlan_icmp.pcap} \
      ${../data/pcaps/icmp_ipv4.pcap} \
      ${../data/pcaps/ipv4frags.pcap} \
      ${../data/pcaps/ipv6-udp-fragmented.pcap} \
      ${../data/pcaps/srv6-end-64.pcap} \
      ${../data/pcaps/srv6-t_encaps_v6-64.pcap}
  '';

  # Common runtime inputs for sweep targets
  sweepInputs = [ xdp2Rs.build pkgs.coreutils pkgs.gnugrep ];

  # Common runtime inputs for perf record targets
  # - pkgs.flamegraph: stackcollapse-perf.pl, flamegraph.pl
  # - pkgs.inferno: inferno-collapse-perf, inferno-flamegraph (Rust, faster)
  perfInputs = [
    xdp2Rs.build pkgs.perf pkgs.coreutils
    pkgs.util-linux   # taskset
    pkgs.inferno
    pkgs.flamegraph
  ];

in
{
  inherit mixed-pcap;

  # ── Sweep: tcp_ipv4.pcap (baseline, fast) ────────────────────────
  sweep-tcp = pkgs.writeShellApplication {
    name = "xdp2-perf-sweep-tcp";
    runtimeInputs = sweepInputs;
    text = ''
      OUTDIR="''${1:-perf-results/tcp_ipv4}"
      export BENCH="xdp2-bench"
      exec ${sweepScript} "${../data/pcaps/tcp_ipv4.pcap}" 500 "$OUTDIR"
    '';
  };

  # ── Sweep: mixed-real.pcap (real protocol diversity, ~871 pkts) ──
  sweep-mixed = pkgs.writeShellApplication {
    name = "xdp2-perf-sweep-mixed";
    runtimeInputs = sweepInputs;
    text = ''
      OUTDIR="''${1:-perf-results/mixed-real}"
      export BENCH="xdp2-bench"
      exec ${sweepScript} "${mixed-pcap}/mixed-real.pcap" 500 "$OUTDIR"
    '';
  };

  # ── Sweep: combo.pcap (full-scale, 500K packets) ────────────────
  sweep-combo = pkgs.writeShellApplication {
    name = "xdp2-perf-sweep-combo";
    runtimeInputs = sweepInputs;
    text = ''
      OUTDIR="''${1:-perf-results/combo}"
      export BENCH="xdp2-bench"
      exec ${sweepScript} "${test-pcap}/combo.pcap" 200 "$OUTDIR"
    '';
  };

  # ── Flamegraphs: graph, compiled, template on combo.pcap ─────────
  flamegraph = pkgs.writeShellApplication {
    name = "xdp2-perf-flamegraph";
    runtimeInputs = perfInputs;
    text = ''
      PCAP="''${1:-${test-pcap}/combo.pcap}"
      ITERATIONS="''${2:-200}"
      OUTDIR="''${3:-perf-results/flamegraphs}"
      CORE_PIN="''${CORE_PIN:-3}"
      mkdir -p "$OUTDIR"

      for MODE in graph compiled template; do
        echo "--- Flamegraph: $MODE ---"
        PERF_DATA=$(mktemp)
        taskset -c "$CORE_PIN" perf record -g -F 10000 -o "$PERF_DATA" -- \
          xdp2-bench --pcap "$PCAP" --iterations "$ITERATIONS" --mode "$MODE" \
          --core-pin "$CORE_PIN" 2>/dev/null

        if command -v inferno-collapse-perf &>/dev/null; then
          perf script -i "$PERF_DATA" | inferno-collapse-perf | \
            inferno-flamegraph > "$OUTDIR/flamegraph_''${MODE}.svg"
          echo "Wrote: $OUTDIR/flamegraph_''${MODE}.svg"
        elif command -v stackcollapse-perf.pl &>/dev/null; then
          perf script -i "$PERF_DATA" | stackcollapse-perf.pl | \
            flamegraph.pl > "$OUTDIR/flamegraph_''${MODE}.svg"
          echo "Wrote: $OUTDIR/flamegraph_''${MODE}.svg"
        else
          echo "warning: neither inferno nor flamegraph.pl found"
          echo "  install: cargo install inferno"
        fi
        rm -f "$PERF_DATA"
      done
    '';
  };

  # ── perf annotate: assembly-level hot function analysis ──────────
  annotate = pkgs.writeShellApplication {
    name = "xdp2-perf-annotate";
    runtimeInputs = perfInputs;
    text = ''
      PCAP="''${1:-${test-pcap}/combo.pcap}"
      ITERATIONS="''${2:-200}"
      OUTDIR="''${3:-perf-results/annotate}"
      CORE_PIN="''${CORE_PIN:-3}"
      mkdir -p "$OUTDIR"

      for MODE in compiled template graph; do
        echo "--- Annotate: $MODE ---"
        PERF_DATA=$(mktemp)
        taskset -c "$CORE_PIN" perf record -g -F 10000 -o "$PERF_DATA" -- \
          xdp2-bench --pcap "$PCAP" --iterations "$ITERATIONS" --mode "$MODE" \
          --core-pin "$CORE_PIN" 2>/dev/null

        perf annotate -i "$PERF_DATA" --stdio > "$OUTDIR/annotate_''${MODE}.txt" 2>/dev/null || true
        rm -f "$PERF_DATA"
        echo "Wrote: $OUTDIR/annotate_''${MODE}.txt"
      done
    '';
  };

  # ── Combined: run all analysis steps sequentially ────────────────
  analysis-all = let
    sweep-tcp = pkgs.writeShellApplication {
      name = "xdp2-perf-sweep-tcp";
      runtimeInputs = sweepInputs;
      text = ''
        OUTDIR="''${1:-perf-results/tcp_ipv4}"
        export BENCH="xdp2-bench"
        exec ${sweepScript} "${../data/pcaps/tcp_ipv4.pcap}" 500 "$OUTDIR"
      '';
    };
    sweep-mixed = pkgs.writeShellApplication {
      name = "xdp2-perf-sweep-mixed";
      runtimeInputs = sweepInputs;
      text = ''
        OUTDIR="''${1:-perf-results/mixed-real}"
        export BENCH="xdp2-bench"
        exec ${sweepScript} "${mixed-pcap}/mixed-real.pcap" 500 "$OUTDIR"
      '';
    };
    sweep-combo = pkgs.writeShellApplication {
      name = "xdp2-perf-sweep-combo";
      runtimeInputs = sweepInputs;
      text = ''
        OUTDIR="''${1:-perf-results/combo}"
        export BENCH="xdp2-bench"
        exec ${sweepScript} "${test-pcap}/combo.pcap" 200 "$OUTDIR"
      '';
    };
    flamegraph-cmd = pkgs.writeShellApplication {
      name = "xdp2-perf-flamegraph";
      runtimeInputs = perfInputs;
      text = ''
        PCAP="''${1:-${test-pcap}/combo.pcap}"
        ITERATIONS="''${2:-200}"
        OUTDIR="''${3:-perf-results/flamegraphs}"
        CORE_PIN="''${CORE_PIN:-3}"
        mkdir -p "$OUTDIR"
        for MODE in graph compiled template; do
          echo "--- Flamegraph: $MODE ---"
          PERF_DATA=$(mktemp)
          taskset -c "$CORE_PIN" perf record -g -F 10000 -o "$PERF_DATA" -- \
            xdp2-bench --pcap "$PCAP" --iterations "$ITERATIONS" --mode "$MODE" \
            --core-pin "$CORE_PIN" 2>/dev/null
          if command -v inferno-collapse-perf &>/dev/null; then
            perf script -i "$PERF_DATA" | inferno-collapse-perf | \
              inferno-flamegraph > "$OUTDIR/flamegraph_''${MODE}.svg"
            echo "Wrote: $OUTDIR/flamegraph_''${MODE}.svg"
          else
            echo "warning: inferno not found — install with: cargo install inferno"
          fi
          rm -f "$PERF_DATA"
        done
      '';
    };
    annotate-cmd = pkgs.writeShellApplication {
      name = "xdp2-perf-annotate";
      runtimeInputs = perfInputs;
      text = ''
        PCAP="''${1:-${test-pcap}/combo.pcap}"
        ITERATIONS="''${2:-200}"
        OUTDIR="''${3:-perf-results/annotate}"
        CORE_PIN="''${CORE_PIN:-3}"
        mkdir -p "$OUTDIR"
        for MODE in compiled template graph; do
          echo "--- Annotate: $MODE ---"
          PERF_DATA=$(mktemp)
          taskset -c "$CORE_PIN" perf record -g -F 10000 -o "$PERF_DATA" -- \
            xdp2-bench --pcap "$PCAP" --iterations "$ITERATIONS" --mode "$MODE" \
            --core-pin "$CORE_PIN" 2>/dev/null
          perf annotate -i "$PERF_DATA" --stdio > "$OUTDIR/annotate_''${MODE}.txt" 2>/dev/null || true
          rm -f "$PERF_DATA"
          echo "Wrote: $OUTDIR/annotate_''${MODE}.txt"
        done
      '';
    };
  in pkgs.writeShellApplication {
    name = "xdp2-perf-analysis-all";
    runtimeInputs = [
      sweep-tcp sweep-mixed sweep-combo
      flamegraph-cmd annotate-cmd
    ];
    text = ''
      echo "=== XDP2 Deep Performance Analysis ==="
      echo "Output: perf-results/"
      echo ""

      echo ">>> Step 1/5: Sweep tcp_ipv4.pcap (baseline)"
      xdp2-perf-sweep-tcp

      echo ""
      echo ">>> Step 2/5: Sweep mixed-real.pcap (protocol diversity)"
      xdp2-perf-sweep-mixed

      echo ""
      echo ">>> Step 3/5: Sweep combo.pcap (full-scale, 500K packets)"
      xdp2-perf-sweep-combo

      echo ""
      echo ">>> Step 4/5: Flamegraphs (graph, compiled, template)"
      xdp2-perf-flamegraph

      echo ""
      echo ">>> Step 5/5: perf annotate (compiled, template, graph)"
      xdp2-perf-annotate

      echo ""
      echo "=== Analysis complete ==="
      echo "Results in: perf-results/"
      find perf-results/ -type f | sort
    '';
  };
}
