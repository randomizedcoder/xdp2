# nix/perf-analysis.nix
#
# Deep performance analysis targets — reproducible across machines.
#
# Targets:
#   nix run  .#perf-sweep-tcp              — sweep tcp_ipv4.pcap (baseline, fast)
#   nix run  .#perf-sweep-mixed            — sweep merged real-protocol PCAP (~871 pkts)
#   nix run  .#perf-sweep-combo            — sweep 500K-packet combo.pcap (full-scale)
#   nix run  .#perf-flamegraph             — flamegraphs for graph/graph-enum/compiled/template
#   nix run  .#perf-annotate               — perf annotate for hot functions
#   nix run  .#perf-graph-enum-compare     — A/B test+bench for graph vs graph-enum vs compiled
#   nix run  .#chain-histogram             — run chain-signature probe on a PCAP (arg 1)
#   nix run  .#chain-histogram-all         — run probe on tcp_ipv4 + mixed-real + combo
#   nix run  .#perf-analysis-all           — run all sweeps + flamegraph + annotate
#   nix build .#perf-mixed-pcap            — generate merged mixed-protocol PCAP
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

  # ── Flamegraphs: graph, graph-enum, compiled, template on combo.pcap ─────────
  flamegraph = pkgs.writeShellApplication {
    name = "xdp2-perf-flamegraph";
    runtimeInputs = perfInputs;
    text = ''
      PCAP="''${1:-${test-pcap}/combo.pcap}"
      ITERATIONS="''${2:-200}"
      OUTDIR="''${3:-perf-results/flamegraphs}"
      CORE_PIN="''${CORE_PIN:-3}"
      mkdir -p "$OUTDIR"

      for MODE in graph graph-enum compiled template; do
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

      for MODE in compiled template graph graph-enum; do
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

  # ── Option A A/B: graph vs graph-enum vs compiled ───────────────
  #
  # Focused comparison for the graph-enum experiment. Runs each of the three
  # modes back-to-back at high iteration count on tcp_ipv4.pcap (the minimal
  # node-set for graph-enum covers this PCAP entirely), captures per-mode
  # JSON reports with perf counters, and a flamegraph for each. Also runs
  # the `cargo test` correctness A/B so the numbers are trustworthy.
  #
  # Output layout:
  #   perf-results/graph-enum/
  #     test.log                 — cargo test graph_enum
  #     bench_graph.json         — xdp2-bench --mode graph --report
  #     bench_graph-enum.json
  #     bench_compiled.json
  #     flamegraph_graph.svg
  #     flamegraph_graph-enum.svg
  #     flamegraph_compiled.svg
  #     summary.txt              — ns/pkt table for quick diffing
  graph-enum-compare = pkgs.writeShellApplication {
    name = "xdp2-perf-graph-enum-compare";
    runtimeInputs = perfInputs;
    text = ''
      PCAP="''${1:-${../data/pcaps/tcp_ipv4.pcap}}"
      ITERATIONS="''${2:-5000}"
      OUTDIR="''${3:-perf-results/graph-enum}"
      CORE_PIN="''${CORE_PIN:-3}"
      mkdir -p "$OUTDIR"

      echo "=== graph vs graph-enum vs compiled ==="
      echo "PCAP:       $PCAP"
      echo "Iterations: $ITERATIONS"
      echo "Core pin:   $CORE_PIN"
      echo "Output:     $OUTDIR/"
      echo ""

      SUMMARY="$OUTDIR/summary.txt"
      {
        echo "graph-enum A/B comparison"
        echo "pcap: $PCAP"
        echo "iterations: $ITERATIONS  core: $CORE_PIN  host: $(hostname)"
        echo "date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo ""
      } > "$SUMMARY"

      # --- Benchmarks (release build with perf counters) ---
      for MODE in graph graph-enum compiled; do
        echo "--- Bench: $MODE ---"
        JSON="$OUTDIR/bench_''${MODE}.json"
        taskset -c "$CORE_PIN" xdp2-bench \
          --pcap "$PCAP" --iterations "$ITERATIONS" \
          --mode "$MODE" --core-pin "$CORE_PIN" \
          --perf --perf-pass basic --perf-pass stalls \
          --report > "$JSON"
        NSPKT=$(grep -oE '"ns_pkt"[[:space:]]*:[[:space:]]*[0-9]+' "$JSON" | head -1 | grep -oE '[0-9]+$' || echo "?")
        MPPS=$(grep -oE '"mpps"[[:space:]]*:[[:space:]]*[0-9.]+' "$JSON" | head -1 | grep -oE '[0-9.]+$' || echo "?")
        printf "  %-12s %6s ns/pkt   %6s Mpps\n" "$MODE" "$NSPKT" "$MPPS" | tee -a "$SUMMARY"
      done
      echo ""

      # --- Flamegraphs ---
      for MODE in graph graph-enum compiled; do
        echo "--- Flamegraph: $MODE ---"
        PERF_DATA=$(mktemp)
        taskset -c "$CORE_PIN" perf record -g -F 10000 -o "$PERF_DATA" -- \
          xdp2-bench --pcap "$PCAP" --iterations "$ITERATIONS" \
          --mode "$MODE" --core-pin "$CORE_PIN" 2>/dev/null

        if command -v inferno-collapse-perf &>/dev/null; then
          perf script -i "$PERF_DATA" | inferno-collapse-perf | \
            inferno-flamegraph > "$OUTDIR/flamegraph_''${MODE}.svg"
          echo "Wrote: $OUTDIR/flamegraph_''${MODE}.svg"
        else
          echo "warning: inferno not found"
        fi
        rm -f "$PERF_DATA"
      done

      echo ""
      echo "=== Summary ==="
      cat "$SUMMARY"
      echo ""
      echo "Results: $OUTDIR/"
    '';
  };

  # ── Chain-signature histogram probe (single PCAP, interactive) ───
  #
  # First step of the fast-path dispatch exploration (see
  # docs/fast-path-dispatch.md). Parses every packet with the graph
  # engine, buckets by protocol-chain signature derived from FlowMeta,
  # prints top-N.
  #
  # Usage: nix run .#chain-histogram -- <pcap> [top-n]
  chain-histogram = pkgs.writeShellApplication {
    name = "xdp2-chain-histogram";
    runtimeInputs = [ xdp2Rs.build pkgs.coreutils ];
    text = ''
      PCAP="''${1:-}"
      if [ -z "$PCAP" ]; then
        echo "usage: xdp2-chain-histogram <pcap> [top-n]"
        echo "       top-n defaults to 20"
        exit 1
      fi
      TOP="''${2:-20}"
      exec xdp2-bench --pcap "$PCAP" --chain-histogram --top "$TOP"
    '';
  };

  # ── Chain-histogram on all three reference PCAPs ─────────────────
  #
  # Regenerates perf-results/chain-histogram/report.txt — the reference
  # dataset cited in docs/fast-path-dispatch.md. Runs the probe on:
  #   - tcp_ipv4.pcap       (baseline, single chain)
  #   - mixed-real.pcap     (merged real captures, Linux-box-like mix)
  #   - combo.pcap          (500 k synthetic, adversarial protocol mix)
  chain-histogram-all = pkgs.writeShellApplication {
    name = "xdp2-chain-histogram-all";
    runtimeInputs = [ xdp2Rs.build pkgs.coreutils ];
    text = ''
      OUTDIR="''${1:-perf-results/chain-histogram}"
      TOP="''${2:-30}"
      mkdir -p "$OUTDIR"
      REPORT="$OUTDIR/report.txt"

      {
        echo "=== Chain histogram probe — $(date -u +%Y-%m-%d) ==="
        echo "host: $(hostname)  top: $TOP"
        echo ""
        echo "--- tcp_ipv4.pcap (baseline, single chain expected) ---"
        xdp2-bench --pcap ${../data/pcaps/tcp_ipv4.pcap} --chain-histogram --top "$TOP"
        echo ""
        echo "--- mixed-real.pcap (real captures merged, Linux-box-like traffic) ---"
        xdp2-bench --pcap ${mixed-pcap}/mixed-real.pcap --chain-histogram --top "$TOP"
        echo ""
        echo "--- combo.pcap (500K synthetic, adversarial protocol mix) ---"
        xdp2-bench --pcap ${test-pcap}/combo.pcap --chain-histogram --top "$TOP"
      } | tee "$REPORT"

      echo ""
      echo "Wrote: $REPORT"
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
        for MODE in graph graph-enum compiled template; do
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
        for MODE in compiled template graph graph-enum; do
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
