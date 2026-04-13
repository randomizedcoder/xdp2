# nix/parser-benchmark.nix
#
# Performance benchmark — compare C and Rust XDP2 parse engines.
#
# Generates a test PCAP, runs both the C flow_dissector benchmark and the
# Rust xdp2-bench on the same packets, and reports side-by-side results.
#
# Supports optional PGO (Profile-Guided Optimization) for both C and Rust:
#   --pgo flag triggers a two-pass build using profiling data from the
#   actual benchmark workload to optimize branch prediction, code layout,
#   and inlining decisions.
#
# Targets:
#   nix build .#parser-benchmark  — run C vs Rust parser benchmark
#
# Usage:
#   ./result/bin/xdp2-parser-benchmark [iterations] [npkts]        — standard
#   ./result/bin/xdp2-parser-benchmark [iterations] [npkts] --pgo  — with PGO
#
# Architecture:
#   gen_test_pcap.py → test.pcap (mixed protocols)
#                          │
#            ┌─────────────┴─────────────┐
#            ▼                           ▼
#     C benchmark.c                Rust xdp2-bench
#     (xdp2_parse)                 (engine::parse)
#            │                           │
#            ▼                           ▼
#     C: ns/pkt, Mpps              Rust: ns/pkt, Mpps
#
# PGO Pipeline (when --pgo):
#   Pass 1: Build instrumented binaries
#   Profile: Run benchmark workload to collect profiling data
#   Pass 2: Rebuild with profiling data for optimized code layout
#

{ pkgs
, xdp2        # The pre-built xdp2 package (C libraries + compiler)
, xdp2Rs      # Rust xdp2-rs build (provides xdp2-bench binary)
}:

let
  # LLVM config for clang include paths
  llvmConfig = import ./llvm.nix { inherit pkgs; lib = pkgs.lib; llvmVersion = 18; };

  # Source directories
  flowDissectorSrc = ../samples/flow_dissector;
  genTestPcap = ../samples/flow_dissector/gen_test_pcap.py;
  rustSrc = ../xdp2-rs;

  # Shared C compiler environment (matches nix/xdp-samples.nix)
  cppCompilerEnv = ''
    export XDP2DIR="${xdp2}"
    export INCDIR="${xdp2}/include"
    export BINDIR="${xdp2}/bin"
    export LIBDIR="${xdp2}/lib"

    export XDP2_CLANG_VERSION="${llvmConfig.version}"
    export XDP2_CLANG_RESOURCE_PATH="${llvmConfig.paths.clangResourceDir}"
    export XDP2_C_INCLUDE_PATH="${llvmConfig.paths.clangResourceDir}/include"
    export XDP2_GLIBC_INCLUDE_PATH="${pkgs.stdenv.cc.libc.dev}/include"
    export XDP2_LINUX_HEADERS_PATH="${pkgs.linuxHeaders}/include"

    export LD_LIBRARY_PATH="${llvmConfig.llvmPackages.llvm.lib}/lib:${llvmConfig.llvmPackages.libclang.lib}/lib:${pkgs.boost}/lib"
  '';

in
pkgs.writeShellApplication {
  name = "xdp2-parser-benchmark";
  runtimeInputs = [
    pkgs.coreutils
    pkgs.gnugrep
    pkgs.gnused
    pkgs.gawk
    pkgs.gcc
    pkgs.libpcap
    pkgs.libpcap.lib
    pkgs.linuxHeaders
    (pkgs.python314.withPackages (ps: [ ps.scapy ]))
    xdp2
    xdp2Rs.build
    # PGO dependencies: Rust toolchain + LLVM profdata merge tool
    pkgs.cargo
    pkgs.rustc
    pkgs.llvmPackages.bintools-unwrapped  # provides llvm-profdata
  ];
  text = ''
    set -euo pipefail

    # ── Parse arguments ──
    PGO_MODE=false
    POSITIONAL_ARGS=()
    for arg in "$@"; do
      case "$arg" in
        --pgo) PGO_MODE=true ;;
        *) POSITIONAL_ARGS+=("$arg") ;;
      esac
    done

    ITERATIONS=''${POSITIONAL_ARGS[0]:-100}
    NPKTS=''${POSITIONAL_ARGS[1]:-500000}

    echo "============================================"
    echo "  XDP2 Parser Benchmark: C vs Rust"
    if [[ "$PGO_MODE" == "true" ]]; then
      echo "  (PGO enabled — two-pass build)"
    fi
    echo "============================================"
    echo ""

    # ── Setup working directory ──
    WORKDIR=$(mktemp -d)
    trap 'chmod -R u+w "$WORKDIR" 2>/dev/null; rm -rf "$WORKDIR"' EXIT
    cd "$WORKDIR"

    # Copy flow_dissector sources for C benchmark build (make writable)
    cp -r ${flowDissectorSrc}/* .
    chmod -R u+w .

    ${cppCompilerEnv}

    # Disable Nix cc-wrapper hardening for benchmark
    export NIX_HARDENING_ENABLE=

    # ── Phase 1: Generate test PCAP ──
    echo "--- Phase 1: Generate test PCAP ($NPKTS packets) ---"
    python3 ${genTestPcap} -o test.pcap -n "$NPKTS" 2>&1
    echo ""

    # ── Phase 2: Filter PCAP to Rust-parseable packets ──
    #
    # xdp2-bench pre-filters: runs each packet through the Rust parser,
    # keeps only successful parses, writes a filtered PCAP. This ensures
    # both C and Rust benchmark on identical packets. As protocols are
    # added to the Rust graph, more packets automatically pass the filter.
    echo "--- Phase 2: Filter PCAP to Rust-parseable packets ---"
    FILTER_OUTPUT=$(xdp2-bench --pcap test.pcap --output-pcap filtered.pcap --iterations 1 --warmup 0 2>&1 || true)
    echo "$FILTER_OUTPUT"

    FILTERED_PKTS=$(echo "$FILTER_OUTPUT" | grep -oP 'Filtered: \K\d+' || echo "0")
    echo "Filtered PCAP: $FILTERED_PKTS packets"
    echo ""

    # ── Phase 3: Build C benchmark ──
    echo "--- Phase 3: Build C flow_dissector benchmark ---"

    C_BUILD_OK=false
    C_NS="N/A"
    C_PARSEONLY_NS="N/A"

    C_COMMON_FLAGS=(
      "-I${xdp2}/include"
      "-I${pkgs.libpcap}/include"
      -g -O2 -march=native
    )
    C_LINK_FLAGS=(
      "-L${xdp2}/lib"
      "-L${pkgs.libpcap.lib}/lib"
      "-Wl,-rpath,${xdp2}/lib"
      "-Wl,-rpath,${pkgs.libpcap.lib}/lib"
    )
    C_LIBS=(-lpcap -lxdp2 -lcli -lflowdis -lsiphash)

    if gcc "''${C_COMMON_FLAGS[@]}" -c -o parser.o parser.c 2>&1; then
      # Generate optimized parser
      ${xdp2}/bin/xdp2-compiler -I${xdp2}/include -i parser.c -o parser.p.c

      if [[ "$PGO_MODE" == "true" ]]; then
        # ── C PGO Pass 1: Build with instrumentation ──
        echo "  C PGO Pass 1: Building instrumented binary..."
        gcc "''${C_COMMON_FLAGS[@]}" -fprofile-generate \
            "''${C_LINK_FLAGS[@]}" \
            -o benchmark-pgo1 benchmark.c parser.p.c \
            "''${C_LIBS[@]}"

        # ── C PGO Profile: Run workload to collect data ──
        echo "  C PGO Profile: Collecting profiling data (10 iterations)..."
        ./benchmark-pgo1 -p -n 10 filtered.pcap >/dev/null 2>&1 || true

        # ── C PGO Pass 2: Rebuild with profile data ──
        echo "  C PGO Pass 2: Building optimized binary..."
        gcc "''${C_COMMON_FLAGS[@]}" -fprofile-use -fprofile-correction \
            "''${C_LINK_FLAGS[@]}" \
            -o benchmark benchmark.c parser.p.c \
            "''${C_LIBS[@]}"
        echo "C benchmark built successfully (PGO optimized)"
      else
        # Standard build (no PGO)
        gcc "''${C_COMMON_FLAGS[@]}" \
            "''${C_LINK_FLAGS[@]}" \
            -o benchmark benchmark.c parser.p.c \
            "''${C_LIBS[@]}"
        echo "C benchmark built successfully"
      fi

      C_BUILD_OK=true
    else
      echo "WARNING: C benchmark build failed (header conflicts with updated xdp2 headers)"
      echo "  The flow_dissector source needs updating to match the new proto_defs."
      echo "  Continuing with Rust-only benchmark."
    fi
    echo ""

    # ── Phase 4: Run C benchmark on FILTERED PCAP ──
    if [[ "$C_BUILD_OK" == "true" ]]; then
      echo "--- Phase 4: C Performance ($FILTERED_PKTS filtered packets x $ITERATIONS iterations) ---"
      C_OUTPUT=$(./benchmark -p -n "$ITERATIONS" filtered.pcap 2>&1 || true)
      echo "$C_OUTPUT"
      echo ""

      # Extract C ns/pkt from output
      C_NS=$(echo "$C_OUTPUT" | grep -oP 'XDP2 parser:\s+\K\d+(?=\s+ns/pkt)' || echo "N/A")
      C_PARSEONLY_NS=$(echo "$C_OUTPUT" | grep -oP 'XDP2 parse-only:\s*\K\d+(?=\s+ns/pkt)' || echo "N/A")
    else
      echo "--- Phase 4: Skipped (C benchmark not available) ---"
      echo ""
    fi

    # ── Phase 5: Run Rust benchmark on FILTERED PCAP ──
    echo "--- Phase 5: Rust Performance ($FILTERED_PKTS filtered packets x $ITERATIONS iterations) ---"

    if [[ "$PGO_MODE" == "true" ]]; then
      # ── Rust PGO Pipeline ──
      #
      # Two-pass PGO build using the same benchmark workload as profiling input.
      # Rust PGO is stable since Rust 1.71 and uses LLVM's instrumentation.
      #
      # Pass 1: cargo build with -Cprofile-generate → instrumented binary
      # Profile: Run the instrumented binary on the filtered PCAP
      # Merge: llvm-profdata merge → single .profdata file
      # Pass 2: cargo build with -Cprofile-use → optimized binary
      echo "  Rust PGO: Preparing source tree..."
      RUST_BUILD_DIR="$WORKDIR/rust-pgo"
      mkdir -p "$RUST_BUILD_DIR"
      cp -r ${rustSrc}/* "$RUST_BUILD_DIR/"
      chmod -R u+w "$RUST_BUILD_DIR"

      PGO_DATA_DIR="$WORKDIR/pgo-data"
      mkdir -p "$PGO_DATA_DIR"

      # Pass 1: Build with instrumentation
      echo "  Rust PGO Pass 1: Building instrumented binary..."
      RUSTFLAGS="-Cprofile-generate=$PGO_DATA_DIR -C target-cpu=native" \
        cargo build --release -p xdp2-bench \
        --manifest-path "$RUST_BUILD_DIR/Cargo.toml" \
        --target-dir "$RUST_BUILD_DIR/target" \
        2>&1 | tail -5

      # Profile: Run workload to collect data
      echo "  Rust PGO Profile: Collecting profiling data (10 iterations)..."
      "$RUST_BUILD_DIR/target/release/xdp2-bench" \
        --pcap "$WORKDIR/filtered.pcap" --iterations 10 --warmup 1 \
        2>&1 | tail -3

      # Merge profiling data
      echo "  Rust PGO: Merging profiling data..."
      PROF_COUNT=$(find "$PGO_DATA_DIR" -name '*.profraw' | wc -l)
      echo "  Found $PROF_COUNT .profraw files"

      llvm-profdata merge -o "$WORKDIR/merged.profdata" "$PGO_DATA_DIR/" 2>&1

      # Pass 2: Build with profile data
      echo "  Rust PGO Pass 2: Building optimized binary..."
      RUSTFLAGS="-Cprofile-use=$WORKDIR/merged.profdata -C target-cpu=native" \
        cargo build --release -p xdp2-bench \
        --manifest-path "$RUST_BUILD_DIR/Cargo.toml" \
        --target-dir "$RUST_BUILD_DIR/target" \
        2>&1 | tail -5

      echo "  Rust PGO: Build complete"
      echo ""

      # Benchmark the PGO-optimized binary
      RUST_OUTPUT=$("$RUST_BUILD_DIR/target/release/xdp2-bench" \
        --pcap "$WORKDIR/filtered.pcap" --iterations "$ITERATIONS" --warmup 3 2>&1 || true)
    else
      # Standard benchmark using pre-built binary
      RUST_OUTPUT=$(xdp2-bench --pcap filtered.pcap --iterations "$ITERATIONS" --warmup 3 2>&1 || true)
    fi

    echo "$RUST_OUTPUT"
    echo ""

    # Extract Rust ns/pkt from output
    RUST_NS=$(echo "$RUST_OUTPUT" | grep -oP 'Rust parser:\s+\K\d+(?=\s+ns/pkt)' || echo "N/A")
    RUST_PARSEONLY_NS=$(echo "$RUST_OUTPUT" | grep -oP 'Rust parse-only:\s*\K\d+(?=\s+ns/pkt)' || echo "N/A")

    # ── Phase 6: Comparison ──
    echo "============================================"
    echo "  Side-by-Side Comparison"
    echo "  ($FILTERED_PKTS packets — Rust-parseable subset)"
    if [[ "$PGO_MODE" == "true" ]]; then
      echo "  (Both C and Rust PGO-optimized)"
    fi
    echo "============================================"
    echo ""
    printf "%-20s  %10s  %10s\n" "" "C (ns/pkt)" "Rust (ns/pkt)"
    printf "%-20s  %10s  %10s\n" "--------------------" "----------" "-------------"
    printf "%-20s  %10s  %10s\n" "Full parse" "$C_NS" "$RUST_NS"
    printf "%-20s  %10s  %10s\n" "Parse-only" "$C_PARSEONLY_NS" "$RUST_PARSEONLY_NS"
    echo ""

    # Compute ratio if both are numeric
    if [[ "$C_NS" =~ ^[0-9]+$ ]] && [[ "$RUST_NS" =~ ^[0-9]+$ ]] && [[ "$C_NS" -gt 0 ]]; then
      RATIO=$(awk "BEGIN {printf \"%.2f\", $RUST_NS / $C_NS}")
      echo "Rust/C ratio: ''${RATIO}x (1.0 = identical, <1.0 = Rust faster)"
    fi
    if [[ "$C_PARSEONLY_NS" =~ ^[0-9]+$ ]] && [[ "$RUST_PARSEONLY_NS" =~ ^[0-9]+$ ]] && [[ "$C_PARSEONLY_NS" -gt 0 ]]; then
      RATIO_PO=$(awk "BEGIN {printf \"%.2f\", $RUST_PARSEONLY_NS / $C_PARSEONLY_NS}")
      echo "Rust/C parse-only ratio: ''${RATIO_PO}x"
    fi
    echo ""
    echo "============================================"
  '';
}
