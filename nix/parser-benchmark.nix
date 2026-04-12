# nix/parser-benchmark.nix
#
# Performance benchmark — compare C and Rust XDP2 parse engines.
#
# Generates a test PCAP, runs both the C flow_dissector benchmark and the
# Rust xdp2-bench on the same packets, and reports side-by-side results.
#
# Targets:
#   nix build .#parser-benchmark  — run C vs Rust parser benchmark
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
    pkgs.gcc
    pkgs.libpcap
    pkgs.libpcap.lib
    pkgs.linuxHeaders
    (pkgs.python314.withPackages (ps: [ ps.scapy ]))
    xdp2
    xdp2Rs.build
  ];
  text = ''
    set -euo pipefail

    echo "============================================"
    echo "  XDP2 Parser Benchmark: C vs Rust"
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
    ITERATIONS=''${1:-100}
    NPKTS=''${2:-500000}

    echo "--- Phase 1: Generate test PCAP ($NPKTS packets) ---"
    python3 ${genTestPcap} -o test.pcap -n "$NPKTS" 2>&1
    ACTUAL_PKTS=$(python3 -c "
import struct, sys
with open('test.pcap','rb') as f:
    f.read(24)
    n=0
    while True:
        h=f.read(16)
        if len(h)<16: break
        caplen=struct.unpack('<I',h[8:12])[0]
        f.read(caplen)
        n+=1
    print(n)
")
    echo "Generated $ACTUAL_PKTS packets in test.pcap"
    echo ""

    # ── Phase 2: Build C benchmark ──
    echo "--- Phase 2: Build C flow_dissector benchmark ---"

    C_BUILD_OK=false
    C_NS="N/A"
    C_PARSEONLY_NS="N/A"

    if gcc -I${xdp2}/include -I${pkgs.libpcap}/include -g -O2 -c -o parser.o parser.c 2>&1; then
      # Generate optimized parser
      ${xdp2}/bin/xdp2-compiler -I${xdp2}/include -i parser.c -o parser.p.c

      # Build benchmark binary
      gcc -I${xdp2}/include -I${pkgs.libpcap}/include -g -O2 \
          -L${xdp2}/lib -L${pkgs.libpcap.lib}/lib \
          -Wl,-rpath,${xdp2}/lib -Wl,-rpath,${pkgs.libpcap.lib}/lib \
          -o benchmark benchmark.c parser.p.c \
          -lpcap -lxdp2 -lcli -lflowdis -lsiphash

      echo "C benchmark built successfully"
      C_BUILD_OK=true
    else
      echo "WARNING: C benchmark build failed (header conflicts with updated xdp2 headers)"
      echo "  The flow_dissector source needs updating to match the new proto_defs."
      echo "  Continuing with Rust-only benchmark."
    fi
    echo ""

    # ── Phase 3: Run C benchmark (if built) ──
    if [[ "$C_BUILD_OK" == "true" ]]; then
      echo "--- Phase 3: C Performance ($ACTUAL_PKTS packets x $ITERATIONS iterations) ---"
      C_OUTPUT=$(./benchmark -p -n "$ITERATIONS" test.pcap 2>&1 || true)
      echo "$C_OUTPUT"
      echo ""

      # Extract C ns/pkt from output
      C_NS=$(echo "$C_OUTPUT" | grep -oP 'XDP2 parser:\s+\K\d+(?=\s+ns/pkt)' || echo "N/A")
      C_PARSEONLY_NS=$(echo "$C_OUTPUT" | grep -oP 'XDP2 parse-only:\s*\K\d+(?=\s+ns/pkt)' || echo "N/A")
    else
      echo "--- Phase 3: Skipped (C benchmark not available) ---"
      echo ""
    fi

    # ── Phase 4: Run Rust benchmark ──
    echo "--- Phase 4: Rust Performance ($ACTUAL_PKTS packets x $ITERATIONS iterations) ---"
    RUST_OUTPUT=$(xdp2-bench --pcap test.pcap --iterations "$ITERATIONS" --warmup 3 2>&1 || true)
    echo "$RUST_OUTPUT"
    echo ""

    # Extract Rust ns/pkt from output
    RUST_NS=$(echo "$RUST_OUTPUT" | grep -oP 'Rust parser:\s+\K\d+(?=\s+ns/pkt)' || echo "N/A")
    RUST_PARSEONLY_NS=$(echo "$RUST_OUTPUT" | grep -oP 'Rust parse-only:\s*\K\d+(?=\s+ns/pkt)' || echo "N/A")

    # ── Phase 5: Comparison ──
    echo "============================================"
    echo "  Side-by-Side Comparison"
    echo "============================================"
    echo ""
    printf "%-20s  %10s  %10s\n" "" "C (ns/pkt)" "Rust (ns/pkt)"
    printf "%-20s  %10s  %10s\n" "--------------------" "----------" "-------------"
    printf "%-20s  %10s  %10s\n" "Full parse" "$C_NS" "$RUST_NS"
    printf "%-20s  %10s  %10s\n" "Parse-only" "$C_PARSEONLY_NS" "$RUST_PARSEONLY_NS"
    echo ""

    # Compute ratio if both are numeric
    if [[ "$C_NS" =~ ^[0-9]+$ ]] && [[ "$RUST_NS" =~ ^[0-9]+$ ]] && [[ "$C_NS" -gt 0 ]]; then
      # Use awk for floating-point division
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
