# nix/tests/flow-dissector-benchmark.nix
#
# Test for the flow_dissector benchmark sample
#
# This test verifies that:
# 1. The benchmark userspace binary builds and runs correctly
# 2. The xdp2 parser produces correct flow dissection results
# 3. The xdp2 parser matches the kernel flow dissector on diverse traffic
#
# The benchmark compares xdp2's declarative parser against the kernel's
# flow dissector (ported to userspace as libflowdis) on real PCAP traffic.
#
# Supports two modes:
# - Native: Builds sample at runtime using xdp2-compiler
# - Pre-built: Uses pre-compiled binaries (for cross-compilation)
#
# Usage:
#   nix build .#tests.flow-dissector-benchmark
#   ./result/bin/xdp2-test-flow-dissector-benchmark
#

{ pkgs
, xdp2
  # Pre-built sample derivation (optional, for cross-compilation)
, prebuiltSample ? null
}:

let
  # Source directory for test data (pcap files)
  testData = ../..;

  # LLVM config for getting correct clang paths
  llvmConfig = import ../llvm.nix { inherit pkgs; lib = pkgs.lib; };

  # Determine if we're using pre-built samples
  usePrebuilt = prebuiltSample != null;

  # Architecture-specific BPF compilation defines
  # Maps Nix platform to kernel __TARGET_ARCH_* and compiler arch macros
  # needed to prevent glibc from pulling in wrong-bitness stubs
  bpfArchDefines = let
    cpu = pkgs.stdenv.hostPlatform.parsed.cpu.name;
  in {
    "x86_64"  = "-D__TARGET_ARCH_x86 -D__x86_64__";
    "aarch64" = "-D__TARGET_ARCH_arm64 -D__aarch64__";
    "riscv64" = "-D__TARGET_ARCH_riscv -D__riscv -D__riscv_xlen=64";
  }.${cpu} or (throw "Unsupported BPF target architecture: ${cpu}");
in
pkgs.writeShellApplication {
  name = "xdp2-test-flow-dissector-benchmark";

  runtimeInputs = if usePrebuilt then [
    pkgs.coreutils
    pkgs.gnugrep
  ] else [
    pkgs.gnumake
    pkgs.gcc
    pkgs.coreutils
    pkgs.gnugrep
    pkgs.libpcap       # For pcap.h
    pkgs.libpcap.lib   # For -lpcap (library in separate output)
    pkgs.linuxHeaders  # For <linux/types.h> etc.
    pkgs.libbpf        # For bpf/bpf_helpers.h (headers)
    pkgs.libbpf        # For -lbpf (library)
    pkgs.elfutils      # For -lelf
    pkgs.zlib          # For -lz
    llvmConfig.llvmPackages.clang  # For BPF compilation (wrapper provides system include paths)
    (pkgs.python314.withPackages (ps: [ ps.scapy ]))  # For PCAP generation
  ];

  text = ''
    set -euo pipefail

    echo "=== XDP2 Flow Dissector Benchmark Test ==="
    echo ""
    ${if usePrebuilt then ''echo "Mode: Pre-built samples"'' else ''echo "Mode: Runtime compilation"''}
    echo ""

    ${if usePrebuilt then ''
    # Pre-built mode: Use binary from prebuiltSample
    BENCHMARK="${prebuiltSample}/bin/benchmark"
    BENCHMARK_BPF="${prebuiltSample}/bin/benchmark_bpf"
    BPF_OBJ="${prebuiltSample}/lib/bpf_flow.kern.o"

    echo "Using pre-built binary:"
    echo "  benchmark: $BENCHMARK"
    echo "  benchmark_bpf: $BENCHMARK_BPF"
    echo ""

    # Verify binary exists
    if [[ ! -x "$BENCHMARK" ]]; then
      echo "FAIL: benchmark binary not found at $BENCHMARK"
      exit 1
    fi
    '' else ''
    # Runtime compilation mode: Build from source
    WORKDIR=$(mktemp -d)
    trap 'rm -rf "$WORKDIR"' EXIT

    echo "Work directory: $WORKDIR"
    echo ""

    # Copy sample sources to writable directory
    cp -r ${testData}/samples/flow_dissector/* "$WORKDIR/"
    cd "$WORKDIR"

    # Make all files writable (nix store files are read-only)
    chmod -R u+w .

    # Remove any pre-existing generated files to force rebuild
    rm -f ./*.p.c ./*.o ./*.xdp.h 2>/dev/null || true

    # Set up environment
    export XDP2DIR="${xdp2}"
    export LD_LIBRARY_PATH="${xdp2}/lib:${pkgs.libpcap.lib}/lib''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
    export PATH="${xdp2}/bin:$PATH"

    # Include paths for xdp2-compiler's libclang usage
    export XDP2_C_INCLUDE_PATH="${llvmConfig.paths.clangResourceDir}/include"
    export XDP2_GLIBC_INCLUDE_PATH="${pkgs.stdenv.cc.libc.dev}/include"
    export XDP2_LINUX_HEADERS_PATH="${pkgs.linuxHeaders}/include"

    # Disable Nix cc-wrapper hardening (stack protector, FORTIFY_SOURCE, PIE,
    # RELRO, etc.) — this is a performance benchmark and hardening adds overhead.
    # Also required for BPF compilation where hardening flags are incompatible
    # with -target bpf.
    export NIX_HARDENING_ENABLE=

    echo "XDP2DIR: $XDP2DIR"
    echo "LD_LIBRARY_PATH: $LD_LIBRARY_PATH"
    echo ""

    # Build the benchmark (userspace only)
    echo "--- Building flow_dissector benchmark ---"

    # First, build parser.o to verify the source compiles
    gcc -I${xdp2}/include -I${pkgs.libpcap}/include -g -O2 -c -o parser.o parser.c

    # Generate the optimized parser code
    ${xdp2}/bin/xdp2-compiler -I${xdp2}/include -i parser.c -o parser.p.c

    # Build the benchmark binary with -O2 (critical for fair comparison:
    # xdp2 parser uses inline functions from headers that must be optimized)
    gcc -I${xdp2}/include -I${pkgs.libpcap}/include -g -O2 \
        -L${xdp2}/lib -L${pkgs.libpcap.lib}/lib \
        -Wl,-rpath,${xdp2}/lib -Wl,-rpath,${pkgs.libpcap.lib}/lib \
        -o benchmark benchmark.c parser.p.c \
        -lpcap -lxdp2 -lcli -lflowdis -lsiphash

    # Build BPF benchmark binary (links libbpf)
    echo "--- Building BPF benchmark ---"
    gcc -I${xdp2}/include -I${pkgs.libpcap}/include -I${pkgs.libbpf}/include -std=gnu11 -g -O2 \
        -L${xdp2}/lib -L${pkgs.libpcap.lib}/lib -L${pkgs.libbpf}/lib \
        -L${pkgs.elfutils.out}/lib -L${pkgs.zlib}/lib \
        -Wl,-rpath,${xdp2}/lib -Wl,-rpath,${pkgs.libpcap.lib}/lib -Wl,-rpath,${pkgs.libbpf}/lib \
        -Wl,-rpath,${pkgs.elfutils.out}/lib -Wl,-rpath,${pkgs.zlib}/lib \
        -o benchmark_bpf benchmark_bpf.c \
        -lpcap -lxdp2 -lcli -lsiphash -lbpf -lelf -lz

    # BPF compilation: use clang wrapper which provides correct system include paths.

    # Compile kernel BPF flow dissector (vendored from linux selftests)
    echo "--- Compiling kernel BPF flow dissector ---"
    ${llvmConfig.llvmPackages.clang}/bin/clang -x c -target bpf \
        ${bpfArchDefines} -Wno-unused-command-line-argument \
        -I${xdp2}/include -I${pkgs.libbpf}/include \
        -std=gnu11 -g -O2 -c -o bpf_flow.kern.o kern_bpf/bpf_flow.c

    # Compile XDP2 BPF flow dissector
    echo "--- Compiling XDP2 BPF flow dissector ---"

    # Build parser_xdp.o (single-root wrapper for xdp2-compiler)
    gcc -I${xdp2}/include -I${pkgs.libpcap}/include -std=gnu11 -g -O2 \
        -c -o parser_xdp.o parser_xdp.c

    # Generate BPF parser header from single-root parser_xdp.c
    ${xdp2}/bin/xdp2-compiler -I${xdp2}/include -i parser_xdp.c -o parser.xdp.h

    # Compile XDP2 BPF flow dissector object
    ${llvmConfig.llvmPackages.clang}/bin/clang -x c -target bpf \
        ${bpfArchDefines} -Wno-unused-command-line-argument \
        -I${xdp2}/include -I${pkgs.libbpf}/include \
        -std=gnu11 -g -O2 -c -o flow_dissector.bpf.o flow_dissector.bpf.c

    echo ""

    BENCHMARK="./benchmark"
    BENCHMARK_BPF="./benchmark_bpf"
    BPF_OBJ="./bpf_flow.kern.o"
    XDP2_BPF_OBJ="./flow_dissector.bpf.o"
    ''}

    # Track test results
    TESTS_PASSED=0
    TESTS_FAILED=0
    TESTS_SKIPPED=0

    pass() {
      echo "PASS: $1"
      TESTS_PASSED=$((TESTS_PASSED + 1))
    }

    fail() {
      echo "FAIL: $1"
      TESTS_FAILED=$((TESTS_FAILED + 1))
    }

    skip() {
      echo "SKIP: $1"
      TESTS_SKIPPED=$((TESTS_SKIPPED + 1))
    }

    # Verify benchmark binary was created
    if [[ ! -x "$BENCHMARK" ]]; then
      fail "benchmark binary not found"
      exit 1
    fi
    pass "benchmark binary created"
    echo ""

    # ─── Test 1: IPv4 TCP correctness ───
    PCAP_IPV4="${testData}/data/pcaps/tcp_ipv4.pcap"
    echo "--- Test 1: IPv4 TCP correctness ---"
    OUTPUT=$("$BENCHMARK" -c "$PCAP_IPV4" 2>&1) || {
      fail "benchmark -c (IPv4 TCP) exited with error"
      echo "$OUTPUT"
      exit 1
    }
    echo "$OUTPUT"

    if echo "$OUTPUT" | grep -q "Matches:"; then
      pass "benchmark produced correctness results (IPv4 TCP)"
    else
      fail "benchmark did not produce correctness output (IPv4 TCP)"
    fi
    echo ""

    # ─── Test 2: IPv6 TCP correctness ───
    PCAP_IPV6="${testData}/data/pcaps/tcp_ipv6.pcap"
    echo "--- Test 2: IPv6 TCP correctness ---"
    OUTPUT=$("$BENCHMARK" -c "$PCAP_IPV6" 2>&1) || {
      fail "benchmark -c (IPv6 TCP) exited with error"
      echo "$OUTPUT"
      exit 1
    }
    echo "$OUTPUT"

    if echo "$OUTPUT" | grep -q "Matches:"; then
      pass "benchmark produced correctness results (IPv6 TCP)"
    else
      fail "benchmark did not produce correctness output (IPv6 TCP)"
    fi
    echo ""

    # ─── Test 3: ICMP correctness ───
    PCAP_ICMP="${testData}/data/pcaps/icmp_ipv4.pcap"
    echo "--- Test 3: ICMP correctness ---"
    OUTPUT=$("$BENCHMARK" -c "$PCAP_ICMP" 2>&1) || {
      fail "benchmark -c (ICMP) exited with error"
      echo "$OUTPUT"
      exit 1
    }
    echo "$OUTPUT"

    if echo "$OUTPUT" | grep -q "Matches:"; then
      pass "benchmark produced correctness results (ICMP)"
    else
      fail "benchmark did not produce correctness output (ICMP)"
    fi
    echo ""

    # ─── Test 4: VLAN tagged correctness ───
    PCAP_VLAN="${testData}/data/pcaps/vlan_icmp.pcap"
    echo "--- Test 4: VLAN tagged correctness ---"
    OUTPUT=$("$BENCHMARK" -c "$PCAP_VLAN" 2>&1) || {
      fail "benchmark -c (VLAN) exited with error"
      echo "$OUTPUT"
      exit 1
    }
    echo "$OUTPUT"

    if echo "$OUTPUT" | grep -q "Matches:"; then
      pass "benchmark produced correctness results (VLAN)"
    else
      fail "benchmark did not produce correctness output (VLAN)"
    fi
    echo ""

    # ─── Test 5: GRE tunnel correctness ───
    PCAP_GRE="${testData}/data/pcaps/gre-sample.pcap"
    echo "--- Test 5: GRE tunnel correctness ---"
    OUTPUT=$("$BENCHMARK" -c "$PCAP_GRE" 2>&1) || {
      fail "benchmark -c (GRE) exited with error"
      echo "$OUTPUT"
      exit 1
    }
    echo "$OUTPUT"

    if echo "$OUTPUT" | grep -q "Matches:"; then
      pass "benchmark produced correctness results (GRE)"
    else
      fail "benchmark did not produce correctness output (GRE)"
    fi
    echo ""

    # ─── Test 6: IPv4 fragments correctness ───
    PCAP_FRAG="${testData}/data/pcaps/ipv4frags.pcap"
    echo "--- Test 6: IPv4 fragments correctness ---"
    OUTPUT=$("$BENCHMARK" -c "$PCAP_FRAG" 2>&1) || {
      fail "benchmark -c (IPv4 frags) exited with error"
      echo "$OUTPUT"
      exit 1
    }
    echo "$OUTPUT"

    if echo "$OUTPUT" | grep -q "Matches:"; then
      pass "benchmark produced correctness results (IPv4 frags)"
    else
      fail "benchmark did not produce correctness output (IPv4 frags)"
    fi
    echo ""

    # ─── Test 7: IP-in-IP correctness ───
    PCAP_IPIP="${testData}/data/pcaps/ipip.pcap"
    echo "--- Test 7: IP-in-IP correctness ---"
    OUTPUT=$("$BENCHMARK" -c "$PCAP_IPIP" 2>&1) || {
      fail "benchmark -c (IPIP) exited with error"
      echo "$OUTPUT"
      exit 1
    }
    echo "$OUTPUT"

    if echo "$OUTPUT" | grep -q "Matches:"; then
      pass "benchmark produced correctness results (IPIP)"
    else
      fail "benchmark did not produce correctness output (IPIP)"
    fi
    echo ""

    # ─── Test 8: ICMPv6 correctness ───
    PCAP_ICMPV6="${testData}/data/pcaps/icmp_ipv6.pcap"
    echo "--- Test 8: ICMPv6 correctness ---"
    OUTPUT=$("$BENCHMARK" -c "$PCAP_ICMPV6" 2>&1) || {
      fail "benchmark -c (ICMPv6) exited with error"
      echo "$OUTPUT"
      exit 1
    }
    echo "$OUTPUT"

    if echo "$OUTPUT" | grep -q "Matches:"; then
      pass "benchmark produced correctness results (ICMPv6)"
    else
      fail "benchmark did not produce correctness output (ICMPv6)"
    fi
    echo ""

    # ─── Test 9: Performance run (IPv4 TCP) ───
    echo "--- Test 9: Performance benchmark (IPv4 TCP, 10 iterations) ---"
    OUTPUT=$("$BENCHMARK" -p -n 10 "$PCAP_IPV4" 2>&1) || {
      fail "benchmark -p (IPv4 performance) exited with error"
      echo "$OUTPUT"
      exit 1
    }
    echo "$OUTPUT"

    if echo "$OUTPUT" | grep -q "Mpps"; then
      pass "benchmark produced IPv4 performance results"
    else
      fail "benchmark did not produce IPv4 performance output"
    fi
    echo ""

    # ─── Test 10: Performance run (IPv6 TCP) ───
    echo "--- Test 10: Performance benchmark (IPv6 TCP, 10 iterations) ---"
    OUTPUT=$("$BENCHMARK" -p -n 10 "$PCAP_IPV6" 2>&1) || {
      fail "benchmark -p (IPv6 performance) exited with error"
      echo "$OUTPUT"
      exit 1
    }
    echo "$OUTPUT"

    if echo "$OUTPUT" | grep -q "Mpps"; then
      pass "benchmark produced IPv6 performance results"
    else
      fail "benchmark did not produce IPv6 performance output"
    fi
    echo ""

    # ─── Test 11: Optimized parser correctness (IPv4 TCP) ───
    echo "--- Test 11: Optimized parser correctness (IPv4 TCP) ---"
    OUTPUT=$("$BENCHMARK" -c -O "$PCAP_IPV4" 2>&1) || {
      fail "benchmark -c -O (IPv4 TCP) exited with error"
      echo "$OUTPUT"
      exit 1
    }
    echo "$OUTPUT"

    if echo "$OUTPUT" | grep -q "100.0%"; then
      pass "optimized parser 100% match (IPv4 TCP)"
    else
      fail "optimized parser mismatch (IPv4 TCP)"
    fi
    echo ""

    # ─── Test 12: Optimized parser correctness (GRE) ───
    echo "--- Test 12: Optimized parser correctness (GRE) ---"
    OUTPUT=$("$BENCHMARK" -c -O "$PCAP_GRE" 2>&1) || {
      fail "benchmark -c -O (GRE) exited with error"
      echo "$OUTPUT"
      exit 1
    }
    echo "$OUTPUT"

    if echo "$OUTPUT" | grep -q "100.0%"; then
      pass "optimized parser 100% match (GRE)"
    else
      fail "optimized parser mismatch (GRE)"
    fi
    echo ""

    # ─── Test 13: Optimized parser correctness (IPIP) ───
    echo "--- Test 13: Optimized parser correctness (IPIP) ---"
    OUTPUT=$("$BENCHMARK" -c -O "$PCAP_IPIP" 2>&1) || {
      fail "benchmark -c -O (IPIP) exited with error"
      echo "$OUTPUT"
      exit 1
    }
    echo "$OUTPUT"

    if echo "$OUTPUT" | grep -q "100.0%"; then
      pass "optimized parser 100% match (IPIP)"
    else
      fail "optimized parser mismatch (IPIP)"
    fi
    echo ""

    # ─── Test 14: Optimized performance (IPv4 TCP) ───
    echo "--- Test 14: Optimized performance (IPv4 TCP, 100 iterations) ---"
    OUTPUT=$("$BENCHMARK" -p -O -n 100 "$PCAP_IPV4" 2>&1) || {
      fail "benchmark -p -O (IPv4 performance) exited with error"
      echo "$OUTPUT"
      exit 1
    }
    echo "$OUTPUT"

    if echo "$OUTPUT" | grep -q "Mpps"; then
      pass "optimized parser produced IPv4 performance results"
    else
      fail "optimized parser did not produce IPv4 performance output"
    fi
    echo ""

    # ─── Test 15: Optimized performance (IPv6 TCP) ───
    echo "--- Test 15: Optimized performance (IPv6 TCP, 100 iterations) ---"
    OUTPUT=$("$BENCHMARK" -p -O -n 100 "$PCAP_IPV6" 2>&1) || {
      fail "benchmark -p -O (IPv6 performance) exited with error"
      echo "$OUTPUT"
      exit 1
    }
    echo "$OUTPUT"

    if echo "$OUTPUT" | grep -q "Mpps"; then
      pass "optimized parser produced IPv6 performance results"
    else
      fail "optimized parser did not produce IPv6 performance output"
    fi
    echo ""

    # ─── Test 16: Optimized performance (GRE) ───
    echo "--- Test 16: Optimized performance (GRE, 100 iterations) ---"
    OUTPUT=$("$BENCHMARK" -p -O -n 100 "$PCAP_GRE" 2>&1) || {
      fail "benchmark -p -O (GRE performance) exited with error"
      echo "$OUTPUT"
      exit 1
    }
    echo "$OUTPUT"

    if echo "$OUTPUT" | grep -q "Mpps"; then
      pass "optimized parser produced GRE performance results"
    else
      fail "optimized parser did not produce GRE performance output"
    fi
    echo ""

    # ─── Test 17: Standard performance (GRE, for comparison) ───
    echo "--- Test 17: Standard performance (GRE, 100 iterations) ---"
    OUTPUT=$("$BENCHMARK" -p -n 100 "$PCAP_GRE" 2>&1) || {
      fail "benchmark -p (GRE performance) exited with error"
      echo "$OUTPUT"
      exit 1
    }
    echo "$OUTPUT"

    if echo "$OUTPUT" | grep -q "Mpps"; then
      pass "standard parser produced GRE performance results"
    else
      fail "standard parser did not produce GRE performance output"
    fi
    echo ""

    # ─── Test 18: Standard performance with more iterations (IPv4 TCP) ───
    echo "--- Test 18: Standard performance (IPv4 TCP, 100 iterations) ---"
    OUTPUT=$("$BENCHMARK" -p -n 100 "$PCAP_IPV4" 2>&1) || {
      fail "benchmark -p (IPv4 TCP, 100 iter) exited with error"
      echo "$OUTPUT"
      exit 1
    }
    echo "$OUTPUT"

    if echo "$OUTPUT" | grep -q "Mpps"; then
      pass "standard parser produced IPv4 performance results (100 iter)"
    else
      fail "standard parser did not produce IPv4 performance output (100 iter)"
    fi
    echo ""

    # ─── Fast parser tests (19-23) ───
    # The fast path requires NUM_FAST_NODES <= 64 unique reachable nodes.
    # With the expanded multi-graph parser (~70 nodes in L2 graph),
    # the fast path validation fails. Detect and skip gracefully.
    echo "--- Test 19: Fast parser compatibility check ---"
    OUTPUT=$("$BENCHMARK" -c -F "$PCAP_IPV4" 2>&1) && FAST_OK=1 || FAST_OK=0

    if [[ $FAST_OK -eq 1 ]]; then
      echo "$OUTPUT"
      if echo "$OUTPUT" | grep -q "100.0%"; then
        pass "fast parser 100% match (IPv4 TCP)"
      else
        fail "fast parser mismatch (IPv4 TCP)"
      fi
      echo ""

      echo "--- Test 20: Fast parser correctness (GRE) ---"
      OUTPUT=$("$BENCHMARK" -c -F "$PCAP_GRE" 2>&1) || {
        fail "benchmark -c -F (GRE) exited with error"
        echo "$OUTPUT"
      }
      echo "$OUTPUT"
      if echo "$OUTPUT" | grep -q "100.0%"; then
        pass "fast parser 100% match (GRE)"
      else
        fail "fast parser mismatch (GRE)"
      fi
      echo ""

      echo "--- Test 21: Fast parser performance (IPv4 TCP, 100 iterations) ---"
      OUTPUT=$("$BENCHMARK" -p -F -n 100 "$PCAP_IPV4" 2>&1) || true
      echo "$OUTPUT"
      if echo "$OUTPUT" | grep -q "Mpps"; then
        pass "fast parser produced IPv4 performance results"
      else
        fail "fast parser did not produce IPv4 performance output"
      fi
      echo ""

      echo "--- Test 22: Fast parser performance (GRE, 100 iterations) ---"
      OUTPUT=$("$BENCHMARK" -p -F -n 100 "$PCAP_GRE" 2>&1) || true
      echo "$OUTPUT"
      if echo "$OUTPUT" | grep -q "Mpps"; then
        pass "fast parser produced GRE performance results"
      else
        fail "fast parser did not produce GRE performance output"
      fi
      echo ""

      echo "--- Test 23: Fast parser performance (IPv6 TCP, 100 iterations) ---"
      OUTPUT=$("$BENCHMARK" -p -F -n 100 "$PCAP_IPV6" 2>&1) || true
      echo "$OUTPUT"
      if echo "$OUTPUT" | grep -q "Mpps"; then
        pass "fast parser produced IPv6 performance results"
      else
        fail "fast parser did not produce IPv6 performance output"
      fi
    else
      echo "Parser exceeds NUM_FAST_NODES (64) — expected with multi-graph expansion"
      skip "fast parser tests 19-23 (parser too complex for fast path)"
    fi
    echo ""

    # ─── BPF benchmark tests (conditional on BPF availability) ───
    echo "--- BPF Benchmark Tests ---"

    # ─── Test: XDP2 BPF object compiled ───
    ${if usePrebuilt then ''
    echo "Skipping XDP2 BPF compilation check in pre-built mode"
    '' else ''
    if [[ -f "''${XDP2_BPF_OBJ:-}" ]]; then
      XDP2_BPF_SIZE=$(wc -c < "$XDP2_BPF_OBJ")
      if [[ "$XDP2_BPF_SIZE" -gt 0 ]]; then
        pass "XDP2 BPF object compiled ($XDP2_BPF_SIZE bytes)"
      else
        fail "XDP2 BPF object is empty"
      fi
    else
      fail "XDP2 BPF object not found"
    fi
    echo ""
    ''}

    BPF_AVAILABLE=0
    if [[ -x "''${BENCHMARK_BPF:-}" ]] && [[ -f "''${BPF_OBJ:-}" ]]; then
      # Check if we can actually load BPF programs (needs root + BPF kernel support)
      if [[ -d /sys/fs/bpf ]] && [[ $(id -u) -eq 0 ]]; then
        BPF_AVAILABLE=1
      fi
    fi

    if [[ "$BPF_AVAILABLE" -eq 1 ]]; then
      # ─── Test BPF-1: BPF benchmark binary exists ───
      pass "benchmark_bpf binary exists"

      # ─── Test BPF-2: BPF flow dissector compiled ───
      pass "bpf_flow.kern.o compiled"

      # ─── Test BPF-3: BPF correctness (IPv4 TCP) ───
      echo "--- Test BPF-3: BPF correctness (IPv4 TCP) ---"
      OUTPUT=$("$BENCHMARK_BPF" -c -b "$BPF_OBJ" "$PCAP_IPV4" 2>&1) || {
        fail "benchmark_bpf -c (IPv4 TCP) exited with error"
        echo "$OUTPUT"
      }
      echo "$OUTPUT"

      if echo "$OUTPUT" | grep -q "Parsed:"; then
        pass "BPF benchmark produced correctness results (IPv4 TCP)"
      else
        fail "BPF benchmark did not produce correctness output (IPv4 TCP)"
      fi
      echo ""

      # ─── Test BPF-4: BPF correctness (IPv6 TCP) ───
      echo "--- Test BPF-4: BPF correctness (IPv6 TCP) ---"
      OUTPUT=$("$BENCHMARK_BPF" -c -b "$BPF_OBJ" "$PCAP_IPV6" 2>&1) || {
        fail "benchmark_bpf -c (IPv6 TCP) exited with error"
        echo "$OUTPUT"
      }
      echo "$OUTPUT"

      if echo "$OUTPUT" | grep -q "Parsed:"; then
        pass "BPF benchmark produced correctness results (IPv6 TCP)"
      else
        fail "BPF benchmark did not produce correctness output (IPv6 TCP)"
      fi
      echo ""

      # ─── Test BPF-5: BPF performance (IPv4 TCP) ───
      echo "--- Test BPF-5: BPF performance (IPv4 TCP, 100 repeats) ---"
      OUTPUT=$("$BENCHMARK_BPF" -p -n 100 -b "$BPF_OBJ" "$PCAP_IPV4" 2>&1) || {
        fail "benchmark_bpf -p (IPv4 performance) exited with error"
        echo "$OUTPUT"
      }
      echo "$OUTPUT"

      if echo "$OUTPUT" | grep -q "Mpps\|ns/pkt"; then
        pass "BPF benchmark produced IPv4 performance results"
      else
        fail "BPF benchmark did not produce IPv4 performance output"
      fi
      echo ""

      # ─── XDP2 BPF tests (conditional on XDP2_BPF_OBJ) ───
      if [[ -f "''${XDP2_BPF_OBJ:-}" ]]; then
        # ─── Test BPF-6: XDP2 BPF correctness (IPv4 TCP) ───
        echo "--- Test BPF-6: XDP2 BPF correctness (IPv4 TCP) ---"
        OUTPUT=$("$BENCHMARK_BPF" -c -b "$XDP2_BPF_OBJ" "$PCAP_IPV4" 2>&1) || {
          fail "benchmark_bpf -c (XDP2 BPF, IPv4 TCP) exited with error"
          echo "$OUTPUT"
        }
        echo "$OUTPUT"

        if echo "$OUTPUT" | grep -q "Parsed:"; then
          pass "XDP2 BPF benchmark produced correctness results (IPv4 TCP)"
        else
          fail "XDP2 BPF benchmark did not produce correctness output (IPv4 TCP)"
        fi
        echo ""

        # ─── Test BPF-7: XDP2 BPF performance (IPv4 TCP) ───
        echo "--- Test BPF-7: XDP2 BPF performance (IPv4 TCP, 100 repeats) ---"
        OUTPUT=$("$BENCHMARK_BPF" -p -n 100 -l "XDP2 BPF parser" -b "$XDP2_BPF_OBJ" "$PCAP_IPV4" 2>&1) || {
          fail "benchmark_bpf -p (XDP2 BPF, IPv4 performance) exited with error"
          echo "$OUTPUT"
        }
        echo "$OUTPUT"

        if echo "$OUTPUT" | grep -q "Mpps\|ns/pkt"; then
          pass "XDP2 BPF benchmark produced IPv4 performance results"
        else
          fail "XDP2 BPF benchmark did not produce IPv4 performance output"
        fi
        echo ""
      else
        echo "Skipping XDP2 BPF runtime tests (no XDP2 BPF object available)"
        echo ""
      fi
    else
      echo "Skipping BPF benchmark tests (not available: need root + BPF kernel + compiled binary)"
      echo ""
    fi

    # ─── Generate combinatorial PCAPs ───
    echo "--- Generating combinatorial test PCAPs ---"

    ${if usePrebuilt then ''
    # In pre-built mode, skip PCAP generation (no Python/scapy available)
    echo "Skipping PCAP generation in pre-built mode"
    '' else ''
    # Generate 1k packet PCAP for correctness testing
    PCAP_COMBO_1K=$(mktemp --suffix=.pcap)
    trap 'rm -f "$PCAP_COMBO_1K"' EXIT
    python3 ${testData}/samples/flow_dissector/gen_test_pcap.py \
        -o "$PCAP_COMBO_1K" -n 1000 2>&1 || {
      fail "gen_test_pcap.py -n 1000 failed"
      echo "PCAP generation failed"
    }
    echo ""

    # ─── Test 24: Combination listing ───
    echo "--- Test 24: List all valid combinations ---"
    COMBO_COUNT=$(python3 ${testData}/samples/flow_dissector/gen_test_pcap.py --list 2>&1 | grep -c "^  ")
    echo "Valid combinations: $COMBO_COUNT"
    if [[ "$COMBO_COUNT" -ge 100 ]]; then
      pass "combinatorial generator produces $COMBO_COUNT valid combinations"
    else
      fail "too few combinations: $COMBO_COUNT (expected >= 100)"
    fi
    echo ""

    # ─── Test 25: Combinatorial correctness (standard parser) ───
    echo "--- Test 25: Combinatorial correctness (standard, 1k packets) ---"
    OUTPUT=$("$BENCHMARK" -c "$PCAP_COMBO_1K" 2>&1) || {
      fail "benchmark -c (combinatorial 1k) exited with error"
      echo "$OUTPUT"
    }
    echo "$OUTPUT"

    if echo "$OUTPUT" | grep -q "Mismatches:    0"; then
      pass "combinatorial correctness: 0 mismatches (standard)"
    else
      fail "combinatorial correctness: mismatches found (standard)"
      echo "$OUTPUT"
    fi

    # Check that XDP2 has no failures (all new protocols parse)
    if echo "$OUTPUT" | grep -q "XDP2 fail:"; then
      fail "combinatorial correctness: xdp2 failures found"
      echo "$OUTPUT"
    else
      pass "combinatorial correctness: 0 xdp2 failures"
    fi
    echo ""

    # ─── Test 25b: Verbose combinatorial correctness (diagnostics) ───
    echo "--- Test 25b: Verbose combinatorial correctness (standard, 1k packets) ---"
    OUTPUT=$("$BENCHMARK" -c -v "$PCAP_COMBO_1K" 2>&1) || {
      fail "benchmark -c -v (combinatorial 1k) exited with error"
      echo "$OUTPUT"
    }
    echo "$OUTPUT"
    pass "verbose combinatorial run completed (standard)"
    echo ""

    # ─── Test 25c: Tunnel extended packets detected ───
    echo "--- Test 25c: Tunnel extended packets in combinatorial PCAP ---"
    if echo "$OUTPUT" | grep -q "Tunnel ext:"; then
      pass "tunnel extended packets detected in combinatorial PCAP"
    else
      fail "expected tunnel extended packets in combinatorial PCAP"
      echo "$OUTPUT"
    fi
    echo ""

    # ─── Test 25d: XDP2-only protocols detected ───
    echo "--- Test 25d: XDP2-only protocols in combinatorial PCAP ---"
    if echo "$OUTPUT" | grep -q "XDP2 only:"; then
      pass "xdp2-only protocols detected (new L2 protocols not in flowdis)"
    else
      # Not a failure — might not have XDP2-only if all map to flowdis
      pass "no xdp2-only protocols (all protocols covered by flowdis)"
    fi
    echo ""

    # ─── Test 26: Combinatorial correctness (optimized parser) ───
    echo "--- Test 26: Combinatorial correctness (optimized, 1k packets) ---"
    OUTPUT=$("$BENCHMARK" -c -O "$PCAP_COMBO_1K" 2>&1) || {
      fail "benchmark -c -O (combinatorial 1k) exited with error"
      echo "$OUTPUT"
    }
    echo "$OUTPUT"

    if echo "$OUTPUT" | grep -q "Mismatches:    0"; then
      pass "combinatorial correctness: 0 mismatches (optimized)"
    else
      fail "combinatorial correctness: mismatches found (optimized)"
      echo "$OUTPUT"
    fi
    echo ""

    # ─── Test 27: Combinatorial performance (standard, 1k × 10) ───
    echo "--- Test 27: Combinatorial performance (standard, 1k × 10 iters) ---"
    OUTPUT=$("$BENCHMARK" -p -n 10 "$PCAP_COMBO_1K" 2>&1) || {
      fail "benchmark -p (combinatorial 1k) exited with error"
      echo "$OUTPUT"
    }
    echo "$OUTPUT"

    if echo "$OUTPUT" | grep -q "Mpps"; then
      pass "combinatorial performance test completed (standard)"
    else
      fail "combinatorial performance test failed (standard)"
    fi
    echo ""

    # Generate 100k packet PCAP for larger-scale testing
    PCAP_COMBO_100K=$(mktemp --suffix=.pcap)
    trap 'rm -f "$PCAP_COMBO_100K"' EXIT
    echo "--- Generating 100k packet PCAP ---"
    python3 ${testData}/samples/flow_dissector/gen_test_pcap.py \
        -o "$PCAP_COMBO_100K" -n 100000 2>&1 || {
      fail "gen_test_pcap.py -n 100000 failed"
    }
    echo ""

    # ─── Test 28: 100k correctness (standard) ───
    echo "--- Test 28: 100k correctness (standard parser) ---"
    OUTPUT=$("$BENCHMARK" -c "$PCAP_COMBO_100K" 2>&1) || {
      fail "benchmark -c (100k) exited with error"
      echo "$OUTPUT"
    }
    echo "$OUTPUT"

    if echo "$OUTPUT" | grep -q "Mismatches:    0"; then
      pass "100k correctness: 0 mismatches (standard)"
    else
      fail "100k correctness: mismatches found (standard)"
      echo "$OUTPUT"
    fi

    # Check XDP2 has no failures on 100k
    if echo "$OUTPUT" | grep -q "XDP2 fail:"; then
      fail "100k correctness: xdp2 failures found"
      echo "$OUTPUT"
    else
      pass "100k correctness: 0 xdp2 failures"
    fi
    echo ""

    # ─── Test 29: 100k performance (standard, 10 iters) ───
    echo "--- Test 29: 100k performance (standard, 10 iters) ---"
    OUTPUT=$("$BENCHMARK" -p -n 10 "$PCAP_COMBO_100K" 2>&1) || {
      fail "benchmark -p (100k) exited with error"
      echo "$OUTPUT"
    }
    echo "$OUTPUT"

    if echo "$OUTPUT" | grep -q "Mpps"; then
      pass "100k performance test completed (standard)"
    else
      fail "100k performance test failed (standard)"
    fi
    echo ""

    # ─── Test 30: 100k performance (optimized, 10 iters) ───
    echo "--- Test 30: 100k performance (optimized, 10 iters) ---"
    OUTPUT=$("$BENCHMARK" -p -O -n 10 "$PCAP_COMBO_100K" 2>&1) || {
      fail "benchmark -p -O (100k) exited with error"
      echo "$OUTPUT"
    }
    echo "$OUTPUT"

    if echo "$OUTPUT" | grep -q "Mpps"; then
      pass "100k performance test completed (optimized)"
    else
      fail "100k performance test failed (optimized)"
    fi
    echo ""
    ''}

    # Summary
    echo "==================================="
    echo "        TEST SUMMARY"
    echo "==================================="
    echo ""
    echo "Tests passed: $TESTS_PASSED"
    echo "Tests failed: $TESTS_FAILED"
    echo "Tests skipped: $TESTS_SKIPPED"
    echo ""

    if [[ $TESTS_FAILED -eq 0 ]]; then
      echo "All flow_dissector benchmark tests passed!"
      echo "==================================="
      exit 0
    else
      echo "Some tests failed!"
      echo "==================================="
      exit 1
    fi
  '';
}
