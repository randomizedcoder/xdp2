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
    pkgs.libbpf        # For bpf/bpf_helpers.h
    llvmConfig.llvmPackages.clang-unwrapped  # For BPF compilation
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

    echo "Using pre-built binary:"
    echo "  benchmark: $BENCHMARK"
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

    echo ""

    BENCHMARK="./benchmark"
    ''}

    # Track test results
    TESTS_PASSED=0
    TESTS_FAILED=0

    pass() {
      echo "PASS: $1"
      TESTS_PASSED=$((TESTS_PASSED + 1))
    }

    fail() {
      echo "FAIL: $1"
      TESTS_FAILED=$((TESTS_FAILED + 1))
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

    # ─── Test 19: Fast parser correctness (IPv4 TCP) ───
    echo "--- Test 19: Fast parser correctness (IPv4 TCP) ---"
    OUTPUT=$("$BENCHMARK" -c -F "$PCAP_IPV4" 2>&1) || {
      fail "benchmark -c -F (IPv4 TCP) exited with error"
      echo "$OUTPUT"
      exit 1
    }
    echo "$OUTPUT"

    if echo "$OUTPUT" | grep -q "100.0%"; then
      pass "fast parser 100% match (IPv4 TCP)"
    else
      fail "fast parser mismatch (IPv4 TCP)"
    fi
    echo ""

    # ─── Test 20: Fast parser correctness (GRE) ───
    echo "--- Test 20: Fast parser correctness (GRE) ---"
    OUTPUT=$("$BENCHMARK" -c -F "$PCAP_GRE" 2>&1) || {
      fail "benchmark -c -F (GRE) exited with error"
      echo "$OUTPUT"
      exit 1
    }
    echo "$OUTPUT"

    if echo "$OUTPUT" | grep -q "100.0%"; then
      pass "fast parser 100% match (GRE)"
    else
      fail "fast parser mismatch (GRE)"
    fi
    echo ""

    # ─── Test 21: Fast parser performance (IPv4 TCP) ───
    echo "--- Test 21: Fast parser performance (IPv4 TCP, 100 iterations) ---"
    OUTPUT=$("$BENCHMARK" -p -F -n 100 "$PCAP_IPV4" 2>&1) || {
      fail "benchmark -p -F (IPv4 performance) exited with error"
      echo "$OUTPUT"
      exit 1
    }
    echo "$OUTPUT"

    if echo "$OUTPUT" | grep -q "Mpps"; then
      pass "fast parser produced IPv4 performance results"
    else
      fail "fast parser did not produce IPv4 performance output"
    fi
    echo ""

    # ─── Test 22: Fast parser performance (GRE) ───
    echo "--- Test 22: Fast parser performance (GRE, 100 iterations) ---"
    OUTPUT=$("$BENCHMARK" -p -F -n 100 "$PCAP_GRE" 2>&1) || {
      fail "benchmark -p -F (GRE performance) exited with error"
      echo "$OUTPUT"
      exit 1
    }
    echo "$OUTPUT"

    if echo "$OUTPUT" | grep -q "Mpps"; then
      pass "fast parser produced GRE performance results"
    else
      fail "fast parser did not produce GRE performance output"
    fi
    echo ""

    # ─── Test 23: Fast parser performance (IPv6 TCP) ───
    echo "--- Test 23: Fast parser performance (IPv6 TCP, 100 iterations) ---"
    OUTPUT=$("$BENCHMARK" -p -F -n 100 "$PCAP_IPV6" 2>&1) || {
      fail "benchmark -p -F (IPv6 TCP performance) exited with error"
      echo "$OUTPUT"
      exit 1
    }
    echo "$OUTPUT"

    if echo "$OUTPUT" | grep -q "Mpps"; then
      pass "fast parser produced IPv6 performance results"
    else
      fail "fast parser did not produce IPv6 performance output"
    fi
    echo ""

    # Summary
    echo "==================================="
    echo "        TEST SUMMARY"
    echo "==================================="
    echo ""
    echo "Tests passed: $TESTS_PASSED"
    echo "Tests failed: $TESTS_FAILED"
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
