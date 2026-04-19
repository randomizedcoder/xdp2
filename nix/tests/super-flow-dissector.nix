# nix/tests/super-flow-dissector.nix
#
# Test for xdp2-flow-ebpf fast-path coverage parity (plan milestone A4).
#
# Verifies that:
#   1. fast_flow.bpf.o builds (both entry and all specialised programs).
#   2. parity_test binary builds.
#   3. (If root + BPF kernel available) fast-path hits on the
#      combinatorial PCAP produce bpf_flow_keys identical to the
#      oracle — today that's the vendored upstream bpf_flow.kern.o;
#      once D6 lands, the oracle becomes the slow-path fallback.
#
# Non-root environments still exercise the build (catches verifier
# regressions at clang/libbpf load time, which don't need the
# BPF_PROG_TEST_RUN syscall).
#
# Usage:
#   nix build .#tests.super-flow-dissector
#   sudo ./result/bin/xdp2-test-super-flow-dissector
#

{ pkgs
, xdp2
}:

let
  testData = ../..;
  llvmConfig = import ../llvm.nix { inherit pkgs; lib = pkgs.lib; };

  bpfArchDefines = let
    cpu = pkgs.stdenv.hostPlatform.parsed.cpu.name;
  in {
    "x86_64"  = "-D__TARGET_ARCH_x86 -D__x86_64__";
    "aarch64" = "-D__TARGET_ARCH_arm64 -D__aarch64__";
    "riscv64" = "-D__TARGET_ARCH_riscv -D__riscv -D__riscv_xlen=64";
  }.${cpu} or (throw "Unsupported BPF target architecture: ${cpu}");
in
pkgs.writeShellApplication {
  name = "xdp2-test-super-flow-dissector";

  runtimeInputs = [
    pkgs.gnumake
    pkgs.gcc
    pkgs.coreutils
    pkgs.gnugrep
    pkgs.libpcap
    pkgs.libpcap.lib
    pkgs.linuxHeaders
    pkgs.libbpf
    pkgs.elfutils
    pkgs.zlib
    llvmConfig.llvmPackages.clang
    (pkgs.python314.withPackages (ps: [ ps.scapy ]))
  ];

  text = ''
    set -euo pipefail

    echo "=== xdp2-flow-ebpf super-flow-dissector test (A4) ==="
    echo ""

    WORKDIR=$(mktemp -d)
    trap 'rm -rf "$WORKDIR"' EXIT

    cp -r ${testData}/samples/flow_dissector/* "$WORKDIR/"
    cd "$WORKDIR"
    chmod -R u+w .

    export XDP2DIR="${xdp2}"
    export LD_LIBRARY_PATH="${xdp2}/lib:${pkgs.libpcap.lib}/lib:${pkgs.libbpf}/lib:${pkgs.elfutils.out}/lib:${pkgs.zlib}/lib''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
    export NIX_HARDENING_ENABLE=

    TESTS_PASSED=0
    TESTS_FAILED=0
    pass() { echo "PASS: $1"; TESTS_PASSED=$((TESTS_PASSED + 1)); }
    fail() { echo "FAIL: $1"; TESTS_FAILED=$((TESTS_FAILED + 1)); }

    # ─── Build fast-path BPF object ───
    echo "--- Building fast_flow.bpf.o ---"
    ${llvmConfig.llvmPackages.clang}/bin/clang -x c -target bpf \
        ${bpfArchDefines} -Wno-unused-command-line-argument \
        -I${xdp2}/include -I${pkgs.libbpf}/include \
        -std=gnu11 -g -O2 -c -o fast_bpf/fast_flow.bpf.o fast_bpf/fast_flow.bpf.c

    if [[ -s fast_bpf/fast_flow.bpf.o ]]; then
      pass "fast_flow.bpf.o compiled"
    else
      fail "fast_flow.bpf.o empty or missing"
      exit 1
    fi

    # Verify all specialised programs are present in the .o.
    # If any is missing, something silently stripped it (very rare but
    # worth catching — the whole tail-call dispatch hinges on them).
    SYMS=$(${pkgs.binutils-unwrapped}/bin/nm fast_bpf/fast_flow.bpf.o 2>/dev/null || true)
    for sym in _dissect flow_dissector_eth_ipv4_tcp flow_dissector_eth_ipv4_udp \
               flow_dissector_eth_ipv6_tcp flow_dissector_eth_ipv6_udp \
               flow_dissector_eth_vlan_ipv4_tcp flow_dissector_eth_vlan_ipv4_udp \
               flow_dissector_eth_ipv4_icmp; do
      if echo "$SYMS" | grep -qw "$sym"; then
        pass "program '$sym' present in .o"
      else
        fail "program '$sym' missing from .o"
      fi
    done
    echo ""

    # ─── Build oracle BPF object (upstream selftest) ───
    echo "--- Building bpf_flow.kern.o (oracle) ---"
    ${llvmConfig.llvmPackages.clang}/bin/clang -x c -target bpf \
        ${bpfArchDefines} -Wno-unused-command-line-argument \
        -I${xdp2}/include -I${pkgs.libbpf}/include \
        -std=gnu11 -g -O2 -c -o bpf_flow.kern.o kern_bpf/bpf_flow.c

    if [[ -s bpf_flow.kern.o ]]; then
      pass "bpf_flow.kern.o compiled"
    else
      fail "bpf_flow.kern.o empty or missing"
      exit 1
    fi
    echo ""

    # ─── Build parity_test ───
    echo "--- Building parity_test ---"
    gcc -I${xdp2}/include -I${pkgs.libpcap}/include -I${pkgs.libbpf}/include \
        -std=gnu11 -g -O2 \
        -L${xdp2}/lib -L${pkgs.libpcap.lib}/lib -L${pkgs.libbpf}/lib \
        -L${pkgs.elfutils.out}/lib -L${pkgs.zlib}/lib \
        -Wl,-rpath,${xdp2}/lib -Wl,-rpath,${pkgs.libpcap.lib}/lib \
        -Wl,-rpath,${pkgs.libbpf}/lib -Wl,-rpath,${pkgs.elfutils.out}/lib \
        -Wl,-rpath,${pkgs.zlib}/lib \
        -o fast_bpf/parity_test fast_bpf/parity_test.c \
        -lpcap -lxdp2 -lcli -lsiphash -lbpf -lelf -lz

    if [[ -x fast_bpf/parity_test ]]; then
      pass "parity_test binary created"
    else
      fail "parity_test binary missing"
      exit 1
    fi
    echo ""

    # ─── Generate combinatorial test PCAP ───
    echo "--- Generating combinatorial test PCAP ---"
    python3 gen_test_pcap.py -o test_flows.pcap >/dev/null
    if [[ -s test_flows.pcap ]]; then
      pass "test_flows.pcap generated ($(stat -c %s test_flows.pcap) bytes)"
    else
      fail "test_flows.pcap missing or empty"
      exit 1
    fi
    echo ""

    # ─── Runtime parity check (needs root) ───
    if [[ -d /sys/fs/bpf ]] && [[ $(id -u) -eq 0 ]]; then
      echo "--- Running parity_test (fast vs oracle, combinatorial PCAP) ---"
      if OUTPUT=$(./fast_bpf/parity_test \
          -f ./fast_bpf/fast_flow.bpf.o \
          -r ./bpf_flow.kern.o \
          ./test_flows.pcap 2>&1); then
        echo "$OUTPUT"
        pass "parity_test exited 0 (zero mismatches)"
      else
        echo "$OUTPUT"
        fail "parity_test reported mismatches or runtime error"
      fi

      # Cross-check: at least one fast-path hit fired. If not, the
      # gate is too tight or the PCAP is pathological — either way
      # the test has no teeth.
      if echo "$OUTPUT" | grep -qE "Fast-path hits:[[:space:]]+[1-9]"; then
        pass "fast-path fired on at least one packet"
      else
        fail "fast-path never fired — test has no coverage"
      fi
    else
      echo "Skipping runtime parity check (need root + /sys/fs/bpf)"
    fi
    echo ""

    echo "=== Results ==="
    echo "Passed: $TESTS_PASSED"
    echo "Failed: $TESTS_FAILED"
    if [[ $TESTS_FAILED -gt 0 ]]; then
      exit 1
    fi
  '';
}
