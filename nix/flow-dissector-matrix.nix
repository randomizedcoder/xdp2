# nix/flow-dissector-matrix.nix
#
# 6-way flow dissector performance matrix, packaged as a Nix
# writeShellApplication so shellcheck validates the script, all input
# paths (benchmark binaries, BPF .o files, LLVM, coreutils) are wired
# up via the Nix store, and `nix run .#flow-dissector-matrix -- PCAP`
# is the single entry point.
#
# Replaces the hand-written samples/flow_dissector/benchmark_matrix.sh
# — or rather, wraps it: the shell body is the same logic, but with
# paths hermetically resolved instead of $SCRIPT_DIR-relative.
#
# The matrix compares six dissector implementations against the same
# PCAP:
#
#   Userspace:
#     1. Kernel flowdis port          (benchmark -p -l "Kernel flowdis")
#     2. XDP2 parser (with metadata)  (benchmark -p -l "XDP2 parser")
#     3. XDP2 parse-only              (benchmark -p -l "XDP2 parse-only")
#
#   BPF (BPF_PROG_TEST_RUN — needs CAP_BPF / root):
#     4. Upstream kernel selftest     (bpf_flow.kern.o)
#     5. XDP2-compiler-generated      (flow_dissector.bpf.o)
#     6. xdp2-flow-ebpf fast-path     (fast_bpf/fast_flow.bpf.o — Track D)
#
# Ways 4–6 require root. Run with:
#
#   sudo $(nix build --no-link --print-out-paths .#flow-dissector-matrix)/bin/xdp2-flow-dissector-matrix /path/to/pcap
#
# The `artifacts` derivation builds all six binaries + BPF objects in
# one hermetic sandbox (same Makefile targets the developer uses
# interactively), and the writeShellApplication embeds those paths.
#
# See samples/flow_dissector/docs/super-flow-dissector-implementation.md
# §3.2 for the measurement methodology.

{ pkgs
, xdp2            # C install tree — provides headers, libs, xdp2-compiler
, llvmPackages    # For clang with BPF target (same as xdp2-flow-ebpf.nix)
}:

let
  lib = pkgs.lib;
  srcRoot = ../samples/flow_dissector;

  # Architecture-specific BPF compile defines.
  # Must match nix/xdp2-flow-ebpf.nix and the Makefile — if the three
  # drift, the BPF object will be ABI-incompatible between how we build
  # and how the user compiles locally.
  bpfArchDefines = let
    cpu = pkgs.stdenv.hostPlatform.parsed.cpu.name;
  in {
    "x86_64"  = "-D__TARGET_ARCH_x86 -D__x86_64__";
    "aarch64" = "-D__TARGET_ARCH_arm64 -D__aarch64__";
    "riscv64" = "-D__TARGET_ARCH_riscv -D__riscv -D__riscv_xlen=64";
  }.${cpu} or (throw "flow-dissector-matrix: unsupported BPF arch: ${cpu}");

  # ── Artifacts derivation ────────────────────────────────────────
  #
  # Builds the six matrix inputs in one sandbox. The Makefile is the
  # source of truth; we just drive it with XDP2DIR pointed at the
  # Nix-built xdp2 install tree and all hardening disabled (BPF target
  # rejects -fzero-call-used-regs).
  artifacts = pkgs.stdenv.mkDerivation {
    pname = "xdp2-flow-dissector-matrix-artifacts";
    version = xdp2.version or "0.1.0";

    src = srcRoot;

    nativeBuildInputs = [
      pkgs.gnumake
      llvmPackages.clang         # For -target bpf compiles
    ];

    buildInputs = [
      pkgs.libpcap               # benchmark + benchmark_bpf
      pkgs.libpcap.lib
      pkgs.libbpf                # benchmark_bpf
      pkgs.elfutils
      pkgs.zlib
      pkgs.linuxHeaders          # kernel UAPI for BPF TUs
    ];

    # Nix cc-wrapper's default hardening flags (-fzero-call-used-regs,
    # -fstack-protector-strong, _FORTIFY_SOURCE) break BPF compiles.
    # Match the Makefile recipes for flow_dissector.bpf.o / bpf_flow.kern.o
    # / fast_flow.bpf.o which all prepend NIX_HARDENING_ENABLE=.
    hardeningDisable = [ "all" ];
    NIX_HARDENING_ENABLE = "";

    # xdp2-compiler uses libclang to parse parser.c; it needs system
    # headers resolved without the cc-wrapper.
    XDP2_C_INCLUDE_PATH = "${llvmPackages.clang.cc.lib}/lib/clang/${lib.versions.major llvmPackages.clang.cc.version}/include";
    XDP2_GLIBC_INCLUDE_PATH = "${pkgs.stdenv.cc.libc.dev}/include";
    XDP2_LINUX_HEADERS_PATH = "${pkgs.linuxHeaders}/include";

    buildPhase = ''
      runHook preBuild

      export PATH="${xdp2}/bin:$PATH"

      # R3.3.6: USE_GENERATED_MONO=1 swaps the c-xdp2-mono binding
      # from the hand-written reference at
      # samples/flow_dissector/flow_dissector_mono.h to the
      # compiler-emitted parser.mono.c. The Makefile recipes for
      # parser.mono.ll + parser.mono.c handle .ll generation +
      # xdp2-compiler invocation under that flag.
      make XDP2DIR=${xdp2} \
           XDP2_SRCDIR=${xdp2} \
           USE_GENERATED_MONO=1 \
           benchmark benchmark_bpf

      # All four BPF objects via the `bpf` meta-target (minus the one
      # we add explicitly — fast_bpf/parity_test is a userspace binary
      # grouped under BPF_TARGETS in the Makefile).
      make XDP2DIR=${xdp2} \
           XDP2_SRCDIR=${xdp2} \
           bpf_flow.kern.o \
           flow_dissector.bpf.o \
           fast_bpf/fast_flow.bpf.o \
           fast_bpf/parity_test

      # Sanity-check artifacts are non-empty — a zero-byte .o is a
      # silent failure mode that only surfaces at BPF_PROG_TEST_RUN.
      for f in benchmark benchmark_bpf \
               bpf_flow.kern.o flow_dissector.bpf.o \
               fast_bpf/fast_flow.bpf.o fast_bpf/parity_test; do
        test -s "$f" || { echo "empty artifact: $f"; exit 1; }
      done

      runHook postBuild
    '';

    installPhase = ''
      runHook preInstall

      mkdir -p $out/bin $out/lib/xdp2-flow-dissector-matrix
      install -m 755 benchmark          $out/bin/
      install -m 755 benchmark_bpf      $out/bin/
      install -m 755 fast_bpf/parity_test $out/bin/xdp2-parity-test
      install -m 644 bpf_flow.kern.o          $out/lib/xdp2-flow-dissector-matrix/
      install -m 644 flow_dissector.bpf.o     $out/lib/xdp2-flow-dissector-matrix/
      install -m 644 fast_bpf/fast_flow.bpf.o $out/lib/xdp2-flow-dissector-matrix/

      runHook postInstall
    '';

    meta = {
      description = "Pre-built 6-way flow-dissector matrix artifacts";
      platforms = lib.platforms.linux;
    };
  };

  # ── Shell matrix runner ─────────────────────────────────────────
  #
  # writeShellApplication runs shellcheck at build time and prepends
  # `set -euo pipefail`. runtimeInputs wire deps into PATH so `grep`,
  # `printf`, `install` etc. are resolved from Nix store, not the
  # user's PATH.
  matrix = pkgs.writeShellApplication {
    name = "xdp2-flow-dissector-matrix";

    runtimeInputs = [
      pkgs.coreutils
      pkgs.gnugrep
      artifacts
    ];

    text = ''
      # shellcheck disable=SC2016
      USAGE=$(cat <<'EOF'
      Usage: xdp2-flow-dissector-matrix [OPTIONS] <pcap_file>

      Runs all six flow-dissector implementations against <pcap_file>
      and prints a comparison matrix. Ways 4–6 (BPF_PROG_TEST_RUN)
      require root / CAP_BPF — run under sudo.

      Options:
        -n <N>   Userspace benchmark iterations           (default: 100)
        -N <N>   BPF_PROG_TEST_RUN repeat count           (default: 1000)
        -h       This help.

      Paths to benchmark binaries and BPF objects are hermetically
      resolved from the Nix store — no $PWD-relative lookups.
      EOF
      )

      REPEAT=100
      BPF_REPEAT=1000

      while getopts "n:N:h" opt; do
        case $opt in
          n) REPEAT="$OPTARG" ;;
          N) BPF_REPEAT="$OPTARG" ;;
          h) echo "$USAGE"; exit 0 ;;
          *) echo "$USAGE" >&2; exit 1 ;;
        esac
      done
      shift $((OPTIND - 1))

      if [[ $# -ne 1 ]]; then
        echo "$USAGE" >&2
        exit 1
      fi

      PCAP="$1"
      if [[ ! -f "$PCAP" ]]; then
        echo "Error: PCAP file not found: $PCAP" >&2
        exit 1
      fi

      # Hermetic paths — baked in by Nix.
      BENCHMARK="${artifacts}/bin/benchmark"
      BENCHMARK_BPF="${artifacts}/bin/benchmark_bpf"
      BPF_OBJ="${artifacts}/lib/xdp2-flow-dissector-matrix/bpf_flow.kern.o"
      XDP2_BPF_OBJ="${artifacts}/lib/xdp2-flow-dissector-matrix/flow_dissector.bpf.o"
      FAST_BPF_OBJ="${artifacts}/lib/xdp2-flow-dissector-matrix/fast_flow.bpf.o"

      extract_nspkt() {
        local match
        match=$(echo "$1" | grep -oE '[0-9]+ ns/pkt' | head -1 || true)
        echo "''${match:-N/A}"
      }
      extract_mpps() {
        local match
        match=$(echo "$1" | grep -oE '[0-9]+ Mpps' | head -1 || true)
        echo "''${match:-N/A}"
      }

      echo "=== 6-Way Flow Dissector Performance Matrix ==="
      echo "PCAP: $PCAP"
      echo "Userspace iterations: $REPEAT"
      echo "BPF repeat count:     $BPF_REPEAT"
      echo "Artifacts:            ${artifacts}"
      echo ""

      # ── Userspace (ways 1–3) ──────────────────────────────────
      echo "--- Running userspace benchmark (ways 1–3) ---"
      if ! USERSPACE_OUT=$("$BENCHMARK" -p -n "$REPEAT" "$PCAP" 2>&1); then
        echo "Error: userspace benchmark failed" >&2
        echo "$USERSPACE_OUT" >&2
        exit 1
      fi
      echo "$USERSPACE_OUT"
      echo ""

      FLOWDIS_LINE=$(echo "$USERSPACE_OUT" | grep "^Kernel flowdis:" || true)
      XDP2_LINE=$(echo "$USERSPACE_OUT" | grep "^XDP2 parser:" || true)
      XDP2_PO_LINE=$(echo "$USERSPACE_OUT" | grep "^XDP2 parse-only:" || true)

      FLOWDIS_NSPKT=$(extract_nspkt "$FLOWDIS_LINE")
      FLOWDIS_MPPS=$(extract_mpps "$FLOWDIS_LINE")
      XDP2_NSPKT=$(extract_nspkt "$XDP2_LINE")
      XDP2_MPPS=$(extract_mpps "$XDP2_LINE")
      XDP2_PO_NSPKT=$(extract_nspkt "$XDP2_PO_LINE")
      XDP2_PO_MPPS=$(extract_mpps "$XDP2_PO_LINE")

      # ── BPF (ways 4–6) ────────────────────────────────────────
      run_bpf() {
        local label="$1" obj="$2" out_var_ns="$3" out_var_mpps="$4"
        local out line nspkt mpps
        echo "--- Running $label ($(basename "$obj")) ---"
        if out=$("$BENCHMARK_BPF" -p -n "$BPF_REPEAT" -l "$label" -b "$obj" "$PCAP" 2>&1); then
          echo "$out"
          line=$(echo "$out" | grep "^$label:" || true)
          nspkt=$(extract_nspkt "$line")
          mpps=$(extract_mpps "$line")
        else
          echo "Warning: $label failed (need root / CAP_BPF?)" >&2
          echo "$out" >&2
          nspkt="N/A"
          mpps="N/A"
        fi
        # shellcheck disable=SC2086
        printf -v "$out_var_ns"   '%s' "$nspkt"
        # shellcheck disable=SC2086
        printf -v "$out_var_mpps" '%s' "$mpps"
        echo ""
      }

      # Initialize targets of indirect assignment so shellcheck (SC2153)
      # can trace them. run_bpf uses `printf -v "$name" ...` to set these.
      BPF_NSPKT="N/A";      BPF_MPPS="N/A"
      XDP2_BPF_NSPKT="N/A"; XDP2_BPF_MPPS="N/A"
      FAST_BPF_NSPKT="N/A"; FAST_BPF_MPPS="N/A"

      run_bpf "Kernel BPF flowdis"  "$BPF_OBJ"       BPF_NSPKT       BPF_MPPS
      run_bpf "XDP2 BPF parser"     "$XDP2_BPF_OBJ"  XDP2_BPF_NSPKT  XDP2_BPF_MPPS
      run_bpf "xdp2-flow-ebpf fast" "$FAST_BPF_OBJ"  FAST_BPF_NSPKT  FAST_BPF_MPPS

      # ── Matrix table ──────────────────────────────────────────
      echo "================================================================="
      echo "              6-Way Performance Comparison Matrix"
      echo "================================================================="
      echo ""
      printf "%-24s | %-24s | %-24s\n" "" "Non-BPF (userspace)" "BPF (in-kernel)"
      printf "%-24s-+-%-24s-+-%-24s\n" "------------------------" "------------------------" "------------------------"
      printf "%-24s | %-24s | %-24s\n" "Kernel flowdis"      "$FLOWDIS_NSPKT, $FLOWDIS_MPPS" "$BPF_NSPKT, $BPF_MPPS"
      printf "%-24s | %-24s | %-24s\n" "XDP2 parser"         "$XDP2_NSPKT, $XDP2_MPPS"       "$XDP2_BPF_NSPKT, $XDP2_BPF_MPPS"
      printf "%-24s | %-24s | %-24s\n" "XDP2 parse-only"     "$XDP2_PO_NSPKT, $XDP2_PO_MPPS" ""
      printf "%-24s | %-24s | %-24s\n" "xdp2-flow-ebpf fast" ""                              "$FAST_BPF_NSPKT, $FAST_BPF_MPPS"
      echo ""
      echo "Notes:"
      echo "  - Non-BPF: clock_gettime(CLOCK_MONOTONIC_RAW) around userspace loops"
      echo "  - BPF: BPF_PROG_TEST_RUN with repeat=$BPF_REPEAT, kernel reports avg ns"
      echo "  - Numbers across columns are not directly comparable (different contexts)"
    '';
  };
in
{
  inherit artifacts matrix;
}
