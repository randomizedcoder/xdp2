#
# flake.nix for XDP2
#
# This flake provides:
# - Development environment: nix develop
# - Package build: nix build
#
# To enter the development environment:
# nix develop
#
# To build the package:
# nix build .#xdp2
#
# If flakes are not enabled, use the following command:
# nix --extra-experimental-features 'nix-command flakes' develop .
# nix --extra-experimental-features 'nix-command flakes' build .
#
# To enable flakes, you may need to enable them in your system configuration:
# test -d /etc/nix || sudo mkdir /etc/nix
# echo 'experimental-features = nix-command flakes' | sudo tee -a /etc/nix/nix.conf
#
# Debugging:
# XDP2_NIX_DEBUG=7 nix develop --verbose --print-build-logs
#
# Alternative commands:
# nix --extra-experimental-features 'nix-command flakes' --option eval-cache false develop
# nix --extra-experimental-features 'nix-command flakes' develop --no-write-lock-file
# nix --extra-experimental-features 'nix-command flakes' print-dev-env --json
#
# Recommended term:
# export TERM=xterm-256color
#
# To run the sample test:
# nix build .#tests.simple-parser
# ./result/bin/xdp2-test-simple-parser
#
{
  description = "XDP2 packet processing framework";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";

    # MicroVM for eBPF testing (Phase 1)
    # See: documentation/nix/microvm-implementation-phase1.md
    microvm = {
      url = "github:astro/microvm.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, flake-utils, microvm }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        lib = nixpkgs.lib;

        # Import LLVM configuration module
        # Use default LLVM version from nixpkgs (no pinning required)
        llvmConfig = import ./nix/llvm.nix { inherit pkgs lib; };
        llvmPackages = llvmConfig.llvmPackages;

        # Import packages module
        packagesModule = import ./nix/packages.nix { inherit pkgs llvmPackages; };

        # Compiler configuration
        compilerConfig = {
          cc = pkgs.gcc;
          cxx = pkgs.gcc;
          ccBin = "gcc";
          cxxBin = "g++";
        };

        # Import environment variables module
        envVars = import ./nix/env-vars.nix {
          inherit pkgs llvmConfig compilerConfig;
          packages = packagesModule;
          configAgeWarningDays = 14;
        };

        # Import package derivation (production build, assertions disabled)
        xdp2 = import ./nix/derivation.nix {
          inherit pkgs lib llvmConfig;
          inherit (packagesModule) nativeBuildInputs buildInputs;
          enableAsserts = false;
        };

        # Debug build with assertions enabled
        xdp2-debug = import ./nix/derivation.nix {
          inherit pkgs lib llvmConfig;
          inherit (packagesModule) nativeBuildInputs buildInputs;
          enableAsserts = true;
        };

        # XDP sample programs (BPF bytecode)
        # Uses xdp2-debug for xdp2-compiler and headers
        xdp-samples = import ./nix/xdp-samples.nix {
          inherit pkgs;
          xdp2 = xdp2-debug;
        };

        # Proto-audit: multi-source protocol definition audit tool
        protoAuditSources = import ./nix/proto-audit-sources.nix { inherit pkgs; };
        proto-audit-bin = import ./nix/proto-audit.nix {
          inherit pkgs protoAuditSources;
        };

        # Wrapped proto-audit with all external sources pre-configured
        proto-audit = pkgs.writeShellApplication {
          name = "proto-audit";
          runtimeInputs = [
            proto-audit-bin
            protoAuditSources.scapyPython
            protoAuditSources.tshark
          ];
          text = ''
            export PROTO_AUDIT_PROTO_DEFS_DIR="''${PROTO_AUDIT_PROTO_DEFS_DIR:-${./src/include/xdp2/proto_defs}}"
            export PROTO_AUDIT_KERNEL_SRC="''${PROTO_AUDIT_KERNEL_SRC:-${protoAuditSources.kernelSrc}}"
            export PROTO_AUDIT_SCAPY_HELPER="''${PROTO_AUDIT_SCAPY_HELPER:-${proto-audit-bin}/share/proto-audit/scapy_dump.py}"
            export PROTO_AUDIT_PYTHON="''${PROTO_AUDIT_PYTHON:-${protoAuditSources.scapyPython}/bin/python3}"
            export PROTO_AUDIT_TSHARK_BIN="''${PROTO_AUDIT_TSHARK_BIN:-${protoAuditSources.tshark}/bin/tshark}"
            export PROTO_AUDIT_PCAP="''${PROTO_AUDIT_PCAP:-${test-pcap}/combo.pcap}"
            export PROTO_AUDIT_ETHERPARSE_SRC="''${PROTO_AUDIT_ETHERPARSE_SRC:-${protoAuditSources.etherparseSrc}}"
            export PROTO_AUDIT_LIBPCAP_SRC="''${PROTO_AUDIT_LIBPCAP_SRC:-${protoAuditSources.libpcapSrc}}"
            export PROTO_AUDIT_TSHARK_REGISTRY="''${PROTO_AUDIT_TSHARK_REGISTRY:-${protoAuditSources.tsharkRegistry}/tshark_registry.json}"
            export PROTO_AUDIT_SCAPY_REGISTRY="''${PROTO_AUDIT_SCAPY_REGISTRY:-${protoAuditSources.scapyRegistry}/scapy_registry.json}"
            export PROTO_AUDIT_KERNEL_REGISTRY="''${PROTO_AUDIT_KERNEL_REGISTRY:-${protoAuditSources.kernelRegistry}/kernel_registry.json}"
            export PROTO_AUDIT_PCAP_TEMPLATES="''${PROTO_AUDIT_PCAP_TEMPLATES:-${protoAuditSources.pcapTemplates}}"
            export PROTO_AUDIT_PCAP_CORPUS="''${PROTO_AUDIT_PCAP_CORPUS:-${protoAuditSources.pcapCorpus}/pdml}"
            export PROTO_AUDIT_IANA_DIR="''${PROTO_AUDIT_IANA_DIR:-${protoAuditSources.ianaRegistries}}"
            export PROTO_AUDIT_KAITAI_DIR="''${PROTO_AUDIT_KAITAI_DIR:-${protoAuditSources.kaitaiFormats}}"
            export PROTO_AUDIT_SURICATA_DIR="''${PROTO_AUDIT_SURICATA_DIR:-${protoAuditSources.suricataSrc}}"
            exec proto-audit "$@"
          '';
        };

        # XDP2 Rust reimplementation — build, test, and analysis targets
        # See nix/xdp2-rs.nix for all available targets
        xdp2Rs = import ./nix/xdp2-rs.nix {
          inherit pkgs;
          xdp2 = xdp2-debug;
        };

        # Compiler verification framework — compare C++ vs Rust xdp2-compiler
        # See nix/compiler-verify.nix for all available targets
        compilerVerify = import ./nix/compiler-verify.nix {
          inherit pkgs xdp2Rs;
          xdp2 = xdp2-debug;
        };

        # Parser performance benchmark — C vs Rust parse engine comparison
        # Usage: nix build .#parser-benchmark && ./result/bin/xdp2-parser-benchmark [iterations] [npkts]
        parserBenchmark = import ./nix/parser-benchmark.nix {
          inherit pkgs xdp2Rs;
          xdp2 = xdp2-debug;
        };

        # Rust parser performance benchmarks (reproducible, all modes)
        # Usage: nix run .#perf-bench           — standard benchmark
        #        nix run .#perf-sweep           — full sweep (all threads, JSON)
        perfBench = import ./nix/perf-bench.nix {
          inherit pkgs xdp2Rs;
        };

        # Deep performance analysis (reproducible across machines)
        # Usage: nix run .#perf-sweep-tcp       — baseline sweep
        #        nix run .#perf-sweep-mixed     — real protocol diversity
        #        nix run .#perf-sweep-combo     — full-scale 500K packets
        #        nix run .#perf-flamegraph      — flamegraphs for 3 modes
        #        nix run .#perf-annotate        — assembly-level hot functions
        #        nix run .#perf-analysis-all    — run everything
        perfAnalysis = import ./nix/perf-analysis.nix {
          inherit pkgs xdp2Rs test-pcap;
        };

        # Common source flags for proto-audit commands
        protoAuditFlags = builtins.concatStringsSep " " [
          "--proto-defs-dir ${./src/include/xdp2/proto_defs}"
          "--kernel-src ${protoAuditSources.kernelSrc}"
          "--scapy-helper ${proto-audit-bin}/share/proto-audit/scapy_dump.py"
          "--python ${protoAuditSources.scapyPython}/bin/python3"
          "--tshark-bin ${protoAuditSources.tshark}/bin/tshark"
          "--pcap ${test-pcap}/combo.pcap"
          "--etherparse-src ${protoAuditSources.etherparseSrc}"
          "--libpcap-src ${protoAuditSources.libpcapSrc}"
        ];

        # Full audit report (cached Nix derivation)
        proto-audit-report = pkgs.runCommand "proto-audit-report" {
          nativeBuildInputs = [
            proto-audit-bin
            protoAuditSources.scapyPython
            protoAuditSources.tshark
          ];
        } ''
          mkdir -p $out

          # Full audit
          proto-audit audit ${protoAuditFlags} \
            > $out/audit.txt 2>&1 || true
          proto-audit audit --json ${protoAuditFlags} \
            > $out/audit.json 2>/dev/null || true

          # Source × protocol matrix
          proto-audit matrix ${protoAuditFlags} \
            > $out/matrix.txt 2>/dev/null || true
          proto-audit matrix --json ${protoAuditFlags} \
            > $out/matrix.json 2>/dev/null || true

          # Detailed cross-source findings
          proto-audit findings ${protoAuditFlags} \
            > $out/findings.txt 2>/dev/null || true
          proto-audit findings --json ${protoAuditFlags} \
            > $out/findings.json 2>/dev/null || true

          # Protocol list
          proto-audit list > $out/protocols.txt
          proto-audit list --json > $out/protocols.json

          # XDP2 scan
          proto-audit scan --proto-defs-dir ${./src/include/xdp2/proto_defs} \
            > $out/xdp2-scan.txt
          proto-audit scan --proto-defs-dir ${./src/include/xdp2/proto_defs} --json \
            > $out/xdp2-scan.json

          echo "Proto-audit report generated at: $out"
          ls -la $out/
        '';

        # Generate all C headers and compile-test with clang -target bpf
        proto-audit-c-check = pkgs.runCommand "proto-audit-c-check" {
          nativeBuildInputs = [
            proto-audit-bin
            protoAuditSources.scapyPython
            protoAuditSources.tshark
            pkgs.llvmPackages.clang
          ];
        } ''
          mkdir -p $out/headers $out/logs

          # Generate all C headers (curated tier only for compile check)
          proto-audit generate-all --target c --tier curated \
            --output-dir $out/headers \
            ${protoAuditFlags} \
            2>$out/logs/generate.log || true

          echo "Generated $(ls $out/headers/*.h 2>/dev/null | wc -l) C headers"

          # Compile-test each header
          passed=0
          failed=0
          for h in $out/headers/*.h; do
            [ -f "$h" ] || continue
            base=$(basename "$h" .h)

            # Create a test .c file that includes the header
            cat > /tmp/test_$base.c <<TESTEOF
          #include <linux/types.h>
          #include "$h"
          TESTEOF

            if clang -fsyntax-only -target bpf \
                -I${protoAuditSources.kernelSrc}/include \
                -I${protoAuditSources.kernelSrc}/include/uapi \
                -I${./src/include} \
                -Wno-everything \
                /tmp/test_$base.c 2>>$out/logs/compile.log; then
              passed=$((passed + 1))
            else
              failed=$((failed + 1))
              echo "FAIL: $base" >> $out/logs/failures.txt
            fi
          done

          echo "Compile test: $passed passed, $failed failed" | tee $out/logs/summary.txt
          echo "Compile test results in $out/logs/"
        '';

        # Run round-trip validation for all curated protocols (batch)
        proto-audit-validate-all = pkgs.runCommand "proto-audit-validate-all" {
          nativeBuildInputs = [
            proto-audit-bin
            protoAuditSources.scapyPython
            protoAuditSources.tshark
          ];
        } ''
          mkdir -p $out

          # Run validate-all: validates each protocol's IR→PCAP→tshark round-trip
          proto-audit validate --proto all --tier curated --json \
            ${protoAuditFlags} \
            > $out/validate_all.json 2>$out/validate.log || true

          # Also produce audit baseline for regression tracking
          proto-audit audit --json ${protoAuditFlags} \
            > $out/audit_baseline.json 2>/dev/null || true

          echo "Validation results in $out/"
          echo "Use as baseline: nix build .#proto-audit-validate-all"
        '';

        # Import development shell module
        devshell = import ./nix/devshell.nix {
          inherit pkgs lib llvmConfig compilerConfig envVars;
          packages = packagesModule;
        };

        # Import tests module (uses debug build for assertion support)
        tests = import ./nix/tests {
          inherit pkgs;
          xdp2 = xdp2-debug;  # Tests use debug build with assertions
        };

        # =====================================================================
        # Static Analysis Infrastructure
        # Ported from reference implementation, adapted for C/Make build system
        # =====================================================================
        analysis = import ./nix/analysis {
          inherit pkgs lib llvmConfig packagesModule;
          src = ./.;
        };

        # =====================================================================
        # Phase 1: Packaging (x86_64 .deb only)
        # See: documentation/nix/microvm-implementation-phase1.md
        # =====================================================================
        packaging = import ./nix/packaging {
          inherit pkgs lib;
          xdp2 = xdp2;  # Use production build for distribution
        };

        # =====================================================================
        # Phase 2: MicroVM infrastructure (x86_64, aarch64, riscv64)
        # See: documentation/nix/microvm-phase2-arm-riscv-plan.md
        #
        # Cross-compilation: We pass buildSystem so that when building for
        # non-native architectures (e.g., riscv64 on x86_64), we use true
        # cross-compilation with native cross-compilers instead of slow
        # binfmt emulation.
        # =====================================================================
        microvms = import ./nix/microvms {
          inherit pkgs lib microvm nixpkgs;
          buildSystem = system;  # Pass host system for cross-compilation
        };

        # Generate combinatorial test PCAPs with all protocol permutations
        # Usage: nix run .#gen-test-pcap -- -n 500000 -o /tmp/combo_500k.pcap
        #        nix run .#gen-test-pcap -- --list
        gen-test-pcap = pkgs.writeShellApplication {
          name = "gen-test-pcap";
          runtimeInputs = [
            (pkgs.python314.withPackages (ps: [ ps.scapy ]))
          ];
          text = ''
            exec python3 ${./samples/flow_dissector/gen_test_pcap.py} "$@"
          '';
        };

        # Pre-built 500k packet PCAP for benchmarking (cached in Nix store)
        # Usage: nix build .#test-pcap
        #        ls result/combo.pcap
        test-pcap = pkgs.runCommand "xdp2-test-pcap" {
          nativeBuildInputs = [
            (pkgs.python314.withPackages (ps: [ ps.scapy ]))
          ];
        } ''
          mkdir -p $out
          python3 ${./samples/flow_dissector/gen_test_pcap.py} \
            -n 500000 -o $out/combo.pcap
        '';

        # Convenience target to run all sample tests
        run-sample-tests = pkgs.writeShellApplication {
          name = "run-sample-tests";
          runtimeInputs = [];
          text = ''
            echo "========================================"
            echo "  XDP2 Sample Tests Runner"
            echo "========================================"
            echo ""

            # Run all tests via the combined test runner
            ${tests.all}/bin/xdp2-test-all
          '';
        };

      in
      {
        # Package outputs
        packages = {
          default = xdp2;
          xdp2 = xdp2;
          xdp2-debug = xdp2-debug;  # Debug build with assertions
          xdp-samples = xdp-samples;  # XDP sample programs (BPF bytecode)

          # Tests (build with: nix build .#tests.simple-parser)
          tests = tests;

          # Convenience aliases for individual tests
          simple-parser-test = tests.simple-parser;
          offset-parser-test = tests.offset-parser;
          ports-parser-test = tests.ports-parser;
          flow-tracker-combo-test = tests.flow-tracker-combo;
          flow-dissector-benchmark-test = tests.flow-dissector-benchmark;
          xdp-build-test = tests.xdp-build;

          # Proto-audit: multi-source protocol definition audit tool
          # Usage: nix run .#proto-audit -- list
          #        nix run .#proto-audit -- compare --proto IPv4
          #        nix build .#proto-audit-report
          inherit proto-audit proto-audit-bin proto-audit-report proto-audit-c-check proto-audit-validate-all;

          # ===================================================================
          # XDP2 Rust Reimplementation
          # Build:       nix build .#xdp2-rs
          # Test:        nix build .#xdp2-rs-test
          # Lint:        nix build .#xdp2-rs-clippy
          # Format:      nix build .#xdp2-rs-fmt-check
          # Docs:        nix build .#xdp2-rs-doc
          # Golden:      nix build .#xdp2-rs-golden
          # Adversarial: nix build .#xdp2-rs-adversarial
          # Stress:      nix run   .#xdp2-rs-stress -- [hours] [threads]
          # ===================================================================
          xdp2-rs = xdp2Rs.build;
          xdp2-rs-test = xdp2Rs.test;
          xdp2-rs-clippy = xdp2Rs.clippy;
          xdp2-rs-fmt-check = xdp2Rs.fmt-check;
          xdp2-rs-doc = xdp2Rs.doc;
          xdp2-rs-golden = xdp2Rs.golden;
          xdp2-rs-adversarial = xdp2Rs.adversarial;
          xdp2-rs-stress = xdp2Rs.stress;

          # ===================================================================
          # Compiler Verification Framework (C++ vs Rust)
          # Extract:   nix build .#compiler-ir-extract
          # Rust gen:  nix build .#compiler-rust-generate
          # JSON cmp:  nix build .#compiler-verify-json
          # DOT cmp:   nix build .#compiler-verify-dot
          # All:       nix build .#compiler-verify-all
          # ===================================================================
          compiler-ir-extract = compilerVerify.ir-extract;
          compiler-rust-generate = compilerVerify.rust-generate;
          compiler-verify-json = compilerVerify.verify-json;
          compiler-verify-dot = compilerVerify.verify-dot;
          compiler-verify-all = compilerVerify.verify-all;

          # ===================================================================
          # Parser Performance Benchmark (C vs Rust)
          # Usage: nix build .#parser-benchmark && ./result/bin/xdp2-parser-benchmark
          # ===================================================================
          parser-benchmark = parserBenchmark;

          # ===================================================================
          # Rust Parser Performance Benchmarks (reproducible)
          # Quick:  nix run .#perf-bench                — all modes, perf counters
          # Custom: nix run .#perf-bench -- --mode template -n 1000
          # Sweep:  nix run .#perf-sweep                — all thread counts, JSON
          # ===================================================================
          perf-bench = perfBench.bench;
          perf-sweep = perfBench.sweep;

          # ===================================================================
          # Deep Performance Analysis (reproducible across machines)
          # Sweeps:     nix run .#perf-sweep-tcp
          #             nix run .#perf-sweep-mixed
          #             nix run .#perf-sweep-combo
          # Flamegraph: nix run .#perf-flamegraph
          # Annotate:   nix run .#perf-annotate
          # All:        nix run .#perf-analysis-all
          # Mixed PCAP: nix build .#perf-mixed-pcap
          # ===================================================================
          perf-sweep-tcp = perfAnalysis.sweep-tcp;
          perf-sweep-mixed = perfAnalysis.sweep-mixed;
          perf-sweep-combo = perfAnalysis.sweep-combo;
          perf-flamegraph = perfAnalysis.flamegraph;
          perf-annotate = perfAnalysis.annotate;
          perf-analysis-all = perfAnalysis.analysis-all;
          perf-mixed-pcap = perfAnalysis.mixed-pcap;

          # Generate combinatorial test PCAPs
          # nix run .#gen-test-pcap -- -n 500000 -o /tmp/combo.pcap
          # nix build .#test-pcap  → result/combo.pcap (500k packets, cached)
          inherit gen-test-pcap test-pcap;

          # Run all sample tests in one go
          # Usage: nix run .#run-sample-tests
          inherit run-sample-tests;

          # Kernel BPF flow dissector source (for updating vendored copy)
          # Usage: nix build .#kern-bpf-flow-src
          #        cp result samples/flow_dissector/kern_bpf/bpf_flow.c
          kern-bpf-flow-src = import ./nix/kern-bpf-flow.nix { inherit pkgs; };

          # ===================================================================
          # Static Analysis
          # Usage: nix build .#analysis-quick
          #        nix build .#analysis-standard
          #        nix build .#analysis-deep
          # ===================================================================
          analysis-quick = analysis.quick;
          analysis-standard = analysis.standard;
          analysis-deep = analysis.deep;
          analysis-clang-tidy = analysis.clang-tidy;
          analysis-cppcheck = analysis.cppcheck;
          analysis-flawfinder = analysis.flawfinder;
          analysis-clang-analyzer = analysis.clang-analyzer;
          analysis-gcc-warnings = analysis.gcc-warnings;
          analysis-gcc-analyzer = analysis.gcc-analyzer;
          analysis-semgrep = analysis.semgrep;
          analysis-sanitizers = analysis.sanitizers;

          # ===================================================================
          # Phase 1: Packaging outputs (x86_64 .deb only)
          # See: documentation/nix/microvm-implementation-phase1.md
          # ===================================================================

          # Staging directory (for inspection/debugging)
          # Usage: nix build .#deb-staging
          deb-staging = packaging.staging.x86_64;

          # Debian package
          # Usage: nix build .#deb-x86_64
          deb-x86_64 = packaging.deb.x86_64;

          # ===================================================================
          # Phase 2: MicroVM outputs (x86_64, aarch64, riscv64)
          # See: documentation/nix/microvm-phase2-arm-riscv-plan.md
          # ===================================================================
          #
          # Primary interface (nested):
          #   nix build .#microvms.x86_64
          #   nix run .#microvms.test-x86_64
          #   nix run .#microvms.test-all
          #
          # Legacy interface (flat, backwards compatible):
          #   nix build .#microvm-x86_64
          #   nix run .#xdp2-lifecycle-full-test
          #

          # ─────────────────────────────────────────────────────────────────
          # Nested MicroVM structure (primary interface)
          # ─────────────────────────────────────────────────────────────────
          microvms = {
            # VM derivations
            x86_64 = microvms.vms.x86_64;
            aarch64 = microvms.vms.aarch64;
            riscv64 = microvms.vms.riscv64;

            # Individual architecture tests
            test-x86_64 = microvms.tests.x86_64;
            test-aarch64 = microvms.tests.aarch64;
            test-riscv64 = microvms.tests.riscv64;

            # Combined test (all architectures)
            test-all = microvms.tests.all;

            # Lifecycle scripts (nested by arch)
            lifecycle = microvms.lifecycleByArch;

            # Helper scripts (nested by arch)
            helpers = microvms.helpers;

            # Expect scripts (nested by arch)
            expect = microvms.expect;
          };

          # ─────────────────────────────────────────────────────────────────
          # Legacy flat exports (backwards compatibility)
          # ─────────────────────────────────────────────────────────────────

          # VM derivations (legacy names)
          microvm-x86_64 = microvms.vms.x86_64;
          microvm-aarch64 = microvms.vms.aarch64;
          microvm-riscv64 = microvms.vms.riscv64;

          # Test runner (legacy name)
          xdp2-test-phase1 = microvms.testRunner;

          # Helper scripts (legacy names, x86_64 default)
          xdp2-vm-console = microvms.connectConsole;
          xdp2-vm-serial = microvms.connectSerial;
          xdp2-vm-status = microvms.vmStatus;

          # Login helpers
          xdp2-vm-login-serial = microvms.loginSerial;
          xdp2-vm-login-virtio = microvms.loginVirtio;

          # Command execution helpers
          xdp2-vm-run-serial = microvms.runCommandSerial;
          xdp2-vm-run-virtio = microvms.runCommandVirtio;

          # Expect-based helpers
          xdp2-vm-expect-run = microvms.expectRunCommand;
          xdp2-vm-debug-expect = microvms.debugVmExpect;
          xdp2-vm-expect-verify-service = microvms.expectVerifyService;

          # Lifecycle scripts (legacy names, x86_64 default)
          xdp2-lifecycle-0-build = microvms.lifecycle.checkBuild;
          xdp2-lifecycle-1-check-process = microvms.lifecycle.checkProcess;
          xdp2-lifecycle-2-check-serial = microvms.lifecycle.checkSerial;
          xdp2-lifecycle-2b-check-virtio = microvms.lifecycle.checkVirtio;
          xdp2-lifecycle-3-verify-ebpf-loaded = microvms.lifecycle.verifyEbpfLoaded;
          xdp2-lifecycle-4-verify-ebpf-running = microvms.lifecycle.verifyEbpfRunning;
          xdp2-lifecycle-5-shutdown = microvms.lifecycle.shutdown;
          xdp2-lifecycle-6-wait-exit = microvms.lifecycle.waitExit;
          xdp2-lifecycle-force-kill = microvms.lifecycle.forceKill;
          xdp2-lifecycle-full-test = microvms.lifecycle.fullTest;
        } // (
          # ===================================================================
          # Cross-compiled packages for RISC-V (built on x86_64, runs on riscv64)
          # ===================================================================
          if system == "x86_64-linux" then
            let
              pkgsCrossRiscv = import nixpkgs {
                localSystem = "x86_64-linux";
                crossSystem = "riscv64-linux";
                config = { allowUnfree = true; };
                overlays = [
                  (final: prev: {
                    boehmgc = prev.boehmgc.overrideAttrs (old: { doCheck = false; });
                    libuv = prev.libuv.overrideAttrs (old: { doCheck = false; });
                    meson = prev.meson.overrideAttrs (old: { doCheck = false; doInstallCheck = false; });
                    libseccomp = prev.libseccomp.overrideAttrs (old: { doCheck = false; });
                  })
                ];
              };

              # For cross-compilation, use HOST LLVM for xdp2-compiler (runs on build machine)
              # Use target packages for the actual xdp2 libraries
              packagesModuleRiscv = import ./nix/packages.nix { pkgs = pkgsCrossRiscv; llvmPackages = llvmConfig.llvmPackages; };

              xdp2-debug-riscv64 = import ./nix/derivation.nix {
                pkgs = pkgsCrossRiscv;
                lib = pkgsCrossRiscv.lib;
                # Use HOST llvmConfig, not target, because xdp2-compiler runs on HOST
                llvmConfig = llvmConfig;
                inherit (packagesModuleRiscv) nativeBuildInputs buildInputs;
                enableAsserts = true;
              };

              # Pre-built samples for RISC-V cross-compilation
              # Key: xdp2-compiler runs on HOST (x86_64), generates .p.c files
              # which are then compiled with TARGET (RISC-V) toolchain
              prebuiltSamplesRiscv64 = import ./nix/samples {
                inherit pkgs;                    # Host pkgs (for xdp2-compiler)
                xdp2 = xdp2-debug;               # Host xdp2 with compiler (x86_64)
                xdp2Target = xdp2-debug-riscv64; # Target xdp2 libraries (RISC-V)
                targetPkgs = pkgsCrossRiscv;     # Target pkgs for binaries
              };

              testsRiscv64 = import ./nix/tests {
                pkgs = pkgsCrossRiscv;
                xdp2 = xdp2-debug-riscv64;
                prebuiltSamples = prebuiltSamplesRiscv64;
              };

              # ─── AArch64 cross-compilation (same pattern as RISC-V) ───
              pkgsCrossAarch64 = import nixpkgs {
                localSystem = "x86_64-linux";
                crossSystem = "aarch64-linux";
                config = { allowUnfree = true; };
                overlays = [
                  (final: prev: {
                    boehmgc = prev.boehmgc.overrideAttrs (old: { doCheck = false; });
                    libuv = prev.libuv.overrideAttrs (old: { doCheck = false; });
                    meson = prev.meson.overrideAttrs (old: { doCheck = false; doInstallCheck = false; });
                    libseccomp = prev.libseccomp.overrideAttrs (old: { doCheck = false; });
                  })
                ];
              };

              packagesModuleAarch64 = import ./nix/packages.nix { pkgs = pkgsCrossAarch64; llvmPackages = llvmConfig.llvmPackages; };

              xdp2-debug-aarch64 = import ./nix/derivation.nix {
                pkgs = pkgsCrossAarch64;
                lib = pkgsCrossAarch64.lib;
                llvmConfig = llvmConfig;
                inherit (packagesModuleAarch64) nativeBuildInputs buildInputs;
                enableAsserts = true;
              };

              prebuiltSamplesAarch64 = import ./nix/samples {
                inherit pkgs;
                xdp2 = xdp2-debug;
                xdp2Target = xdp2-debug-aarch64;
                targetPkgs = pkgsCrossAarch64;
              };

              testsAarch64 = import ./nix/tests {
                pkgs = pkgsCrossAarch64;
                xdp2 = xdp2-debug-aarch64;
                prebuiltSamples = prebuiltSamplesAarch64;
              };
            in {
              # Cross-compiled xdp2 for RISC-V
              xdp2-debug-riscv64 = xdp2-debug-riscv64;

              # Pre-built samples for RISC-V (built on x86_64, runs on riscv64)
              prebuilt-samples-riscv64 = prebuiltSamplesRiscv64.all;

              # Cross-compiled tests for RISC-V (using pre-built samples)
              riscv64-tests = testsRiscv64;

              # Runner script for RISC-V tests in VM
              run-riscv64-tests = pkgs.writeShellApplication {
                name = "run-riscv64-tests";
                runtimeInputs = [ pkgs.expect pkgs.netcat-gnu ];
                text = ''
                  echo "========================================"
                  echo "  XDP2 RISC-V Sample Tests"
                  echo "========================================"
                  echo ""
                  echo "Test binary: ${testsRiscv64.all}/bin/xdp2-test-all"
                  echo ""
                  echo "Running tests inside RISC-V VM..."

                  # Use expect to run the tests
                  ${microvms.expect.riscv64.runCommand}/bin/xdp2-vm-expect-run-riscv64 \
                    "${testsRiscv64.all}/bin/xdp2-test-all"
                '';
              };

              # ─── AArch64 exports ───

              # Cross-compiled xdp2 for AArch64
              xdp2-debug-aarch64 = xdp2-debug-aarch64;

              # Pre-built samples for AArch64 (built on x86_64, runs on aarch64)
              prebuilt-samples-aarch64 = prebuiltSamplesAarch64.all;

              # Cross-compiled tests for AArch64 (using pre-built samples)
              aarch64-tests = testsAarch64;

              # Runner script for AArch64 tests in VM
              run-aarch64-tests = pkgs.writeShellApplication {
                name = "run-aarch64-tests";
                runtimeInputs = [ pkgs.expect pkgs.netcat-gnu ];
                text = ''
                  echo "========================================"
                  echo "  XDP2 AArch64 Sample Tests"
                  echo "========================================"
                  echo ""
                  echo "Test binary: ${testsAarch64.all}/bin/xdp2-test-all"
                  echo ""
                  echo "Running tests inside AArch64 VM..."

                  # Use expect to run the tests
                  ${microvms.expect.aarch64.runCommand}/bin/xdp2-vm-expect-run-aarch64 \
                    "${testsAarch64.all}/bin/xdp2-test-all"
                '';
              };
            }
          else {}
        );

        # Development shell
        devShells.default = devshell;
      });
}
