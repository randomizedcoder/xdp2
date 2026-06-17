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
        # Overlay applies a User-Agent fix to Nixpkgs' rustPlatform
        # .fetchCargoVendor so crates.io stops returning HTTP 403
        # under its API data-access policy. See
        # nix/overlays/fetch-cargo-vendor-ua-fix.nix for the diagnosis,
        # the empirical UA → status code map, and the removal criterion.
        pkgs = import nixpkgs {
          inherit system;
          overlays = [
            (import ./nix/overlays/fetch-cargo-vendor-ua-fix.nix)
          ];
        };
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
            export PROTO_AUDIT_DPDK_SRC="''${PROTO_AUDIT_DPDK_SRC:-${protoAuditSources.dpdkSrc}}"
            export PROTO_AUDIT_NDPI_SRC="''${PROTO_AUDIT_NDPI_SRC:-${protoAuditSources.ndpiSrc}}"
            export PROTO_AUDIT_PPPD_SRC="''${PROTO_AUDIT_PPPD_SRC:-${protoAuditSources.pppdSrc}}"
            export PROTO_AUDIT_RDMA_SRC="''${PROTO_AUDIT_RDMA_SRC:-${protoAuditSources.rdmaSrc}/include}"
            export PROTO_AUDIT_XDP2_HEADERS_DIR="''${PROTO_AUDIT_XDP2_HEADERS_DIR:-${./src/include}}"
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
            export PROTO_AUDIT_OMI_CSTRUCTS_DIR="''${PROTO_AUDIT_OMI_CSTRUCTS_DIR:-${protoAuditSources.omiCStructs}}"
            export PROTO_AUDIT_OMI_LUA_DIR="''${PROTO_AUDIT_OMI_LUA_DIR:-${protoAuditSources.omiWiresharkLua}}"
            export PROTO_AUDIT_OMI_PCAPS_DIR="''${PROTO_AUDIT_OMI_PCAPS_DIR:-${protoAuditSources.omiDataPackets}}"
            export PROTO_AUDIT_XTCP2_SRC="''${PROTO_AUDIT_XTCP2_SRC:-${protoAuditSources.xtcp2Src}}"
            export PROTO_AUDIT_XTCP2_PCAPS="''${PROTO_AUDIT_XTCP2_PCAPS:-${protoAuditSources.xtcp2Src}/pkg/xtcpnl/testdata}"
            exec proto-audit "$@"
          '';
        };

        # XDP2 Rust reimplementation — build, test, and analysis targets
        # See nix/xdp2-rs.nix for all available targets
        xdp2Rs = import ./nix/xdp2-rs.nix {
          inherit pkgs;
          xdp2 = xdp2-debug;
        };

        # xdp2-flow-ebpf — production-distribution bundle:
        # fast_flow.bpf.o + xdp2-flow-loader + man page + systemd unit.
        # See nix/xdp2-flow-ebpf.nix.
        xdp2FlowEbpf = import ./nix/xdp2-flow-ebpf.nix {
          inherit pkgs llvmPackages;
          xdp2 = xdp2-debug;
        };

        # xdp2-flow-ebpf OCI container image. D10 deliverable — packages
        # xdp2FlowEbpf as a layered image for Kubernetes DaemonSet
        # deployment. See nix/xdp2-flow-ebpf-image.nix.
        xdp2FlowEbpfImage = import ./nix/xdp2-flow-ebpf-image.nix {
          inherit pkgs;
          xdp2-flow-ebpf = xdp2FlowEbpf;
        };

        # 6-way flow dissector performance matrix — shellcheck-validated
        # wrapper packaged via writeShellApplication, hermetic artifact
        # paths. See nix/flow-dissector-matrix.nix.
        flowDissectorMatrix = import ./nix/flow-dissector-matrix.nix {
          inherit pkgs llvmPackages;
          xdp2 = xdp2-debug;
        };

        # Unified xdp2-rs vs C-matrix harness — runs the 6-way C matrix
        # AND xdp2-bench (graph/mono/compiled/template) against the same
        # filtered pcap. See nix/xdp2-rs-matrix.nix and
        # samples/flow_dissector/docs/benchmarks.md "Unified" section.
        flowDissectorMatrixUnified = import ./nix/xdp2-rs-matrix.nix {
          inherit pkgs xdp2Rs flowDissectorMatrix;
          workloadPcapHttpsWeb = perfAnalysis.workload-pcap-https-web;
          # Phase 17.E: when XDP2_MATRIX_PARITY=1, the runner invokes
          # this binary on the same pcap and stamps parity_ok +
          # parity_disagreements into every per-cell JSON.
          parityCheck = flowDissectorParityCheck;
        };

        # Aggregator over Phase-5 per-cell JSONs. Walks a result tree
        # and emits summary.md / summary.csv / regressions.md. Stdlib-
        # only Python. See nix/scripts/aggregate-results.py.
        flowDissectorMatrixAggregate =
          import ./nix/aggregate-results.nix { inherit pkgs; };

        # Phase L4: live-wire AF_XDP campaign aggregator. Walks
        # <results>/<date>/<testbed>/afxdp/<mode>/<size>b/*.json and
        # emits summary-afxdp.{md,csv}. Separate from the matrix
        # aggregator because the two campaigns measure different
        # things (per-pcap PCAP replay vs. per-cell live-wire).
        flowDissectorAfxdpAggregate =
          import ./nix/aggregate-afxdp.nix { inherit pkgs; };

        # Phase A1 (assembly-level analysis): bundles dump-asm.sh with
        # binutils + llvm so `objdump` and `llvm-objdump` are on PATH.
        # Drives per-impl asm extraction across 14 implementations
        # (8 Rust + 3 C + 3 BPF).
        flowDissectorDumpAsm =
          import ./nix/dump-asm.nix {
            inherit pkgs xdp2Rs flowDissectorMatrix;
          };

        # Phase 7: composed runner (orchestrator + aggregator).
        # nix run .#flow-dissector-matrix-run -- --testbed PATH
        flowDissectorMatrixRun =
          import ./nix/flow-dissector-matrix-run.nix {
            inherit pkgs;
            runOnHost = run-on-host;
            aggregate = flowDissectorMatrixAggregate;
          };

        # 2026-05-19 post-R3.4: multi-workload sweep harness that
        # pre-scps cached workload-pcap-* derivations to each host
        # in the testbed and loops calling matrix-run for each.
        # Used to reproduce perf-results/2026-05-19-* runs.
        flowDissectorMatrixSweep =
          import ./nix/flow-dissector-matrix-sweep.nix {
            inherit pkgs lib;
            matrixRun = flowDissectorMatrixRun;
            matrixAggregate = flowDissectorMatrixAggregate;
            workloadPcaps = {
              "https-web"         = perfAnalysis.workload-pcap-https-web;
              "nfs-server"        = perfAnalysis.workload-pcap-nfs-server;
              "k8s-microservices" = perfAnalysis.workload-pcap-k8s-microservices;
              "vlan-tcp-mix"      = perfAnalysis.workload-pcap-vlan-tcp-mix;
              "pppoe-isp"         = perfAnalysis.workload-pcap-pppoe-isp;
              "vxlan-k8s-pure"    = perfAnalysis.workload-pcap-vxlan-k8s-pure;
            };
          };

        # 2026-05-19 post-R3.4: icache / branch-miss / cycle counter
        # sweep. Wraps `benchmark -p -<mode>` in `perf stat` for each
        # (host, workload, parser-mode) cell. Output is a markdown
        # table comparing parser modes on cache behavior — used to
        # test code-size hypotheses (see
        # perf-results/2026-05-19-O3-march-native-flto/comparison.md
        # for the remaining c-xdp2-mono vs rust-mono gap analysis).
        flowDissectorIcacheSweep =
          import ./nix/flow-dissector-icache-sweep.nix {
            inherit pkgs lib;
            workloadPcaps = {
              "https-web"         = perfAnalysis.workload-pcap-https-web;
              "nfs-server"        = perfAnalysis.workload-pcap-nfs-server;
              "k8s-microservices" = perfAnalysis.workload-pcap-k8s-microservices;
              "vlan-tcp-mix"      = perfAnalysis.workload-pcap-vlan-tcp-mix;
              "pppoe-isp"         = perfAnalysis.workload-pcap-pppoe-isp;
              "vxlan-k8s-pure"    = perfAnalysis.workload-pcap-vxlan-k8s-pure;
            };
          };

        # Phase 7: smoke regression gate. Wraps -run --smoke with
        # the aggregator's --baseline / --fail-on-regression mode.
        flowDissectorMatrixCheck =
          import ./nix/flow-dissector-matrix-check.nix {
            inherit pkgs;
            runOnHost = run-on-host;
            aggregate = flowDissectorMatrixAggregate;
            matrixRun = flowDissectorMatrixRun;
          };

        # Phase 8: AF_XDP live offered-load sweep. Composes
        # flow-dissector-ntuple-template-bench across [1,2,5,10] Mpps
        # and emits per-load JSON.
        flowDissectorAfxdpLive =
          import ./nix/flow-dissector-afxdp-live.nix {
            inherit pkgs;
            ntupleTemplateBench = flowDissectorNtupleTemplateBench;
          };

        # Phase 17: cross-parser parity comparator (Python). Wraps
        # nix/scripts/parity-compare.py with a vendored default --scope
        # path so the comparator is invocable hermetically.
        parityCompare = import ./nix/parity-compare.nix { inherit pkgs; };

        # Phase 17: parity gate driver. Runs each of 14 flow-dissector
        # parsers on a pcap with the dump-meta protocol added in 17.B,
        # captures per-packet ParityRecord JSONL, and feeds the tree
        # into the comparator. Exits non-zero on any unexpected
        # cross-parser disagreement.
        flowDissectorParityCheck =
          import ./nix/flow-dissector-parity-check.nix {
            inherit pkgs xdp2Rs flowDissectorMatrix parityCompare;
          };

        # Phase 2 of the protocol-coverage-matrix plan: runs the
        # parity-check driver against every per-protocol pcap
        # template under samples/proto_audit/pcap_templates/ and
        # aggregates the resulting JSONLs into a (protocol × parser)
        # matrix. Report-only by default; --require-expectations
        # turns it into a gate. See nix/protocol-coverage-matrix.nix.
        protocolCoverageMatrix =
          import ./nix/protocol-coverage-matrix.nix {
            inherit pkgs lib;
            parityCheck = flowDissectorParityCheck;
          };

        # Peer-side kernel pktgen driver, shellchecked + packaged as a
        # standalone writeShellApplication. The orchestrator below scp's
        # this to the peer at runtime.
        flowDissectorPktgenNtupleTemplate =
          import ./nix/pktgen-ntuple-template.nix { inherit pkgs; };

        # Peer-side DPDK-pktgen driver, Deliverable-2 alternative for the
        # hp2 kernel pktgen ~1.37 Mpps TX cap. Same start/stop/status
        # CLI as the kernel variant so run_ntuple_template_bench.sh
        # orchestrates either by swapping PKTGEN_SCRIPT. See
        # docs/physical-testbed.md §13 Future work.
        flowDissectorPktgenDpdkNtupleTemplate =
          import ./nix/pktgen-dpdk-ntuple-template.nix { inherit pkgs; };

        # Live X710 ntuple + AF_XDP + template bench orchestrator —
        # drives a two-host run (target + peer) over SSH. Requires the
        # target to have xdp2.testbed.flowDirectorRules and
        # realServicesBench = true via the physical-testbed module.
        # See docs/ntuple-template-bench.md.
        flowDissectorNtupleTemplateBench = import ./nix/ntuple-template-bench.nix {
          inherit pkgs;
          # Bundled af_xdp_parser.xdp.o — wrapper exports XDP_OBJ so the
          # orchestrator script can scp it onto the target before loading.
          xdpSamples = xdp-samples;
          # Peer-side pktgen driver — wrapper exports PKTGEN_SCRIPT so
          # the orchestrator scp's a known-good store path, not a
          # `dirname "$0"` guess.
          pktgenDriver = flowDissectorPktgenNtupleTemplate;
        };

        # DPDK-driven variant of the above. The target side is
        # identical (XDP attach + FD rules + AF_XDP); only PKTGEN_SCRIPT
        # points at the DPDK pktgen driver. Requires the PEER host to
        # have xdp2.testbed.dpdkBenchHost = true so vfio-pci is loaded
        # and 1024×2MB hugepages are reserved at boot.
        flowDissectorDpdkNtupleTemplateBench = import ./nix/dpdk-ntuple-template-bench.nix {
          inherit pkgs;
          xdpSamples = xdp-samples;
          pktgenDpdkDriver = flowDissectorPktgenDpdkNtupleTemplate;
        };

        # Factory for one-shot testbed experiment wrappers. Each
        # Deliverable-1/2/3 experiment (see docs/physical-testbed.md
        # §9 Category H / §13 Future work) is a writeShellApplication
        # built from this helper, so `nix flake show` surfaces every
        # tunable knob by name, and each result lands in a stable
        # perf-results/${target}/exp-${name}-${ts}/ directory with a
        # summary.json for downstream tooling.
        mkBenchExperiment = import ./nix/lib/mkBenchExperiment.nix {
          inherit pkgs;
          ntupleTemplateBench = flowDissectorNtupleTemplateBench;
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

        # Protocol coverage verification
        # Usage: nix run .#coverage-check       — acceptance rate on combo.pcap
        #        nix run .#coverage-check-all   — acceptance rate on all PCAPs
        coverageCheck = import ./nix/coverage-check.nix {
          inherit pkgs xdp2Rs test-pcap;
        };

        # Physical-testbed automation wrapper
        # Drives nix targets on hp2/hp5 (or any SSH-reachable host) via
        # rsync + ssh + nix build/run. See docs/physical-testbed.md §9.
        # Usage: nix run .#run-on-host -- HOST [HOST...] -- TARGET [TARGET...]
        run-on-host = import ./nix/physical-testbed-runner.nix {
          inherit pkgs;
        };

        # Series 3 flow_dissector fast-path A/B harnesses. See
        # kernel-patches/series3-flowdis-fastpath/v1/STATUS.md for the
        # patch shape and perf-results/2026-06-09-series3-arm-microbench
        # for the canonical x86+ARM dataset shape these reproduce.
        #
        #   nix run .#series3-traffic-ab -- GEN DUT DUT_V4 DUT_V6 [N]
        #     Cross-host iperf3 A/B (TCP+UDP, v4+v6, interleaved
        #     sysctl, sidecar telemetry).
        #
        #   nix run .#series3-microbench -- HOST PATCHED BASELINE [N]
        #     Userspace libflowdis A/B. Requires two xdp2 closures
        #     pre-built and nix-copy-closure'd to HOST.
        series3-traffic-ab = import ./nix/series3-traffic-ab.nix {
          inherit pkgs;
        };
        series3-microbench = import ./nix/series3-microbench.nix {
          inherit pkgs;
        };
        series3-pcap-microbench = import ./nix/series3-pcap-microbench.nix {
          inherit pkgs;
        };
        # 10-cell × 1-hour real-traffic soak across the Pi pair fleet.
        # Static matrix (pi5-1↔pi5-2, pi5-2↔pi4-1, pi5-2↔pi3-1) over
        # iperf3 TCP + iperf2 TCP + tcpreplay vxlan, A/B on sysctl.
        # ~10.3 h wall clock at default DUR=3600 / COOLDOWN=120.
        series3-soak = import ./nix/series3-soak.nix {
          inherit pkgs;
        };
        # 12-cell soak for the x86 back-to-back pair l (generator) <-> l2
        # (DUT) over the Mellanox 25 GbE link. The high-performance
        # analogue of series3-soak (Pi fleet): /sys+/proc sidecar,
        # CPU-bound UDP + tunnelled tcpreplay cells, taskset-pinned
        # generator. ~12 h at default DUR=3600.
        series3-soak-l-l2 = import ./nix/series3-soak-x86.nix {
          inherit pkgs;
        };

        # ===================================================================
        # Network-config scenarios for the series3 extension patches.
        # Each script reconfigures a host pair (over SSH) for a named
        # encap shape (single VLAN, QinQ, VXLAN, PPPoE), runs an
        # `up | down | verify` op, and emits scenario-specific env
        # vars (L_SCENARIO_DEV, L_SCENARIO_V4, ...) on stdout for the
        # orchestrator to ingest. The underlying NixOS-managed static
        # config is never modified — these scripts add and remove
        # sub-interfaces only.
        #
        # See nix/scenarios/lib.sh for shared helpers and
        # kernel-patches/series3-flowdis-fastpath/docs/packet-flow-context.md
        # section 9 for the design rationale.
        netconf-vlan  = import ./nix/scenarios/netconf-vlan.nix  { inherit pkgs; };
        netconf-qinq  = import ./nix/scenarios/netconf-qinq.nix  { inherit pkgs; };
        netconf-vxlan = import ./nix/scenarios/netconf-vxlan.nix { inherit pkgs; };
        netconf-pppoe = import ./nix/scenarios/netconf-pppoe.nix { inherit pkgs; };
        netconf-mpls  = import ./nix/scenarios/netconf-mpls.nix  { inherit pkgs; };
        netconf-ipip  = import ./nix/scenarios/netconf-ipip.nix  { inherit pkgs; };

        # Phase 2 orchestrator: loops {pair × scenario × proto × sysctl},
        # composing the netconf-<scenario> scripts with iperf3 A/B cells
        # in the spirit of series3-soak-x86.nix. Emits matrix.csv.
        series3-extensions-soak = import ./nix/series3-extensions-soak.nix {
          inherit pkgs;
        };

        # 10-hour soak wrapper around series3-extensions-soak with
        # DUR=600 across 60 cells (3 pairs × 5 scenarios × 4 cells).
        # Goal: pin down recv_soft delta confidence intervals beyond
        # the ±0.3pp noise floor of the DUR=60 runs.
        series3-extensions-soak-10h = import ./nix/series3-extensions-soak-10h.nix {
          inherit pkgs;
        };

        # R1.1 — focused perf-record on the post-S _opt path of the
        # flow-dissector benchmark. Outputs land in result/perf-hp5/
        # so the run-on-host orchestrator's result rsync carries them
        # home. Defined late because it depends on
        # flowDissectorMatrix.artifacts (assigned further down).
        perfRecordR1 = import ./nix/perf-record-c-xdp2-r1.nix {
          inherit pkgs test-pcap;
          flow-dissector-matrix-artifacts = flowDissectorMatrix.artifacts;
        };

        perfRecordR7MonoVsRust = import ./nix/perf-record-r7-mono-vs-rust.nix {
          inherit pkgs;
          flow-dissector-matrix-artifacts = flowDissectorMatrix.artifacts;
          xdp2-rs = xdp2Rs.build;
          workload-pcap-vxlan-k8s-pure = perfAnalysis.workload-pcap-vxlan-k8s-pure;
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
          "--omi-cstructs-dir ${protoAuditSources.omiCStructs}"
          "--omi-lua-dir ${protoAuditSources.omiWiresharkLua}"
          "--omi-pcaps-dir ${protoAuditSources.omiDataPackets}"
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

        # Kernel-source static-analysis tools (sparse-master, smatch).
        # For vetting kernel-patches/ series before posting to netdev.
        # See nix/kernel-static-analysis.nix for usage.
        kernelStaticAnalysis = import ./nix/kernel-static-analysis.nix {
          inherit pkgs lib;
        };

        # iperf3 + iperf2 long-running soak runners for the testbed
        # pairs. See nix/testbed-soaks.nix for the parameter list and
        # usage examples.
        testbedSoaks = import ./nix/testbed-soaks.nix {
          inherit pkgs lib;
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
          super-flow-dissector-test = tests.super-flow-dissector;
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
          # ===================================================================
          # xdp2-flow-ebpf — production fast-path flow dissector bundle
          # Build:  nix build .#xdp2-flow-ebpf
          # Run:    sudo ./result/bin/xdp2-flow-loader \
          #             --bpf ./result/lib/xdp2-flow-ebpf/fast_flow.bpf.o
          # Layout: bin/xdp2-flow-loader + lib/xdp2-flow-ebpf/fast_flow.bpf.o
          #         + share/man/man1/xdp2-flow-loader.1
          #         + share/xdp2-flow-ebpf/xdp2-flow-loader.service
          # ===================================================================
          xdp2-flow-ebpf = xdp2FlowEbpf;

          # ===================================================================
          # xdp2-flow-ebpf-image — OCI container for k8s DaemonSet deploy
          # Build: nix build .#xdp2-flow-ebpf-image
          # Load:  docker load < result
          # ===================================================================
          xdp2-flow-ebpf-image = xdp2FlowEbpfImage;

          # ===================================================================
          # flow-dissector-matrix — 6-way performance comparison
          # Build:  nix build .#flow-dissector-matrix
          # Run:    sudo ./result/bin/xdp2-flow-dissector-matrix PCAP
          # Inputs: also exposes .#flow-dissector-matrix-artifacts (bins + .o)
          # ===================================================================
          flow-dissector-matrix = flowDissectorMatrix.matrix;
          flow-dissector-matrix-artifacts = flowDissectorMatrix.artifacts;
          # Clang-stdenv build for the R-followup compiler-comparison
          # experiment. Same parser.mono.c source (xdp2-compiler is
          # gcc-built either way), but clang-21 compiles the userspace
          # benchmark + the mono parser instead of gcc-15.
          flow-dissector-matrix-artifacts-clang =
            flowDissectorMatrix.artifacts-clang;

          # ===================================================================
          # flow-dissector-matrix-unified — C matrix + xdp2-bench,
          # same filtered pcap, one unified comparison table.
          # Build:  nix build .#flow-dissector-matrix-unified
          # Run:    sudo ./result/bin/xdp2-flow-dissector-matrix-unified [pcap]
          # ===================================================================
          flow-dissector-matrix-unified = flowDissectorMatrixUnified;

          # ===================================================================
          # flow-dissector-matrix-aggregate — Phase 6 aggregator over
          # the per-cell JSONs emitted by flow-dissector-matrix-unified
          # under -j <dir>. Emits summary.md / summary.csv and, when
          # --baseline is given, regressions.md.
          # Build:  nix build .#flow-dissector-matrix-aggregate
          # Run:    nix run .#flow-dissector-matrix-aggregate -- --results <dir>
          # ===================================================================
          flow-dissector-matrix-aggregate = flowDissectorMatrixAggregate;

          # ===================================================================
          # flow-dissector-afxdp-aggregate — Phase L4. Walks afxdp/<mode>/<size>b/
          # cell tree and emits summary-afxdp.{md,csv}. Separate from the matrix
          # aggregator because the two campaigns measure different things.
          # Build:  nix build .#flow-dissector-afxdp-aggregate
          # Run:    nix run .#flow-dissector-afxdp-aggregate -- --results <dir>
          # ===================================================================
          flow-dissector-afxdp-aggregate = flowDissectorAfxdpAggregate;

          # ===================================================================
          # flow-dissector-dump-asm — Phase A1. Per-impl asm extraction
          # across 8 Rust + 3 C + 3 BPF implementations. Output tree at
          # perf-results/asm/<date>/<impl>/disasm.asm + INDEX.md.
          # Build:  nix build .#flow-dissector-dump-asm
          # Run:    nix run .#flow-dissector-dump-asm -- [--out DIR] [--with-bpf-jit]
          # ===================================================================
          flow-dissector-dump-asm = flowDissectorDumpAsm;

          # ===================================================================
          # flow-dissector-matrix-run — Phase 7 composed runner.
          # Orchestrates flow-dissector-matrix-unified across the testbed
          # (via run-on-host) and aggregates results.
          # Run:  nix run .#flow-dissector-matrix-run -- \
          #         --testbed testbeds/<name>.toml [--smoke] [--results <dir>]
          # ===================================================================
          flow-dissector-matrix-run = flowDissectorMatrixRun;

          # ===================================================================
          # flow-dissector-matrix-sweep — multi-workload reproducibility
          # harness for the 2026-05-19 post-R3.4 sweep. Pre-scps each
          # cached workload-pcap-* derivation to every host in the
          # testbed TOML, loops calling matrix-run for each, and
          # aggregates at the end. Default workload list is all 6:
          #   https-web, nfs-server, k8s-microservices,
          #   vlan-tcp-mix, pppoe-isp, vxlan-k8s-pure.
          # Run:  nix run .#flow-dissector-matrix-sweep -- \
          #         --testbed testbeds/<name>.toml [--smoke]
          # See:  docs/r3.4-hp5-perf-targets.md
          # ===================================================================
          flow-dissector-matrix-sweep = flowDissectorMatrixSweep;

          # ===================================================================
          # flow-dissector-icache-sweep — perf-counter sweep for code-
          # size hypothesis investigation. Wraps `benchmark -p -<mode>`
          # in `perf stat -e l1-icache-load-misses,instructions,cycles,
          # branch-misses,iTLB-load-misses` for each (host, workload,
          # parser-mode) cell. Emits a markdown table with IPC and
          # miss/Mi columns. Requires perf_event_paranoid <= 1 or root.
          # Run:  nix run .#flow-dissector-icache-sweep -- \
          #         --testbed testbeds/<name>.toml [--workloads CSV] \
          #         [--modes M,O,S] [--iters N]
          # See:  perf-results/2026-05-19-O3-march-native-flto/comparison.md
          # ===================================================================
          flow-dissector-icache-sweep = flowDissectorIcacheSweep;

          # ===================================================================
          # flow-dissector-matrix-check — Phase 7 smoke regression gate.
          # Wraps -run --smoke with the aggregator's --baseline /
          # --fail-on-regression mode. Exits non-zero on any cell
          # regression. Designed for CI.
          # Run:  nix run .#flow-dissector-matrix-check -- \
          #         --testbed testbeds/<name>.toml [--baseline ...] [--threshold N]
          # ===================================================================
          flow-dissector-matrix-check = flowDissectorMatrixCheck;

          # ===================================================================
          # flow-dissector-afxdp-live — Phase 8 offered-load sweep.
          # Sweeps pktgen rates [1,2,5,10] Mpps against the testbed's
          # DUT (running xdp2-bench --mode af-xdp-template) and emits
          # per-load JSON under <results>/<date>/<testbed>/afxdp/.
          # Run:  nix run .#flow-dissector-afxdp-live -- \
          #         --testbed testbeds/<name>.toml [--duration N] [--loads CSV]
          # ===================================================================
          flow-dissector-afxdp-live = flowDissectorAfxdpLive;

          # ===================================================================
          # flow-dissector-parity-check — Phase 17 cross-parser parity gate.
          # Runs each of 14 flow-dissector parsers on a pcap with their
          # dump-meta path, captures per-packet ParityRecord JSONL, and
          # feeds the tree into the symmetric all-vs-all comparator at
          # nix/scripts/parity-compare.py. Catches the gaps the matrix
          # campaign masks: c-bpf-fast slow-path fall-through reported
          # as accepted, parser-specific extract bugs, scope drift.
          # Run:  nix run .#flow-dissector-parity-check -- --pcap PATH
          # See:  docs/flow-dissector-parity.md (Phase 17.D)
          # ===================================================================
          flow-dissector-parity-check = flowDissectorParityCheck;
          parity-compare = parityCompare;

          # ===================================================================
          # protocol-coverage-matrix — Phase 2 of the protocol coverage plan.
          # Runs flow-dissector-parity-check once per per-protocol pcap
          # template under samples/proto_audit/pcap_templates/ (378 single-
          # packet shapes) and aggregates the JSONL output into a
          # (protocol × parser) markdown + CSV matrix.
          # Run:  nix run .#protocol-coverage-matrix -- [--out DIR]
          # See:  nix/protocol-coverage-matrix.nix,
          #       nix/scripts/protocol-coverage-matrix.py
          # ===================================================================
          protocol-coverage-matrix = protocolCoverageMatrix;
          # Note: the existing `xdp2-rs-golden` flake output (defined at
          # line 920) is the natural place to alias to
          # flow-dissector-parity-check; that's a follow-up refactor
          # (Phase 17.D housekeeping) since it requires also updating
          # nix/xdp2-rs.nix's golden target definition.

          # ===================================================================
          # flow-dissector-ntuple-template-bench — live X710 Flow Director
          # + AF_XDP + template extraction. Two-host orchestration; the
          # target must have the xdp2.testbed physical-testbed module with
          # flowDirectorRules + realServicesBench configured.
          # Run:  nix run .#flow-dissector-ntuple-template-bench -- hp5 hp2
          # See:  docs/ntuple-template-bench.md
          # ===================================================================
          flow-dissector-ntuple-template-bench = flowDissectorNtupleTemplateBench;

          # Standalone peer-side kernel pktgen driver (shellchecked).
          # Build:  nix build .#flow-dissector-pktgen-ntuple-template
          # Normally consumed by flow-dissector-ntuple-template-bench,
          # but exposed here for inspection / direct deployment.
          flow-dissector-pktgen-ntuple-template =
            flowDissectorPktgenNtupleTemplate;

          # Deliverable-2: DPDK-pktgen variants.
          # flow-dissector-pktgen-dpdk-ntuple-template — peer-side DPDK
          #   pktgen driver (same CLI as the kernel variant).
          # flow-dissector-dpdk-ntuple-template-bench — dev-box
          #   orchestrator wrapping the DPDK driver.
          # Requires the peer to have xdp2.testbed.dpdkBenchHost = true.
          # Run:  nix run .#flow-dissector-dpdk-ntuple-template-bench -- hp5 hp2
          flow-dissector-pktgen-dpdk-ntuple-template =
            flowDissectorPktgenDpdkNtupleTemplate;
          flow-dissector-dpdk-ntuple-template-bench =
            flowDissectorDpdkNtupleTemplateBench;

          # ===================================================================
          # Deliverable-1 pktgen TX-cap diagnostic experiments.
          # Each target twists one tunable vs baseline and lands a
          # summary.json in perf-results/<target>/exp-<name>-<ts>/.
          # See docs/physical-testbed.md §9 Category H + §13.
          # Run:  nix run .#xdp2-exp-pktgen-<variant> -- hp5 hp2
          # ===================================================================
          xdp2-exp-pktgen-baseline = mkBenchExperiment {
            name = "xdp2-exp-pktgen-baseline";
            description = ''
              Regression check: today's defaults unchanged. Proves the
              experiment wrapper doesn't itself perturb the measurement.
            '';
            expectation = "RX ~1.37 Mpps at 64B/6T (within run-to-run noise).";
            envVars = { };
            benchArgs = "-d 30 -s 64 -t 6";
          };

          xdp2-exp-pktgen-burst-32 = mkBenchExperiment {
            name = "xdp2-exp-pktgen-burst-32";
            description = ''
              Hypothesis: kernel pktgen defaults to burst=1, so each
              kpktgend wake sends exactly one packet. burst=32
              amortises softirq overhead and should lift TX if the
              ceiling is softirq-bound.
            '';
            expectation = "TX ≥ 3 Mpps if the softirq-per-packet cost dominates.";
            envVars = { PKTGEN_BURST = "32"; };
            benchArgs = "-d 30 -s 64 -t 6";
          };

          xdp2-exp-pktgen-queue-map = mkBenchExperiment {
            name = "xdp2-exp-pktgen-queue-map";
            description = ''
              Hypothesis: without queue_map_min/max, multiple pktgen
              threads collide on a single X710 TX ring. Pinning each
              thread to its own TX queue should fan the load out
              deterministically across the NIC's TX rings.
            '';
            expectation = "TX ≥ 6 Mpps if (burst=32)+(per-thread TX queues) clears the cap.";
            envVars = {
              PKTGEN_BURST = "32";
              PKTGEN_QUEUE_MAP_MODE = "per-thread";
            };
            benchArgs = "-d 30 -s 64 -t 6";
          };

          xdp2-exp-pktgen-cpu-pin = mkBenchExperiment {
            name = "xdp2-exp-pktgen-cpu-pin";
            description = ''
              Hypothesis: kpktgend_0..5 float on housekeeping CPUs 0/1
              where sshd + nix-daemon live. Shifting to isolcpus-aligned
              starts binding at kpktgend_''${PKTGEN_CPU_OFFSET:-2} so the
              generator runs only on isolated cores.
            '';
            expectation = "Marginal Mpps gain (≤5%) or jitter reduction vs queue-map alone.";
            envVars = {
              PKTGEN_BURST = "32";
              PKTGEN_QUEUE_MAP_MODE = "per-thread";
              PKTGEN_CPU_PIN_MODE = "isolcpus-aligned";
            };
            benchArgs = "-d 30 -s 64 -t 6";
          };

          xdp2-exp-pktgen-cloneskb-zero = mkBenchExperiment {
            name = "xdp2-exp-pktgen-cloneskb-zero";
            description = ''
              Diagnostic: does clone_skb 100000 actually help? clone_skb
              reuses the skb buffer; if the bottleneck is TX descriptor
              recycling on i40e rather than skb alloc, this is
              irrelevant. clone_skb=0 forces a fresh skb per packet.
              Regression vs baseline proves skb reuse matters.
            '';
            expectation = "TX drop vs baseline if skb reuse is load-bearing; flat if not.";
            envVars = { PKTGEN_CLONE_SKB = "0"; };
            benchArgs = "-d 30 -s 64 -t 6";
          };

          # ===================================================================
          # Deliverable-3 AF_XDP RX-drop diagnostic experiments.
          # The 7.8% RX drop at 1.37 Mpps + xdpdrv + ZC + busy-poll is
          # currently unattributed — these four wrappers each flip one
          # AF_XDP/kernel knob so the drop's root cause is bisectable.
          # See docs/physical-testbed.md §13 Future-work + Appendix A #10.
          # Run:  nix run .#xdp2-exp-afxdp-<variant> -- hp5 hp2
          # ===================================================================
          xdp2-exp-afxdp-rings-baseline = mkBenchExperiment {
            name = "xdp2-exp-afxdp-rings-baseline";
            description = ''
              Regression check for the D3 series: crate defaults unchanged
              (rx=2048, fill=2048, frames=4096). Produces the reference
              drop% that every other D3 experiment is compared against.
            '';
            expectation = "Drop ≈ 7.8% at 1.37 Mpps (matches the §13 baseline).";
            envVars = { };
            benchArgs = "-d 30 -s 64 -t 6";
          };

          xdp2-exp-afxdp-rings-large = mkBenchExperiment {
            name = "xdp2-exp-afxdp-rings-large";
            description = ''
              Hypothesis (ranked #1 in the plan): the default fill ring
              (2048) + lazy refill at xdp2-bench/src/af_xdp.rs drains on
              any stall at 1.37 Mpps + busy-poll latency. Doubling rx/
              fill to 4096 and bumping frame_count to 16384 gives four
              times the headroom. UMEM footprint rises 16 → 64 MiB —
              negligible on hp5 (64 GiB RAM).
            '';
            expectation = "Drop approaches 0% if ring sizing is the bottleneck.";
            envVars = {
              RX_RING = "4096";
              FILL_RING = "4096";
              FRAME_COUNT = "16384";
            };
            benchArgs = "-d 30 -s 64 -t 6";
          };

          xdp2-exp-afxdp-busypoll-100 = mkBenchExperiment {
            name = "xdp2-exp-afxdp-busypoll-100";
            description = ''
              Hypothesis #3: the 50µs busy-poll budget lets the kernel
              fall back to NAPI-interrupt mode between bursts, adding
              fill-ring refill latency. Doubling to 100µs keeps the
              kernel in busy-poll longer. Independent of ring sizing —
              leave RX/FILL/FRAME_COUNT at defaults so this isolates
              the busy-poll knob.
            '';
            expectation = "Modest drop reduction if busy-poll gap is the bottleneck.";
            envVars = { BUSY_POLL_US = "100"; };
            benchArgs = "-d 30 -s 64 -t 6";
          };

          xdp2-exp-afxdp-netdev-budget = mkBenchExperiment {
            name = "xdp2-exp-afxdp-netdev-budget";
            description = ''
              Hypothesis #4: softirq NAPI budget (default 300) caps how
              many packets the kernel moves per softirq dispatch. This
              experiment requires the hp5 host to already be running
              the physical-testbed module with net.core.netdev_budget=600
              (introduced in C4 as a mkDefault sysctl). The experiment
              itself sets no env vars — it verifies the host-side bump
              lands and the change is measurable. If hp5 still has 300,
              the result will match the baseline; rebuild hp5 first.
            '';
            expectation = "Modest drop reduction if softirq budget is the bottleneck.";
            envVars = { };
            benchArgs = "-d 30 -s 64 -t 6";
          };

          # ===================================================================
          # Deliverable-2 DPDK-pktgen experiments. These bypass the
          # kernel pktgen TX cap by taking over the peer's NIC with
          # vfio-pci + DPDK userspace TX. Target side is unchanged.
          # Requires hp2 (peer) to have xdp2.testbed.dpdkBenchHost=true
          # for vfio-pci + 1024×2MB hugepages at boot. See
          # docs/physical-testbed.md §13 Future work / Deliverable 2.
          # Run:  nix run .#xdp2-exp-dpdk-<variant> -- hp5 hp2
          # ===================================================================
          xdp2-exp-dpdk-baseline = mkBenchExperiment {
            name = "xdp2-exp-dpdk-baseline";
            description = ''
              Hypothesis: kernel pktgen on hp2/i40e is capped at
              ~1.37 Mpps regardless of tuning (validated across D1's
              five experiments). DPDK userspace TX via vfio-pci should
              exceed that ceiling because it bypasses the kernel
              softirq path entirely. Default lcore layout (1 main + 2
              worker) — just prove the pipeline works end-to-end.
            '';
            expectation = "TX ≥ 5 Mpps at 64B if i40e PMD supports it on this NIC.";
            envVars = { };
            benchArgs = "-d 30 -s 64 -t 2";
            benchTool = flowDissectorDpdkNtupleTemplateBench;
            benchBin = "xdp2-flow-dissector-dpdk-ntuple-template-bench";
          };

          xdp2-exp-dpdk-multi-lcore = mkBenchExperiment {
            name = "xdp2-exp-dpdk-multi-lcore";
            description = ''
              Hypothesis: a single DPDK TX lcore is PCIe-descriptor-
              bound on the X710 single TX ring. Fanning out to 4
              worker lcores spread across TX rings should approach the
              40 GbE line rate at 64B (~59 Mpps). The peer-side driver
              maps lcores via the EAL -l flag and assigns 4 workers to
              port 0 via the PKTGEN_DPDK_LCORES override.
            '';
            expectation = "TX approaches line rate if the single-lcore ceiling is descriptor-bound.";
            envVars = {
              PKTGEN_DPDK_LCORES = "0@0,1@1,2@2,3@3,4@4";
            };
            benchArgs = "-d 30 -s 64 -t 4";
            benchTool = flowDissectorDpdkNtupleTemplateBench;
            benchBin = "xdp2-flow-dissector-dpdk-ntuple-template-bench";
          };

          # Build-time execution smoke — runs the matrix against an
          # in-tree PCAP and captures results to $out/matrix.txt. Ways
          # 4–6 degrade to N/A in the sandbox (no CAP_BPF); ways 1–3
          # must produce ns/pkt timings or the build fails.
          flow-dissector-matrix-smoke = import ./nix/flow-dissector-matrix-smoke.nix {
            inherit pkgs;
            matrix = flowDissectorMatrix.matrix;
          };

          xdp2-rs = xdp2Rs.build;
          xdp2-rs-test = xdp2Rs.test;
          xdp2-rs-test-graph-enum = xdp2Rs.test-graph-enum;
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
          # Option A:   nix run .#perf-graph-enum-compare
          # All:        nix run .#perf-analysis-all
          # Mixed PCAP: nix build .#perf-mixed-pcap
          # ===================================================================
          perf-sweep-tcp = perfAnalysis.sweep-tcp;
          perf-sweep-mixed = perfAnalysis.sweep-mixed;
          perf-sweep-combo = perfAnalysis.sweep-combo;
          perf-flamegraph = perfAnalysis.flamegraph;
          perf-annotate = perfAnalysis.annotate;
          # A/B comparison for the graph-enum (Option A) experiment:
          # runs cargo test + bench + flamegraph for graph / graph-enum / compiled
          # on tcp_ipv4.pcap. Output: perf-results/graph-enum/
          perf-graph-enum-compare = perfAnalysis.graph-enum-compare;
          # R1.1 — focused perf-record + annotate on c-xdp2-usp's _opt
          # vs _generic path. Invoked via run-on-host on hp5.
          perf-record-c-xdp2-r1 = perfRecordR1;
          perf-record-r7-mono-vs-rust = perfRecordR7MonoVsRust;
          # Chain-signature histogram probe (fast-path exploration, step 1).
          # Single PCAP: nix run .#chain-histogram -- <pcap> [top-n]
          # All 3 refs:  nix run .#chain-histogram-all
          chain-histogram = perfAnalysis.chain-histogram;
          chain-histogram-all = perfAnalysis.chain-histogram-all;
          perf-analysis-all = perfAnalysis.analysis-all;
          perf-mixed-pcap = perfAnalysis.mixed-pcap;

          # Workload PCAPs — realistic deployment traffic mixes
          # Cached builds:
          #   nix build .#workload-pcap-https-web
          #   nix build .#workload-pcap-nfs-server
          #   nix build .#workload-pcap-k8s-microservices
          # Interactive generator:
          #   nix run .#gen-workload-pcap -- --list
          #   nix run .#gen-workload-pcap -- --workload https-web -n 50000 -o /tmp/x.pcap
          # Chain-histogram over the three workload PCAPs:
          #   nix run .#chain-histogram-workloads
          # Perf sweeps:
          #   nix run .#sweep-workload-https-web
          #   nix run .#sweep-workload-nfs-server
          #   nix run .#sweep-workload-k8s
          #   nix run .#sweep-workloads-all
          workload-pcap-https-web        = perfAnalysis.workload-pcap-https-web;
          workload-pcap-nfs-server       = perfAnalysis.workload-pcap-nfs-server;
          workload-pcap-k8s-microservices = perfAnalysis.workload-pcap-k8s-microservices;
          # Post-R3.4 (2026-05-19) — see docs/r3.4-hp5-perf-targets.md.
          workload-pcap-vlan-tcp-mix     = perfAnalysis.workload-pcap-vlan-tcp-mix;
          workload-pcap-pppoe-isp        = perfAnalysis.workload-pcap-pppoe-isp;
          workload-pcap-vxlan-k8s-pure   = perfAnalysis.workload-pcap-vxlan-k8s-pure;
          # Series-3 controlled-ratio mixes (2026-06-10) — used by
          # perf-results/2026-06-10-series3-controlled-mix/ to plot
          # ns/pkt vs fast-path-eligible fraction p.
          workload-pcap-series3-fast-vs-slow-10 = perfAnalysis.workload-pcap-series3-fast-vs-slow-10;
          workload-pcap-series3-fast-vs-slow-25 = perfAnalysis.workload-pcap-series3-fast-vs-slow-25;
          workload-pcap-series3-fast-vs-slow-50 = perfAnalysis.workload-pcap-series3-fast-vs-slow-50;
          workload-pcap-series3-fast-vs-slow-75 = perfAnalysis.workload-pcap-series3-fast-vs-slow-75;
          workload-pcap-series3-fast-vs-slow-90 = perfAnalysis.workload-pcap-series3-fast-vs-slow-90;
          gen-workload-pcap              = perfAnalysis.gen-workload-pcap;
          chain-histogram-workloads      = perfAnalysis.chain-histogram-workloads;
          sweep-workload-https-web       = perfAnalysis.sweep-workload-https-web;
          sweep-workload-nfs-server      = perfAnalysis.sweep-workload-nfs-server;
          sweep-workload-k8s             = perfAnalysis.sweep-workload-k8s;
          sweep-workloads-all            = perfAnalysis.sweep-workloads-all;

          # Protocol coverage verification
          # nix run .#coverage-check         — acceptance rate + chain histogram
          # nix run .#coverage-check-all     — acceptance rate on all PCAPs
          coverage-check     = coverageCheck.check;
          coverage-check-all = coverageCheck.check-all;

          # Generate combinatorial test PCAPs
          # nix run .#gen-test-pcap -- -n 500000 -o /tmp/combo.pcap
          # nix build .#test-pcap  → result/combo.pcap (500k packets, cached)
          inherit gen-test-pcap test-pcap;

          # Run all sample tests in one go
          # Usage: nix run .#run-sample-tests
          inherit run-sample-tests;

          # Physical-testbed runner: drive nix targets on hp2/hp5 via
          # rsync+ssh. See docs/physical-testbed.md §9.
          # Usage: nix run .#run-on-host -- hp5 -- xdp2-rs-test
          inherit run-on-host;

          # Series 3 flow_dissector fast-path A/B harnesses.
          # See nix/series3-traffic-ab.nix and nix/series3-microbench.nix
          # for the wrappers; the canonical input/output shape they
          # implement is documented in
          # perf-results/2026-06-09-series3-arm-microbench/results.md
          # (microbench) and
          # perf-results/2026-06-09-series3-cross-uarch/ (traffic A/B).
          inherit series3-traffic-ab;
          inherit series3-microbench;
          inherit series3-pcap-microbench;
          inherit series3-soak;
          # x86 25 GbE soak for the l <-> l2 pair. Usage:
          #   L2_V4=10.10.4.5 L2_V6=fd10:10:4::5 \
          #     nix run .#series3-soak-l-l2
          #   DUR=60 COOLDOWN=10 L2_V4=10.10.4.5 nix run .#series3-soak-l-l2  # smoke
          inherit series3-soak-l-l2;

          # Network-config scenarios for the series3 extension patches.
          # Usage:
          #   OP=up L=l L2=l2 GEN_DEV=enp35s0f0np0 DUT_DEV=enp35s0f0np0 \
          #     nix run .#netconf-vlan
          #   (symmetric: netconf-qinq, netconf-vxlan, netconf-pppoe,
          #              netconf-mpls, netconf-ipip)
          # See nix/scenarios/lib.sh and kernel-patches/series3-
          # flowdis-fastpath/docs/packet-flow-context.md §9.
          inherit netconf-vlan;
          inherit netconf-qinq;
          inherit netconf-vxlan;
          inherit netconf-pppoe;
          inherit netconf-mpls;
          inherit netconf-ipip;

          # Phase 2 orchestrator for the extension-patches scenario
          # matrix. Usage:
          #   PAIRS=pi5-pair SCENARIOS=vlan DUR=10 \
          #     nix run .#series3-extensions-soak
          inherit series3-extensions-soak;

          # 10-hour soak across the v4 testbed fleet — same matrix
          # shape as series3-extensions-soak but with DUR=600 to nail
          # per-cell recv_soft confidence intervals beyond the
          # ±0.3pp DUR=60 noise floor. Usage:
          #   nix run .#series3-extensions-soak-10h
          inherit series3-extensions-soak-10h;

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
          # Kernel-patch static analysis
          # See: nix/kernel-static-analysis.nix
          # Usage:
          #   nix build .#sparse-master   # sparse from upstream master
          #   nix build .#kernel-smatch   # Dan Carpenter's smatch
          #   nix run   .#kernel-check -- /path/to/kernel-tree net/core/file.o
          # ===================================================================
          sparse-master = kernelStaticAnalysis.sparseMaster;
          kernel-smatch = kernelStaticAnalysis.smatch;
          kernel-check = kernelStaticAnalysis.kernelCheck;

          # ===================================================================
          # Testbed soak runners (24h iperf3, 24h iperf2)
          # See: nix/testbed-soaks.nix
          # Usage:
          #   PAIR=hp2-hp5-x710 GEN=hp2 DUT=hp5 \
          #     DUT_IP4=10.10.0.5 DEV=enp1s0f0np0 BANDWIDTH=10Gbit \
          #     DURATION=86400 nix run .#soak-iperf3
          # ===================================================================
          soak-iperf3 = testbedSoaks.soakIperf3;
          soak-iperf2 = testbedSoaks.soakIperf2;

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

        # Pure-Nix evaluation checks. Picked up by `nix flake check`.
        checks = {
          # Synthetic NixOS evaluation of the nic-tuning module:
          # asserts that `i40e` produces the expected per-interface
          # systemd units, and that `mlx5_core` (not yet implemented)
          # produces no tune services and a warning.
          nic-tuning-eval = import ./nix/modules/tests/nic-tuning-eval-test.nix {
            inherit pkgs lib;
          };

          # Per-cell JSON schema regression gate for the unified
          # flow-dissector matrix runner. Catches accidental drift in
          # the `--json-out` printf template (xdp2-rs-matrix.nix and
          # the standalone shell script).
          matrix-runner-json-shape = import ./nix/checks/matrix-runner-json-shape.nix {
            inherit pkgs lib;
          };

          # End-to-end check for the Phase-6 aggregator:
          # builds a synthetic Phase-5 result tree, runs the aggregator,
          # validates summary/regressions outputs and the baseline-
          # incomplete error path.
          aggregate-results = import ./nix/checks/aggregate-results-test.nix {
            inherit pkgs lib;
          };

          # Phase 7 wiring check: builds the public matrix-run /
          # matrix-check wrappers and asserts that --help, missing-
          # required-arg, and bogus-path code paths behave as
          # documented. Behavioral regression detection is covered
          # by the aggregate-results check above.
          matrix-check-smoke = import ./nix/checks/matrix-check-smoke.nix {
            inherit pkgs lib;
            matrixRun = flowDissectorMatrixRun;
            matrixCheck = flowDissectorMatrixCheck;
          };

          # Phase 8 wiring check: builds flow-dissector-afxdp-live and
          # exercises --help, missing-arg, bogus-path, bad-duration,
          # bad-loads, and missing-generator error paths. Live AF_XDP
          # sweep is hardware-bound and exercised in a hardware
          # session.
          afxdp-live-smoke = import ./nix/checks/afxdp-live-smoke.nix {
            inherit pkgs lib;
            afxdpLive = flowDissectorAfxdpLive;
          };

          # Phase 17 cross-parser parity gate: runs flow-dissector-parity-check
          # against a small synthetic corpus (4 protocol-specific PCAPs)
          # with 12 of 14 parsers — c-bpf-flowdis and c-bpf-fast are
          # excluded because Nix's sandbox doesn't grant CAP_BPF for
          # BPF_PROG_TEST_RUN. c-bpf-xdp2 is included (synthesised as
          # all-rejected per its documented verifier-rejection
          # divergence). Asserts zero unexpected disagreements;
          # tripping the gate means a parser's extracted FlowMeta drifted.
          parity-gate = import ./nix/checks/parity-gate.nix {
            inherit pkgs lib;
            parityCheck = flowDissectorParityCheck;
          };

          # Phase 4 of the protocol-coverage-matrix plan: gates flake
          # check on a curated 33-protocol subset of
          # samples/proto_audit/pcap_templates. Subset is declared in
          # parity_scope.json (`protocol_coverage_smoke_subset`) and
          # exercised via the protocol-coverage-matrix Nix driver with
          # --require-expectations. Today's matrix has zero
          # REJ-unexpected cells on the subset; a future regression
          # (parser silently changes its acceptance for any subset
          # protocol) fails this check.
          protocol-coverage-smoke = import ./nix/checks/protocol-coverage-smoke.nix {
            inherit pkgs lib;
            coverageMatrix = protocolCoverageMatrix;
          };
        };
      }) // (
        let
          # System-independent outputs reuse nixpkgs.lib directly.
          lib = nixpkgs.lib;
          testbedLib = import ./nix/testbed-config.nix { inherit lib; };
          testbedAdapter = import ./nix/modules/testbed-config-adapter.nix { inherit lib; };
        in
        {
          # ---- System-independent outputs ----

          # NixOS module for physical benchmark hosts (hp2, hp5, replicas).
          # See docs/physical-testbed.md §5–§6 for the full option set.
          # Consumer:
          #   imports = [ inputs.xdp2.nixosModules.physical-testbed ];
          #   xdp2.testbed = {
          #     enable = true;
          #     peerInterfaces = [ "enp1s0f0np0" "enp1s0f1np1" ];
          #     addresses = {
          #       enp1s0f0np0 = { local = "10.10.0.5/29"; peer = "10.10.0.2"; };
          #       enp1s0f1np1 = { local = "10.10.1.5/29"; peer = "10.10.1.2"; };
          #     };
          #     isolatedCpus = [ 2 3 4 5 6 7 ];
          #     hugepages2M = 512;
          #   };
          nixosModules.physical-testbed = ./nix/modules/physical-testbed.nix;

          # NixOS module for NIC-driver-aware data-plane tuning (ethtool,
          # queues, IRQ affinity, Flow Director). Imported automatically
          # by physical-testbed.nix; can also be imported standalone for
          # hosts that don't need the full testbed treatment.
          # See nix/modules/nic-tuning.nix for the option surface.
          nixosModules.nicTuning = ./nix/modules/nic-tuning.nix;

          # NixOS module: apply the series3 fast-path extension patches
          # (single VLAN, QinQ, optionally VXLAN-inner) on top of the
          # host's existing kernel. See nix/modules/flowdis-fastpath-
          # extensions.nix for the option surface and consumer doc.
          # Consumer:
          #   imports = [ inputs.xdp2.nixosModules.flowdisFastpathExtensions ];
          #   xdp2.flowdisFastpathExtensions.enable = true;
          # Then: sudo nixos-rebuild boot && sudo reboot
          nixosModules.flowdisFastpathExtensions =
            ./nix/modules/flowdis-fastpath-extensions.nix;

          # ---- Testbed configurations ----
          #
          # Each *.toml in ./testbeds/ is loaded and validated by
          # nix/testbed-config.nix. Schema is documented in
          # docs/flow-dissector-matrix-physical-testbed.md §3.
          #
          # Inspect:
          #   nix eval .#testbedConfigs.hp2-hp5-x710.nic.driver
          #   nix eval .#testbedConfigs.hp2-hp5-x710.hosts.dut.hostname
          testbedConfigs = testbedLib.loadAll ./testbeds;

          # Helpers for downstream consumers (NixOS host configs,
          # Phase 2 adapter).
          lib = {
            inherit (testbedLib) loadTestbedConfig loadAll;
            # Adapter: lowers a testbed-config onto xdp2.testbed.*
            # options for a given host role.
            inherit (testbedAdapter) testbedConfigToModule parseCpuRange;
            # Pure-Nix unit tests for the adapter (CPU-range parser
            # round-trips). Evaluation throws on failure.
            testbedConfigAdapterTests = testbedAdapter.tests;
          };
        }
      );
}
