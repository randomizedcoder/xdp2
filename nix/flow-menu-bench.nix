# nix/flow-menu-bench.nix
#
# Benchmark + Gold-parity harness for the per-encapsulation
# xdp2-flow-ebpf menu (kernel-patches/series6-common-case/ebpf-menu.md).
#
# Builds benchmark_bpf, parity_test, the in-tree bpf_flow.kern.o oracle
# and the ten fast_flow_<encap>.bpf.o menu objects in one hermetic
# sandbox, bakes a normalised per-shape corpus, and wraps
# samples/flow_dissector/fast_bpf/bench_menu.sh with those paths.
#
# BPF_PROG_TEST_RUN needs root/CAP_BPF, so run on a testbed host:
#   nix run .#run-on-host -- l2 -- flow-menu-bench
# or locally under sudo:
#   sudo $(nix build --no-link --print-out-paths .#flow-menu-bench)/bin/xdp2-flow-menu-bench
#
# Mirrors nix/flow-dissector-matrix.nix's artifacts recipe (same
# NIX_HARDENING_ENABLE= / XDP2DIR conventions), but builds only the menu
# targets — no XDP2-compiler codegen path.

{ pkgs
, xdp2
, llvmPackages
}:

let
  lib = pkgs.lib;
  srcRoot = ../samples/flow_dissector;

  shapes = [ "eth_ip" "vlan" "qinq" "mpls" "ipip" "gre" "pppoe"
             "vxlan" "geneve" "gtpu" ];
  menuObjs = lib.concatMapStringsSep " "
    (s: "fast_bpf/fast_flow_${s}.bpf.o") shapes;

  # Normalised per-shape corpus: <shape>.pcap. BPF_PROG_TEST_RUN repeats
  # each packet, so single-packet templates give a stable ns/pkt.
  corpus = pkgs.runCommand "xdp2-flow-menu-corpus" { } ''
    mkdir -p $out
    cp ${../data/pcaps/tcp_ipv4.pcap}                        $out/eth_ip.pcap
    cp ${../samples/proto_audit/pcap_templates/vlan.pcap}    $out/vlan.pcap
    cp ${../data/pcaps/QinQ.pcap}                            $out/qinq.pcap
    cp ${../samples/proto_audit/pcap_templates/mpls.pcap}    $out/mpls.pcap
    cp ${../data/pcaps/ipip.pcap}                            $out/ipip.pcap
    cp ${../data/pcaps/gre-sample.pcap}                      $out/gre.pcap
    cp ${../samples/proto_audit/pcap_templates/pppoe.pcap}   $out/pppoe.pcap
    cp ${../data/pcaps/vxlan.pcap}                           $out/vxlan.pcap
    cp ${../samples/proto_audit/pcap_templates/geneve.pcap}  $out/geneve.pcap
    cp ${../samples/proto_audit/pcap_templates/gtp_u.pcap}   $out/gtpu.pcap
  '';

  artifacts = pkgs.stdenv.mkDerivation {
    pname = "xdp2-flow-menu-artifacts";
    version = xdp2.version or "0.1.0";
    src = srcRoot;

    nativeBuildInputs = [ pkgs.gnumake llvmPackages.clang ];
    buildInputs = [
      pkgs.libpcap pkgs.libpcap.lib pkgs.libbpf pkgs.elfutils
      pkgs.zlib pkgs.linuxHeaders
    ];

    hardeningDisable = [ "all" ];
    NIX_HARDENING_ENABLE = "";
    NIX_ENFORCE_NO_NATIVE = "";

    buildPhase = ''
      runHook preBuild
      export PATH="${xdp2}/bin:$PATH"

      make XDP2DIR=${xdp2} XDP2_SRCDIR=${xdp2} \
           benchmark_bpf fast_bpf/parity_test bpf_flow.kern.o ${menuObjs}

      for f in benchmark_bpf fast_bpf/parity_test bpf_flow.kern.o \
               ${menuObjs}; do
        test -s "$f" || { echo "empty artifact: $f"; exit 1; }
      done
      runHook postBuild
    '';

    installPhase = ''
      runHook preInstall
      mkdir -p $out/bin $out/lib/xdp2-flow-menu
      install -m 755 benchmark_bpf        $out/bin/
      install -m 755 fast_bpf/parity_test $out/bin/parity_test
      install -m 755 fast_bpf/bench_menu.sh $out/bin/bench_menu.sh
      patchShebangs $out/bin/bench_menu.sh
      install -m 644 bpf_flow.kern.o      $out/lib/xdp2-flow-menu/
      for s in ${lib.concatStringsSep " " shapes}; do
        install -m 644 "fast_bpf/fast_flow_$s.bpf.o" $out/lib/xdp2-flow-menu/
      done
      runHook postInstall
    '';

    meta = {
      description = "xdp2-flow-ebpf menu benchmark artifacts (10 objects + oracle)";
      platforms = lib.platforms.linux;
    };
  };
in
pkgs.writeShellApplication {
  name = "xdp2-flow-menu-bench";
  runtimeInputs = [ pkgs.coreutils pkgs.gnugrep pkgs.bash artifacts ];
  text = ''
    export BENCHMARK_BPF="${artifacts}/bin/benchmark_bpf"
    export PARITY_TEST="${artifacts}/bin/parity_test"
    export OBJDIR="${artifacts}/lib/xdp2-flow-menu"
    export CORPUS="${corpus}"
    export BPF_REPEAT="''${BPF_REPEAT:-1000}"
    exec bash ${artifacts}/bin/bench_menu.sh "$@"
  '';
}
