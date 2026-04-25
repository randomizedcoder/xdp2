# SPDX-License-Identifier: BSD-2-Clause-FreeBSD
#
# Live X710 ntuple + AF_XDP + template bench orchestrator — DPDK variant.
#
# Parallel to nix/ntuple-template-bench.nix. Only the peer-side
# traffic generator differs: this wrapper exports PKTGEN_SCRIPT
# pointing at the DPDK pktgen driver instead of the kernel pktgen
# driver. The target-side pipeline (XDP attach, FD rules, AF_XDP) is
# unchanged — DPDK only takes over the PEER's NIC.
#
# The peer-side DPDK driver implements the same start/stop/status CLI
# contract as pktgen_ntuple_template.sh (see its header comment for
# why). That lets run_ntuple_template_bench.sh drive either by
# swapping one env var instead of duplicating the orchestration logic.
#
# Invoke as:
#   nix run .#flow-dissector-dpdk-ntuple-template-bench -- <target> <peer>
#
# See docs/physical-testbed.md §13 Future work / Deliverable 2 for the
# rationale (kernel pktgen ~1.37 Mpps TX cap at 64B on hp2/i40e).

{ pkgs, xdpSamples, pktgenDpdkDriver }:

pkgs.writeShellApplication {
  name = "xdp2-flow-dissector-dpdk-ntuple-template-bench";

  runtimeInputs = [
    pkgs.openssh
    pkgs.coreutils
    pkgs.gawk
    pkgs.gnugrep
    pkgs.gnused
  ];

  text = ''
    # Wire the bundled BPF object — target-side pipeline is identical
    # to the kernel-pktgen orchestrator.
    export XDP_OBJ="${xdpSamples}/lib/xdp/af_xdp_parser.xdp.o"
    if [[ ! -f "$XDP_OBJ" ]]; then
      echo "ERROR: af_xdp_parser.xdp.o not in xdp-samples output ($XDP_OBJ)" >&2
      exit 7
    fi
    # Swap the peer-side driver: DPDK instead of kernel pktgen.
    # Same start/stop/status CLI, so run_ntuple_template_bench.sh can
    # orchestrate without knowing which traffic generator is in use.
    export PKTGEN_SCRIPT="${pktgenDpdkDriver}/bin/xdp2-pktgen-dpdk-ntuple-template"
    if [[ ! -f "$PKTGEN_SCRIPT" ]]; then
      echo "ERROR: DPDK pktgen driver not found at $PKTGEN_SCRIPT" >&2
      exit 8
    fi

    ${builtins.readFile ../samples/flow_dissector/run_ntuple_template_bench.sh}
  '';
}
