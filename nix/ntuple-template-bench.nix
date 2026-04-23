# SPDX-License-Identifier: BSD-2-Clause-FreeBSD
#
# Live X710 ntuple + AF_XDP + template bench wrapper.
#
# Wraps samples/flow_dissector/run_ntuple_template_bench.sh with the
# right runtime tools (openssh + coreutils) so it's invocable as:
#
#   nix run .#flow-dissector-ntuple-template-bench -- <target> <peer>
#
# The script itself orchestrates over SSH: verifies Flow Director
# rules + nginx on the target, spins up wrk2 + ssh -N on the peer,
# runs `xdp2-bench --mode af-xdp-template` on the target, and pulls
# per-queue results back to perf-results/${target}/.
#
# See docs/ntuple-template-bench.md for the measurement model and
# samples/flow_dissector/docs/benchmarks.md for where results land.

{ pkgs, xdpSamples }:

pkgs.writeShellApplication {
  name = "xdp2-flow-dissector-ntuple-template-bench";

  runtimeInputs = [
    pkgs.openssh
    pkgs.coreutils
    pkgs.gawk
    pkgs.gnugrep
  ];
  # Target-host tools (bpftool, ethtool, ip) are declared in Nix at a
  # different layer: nix/modules/physical-testbed.nix adds pkgs.bpftools,
  # pkgs.ethtool and the kernel's perf to environment.systemPackages when
  # installEthtool = true (default). That's why this wrapper only lists
  # dev-box tools — all bpftool/ethtool/ip invocations in the script run
  # via ssh on the target, resolving against the target's systemPackages.

  text = ''
    script="${../samples/flow_dissector/run_ntuple_template_bench.sh}"
    # Point the orchestrator at the bundled BPF object. The script will
    # scp it to the target and load it with `ip link set xdpgeneric`.
    export XDP_OBJ="${xdpSamples}/lib/xdp/af_xdp_parser.xdp.o"
    if [[ ! -f "$XDP_OBJ" ]]; then
      echo "ERROR: af_xdp_parser.xdp.o not in xdp-samples output ($XDP_OBJ)" >&2
      echo "  This is a Nix build bug — rebuild with: nix build .#xdp-samples" >&2
      exit 7
    fi
    exec bash "$script" "$@"
  '';
}
