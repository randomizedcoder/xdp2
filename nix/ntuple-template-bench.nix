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

{ pkgs }:

pkgs.writeShellApplication {
  name = "xdp2-flow-dissector-ntuple-template-bench";

  runtimeInputs = [
    pkgs.openssh
    pkgs.coreutils
    pkgs.gawk
    pkgs.gnugrep
  ];

  text = ''
    script="${../samples/flow_dissector/run_ntuple_template_bench.sh}"
    exec bash "$script" "$@"
  '';
}
