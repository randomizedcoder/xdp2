# SPDX-License-Identifier: BSD-2-Clause-FreeBSD
#
# Live X710 ntuple + AF_XDP + template bench orchestrator.
#
# This is a single-host driver that runs on the DEV BOX and fans out
# over SSH to a (target, peer) pair. It wraps
# samples/flow_dissector/run_ntuple_template_bench.sh via
# pkgs.writeShellApplication so that:
#
#   - the full orchestrator body is run through shellcheck at build
#     time (catches unset vars, quoting slips, etc.),
#   - runtimeInputs are declared explicitly: openssh / coreutils /
#     gawk / gnugrep / gnused. The orchestrator never assumes the
#     dev box's PATH.
#   - XDP_OBJ is wired to the bundled af_xdp_parser.xdp.o from
#     xdp-samples. PKTGEN_SCRIPT is wired to the peer-side pktgen
#     driver derivation, so scp'ing it to the peer doesn't depend on
#     cwd or `$(dirname "$0")` guesswork.
#
# Invoke as:
#
#   nix run .#flow-dissector-ntuple-template-bench -- <target> <peer>
#
# See docs/ntuple-template-bench.md for the measurement model and
# samples/flow_dissector/docs/benchmarks.md for where results land.

{ pkgs, xdpSamples, pktgenDriver }:

pkgs.writeShellApplication {
  name = "xdp2-flow-dissector-ntuple-template-bench";

  runtimeInputs = [
    pkgs.openssh
    pkgs.coreutils
    pkgs.gawk
    pkgs.gnugrep
    pkgs.gnused
  ];
  # Target-host tools (bpftool, ethtool, ip) are declared in Nix at a
  # different layer: nix/modules/physical-testbed.nix adds pkgs.bpftools,
  # pkgs.ethtool and the kernel's perf to environment.systemPackages when
  # installEthtool = true (default). That's why this wrapper only lists
  # dev-box tools — all bpftool/ethtool/ip invocations in the script run
  # via ssh on the target, resolving against the target's systemPackages.
  # Peer-side tools (kmod/coreutils/gawk) likewise come from the peer's
  # own systemPackages; pktgenDriver is scp'd there as a plain bash
  # script and invoked via `bash <path>`.

  text = ''
    # Wire the bundled BPF object and peer-side pktgen driver into the
    # orchestrator via env vars the underlying script reads. Both are
    # nix-store paths so they're guaranteed to exist in the wrapper's
    # closure; neither is resolved relative to cwd or $0.
    export XDP_OBJ="${xdpSamples}/lib/xdp/af_xdp_parser.xdp.o"
    if [[ ! -f "$XDP_OBJ" ]]; then
      echo "ERROR: af_xdp_parser.xdp.o not in xdp-samples output ($XDP_OBJ)" >&2
      echo "  This is a Nix build bug — rebuild with: nix build .#xdp-samples" >&2
      exit 7
    fi
    # Peer-side kernel pktgen driver. Shipped as a writeShellApplication
    # derivation (runtimeInputs=[]) whose $out/bin/xdp2-pktgen-ntuple-template
    # is a shellchecked bash script runnable on any NixOS peer whose
    # systemPackages include kmod/coreutils/gawk/grep. The orchestrator
    # scp's this to /tmp on the peer and invokes it there.
    export PKTGEN_SCRIPT="${pktgenDriver}/bin/xdp2-pktgen-ntuple-template"
    if [[ ! -f "$PKTGEN_SCRIPT" ]]; then
      echo "ERROR: pktgen driver not found at $PKTGEN_SCRIPT" >&2
      exit 8
    fi

    ${builtins.readFile ../samples/flow_dissector/run_ntuple_template_bench.sh}
  '';
}
