# SPDX-License-Identifier: BSD-2-Clause-FreeBSD
#
# Peer-side kernel pktgen driver for the ntuple+template bench.
#
# writeShellApplication wraps samples/flow_dissector/pktgen_ntuple_template.sh
# and runs shellcheck over it at build time. The runtimeInputs list is
# empty on purpose: this script is scp'd to a *remote* NixOS peer
# (hp2/hp5) and executed there, so the wrapper's usual trick of
# PATH-pinning to the builder's /nix/store would dangle on the peer.
# The peer provides kmod / coreutils / gawk / grep via its own
# systemPackages (the physical-testbed module guarantees those).
#
# Exposed as `xdp2-pktgen-ntuple-template` so the orchestrator can
# reference `${pktgen-driver}/bin/xdp2-pktgen-ntuple-template` and
# scp it to the peer at runtime.

{ pkgs }:

pkgs.writeShellApplication {
  name = "xdp2-pktgen-ntuple-template";
  # Empty runtimeInputs: script executes on a remote host where the
  # builder's /nix/store is not mounted. Peer-side prerequisites
  # (kmod for modprobe, coreutils, gawk, grep) are provided by the
  # peer's own environment.systemPackages via the physical-testbed
  # NixOS module. Shellcheck still runs at build time regardless.
  runtimeInputs = [ ];
  # bashOptions defaults to [ "errexit" "nounset" "pipefail" ] which
  # matches the source script's `set -euo pipefail`. Harmless to
  # double-set.
  text = builtins.readFile ../samples/flow_dissector/pktgen_ntuple_template.sh;
}
