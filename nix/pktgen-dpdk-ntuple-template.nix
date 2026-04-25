# SPDX-License-Identifier: BSD-2-Clause-FreeBSD
#
# Peer-side DPDK-pktgen driver for the ntuple+template bench.
#
# Parallel to nix/pktgen-ntuple-template.nix (kernel path). Unlike the
# kernel driver — which was empty-runtimeInputs because it runs on the
# remote peer's own systemPackages — this wrapper pins a real runtime
# closure: pkgs.pktgen (DPDK-pktgen binary) and pkgs.dpdk (for
# dpdk-devbind.py). When the orchestrator scp's this script to the
# peer, the wrapped PATH still references store paths local to the
# peer; the peer must therefore have an identical store or the
# orchestrator must re-build this wrapper on the peer.
#
# In our testbed both hp2 (peer) and hp5 (target) run NixOS with the
# same flake, so `nix run .#flow-dissector-pktgen-dpdk-ntuple-template`
# on the peer resolves correctly. We still scp it at runtime so
# operators who use `nix run` from the dev box don't need a per-peer
# rebuild.
#
# Exposed as `xdp2-pktgen-dpdk-ntuple-template` — symmetric naming
# with `xdp2-pktgen-ntuple-template`.

{ pkgs }:

let
  # Ship the Lua config inside the derivation so the driver script
  # can find it via $(dirname $0)/pktgen_dpdk_ntuple_template.lua
  # — same pattern as the kernel-pktgen driver but with a sibling
  # Lua file instead of a sibling bash-only script.
  pktgenDpdkSources = pkgs.runCommand "pktgen-dpdk-ntuple-template-src" { } ''
    mkdir -p $out
    cp ${../samples/flow_dissector/pktgen_dpdk_ntuple_template.sh} \
       $out/pktgen_dpdk_ntuple_template.sh
    cp ${../samples/flow_dissector/pktgen_dpdk_ntuple_template.lua} \
       $out/pktgen_dpdk_ntuple_template.lua
    chmod +x $out/pktgen_dpdk_ntuple_template.sh
  '';
in
pkgs.writeShellApplication {
  name = "xdp2-pktgen-dpdk-ntuple-template";
  # pktgen + dpdk are both on the peer's PATH via runtimeInputs so
  # the driver script can call `pktgen ...` and `dpdk-devbind.py` by
  # name. kmod provides modprobe for loading vfio-pci; util-linux
  # ships mount/mountpoint for hugetlbfs. iproute2 for `ip link`.
  runtimeInputs = [
    pkgs.pktgen
    pkgs.dpdk
    pkgs.kmod
    pkgs.util-linux
    pkgs.iproute2
    pkgs.coreutils
    pkgs.gawk
  ];
  text = ''
    # Point the driver at its bundled Lua config by default so callers
    # don't have to know the staging path. The script still honours
    # PKTGEN_DPDK_LUA if the operator wants a custom config.
    export PKTGEN_DPDK_LUA="''${PKTGEN_DPDK_LUA:-${pktgenDpdkSources}/pktgen_dpdk_ntuple_template.lua}"
    exec bash ${pktgenDpdkSources}/pktgen_dpdk_ntuple_template.sh "$@"
  '';
}
