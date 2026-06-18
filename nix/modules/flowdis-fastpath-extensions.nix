# SPDX-License-Identifier: BSD-2-Clause-FreeBSD
#
# NixOS module: apply the v3 flow_dissector fast-path series.
#
# v3 replaces v1 (single net.core.flow_dissector_fastpath sysctl) +
# the extensions-draft VLAN/QinQ/VXLAN-inner patches with a unified
# 4-patch series shipping per-shape sysctls under
# /proc/sys/net/flow_dissector/. See
# kernel-patches/series3-flowdis-fastpath/v3-namespace/ for the
# patches and cover letter.
#
# Stacks directly on stock kernels: no prerequisite kernel patches.
# Patch 1 is the parent (eth+IPv{4,6}+TCP/UDP); patches 2-4 add
# single-VLAN, QinQ (depth-2), and VXLAN inner descent. All four are
# default-off at sysctl level; flipping a knob takes effect at
# runtime.
#
# Consumer (in your host configuration.nix):
#
#   { inputs, ... }: {
#     imports = [ inputs.xdp2.nixosModules.flowdisFastpathExtensions ];
#     xdp2.flowdisFastpathExtensions = {
#       enable = true;                 # apply patches 1-3 (byte-identical)
#       enableVxlanInner = false;      # default; patch 4 is RFC EXPERIMENT
#     };
#   }
#
# After importing:
#   sudo nixos-rebuild boot
#   sudo reboot
#
# Then enable the shapes you want at runtime:
#   sysctl -w net.flow_dissector.eth_ip=1
#   sysctl -w net.flow_dissector.vlan=1
#   sysctl -w net.flow_dissector.qinq=1   # auto-enables vlan
#   sysctl -w net.flow_dissector.vxlan_inner=1   # only if module's
#                                                # enableVxlanInner=true

{ config, lib, ... }:

let
  cfg = config.xdp2.flowdisFastpathExtensions;
  patchDir   = ../../kernel-patches/series3-flowdis-fastpath/v3-namespace;
  patchDirV4 = ../../kernel-patches/series3-flowdis-fastpath/v4-namespace;
in
{
  options.xdp2.flowdisFastpathExtensions = {
    enable = lib.mkEnableOption ''
      the v3+v4 flow_dissector fast-path patch series. v3 applies
      patches 1 (eth_ip parent), 2 (single VLAN), and 3 (QinQ
      depth-2) — all byte-identical with the slow path. v4 stacks
      three more byte-identical shapes on top: 5 (PPPoE session), 6
      (single-label MPLS), 7 (IP-in-IP family). Patch 4 (VXLAN
      inner descent, RFC EXPERIMENT) is a behaviour change and is
      gated separately via `enableVxlanInner`'';

    enableVxlanInner = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Apply patch 4 — VXLAN inner descent (RFC EXPERIMENT). This
        patch deliberately changes the dissector's behaviour for the
        standard flow_keys_dissector: it descends into the VXLAN
        payload and hashes on the inner 5-tuple instead of the outer
        UDP. That improves k8s overlay fairness in cake / fq / ECMP
        but breaks the "fast-path output == slow-path output"
        contract of the byte-identical patches. Default off; turn on
        explicitly for A/B experiments. See the v3 cover letter in
        kernel-patches/series3-flowdis-fastpath/v3-namespace/ for the
        design discussion.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    boot.kernelPatches = [
      {
        name = "v3-flow_dissector-eth-ip";
        patch = "${patchDir}/0001-net-flow_dissector-opt-in-fast-path-for-eth-IPv-4-6-.patch";
      }
      {
        name = "v3-flow_dissector-vlan";
        patch = "${patchDir}/0002-net-flow_dissector-add-fast-path-for-single-Eth-VLAN.patch";
      }
      {
        name = "v3-flow_dissector-qinq";
        patch = "${patchDir}/0003-net-flow_dissector-extend-VLAN-fast-path-to-QinQ-dep.patch";
      }
      {
        name = "v4-flow_dissector-pppoe";
        patch = "${patchDirV4}/0001-net-flow_dissector-pppoe-session.patch";
      }
      {
        name = "v4-flow_dissector-mpls-single-label";
        patch = "${patchDirV4}/0002-net-flow_dissector-mpls-single-label.patch";
      }
      {
        name = "v4-flow_dissector-ipip-family";
        patch = "${patchDirV4}/0003-net-flow_dissector-ipip-family.patch";
      }
      {
        name = "v4-flow_dissector-gre-byte-identical";
        patch = "${patchDirV4}/0004-net-flow_dissector-gre-byte-identical.patch";
      }
      # Phase E RFC EXPERIMENT descents. Behaviour-change patches:
      # the standard flow_keys_dissector stops at outer UDP today, so
      # turning these on gives Geneve / GTP-U overlays per-inner-flow
      # fairness but changes the hash output. Knobs default to 0 at
      # sysctl level so behaviour is unchanged unless an operator
      # opts in. Same posture as the existing v3 vxlan_inner patch.
      {
        name = "v4-flow_dissector-geneve-inner-RFC-EXPERIMENT";
        patch = "${patchDirV4}/0005-RFC-EXPERIMENT-flow_dissector-geneve-inner.patch";
      }
      {
        name = "v4-flow_dissector-gtpu-inner-RFC-EXPERIMENT";
        patch = "${patchDirV4}/0006-RFC-EXPERIMENT-flow_dissector-gtpu-inner.patch";
      }
    ] ++ lib.optional cfg.enableVxlanInner {
      name = "v3-flow_dissector-vxlan-inner-RFC-EXPERIMENT";
      patch = "${patchDir}/0004-RFC-EXPERIMENT-net-flow_dissector-descend-into-VXLAN.patch";
    };
  };
}
