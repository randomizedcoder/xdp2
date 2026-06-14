# SPDX-License-Identifier: BSD-2-Clause-FreeBSD
#
# NixOS module: apply the series3-flowdis-fastpath extension patches
# (single VLAN, QinQ, optionally VXLAN-inner) on top of whatever kernel
# the host already runs. Stacks on the parent series3 patches that
# bring `net.core.flow_dissector_fastpath` into existence — those are
# expected to be in the host's kernel (in net-next 7.1.0-rc4+ they are
# upstream as commit 8013aee91ccb; on older bases they typically come
# from a sibling boot.kernelPatches entry).
#
# Patches in this set live in
# kernel-patches/series3-flowdis-fastpath/extensions-draft/. Each is a
# standard `git format-patch` output that the NixOS kernel build
# machinery consumes via boot.kernelPatches.
#
# Consumer (in your host configuration.nix):
#
#   { inputs, ... }: {
#     imports = [ inputs.xdp2.nixosModules.flowdisFastpathExtensions ];
#     xdp2.flowdisFastpathExtensions = {
#       enable = true;
#       enableVxlanInner = false;  # default; opt in only for the experiment
#     };
#   }
#
# After importing:
#   sudo nixos-rebuild boot       # stage the new kernel
#   sudo reboot                   # boot into it
#   sysctl -n net.core.flow_dissector_fastpath   # 0 (default; gate is off)
#   sysctl -w net.core.flow_dissector_fastpath=1 # enable
#
# To verify the extension patches landed (look for the depth counter
# the VLAN patch adds):
#   grep -c 'vlan_depth' /proc/config.gz  # (not applicable for patches,
#   # just confirm by running netconf-vlan + checking that
#   # sysctl=1 cells show a delta vs sysctl=0 in the orchestrator
#   # matrix.csv).

{ config, lib, ... }:

let
  cfg = config.xdp2.flowdisFastpathExtensions;
  patchDir = ../../kernel-patches/series3-flowdis-fastpath/extensions-draft;
in
{
  options.xdp2.flowdisFastpathExtensions = {
    enable = lib.mkEnableOption ''
      the series3-flowdis-fastpath extension patches. By default this
      activates patches 0001 (single VLAN) and 0002 (QinQ) — both
      byte-identical with the slow path for the shapes they cover.
      Patch 0003 (VXLAN-inner descent) is a behaviour change and is
      gated separately via `enableVxlanInner`'';

    enableVxlanInner = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Apply patch 0003 — VXLAN inner descent. This patch
        deliberately changes the dissector's behaviour for the
        standard flow_keys_dissector: it descends into the VXLAN
        payload and hashes on the inner 5-tuple instead of the outer
        UDP. That improves k8s overlay fairness in cake / fq / ECMP
        but breaks the "fast-path output == slow-path output"
        contract of the parent series. Default off; turn on
        explicitly for A/B experiments. See the patch commit message
        and the cover letter in
        kernel-patches/series3-flowdis-fastpath/extensions-draft/
        for the design discussion.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    boot.kernelPatches = [
      {
        name = "flowdis-ext-0001-vlan";
        patch = "${patchDir}/0001-net-flow_dissector-add-fast-path-for-single-Eth-VLAN.patch";
      }
      {
        name = "flowdis-ext-0002-qinq";
        patch = "${patchDir}/0002-net-flow_dissector-extend-VLAN-fast-path-to-QinQ-dep.patch";
      }
    ] ++ lib.optional cfg.enableVxlanInner {
      name = "flowdis-ext-0003-vxlan-inner";
      patch = "${patchDir}/0003-RFC-EXPERIMENT-net-flow_dissector-descend-into-VXLAN.patch";
    };
  };
}
