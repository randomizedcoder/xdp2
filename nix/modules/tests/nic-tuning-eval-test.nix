# SPDX-License-Identifier: BSD-2-Clause-FreeBSD
#
# Pure-Nix evaluation test for the nic-tuning NixOS module.
#
# Builds a synthetic NixOS configuration that imports
# nix/modules/nic-tuning.nix with a tiny inline `xdp2.nicTuning`
# block, then asserts:
#   - `i40e` driver produces the expected per-interface systemd
#     units (`xdp2-nic-tune-<iface>` + `xdp2-nic-affinity-<iface>`).
#   - An unsupported driver produces zero `xdp2-nic-tune-*` units
#     and a documented warning.
#
# The test does not require live hardware and runs as part of
# `nix flake check`.

{ pkgs, lib, nixpkgsPath ? pkgs.path }:

let
  evalConfigPath = nixpkgsPath + "/nixos/lib/eval-config.nix";

  # Skeleton needed by NixOS evalConfig that nic-tuning itself does
  # not care about (filesystems, bootloader, stateVersion).
  bootSkeleton = {
    fileSystems."/" = { device = "none"; fsType = "tmpfs"; };
    boot.loader.grub.enable = false;
    system.stateVersion = "24.11";
  };

  evalWith = nicTuningModuleConfig:
    (import evalConfigPath {
      system = "x86_64-linux";
      modules = [
        ../nic-tuning.nix
        bootSkeleton
        { xdp2.nicTuning = nicTuningModuleConfig; }
      ];
    }).config;

  # Case A — i40e driver, one peer interface. Expect both services.
  i40e = evalWith {
    enable = true;
    driver = "i40e";
    peerInterfaces = [ "enp1s0f0" ];
    isolatedCpus = [ 2 3 ];
  };
  i40eServiceNames = builtins.attrNames i40e.systemd.services;
  i40eRequired = [ "xdp2-nic-tune-enp1s0f0" "xdp2-nic-affinity-enp1s0f0" ];
  i40eMissing = builtins.filter
    (n: !(builtins.elem n i40eServiceNames))
    i40eRequired;

  # Case B — mlx5_core driver. Expect zero xdp2-nic-tune-* services
  # and a non-empty warnings list.
  mlx5 = evalWith {
    enable = true;
    driver = "mlx5_core";
    peerInterfaces = [ "enp1s0f0np0" ];
    isolatedCpus = [ 8 9 ];
  };
  mlx5StubServices = builtins.filter
    (lib.hasPrefix "xdp2-nic-tune-")
    (builtins.attrNames mlx5.systemd.services);
  mlx5HasWarning = builtins.any
    (w: lib.hasInfix "mlx5_core" w)
    mlx5.warnings;

  # Aggregate outcome — `result` throws on any failure with a clear
  # message, otherwise evaluates to the literal "ok".
  result =
    if i40eMissing != [ ] then
      throw "nic-tuning-eval (i40e): missing services ${toString i40eMissing}; got ${toString i40eServiceNames}"
    else if mlx5StubServices != [ ] then
      throw "nic-tuning-eval (mlx5_core): expected no xdp2-nic-tune-* services, got ${toString mlx5StubServices}"
    else if !mlx5HasWarning then
      throw "nic-tuning-eval (mlx5_core): expected a warning mentioning 'mlx5_core'"
    else
      "ok";

in
pkgs.runCommand "nic-tuning-eval-${result}" { } ''
  echo "${result}" > $out
''
