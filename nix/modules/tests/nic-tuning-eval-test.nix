# SPDX-License-Identifier: BSD-2-Clause-FreeBSD
#
# Pure-Nix evaluation test for the nic-tuning NixOS module.
#
# Builds a synthetic NixOS configuration that imports
# nix/modules/nic-tuning.nix with a tiny inline `xdp2.nicTuning`
# block, then asserts:
#   - `i40e` and `mlx5_core` produce the expected per-interface
#     systemd units (`xdp2-nic-tune-<iface>` +
#     `xdp2-nic-affinity-<iface>`) and emit no driver warning.
#   - mlx5_core's tune unit script installs tc-flower steering
#     (clsact qdisc + flower filter), distinguishing it from the
#     i40e ethtool ntuple path.
#   - A still-stubbed driver (`ice`) produces zero
#     `xdp2-nic-tune-*` units and a documented warning.
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

  # Case B — mlx5_core driver. Phase 9 lifts this from stub to real:
  # expect both services present, no warning, and tc-flower commands
  # in the tune script.
  mlx5 = evalWith {
    enable = true;
    driver = "mlx5_core";
    peerInterfaces = [ "enp1s0f0np0" ];
    isolatedCpus = [ 8 9 ];
    flowDirectorRules = [
      { interface = "enp1s0f0np0"; flowType = "tcp4"; destPort = 443; queue = 2; }
    ];
  };
  mlx5ServiceNames = builtins.attrNames mlx5.systemd.services;
  mlx5Required = [ "xdp2-nic-tune-enp1s0f0np0" "xdp2-nic-affinity-enp1s0f0np0" ];
  mlx5Missing = builtins.filter
    (n: !(builtins.elem n mlx5ServiceNames))
    mlx5Required;
  mlx5HasMlxWarning = builtins.any
    (w: lib.hasInfix "mlx5_core" w)
    mlx5.warnings;
  mlx5TuneScript = mlx5.systemd.services.xdp2-nic-tune-enp1s0f0np0.script or "";
  mlx5HasTcFlower =
    (lib.hasInfix "tc qdisc replace dev" mlx5TuneScript)
    && (lib.hasInfix "flower" mlx5TuneScript)
    && (lib.hasInfix "skbedit queue_mapping 2" mlx5TuneScript);

  # Case C — `ice` driver (still stubbed). Expect zero
  # xdp2-nic-tune-* services and a warning.
  ice = evalWith {
    enable = true;
    driver = "ice";
    peerInterfaces = [ "enp4s0f0" ];
    isolatedCpus = [ 4 5 ];
  };
  iceStubServices = builtins.filter
    (lib.hasPrefix "xdp2-nic-tune-")
    (builtins.attrNames ice.systemd.services);
  iceHasWarning = builtins.any
    (w: lib.hasInfix "'ice'" w)
    ice.warnings;

  # Aggregate outcome — `result` throws on any failure with a clear
  # message, otherwise evaluates to the literal "ok".
  result =
    if i40eMissing != [ ] then
      throw "nic-tuning-eval (i40e): missing services ${toString i40eMissing}; got ${toString i40eServiceNames}"
    else if mlx5Missing != [ ] then
      throw "nic-tuning-eval (mlx5_core): missing services ${toString mlx5Missing}; got ${toString mlx5ServiceNames}"
    else if mlx5HasMlxWarning then
      throw "nic-tuning-eval (mlx5_core): expected NO warning for an implemented driver, but got: ${toString mlx5.warnings}"
    else if !mlx5HasTcFlower then
      throw "nic-tuning-eval (mlx5_core): tune script missing tc-flower commands (clsact / flower / skbedit queue_mapping)"
    else if iceStubServices != [ ] then
      throw "nic-tuning-eval (ice): expected no xdp2-nic-tune-* services, got ${toString iceStubServices}"
    else if !iceHasWarning then
      throw "nic-tuning-eval (ice): expected a warning mentioning the 'ice' driver"
    else
      "ok";

in
pkgs.runCommand "nic-tuning-eval-${result}" { } ''
  echo "${result}" > $out
''
