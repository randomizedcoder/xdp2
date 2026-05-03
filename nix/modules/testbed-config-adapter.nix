# SPDX-License-Identifier: BSD-2-Clause-FreeBSD
#
# testbed-config-adapter — pure helper that maps a testbed-config
# attrset (loaded by nix/testbed-config.nix) onto the option shape
# exposed by nix/modules/physical-testbed.nix (`xdp2.testbed.*`).
#
# This is NOT itself a NixOS module; it is a pure function that
# returns the *config values* an external host configuration should
# pass to the physical-testbed module.
#
# Consumer (in an external host's configuration.nix):
#
#   { inputs, ... }: {
#     imports = [ inputs.xdp2.nixosModules.physical-testbed ];
#     config = inputs.xdp2.lib.testbedConfigToModule {
#       config = inputs.xdp2.testbedConfigs.hp2-hp5-x710;
#       role   = "dut";
#     };
#   }
#
# Schema documented in docs/flow-dissector-matrix-physical-testbed.md §3.

{ lib }:

let
  # parseCpuRange — convert a Linux-style isolcpus string into a list
  # of ints. Accepts comma-separated singletons and dash-separated
  # closed ranges; whitespace is tolerated. Examples:
  #   "2-7"   -> [ 2 3 4 5 6 7 ]
  #   "2,4-6" -> [ 2 4 5 6 ]
  #   "0"     -> [ 0 ]
  #   ""      -> [ ]
  parseCpuRange = s:
    let
      trimmed = lib.strings.removePrefix " " (lib.strings.removeSuffix " " s);
      parts = lib.filter (p: p != "") (lib.splitString "," trimmed);
      expandPart = part:
        let
          dashSplit = lib.splitString "-" part;
        in
        if builtins.length dashSplit == 1 then
          [ (lib.toInt (lib.head dashSplit)) ]
        else if builtins.length dashSplit == 2 then
          let
            lo = lib.toInt (lib.head dashSplit);
            hi = lib.toInt (lib.last dashSplit);
          in
          if lo > hi then
            throw "testbed-config-adapter: invalid CPU range '${part}': lo > hi"
          else
            lib.genList (i: lo + i) (hi - lo + 1)
        else
          throw "testbed-config-adapter: malformed CPU range '${part}'";
    in
    builtins.concatLists (map expandPart parts);

  # Lower a testbed-config attrset onto xdp2.testbed.* options for
  # a specific role ("dut" or "generator").
  testbedConfigToModule =
    { config
    , role
    }:
    let
      host = config.hosts.${role} or (throw
        "testbed-config-adapter: testbed '${config.testbed.name}' has no host with role='${role}'");

      isolatedCpus = parseCpuRange host.isolated_cpus;

      # The host's own data-plane NIC interface. DUT uses dut_iface;
      # generator uses gen_iface. If they happen to be the same
      # (single-port NIC, single-host loopback test), that's still
      # valid.
      iface =
        if role == "dut" then config.nic.dut_iface
        else if role == "generator" then config.nic.gen_iface
        else throw "testbed-config-adapter: unsupported role '${role}'";

      # lowJitter = honest-perf bench mode. Triggered when the host
      # asks for the performance governor with kernel mitigations
      # disabled. The physical-testbed module turns off turbo and
      # rebalances IRQs accordingly.
      lowJitter =
        (host.governor or "") == "performance"
        && (host.mitigations or "") == "off";
    in
    {
      xdp2.testbed = {
        enable = true;
        peerInterfaces = [ iface ];
        isolatedCpus = isolatedCpus;
        hugepages2M = host.hugepage_count or 512;
        inherit lowJitter;
        # Honest-perf banner: when mitigations=off, the
        # physical-testbed module should label the boot accordingly.
        disableMitigations = (host.mitigations or "") == "off";
        # Jumbo frames and GRO/LRO/TSO/GSO are NOT inferred from
        # testbed-config; the module's defaults stand
        # (jumbo=false, gro=false) for parser-result reproducibility.
      };
      # nic-tuning module driver dispatch — forwarded from
      # [nic].driver so the right per-driver implementation is
      # selected. physical-testbed.nix sets driver = "i40e" via
      # mkDefault; this assignment overrides it.
      xdp2.nicTuning.driver = config.nic.driver;
    };

  # ---------- Pure-Nix unit tests ----------
  #
  # Evaluating `tests` triggers the asserts; throws on failure. The
  # flake exposes this attribute as `lib.testbedConfigAdapterTests`
  # so `nix eval` is sufficient verification.
  tests =
    let
      check = name: actual: expected:
        if actual == expected then true
        else throw "testbed-config-adapter test '${name}' failed: got ${builtins.toJSON actual}, expected ${builtins.toJSON expected}";
    in
    {
      parseCpuRange-2-7      = check "2-7"      (parseCpuRange "2-7")      [ 2 3 4 5 6 7 ];
      parseCpuRange-2-comma  = check "2,4-6"    (parseCpuRange "2,4-6")    [ 2 4 5 6 ];
      parseCpuRange-single   = check "0"        (parseCpuRange "0")        [ 0 ];
      parseCpuRange-empty    = check ""         (parseCpuRange "")         [ ];
      parseCpuRange-multiple = check "0,2-3,5"  (parseCpuRange "0,2-3,5")  [ 0 2 3 5 ];
      ok = true;
    };

in
{
  inherit testbedConfigToModule parseCpuRange tests;
}
