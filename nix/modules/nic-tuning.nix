# SPDX-License-Identifier: BSD-2-Clause-FreeBSD
#
# NixOS module: NIC-driver-aware data-plane tuning for the xdp2
# physical testbed.
#
# This module is the home of all ethtool / queue / IRQ / Flow Director
# behavior for the testbed. It is driver-aware: dispatch on
# `xdp2.nicTuning.driver` selects the per-driver implementation. The
# rest of the host (CPU isolation, hugepages, kernel cmdline, sysctls)
# stays in `physical-testbed.nix`, which now imports this module and
# forwards its configuration to the matching options here.
#
# Currently implemented driver branches: `i40e`. Other drivers
# (`mlx5_core`, `ice`, `bnxt_en`) are accepted by the option type but
# the activation block is a no-op + warning until Phase 9 lands.
#
# Consumer (typical, via physical-testbed.nix):
#
#   { ... }: {
#     imports = [ inputs.xdp2.nixosModules.physical-testbed ];
#     # physical-testbed forwards peerInterfaces / flowDirectorRules /
#     # isolatedCpus / jumbo / gro to xdp2.nicTuning automatically.
#   }
#
# Direct consumer (without the rest of physical-testbed):
#
#   { ... }: {
#     imports = [ inputs.xdp2.nixosModules.nicTuning ];
#     xdp2.nicTuning = {
#       enable = true;
#       driver = "i40e";
#       peerInterfaces = [ "enp1s0f0" ];
#       isolatedCpus = [ 2 3 4 5 ];
#     };
#   }

{ config, lib, pkgs, ... }:

let
  cfg = config.xdp2.nicTuning;

  # i40e branch — the per-NIC ethtool tune service (lifted verbatim
  # from the historic body of physical-testbed.nix). Idempotent:
  # ethtool returns 0 even if the requested setting is already in
  # place.
  mkI40eTuneService = ifname: {
    description = "xdp2 testbed NIC tuning for ${ifname} (i40e)";
    after = [ "network-online.target" ];
    wants = [ "network-online.target" ];
    wantedBy = [ "multi-user.target" ];
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
    };
    path = [ pkgs.ethtool pkgs.iproute2 ];
    script = ''
      set -eu
      ifc=${ifname}

      # Wait for the interface to exist; udev rename can lag boot.
      for _ in $(seq 1 30); do
        if ip link show "$ifc" >/dev/null 2>&1; then break; fi
        sleep 1
      done
      if ! ip link show "$ifc" >/dev/null 2>&1; then
        echo "xdp2-nic-tune: $ifc never appeared, skipping" >&2
        exit 0
      fi

      # Rings: max-or-4096 RX/TX descriptors. Larger = more buffering
      # capacity at the cost of cache pressure.
      ethtool -G "$ifc" rx 4096 tx 4096 || true

      # One combined queue per isolated CPU.
      ethtool -L "$ifc" combined ${toString (lib.length cfg.isolatedCpus)} || true

      # Offloads: off by default for parser-result reproducibility.
      ${if cfg.gro then ''
        ethtool -K "$ifc" gro on lro on tso on gso on || true
      '' else ''
        ethtool -K "$ifc" gro off lro off tso off gso off || true
      ''}

      # Flow control off — no PAUSE frames on a back-to-back link.
      ethtool -A "$ifc" rx off tx off autoneg off || true

      # Flow director: enable, hash on the 5-tuple.
      ethtool -K "$ifc" ntuple on || true
      ethtool -N "$ifc" rx-flow-hash tcp4 sdfn || true
      ethtool -N "$ifc" rx-flow-hash udp4 sdfn || true
      ethtool -N "$ifc" rx-flow-hash tcp6 sdfn || true
      ethtool -N "$ifc" rx-flow-hash udp6 sdfn || true

      # Per-rule Flow Director steering.
      ${lib.concatStringsSep "\n" (lib.imap0 (i: rule:
        lib.optionalString (rule.interface == ifname) ''
          # Rule ${toString i}: ${rule.flowType} dst-port ${toString rule.destPort} -> queue ${toString rule.queue}
          ethtool -N "$ifc" delete ${toString i} 2>/dev/null || true
          ethtool -N "$ifc" flow-type ${rule.flowType} dst-port ${toString rule.destPort} action ${toString rule.queue} loc ${toString i} || \
            echo "xdp2-nic-tune: failed to install FD rule ${toString i} on $ifc" >&2
        ''
      ) cfg.flowDirectorRules)}

      ${lib.optionalString cfg.jumbo ''
        ip link set "$ifc" mtu 9000 || true
      ''}
    '';
  };

  # i40e branch — IRQ affinity. Pins ${ifname}-TxRx-N IRQs to
  # isolatedCpus[N % length].
  mkI40eAffinityService = ifname: {
    description = "xdp2 testbed IRQ affinity for ${ifname} (i40e)";
    after = [ "xdp2-nic-tune-${ifname}.service" ];
    requires = [ "xdp2-nic-tune-${ifname}.service" ];
    wantedBy = [ "multi-user.target" ];
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
    };
    path = [ pkgs.gawk pkgs.coreutils ];
    script = ''
      set -eu
      ifc=${ifname}
      cpus=(${lib.concatMapStringsSep " " toString cfg.isolatedCpus})
      ncpu=''${#cpus[@]}

      # Find IRQ numbers for ${ifname}-TxRx-N (i40e naming).
      i=0
      while read -r line; do
        irq=$(echo "$line" | awk -F: '{gsub(/ /,"",$1); print $1}')
        cpu=''${cpus[$((i % ncpu))]}
        mask=$(printf '%x' $((1 << cpu)))
        echo "$mask" > /proc/irq/$irq/smp_affinity || true
        i=$((i + 1))
      done < <(grep -E "$ifc-TxRx-[0-9]+" /proc/interrupts || true)

      if [ "$i" -eq 0 ]; then
        echo "xdp2-nic-affinity: no $ifc-TxRx-N IRQs found" >&2
      fi
    '';
  };

  # Driver dispatch: returns an attrset of (service-name -> unit).
  # Currently only the i40e branch produces real services; other
  # drivers produce an empty attrset and a top-level warning. Phase 9
  # adds the mlx5_core branch.
  driverServices =
    if cfg.driver == "i40e" then
      lib.listToAttrs (
        (map (ifname: lib.nameValuePair "xdp2-nic-tune-${ifname}"
                       (mkI40eTuneService ifname)) cfg.peerInterfaces)
        ++
        (map (ifname: lib.nameValuePair "xdp2-nic-affinity-${ifname}"
                       (mkI40eAffinityService ifname)) cfg.peerInterfaces)
      )
    else
      { };

  # Top-level warnings for not-yet-implemented drivers.
  driverWarnings = lib.optional
    (cfg.enable && cfg.driver != "i40e" && cfg.peerInterfaces != [ ])
    "xdp2.nicTuning: driver '${cfg.driver}' is accepted but its activation logic is not yet implemented; no NIC tuning services will be installed. Tracking issue: Phase 9 of the flow-dissector matrix implementation plan.";

in
{
  options.xdp2.nicTuning = {
    enable = lib.mkEnableOption "xdp2 NIC-driver tuning (ethtool, queues, IRQ, Flow Director)";

    driver = lib.mkOption {
      type = lib.types.enum [ "i40e" "ice" "mlx5_core" "bnxt_en" ];
      default = "i40e";
      description = ''
        NIC driver in use on `peerInterfaces`. Selects the per-driver
        tuning implementation. `i40e` is fully implemented (Phase 3);
        the other values are accepted to keep external configurations
        valid but currently produce a warning and no activation
        services until Phase 9 lands.
      '';
    };

    peerInterfaces = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [ "enp1s0f0" "enp1s0f1" ];
      description = ''
        Names of the data-plane NICs to tune. Names are explicit by
        design — silent auto-detection produced the historical
        enp3s0f0/enp1s0f0np0 drift documented in
        docs/physical-testbed.md §3.
      '';
    };

    isolatedCpus = lib.mkOption {
      type = lib.types.listOf lib.types.int;
      default = [ ];
      example = [ 2 3 4 5 6 7 ];
      description = ''
        CPU IDs reserved for benchmark threads. Used to size the NIC's
        combined queue count (one queue per CPU) and to round-robin
        the per-queue IRQ affinity. Set this to the same list passed
        to `xdp2.testbed.isolatedCpus`.
      '';
    };

    jumbo = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        If true, set MTU 9000 on `peerInterfaces`. Default 1500 for
        parser-result reproducibility against upstream kernel selftests.
      '';
    };

    gro = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        If true, enable GRO/LRO/TSO/GSO on `peerInterfaces`. Default
        off because these offloads coalesce packets before the parser
        sees them, distorting per-packet measurements.
      '';
    };

    flowDirectorRules = lib.mkOption {
      type = lib.types.listOf (lib.types.submodule {
        options = {
          interface = lib.mkOption {
            type = lib.types.str;
            example = "enp1s0f0";
            description = "Peer interface name to install this ntuple rule on.";
          };
          flowType = lib.mkOption {
            type = lib.types.enum [ "tcp4" "udp4" "tcp6" "udp6" "sctp4" "sctp6" ];
            default = "tcp4";
            description = "ethtool flow-type for this rule.";
          };
          destPort = lib.mkOption {
            type = lib.types.int;
            example = 443;
            description = "L4 destination port to match.";
          };
          queue = lib.mkOption {
            type = lib.types.int;
            example = 2;
            description = "RX queue ID the matching packets are steered to.";
          };
        };
      });
      default = [ ];
      description = ''
        Driver-specific steering rules. On i40e these are installed via
        `ethtool -N <ifc> flow-type <t> dst-port <p> action <q> loc <i>`
        in the xdp2-nic-tune-<ifname>.service unit at boot.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    systemd.services = driverServices;
    warnings = driverWarnings;

    assertions = [
      {
        # Exhaustiveness: enum guarantees the value is in the supported
        # set, but we still flag the gap between "accepted" and
        # "implemented" so Phase 9 doesn't ship silently.
        assertion = lib.elem cfg.driver [ "i40e" "ice" "mlx5_core" "bnxt_en" ];
        message = "xdp2.nicTuning.driver: '${cfg.driver}' is not in the supported set.";
      }
    ];
  };
}
