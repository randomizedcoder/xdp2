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
# Currently implemented driver branches: `i40e`, `mlx5_core`. The
# remaining drivers (`ice`, `bnxt_en`) are accepted by the option type
# but their activation blocks are no-ops + warning placeholders.
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

  # mlx5_core branch — per-NIC tuning. Differences from i40e:
  #   - Flow steering uses tc-flower (queue_mapping skbedit) instead
  #     of ethtool ntuple/Flow Director, because mlx5_core's
  #     "ethtool -N" only exposes RSS/hash control, not destination
  #     steering. The qdisc must exist before filters can attach.
  #   - IRQ names are `mlx5_comp<N>@pci:<bdf>` rather than the i40e
  #     `<iface>-TxRx-<N>` pattern, so the affinity service greps
  #     for the device's PCI BDF (resolved at runtime via
  #     `readlink /sys/class/net/<ifc>/device`) rather than `<ifc>`.
  #   - mlx5 supports the same ethtool -G/-K/-A flags as i40e for
  #     ring sizing, offloads, and pause-frame control.
  mkMlx5TuneService = ifname: {
    description = "xdp2 testbed NIC tuning for ${ifname} (mlx5_core)";
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

      # Rings: 4096 RX/TX descriptors. mlx5 supports up to 8192 but we
      # match i40e for cross-driver comparability.
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

      # mlx5 supports rx-flow-hash configuration via ethtool -N for
      # RSS hashing; keep the 5-tuple distribution.
      ethtool -N "$ifc" rx-flow-hash tcp4 sdfn || true
      ethtool -N "$ifc" rx-flow-hash udp4 sdfn || true
      ethtool -N "$ifc" rx-flow-hash tcp6 sdfn || true
      ethtool -N "$ifc" rx-flow-hash udp6 sdfn || true

      # tc-flower flow steering. The clsact qdisc lets filters attach
      # to the ingress hook; `replace` is idempotent so re-running
      # the unit after a reboot is safe.
      tc qdisc replace dev "$ifc" clsact || true

      # Per-rule tc-flower steering. Action: skbedit queue_mapping.
      ${lib.concatStringsSep "\n" (lib.imap0 (i: rule:
        lib.optionalString (rule.interface == ifname) ''
          # Rule ${toString i}: ${rule.flowType} dst-port ${toString rule.destPort} -> queue ${toString rule.queue}
          tc filter del dev "$ifc" ingress pref ${toString (1000 + i)} 2>/dev/null || true
          tc filter add dev "$ifc" ingress pref ${toString (1000 + i)} protocol ${
            if lib.hasSuffix "6" rule.flowType then "ipv6" else "ip"
          } flower ip_proto ${
            if lib.hasPrefix "tcp" rule.flowType then "tcp"
            else if lib.hasPrefix "udp" rule.flowType then "udp"
            else "sctp"
          } dst_port ${toString rule.destPort} action skbedit queue_mapping ${toString rule.queue} || \
            echo "xdp2-nic-tune: failed to install tc-flower rule ${toString i} on $ifc" >&2
        ''
      ) cfg.flowDirectorRules)}

      ${lib.optionalString cfg.jumbo ''
        ip link set "$ifc" mtu 9000 || true
      ''}
    '';
  };

  # mlx5_core branch — IRQ affinity. mlx5 names completion-vector IRQs
  # `mlx5_comp<N>@pci:<bdf>`, so we match against the interface's PCI
  # BDF (resolved at runtime via /sys/class/net/<ifc>/device) rather
  # than the interface name.
  mkMlx5AffinityService = ifname: {
    description = "xdp2 testbed IRQ affinity for ${ifname} (mlx5_core)";
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

      # Resolve the interface's PCI BDF (e.g. "0000:01:00.0").
      if [ ! -e "/sys/class/net/$ifc/device" ]; then
        echo "xdp2-nic-affinity: $ifc has no /sys device link, skipping" >&2
        exit 0
      fi
      bdf=$(basename "$(readlink "/sys/class/net/$ifc/device")")

      # Find IRQ numbers for mlx5_comp*@pci:<bdf>.
      i=0
      while read -r line; do
        irq=$(echo "$line" | awk -F: '{gsub(/ /,"",$1); print $1}')
        cpu=''${cpus[$((i % ncpu))]}
        mask=$(printf '%x' $((1 << cpu)))
        echo "$mask" > /proc/irq/$irq/smp_affinity || true
        i=$((i + 1))
      done < <(grep -E "mlx5_comp[0-9]+@pci:$bdf" /proc/interrupts || true)

      if [ "$i" -eq 0 ]; then
        echo "xdp2-nic-affinity: no mlx5_comp*@pci:$bdf IRQs found" >&2
      fi
    '';
  };

  # Per-driver service builders: returns the attrset of services for a
  # given driver. An attrset-keyed dispatch (rather than a chain of
  # `if`s) makes the structure visible and lets us assert
  # exhaustiveness with a single `or throw`: any driver value not
  # listed here causes evaluation to fail with a clear message.
  driverImpls = {
    i40e = {
      services =
        (map (ifname: lib.nameValuePair "xdp2-nic-tune-${ifname}"
                       (mkI40eTuneService ifname)) cfg.peerInterfaces)
        ++
        (map (ifname: lib.nameValuePair "xdp2-nic-affinity-${ifname}"
                       (mkI40eAffinityService ifname)) cfg.peerInterfaces);
      stubbed = false;
    };
    mlx5_core = {
      services =
        (map (ifname: lib.nameValuePair "xdp2-nic-tune-${ifname}"
                       (mkMlx5TuneService ifname)) cfg.peerInterfaces)
        ++
        (map (ifname: lib.nameValuePair "xdp2-nic-affinity-${ifname}"
                       (mkMlx5AffinityService ifname)) cfg.peerInterfaces);
      stubbed = false;
    };
    ice = { services = [ ]; stubbed = true; };
    bnxt_en = { services = [ ]; stubbed = true; };
  };

  # Driver dispatch: attrset lookup + `or throw`. The throw never
  # triggers in practice (option enum guarantees `cfg.driver` is in
  # the supported set) but it makes removing a branch from
  # `driverImpls` a hard eval-time error rather than a silent gap.
  driverImpl = driverImpls.${cfg.driver}
    or (throw "xdp2.nicTuning: unhandled driver '${cfg.driver}' — driverImpls is missing a branch.");

  driverServices = lib.listToAttrs driverImpl.services;

  # Top-level warning for stubbed (no-op) drivers only. Implemented
  # branches (`i40e`, `mlx5_core`) install real services and emit no
  # warning.
  driverWarnings = lib.optional
    (cfg.enable && driverImpl.stubbed && cfg.peerInterfaces != [ ])
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
        tuning implementation. `i40e` (Intel X710 / XL710) and
        `mlx5_core` (Mellanox ConnectX-4 and later) are implemented;
        `ice` and `bnxt_en` are accepted to keep external
        configurations valid but currently install no tuning
        services and emit a warning.
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
        `ethtool -N <ifc> flow-type <t> dst-port <p> action <q> loc <i>`.
        On mlx5_core they translate to tc-flower:
        `tc filter add dev <ifc> ingress flower ip_proto <t> dst_port <p>
        action skbedit queue_mapping <q>` (the clsact qdisc is created
        first). Both paths run inside the xdp2-nic-tune-<ifname>.service
        unit at boot.
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
