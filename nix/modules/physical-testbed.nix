# SPDX-License-Identifier: BSD-2-Clause-FreeBSD
#
# NixOS module: xdp2 physical testbed tuning.
#
# Imported by hosts dedicated to xdp2 benchmarking (hp2, hp5, and any
# replicating site). Each tuning decision is documented in
# docs/physical-testbed.md §7. Override individual options if your
# workload needs different behaviour.
#
# Consumer (in your host configuration.nix):
#
#   { ... }: {
#     imports = [ inputs.xdp2.nixosModules.physical-testbed ];
#     xdp2.testbed = {
#       enable = true;
#       peerInterfaces = [ "enp1s0f0np0" "enp1s0f1np1" ];
#       addresses = {
#         enp1s0f0np0 = { local = "10.10.0.5/30"; peer = "10.10.0.2"; };
#         enp1s0f1np1 = { local = "10.10.1.5/30"; peer = "10.10.1.2"; };
#       };
#       isolatedCpus = [ 2 3 4 5 6 7 ];
#       hugepages2M = 512;
#     };
#   }

{ config, lib, pkgs, ... }:

let
  cfg = config.xdp2.testbed;

  cpuList = lib.concatMapStringsSep "," toString cfg.isolatedCpus;
  cpuMaskCount = lib.length cfg.isolatedCpus;

  # Per-NIC ethtool tuning service — runs once at network-online.
  # Idempotent: ethtool returns 0 even if the requested setting is
  # already in place.
  mkNicTuneService = ifname: {
    description = "xdp2 testbed NIC tuning for ${ifname}";
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
      ethtool -L "$ifc" combined ${toString cpuMaskCount} || true

      # Offloads: off by default for parser-result reproducibility.
      # GRO collapses packets before the parser sees them; TSO/GSO
      # likewise distort what the parser observes.
      ${if cfg.gro then ''
        ethtool -K "$ifc" gro on lro on tso on gso on || true
      '' else ''
        ethtool -K "$ifc" gro off lro off tso off gso off || true
      ''}

      # Flow control off — no PAUSE frames on a back-to-back link.
      ethtool -A "$ifc" rx off tx off autoneg off || true

      # Flow director: enable, hash on the 5-tuple. ntuple-rule
      # programming is left to per-test scripts.
      ethtool -K "$ifc" ntuple on || true
      ethtool -N "$ifc" rx-flow-hash tcp4 sdfn || true
      ethtool -N "$ifc" rx-flow-hash udp4 sdfn || true
      ethtool -N "$ifc" rx-flow-hash tcp6 sdfn || true
      ethtool -N "$ifc" rx-flow-hash udp6 sdfn || true

      ${lib.optionalString cfg.jumbo ''
        ip link set "$ifc" mtu 9000 || true
      ''}
    '';
  };

  # Per-NIC IRQ affinity service — pins ${ifname}-TxRx-N IRQs to
  # isolatedCpus[N % length]. Replaces irqbalance for the data-plane
  # NICs (irqbalance itself is disabled module-wide).
  mkNicAffinityService = ifname: {
    description = "xdp2 testbed IRQ affinity for ${ifname}";
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

in
{
  options.xdp2.testbed = {
    enable = lib.mkEnableOption "xdp2 physical testbed tuning";

    peerInterfaces = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [ "enp1s0f0np0" "enp1s0f1np1" ];
      description = ''
        Names of the data-plane NICs cabled to the peer host. These get
        ethtool tuning, IRQ pinning, and (if `addresses` is set) static
        IPv4 configuration. Names are explicit by design — silent
        auto-detection produced the historical enp3s0f0/enp1s0f0np0
        drift documented in docs/physical-testbed.md §3.
      '';
    };

    addresses = lib.mkOption {
      type = lib.types.attrsOf (lib.types.submodule {
        options = {
          local = lib.mkOption {
            type = lib.types.str;
            example = "10.10.0.5/30";
            description = "Local IPv4 address in CIDR form for this interface.";
          };
          peer = lib.mkOption {
            type = lib.types.str;
            example = "10.10.0.2";
            description = "Peer IPv4 address (informational; used by test scripts).";
          };
        };
      });
      default = { };
      description = ''
        Per-interface static address assignment. Replaces the accidental
        link-local 169.254.x.x fallback that hosts get with no config.
      '';
    };

    isolatedCpus = lib.mkOption {
      type = lib.types.listOf lib.types.int;
      default = [ ];
      example = [ 2 3 4 5 6 7 ];
      description = ''
        CPU IDs reserved for benchmark threads via isolcpus, nohz_full,
        and rcu_nocbs. Leave at least one CPU (typically 0,1) for
        housekeeping (kernel threads, ssh, nix-daemon). Empty list
        disables CPU isolation entirely.
      '';
    };

    hugepages2M = lib.mkOption {
      type = lib.types.int;
      default = 512;
      description = ''
        Number of 2 MiB hugepages to reserve at boot (default 1 GiB
        total). Used for AF_XDP UMEM and large parser ring allocations.
      '';
    };

    jumbo = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        If true, set MTU 9000 on peer interfaces. Default 1500 for
        parser-result reproducibility against upstream kernel selftests.
      '';
    };

    gro = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        If true, enable GRO/LRO/TSO/GSO on peer interfaces. Default off
        because these offloads coalesce packets before the parser sees
        them, distorting per-packet measurements. Turn on for pure
        aggregate-throughput tests.
      '';
    };

    installEthtool = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        If true, add ethtool, bpftools, and perf to systemPackages.
        Required for the per-NIC tuning services and for manual
        diagnostics. Disable only if you provision these elsewhere.
      '';
    };

    disableMitigations = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        If true, set mitigations=off on the kernel command line. Removes
        ~10-20% syscall-path overhead. INSECURE on multi-tenant or
        internet-facing hosts; safe on a dedicated benchmark host with
        no untrusted code.
      '';
    };

    disableNonEssentialServices = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        If true (default), force-disable services that don't belong on a
        dedicated benchmark host because they introduce scheduler noise,
        periodic wakeups, or packet traffic on peer NICs. Disables:
        grafana, prometheus, prometheus-exporter-node, nginx, avahi,
        lldpd (the sneakiest — sends LLDP frames on ALL interfaces
        including the peer NICs every 30s, polluting the measurement
        window), docker, systemd-oomd, and the fstrim / logrotate /
        systemd-tmpfiles-clean / nix-gc timers. Set false if you genuinely
        want any of these (e.g. a dashboard on a shared host).
      '';
    };

    lowJitter = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Opt-in aggressive jitter reduction for ns-precision latency
        measurements. When true:
          - disables CPU turbo boost at boot (AMD/Intel: writes 0 to
            /sys/devices/system/cpu/cpufreq/boost or intel_pstate/no_turbo)
          - adds nowatchdog + cpufreq.default_governor=performance to
            kernel params (complements the sysctl + governor settings
            applied later in boot)
          - sets kernel.nmi_watchdog=0 (removes 1 Hz per-CPU NMI)
          - sets kernel.numa_balancing=0 (single-NUMA Ryzen has no work
            to do anyway, but the scanner thread still wakes up)
          - pins management-interface IRQs to housekeeping CPUs (0, 1)
            so they never touch the isolated cores

        COST: ~8% peak single-thread throughput (no turbo). Worth it for
        ns-precision latency tails; turn off for Mpps-ceiling runs.
      '';
    };

    managementInterface = lib.mkOption {
      type = lib.types.str;
      default = "eno1";
      description = ''
        Name of the management / admin interface. Its IRQs are pinned
        off the isolated cores when lowJitter = true. Default "eno1"
        matches hp2/hp5 (Realtek onboard 1GbE); override to e.g. "eth0"
        on other hardware.
      '';
    };
  };

  config = lib.mkIf cfg.enable {

    # ---- Kernel command line ----
    boot.kernelParams = [
      "processor.max_cstate=1"
      "transparent_hugepage=never"
      "audit=0"
      "default_hugepagesz=2M"
      "hugepagesz=2M"
      "hugepages=${toString cfg.hugepages2M}"
    ]
    ++ lib.optional cfg.disableMitigations "mitigations=off"
    ++ lib.optionals (cfg.isolatedCpus != [ ]) [
      "isolcpus=${cpuList}"
      "nohz_full=${cpuList}"
      "rcu_nocbs=${cpuList}"
    ]
    ++ lib.optionals cfg.lowJitter [
      # Suppress per-CPU NMI watchdog timer (1 Hz on each CPU — a
      # persistent jitter floor for ns-precision tails).
      "nowatchdog"
      # Lock the governor at boot so early userspace doesn't briefly
      # run at "ondemand" before the sysctl takes over.
      "cpufreq.default_governor=performance"
    ];

    # ---- sysctls ----
    boot.kernel.sysctl = {
      "kernel.perf_event_paranoid" = lib.mkDefault 0;
      "kernel.sched_rt_runtime_us" = lib.mkDefault (-1);
      "net.core.bpf_jit_enable" = lib.mkDefault 1;
      "net.core.bpf_jit_harden" = lib.mkDefault 0;
      "net.core.busy_poll" = lib.mkDefault 50;
      "net.core.busy_read" = lib.mkDefault 50;
      "net.core.netdev_max_backlog" = lib.mkDefault 50000;
    } // lib.optionalAttrs cfg.lowJitter {
      # Complements the nowatchdog kernel param at runtime.
      "kernel.nmi_watchdog" = lib.mkDefault 0;
      # Single-NUMA Ryzen: no pages to migrate, but the scanner thread
      # still periodically walks every process's mm.
      "kernel.numa_balancing" = lib.mkDefault 0;
    };

    # ---- Power & scheduler ----
    powerManagement.cpuFreqGovernor = lib.mkDefault "performance";
    services.irqbalance.enable = lib.mkForce false;

    # ---- Static addressing on peer interfaces ----
    networking.interfaces = lib.mapAttrs' (ifname: addr:
      lib.nameValuePair ifname {
        ipv4.addresses = [
          (let
            parts = lib.splitString "/" addr.local;
            ip = lib.elemAt parts 0;
            prefix = lib.toInt (lib.elemAt parts 1);
          in { address = ip; prefixLength = prefix; })
        ];
      }
    ) cfg.addresses;

    # Disable DHCP on peer interfaces (we set static IPs above).
    networking.dhcpcd.denyInterfaces = cfg.peerInterfaces;

    # ---- Per-NIC tuning + affinity services ----
    systemd.services = lib.mkMerge ([
      (lib.listToAttrs (map
        (ifname: lib.nameValuePair "xdp2-nic-tune-${ifname}"
          (mkNicTuneService ifname))
        cfg.peerInterfaces))
      (lib.listToAttrs (map
        (ifname: lib.nameValuePair "xdp2-nic-affinity-${ifname}"
          (mkNicAffinityService ifname))
        cfg.peerInterfaces))
    ] ++ lib.optional cfg.lowJitter {
      # Disable CPU turbo boost. Not exposed as a sysctl; has to be
      # poked via /sys. Runs early so the first benchmark after boot
      # sees steady-state frequency. Works for AMD (cpufreq/boost) and
      # Intel (intel_pstate/no_turbo) paths — tries both, ignores
      # failure on the path that isn't present.
      xdp2-testbed-disable-boost = {
        description = "xdp2 testbed: disable CPU turbo for jitter reduction";
        wantedBy = [ "multi-user.target" ];
        after = [ "sysinit.target" ];
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
        };
        script = ''
          if [ -w /sys/devices/system/cpu/cpufreq/boost ]; then
            echo 0 > /sys/devices/system/cpu/cpufreq/boost || true
          fi
          if [ -w /sys/devices/system/cpu/intel_pstate/no_turbo ]; then
            echo 1 > /sys/devices/system/cpu/intel_pstate/no_turbo || true
          fi
        '';
      };

      # Pin management-interface IRQs to the housekeeping CPUs (0 and 1
      # — mask 0x3) so ssh / prometheus-scrape / etc. never steal cycles
      # from the isolated cores.
      xdp2-testbed-mgmt-affinity = {
        description = "xdp2 testbed: pin ${cfg.managementInterface} IRQs to CPUs 0,1";
        wantedBy = [ "multi-user.target" ];
        after = [ "network-online.target" ];
        wants = [ "network-online.target" ];
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
        };
        path = [ pkgs.gawk pkgs.coreutils ];
        script = ''
          set -u
          ifc=${cfg.managementInterface}
          # Match either "ifc" or "ifc-..." at end of /proc/interrupts line.
          while read -r line; do
            irq=$(echo "$line" | awk -F: '{gsub(/ /,"",$1); print $1}')
            echo 3 > /proc/irq/$irq/smp_affinity 2>/dev/null || true
          done < <(grep -E "($ifc|$ifc-)" /proc/interrupts || true)
        '';
      };
    });

    # ---- Disable noisy / non-essential services ----
    # Each of these shows up in perf top / ftrace as a periodic wakeup
    # or as packet traffic on the peer NICs. All can be re-enabled by
    # setting xdp2.testbed.disableNonEssentialServices = false; or by
    # using lib.mkForce in the importing configuration.
    services.grafana.enable = lib.mkIf cfg.disableNonEssentialServices (lib.mkForce false);
    services.prometheus.enable = lib.mkIf cfg.disableNonEssentialServices (lib.mkForce false);
    services.prometheus.exporters.node.enable = lib.mkIf cfg.disableNonEssentialServices (lib.mkForce false);
    services.nginx.enable = lib.mkIf cfg.disableNonEssentialServices (lib.mkForce false);
    services.avahi.enable = lib.mkIf cfg.disableNonEssentialServices (lib.mkForce false);
    # lldpd is the worst offender: sends LLDP frames on ALL interfaces
    # (including peer NICs) every 30s, landing inside measurement windows.
    services.lldpd.enable = lib.mkIf cfg.disableNonEssentialServices (lib.mkForce false);
    virtualisation.docker.enable = lib.mkIf cfg.disableNonEssentialServices (lib.mkForce false);
    systemd.oomd.enable = lib.mkIf cfg.disableNonEssentialServices (lib.mkForce false);

    # Periodic timers — each fires a wakeup on some CPU. Negligible in
    # aggregate, visible in ns-precision tails. Disable the services
    # that own these timers; NixOS then never generates the .timer unit.
    services.fstrim.enable = lib.mkIf cfg.disableNonEssentialServices (lib.mkForce false);
    services.logrotate.enable = lib.mkIf cfg.disableNonEssentialServices (lib.mkForce false);
    nix.gc.automatic = lib.mkIf cfg.disableNonEssentialServices (lib.mkForce false);

    # ---- Tools ----
    environment.systemPackages = lib.optionals cfg.installEthtool [
      pkgs.ethtool
      pkgs.bpftools
      config.boot.kernelPackages.perf
    ];

    # ---- Sanity assertions ----
    assertions = [
      {
        assertion = lib.all (ifname: cfg.addresses ? ${ifname})
          cfg.peerInterfaces || cfg.addresses == { };
        message = ''
          xdp2.testbed: peerInterfaces and addresses must agree —
          either set addresses for every peer interface, or leave
          addresses empty (and configure IPs elsewhere).
        '';
      }
      {
        assertion = cfg.hugepages2M >= 0;
        message = "xdp2.testbed.hugepages2M must be non-negative.";
      }
    ];
  };
}
