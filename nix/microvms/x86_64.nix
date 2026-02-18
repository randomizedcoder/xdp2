# nix/microvms/x86_64.nix
#
# MicroVM definition for x86_64 eBPF testing.
#
# Phase 1: Single VM with stable kernel
# See: documentation/nix/microvm-implementation-phase1.md
#
{ pkgs, lib, microvm, nixpkgs }:

let
  constants = import ./constants.nix;
  cfg = constants.architectures.x86_64;
  hostname = constants.getHostname "x86_64";

  # Check that the kernel has BTF support
  # This is required for CO-RE eBPF programs
  kernelHasBtf = pkgs.${constants.kernelPackage}.kernel.configfile != null &&
    builtins.match ".*CONFIG_DEBUG_INFO_BTF=y.*"
      (builtins.readFile pkgs.${constants.kernelPackage}.kernel.configfile) != null;

  # Assertion to fail early if BTF is not available
  _ = assert kernelHasBtf || throw ''
    ERROR: Kernel ${constants.kernelPackage} does not have BTF support enabled.

    BTF (BPF Type Format) is required for CO-RE eBPF programs.
    The VM guest kernel must be built with CONFIG_DEBUG_INFO_BTF=y.

    Note: The hypervisor (host) machine compiles eBPF to bytecode quickly,
    while the VM only needs to verify and JIT the pre-compiled bytecode.
    A more powerful host machine speeds up eBPF compilation significantly.

    Options:
    1. Use a different kernel package (e.g., linuxPackages_latest)
    2. Build a custom kernel with BTF enabled
    3. Use a NixOS system with BTF-enabled kernel

    Current kernel: ${constants.kernelPackage}
  ''; true;

in (nixpkgs.lib.nixosSystem {
  system = cfg.nixSystem;

  modules = [
    # MicroVM module
    microvm.nixosModules.microvm

    # VM configuration
    ({ config, pkgs, ... }:
    let
      # bpftools package (provides bpftool command)
      bpftools = pkgs.bpftools;

      # Self-test script using writeShellApplication for correctness
      selfTestScript = pkgs.writeShellApplication {
        name = "xdp2-self-test";
        runtimeInputs = [
          pkgs.coreutils
          pkgs.iproute2
          bpftools
        ];
        text = ''
          echo "========================================"
          echo "  XDP2 MicroVM Self-Test"
          echo "========================================"
          echo ""
          echo "Architecture: $(uname -m)"
          echo "Kernel: $(uname -r)"
          echo "Hostname: $(hostname)"
          echo ""

          # Check BTF availability
          echo "--- BTF Check ---"
          if [ -f /sys/kernel/btf/vmlinux ]; then
            echo "BTF: AVAILABLE"
            ls -la /sys/kernel/btf/vmlinux
          else
            echo "BTF: NOT AVAILABLE"
            echo "ERROR: BTF is required for CO-RE eBPF programs"
            exit 1
          fi
          echo ""

          # Check bpftool
          echo "--- bpftool Check ---"
          bpftool version
          echo ""

          # Probe BPF features
          echo "--- BPF Features (first 15) ---"
          bpftool feature probe kernel 2>/dev/null | head -15 || true
          echo ""

          # Check XDP support
          echo "--- XDP Support ---"
          if bpftool feature probe kernel 2>/dev/null | grep -q "xdp"; then
            echo "XDP: SUPPORTED"
          else
            echo "XDP: Check manually"
          fi
          echo ""

          # Check network interface for XDP
          echo "--- Network Interface (${constants.xdpInterface}) ---"
          if ip link show ${constants.xdpInterface} >/dev/null 2>&1; then
            echo "Interface: ${constants.xdpInterface} AVAILABLE"
            ip link show ${constants.xdpInterface}
          else
            echo "Interface: ${constants.xdpInterface} NOT FOUND"
            echo "Available interfaces:"
            ip link show
          fi
          echo ""

          echo "========================================"
          echo "  Self-Test Complete: SUCCESS"
          echo "========================================"
        '';
      };
    in {
      # ==================================================================
      # Basic NixOS configuration
      # ==================================================================

      system.stateVersion = "26.05";
      networking.hostName = hostname;

      # ==================================================================
      # MicroVM configuration
      # ==================================================================

      microvm = {
        hypervisor = "qemu";
        mem = cfg.mem;
        vcpu = cfg.vcpu;

        # No persistent storage needed for testing
        volumes = [];

        # Network interface for XDP testing
        # This creates eth0 inside the VM where XDP programs can be attached
        interfaces = [{
          type = "user";  # QEMU user networking (NAT to host)
          id = "eth0";
          mac = constants.tapConfig.mac;
        }];

        # Mount host Nix store for instant access to binaries
        # This avoids copying binaries into the VM image
        shares = [{
          source = "/nix/store";
          mountPoint = "/nix/store";
          tag = "nix-store";
          proto = "9p";
        }];

        # QEMU configuration
        qemu = {
          # Disable default serial console (we configure our own)
          serialConsole = false;

          extraArgs = [
            # Enable KVM acceleration
            "-enable-kvm"
            "-cpu" cfg.qemuCpu

            # VM identification
            "-name" "${hostname},process=${hostname}"

            # Serial console on TCP port (for boot messages)
            "-serial" "tcp:127.0.0.1:${toString cfg.serialPort},server,nowait"

            # Virtio console (faster, for interactive use)
            "-device" "virtio-serial-pci"
            "-chardev" "socket,id=virtcon,port=${toString cfg.virtioPort},host=127.0.0.1,server=on,wait=off"
            "-device" "virtconsole,chardev=virtcon"
          ];
        };
      };

      # ==================================================================
      # Kernel configuration
      # ==================================================================

      # Use stable kernel (Phase 1)
      boot.kernelPackages = pkgs.${constants.kernelPackage};

      # Console configuration
      boot.kernelParams = [
        "console=ttyS0,115200"  # Serial first (for early boot)
        "console=hvc0"          # Virtio console (becomes primary)
      ];

      # BTF support for CO-RE eBPF programs
      # Note: Default NixOS kernel already has CONFIG_DEBUG_INFO_BTF=y
      # No patch needed - using cached kernel from nixpkgs

      # eBPF sysctls
      boot.kernel.sysctl = {
        "net.core.bpf_jit_enable" = 1;
        "kernel.unprivileged_bpf_disabled" = 0;
      };

      # ==================================================================
      # User configuration
      # ==================================================================

      # Auto-login for testing (no password prompts)
      services.getty.autologinUser = "root";
      users.users.root.password = "";

      # ==================================================================
      # Test tools
      # ==================================================================

      environment.systemPackages = with pkgs; [
        # BPF tools (kernel-matched version)
        bpftools

        # Network tools
        iproute2
        tcpdump
        ethtool

        # Basic utilities
        coreutils
        procps
        util-linux

        # Self-test script
        selfTestScript
      ];

      # ==================================================================
      # Self-test service (runs the writeShellApplication script)
      # ==================================================================

      systemd.services.xdp2-self-test = {
        description = "XDP2 MicroVM Self-Test";
        after = [ "multi-user.target" ];
        wantedBy = [ "multi-user.target" ];

        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          ExecStart = "${selfTestScript}/bin/xdp2-self-test";
        };
      };
    })
  ];
}).config.microvm.declaredRunner
