# Adding New Architectures to MicroVM Infrastructure

This guide explains how to add support for new CPU architectures to the XDP2 MicroVM test infrastructure.

## Overview

The MicroVM infrastructure uses a modular, parameterized design that generates all scripts and VM definitions from templates. Adding a new architecture requires changes to only 3 files:

1. `nix/microvms/constants.nix` - Architecture configuration
2. `nix/microvms/default.nix` - Enable the architecture
3. `nix/microvms/mkVm.nix` - QEMU-specific arguments

All lifecycle scripts, helper tools, and flake packages are automatically generated.

## Step-by-Step Guide

### Step 1: Add Architecture Configuration

Edit `nix/microvms/constants.nix` to add the new architecture's configuration:

```nix
architectures = {
  # Existing x86_64 config...
  x86_64 = { ... };

  # Add new architecture
  aarch64 = {
    # Nix system identifier (must match nixpkgs system)
    nixSystem = "aarch64-linux";

    # QEMU configuration
    qemuMachine = "virt";
    qemuCpu = "cortex-a72";
    useKvm = false;  # true only if running on matching host

    # Console ports - use the port allocation scheme
    # Each arch gets a block of 10 ports starting at portBase + offset
    serialPort = portBase + archPortOffset.aarch64;       # 23510
    virtioPort = portBase + archPortOffset.aarch64 + 1;   # 23511

    # VM resources
    mem = 1024;  # MB
    vcpu = 2;

    # Description for UI/logs
    description = "aarch64 (ARM64)";
  };
};
```

Also add the port offset and hostname mapping:

```nix
# Port offset per architecture (each arch gets 10 ports)
archPortOffset = {
  x86_64 = 0;
  aarch64 = 10;   # Add this
  riscv64 = 20;
  riscv32 = 30;
};

# Hostname mapping (must be valid hostname - no underscores)
archHostname = {
  x86_64 = "x86-64";
  aarch64 = "aarch64";   # Add this
  riscv64 = "riscv64";
  riscv32 = "riscv32";
};
```

### Step 2: Enable the Architecture

Edit `nix/microvms/default.nix` to add the architecture to the supported list:

```nix
# Add new architectures here as they become supported.
# Each architecture must have a corresponding entry in constants.nix
supportedArchs = [ "x86_64" "aarch64" ];  # Add "aarch64"
```

### Step 3: Add QEMU Arguments

Edit `nix/microvms/mkVm.nix` to add architecture-specific QEMU arguments:

```nix
# Architecture-specific QEMU arguments
archQemuArgs = {
  x86_64 = [
    "-enable-kvm"
    "-cpu" cfg.qemuCpu
  ];

  # Add new architecture
  aarch64 = [
    "-machine" "virt"
    "-cpu" cfg.qemuCpu
    # Add any other aarch64-specific QEMU flags
  ];

  riscv64 = [
    "-machine" "virt"
    "-cpu" "rv64"
  ];
};
```

### Step 4: Verify the Configuration

After making changes, verify the configuration evaluates correctly:

```bash
# Stage new files if any (required for Nix to see them)
git add -A

# Verify evaluation
nix eval --json '.#packages.x86_64-linux.microvm-aarch64.name'

# List all packages for the new architecture
nix flake show 2>&1 | grep aarch64
```

### Step 5: Build and Test

```bash
# Build the VM
nix build .#microvm-aarch64

# Run lifecycle test (note: cross-arch VMs are slower without KVM)
nix run .#xdp2-lifecycle-full-test-aarch64

# Or run individual phases
nix run .#xdp2-lifecycle-0-build-aarch64
nix run .#xdp2-lifecycle-1-check-process-aarch64
```

## Generated Outputs

Once an architecture is added, the following are automatically generated:

### Flake Packages

| Package | Description |
|---------|-------------|
| `microvm-{arch}` | The MicroVM derivation |
| `xdp2-test-{arch}` | Simple test runner |
| `xdp2-lifecycle-0-build-{arch}` | Build phase |
| `xdp2-lifecycle-1-check-process-{arch}` | Process check |
| `xdp2-lifecycle-2-check-serial-{arch}` | Serial console check |
| `xdp2-lifecycle-2b-check-virtio-{arch}` | Virtio console check |
| `xdp2-lifecycle-3-verify-ebpf-loaded-{arch}` | eBPF load verification |
| `xdp2-lifecycle-4-verify-ebpf-running-{arch}` | eBPF status check |
| `xdp2-lifecycle-5-shutdown-{arch}` | Graceful shutdown |
| `xdp2-lifecycle-6-wait-exit-{arch}` | Wait for exit |
| `xdp2-lifecycle-force-kill-{arch}` | Force kill |
| `xdp2-lifecycle-full-test-{arch}` | Full lifecycle test |
| `xdp2-vm-serial-{arch}` | Serial console connection |
| `xdp2-vm-virtio-{arch}` | Virtio console connection |
| `xdp2-vm-login-serial-{arch}` | Interactive serial login |
| `xdp2-vm-login-virtio-{arch}` | Interactive virtio login |
| `xdp2-vm-run-serial-{arch}` | Run command via serial |
| `xdp2-vm-run-virtio-{arch}` | Run command via virtio |
| `xdp2-vm-status-{arch}` | VM status check |
| `xdp2-vm-expect-run-{arch}` | Expect-based command runner |
| `xdp2-vm-debug-expect-{arch}` | Expect-based debug tool |
| `xdp2-vm-expect-verify-service-{arch}` | Service verification |

### Programmatic Access

```nix
# In flake.nix or other Nix code
microvms.vms.aarch64                    # VM derivation
microvms.lifecycle.aarch64.fullTest     # Full test script
microvms.helpers.aarch64.status         # Status helper
microvms.expect.aarch64.runCommand      # Expect runner
```

## Port Allocation

Each architecture is allocated a block of 10 TCP ports:

| Architecture | Base Port | Serial | Virtio | Reserved |
|--------------|-----------|--------|--------|----------|
| x86_64 | 23500 | 23500 | 23501 | 23502-23509 |
| aarch64 | 23510 | 23510 | 23511 | 23512-23519 |
| riscv64 | 23520 | 23520 | 23521 | 23522-23529 |
| riscv32 | 23530 | 23530 | 23531 | 23532-23539 |

Reserved ports can be used for future features (GDB, QEMU monitor, etc.).

## Architecture-Specific Considerations

### KVM Acceleration

KVM can only be used when the host and guest architectures match:

| Host | Guest | KVM Available |
|------|-------|---------------|
| x86_64 | x86_64 | Yes |
| x86_64 | aarch64 | No (TCG emulation) |
| aarch64 | aarch64 | Yes |
| aarch64 | x86_64 | No (TCG emulation) |

Set `useKvm = false` in constants.nix for cross-architecture VMs.

### Kernel Packages

The default kernel package (`linuxPackages`) may not support all architectures. You may need to:

1. Use architecture-specific kernel packages
2. Override `constants.kernelPackage` per architecture
3. Build custom kernels with required features

### QEMU Machine Types

Common QEMU machine types:

| Architecture | Machine Type | Notes |
|--------------|--------------|-------|
| x86_64 | `pc` or `q35` | Standard PC |
| aarch64 | `virt` | ARM virtual machine |
| riscv64 | `virt` | RISC-V virtual machine |
| riscv32 | `virt` | RISC-V 32-bit |

### Console Devices

Console device names vary by architecture:

| Architecture | Serial | Virtio |
|--------------|--------|--------|
| x86_64 | ttyS0 | hvc0 |
| aarch64 | ttyAMA0 | hvc0 |
| riscv64 | ttyS0 | hvc0 |

Update kernel parameters in `mkVm.nix` if needed:

```nix
boot.kernelParams = [
  "console=ttyAMA0,115200"  # aarch64 serial
  "console=hvc0"            # virtio (universal)
];
```

## Troubleshooting

### VM Fails to Boot

1. Check QEMU arguments are correct for the architecture
2. Verify kernel package supports the architecture
3. Check console device names in kernel parameters
4. Try with increased memory (`mem = 2048`)

### Port Conflicts

If you see "port already in use" errors:

1. Check no other VMs are running: `nix run .#xdp2-vm-status-{arch}`
2. Force kill any stuck VMs: `nix run .#xdp2-lifecycle-force-kill-{arch}`
3. Verify port allocation doesn't conflict with other services

### Slow Performance

Cross-architecture VMs use QEMU's TCG (software emulation) instead of KVM:

1. Expect 10-100x slower execution
2. Increase timeouts in constants.nix for cross-arch testing
3. Consider using native hardware for CI

### BTF Not Available

If BTF verification fails:

1. Verify the kernel package has `CONFIG_DEBUG_INFO_BTF=y`
2. Check kernel version supports BTF for the architecture
3. Consider using `linuxPackages_latest` for newer BTF support

## Example: Adding RISC-V 64-bit

Complete example of adding riscv64 support:

```nix
# constants.nix
architectures.riscv64 = {
  nixSystem = "riscv64-linux";
  qemuMachine = "virt";
  qemuCpu = "rv64";
  useKvm = false;
  serialPort = 23520;
  virtioPort = 23521;
  mem = 1024;
  vcpu = 2;
  description = "RISC-V 64-bit";
};

# default.nix
supportedArchs = [ "x86_64" "riscv64" ];

# mkVm.nix
archQemuArgs.riscv64 = [
  "-machine" "virt"
  "-cpu" "rv64"
  "-bios" "default"
];
```

## See Also

- [MicroVM Lifecycle Management](./microvm-lifecycle.md) - Lifecycle phases and scripts
- [MicroVM Implementation Phase 1](./microvm-implementation-phase1.md) - Original implementation plan
- [MicroVM eBPF Test Design](./microvm-ebpf-test-design.md) - Comprehensive design document
