# MicroVM Phase 2: Adding ARM and RISC-V Architectures

**Status:** APPROVED - Ready for Implementation
**Created:** 2026-02-18
**Author:** Claude (with user guidance)

---

## Decisions

- **Timeouts**: Start with proposed values, adjust as needed
- **Kernel**: Use `linuxPackages_latest` for cross-arch VMs (better BTF support)
- **Cleanup**: Delete unused `x86_64.nix`
- **Package layout**: Nested structure (`.#microvms.aarch64`, not `.#microvm-aarch64`)
- **Test targets**: Individual per-arch tests AND combined all-architectures test

---

## Overview

This plan adds **aarch64** (ARM64) and **riscv64** (RISC-V 64-bit) architectures to the existing MicroVM test infrastructure. The current implementation supports only x86_64; this phase extends it to cover cross-architecture eBPF testing.

### Goals

1. Add aarch64 and riscv64 VM definitions
2. Keep the Nix code DRY, modular, and idiomatic
3. Maintain backwards compatibility with existing x86_64 workflows
4. Prepare the foundation for future architectures (riscv32, s390x, etc.)
5. Provide test targets for individual and combined architecture testing

### Non-Goals (Deferred to Phase 3+)

- Kernel version matrix testing
- s390x (Big Endian validation)
- riscv32 (32-bit validation)
- Parallel test execution
- CI integration

---

## Current State Analysis

### Existing Files

| File | Purpose |
|------|---------|
| `nix/microvms/constants.nix` | Port allocation, architecture configs, timeouts |
| `nix/microvms/default.nix` | Entry point, generates packages for `supportedArchs` |
| `nix/microvms/mkVm.nix` | VM builder function (arch-parameterized) |
| `nix/microvms/lib.nix` | Helper functions for lifecycle/console scripts |
| `nix/microvms/x86_64.nix` | **Unused** - appears to be legacy |

### Current Architecture Support

Only `x86_64` is currently in `supportedArchs`. The infrastructure is designed to be extensible:
- `lib.genAttrs supportedArchs` generates scripts for all architectures
- `constants.nix` has port allocation scheme for aarch64, riscv64, riscv32
- `mkVm.nix` has placeholders for future architectures

### Key Design Principles (from existing code)

1. **Single source of truth**: All arch configs in `constants.nix`
2. **DRY generation**: `lib.genAttrs` loops over `supportedArchs`
3. **Backwards compatibility**: Legacy exports for x86_64 without arch suffix
4. **Flat package exports**: `packages.xdp2-lifecycle-full-test-aarch64`

---

## Implementation Plan

### Step 1: Update `constants.nix` - Add Architecture Definitions

Add complete architecture configurations for aarch64 and riscv64.

**Changes:**

```nix
# In architectures = { ... }

aarch64 = {
  nixSystem = "aarch64-linux";
  qemuMachine = "virt";
  qemuCpu = "cortex-a72";
  useKvm = false;  # Cross-arch emulation (QEMU TCG)
  serialPort = portBase + archPortOffset.aarch64;       # 23510
  virtioPort = portBase + archPortOffset.aarch64 + 1;   # 23511
  mem = 1024;
  vcpu = 2;
  description = "aarch64 (ARM64, QEMU emulated)";
};

riscv64 = {
  nixSystem = "riscv64-linux";
  qemuMachine = "virt";
  qemuCpu = "rv64";  # Default RISC-V 64-bit CPU
  useKvm = false;    # Cross-arch emulation (QEMU TCG)
  serialPort = portBase + archPortOffset.riscv64;       # 23520
  virtioPort = portBase + archPortOffset.riscv64 + 1;   # 23521
  mem = 1024;
  vcpu = 2;
  description = "riscv64 (RISC-V 64-bit, QEMU emulated)";
};
```

**Add kernel package configuration** (use latest for better BTF support):

```nix
# Kernel configuration
# Use linuxPackages_latest for cross-arch VMs (better BTF/eBPF support)
getKernelPackage = arch:
  if architectures.${arch}.useKvm or false
  then "linuxPackages"        # Stable for KVM (x86_64)
  else "linuxPackages_latest"; # Latest for emulated (better BTF)
```

**Add timeout profiles** for emulated architectures (they're slower than KVM):

```nix
# New timeout profiles for emulated architectures
timeoutsQemu = {
  build = 600;
  processStart = 10;      # Slower startup
  serialReady = 60;       # Emulation overhead
  virtioReady = 90;       # More time for virtio
  serviceReady = 120;     # More time for systemd
  command = 10;
  shutdown = 60;
  boot = 120;
};

timeoutsQemuSlow = {
  build = 600;
  processStart = 15;
  serialReady = 90;
  virtioReady = 120;
  serviceReady = 180;     # RISC-V is slower
  command = 15;
  shutdown = 90;
  boot = 180;
};
```

**Add helper to get timeouts by architecture:**

```nix
getTimeouts = arch:
  if architectures.${arch}.useKvm or false
  then timeouts       # KVM (fast)
  else if arch == "riscv64" || arch == "riscv32"
  then timeoutsQemuSlow  # RISC-V is particularly slow
  else timeoutsQemu;     # Other emulated archs
```

---

### Step 2: Update `mkVm.nix` - Add QEMU Arguments

Add architecture-specific QEMU arguments for aarch64 and riscv64.

**Changes:**

```nix
# In archQemuArgs = { ... }

aarch64 = [
  "-machine" cfg.qemuMachine
  "-cpu" cfg.qemuCpu
];

riscv64 = [
  "-machine" cfg.qemuMachine
  "-cpu" cfg.qemuCpu
  "-bios" "default"  # Use OpenSBI firmware
];
```

**Handle console device differences:**

The aarch64 serial console uses `ttyAMA0` instead of `ttyS0`. Add architecture-aware console parameters:

```nix
# Console device mapping
archConsoleDevice = {
  x86_64 = "ttyS0";
  aarch64 = "ttyAMA0";
  riscv64 = "ttyS0";
};

# In boot.kernelParams:
boot.kernelParams = [
  "console=${archConsoleDevice.${arch}},115200"
  "console=hvc0"
];
```

---

### Step 3: Update `default.nix` - Enable New Architectures

Simply add the new architectures to `supportedArchs`:

```nix
supportedArchs = [ "x86_64" "aarch64" "riscv64" ];
```

That's it! The existing `lib.genAttrs supportedArchs` pattern automatically generates all lifecycle scripts, helpers, and packages for the new architectures.

---

### Step 4: Update `lib.nix` - Use Architecture-Specific Timeouts

Modify the lifecycle scripts to use architecture-aware timeouts.

**Changes:**

Pass timeouts through the arch config rather than using global constants:

```nix
mkLifecycleScripts = { arch, scriptsDir }:
let
  cfg = getArchConfig arch;
  hostname = getHostname arch;
  processName = getProcessName arch;
  timeouts = constants.getTimeouts arch;  # NEW: arch-specific timeouts
in {
  # Use timeouts.serialReady instead of constants.timeouts.serialReady
  # ... etc
};
```

---

### Step 5: Update `flake.nix` - Nested Package Structure & Test Targets

Reorganize packages into nested structure and add test targets.

**Changes:**

```nix
packages = {
  # ... existing packages (xdp2, tests, etc.) ...

  # =========================================================
  # MicroVM Infrastructure (nested structure)
  # =========================================================
  #
  # Usage:
  #   nix build .#microvms.x86_64      # Build x86_64 VM
  #   nix build .#microvms.aarch64     # Build aarch64 VM
  #   nix build .#microvms.riscv64     # Build riscv64 VM
  #
  #   nix run .#microvms.test-x86_64   # Test x86_64 only
  #   nix run .#microvms.test-aarch64  # Test aarch64 only
  #   nix run .#microvms.test-riscv64  # Test riscv64 only
  #   nix run .#microvms.test-all      # Test ALL architectures
  #
  microvms = {
    # VM derivations
    x86_64 = microvms.vms.x86_64;
    aarch64 = microvms.vms.aarch64;
    riscv64 = microvms.vms.riscv64;

    # Individual architecture tests
    test-x86_64 = microvms.tests.x86_64;
    test-aarch64 = microvms.tests.aarch64;
    test-riscv64 = microvms.tests.riscv64;

    # Combined test (all architectures)
    test-all = microvms.tests.all;

    # Lifecycle scripts (nested by arch)
    lifecycle = microvms.lifecycleByArch;

    # Helper scripts (nested by arch)
    helpers = microvms.helpers;
  };

  # =========================================================
  # Backwards compatibility (legacy flat exports)
  # =========================================================
  # Keep existing exports working:
  #   nix build .#microvm-x86_64
  #   nix run .#xdp2-lifecycle-full-test
  #
  microvm-x86_64 = microvms.vms.x86_64;
  # ... other legacy exports via microvms.packages ...
};
```

**Test targets implementation** (in `default.nix`):

```nix
# Individual architecture test runners
testsByArch = lib.genAttrs supportedArchs (arch:
  pkgs.writeShellApplication {
    name = "xdp2-test-${arch}";
    runtimeInputs = [ pkgs.coreutils ];
    text = ''
      echo "========================================"
      echo "  XDP2 MicroVM Test: ${arch}"
      echo "========================================"
      ${lifecycleByArch.${arch}.fullTest}/bin/xdp2-lifecycle-full-test-${arch}
    '';
  }
);

# Combined test runner (all architectures)
testAll = pkgs.writeShellApplication {
  name = "xdp2-test-all-architectures";
  runtimeInputs = [ pkgs.coreutils ];
  text = ''
    echo "========================================"
    echo "  XDP2 MicroVM Test: ALL ARCHITECTURES"
    echo "========================================"
    echo ""
    echo "Architectures: ${lib.concatStringsSep ", " supportedArchs}"
    echo ""

    FAILED=""
    for arch in ${lib.concatStringsSep " " supportedArchs}; do
      echo ""
      echo "════════════════════════════════════════"
      echo "  Testing: $arch"
      echo "════════════════════════════════════════"
      if ! nix run ".#microvms.test-$arch"; then
        FAILED="$FAILED $arch"
        echo "FAIL: $arch"
      else
        echo "PASS: $arch"
      fi
    done

    echo ""
    echo "========================================"
    echo "  Summary"
    echo "========================================"
    if [ -n "$FAILED" ]; then
      echo "FAILED:$FAILED"
      exit 1
    else
      echo "All architectures passed!"
      exit 0
    fi
  '';
};
```

---

### Step 6: Clean Up Legacy File

Remove or archive `nix/microvms/x86_64.nix` if it's unused (appears to be a leftover from early development).

---

## File-by-File Changes Summary

| File | Changes |
|------|---------|
| `constants.nix` | Add aarch64/riscv64 configs, timeout profiles, `getTimeouts`, `getKernelPackage` |
| `mkVm.nix` | Add QEMU args, console device mapping, use `getKernelPackage` |
| `default.nix` | Add to `supportedArchs`, add `testsByArch`, add `testAll` |
| `lib.nix` | Use arch-specific timeouts in lifecycle scripts |
| `flake.nix` | Nested `microvms.*` structure, test targets, backwards compat |
| `x86_64.nix` | **Delete** (unused wrapper) |

---

## Generated Outputs

Once implemented, the following package structure will be available:

### Primary Interface (Nested)

```bash
# Build VMs
nix build .#microvms.x86_64
nix build .#microvms.aarch64
nix build .#microvms.riscv64

# Test individual architectures
nix run .#microvms.test-x86_64
nix run .#microvms.test-aarch64
nix run .#microvms.test-riscv64

# Test ALL architectures (sequential)
nix run .#microvms.test-all

# Access lifecycle scripts
nix run .#microvms.lifecycle.aarch64.fullTest
nix run .#microvms.lifecycle.riscv64.checkBuild

# Access helper scripts
nix run .#microvms.helpers.aarch64.status
nix run .#microvms.helpers.riscv64.loginVirtio
```

### Legacy Interface (Backwards Compatible)

Existing flat exports continue to work:

```bash
# Legacy x86_64 exports (no arch suffix)
nix build .#microvm-x86_64
nix run .#xdp2-lifecycle-full-test
nix run .#xdp2-vm-console

# Arch-suffixed exports (generated automatically)
nix run .#xdp2-lifecycle-full-test-aarch64
nix run .#xdp2-lifecycle-full-test-riscv64
nix run .#xdp2-vm-status-aarch64
nix run .#xdp2-vm-status-riscv64
```

### Per-Architecture Scripts (Auto-Generated)

For each architecture, these are automatically generated:

| Script Pattern | Description |
|---------------|-------------|
| `xdp2-lifecycle-full-test-{arch}` | Full lifecycle test |
| `xdp2-lifecycle-0-build-{arch}` | Build phase |
| `xdp2-lifecycle-1-check-process-{arch}` | Process check |
| `xdp2-lifecycle-2-check-serial-{arch}` | Serial console check |
| `xdp2-lifecycle-2b-check-virtio-{arch}` | Virtio console check |
| `xdp2-lifecycle-3-verify-ebpf-loaded-{arch}` | eBPF load verification |
| `xdp2-lifecycle-4-verify-ebpf-running-{arch}` | eBPF status check |
| `xdp2-lifecycle-5-shutdown-{arch}` | Graceful shutdown |
| `xdp2-lifecycle-6-wait-exit-{arch}` | Wait for exit |
| `xdp2-lifecycle-force-kill-{arch}` | Force kill |
| `xdp2-vm-serial-{arch}` | Serial console connection |
| `xdp2-vm-virtio-{arch}` | Virtio console connection |
| `xdp2-vm-login-serial-{arch}` | Interactive serial login |
| `xdp2-vm-login-virtio-{arch}` | Interactive virtio login |
| `xdp2-vm-status-{arch}` | VM status check |
| `xdp2-vm-expect-run-{arch}` | Expect-based command runner |

---

## Testing Plan

### Phase 2a: Basic Validation

1. **Nix evaluation**: Verify configs evaluate correctly
   ```bash
   nix eval --json '.#packages.x86_64-linux.microvm-aarch64.name'
   nix eval --json '.#packages.x86_64-linux.microvm-riscv64.name'
   ```

2. **Build VMs**: Build each architecture
   ```bash
   nix build .#microvm-aarch64
   nix build .#microvm-riscv64
   ```

3. **Boot test**: Verify VMs boot (will be slow due to emulation)
   ```bash
   nix run .#xdp2-lifecycle-full-test-aarch64
   nix run .#xdp2-lifecycle-full-test-riscv64
   ```

### Phase 2b: eBPF Validation

1. **BTF check**: Verify BTF is available in guest
2. **bpftool check**: Verify bpftool works
3. **XDP capability**: Verify XDP can be attached

### Expected Timing

| Architecture | Boot Time | Total Lifecycle |
|--------------|-----------|-----------------|
| x86_64 (KVM) | ~5-10s | ~30s |
| aarch64 (QEMU) | ~30-60s | ~2-3 min |
| riscv64 (QEMU) | ~60-120s | ~3-5 min |

---

## Implementation Order

1. **Step 1**: `constants.nix` - Add arch configs, timeout profiles, kernel helper
2. **Step 2**: `mkVm.nix` - Add QEMU args, console mapping, use kernel helper
3. **Step 3**: `default.nix` - Enable archs, add test runners (`testsByArch`, `testAll`)
4. **Step 4**: `lib.nix` - Wire up arch-specific timeouts
5. **Step 5**: `flake.nix` - Nested `microvms.*` structure, test targets
6. **Step 6**: Delete `x86_64.nix`
7. **Step 7**: Test - Verify nix evaluation
8. **Step 8**: Test - Build and run aarch64 (simpler emulation)
9. **Step 9**: Test - Build and run riscv64 (slower, may need timeout tuning)
10. **Step 10**: Test - Run `test-all` to verify combined runner

---

## Risks and Mitigations

### Risk 1: Kernel/BTF Support for Cross-Arch

**Issue**: The default `linuxPackages` may not have full BTF support for all architectures.

**Mitigation**: The existing BTF check in `mkVm.nix` will fail early if BTF is missing. If this happens, we may need to use `linuxPackages_latest` or configure kernel patches per-architecture.

### Risk 2: QEMU Emulation Speed

**Issue**: RISC-V emulation is notably slow (10-50x slower than native).

**Mitigation**:
- Increased timeouts for emulated architectures
- Document expected timing
- Future: parallel execution to amortize wall-clock time

### Risk 3: Console Device Differences

**Issue**: aarch64 uses `ttyAMA0` instead of `ttyS0` for serial.

**Mitigation**: Add architecture-aware console device mapping in `mkVm.nix`.

---

## Future Work (Phase 3+)

- Add riscv32 (32-bit pointer validation)
- Add s390x (Big Endian validation)
- Implement test modes (`fast`, `full`, `matrix`)
- Parallel VM execution
- Kernel version matrix
- CI integration with resource throttling

---

## Resolved Questions

All questions have been answered:

1. **Timeout values**: Start with proposed values, adjust as needed ✓
2. **Default kernel**: Use `linuxPackages_latest` for cross-arch VMs ✓
3. **x86_64.nix cleanup**: Confirmed - delete it ✓
4. **Package layout**: Nested structure (`.#microvms.aarch64`) ✓
5. **Test targets**: Added individual and combined test runners ✓
