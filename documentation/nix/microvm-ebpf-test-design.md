# MicroVM eBPF Test Infrastructure Design

**Status:** DRAFT
**Created:** 2026-02-16
**Updated:** 2026-02-16
**Author:** Claude (with user guidance)

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Quick Start](#quick-start)
3. [Test Modes](#test-modes)
   - [Fast Mode (Development)](#fast-mode-development)
   - [Full Mode (CI/Release)](#full-mode-cirelease)
4. [High Confidence Testing](#high-confidence-testing)
   - [Endianness Validation](#endianness-validation)
   - [Kernel Version Matrix](#kernel-version-matrix)
   - [Verifier Log Export](#verifier-log-export)
5. [Performance Optimization](#performance-optimization)
   - [Compilation Strategy](#compilation-strategy)
   - [VM Resource Tuning](#vm-resource-tuning)
   - [Parallel Execution](#parallel-execution)
   - [CI Resource Throttling](#ci-resource-throttling)
   - [Caching](#caching)
6. [Architecture Overview](#architecture-overview)
7. [Supported Architectures](#supported-architectures)
8. [Advanced Nix Patterns](#advanced-nix-patterns)
   - [Functional Matrix Generation](#functional-matrix-generation)
   - [Store Injection via virtio-9p](#store-injection-via-virtio-9p)
   - [Systemd Test Driver](#systemd-test-driver)
   - [Cross-Compilation Overlays](#cross-compilation-overlays)
   - [NixOS Module Pattern](#nixos-module-pattern)
9. [Implementation](#implementation)
   - [Directory Structure](#directory-structure)
   - [Constants Module](#constants-module-nixmicrovmsconstantsnix)
   - [Matrix Generator](#matrix-generator-nixmicrovmsmatrixnix)
   - [VM Builder Function](#vm-builder-function-nixlibmk-vmnix)
   - [eBPF Base Module](#ebpf-base-module-nixmodulesebpf-basenix)
   - [Packages Module](#packages-module-nixmicrovmspackagesnix)
   - [Flake Integration](#flake-integration)
10. [Console Architecture](#console-architecture)
11. [BTF Requirements](#btf-bpf-type-format-requirements)
12. [VM Management Scripts](#vm-management-scripts)
13. [Automated Testing](#automated-testing)
14. [Usage Examples](#usage-examples)
15. [Troubleshooting](#troubleshooting)
16. [Future Enhancements](#future-enhancements)
17. [Cross-Compilation for Distribution](#cross-compilation-for-distribution)
   - [Architecture Targets](#architecture-targets)
   - [Cross-Compilation Strategy](#cross-compilation-strategy)
   - [Implementation](#implementation-1)
18. [Linux Package Generation](#linux-package-generation)
   - [Package Contents](#package-contents)
   - [Package Metadata](#package-metadata)
   - [Implementation Approach: FPM](#implementation-approach-fpm-effing-package-management)
   - [CI Release Workflow](#ci-release-workflow)
19. [Revision History](#revision-history)
20. [References](#references)

---

## Executive Summary

This document describes the design for a NixOS MicroVM-based test infrastructure for XDP2 eBPF programs. The infrastructure enables:

1. **Cross-architecture testing** - QEMU emulation for ARM64, RISC-V, MIPS64, PowerPC64, and s390x
2. **Native performance testing** - KVM acceleration for x86_64
3. **Dual console access** - Serial (ttyS0) for boot debugging, virtio (hvc0) for interactive use
4. **Reproducible environments** - Nix-based VM definitions with pinned kernel versions
5. **BTF-enabled kernels** - Required for CO-RE eBPF programs (CONFIG_DEBUG_INFO_BTF=y)
6. **Two test modes** - Fast mode for development iteration, full mode for CI/release
7. **Cross-compilation** - Build XDP2 binaries for x86_64, aarch64, riscv64, and armv7l
8. **Package generation** - Produce `.deb` (apt) and `.rpm` (dnf) packages for distribution

> **Note:** XDP and eBPF are Linux-only technologies. This infrastructure does not support FreeBSD, Solaris, or other non-Linux operating systems.

### BTF Support Status

> A PR has been submitted to microvm.nix to add native BTF support (`microvm.btf.enable = true`).
> Until that PR is merged, this design uses a kernel patch workaround (`CONFIG_DEBUG_INFO_BTF=y`).
> See the [BTF Requirements](#btf-bpf-type-format-requirements) section for details.

---

## Quick Start

```bash
# Fast mode: Test on x86_64 and riscv64 only (development)
nix run .#xdp2-test-fast

# Full mode: Test all 7 architectures (CI/release)
nix run .#xdp2-test-all

# Run a single architecture
nix build .#xdp2-test-vm-x86_64
./result/bin/microvm-run &
./result/bin/connect-console

# Check VM status
nix run .#xdp2-vm-check

# Cross-compile for different architectures
nix build .#cross.aarch64
nix build .#cross.riscv64
nix build .#cross.riscv32

# Generate distribution packages
nix build .#deb-x86_64    # Debian/Ubuntu x86_64
nix build .#deb-riscv64   # Debian/Ubuntu RISC-V 64-bit
nix build .#deb-riscv32   # Debian/Ubuntu RISC-V 32-bit
nix build .#rpm-riscv64   # Fedora RISC-V 64-bit
nix build .#packages-all  # All packages for all architectures
```

---

## Test Modes

The infrastructure provides two testing modes to balance development velocity with comprehensive coverage.

### Fast Mode (Development)

**Purpose:** Rapid iteration during development
**Architectures:** x86_64 (KVM), riscv64 (QEMU)
**Use case:** Local development, pre-commit checks

```bash
nix run .#xdp2-test-fast
```

Fast mode tests only two architectures:

| Architecture | Why Included |
|-------------|--------------|
| **x86_64** | Native KVM acceleration, fastest execution, primary development platform |
| **riscv64** | Catches cross-compilation issues, different endianness handling, growing embedded market |

This combination catches most issues while providing quick feedback. x86_64 runs at near-native speed with KVM, while riscv64 validates cross-architecture correctness.

### Full Mode (CI/Release)

**Purpose:** Comprehensive validation before merge/release
**Architectures:** All 7 (x86_64, aarch64, riscv64, riscv32, mips64, ppc64, s390x)
**Use case:** CI pipelines, release validation

```bash
nix run .#xdp2-test-all
```

Full mode tests every supported architecture to ensure:
- 32-bit compatibility (riscv32)
- Big-endian and little-endian correctness
- Architecture-specific BPF JIT behavior
- Pointer size handling across word sizes

### Mode Selection in CI

```yaml
# .github/workflows/test.yml
jobs:
  fast-check:
    # Run on every PR push
    runs-on: ubuntu-latest
    steps:
      - run: nix run .#xdp2-test-fast

  full-check:
    # Run on merge to main or release tags
    if: github.ref == 'refs/heads/main' || startsWith(github.ref, 'refs/tags/')
    runs-on: ubuntu-latest
    steps:
      - run: nix run .#xdp2-test-all
```

---

## High Confidence Testing

This section describes features designed to catch subtle bugs that only manifest on specific architectures or kernel versions.

### Endianness Validation

**Why it matters:** Network headers are Big Endian (network byte order). eBPF developers frequently make mistakes with `htons()`/`ntohs()` that only manifest on Big Endian hardware.

Our architecture matrix includes:
- **Little Endian:** x86_64, aarch64, riscv64, riscv32, mips64el, ppc64le
- **Big Endian:** s390x

The s390x (IBM z/Architecture) VM serves as our Big Endian validation target. Tests on s390x will catch byte-order bugs that pass on all Little Endian architectures.

**Byte-order verification test case:**

```bash
# Included in automated test suite for s390x
# Verifies XDP2's abstraction layer handles endianness correctly

# Test 1: Parse Ethernet header, verify EtherType
# Inject packet with EtherType 0x0800 (IPv4)
# XDP2 must correctly read this as 0x0800, not 0x0008

# Test 2: Parse IPv4 header, verify protocol field
# Inject packet with protocol 0x06 (TCP)
# Verify correct extraction regardless of host byte order

# Test 3: Parse TCP header, verify port numbers
# Inject packet with dst_port 80 (0x0050)
# XDP2 must read 80, not 20480 (0x5000)
```

**Implementation note:** The byte-order tests are critical for XDP2's value proposition. If the abstraction layer doesn't handle endianness correctly, users will write buggy code that "works on my machine" but fails in production on different hardware.

### Kernel Version Matrix

The BPF subsystem evolves rapidly. Features available in 6.x may not exist in 5.15 LTS:

| Feature | Minimum Kernel | Notes |
|---------|---------------|-------|
| `bpf_ringbuf` | 5.8 | Preferred over `bpf_perf_event_array` |
| `bpf_timer` | 5.15 | Delayed work in BPF |
| `bpf_loop` | 5.17 | Bounded loops helper |
| `bpf_dynptr` | 5.19 | Dynamic pointers |
| `bpf_kfunc` | 6.0+ | Kernel function calls |

**Kernel version strategy:**

| Test Mode | Architectures | Kernels | Purpose |
|-----------|---------------|---------|---------|
| `fast` | x86_64, riscv64 | latest | Quick iteration |
| `full` | All 7 | latest | Architecture breadth |
| `matrix` | x86_64, riscv64 | latest, stable, LTS | Kernel version breadth |

**Configurable kernel version in constants.nix:**

```nix
# In constants.nix
kernelVersions = {
  # Latest mainline kernel (bleeding edge, newest eBPF features)
  latest = "linuxPackages_latest";

  # Stable kernel (nixpkgs default, well-tested)
  stable = "linuxPackages";

  # LTS kernels for backward compatibility
  lts-6_6 = "linuxPackages_6_6";
  lts-5_15 = "linuxPackages_5_15";
};

# Which kernels to test in matrix mode
testModeKernels = {
  fast = [ "latest" ];
  full = [ "latest" ];
  matrix = [ "latest" "stable" "lts-6_6" ];
};
```

**Usage:**

```bash
# Fast mode with latest kernel (default)
nix run .#xdp2-test-fast

# Fast mode with specific kernel
nix run .#xdp2-test-fast -- --kernel stable
nix run .#xdp2-test-fast -- --kernel lts-6_6

# Matrix mode: test fast architectures on multiple kernels
nix run .#xdp2-test-matrix
# Tests: x86_64 + riscv64 on latest, stable, and LTS-6.6
```

**Why this matters:** Nix's reproducibility is a superpower here. The same MicroVM definition can be built with any kernel version, making it trivial to:
- Validate that XDP2 works on enterprise LTS kernels (5.15, 6.6)
- Test new eBPF features on latest mainline
- Bisect regressions across kernel versions

### Verifier Log Export

When a BPF program fails to load, the kernel verifier provides detailed error messages. These logs are essential for debugging but are lost if not captured.

**Automatic verifier log capture:**

```nix
# In test runner - capture verifier output on failure
verifierLogExport = ''
  # Attempt to load BPF program, capture verifier output
  VERIFIER_LOG=$(mktemp /tmp/verifier-XXXXXX.log)

  if ! bpftool prog load "$BPF_OBJ" /sys/fs/bpf/test 2>"$VERIFIER_LOG"; then
    echo "BPF load failed. Verifier log:"
    cat "$VERIFIER_LOG"

    # Export to host filesystem via shared directory
    if [ -d /mnt/host-logs ]; then
      cp "$VERIFIER_LOG" "/mnt/host-logs/verifier-${ARCH}-$(date +%s).log"
      echo "Verifier log exported to host"
    fi

    exit 1
  fi
'';
```

**Host-side log collection:**

```bash
# After test failure, logs are available at:
ls ./test-logs/verifier-*.log

# View the most recent failure
cat ./test-logs/verifier-s390x-*.log
```

**bpftool version matching:** The `bpftool` in the VM must match the guest kernel version to ensure accurate feature probing and program inspection. The packages module uses `linuxPackages_latest.bpftool` which automatically matches when using `linuxPackages_latest` for the kernel.

```nix
# In packages.nix - ensure bpftool matches kernel
ebpf = with pkgs; [
  # Use bpftool from the same kernel package set
  config.boot.kernelPackages.bpftool  # Matches guest kernel
  # NOT: pkgs.bpftool  # This could mismatch
];
```

---

## Performance Optimization

### Compilation Strategy

**Key Insight:** Compile on the host, load in the VM.

The host machine typically has many cores and substantial RAM. QEMU emulation is slow. Therefore:

1. **Cross-compile eBPF bytecode on the host** - Uses all available host cores
2. **Cross-compile userspace binaries on the host** - Nix handles cross-compilation automatically
3. **Load pre-compiled artifacts into VM** - Only kernel eBPF verification runs inside VM
4. **Kernel eBPF JIT runs in VM** - This must run inside the VM (architecture-specific)

```
┌─────────────────────────────────────────────────────────────────────────┐
│                            HOST (x86_64)                                │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │  nix build .#xdp2-cross-aarch64                                  │  │
│  │  - Compiles eBPF bytecode (.o files)     [fast, parallel]        │  │
│  │  - Cross-compiles userspace loader       [fast, parallel]        │  │
│  │  - Builds VM image with pre-built binaries                       │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                                  │                                      │
│                                  ▼                                      │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │  VM (aarch64 via QEMU)                                           │  │
│  │  - Kernel loads eBPF bytecode            [must run in VM]        │  │
│  │  - BPF verifier checks program           [must run in VM]        │  │
│  │  - JIT compiles to native aarch64        [must run in VM]        │  │
│  │  - Attaches to XDP hook                  [must run in VM]        │  │
│  └──────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
```

### VM Resource Tuning

If tests are slow, increase VM resources. Emulated architectures benefit significantly from more CPU and RAM:

```nix
# In constants.nix - adjust for your hardware
xdp2-test-aarch64 = {
  # Default (conservative)
  mem = 1024;   # 1GB RAM
  vcpu = 2;     # 2 vCPUs

  # For faster tests on beefy machines
  # mem = 4096;   # 4GB RAM
  # vcpu = 8;     # 8 vCPUs
};
```

**Recommendations by host RAM:**

| Host RAM | Recommended VM Memory | Notes |
|----------|----------------------|-------|
| 16 GB | 1024 MB per VM | Conservative, may be slow |
| 32 GB | 2048 MB per VM | Good balance |
| 64+ GB | 4096 MB per VM | Fast emulation |

### Parallel Execution

Run multiple VMs simultaneously when testing:

```bash
# Sequential (slower but uses less resources)
nix run .#xdp2-test-all

# Parallel (faster, needs more RAM)
nix run .#xdp2-test-all -- --parallel

# Parallel with specific architectures
nix run .#xdp2-test-all -- --parallel x86_64 aarch64 riscv64
```

For parallel execution, ensure sufficient RAM (approximately 2GB per concurrent VM).

### CI Resource Throttling

QEMU emulation can starve the host CPU, potentially freezing CI runners. Use cgroups or nice wrappers to prevent this:

```nix
# In mkTestRunner - wrap QEMU execution with resource limits
mkThrottledRunner = { name, ... }:
  pkgs.writeShellApplication {
    inherit name;
    runtimeInputs = with pkgs; [ coreutils systemd ];
    text = ''
      # Run tests in a cgroup with CPU limits
      # Prevents emulation from starving the CI runner

      if command -v systemd-run &>/dev/null; then
        # Use systemd for cgroup management
        exec systemd-run --user --scope \
          -p CPUQuota=80% \
          -p MemoryMax=8G \
          "$@"
      else
        # Fallback: use nice for basic throttling
        exec nice -n 10 "$@"
      fi
    '';
  };
```

**CI workflow with resource limits:**

```yaml
# .github/workflows/test.yml
jobs:
  full-check:
    runs-on: ubuntu-latest
    steps:
      - name: Run tests with resource limits
        run: |
          # Limit to 80% CPU to keep runner responsive
          systemd-run --user --scope -p CPUQuota=80% \
            nix run .#xdp2-test-all
```

**Why this matters:** Without throttling, 7 concurrent QEMU VMs (especially for slow architectures like RISC-V or MIPS) can consume 100% CPU and cause:
- CI runner timeouts
- Unresponsive runner UI
- Failed SSH health checks
- Zombie processes if the runner is force-killed

### Caching

Use Nix binary caches to avoid rebuilding:

```nix
# In flake.nix
nixConfig = {
  extra-substituters = [
    "https://microvm.cachix.org"
    "https://your-org.cachix.org"  # Your CI cache
  ];
  extra-trusted-public-keys = [
    "microvm.cachix.org-1:oXnBc6hRE3eX5rSYdRyMYXnfzcCxC7yKPTbZXALsqys="
  ];
};
```

Push build artifacts to cache in CI:

```bash
nix build .#xdp2-test-vm-x86_64 | cachix push your-org
```

### Performance Summary

| Optimization | Impact | Implementation |
|-------------|--------|----------------|
| Host cross-compilation | 10-100x faster build | Default behavior |
| KVM for x86_64 | ~1x native speed | Automatic when host matches |
| Increased VM RAM | 2-5x faster boot | Adjust constants.nix |
| Parallel VM execution | Linear speedup | `--parallel` flag |
| Binary caches | Skip rebuilds entirely | Configure cachix |

---

## Architecture Overview

```
┌───────────────────────────────────────────────────────────────────────────────────┐
│                         XDP2 MicroVM Test Infrastructure                          │
├───────────────────────────────────────────────────────────────────────────────────┤
│                                                                                   │
│  ┌─────────────────────────────────────────────────────────────────────────────┐ │
│  │                              flake.nix                                       │ │
│  │                                                                              │ │
│  │  Test Modes:                                                                 │ │
│  │    xdp2-test-fast    (x86_64 + riscv64)   ← Development                     │ │
│  │    xdp2-test-all     (all 7 architectures) ← CI/Release                     │ │
│  │                                                                              │ │
│  │  Per-Architecture VMs:                                                       │ │
│  │    xdp2-test-vm-x86_64   (KVM)     xdp2-test-vm-mips64   (QEMU)             │ │
│  │    xdp2-test-vm-aarch64  (QEMU)    xdp2-test-vm-ppc64    (QEMU)             │ │
│  │    xdp2-test-vm-riscv64  (QEMU)    xdp2-test-vm-s390x    (QEMU)             │ │
│  │    xdp2-test-vm-riscv32  (QEMU)                                              │ │
│  └─────────────────────────────────────────────────────────────────────────────┘ │
│                                       │                                          │
│                                       ▼                                          │
│  ┌─────────────────────────────────────────────────────────────────────────────┐ │
│  │                         nix/microvms/                                        │ │
│  │  constants.nix   ─── Ports, timeouts, resources (single source of truth)   │ │
│  │  arch.nix        ─── Architecture generator (DRY VM creation)               │ │
│  │  base.nix        ─── Shared VM configuration                                │ │
│  │  packages.nix    ─── Tool packages (profiling, debugging, network)          │ │
│  │  default.nix     ─── Entry point, exports all VMs                           │ │
│  └─────────────────────────────────────────────────────────────────────────────┘ │
│         │            │            │            │            │            │       │
│         ▼            ▼            ▼            ▼            ▼            ▼       │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐  │
│  │ x86_64   │ │ aarch64  │ │ riscv64  │ │ mips64   │ │ ppc64    │ │ s390x    │  │
│  │ (KVM)    │ │ (QEMU)   │ │ (QEMU)   │ │ (QEMU)   │ │ (QEMU)   │ │ (QEMU)   │  │
│  │          │ │          │ │          │ │          │ │          │ │          │  │
│  │ Desktop  │ │ ARM      │ │ Embedded │ │ Routers  │ │ Network  │ │Enterprise│  │
│  │ Servers  │ │ Servers  │ │ IoT      │ │ Switches │ │ Appliance│ │Mainframe │  │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────────┘  │
│         │            │            │            │            │            │       │
│         └────────────┴────────────┴─────┬──────┴────────────┴────────────┘       │
│                                         ▼                                        │
│  ┌─────────────────────────────────────────────────────────────────────────────┐ │
│  │                          Dual Console Access                                 │ │
│  │  ttyS0 (serial)  - TCP socket - Boot messages, kernel panics                │ │
│  │  hvc0  (virtio)  - TCP socket - Fast interactive shell                      │ │
│  └─────────────────────────────────────────────────────────────────────────────┘ │
│                                                                                   │
└───────────────────────────────────────────────────────────────────────────────────┘
```

---

## Supported Architectures

XDP2 MicroVM test infrastructure supports seven architectures covering the major platforms where eBPF/XDP packet processing is relevant.

| Architecture | QEMU Machine | Execution | Use Case | Serial/Virtio Ports | Test Mode |
|-------------|--------------|-----------|----------|---------------------|-----------|
| **x86_64** | pc | KVM (native) | Desktop, servers, cloud | 5000/5001 | fast, full |
| **aarch64** | virt | QEMU | ARM servers, Graviton, RPi | 5010/5011 | full |
| **riscv64** | virt | QEMU | Embedded, IoT, future networking | 5020/5021 | fast, full |
| **riscv32** | virt | QEMU | 32-bit validation, embedded | 5025/5026 | full |
| **mips64el** | malta | QEMU | Routers (Cisco, Ubiquiti, home) | 5030/5031 | full |
| **ppc64le** | pseries | QEMU | Network appliances, high-end switches | 5040/5041 | full |
| **s390x** | s390-ccw-virtio | QEMU | Enterprise mainframes | 5050/5051 | full |

### Architecture Notes

- **x86_64** - Primary development platform with KVM acceleration
- **riscv64** - Included in fast mode as a cross-architecture sanity check
- **riscv32** - Validates 32-bit pointer handling and struct packing
- **mips64** - Common in networking equipment (home routers, Cisco, Ubiquiti)
- **ppc64** - Enterprise networking and telecom infrastructure
- **s390x** - IBM mainframes (enterprise data centers)

### Platform Limitations

> **Important:** XDP and eBPF are Linux-only technologies.
> - FreeBSD has classic BPF (cBPF) but **not** eBPF
> - Solaris has DTrace but **not** eBPF
> - XDP hooks are specific to the Linux network stack
>
> This test infrastructure only supports Linux guests.

---

## Advanced Nix Patterns

This section describes idiomatic Nix patterns that make the infrastructure more elegant, DRY, and maintainable. The goal is to let Nix's evaluation engine handle dependency resolution and architecture mapping before the first VM starts.

### Functional Matrix Generation

Instead of imperative loops in shell scripts, use `lib.cartesianProductOfSets` to generate every combination of (Architecture × Kernel × TestMode) as distinct Nix derivations.

**Why this is elegant:** You can run `nix build .#tests.x86_64.lts-6_6` directly. Nix handles the matrix logic, not bash.

```nix
# nix/microvms/matrix.nix
{ lib, mkTestVM }:

let
  # Define the matrix dimensions
  matrix = lib.cartesianProductOfSets {
    arch = [ "x86_64" "aarch64" "riscv64" "s390x" ];
    kernel = [ "latest" "stable" "lts-6_6" ];
  };

in
  # Generate an attribute set of all permutations
  # Result: { "x86_64-latest" = <vm>; "x86_64-stable" = <vm>; ... }
  lib.listToAttrs (map (comb: {
    name = "${comb.arch}-${comb.kernel}";
    value = mkTestVM {
      inherit (comb) arch kernel;
    };
  }) matrix)
```

**Usage:**

```bash
# Build a specific combination
nix build .#tests.x86_64-lts-6_6

# Build all combinations (Nix evaluates the matrix)
nix build .#tests

# List all available test targets
nix flake show | grep tests
```

### Store Injection via virtio-9p

Instead of copying binaries into the VM image, use `microvm.shares` to mount the host's `/nix/store` directly into the guest via virtio-9p.

**Why this is elegant:** VM boot is nearly instantaneous because XDP2 binaries aren't inside the disk image—they're mounted from the host's memory-cached Nix store.

```nix
# In the VM module
microvm.shares = [{
  source = "/nix/store";
  mountPoint = "/nix/store";
  tag = "nix-store";
  proto = "9p";
  # Use msize=104857600 for better 9p performance
}];

# The guest can now access all host store paths
# No need to copy binaries into the VM image
```

**Benefits:**
- **Instant boot:** No time spent copying binaries
- **Smaller images:** VM images contain only kernel and initrd
- **Live updates:** Change code on host, immediately available in VM

### Systemd Test Driver

Instead of shell scripts polling console ports, use a Systemd oneshot service inside the guest that reports success/failure via exit code.

**Why this is elegant:** The test becomes a unit that either succeeds or fails. The host waits for the VM process to exit with code 0—no polling, no timeouts, no race conditions.

```nix
# nix/modules/ebpf-test.nix
{ config, pkgs, lib, ... }:

{
  options.xdp2.test = {
    enable = lib.mkEnableOption "XDP2 self-test on boot";

    exitOnComplete = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Shut down VM after test completion";
    };
  };

  config = lib.mkIf config.xdp2.test.enable {
    systemd.services.xdp2-self-test = {
      description = "XDP2 eBPF Self-Test";
      after = [ "network.target" ];
      wantedBy = [ "multi-user.target" ];

      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        # Exit code propagates to VM exit code
        SuccessExitStatus = "0";
      };

      script = ''
        set -euo pipefail

        echo "═══════════════════════════════════════════════════════"
        echo "  XDP2 Self-Test: $(uname -m)"
        echo "═══════════════════════════════════════════════════════"

        # Check BTF
        if [ -f /sys/kernel/btf/vmlinux ]; then
          echo "✓ BTF enabled"
        else
          echo "✗ BTF not available"
          exit 1
        fi

        # Check bpftool
        ${pkgs.bpftool}/bin/bpftool feature probe | head -5
        echo "✓ bpftool works"

        # Run XDP2 test suite
        ${pkgs.xdp2}/bin/xdp2-test --all
        echo "✓ XDP2 tests passed"

        echo "═══════════════════════════════════════════════════════"
        echo "  All tests passed!"
        echo "═══════════════════════════════════════════════════════"

        ${lib.optionalString config.xdp2.test.exitOnComplete ''
          # Shut down VM - exit code 0 indicates success
          ${pkgs.systemd}/bin/poweroff
        ''}
      '';
    };
  };
}
```

**Host-side usage:**

```bash
# Run VM - it boots, runs tests, and exits
# Exit code 0 = success, non-zero = failure
./result/bin/microvm-run
echo "Exit code: $?"
```

### Cross-Compilation Overlays

Use Nix overlays to ensure consistent compiler flags across all architectures.

```nix
# nix/overlays/xdp2-cross.nix
final: prev: {
  xdp2 = prev.xdp2.overrideAttrs (old: {
    # Ensure consistent optimization across architectures
    NIX_CFLAGS_COMPILE = (old.NIX_CFLAGS_COMPILE or "") + " -O2";

    # Architecture-specific flags handled by Nix cross-compilation
    # No manual -march needed - crossSystem handles this
  });

  # Ensure bpftool matches kernel
  bpftool = final.linuxPackages.bpftool;
}
```

### NixOS Module Pattern

Structure reusable configuration as NixOS modules. This enables clean option-based configuration.

```nix
# nix/modules/ebpf-base.nix
{ config, pkgs, lib, ... }:

{
  options.xdp2 = {
    debug = {
      exportVerifierLogs = lib.mkEnableOption "Export BPF verifier logs to shared directory";

      logDirectory = lib.mkOption {
        type = lib.types.path;
        default = "/var/log/xdp2";
        description = "Directory for verifier logs";
      };
    };
  };

  config = {
    # Always enable BTF
    boot.kernelPatches = [{
      name = "btf-support";
      patch = null;
      extraConfig = ''
        DEBUG_INFO_BTF y
      '';
    }];

    # Always enable BPF JIT
    boot.kernel.sysctl = {
      "net.core.bpf_jit_enable" = 1;
      "kernel.unprivileged_bpf_disabled" = 0;
    };

    # Conditional verifier log export
    environment.systemPackages = lib.mkIf config.xdp2.debug.exportVerifierLogs [
      (pkgs.writeShellScriptBin "xdp2-load-with-log" ''
        OBJ="$1"
        LOG_DIR="${config.xdp2.debug.logDirectory}"
        mkdir -p "$LOG_DIR"
        LOG_FILE="$LOG_DIR/verifier-$(date +%s).log"

        if ! ${pkgs.bpftool}/bin/bpftool prog load "$OBJ" /sys/fs/bpf/test 2>"$LOG_FILE"; then
          echo "Load failed. Verifier log: $LOG_FILE"
          cat "$LOG_FILE"
          exit 1
        fi
        rm -f "$LOG_FILE"  # Clean up on success
      '')
    ];
  };
}
```

**Usage in VM definition:**

```nix
# Enable debug features
xdp2.debug.exportVerifierLogs = true;
xdp2.test.enable = true;
```

---

## Implementation

### Directory Structure

The directory structure follows Nix best practices with clear separation between library functions, modules, and entry points:

```
nix/
├── lib/
│   └── mk-vm.nix                # Function: (arch, kernel) -> VM derivation
├── modules/
│   ├── ebpf-base.nix            # Common BTF, sysctls, eBPF requirements
│   ├── ebpf-test.nix            # Systemd test driver
│   ├── logging.nix              # Verifier log export
│   └── network-test.nix         # Future: TAP/bridge for packet injection
├── microvms/
│   ├── default.nix              # Entry point: applies lib/mk-vm to matrix
│   ├── constants.nix            # Data: ports, timeouts, architectures
│   ├── matrix.nix               # Generates arch × kernel combinations
│   └── packages.nix             # Tool packages for VMs
├── overlays/
│   └── xdp2-cross.nix           # Cross-compilation overlays
├── scripts/
│   └── vm-management.nix        # Helper scripts
└── tests/
    ├── default.nix              # Test exports
    ├── run-fast.nix             # Fast mode runner
    ├── run-all.nix              # Full mode runner
    └── run-matrix.nix           # Kernel matrix runner
```

**Layer diagram:**

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  Top Layer: constants.nix (Data)                                            │
│  - Architectures, ports, timeouts, kernel versions                          │
│  - Pure data, no functions                                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│  Middle Layer: lib/mk-vm.nix + matrix.nix (Logic/Transform)                 │
│  - mkTestVM: (arch, kernel) -> VM derivation                                │
│  - cartesianProductOfSets generates all combinations                        │
├─────────────────────────────────────────────────────────────────────────────┤
│  Bottom Layer: Artifacts (Multiple .qcow2 or 9p mounts)                     │
│  - tests.x86_64-latest, tests.s390x-lts-6_6, etc.                           │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Constants Module (`nix/microvms/constants.nix`)

Single source of truth for all configuration. This makes maintenance easy and prevents inconsistencies.

```nix
# nix/microvms/constants.nix
#
# Centralized configuration for all XDP2 MicroVMs.
# Edit this file to change ports, timeouts, or resources.
#
{
  # ═══════════════════════════════════════════════════════════════════════════
  # Port Allocation Scheme
  # ═══════════════════════════════════════════════════════════════════════════
  #
  # Range 5000-5099 reserved for XDP2 test VMs
  #
  #   Architecture   Serial Port   Virtio Port   Range
  #   ───────────────────────────────────────────────────
  #   x86_64         5000          5001          5000-5009
  #   aarch64        5010          5011          5010-5019
  #   riscv64        5020          5021          5020-5024
  #   riscv32        5025          5026          5025-5029
  #   mips64         5030          5031          5030-5039
  #   ppc64          5040          5041          5040-5049
  #   s390x          5050          5051          5050-5059
  #

  # ═══════════════════════════════════════════════════════════════════════════
  # Test Mode Definitions
  # ═══════════════════════════════════════════════════════════════════════════

  testModes = {
    # Fast mode: Development iteration (2 architectures, latest kernel)
    fast = [ "x86_64" "riscv64" ];

    # Full mode: CI/release validation (all architectures, latest kernel)
    full = [ "x86_64" "aarch64" "riscv64" "riscv32" "mips64" "ppc64" "s390x" ];

    # Matrix mode: Kernel version breadth (fast architectures, multiple kernels)
    matrix = [ "x86_64" "riscv64" ];

    # Endianness mode: Big Endian validation only
    endian = [ "s390x" ];
  };

  # ═══════════════════════════════════════════════════════════════════════════
  # Kernel Version Matrix
  # ═══════════════════════════════════════════════════════════════════════════
  #
  # Nix provides reproducibility: we can easily build MicroVMs with different
  # kernel versions to validate eBPF compatibility across the kernel ecosystem.
  #
  # Kernel packages in nixpkgs:
  #   linuxPackages_latest  - Latest mainline kernel (bleeding edge)
  #   linuxPackages         - Current stable kernel (nixpkgs default)
  #   linuxPackages_6_6     - Specific LTS version
  #   linuxPackages_5_15    - Older LTS for maximum compatibility
  #

  kernelVersions = {
    # Latest mainline kernel (bleeding edge, newest eBPF features)
    latest = "linuxPackages_latest";

    # Stable kernel (nixpkgs default, well-tested)
    stable = "linuxPackages";

    # LTS kernels for backward compatibility testing
    lts-6_6 = "linuxPackages_6_6";
    lts-5_15 = "linuxPackages_5_15";
  };

  # Default kernel for each test mode
  testModeKernels = {
    # Fast mode: use latest for quick iteration
    fast = [ "latest" ];

    # Full mode: test latest only (architecture breadth over kernel depth)
    full = [ "latest" ];

    # Matrix mode: test kernel breadth on fast architectures
    matrix = [ "latest" "stable" "lts-6_6" ];
  };

  # Default kernel version (can be overridden via CLI)
  defaultKernel = "latest";

  # ═══════════════════════════════════════════════════════════════════════════
  # Default Resource Settings
  # ═══════════════════════════════════════════════════════════════════════════

  defaults = {
    # Standard VM resources
    mem = 1024;           # 1GB RAM
    vcpu = 2;             # 2 vCPUs

    # Small VM resources (32-bit, constrained)
    memSmall = 512;       # 512MB RAM
    vcpuSmall = 1;        # 1 vCPU

    # Timeouts for KVM (native speed)
    kvm = {
      pollInterval = 1;
      portTimeout = 60;
      bootTimeout = 120;
      commandTimeout = 5;
    };

    # Timeouts for QEMU emulation (slower)
    qemu = {
      pollInterval = 2;
      portTimeout = 120;
      bootTimeout = 300;
      commandTimeout = 10;
    };

    # Timeouts for slow emulation (RISC-V, MIPS)
    qemuSlow = {
      pollInterval = 3;
      portTimeout = 180;
      bootTimeout = 600;
      commandTimeout = 15;
    };
  };

  # ═══════════════════════════════════════════════════════════════════════════
  # Architecture Definitions
  # ═══════════════════════════════════════════════════════════════════════════
  #
  # Each architecture defines:
  #   - nixSystem: Nix system string for cross-compilation
  #   - qemuSystem: QEMU system name (if different)
  #   - machine: QEMU -machine argument
  #   - cpu: QEMU -cpu argument
  #   - serialPort: TCP port for ttyS0
  #   - virtioPort: TCP port for hvc0
  #   - useKvm: true if can use KVM on x86_64 host
  #   - timeoutProfile: which timeout defaults to use
  #   - consoleOverride: architecture-specific console kernel params (optional)
  #

  architectures = {
    x86_64 = {
      nixSystem = "x86_64-linux";
      machine = "pc";
      cpu = "host";
      serialPort = 5000;
      virtioPort = 5001;
      useKvm = true;
      timeoutProfile = "kvm";
      description = "Desktop, servers, cloud";
    };

    aarch64 = {
      nixSystem = "aarch64-linux";
      machine = "virt";
      cpu = "cortex-a72";
      serialPort = 5010;
      virtioPort = 5011;
      useKvm = false;
      timeoutProfile = "qemu";
      description = "ARM servers, Graviton, Raspberry Pi";
    };

    riscv64 = {
      nixSystem = "riscv64-linux";
      machine = "virt";
      cpu = "rv64";
      serialPort = 5020;
      virtioPort = 5021;
      useKvm = false;
      timeoutProfile = "qemuSlow";
      description = "Embedded, IoT, future networking";
    };

    riscv32 = {
      nixSystem = "riscv32-linux";
      machine = "virt";
      cpu = "rv32";
      serialPort = 5025;
      virtioPort = 5026;
      useKvm = false;
      timeoutProfile = "qemuSlow";
      mem = 512;  # Override: less memory for 32-bit
      vcpu = 1;   # Override: single vCPU
      description = "32-bit validation, embedded";
    };

    mips64 = {
      nixSystem = "mips64el-linux";
      machine = "malta";
      cpu = "MIPS64R2-generic";
      serialPort = 5030;
      virtioPort = 5031;
      useKvm = false;
      timeoutProfile = "qemuSlow";
      description = "Routers (Cisco, Ubiquiti, home routers)";
    };

    ppc64 = {
      nixSystem = "powerpc64le-linux";
      machine = "pseries";
      cpu = "POWER9";
      serialPort = 5040;
      virtioPort = 5041;
      useKvm = false;
      timeoutProfile = "qemu";
      description = "Network appliances, high-end Cisco";
    };

    s390x = {
      nixSystem = "s390x-linux";
      machine = "s390-ccw-virtio";
      cpu = "max";
      serialPort = 5050;
      virtioPort = 5051;
      useKvm = false;
      timeoutProfile = "qemu";
      # s390x has different console device
      consoleOverride = [ "console=ttysclp0" "console=hvc0" ];
      description = "Enterprise mainframes (IBM z/Architecture)";
    };
  };

  # ═══════════════════════════════════════════════════════════════════════════
  # Helper: Get full config for an architecture
  # ═══════════════════════════════════════════════════════════════════════════

  getArchConfig = arch:
    let
      base = architectures.${arch};
      timeouts = defaults.${base.timeoutProfile};
    in base // {
      mem = base.mem or defaults.mem;
      vcpu = base.vcpu or defaults.vcpu;
      inherit (timeouts) pollInterval portTimeout bootTimeout commandTimeout;
      hostName = "xdp2-test-${arch}";
    };
}
```

### Matrix Generator (`nix/microvms/matrix.nix`)

Uses `lib.cartesianProductOfSets` to generate all (Architecture × Kernel) combinations as distinct derivations.

```nix
# nix/microvms/matrix.nix
#
# Generates the full test matrix using functional Nix patterns.
# No imperative loops - Nix evaluation handles the combinatorics.
#
{ lib, callPackage }:

let
  constants = import ./constants.nix;
  mkVM = callPackage ../lib/mk-vm.nix {};

  # Generate matrix for a given test mode
  mkMatrix = { archs, kernels }:
    let
      matrix = lib.cartesianProductOfSets {
        arch = archs;
        kernel = kernels;
      };
    in
      lib.listToAttrs (map (comb: {
        name = "${comb.arch}-${comb.kernel}";
        value = mkVM {
          inherit (comb) arch kernel;
        };
      }) matrix);

in {
  # ─── Pre-defined Test Matrices ──────────────────────────────────────────

  # Fast: 2 archs × 1 kernel = 2 VMs
  fast = mkMatrix {
    archs = constants.testModes.fast;
    kernels = constants.testModeKernels.fast;
  };

  # Full: 7 archs × 1 kernel = 7 VMs
  full = mkMatrix {
    archs = constants.testModes.full;
    kernels = constants.testModeKernels.full;
  };

  # Matrix: 2 archs × 3 kernels = 6 VMs
  matrix = mkMatrix {
    archs = constants.testModes.matrix;
    kernels = constants.testModeKernels.matrix;
  };

  # Endian: 1 arch × 1 kernel = 1 VM (Big Endian validation)
  endian = mkMatrix {
    archs = constants.testModes.endian;
    kernels = [ "latest" ];
  };

  # ─── Custom Matrix Generation ───────────────────────────────────────────
  inherit mkMatrix;
}
```

**Usage examples:**

```bash
# Build a specific combination directly
nix build .#tests.fast.x86_64-latest
nix build .#tests.matrix.riscv64-lts-6_6

# Build entire test mode
nix build .#tests.fast    # All 2 VMs
nix build .#tests.matrix  # All 6 VMs

# List available combinations
nix eval .#tests.matrix --apply 'builtins.attrNames'
# => ["riscv64-latest" "riscv64-lts-6_6" "riscv64-stable" "x86_64-latest" ...]
```

### VM Builder Function (`nix/lib/mk-vm.nix`)

The core VM builder, used via `callPackage` for clean dependency injection.

```nix
# nix/lib/mk-vm.nix
#
# VM builder function: (arch, kernel) -> MicroVM derivation
#
# Uses callPackage pattern for dependency injection.
#
{ lib, pkgs, microvm, nixpkgs }:

{ arch, kernel ? "latest" }:

let
  constants = import ../microvms/constants.nix;
  cfg = constants.getArchConfig arch;
  archDef = constants.architectures.${arch};
  kernelPkg = pkgs.${constants.kernelVersions.${kernel}};

in (nixpkgs.lib.nixosSystem {
  system = cfg.nixSystem;

  modules = [
    microvm.nixosModules.microvm

    # Import our reusable modules
    ../modules/ebpf-base.nix
    ../modules/ebpf-test.nix

    ({ config, pkgs, ... }: {
      system.stateVersion = "24.05";
      networking.hostName = cfg.hostName;

      # ─── Enable Our Modules ──────────────────────────────────────────
      xdp2.test.enable = true;
      xdp2.debug.exportVerifierLogs = true;

      # ─── MicroVM Configuration ───────────────────────────────────────
      microvm = {
        hypervisor = "qemu";
        mem = cfg.mem;
        vcpu = cfg.vcpu;
        interfaces = [];

        # Store injection: mount host /nix/store directly
        shares = [{
          source = "/nix/store";
          mountPoint = "/nix/store";
          tag = "nix-store";
          proto = "9p";
        }];

        qemu.serialConsole = false;
        qemu.extraArgs = [
          "-name" "${cfg.hostName},process=${cfg.hostName}"
          "-machine" archDef.machine
          "-cpu" archDef.cpu
        ] ++ (lib.optionals archDef.useKvm [ "-enable-kvm" ]);
      };

      # ─── Kernel Configuration ────────────────────────────────────────
      # Use the specified kernel version
      boot.kernelPackages = kernelPkg;

      boot.kernelParams = archDef.consoleOverride or [
        "console=ttyS0,115200"
        "console=hvc0"
      ];

      # ─── Auto-login for Testing ──────────────────────────────────────
      services.getty.autologinUser = "root";
      users.users.root.password = "";
    })
  ];
}).config.microvm.declaredRunner
```

### eBPF Base Module (`nix/modules/ebpf-base.nix`)

Reusable NixOS module for eBPF requirements.

```nix
# nix/modules/ebpf-base.nix
#
# Base eBPF configuration module.
# Provides common options for BTF, sysctls, and debugging.
#
{ config, pkgs, lib, ... }:

{
  options.xdp2 = {
    debug = {
      exportVerifierLogs = lib.mkEnableOption "Export BPF verifier logs";

      logDirectory = lib.mkOption {
        type = lib.types.path;
        default = "/var/log/xdp2";
        description = "Directory for verifier logs";
      };
    };
  };

  config = {
    # ─── BTF Support ───────────────────────────────────────────────────
    boot.kernelPatches = [{
      name = "btf-support";
      patch = null;
      extraConfig = ''
        DEBUG_INFO_BTF y
      '';
    }];

    # ─── eBPF sysctls ──────────────────────────────────────────────────
    boot.kernel.sysctl = {
      "net.core.bpf_jit_enable" = 1;
      "kernel.unprivileged_bpf_disabled" = 0;
    };

    # ─── bpftool matching kernel ───────────────────────────────────────
    environment.systemPackages = [
      config.boot.kernelPackages.bpftool
    ] ++ lib.optionals config.xdp2.debug.exportVerifierLogs [
      (pkgs.writeShellScriptBin "xdp2-load-with-log" ''
        set -euo pipefail
        OBJ="$1"
        LOG_DIR="${config.xdp2.debug.logDirectory}"
        mkdir -p "$LOG_DIR"
        LOG_FILE="$LOG_DIR/verifier-$(date +%s).log"

        if ! ${config.boot.kernelPackages.bpftool}/bin/bpftool prog load "$OBJ" /sys/fs/bpf/test 2>"$LOG_FILE"; then
          echo "BPF load failed. Verifier log saved to: $LOG_FILE"
          cat "$LOG_FILE"
          exit 1
        fi
        rm -f "$LOG_FILE"
      '')
    ];
  };
}
```

### Packages Module (`nix/microvms/packages.nix`)

```nix
# nix/microvms/packages.nix
#
# Tool packages for XDP2 MicroVM test environments.
#
{ pkgs }:

{
  # ─── eBPF Development Tools ─────────────────────────────────────────────
  ebpf = with pkgs; [
    bpftool              # BPF introspection and manipulation
    bpftrace             # High-level tracing language
    bcc                  # BPF Compiler Collection
    libbpf               # CO-RE BPF library
  ];

  # ─── Performance Profiling ──────────────────────────────────────────────
  profiling = with pkgs; [
    linuxPackages_latest.perf   # Linux perf tools
    flamegraph                  # Stack trace visualization
    trace-cmd                   # Ftrace frontend
  ];

  # ─── Debugging Tools ────────────────────────────────────────────────────
  debugging = with pkgs; [
    gdb                  # GNU debugger
    strace               # System call tracer
    binutils             # readelf, objdump, nm
    llvmPackages.bintools  # llvm-objdump for BPF bytecode
    elfutils             # eu-readelf, eu-objdump
  ];

  # ─── Network Testing Tools ──────────────────────────────────────────────
  network = with pkgs; [
    tcpdump              # Packet capture
    tshark               # Wireshark CLI
    iperf2               # Network bandwidth testing
    iproute2             # ip, tc, ss commands
    ethtool              # NIC configuration
  ];

  # ─── XDP Specific Tools ─────────────────────────────────────────────────
  xdp = with pkgs; [
    xdp-tools            # xdp-loader, xdp-filter, xdp-dump
    libxdp               # XDP library
  ];

  # ─── Core Utilities ─────────────────────────────────────────────────────
  core = with pkgs; [
    coreutils
    util-linux
    procps               # ps, top, vmstat
    kmod                 # modprobe, lsmod
    vim
    tmux
  ];

  # ─── Combined: All packages ─────────────────────────────────────────────
  all = ebpf ++ profiling ++ debugging ++ network ++ xdp ++ core;

  # ─── Minimal: Essential packages only ───────────────────────────────────
  minimal = with pkgs; [
    bpftool
    tcpdump
    iproute2
    coreutils
    procps
  ];
}
```

### Flake Integration

Using `callPackage` for clean dependency injection and exposing the test matrix.

```nix
# flake.nix
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    microvm = {
      url = "github:astro/microvm.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  nixConfig = {
    extra-substituters = [ "https://microvm.cachix.org" ];
    extra-trusted-public-keys = [
      "microvm.cachix.org-1:oXnBc6hRE3eX5rSYdRyMYXnfzcCxC7yKPTbZXALsqys="
    ];
  };

  outputs = { self, nixpkgs, flake-utils, microvm }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};

        # Use callPackage for dependency injection
        callPackage = pkgs.lib.callPackageWith (pkgs // {
          inherit microvm nixpkgs;
        });

        # Import matrix generator
        matrix = callPackage ./nix/microvms/matrix.nix {};

        # XDP2 package with overlays
        xdp2 = callPackage ./nix/derivation.nix {};

      in {
        # ─── Test Matrix ────────────────────────────────────────────────────
        # Access: nix build .#tests.fast.x86_64-latest
        #         nix build .#tests.matrix.riscv64-lts-6_6
        tests = {
          inherit (matrix) fast full matrix endian;
        };

        # ─── Convenience Aliases ────────────────────────────────────────────
        packages = {
          inherit xdp2;

          # Test mode runners (for shell scripts / CI)
          xdp2-test-fast = pkgs.writeShellApplication {
            name = "xdp2-test-fast";
            text = ''
              for vm in ${pkgs.lib.concatStringsSep " " (builtins.attrNames matrix.fast)}; do
                echo "Testing: $vm"
                nix build ".#tests.fast.$vm" --no-link
                $(nix build ".#tests.fast.$vm" --print-out-paths)/bin/microvm-run
              done
            '';
          };

          xdp2-test-all = pkgs.writeShellApplication {
            name = "xdp2-test-all";
            text = ''
              for vm in ${pkgs.lib.concatStringsSep " " (builtins.attrNames matrix.full)}; do
                echo "Testing: $vm"
                nix build ".#tests.full.$vm" --no-link
                $(nix build ".#tests.full.$vm" --print-out-paths)/bin/microvm-run
              done
            '';
          };

          xdp2-test-matrix = pkgs.writeShellApplication {
            name = "xdp2-test-matrix";
            text = ''
              for vm in ${pkgs.lib.concatStringsSep " " (builtins.attrNames matrix.matrix)}; do
                echo "Testing: $vm"
                nix build ".#tests.matrix.$vm" --no-link
                $(nix build ".#tests.matrix.$vm" --print-out-paths)/bin/microvm-run
              done
            '';
          };
        };
      });
}
```

**Key improvements:**
- `callPackage` automatically passes `pkgs`, `lib`, etc. - no manual threading
- Test matrix is a first-class flake output: `nix build .#tests.matrix.x86_64-stable`
- Each (arch × kernel) combination is a distinct derivation
- Nix evaluation handles combinatorics, not bash loops

---

## Console Architecture

### Why Two Consoles?

| Aspect | ttyS0 (Serial) | hvc0 (Virtio-Console) |
|--------|----------------|----------------------|
| **Type** | Emulated 16550 UART | Paravirtualized |
| **Speed** | Slow (per-byte traps) | Fast (batched I/O) |
| **Availability** | Immediate | After virtio drivers load |
| **Kernel panics** | Captured | May be lost |
| **Use case** | Boot debug, crashes | Interactive sessions |

### Kernel Command Line

```
console=ttyS0,115200 console=hvc0
```

- First `console=` directs early boot output to serial
- Last `console=` becomes `/dev/console` (primary for userspace)
- Both receive kernel messages initially

---

## BTF (BPF Type Format) Requirements

### Why BTF is Required

Modern eBPF programs using CO-RE (Compile Once, Run Everywhere) require BTF kernel support. BTF provides type information that allows eBPF programs to adapt to different kernel versions without recompilation.

**Verification command:**
```bash
ls /sys/kernel/btf/vmlinux
```

### Kernel Configuration

```
CONFIG_DEBUG_INFO_BTF=y
```

### Build Dependencies

BTF generation requires `pahole` (from `dwarves` package) during kernel build. Ensure it's available in `nativeBuildInputs`:

```nix
# In the kernel build derivation
nativeBuildInputs = [
  pkgs.pahole  # Required for BTF generation
  # ... other build inputs
];
```

**Note:** If `pahole` is missing, the kernel will build but BTF will silently fail to generate. The VM will boot, but `/sys/kernel/btf/vmlinux` won't exist, and CO-RE eBPF programs will fail.

### Current Implementation

Until the microvm.nix BTF feature is merged, we use kernel patches:

```nix
boot.kernelPatches = [{
  name = "btf-support";
  patch = null;
  extraConfig = ''
    DEBUG_INFO_BTF y
  '';
}];

# Ensure pahole is available for BTF generation
boot.kernelPackages = pkgs.linuxPackages_latest.extend (self: super: {
  kernel = super.kernel.override {
    nativeBuildInputs = (super.kernel.nativeBuildInputs or []) ++ [ pkgs.pahole ];
  };
});
```

### Future: Native microvm.nix BTF

When merged:

```nix
microvm = {
  btf.enable = true;  # Native BTF support
};
```

---

## VM Management Scripts

Generated for all architectures from constants:

| Script | Description |
|--------|-------------|
| `xdp2-vm-console-<arch>` | Connect to virtio console |
| `xdp2-vm-serial-<arch>` | Connect to serial console |
| `xdp2-vm-status-<arch>` | Check console port status |
| `xdp2-vm-check` | Show status of all VMs |
| `xdp2-vm-stop-all` | Stop all running VMs |

---

## Automated Testing

### Fast Mode

```bash
nix run .#xdp2-test-fast
```

Tests x86_64 and riscv64 only.

### Full Mode

```bash
nix run .#xdp2-test-all
```

Tests all 7 architectures.

### Test Sequence

For each architecture:
1. Build VM
2. Start VM
3. Wait for console
4. Verify BTF
5. Check bpftool
6. Verify architecture
7. Shutdown

---

## Usage Examples

### Quick Development Test

```bash
# Fast mode - x86_64 + riscv64 only
nix run .#xdp2-test-fast
```

### Full CI Test

```bash
# All 7 architectures
nix run .#xdp2-test-all
```

### Single Architecture

```bash
nix build .#xdp2-test-vm-mips64
./result/bin/microvm-run &
./result/bin/connect-console
# Inside VM:
uname -m        # Shows: mips64
bpftool prog list
```

### Check VM Status

```bash
nix run .#xdp2-vm-check
```

---

## Troubleshooting

### VM won't start

1. Check port availability:
   ```bash
   nc -z localhost 5000 && echo "Port 5000 in use"
   ```

2. Stop stale VMs:
   ```bash
   nix run .#xdp2-vm-stop-all
   ```

### Slow emulation

1. Increase VM resources in `constants.nix`
2. Use `--parallel` for multiple VMs
3. Ensure binary cache is configured

### BTF not available

Check kernel config:
```bash
zcat /proc/config.gz | grep BTF
```

---

## Future Enhancements

### Phase 1.5: Native BTF

Replace kernel patches with `microvm.btf.enable = true` when available.

### Phase 2: Network Topology Simulation

Add TAP interfaces for XDP program testing with real packet flows and packet injection.

**Goal:** Enable host-side test scripts to inject packets into the VM's XDP hook and verify the output.

**Approach 1: QEMU User Networking with guestfwd**

```nix
# In microvm QEMU args
qemu.extraArgs = [
  "-netdev" "user,id=net0,guestfwd=tcp:10.0.2.100:5555-cmd:nc -l 5555"
  "-device" "virtio-net-device,netdev=net0"
];
```

**Approach 2: veth Pair with Host Bridge**

```nix
# Create veth pair in NixOS module
microvm.interfaces = [{
  type = "tap";
  id = "xdp2-tap0";
  mac = "02:00:00:00:01:00";
}];

# Host-side: Attach to bridge for packet injection
networking.bridges.xdp2-br0.interfaces = [ "xdp2-tap0" ];
```

**Host-side packet injection with scapy:**

```python
#!/usr/bin/env python3
# test-xdp-injection.py
from scapy.all import *

# Send test packet into VM's XDP hook
pkt = Ether()/IP(dst="10.0.2.15")/TCP(dport=80)
sendp(pkt, iface="xdp2-tap0")

# Capture and verify XDP output
result = sniff(iface="xdp2-tap0", count=1, timeout=5)
assert result[0][IP].dst == "10.0.2.15", "XDP modified packet unexpectedly"
```

**Test scenarios:**

| Test | Input | Expected XDP Action | Validates |
|------|-------|---------------------|-----------|
| Pass-through | Valid IPv4 | XDP_PASS | Basic forwarding |
| Drop invalid | Malformed header | XDP_DROP | Header validation |
| Redirect | Matching flow | XDP_REDIRECT | Flow steering |
| Byte-order | BE EtherType | Correct parse | Endianness handling |

### Phase 3: CI Integration

Full GitHub Actions workflow with fast/full mode selection.

```yaml
# .github/workflows/xdp2-test.yml
name: XDP2 MicroVM Tests

on:
  push:
    branches: [main]
  pull_request:

jobs:
  fast-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: cachix/install-nix-action@v26
      - uses: cachix/cachix-action@v14
        with:
          name: xdp2
      - name: Fast mode (x86_64 + riscv64)
        run: |
          systemd-run --user --scope -p CPUQuota=80% \
            nix run .#xdp2-test-fast

  full-test:
    if: github.ref == 'refs/heads/main'
    runs-on: ubuntu-latest
    strategy:
      matrix:
        kernel: [latest, lts]
    steps:
      - uses: actions/checkout@v4
      - uses: cachix/install-nix-action@v26
      - name: Full mode (${{ matrix.kernel }} kernel)
        run: |
          systemd-run --user --scope -p CPUQuota=80% -p MemoryMax=12G \
            nix run .#xdp2-test-all -- --kernel ${{ matrix.kernel }}
      - name: Upload verifier logs
        if: failure()
        uses: actions/upload-artifact@v4
        with:
          name: verifier-logs-${{ matrix.kernel }}
          path: test-logs/verifier-*.log

  endianness-test:
    if: github.ref == 'refs/heads/main'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: cachix/install-nix-action@v26
      - name: Big Endian validation (s390x)
        run: nix run .#xdp2-test-endian
```

### Phase 4: Kernel Version Matrix Testing

Test against multiple kernel versions to ensure backward compatibility:

```bash
# Test all architectures on both LTS and latest kernels
nix run .#xdp2-test-matrix

# Output:
# ┌─────────────┬─────────────┬─────────────┐
# │ Architecture│ Kernel 5.15 │ Kernel 6.x  │
# ├─────────────┼─────────────┼─────────────┤
# │ x86_64      │     ✓       │     ✓       │
# │ riscv64     │     ✓       │     ✓       │
# │ s390x       │     ✗       │     ✓       │  ← Feature requires 6.x
# └─────────────┴─────────────┴─────────────┘
```

---

## Cross-Compilation for Distribution

This section describes how to cross-compile XDP2 binaries for multiple architectures and generate Linux distribution packages (.deb and .rpm).

### Architecture Targets

XDP2 compiler binaries should be available for these architectures:

| Architecture | Nix System | Target Use Case | Package Priority |
|-------------|------------|-----------------|------------------|
| **x86_64** | `x86_64-linux` | Servers, desktops, CI | High |
| **aarch64** | `aarch64-linux` | ARM servers, Graviton, RPi 4/5 | High |
| **riscv64** | `riscv64-linux` | RISC-V servers, SiFive, StarFive VisionFive | High |
| **riscv32** | `riscv32-linux` | RISC-V embedded, ESP32-C3, microcontrollers | High |
| **armv7l** | `armv7l-linux` | Older ARM (RPi 2/3 32-bit) | Medium |

> **Note:** RISC-V is a priority target for XDP2. The architecture is gaining traction in networking equipment, embedded systems, and data center infrastructure. Both 32-bit (microcontrollers, IoT) and 64-bit (servers, network appliances) variants are important.

### Cross-Compilation Strategy

Nix provides `pkgsCross.<arch>` for cross-compilation. The key insight is separating:

1. **Build-time tools** (`nativeBuildInputs`) - Run on the build host (always x86_64)
2. **Target libraries** (`buildInputs`) - Link into the cross-compiled binary

**Special case for xdp2-compiler:** The compiler itself is a code generator that runs on the host, not a runtime tool. For distribution, we cross-compile it so users on ARM servers can run it natively.

### Implementation

#### Cross-Compilation Module (`nix/cross.nix`)

```nix
# nix/cross.nix
#
# Cross-compilation support for XDP2 binaries.
# Generates binaries for multiple target architectures from an x86_64 host.
#
{ pkgs, lib }:

let
  # Target architectures for cross-compilation
  # RISC-V (both 32 and 64-bit) are priority targets
  crossTargets = {
    x86_64 = pkgs;  # Native build
    aarch64 = pkgs.pkgsCross.aarch64-multiplatform;
    riscv64 = pkgs.pkgsCross.riscv64;
    riscv32 = pkgs.pkgsCross.riscv32;
    armv7l = pkgs.pkgsCross.armv7l-hf-multiplatform;
  };

  # Import base derivation
  mkXdp2 = crossPkgs: import ./derivation.nix {
    pkgs = crossPkgs;
    lib = crossPkgs.lib;
    llvmConfig = import ./llvm.nix { pkgs = crossPkgs; lib = crossPkgs.lib; };
    inherit (import ./packages.nix {
      pkgs = crossPkgs;
      llvmPackages = (import ./llvm.nix { pkgs = crossPkgs; lib = crossPkgs.lib; }).llvmPackages;
    }) nativeBuildInputs buildInputs;
    enableAsserts = false;
  };

in {
  # Cross-compiled packages
  # Usage: nix build .#cross.aarch64
  packages = lib.mapAttrs (name: crossPkgs: mkXdp2 crossPkgs) crossTargets;

  # Convenience: build all architectures
  # Usage: nix build .#cross.all
  all = pkgs.symlinkJoin {
    name = "xdp2-cross-all";
    paths = lib.attrValues (lib.mapAttrs (name: crossPkgs:
      pkgs.runCommand "xdp2-${name}" {} ''
        mkdir -p $out/${name}
        cp -r ${mkXdp2 crossPkgs}/* $out/${name}/
      ''
    ) crossTargets);
  };
}
```

#### Cross-Compilation Caveats

**LLVM/Clang dependency:** The xdp2-compiler links against libclang. Cross-compiling LLVM is complex. Two approaches:

1. **Static linking** (recommended): Link libclang statically to avoid runtime dependency issues
2. **Host-only compiler**: Build xdp2-compiler only for the host, cross-compile libraries only

```nix
# In derivation.nix - static LLVM linking for portability
buildPhase = ''
  # ... existing build steps ...

  # For cross-compiled builds, use static LLVM linking
  ${lib.optionalString (pkgs.stdenv.hostPlatform != pkgs.stdenv.buildPlatform) ''
    export LLVM_LINK_STATIC=1
  ''}
'';
```

**Build-time vs runtime tools:** Some tools (like the xdp2-compiler) need to run during build. For cross-compilation:

```nix
nativeBuildInputs = [
  # These run on the BUILD machine (always x86_64)
  pkgs.buildPackages.gcc
  pkgs.buildPackages.gnumake
  pkgs.buildPackages.pkg-config
];

buildInputs = [
  # These link into the TARGET binary
  pkgs.boost
  pkgs.libelf
];
```

### Flake Integration

```nix
# In flake.nix - add cross-compilation outputs
{
  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        cross = import ./nix/cross.nix { inherit pkgs lib; };
      in {
        packages = {
          # ... existing packages ...

          # Cross-compiled binaries
          cross = cross.packages;
          cross-all = cross.all;
        };
      });
}
```

**Usage:**

```bash
# Build for specific architecture
nix build .#cross.aarch64
nix build .#cross.riscv64
nix build .#cross.riscv32

# Build all architectures
nix build .#cross.all
ls result/
# => aarch64/ riscv64/ riscv32/ x86_64/ armv7l/

# Inspect cross-compiled binaries
file result/riscv64/bin/xdp2-compiler
# => ELF 64-bit LSB executable, UCB RISC-V, ...

file result/riscv32/bin/xdp2-compiler
# => ELF 32-bit LSB executable, UCB RISC-V, ...
```

---

## Linux Package Generation

Generate `.deb` (Debian/Ubuntu) and `.rpm` (RHEL/Fedora) packages from Nix builds.

### Package Contents

Each package should include:

| Component | Destination | Description |
|-----------|-------------|-------------|
| `xdp2-compiler` | `/usr/bin/` | Main compiler tool |
| `cppfront-compiler` | `/usr/bin/` | C++ metaprogramming tool |
| `libxdp2.so` | `/usr/lib/` | Core library |
| `libxdp2.a` | `/usr/lib/` | Static library |
| Headers | `/usr/include/xdp2/` | API headers |
| Templates | `/usr/share/xdp2/` | Code templates |

### Package Metadata

```nix
# nix/packaging/metadata.nix
{
  name = "xdp2";
  version = "0.1.0";
  maintainer = "XDP2 Team <team@xdp2.dev>";
  description = "High-performance packet processing framework using eBPF/XDP";
  homepage = "https://github.com/xdp2/xdp2";
  license = "MIT";

  # Runtime dependencies (translated to package deps)
  depends = {
    deb = [ "libboost-all-dev" "libelf1" "libbpf0" ];
    rpm = [ "boost-devel" "elfutils-libelf" "libbpf" ];
  };
}
```

### Implementation Approach: FPM (Effing Package Management)

FPM is a tool that converts directory structures into native packages. Nix can drive FPM to generate packages.

#### Package Builder Module (`nix/packaging/default.nix`)

```nix
# nix/packaging/default.nix
#
# Generate .deb and .rpm packages from Nix builds.
# Uses FPM (Effing Package Management) for package creation.
#
{ pkgs, lib, xdp2 }:

let
  metadata = import ./metadata.nix;

  # Common FPM arguments
  fpmCommon = arch: ''
    --name ${metadata.name} \
    --version ${metadata.version} \
    --maintainer "${metadata.maintainer}" \
    --description "${metadata.description}" \
    --url "${metadata.homepage}" \
    --license "${metadata.license}" \
    --architecture ${arch}
  '';

  # Create package staging directory
  mkStaging = arch: pkgs.runCommand "xdp2-staging-${arch}" {} ''
    mkdir -p $out/usr/bin
    mkdir -p $out/usr/lib
    mkdir -p $out/usr/include
    mkdir -p $out/usr/share/xdp2

    # Copy binaries
    cp ${xdp2}/bin/* $out/usr/bin/ 2>/dev/null || true

    # Copy libraries
    cp ${xdp2}/lib/*.so $out/usr/lib/ 2>/dev/null || true
    cp ${xdp2}/lib/*.a $out/usr/lib/ 2>/dev/null || true

    # Copy headers
    cp -r ${xdp2}/include/* $out/usr/include/ 2>/dev/null || true

    # Copy templates
    cp -r ${xdp2}/share/xdp2/* $out/usr/share/xdp2/ 2>/dev/null || true
  '';

  # Generate .deb package
  mkDeb = { arch, debArch }: pkgs.runCommand "xdp2-${metadata.version}-${debArch}.deb" {
    nativeBuildInputs = [ pkgs.fpm ];
  } ''
    mkdir -p $out

    fpm -s dir -t deb \
      ${fpmCommon debArch} \
      ${lib.concatMapStringsSep " " (d: "--depends ${d}") metadata.depends.deb} \
      --chdir ${mkStaging arch} \
      --package $out/xdp2_${metadata.version}_${debArch}.deb \
      .
  '';

  # Generate .rpm package
  mkRpm = { arch, rpmArch }: pkgs.runCommand "xdp2-${metadata.version}-${rpmArch}.rpm" {
    nativeBuildInputs = [ pkgs.fpm pkgs.rpm ];
  } ''
    mkdir -p $out

    fpm -s dir -t rpm \
      ${fpmCommon rpmArch} \
      ${lib.concatMapStringsSep " " (d: "--depends ${d}") metadata.depends.rpm} \
      --chdir ${mkStaging arch} \
      --package $out/xdp2-${metadata.version}-1.${rpmArch}.rpm \
      .
  '';

in {
  # Individual packages
  # Note: RISC-V uses "riscv64" and "riscv32" for both deb and rpm
  deb = {
    x86_64 = mkDeb { arch = "x86_64"; debArch = "amd64"; };
    aarch64 = mkDeb { arch = "aarch64"; debArch = "arm64"; };
    riscv64 = mkDeb { arch = "riscv64"; debArch = "riscv64"; };
    riscv32 = mkDeb { arch = "riscv32"; debArch = "riscv32"; };
    armv7l = mkDeb { arch = "armv7l"; debArch = "armhf"; };
  };

  rpm = {
    x86_64 = mkRpm { arch = "x86_64"; rpmArch = "x86_64"; };
    aarch64 = mkRpm { arch = "aarch64"; rpmArch = "aarch64"; };
    riscv64 = mkRpm { arch = "riscv64"; rpmArch = "riscv64"; };
    riscv32 = mkRpm { arch = "riscv32"; rpmArch = "riscv32"; };
  };

  # All packages combined
  all = pkgs.symlinkJoin {
    name = "xdp2-packages-all";
    paths = [
      (mkDeb { arch = "x86_64"; debArch = "amd64"; })
      (mkDeb { arch = "aarch64"; debArch = "arm64"; })
      (mkDeb { arch = "riscv64"; debArch = "riscv64"; })
      (mkDeb { arch = "riscv32"; debArch = "riscv32"; })
      (mkRpm { arch = "x86_64"; rpmArch = "x86_64"; })
      (mkRpm { arch = "aarch64"; rpmArch = "aarch64"; })
      (mkRpm { arch = "riscv64"; rpmArch = "riscv64"; })
      (mkRpm { arch = "riscv32"; rpmArch = "riscv32"; })
    ];
  };
}
```

### Flake Integration

```nix
# In flake.nix - add packaging outputs
{
  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        xdp2 = import ./nix/derivation.nix { /* ... */ };

        # Cross-compiled variants
        cross = import ./nix/cross.nix { inherit pkgs lib; };

        # Package generator
        packaging = import ./nix/packaging {
          inherit pkgs lib;
          xdp2 = xdp2;  # or cross.packages.aarch64 for ARM packages
        };

      in {
        packages = {
          # ... existing packages ...

          # Linux packages - x86_64
          deb-x86_64 = packaging.deb.x86_64;
          rpm-x86_64 = packaging.rpm.x86_64;

          # Linux packages - ARM64
          deb-aarch64 = packaging.deb.aarch64;
          rpm-aarch64 = packaging.rpm.aarch64;

          # Linux packages - RISC-V 64-bit (priority target)
          deb-riscv64 = packaging.deb.riscv64;
          rpm-riscv64 = packaging.rpm.riscv64;

          # Linux packages - RISC-V 32-bit (priority target)
          deb-riscv32 = packaging.deb.riscv32;
          rpm-riscv32 = packaging.rpm.riscv32;

          # Linux packages - ARM 32-bit
          deb-armv7l = packaging.deb.armv7l;

          # All packages
          packages-all = packaging.all;
        };
      });
}
```

**Usage:**

```bash
# Build specific package
nix build .#deb-x86_64
ls result/
# => xdp2_0.1.0_amd64.deb

nix build .#rpm-aarch64
ls result/
# => xdp2-0.1.0-1.aarch64.rpm

# Build all packages
nix build .#packages-all
ls result/
# => xdp2_0.1.0_amd64.deb  xdp2_0.1.0_arm64.deb  xdp2-0.1.0-1.x86_64.rpm  ...

# Test installation (in a container)
docker run -v $(pwd)/result:/pkg debian:bookworm dpkg -i /pkg/xdp2_0.1.0_amd64.deb
docker run -v $(pwd)/result:/pkg fedora:40 rpm -i /pkg/xdp2-0.1.0-1.x86_64.rpm
```

### CI Release Workflow

```yaml
# .github/workflows/release.yml
name: Release Packages

on:
  push:
    tags: ['v*']

jobs:
  build-packages:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        include:
          - arch: x86_64
            deb: amd64
            rpm: x86_64
          - arch: aarch64
            deb: arm64
            rpm: aarch64
          - arch: riscv64
            deb: riscv64
            rpm: riscv64
          - arch: riscv32
            deb: riscv32
            rpm: riscv32

    steps:
      - uses: actions/checkout@v4
      - uses: cachix/install-nix-action@v26

      - name: Build .deb
        run: nix build .#deb-${{ matrix.arch }}

      - name: Build .rpm
        run: nix build .#rpm-${{ matrix.arch }}

      - name: Upload artifacts
        uses: actions/upload-artifact@v4
        with:
          name: packages-${{ matrix.arch }}
          path: |
            result/*.deb
            result/*.rpm

  create-release:
    needs: build-packages
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4

      - name: Create GitHub Release
        uses: softprops/action-gh-release@v1
        with:
          files: |
            packages-*/*.deb
            packages-*/*.rpm
```

### Alternative: Native Nix Package Generation

For environments without FPM, Nix can generate packages directly using `dpkg-deb` and `rpmbuild`:

```nix
# Direct .deb generation without FPM
mkDebNative = { arch, debArch }: pkgs.runCommand "xdp2-${metadata.version}-${debArch}.deb" {
  nativeBuildInputs = [ pkgs.dpkg ];
} ''
  # Create DEBIAN control directory
  mkdir -p pkg/DEBIAN
  cat > pkg/DEBIAN/control << EOF
  Package: xdp2
  Version: ${metadata.version}
  Architecture: ${debArch}
  Maintainer: ${metadata.maintainer}
  Description: ${metadata.description}
  Depends: ${lib.concatStringsSep ", " metadata.depends.deb}
  EOF

  # Copy files
  mkdir -p pkg/usr
  cp -r ${mkStaging arch}/usr/* pkg/usr/

  # Build package
  dpkg-deb --build pkg $out/xdp2_${metadata.version}_${debArch}.deb
'';
```

### Package Verification

```bash
# Verify .deb contents
dpkg-deb --contents result/xdp2_0.1.0_amd64.deb

# Verify .rpm contents
rpm -qlp result/xdp2-0.1.0-1.x86_64.rpm

# Check dependencies
dpkg-deb --info result/xdp2_0.1.0_amd64.deb | grep Depends
rpm -qpR result/xdp2-0.1.0-1.x86_64.rpm
```

---

## Revision History

- **2026-02-16**: Initial draft
- Added BTF requirements and workaround (CONFIG_DEBUG_INFO_BTF=y)
- Added comprehensive tooling (profiling, debugging, network testing)
- Added MIPS64, PowerPC64, and s390x architecture support
- Added note on Linux-only (no FreeBSD/Solaris)
- Added RISC-V 32-bit (riscv32) to demonstrate 32-bit architecture support
- Added VM management helper scripts section
- Added automated testing section
- **2026-02-16**: Major revision
- Added Table of Contents
- Added Test Modes (fast/full)
- Added Performance Optimization section
- Refactored Nix to DRY pattern with arch.nix generator
- Consolidated constants into single source of truth
- Reorganized document for better flow
- **2026-02-16**: High Confidence Testing revision
- Added High Confidence Testing section
  - Endianness validation (s390x as Big Endian target)
  - Kernel version matrix (LTS + latest)
  - Verifier log export for debugging
- Added CI Resource Throttling (cgroups/nice)
- Added pahole requirement for BTF generation
- Expanded Future Enhancements with packet injection details
- Added bpftool version matching guidance
- **2026-02-16**: Advanced Nix Patterns revision
- Added Advanced Nix Patterns section
  - Functional matrix generation with `lib.cartesianProductOfSets`
  - Store injection via virtio-9p for instant boot
  - Systemd test driver (oneshot service instead of console polling)
  - Cross-compilation overlays
  - NixOS module pattern for reusable configuration
- Restructured Implementation section
  - `nix/lib/mk-vm.nix` - VM builder function with callPackage
  - `nix/microvms/matrix.nix` - Generates (arch × kernel) combinations
  - `nix/modules/ebpf-base.nix` - Reusable eBPF NixOS module
- Updated Flake Integration to use callPackage pattern
- Test matrix now a first-class flake output: `nix build .#tests.matrix.x86_64-stable`
- **2026-02-17**: Cross-Compilation and Packaging revision
- Added Cross-Compilation for Distribution section
  - Architecture targets (x86_64, aarch64, riscv64, riscv32, armv7l)
  - **RISC-V 32-bit and 64-bit as priority targets**
  - `pkgsCross.*` strategy with nativeBuildInputs/buildInputs separation
  - LLVM static linking for portability
  - `nix/cross.nix` module implementation
- Added Linux Package Generation section
  - `.deb` for Debian/Ubuntu (apt) - all architectures including RISC-V
  - `.rpm` for RHEL/Fedora (dnf) - all architectures including RISC-V
  - FPM-based and native dpkg-deb approaches
  - `nix/packaging/` module implementation
  - CI release workflow for GitHub Actions with full RISC-V support

---

## References

- [microvm.nix Documentation](https://github.com/astro/microvm.nix)
- [Console Demo Example](https://github.com/astro/microvm.nix/tree/main/examples/console-demo)
- [XDP2 Nix Infrastructure](documentation/nix/xdp-samples-status.md)
- [PCP BPF BTF Pattern](file:///home/das/Downloads/pcp/nix/bpf.nix) - Reference for BTF workaround
- **Pending:** microvm.nix BTF feature PR
