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
8. [Implementation](#implementation)
   - [Directory Structure](#directory-structure)
   - [Constants Module](#constants-module-nixmicrovmsconstantsnix)
   - [Architecture Generator](#architecture-generator-nixmicrovmsarchnix)
   - [Base VM Module](#base-vm-module-nixmicrovmsbasenix)
   - [Packages Module](#packages-module-nixmicrovmspackagesnix)
   - [QEMU Console Configuration](#qemu-console-configuration)
   - [VM Generator Entry Point](#vm-generator-entry-point)
   - [Flake Integration](#flake-integration)
9. [Console Architecture](#console-architecture)
10. [BTF Requirements](#btf-bpf-type-format-requirements)
11. [VM Management Scripts](#vm-management-scripts)
12. [Automated Testing](#automated-testing)
13. [Usage Examples](#usage-examples)
14. [Troubleshooting](#troubleshooting)
15. [Future Enhancements](#future-enhancements)
16. [Revision History](#revision-history)
17. [References](#references)

---

## Executive Summary

This document describes the design for a NixOS MicroVM-based test infrastructure for XDP2 eBPF programs. The infrastructure enables:

1. **Cross-architecture testing** - QEMU emulation for ARM64, RISC-V, MIPS64, PowerPC64, and s390x
2. **Native performance testing** - KVM acceleration for x86_64
3. **Dual console access** - Serial (ttyS0) for boot debugging, virtio (hvc0) for interactive use
4. **Reproducible environments** - Nix-based VM definitions with pinned kernel versions
5. **BTF-enabled kernels** - Required for CO-RE eBPF programs (CONFIG_DEBUG_INFO_BTF=y)
6. **Two test modes** - Fast mode for development iteration, full mode for CI/release

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

## Implementation

### Directory Structure

```
nix/
├── microvms/
│   ├── default.nix              # Entry point, exports VMs and scripts
│   ├── constants.nix            # Ports, timeouts, resources (single source of truth)
│   ├── arch.nix                 # Architecture generator (DRY pattern)
│   ├── base.nix                 # Base VM configuration module
│   ├── packages.nix             # Tool packages (profiling, debugging, network)
│   └── qemu-consoles.nix        # Dual console QEMU args
├── scripts/
│   ├── default.nix              # Script exports
│   └── vm-management.nix        # VM management scripts (start/stop/console/tmux)
├── tests/
│   ├── default.nix              # Test exports
│   ├── run-fast.nix             # Fast mode runner (x86_64 + riscv64)
│   ├── run-all.nix              # Full mode runner (all architectures)
│   └── test-lib.nix             # Shared test utilities
└── lib/
    └── microvm-lib.nix          # Helper functions
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

### Architecture Generator (`nix/microvms/arch.nix`)

DRY pattern for generating architecture-specific VMs from constants.

```nix
# nix/microvms/arch.nix
#
# Architecture generator - creates VMs from architecture definitions.
# This eliminates the need for separate per-architecture files.
#
{ pkgs, lib, microvm, nixpkgs, system, xdp2 }:

let
  constants = import ./constants.nix;
  qemuConsoles = import ./qemu-consoles.nix;
  vmPackages = import ./packages.nix { inherit pkgs; };

  # ═══════════════════════════════════════════════════════════════════════════
  # VM Generator Function
  # ═══════════════════════════════════════════════════════════════════════════

  mkTestVM = arch:
    let
      cfg = constants.getArchConfig arch;
      archDef = constants.architectures.${arch};

    in (nixpkgs.lib.nixosSystem {
      system = cfg.nixSystem;

      modules = [
        microvm.nixosModules.microvm

        ({ config, pkgs, ... }: {
          system.stateVersion = "24.05";
          networking.hostName = cfg.hostName;

          # ─── MicroVM Configuration ──────────────────────────────────────
          microvm = {
            hypervisor = "qemu";
            mem = cfg.mem;
            vcpu = cfg.vcpu;
            interfaces = [];

            qemu.serialConsole = false;

            qemu.extraArgs = [
              "-name" "${cfg.hostName},process=${cfg.hostName}"
              "-machine" archDef.machine
              "-cpu" archDef.cpu
            ]
            ++ (lib.optionals archDef.useKvm [ "-enable-kvm" ])
            ++ (qemuConsoles {
              serialPort = cfg.serialPort;
              virtioPort = cfg.virtioPort;
            });
          };

          # ─── Kernel Configuration ───────────────────────────────────────
          boot.kernelParams = archDef.consoleOverride or [
            "console=ttyS0,115200"
            "console=hvc0"
          ];

          boot.kernelPackages = pkgs.linuxPackages_latest;

          # Enable BTF for CO-RE eBPF programs
          boot.kernelPatches = [{
            name = "btf-support";
            patch = null;
            extraConfig = ''
              DEBUG_INFO_BTF y
            '';
          }];

          # ─── Getty Configuration ────────────────────────────────────────
          systemd.services."serial-getty@ttyS0" = {
            enable = true;
            wantedBy = [ "getty.target" ];
          };
          systemd.services."serial-getty@hvc0" = {
            enable = true;
            wantedBy = [ "getty.target" ];
          };
          services.getty.autologinUser = "root";
          users.users.root.password = "";

          # ─── eBPF Requirements ──────────────────────────────────────────
          boot.kernel.sysctl = {
            "net.core.bpf_jit_enable" = 1;
            "kernel.unprivileged_bpf_disabled" = 0;
          };

          # ─── Packages ───────────────────────────────────────────────────
          environment.systemPackages = [ xdp2 ] ++ vmPackages.all;

          # ─── Welcome Message ────────────────────────────────────────────
          users.motd = ''
            ┌─────────────────────────────────────────────────────────────┐
            │              XDP2 eBPF Test VM (${arch})
            ├─────────────────────────────────────────────────────────────┤
            │  ${archDef.description}
            │
            │  Consoles:
            │    ttyS0 (serial) - port ${toString cfg.serialPort}
            │    hvc0  (virtio) - port ${toString cfg.virtioPort}
            │
            │  Quick tests:
            │    bpftool prog list
            │    bpftool feature probe
            └─────────────────────────────────────────────────────────────┘
          '';
        })
      ];
    }).config.microvm.declaredRunner;

  # ═══════════════════════════════════════════════════════════════════════════
  # Console Script Generator
  # ═══════════════════════════════════════════════════════════════════════════

  mkConsoleScripts = arch:
    let
      cfg = constants.getArchConfig arch;
    in {
      connect-serial = pkgs.writeShellApplication {
        name = "connect-serial";
        runtimeInputs = [ pkgs.netcat ];
        text = ''
          echo "Connecting to ${cfg.hostName} serial (ttyS0) on port ${toString cfg.serialPort}"
          exec nc localhost ${toString cfg.serialPort}
        '';
      };

      connect-console = pkgs.writeShellApplication {
        name = "connect-console";
        runtimeInputs = [ pkgs.netcat ];
        text = ''
          echo "Connecting to ${cfg.hostName} virtio (hvc0) on port ${toString cfg.virtioPort}"
          exec nc localhost ${toString cfg.virtioPort}
        '';
      };

      console-status = pkgs.writeShellApplication {
        name = "console-status";
        runtimeInputs = [ pkgs.netcat ];
        text = ''
          echo "Console Status for ${cfg.hostName}"
          echo "═══════════════════════════════════"
          printf "ttyS0 (serial) port ${toString cfg.serialPort}: "
          if nc -z localhost ${toString cfg.serialPort} 2>/dev/null; then
            echo "listening"
          else
            echo "not available"
          fi
          printf "hvc0 (virtio) port ${toString cfg.virtioPort}: "
          if nc -z localhost ${toString cfg.virtioPort} 2>/dev/null; then
            echo "listening"
          else
            echo "not available"
          fi
        '';
      };
    };

in {
  # Generate VMs for all architectures
  vms = lib.mapAttrs (arch: _: mkTestVM arch) constants.architectures;

  # Generate console scripts for all architectures
  scripts = lib.mapAttrs (arch: _: mkConsoleScripts arch) constants.architectures;

  # Export constants for other modules
  inherit constants;

  # Export architecture list
  architectureNames = builtins.attrNames constants.architectures;
}
```

### Base VM Module (`nix/microvms/base.nix`)

With the architecture generator, `base.nix` becomes simpler - just shared utilities:

```nix
# nix/microvms/base.nix
#
# Shared utilities for MicroVM configuration.
# Most VM generation is now handled by arch.nix.
#
{ lib }:

{
  # BTF check script (injected into VMs)
  btfCheckScript = ''
    if [ -f /sys/kernel/btf/vmlinux ]; then
      echo "BTF enabled"
    else
      echo "WARNING: BTF not enabled - CO-RE eBPF programs will fail"
      echo "Verify with: ls /sys/kernel/btf/vmlinux"
    fi
  '';

  # eBPF verification commands
  ebpfVerifyCommands = [
    "bpftool feature probe"
    "bpftool prog list"
    "ls /sys/kernel/btf/vmlinux"
  ];
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

### QEMU Console Configuration

```nix
# nix/microvms/qemu-consoles.nix
#
# QEMU command-line arguments for TCP-accessible consoles.
#
{ serialPort, virtioPort }:

[
  # ttyS0: Serial console on TCP socket
  "-chardev"
  "socket,id=serial0,host=localhost,port=${toString serialPort},server=on,wait=off"
  "-serial"
  "chardev:serial0"

  # hvc0: virtio-console on TCP socket
  "-device"
  "virtio-serial-device"
  "-chardev"
  "socket,id=virtcon0,host=localhost,port=${toString virtioPort},server=on,wait=off"
  "-device"
  "virtconsole,chardev=virtcon0"
]
```

### VM Generator Entry Point

```nix
# nix/microvms/default.nix
#
# XDP2 MicroVM test infrastructure entry point.
#
{ pkgs, lib, microvm, nixpkgs, system, xdp2 }:

let
  arch = import ./arch.nix {
    inherit pkgs lib microvm nixpkgs system xdp2;
  };

  constants = arch.constants;

  # ═══════════════════════════════════════════════════════════════════════════
  # Test Mode Runners
  # ═══════════════════════════════════════════════════════════════════════════

  mkTestRunner = { name, architectures, description }:
    pkgs.writeShellApplication {
      inherit name;
      runtimeInputs = with pkgs; [ coreutils gnugrep netcat nix ];
      text = ''
        echo "════════════════════════════════════════════════════════════════"
        echo "  XDP2 Test: ${description}"
        echo "  Architectures: ${lib.concatStringsSep ", " architectures}"
        echo "════════════════════════════════════════════════════════════════"

        FAILED=""
        PASSED=""

        for arch in ${lib.concatStringsSep " " architectures}; do
          echo ""
          echo "Testing: $arch"
          if nix build ".#xdp2-test-vm-$arch" --no-link 2>/dev/null; then
            RESULT=$(nix build ".#xdp2-test-vm-$arch" --print-out-paths)
            if [ -x "$RESULT/bin/run-test" ] && "$RESULT/bin/run-test"; then
              echo "  PASSED: $arch"
              PASSED="$PASSED $arch"
            else
              echo "  FAILED: $arch"
              FAILED="$FAILED $arch"
            fi
          else
            echo "  FAILED: $arch (build error)"
            FAILED="$FAILED $arch"
          fi
        done

        echo ""
        echo "════════════════════════════════════════════════════════════════"
        if [ -n "$PASSED" ]; then echo "Passed:$PASSED"; fi
        if [ -n "$FAILED" ]; then
          echo "Failed:$FAILED"
          exit 1
        else
          echo "All tests passed!"
        fi
      '';
    };

in {
  # ─── VM Exports ─────────────────────────────────────────────────────────
  inherit (arch) vms scripts constants architectureNames;

  # ─── Test Mode Runners ──────────────────────────────────────────────────
  testRunners = {
    fast = mkTestRunner {
      name = "xdp2-test-fast";
      architectures = constants.testModes.fast;
      description = "Fast Mode (Development)";
    };

    all = mkTestRunner {
      name = "xdp2-test-all";
      architectures = constants.testModes.full;
      description = "Full Mode (CI/Release)";
    };
  };
}
```

### Flake Integration

```nix
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
        xdp2 = import ./nix/derivation.nix { inherit pkgs; };

        microvms = import ./nix/microvms {
          inherit pkgs microvm nixpkgs system xdp2;
          lib = pkgs.lib;
        };

      in {
        packages = {
          # ─── Test Mode Runners ──────────────────────────────────────────
          xdp2-test-fast = microvms.testRunners.fast;
          xdp2-test-all = microvms.testRunners.all;

          # ─── Per-Architecture VMs (generated from constants) ────────────
        } // (pkgs.lib.mapAttrs'
          (arch: vm: pkgs.lib.nameValuePair "xdp2-test-vm-${arch}" vm)
          microvms.vms
        ) // (pkgs.lib.foldl' (acc: arch:
          acc // {
            "xdp2-vm-console-${arch}" = microvms.scripts.${arch}.connect-console;
            "xdp2-vm-serial-${arch}" = microvms.scripts.${arch}.connect-serial;
            "xdp2-vm-status-${arch}" = microvms.scripts.${arch}.console-status;
          }
        ) {} microvms.architectureNames);
      });
}
```

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

---

## References

- [microvm.nix Documentation](https://github.com/astro/microvm.nix)
- [Console Demo Example](https://github.com/astro/microvm.nix/tree/main/examples/console-demo)
- [XDP2 Nix Infrastructure](documentation/nix/xdp-samples-status.md)
- [PCP BPF BTF Pattern](file:///home/das/Downloads/pcp/nix/bpf.nix) - Reference for BTF workaround
- **Pending:** microvm.nix BTF feature PR
