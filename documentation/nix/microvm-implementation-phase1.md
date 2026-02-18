# MicroVM Implementation Phase 1: Single-Thread Validation

**Status:** IMPLEMENTATION PLAN
**Created:** 2026-02-17
**Parent Design:** [microvm-ebpf-test-design.md](./microvm-ebpf-test-design.md)

---

## Overview

The [comprehensive design](./microvm-ebpf-test-design.md) describes a full matrix of:
- 7 architectures (x86_64, aarch64, riscv64, riscv32, mips64, ppc64, s390x)
- Multiple kernel versions (latest, stable, LTS)
- Multiple package formats (.deb, .rpm)
- MicroVM testing infrastructure

**This document describes Phase 1:** Implement a single path through all features to validate the design before taking on full complexity.

### Why Single-Thread First?

1. **Validate assumptions** - The design makes assumptions about Nix patterns, FPM behavior, and MicroVM integration that need testing
2. **Discover unknowns** - Cross-compilation and packaging often have subtle issues that only surface during implementation
3. **Establish patterns** - Get the code structure right once, then replicate
4. **Fast feedback** - A working x86_64 path can be tested immediately without QEMU emulation delays
5. **Incremental complexity** - Add architectures one at a time, learning from each

---

## Phase 1 Scope

### What We're Building

| Dimension | Phase 1 Choice | Why |
|-----------|---------------|-----|
| **Architecture** | x86_64 only | Native build, no cross-compilation complexity |
| **Package format** | .deb only | Simpler than RPM, broader user base (Ubuntu/Debian) |
| **Kernel version** | stable only | Well-tested, fewer edge cases |
| **Test mode** | Single VM | Validate one VM works before matrix |

### What We're Deferring

- Cross-compilation (aarch64, riscv64, riscv32, etc.)
- RPM package generation
- Multiple kernel versions (latest, LTS)
- Full test matrix
- Parallel VM execution
- CI workflow integration

---

## Implementation Plan

### Directory Structure (Phase 1)

```
nix/
├── derivation.nix          # Existing - XDP2 build
├── packages.nix            # Existing - Dependencies
├── llvm.nix                # Existing - LLVM config
├── packaging/              # NEW - Package generation
│   ├── default.nix         # Entry point
│   ├── metadata.nix        # Package metadata
│   └── deb.nix             # .deb generation (x86_64 only)
└── microvms/               # NEW - MicroVM infrastructure
    ├── default.nix         # Entry point
    ├── constants.nix       # Configuration (x86_64 only)
    └── x86_64.nix          # Single VM definition
```

### Step-by-Step Implementation

#### Step 1: Package Metadata (`nix/packaging/metadata.nix`)

Define package information in one place.

```nix
# nix/packaging/metadata.nix
{
  name = "xdp2";
  version = "0.1.0";
  maintainer = "XDP2 Team <team@xdp2.dev>";
  description = "High-performance packet processing framework using eBPF/XDP";
  homepage = "https://github.com/xdp2/xdp2";
  license = "MIT";

  # Debian dependencies (runtime)
  debDepends = [
    "libc6"
    "libstdc++6"
    "libboost-all-dev"
    "libelf1"
  ];
}
```

**Validation:** Can be imported and values accessed.

---

#### Step 2: Staging Directory (`nix/packaging/deb.nix`)

Create a directory structure matching the .deb layout.

```nix
# nix/packaging/deb.nix
{ pkgs, lib, xdp2 }:

let
  metadata = import ./metadata.nix;

  # Create staging directory with FHS layout
  staging = pkgs.runCommand "xdp2-staging" {} ''
    mkdir -p $out/usr/bin
    mkdir -p $out/usr/lib
    mkdir -p $out/usr/include/xdp2
    mkdir -p $out/usr/share/xdp2
    mkdir -p $out/usr/share/doc/xdp2

    # Binaries
    cp -v ${xdp2}/bin/xdp2-compiler $out/usr/bin/ || echo "No xdp2-compiler"
    cp -v ${xdp2}/bin/cppfront-compiler $out/usr/bin/ || echo "No cppfront-compiler"

    # Libraries
    for lib in ${xdp2}/lib/*.so ${xdp2}/lib/*.a; do
      [ -f "$lib" ] && cp -v "$lib" $out/usr/lib/
    done 2>/dev/null || echo "No libraries"

    # Headers
    if [ -d ${xdp2}/include ]; then
      cp -rv ${xdp2}/include/* $out/usr/include/xdp2/
    fi

    # Templates and data
    if [ -d ${xdp2}/share/xdp2 ]; then
      cp -rv ${xdp2}/share/xdp2/* $out/usr/share/xdp2/
    fi

    # Basic documentation
    echo "${metadata.description}" > $out/usr/share/doc/xdp2/README
  '';

in {
  inherit staging metadata;
}
```

**Validation:**
```bash
nix build .#deb-staging
ls -la result/usr/bin/
ls -la result/usr/lib/
```

---

#### Step 3: .deb Package Generation (`nix/packaging/deb.nix` continued)

Add FPM-based .deb creation.

```nix
# Add to nix/packaging/deb.nix

  # Generate .deb using FPM
  deb = pkgs.runCommand "xdp2-${metadata.version}-amd64.deb" {
    nativeBuildInputs = [ pkgs.fpm ];
  } ''
    mkdir -p $out

    fpm \
      --input-type dir \
      --output-type deb \
      --name "${metadata.name}" \
      --version "${metadata.version}" \
      --architecture "amd64" \
      --maintainer "${metadata.maintainer}" \
      --description "${metadata.description}" \
      --url "${metadata.homepage}" \
      --license "${metadata.license}" \
      ${lib.concatMapStringsSep " " (d: "--depends \"${d}\"") metadata.debDepends} \
      --chdir ${staging} \
      --package $out/${metadata.name}_${metadata.version}_amd64.deb \
      .

    echo "Package created:"
    ls -la $out/
  '';
```

**Validation:**
```bash
nix build .#deb-x86_64
dpkg-deb --info result/*.deb
dpkg-deb --contents result/*.deb
```

---

#### Step 4: Packaging Entry Point (`nix/packaging/default.nix`)

```nix
# nix/packaging/default.nix
{ pkgs, lib, xdp2 }:

let
  debPackaging = import ./deb.nix { inherit pkgs lib xdp2; };
in {
  # Phase 1: x86_64 .deb only
  deb.x86_64 = debPackaging.deb;

  # Expose staging for debugging
  staging.x86_64 = debPackaging.staging;

  # Metadata for other modules
  metadata = debPackaging.metadata;
}
```

---

#### Step 5: MicroVM Constants (`nix/microvms/constants.nix`)

Simplified constants for Phase 1.

```nix
# nix/microvms/constants.nix
#
# Phase 1: x86_64 only, stable kernel
#
{
  # Single architecture for Phase 1
  architectures = {
    x86_64 = {
      nixSystem = "x86_64-linux";
      qemuMachine = "pc";
      qemuCpu = "host";
      useKvm = true;
      serialPort = 5000;
      virtioPort = 5001;
      mem = 1024;
      vcpu = 2;
    };
  };

  # Single kernel for Phase 1
  kernel = "linuxPackages";  # stable

  # Timeouts (KVM is fast)
  timeouts = {
    boot = 60;
    command = 5;
  };
}
```

---

#### Step 6: MicroVM Definition (`nix/microvms/x86_64.nix`)

Single VM for x86_64 testing.

```nix
# nix/microvms/x86_64.nix
{ pkgs, lib, microvm, nixpkgs }:

let
  constants = import ./constants.nix;
  cfg = constants.architectures.x86_64;

in (nixpkgs.lib.nixosSystem {
  system = cfg.nixSystem;

  modules = [
    microvm.nixosModules.microvm

    ({ config, pkgs, ... }: {
      system.stateVersion = "26.05";
      networking.hostName = "xdp2-test-x86_64";

      # MicroVM configuration
      microvm = {
        hypervisor = "qemu";
        mem = cfg.mem;
        vcpu = cfg.vcpu;

        # Mount host Nix store for fast access
        shares = [{
          source = "/nix/store";
          mountPoint = "/nix/store";
          tag = "nix-store";
          proto = "9p";
        }];

        qemu.extraArgs = [
          "-enable-kvm"
          "-cpu" cfg.qemuCpu
        ];
      };

      # Kernel with BTF support
      boot.kernelPackages = pkgs.${constants.kernel};
      boot.kernelPatches = [{
        name = "btf-support";
        patch = null;
        extraConfig = ''
          DEBUG_INFO_BTF y
        '';
      }];

      # eBPF settings
      boot.kernel.sysctl = {
        "net.core.bpf_jit_enable" = 1;
      };

      # Auto-login for testing
      services.getty.autologinUser = "root";
      users.users.root.password = "";

      # Test tools
      environment.systemPackages = with pkgs; [
        config.boot.kernelPackages.bpftool
        iproute2
        tcpdump
      ];

      # Self-test service
      systemd.services.xdp2-self-test = {
        description = "XDP2 Self-Test";
        after = [ "multi-user.target" ];
        wantedBy = [ "multi-user.target" ];
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
        };
        script = ''
          echo "=== XDP2 MicroVM Self-Test ==="
          echo "Architecture: $(uname -m)"
          echo "Kernel: $(uname -r)"

          if [ -f /sys/kernel/btf/vmlinux ]; then
            echo "BTF: OK"
          else
            echo "BTF: MISSING"
            exit 1
          fi

          bpftool feature probe kernel | head -10
          echo "=== Self-Test Complete ==="
        '';
      };
    })
  ];
}).config.microvm.declaredRunner
```

---

#### Step 7: MicroVM Entry Point (`nix/microvms/default.nix`)

```nix
# nix/microvms/default.nix
{ pkgs, lib, microvm, nixpkgs }:

{
  # Phase 1: Single VM
  vms = {
    x86_64 = import ./x86_64.nix { inherit pkgs lib microvm nixpkgs; };
  };

  # Test runner (Phase 1: just runs x86_64)
  test-runner = pkgs.writeShellApplication {
    name = "xdp2-test-phase1";
    text = ''
      echo "=== XDP2 Phase 1 Test ==="
      echo "Testing x86_64 with stable kernel"

      VM_PATH=$(nix build .#microvm-x86_64 --print-out-paths --no-link)

      echo "Starting VM..."
      "$VM_PATH/bin/microvm-run" &
      VM_PID=$!

      # Wait for VM to complete self-test and shut down
      # (In Phase 1, we rely on the systemd service output)
      wait $VM_PID
      EXIT_CODE=$?

      if [ $EXIT_CODE -eq 0 ]; then
        echo "=== Test PASSED ==="
      else
        echo "=== Test FAILED (exit code: $EXIT_CODE) ==="
        exit 1
      fi
    '';
  };
}
```

---

#### Step 8: Flake Integration

Update `flake.nix` with Phase 1 outputs.

```nix
# Add to flake.nix outputs

# Phase 1 packaging (x86_64 .deb only)
packaging = import ./nix/packaging {
  inherit pkgs lib;
  xdp2 = xdp2;  # Use the existing xdp2 derivation
};

# Phase 1 MicroVM (x86_64 only, requires microvm input)
# microvms = import ./nix/microvms { inherit pkgs lib microvm nixpkgs; };

# ... in packages = { ... }

# Phase 1: Packaging
deb-staging = packaging.staging.x86_64;
deb-x86_64 = packaging.deb.x86_64;

# Phase 1: MicroVM (uncomment when microvm input added)
# microvm-x86_64 = microvms.vms.x86_64;
# xdp2-test-phase1 = microvms.test-runner;
```

---

## Validation Checklist

### Packaging Validation

```bash
# 1. Build staging directory
nix build .#deb-staging
ls -la result/usr/bin/        # Should have xdp2-compiler
ls -la result/usr/lib/        # Should have libraries
ls -la result/usr/include/    # Should have headers

# 2. Build .deb package
nix build .#deb-x86_64
ls -la result/                # Should have .deb file

# 3. Inspect package
dpkg-deb --info result/*.deb  # Check metadata
dpkg-deb --contents result/*.deb  # Check file list

# 4. Test installation (in Docker)
docker run --rm -v $(pwd)/result:/pkg debian:bookworm \
  bash -c "dpkg -i /pkg/*.deb && xdp2-compiler --version"
```

### MicroVM Validation

```bash
# 1. Build VM (requires microvm.nix input in flake)
nix build .#microvm-x86_64

# 2. Run VM manually
./result/bin/microvm-run

# 3. Check VM output for:
#    - "BTF: OK"
#    - bpftool feature output
#    - "Self-Test Complete"

# 4. Run automated test
nix run .#xdp2-test-phase1
```

---

## What We'll Learn

| Area | Questions to Answer |
|------|---------------------|
| **FPM** | Does FPM work reliably in Nix sandbox? Any permission issues? |
| **Dependencies** | Are the .deb runtime deps correct? Missing libraries? |
| **Staging** | Is the FHS layout correct for xdp2? Missing files? |
| **MicroVM** | Does virtio-9p store mounting work? Performance acceptable? |
| **BTF** | Does the kernel patch approach work? pahole available? |
| **Self-test** | Is the systemd oneshot pattern reliable? Exit code propagation? |

---

## Phase 1 → Phase 2 Transition

Once Phase 1 is validated, expand incrementally:

| Step | Addition | Validates |
|------|----------|-----------|
| 2a | Add .rpm generation | RPM tooling in Nix |
| 2b | Add aarch64 cross-compilation | Cross-compile basics |
| 2c | Add aarch64 MicroVM | QEMU emulation |
| 2d | Add riscv64 (priority target) | RISC-V toolchain |
| 2e | Add kernel matrix (stable + latest) | Kernel version switching |
| 2f | Add parallel execution | Resource management |

Each step builds on validated Phase 1 patterns.

---

## Implementation Order

1. **Create `nix/packaging/metadata.nix`** - Package info
2. **Create `nix/packaging/deb.nix`** - Staging + .deb generation
3. **Create `nix/packaging/default.nix`** - Entry point
4. **Update `flake.nix`** - Add packaging outputs
5. **Validate packaging** - Build and test .deb
6. **Add microvm input to flake** - Enable MicroVM support
7. **Create `nix/microvms/constants.nix`** - VM config
8. **Create `nix/microvms/x86_64.nix`** - VM definition
9. **Create `nix/microvms/default.nix`** - Entry point
10. **Update `flake.nix`** - Add MicroVM outputs
11. **Validate MicroVM** - Run VM and test

---

## Success Criteria

Phase 1 is complete when:

- [ ] `nix build .#deb-x86_64` produces a valid .deb
- [ ] .deb installs cleanly in Debian container
- [ ] `xdp2-compiler --help` works after installation
- [ ] `nix build .#microvm-x86_64` produces a bootable VM
- [ ] VM boots with BTF-enabled kernel
- [ ] `bpftool` works inside VM
- [ ] Self-test service reports success
- [ ] All code follows patterns from comprehensive design

---

## References

- [Comprehensive Design](./microvm-ebpf-test-design.md) - Full matrix design
- [XDP2 Nix Infrastructure](./xdp-samples-status.md) - Existing Nix setup
- [FPM Documentation](https://fpm.readthedocs.io/) - Package generation tool
- [microvm.nix](https://github.com/astro/microvm.nix) - NixOS MicroVM framework
