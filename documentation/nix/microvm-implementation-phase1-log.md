# MicroVM Implementation Phase 1 - Progress Log

**Started:** 2026-02-17
**Status:** IN PROGRESS

---

## References

- **Implementation Plan:** [microvm-implementation-phase1.md](./microvm-implementation-phase1.md)
- **Comprehensive Design:** [microvm-ebpf-test-design.md](./microvm-ebpf-test-design.md)

---

## Goal

Implement a single path through all features (x86_64 + .deb + stable kernel) to validate the design before expanding to the full matrix.

---

## Implementation Checklist

### Packaging (Steps 1-5)

- [x] Step 1: Create `nix/packaging/metadata.nix`
- [x] Step 2: Create `nix/packaging/deb.nix` (staging)
- [x] Step 3: Create `nix/packaging/deb.nix` (dpkg-deb generation) *(changed from FPM)*
- [x] Step 4: Create `nix/packaging/default.nix`
- [x] Step 5: Update `flake.nix` with packaging outputs
- [x] Step 5a: Validate staging: `nix build .#deb-staging`
- [x] Step 5b: Validate .deb: `nix build .#deb-x86_64`
- [x] Step 5c: Test installation in Docker *(partial - structure OK, portability issue identified)*

### MicroVM (Steps 6-11)

- [x] Step 6: Add microvm input to `flake.nix`
- [x] Step 7: Create `nix/microvms/constants.nix`
- [x] Step 8: Create `nix/microvms/x86_64.nix`
- [x] Step 9: Create `nix/microvms/default.nix`
- [x] Step 10: Update `flake.nix` with MicroVM outputs
- [x] Step 11a: Validate VM build: `nix build .#microvm-x86_64`
- [x] Step 11b: Validate VM boot and self-test

---

## Progress Log

### 2026-02-17 - Session Start

**Objective:** Begin Phase 1 implementation following the plan.

**Notes:**
- Target NixOS version: 26.05 (updated from 24.05 in plan)
- Starting with Step 1: Package metadata

---

#### Step 1: Create `nix/packaging/metadata.nix`

**Status:** COMPLETE

**File:** `nix/packaging/metadata.nix`

**Created:**
- Package name, version, maintainer
- Description, homepage, license
- Debian dependencies (with version alternatives for Boost)
- Architecture mapping table

**Validation:** `nix eval --impure --expr '(import ./nix/packaging/metadata.nix).name'` returned `"xdp2"`

---

#### Step 2: Create `nix/packaging/deb.nix` (staging)

**Status:** COMPLETE

**File:** `nix/packaging/deb.nix`

**Created:**
- Staging directory with FHS layout (`/usr/bin`, `/usr/lib`, `/usr/include`, `/usr/share`)
- Copies binaries, libraries, headers from xdp2 derivation
- Creates copyright and README documentation

**Validation:** `nix build .#deb-staging` succeeded
- Binaries: `xdp2-compiler` (11MB), `cppfront-compiler` (5MB)
- Libraries: 10 .so and 10 .a files
- Headers: Full include tree

---

#### Step 3: Add .deb generation to `nix/packaging/deb.nix`

**Status:** COMPLETE (with modification)

**Original plan:** Use FPM
**Actual:** Used dpkg-deb directly

**Why change:**
- FPM fails in Nix sandbox due to `lchown` permission errors
- Native `dpkg-deb` works perfectly in sandboxed builds

**Created:**
- Control file generation via `pkgs.writeText`
- md5sums generation
- dpkg-deb invocation with `--root-owner-group`

**Validation:** `nix build .#deb-x86_64` succeeded

---

#### Step 4: Create `nix/packaging/default.nix`

**Status:** COMPLETE

**File:** `nix/packaging/default.nix`

**Created:**
- Entry point importing deb.nix
- Exports: `deb.x86_64`, `staging.x86_64`, `metadata`, `archInfo`

---

#### Step 5: Update `flake.nix`

**Status:** COMPLETE

**Changes:**
- Added `packaging` import
- Added `deb-staging` output
- Added `deb-x86_64` output

---

## Issues Encountered

| Issue | Description | Resolution |
|-------|-------------|------------|
| FPM lchown | FPM fails in Nix sandbox with `lchown: Invalid argument` | Switch to native dpkg-deb |
| find pipe | `find \| head` causes exit code 141 (SIGPIPE) | Added `\|\| true` |
| Control newline | Debian control file requires final newline | Fixed heredoc formatting |
| Description format | Multi-line Description must use continuation syntax | Use ` .` for blank lines, space prefix for continuation |

---

## Lessons Learned

| Area | Lesson | Impact on Design |
|------|--------|------------------|
| FPM | FPM doesn't work in Nix sandbox (lchown fails) | **Update comprehensive design**: Remove FPM as primary approach, use dpkg-deb as primary, FPM as fallback for non-sandboxed environments |
| Control file | Debian control file has strict formatting requirements | Generate control file at Nix eval time using `writeText`, not shell heredocs |
| Staging | Staging directory pattern works well | Keep this pattern for all architectures |
| Broken pipe | Shell pipelines with `head` cause non-zero exit | Always add `\|\| true` for informational pipelines in builds |
| **Portability** | **Nix-built binaries are linked against Nix store paths** | **Critical**: Add "Binary Portability Strategy" section to comprehensive design. Options: static linking, bundled libs with patchelf, nix-bundle, or build in target distro container |

---

## Validation Results

### Packaging

| Test | Command | Result | Notes |
|------|---------|--------|-------|
| Build staging | `nix build .#deb-staging` | PASS | Contains binaries, libs, headers |
| Build .deb | `nix build .#deb-x86_64` | PASS | 2.1MB package |
| Inspect .deb | `dpkg-deb --info result/*.deb` | PASS | Metadata correct |
| Docker install | `docker run ... dpkg -i` | PARTIAL | Package installs but binary not portable (see below) |

#### Binary Portability Issue

**Finding:** The .deb package structure is correct, but the binaries are linked against Nix store paths:

```
libLLVM.so.18.1 => not found
libclang-cpp.so.18.1 => not found
libboost_wave.so.1.87.0 => not found
/nix/store/.../ld-linux-x86-64.so.2 (hardcoded interpreter)
```

**Impact:** Binaries built in Nix cannot run on standard Debian without bundling dependencies.

**Options for Phase 2:**
1. **Static linking** - Link LLVM/Clang statically (increases binary size significantly)
2. **Bundle libraries** - Include required .so files in `/usr/lib/xdp2/` and set RPATH
3. **nix-bundle / AppImage** - Create fully self-contained executables
4. **patchelf** - Rewrite interpreter and RPATH to use bundled libs
5. **Build in Docker** - Use Debian-based build environment instead of Nix

**For Phase 1:** Package structure validated. Portability is a Phase 2 enhancement.

**Recommendation:** Add to comprehensive design: "Binary Portability Strategy" section describing how to make Nix-built binaries work on target distributions.

---

### 2026-02-17 - MicroVM Implementation

#### Step 6: Add microvm input to `flake.nix`

**Status:** COMPLETE

**Changes:**
- Added microvm flake input with `nixpkgs.follows`
- Updated outputs function signature

#### Step 7: Create `nix/microvms/constants.nix`

**Status:** COMPLETE

**File:** `nix/microvms/constants.nix`

**Created:**
- x86_64 architecture configuration (KVM, ports 5000/5001)
- Kernel package setting (stable)
- Timeout configuration
- VM naming helpers

**Issues Fixed:**
- Nix scoping: `getHostname` function couldn't reference `vmNamePrefix` in same attrset
- Solution: Inline the prefix string

#### Step 8: Create `nix/microvms/x86_64.nix`

**Status:** COMPLETE

**File:** `nix/microvms/x86_64.nix`

**Created:**
- Full NixOS MicroVM definition
- QEMU configuration with KVM and dual consoles
- Kernel with BTF patch
- Self-test script using `writeShellApplication`
- Systemd service to run self-test on boot

**Issues Fixed:**
- `bpftool` package name: nixpkgs uses `bpftools` (plural), not `bpftool`
- Variable shadowing: Renamed local `bpftools` to avoid conflict with `with pkgs;`

#### Step 9: Create `nix/microvms/default.nix`

**Status:** COMPLETE

**File:** `nix/microvms/default.nix`

**Created:**
- Entry point importing VM definitions
- Test runner script using `writeShellApplication`
- Console connection helpers using `writeShellApplication`
- VM status checker using `writeShellApplication`

#### Step 10: Update `flake.nix` with MicroVM outputs

**Status:** COMPLETE

**Added outputs:**
- `microvm-x86_64` - VM derivation
- `xdp2-test-phase1` - Test runner
- `xdp2-vm-console` - Console connection
- `xdp2-vm-serial` - Serial connection
- `xdp2-vm-status` - Status checker

#### Step 11a: Validate VM build

**Status:** COMPLETE

**Command:** `nix build .#microvm-x86_64`

**Result:** `/nix/store/6smi4wxrjbkayr11bg0zglc76gk6k5g9-microvm-qemu-xdp2-test-x86_64`

**Key fix:** Removed unnecessary kernel patch for BTF. Default NixOS kernel already has `CONFIG_DEBUG_INFO_BTF=y`, so we use the cached kernel from nixpkgs instead of compiling.

**Added:** BTF availability check that fails with clear error if kernel lacks BTF support.

#### Step 11b: Validate VM boot and self-test

**Status:** COMPLETE

**Test output:**
```
[OK] Started XDP2 MicroVM Self-Test
[OK] Finished XDP2 MicroVM Self-Test
<<< Welcome to NixOS 25.11.20250921.554be64 (x86_64) - hvc0 >>>
xdp2-test-x8664 login: root (automatic login)
```

**Validated:**
- VM boots with KVM acceleration
- Virtio console available on port 5001
- Serial console available on port 5000
- Self-test service runs successfully
- Auto-login works

---

## Phase 1 Complete

**Summary:** Successfully implemented single-thread validation path:
- x86_64 architecture
- .deb package generation (using dpkg-deb)
- Stable kernel with BTF
- MicroVM boots and runs self-test

**Build times:**
- .deb package: ~2 minutes (compiles xdp2)
- MicroVM: ~30 seconds (uses cached kernel)

**Next:** Proceed to Phase 2 - add more architectures, .rpm, kernel matrix

### MicroVM

| Test | Command | Result | Notes |
|------|---------|--------|-------|
| Build VM | `nix build .#microvm-x86_64` | PENDING | |
| Boot VM | `./result/bin/microvm-run` | PENDING | |
| BTF check | Self-test output | PENDING | |
| bpftool | Self-test output | PENDING | |

---

---

### 2026-02-17 - VM Lifecycle Check Scripts

#### Added Network Interface for XDP Testing

**Status:** COMPLETE

**Changes to `nix/microvms/constants.nix`:**
- Added `xdpInterface = "eth0"` - the interface name inside VM for XDP attachment
- Added `tapConfig` for QEMU user networking configuration
- Added `getProcessName` helper for consistent VM process naming
- Added per-phase timeouts and `pollInterval` configuration

**Changes to `nix/microvms/x86_64.nix`:**
- Added network interface configuration (QEMU user networking)
- Self-test now checks for network interface availability

#### Lifecycle Check Scripts

**Status:** COMPLETE

Added individual lifecycle check scripts with polling loops:

| Phase | Script | Timeout | Purpose |
|-------|--------|---------|---------|
| 1 | `xdp2-lifecycle-1-check-process` | 5s | Poll for VM process in ps |
| 2 | `xdp2-lifecycle-2-check-serial` | 30s | Poll for serial console (ttyS0) |
| 2b | `xdp2-lifecycle-2b-check-virtio` | 45s | Poll for virtio console (hvc0) |
| 3 | `xdp2-lifecycle-3-verify-ebpf-loaded` | 60s | Poll for self-test service |
| 4 | `xdp2-lifecycle-4-verify-ebpf-running` | - | Check BTF, bpftool, interface |
| 5 | `xdp2-lifecycle-5-shutdown` | - | Send poweroff command |
| 6 | `xdp2-lifecycle-6-wait-exit` | 30s | Poll until process exits |
| - | `xdp2-lifecycle-force-kill` | - | pkill VM process (SIGTERM/SIGKILL) |
| - | `xdp2-lifecycle-full-test` | - | Run all phases in sequence |

**Design decisions:**
- All scripts use `writeShellApplication` for correctness
- Polling interval is 1 second (configurable in constants.nix)
- Each phase has its own timeout appropriate to the operation
- Scripts report progress during polling (`Polling... (X/Y s)`)
- VM process name (`xdp2-test-x86_64`) defined centrally for consistency

---

## Next Steps

After completing Phase 1:
1. Review lessons learned
2. Update comprehensive design if needed
3. Proceed to Phase 2a: Add .rpm generation
