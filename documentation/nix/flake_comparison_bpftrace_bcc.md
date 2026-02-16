# XDP2 flake.nix Comparison with bpftrace and bcc

This document compares how xdp2's `flake.nix` handles Clang/LLVM for eBPF compilation versus how the `bpftrace` and `bcc` packages in nixpkgs handle the same dependencies.

## Executive Summary

The xdp2 `flake.nix` takes a fundamentally different approach from both bpftrace and bcc. While both nixpkgs packages use `stdenv.mkDerivation` with cmake and proper Nix idioms, xdp2 currently only provides a development shell (`pkgs.mkShell`) that relies heavily on environment variables and a custom configure script. This leads to several integration issues.

**Key finding:** The flake.nix should be refactored to follow the patterns established by bpftrace and bcc for better Nix integration.

---

## Quick Reference: Package Structure

| Aspect | bpftrace | bcc | xdp2 (current) |
|--------|----------|-----|----------------|
| Derivation type | `stdenv.mkDerivation` | `python3Packages.buildPythonApplication` | `pkgs.mkShell` (dev shell only) |
| Build system | cmake | cmake | Custom configure.sh + make |
| LLVM reference | `llvmPackages` (parameter) | `llvmPackages` (parameter) | `pkgs.llvmPackages_20` (hardcoded) |
| Package output | Full package with `out`, `man` | Full package with `out`, `man` | No package, dev shell only |

---

## Detailed Comparison

### 1. LLVM/Clang Package References

#### bpftrace (package.nix lines 6, 35-45, 47-55)

```nix
{ llvmPackages, ... }:

buildInputs = with llvmPackages; [
  llvm
  libclang
  # ...
];

nativeBuildInputs = [
  llvmPackages.llvm.dev
  # ...
];
```

#### bcc (package.nix lines 13, 59-78)

```nix
{ llvmPackages, ... }:

nativeBuildInputs = [
  llvmPackages.llvm
  # ...
];

buildInputs = [
  llvmPackages.llvm
  llvmPackages.libclang
  # ...
];
```

#### xdp2 flake.nix (lines 43, 90-98, 115-126)

```nix
let
  llvmP = pkgs.llvmPackages_20;  # Hardcoded version
in
{
  corePackages = with pkgs; [
    llvmP.clang
    llvmP.llvm.dev
    llvmP.clang-unwrapped
    llvmP.libclang
    llvmP.lld
    # ...
  ];

  buildInputs = with pkgs; [
    llvmP.llvm
    llvmP.llvm.dev
    llvmP.clang-unwrapped
    llvmP.libclang
    llvmP.lld
  ];
}
```

**Differences:**
- bpftrace/bcc use `llvmPackages` as a function parameter, allowing version flexibility
- xdp2 hardcodes `llvmPackages_20`
- xdp2 includes many redundant LLVM packages (`clang`, `clang-unwrapped`, `libclang`, `llvm.dev`)
- bpftrace/bcc use cleaner `with llvmPackages; [...]` pattern

**Recommendation:** Use `llvmPackages` as a function parameter:

```nix
{
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      pkgs = nixpkgs.legacyPackages.x86_64-linux;
      # Use default llvmPackages, or allow override
      llvmPackages = pkgs.llvmPackages;
    in {
      # ...
    };
}
```

---

### 2. Build System Integration

#### bpftrace (cmake)

```nix
nativeBuildInputs = [
  cmake
  pkg-config
  flex
  bison
  # ...
];

cmakeFlags = [
  "-DLIBBCC_INCLUDE_DIRS=${bcc}/include"
  "-DUSE_SYSTEM_LIBBPF=ON"
  "-DSYSTEM_INCLUDE_PATHS=${glibc.dev}/include"
];
```

#### bcc (cmake)

```nix
nativeBuildInputs = [
  cmake
  flex
  bison
  # ...
];

cmakeFlags = [
  (lib.cmakeFeature "BCC_KERNEL_MODULES_DIR" "/run/booted-system/kernel-modules/lib/modules")
  (lib.cmakeFeature "REVISION" version)
  (lib.cmakeBool "ENABLE_USDT" true)
  (lib.cmakeBool "CMAKE_USE_LIBBPF_PACKAGE" true)
];
```

#### xdp2 (custom configure.sh + environment variables)

```nix
shellHook = ''
  export HOST_LLVM_CONFIG="${llvm-config-wrapped}/bin/llvm-config"
  export LLVM_LIBS="-L${llvmP.llvm}/lib"
  export CLANG_LIBS="-lclang -lLLVM -lclang-cpp"
  export LIBCLANG_PATH=${llvmP.libclang.lib}/lib
  # ... many more environment variables
'';
```

**Differences:**
- bpftrace/bcc use cmake with proper `cmakeFlags`
- xdp2 relies on a custom `configure.sh` script and extensive environment variables
- bpftrace/bcc paths are resolved at build time via Nix expressions
- xdp2 tries to resolve paths at shell-hook time via environment variables

**Recommendation:** Either:
1. Create a proper `stdenv.mkDerivation` that patches the configure script
2. Or convert the build system to cmake for better Nix integration

---

### 3. Path Resolution Patterns

#### bpftrace - Direct Nix store paths in cmake flags

```nix
cmakeFlags = [
  "-DLIBBCC_INCLUDE_DIRS=${bcc}/include"
  "-DSYSTEM_INCLUDE_PATHS=${glibc.dev}/include"
];
```

#### bcc - substituteInPlace for runtime path fixes

```nix
postPatch = ''
  substituteInPlace src/python/bcc/libbcc.py \
    --replace-fail "libbcc.so.0" "$out/lib/libbcc.so.0"
'';
```

#### xdp2 - Environment variables and wrapper scripts

```nix
llvm-config-wrapped = pkgs.runCommand "llvm-config-wrapped" { } ''
  mkdir -p $out/bin
  cat > $out/bin/llvm-config <<EOF
  #!${pkgs.bash}/bin/bash
  if [[ "\$1" == "--includedir" ]]; then
    echo "${llvmP.clang-unwrapped.dev}/include"
  # ...
  EOF
'';

sharedEnvVars = ''
  export HOST_LLVM_CONFIG="${llvm-config-wrapped}/bin/llvm-config"
'';
```

**Differences:**
- bpftrace uses cmake flags directly with Nix store paths
- bcc uses `substituteInPlace` to patch source files
- xdp2 creates wrapper scripts and relies on environment variables

**Recommendation:** Use `substituteInPlace` or cmake flags instead of wrapper scripts:

```nix
postPatch = ''
  substituteInPlace src/configure.sh \
    --replace '/usr/bin/llvm-config' '${llvmPackages.llvm.dev}/bin/llvm-config'
'';
```

---

### 4. Derivation vs Development Shell

#### bpftrace - Full derivation with outputs

```nix
stdenv.mkDerivation rec {
  pname = "bpftrace";
  version = "0.24.2";

  outputs = [ "out" "man" ];

  # ...
}
```

#### bcc - Full derivation with outputs

```nix
python3Packages.buildPythonApplication rec {
  pname = "bcc";
  version = "0.35.0";

  outputs = [ "out" "man" ];

  # ...
}
```

#### xdp2 - Development shell only

```nix
devShells.default = pkgs.mkShell {
  packages = sharedConfig.corePackages;
  shellHook = ''...'';
};
```

**Differences:**
- bpftrace/bcc are full packages that can be installed
- xdp2 only provides a development shell
- No `nix build` support for xdp2

**Recommendation:** Add a proper package derivation alongside the dev shell:

```nix
outputs = { self, nixpkgs, flake-utils }:
  flake-utils.lib.eachDefaultSystem (system:
    let
      pkgs = nixpkgs.legacyPackages.${system};
    in {
      packages.default = pkgs.stdenv.mkDerivation {
        pname = "xdp2";
        version = "0.1.0";
        # ... proper derivation
      };

      devShells.default = pkgs.mkShell {
        inputsFrom = [ self.packages.${system}.default ];
        # Additional dev tools
      };
    });
```

---

### 5. libbpf Integration

#### bpftrace

```nix
buildInputs = [
  libbpf
  # ...
];

cmakeFlags = [
  "-DUSE_SYSTEM_LIBBPF=ON"
];
```

#### bcc

```nix
buildInputs = [
  libbpf
  # ...
];

cmakeFlags = [
  (lib.cmakeBool "CMAKE_USE_LIBBPF_PACKAGE" true)
];
```

#### xdp2

```nix
corePackages = with pkgs; [
  libbpf
  # ...
];

buildInputs = with pkgs; [
  libbpf
  # ...
];
```

**Analysis:** All three include libbpf correctly. xdp2's approach is acceptable here.

---

### 6. Impure Operations

#### xdp2 uses builtins.getEnv (IMPURE)

```nix
nixDebug = let
  envDebug = builtins.getEnv "XDP2_NIX_DEBUG";
in
  if envDebug == "" then 0 else builtins.fromJSON envDebug;
```

**Problem:** `builtins.getEnv` makes the flake impure. Flakes are supposed to be hermetic and reproducible.

**Recommendation:** Remove `builtins.getEnv` and use a different debugging approach:

```nix
# Option 1: Use a flake config option
# nix develop .#debug

# Option 2: Pass via --override-input or similar
```

---

### 7. nativeBuildInputs vs buildInputs Usage

#### bpftrace - Correct separation

```nix
# Tools needed at build time
nativeBuildInputs = [
  cmake
  pkg-config
  flex
  bison
  llvmPackages.llvm.dev
];

# Libraries needed at build and runtime
buildInputs = with llvmPackages; [
  llvm
  libclang
  elfutils
  libbpf
];
```

#### bcc - Correct separation

```nix
nativeBuildInputs = [
  bison
  cmake
  flex
  llvmPackages.llvm  # Note: llvm is needed for build tools
];

buildInputs = [
  llvmPackages.llvm
  llvmPackages.libclang
  elfutils
  libbpf
];
```

#### xdp2 - Mixed usage

```nix
corePackages = with pkgs; [
  # Build tools mixed with libraries
  gnumake pkg-config bison flex
  boost libpcap libelf libbpf
  gcc llvmP.clang llvmP.llvm.dev
  gdb valgrind  # debugging tools
];

buildInputs = with pkgs; [
  boost libpcap libelf libbpf
  llvmP.llvm llvmP.llvm.dev  # Both llvm and llvm.dev
];

nativeBuildInputs = [
  pkgs.pkg-config
  llvmP.clang
  llvmP.llvm.dev
];
```

**Recommendation:** Properly separate build tools from libraries:

```nix
nativeBuildInputs = [
  cmake  # or: gnumake
  pkg-config
  bison
  flex
  llvmPackages.llvm.dev  # llvm-config and headers
];

buildInputs = [
  llvmPackages.llvm
  llvmPackages.libclang
  elfutils
  libbpf
  boost
  libpcap
];
```

---

## Summary of Recommendations

### High Priority

1. **Add stdenv.mkDerivation**: Create a proper package derivation, not just a dev shell
2. **Use llvmPackages parameter**: Don't hardcode `llvmPackages_20`
3. **Remove builtins.getEnv**: This makes the flake impure
4. **Use substituteInPlace**: Patch paths in source files instead of using wrapper scripts

### Medium Priority

5. **Clean up LLVM package references**: Only include what's actually needed
6. **Properly separate nativeBuildInputs and buildInputs**
7. **Consider cmake migration**: Would simplify Nix integration significantly
8. **Use inputsFrom pattern**: Dev shell should inherit from package derivation

### Low Priority

9. **Add passthru.tests**: Like bpftrace/bcc for NixOS integration testing
10. **Add multiple outputs**: Consider `out` and `man` outputs

---

## Example Refactored Structure

Here's a sketch of how the flake.nix could be restructured following bpftrace/bcc patterns:

```nix
{
  description = "XDP2 - High-performance packet processing";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        llvmPackages = pkgs.llvmPackages;  # Use default, allow override
      in {
        packages.default = pkgs.stdenv.mkDerivation {
          pname = "xdp2";
          version = "0.1.0";

          src = ./.;

          nativeBuildInputs = [
            pkgs.gnumake
            pkgs.pkg-config
            pkgs.bison
            pkgs.flex
            llvmPackages.llvm.dev
          ];

          buildInputs = [
            llvmPackages.llvm
            llvmPackages.libclang
            pkgs.elfutils
            pkgs.libbpf
            pkgs.boost
            pkgs.libpcap
          ];

          postPatch = ''
            # Patch configure script to use Nix paths
            substituteInPlace src/configure.sh \
              --replace '/usr/bin/llvm-config' '${llvmPackages.llvm.dev}/bin/llvm-config'
          '';

          configurePhase = ''
            cd src
            ./configure.sh --build-opt-parser --installdir $out
            cd ..
          '';

          buildPhase = ''
            make -C src -j$NIX_BUILD_CORES
          '';

          installPhase = ''
            make -C src install DESTDIR=$out
          '';

          meta = {
            description = "XDP2 packet processing framework";
            platforms = pkgs.lib.platforms.linux;
          };
        };

        devShells.default = pkgs.mkShell {
          inputsFrom = [ self.packages.${system}.default ];

          packages = [
            pkgs.gdb
            pkgs.valgrind
            pkgs.strace
          ];
        };
      });
}
```

---

## Modularization Strategy

The current `flake.nix` is over 1000 lines and difficult to maintain. This section describes how to split it into smaller, focused modules in a `./nix/` directory.

### Current Structure Analysis

The existing `flake.nix` contains these logical sections:

| Section | Lines | Description |
|---------|-------|-------------|
| Inputs & setup | 1-46 | Flake inputs, pkgs, llvmP definitions |
| sharedConfig | 49-127 | Package lists, compiler config, hardening |
| llvm-config-wrapped | 129-143 | Custom LLVM wrapper derivation |
| sharedEnvVars | 145-190 | Environment variable exports |
| smart-configure | 192-238 | Configure script helper |
| build-cppfront-fn | 240-343 | Cppfront build function |
| check-cppfront-age-fn | 345-405 | Cppfront age check |
| build-xdp2-compiler-fn | 407-500 | XDP2 compiler build |
| build-xdp2-fn | 502-568 | Main XDP2 build |
| build-all-fn | 570-597 | Combined build |
| clean-all-fn | 599-610 | Combined clean |
| shellcheck functions | 612-710 | Validation |
| Platform/locale functions | 718-776 | Environment setup |
| Navigation functions | 867-923 | Directory helpers |
| Clean functions | 925-1001 | Individual clean helpers |
| build-functions | 1003-1030 | Combined function string |
| devShell | 1033-1062 | Shell definition |

**Total: ~1065 lines** - far too large for a single file.

### Proposed Module Structure

```
xdp2/
├── flake.nix              # Minimal: inputs, outputs, imports
├── flake.lock
└── nix/
    ├── packages.nix       # Package lists (nativeBuildInputs, buildInputs)
    ├── llvm.nix           # LLVM/Clang configuration
    ├── env-vars.nix       # Environment variable definitions
    ├── shell-functions/   # Shell functions (split by category)
    │   ├── build.nix      # build-cppfront, build-xdp2-compiler, build-xdp2
    │   ├── clean.nix      # clean-cppfront, clean-xdp2-compiler, clean-xdp2
    │   ├── navigation.nix # navigate-to-repo-root, navigate-to-component
    │   ├── configure.nix  # smart-configure
    │   └── validation.nix # run-shellcheck, platform checks
    ├── devshell.nix       # Development shell configuration
    └── derivation.nix     # Package derivation (NEW)
```

### Module Responsibilities

#### `nix/packages.nix`
Defines all package dependencies in one place.

```nix
# nix/packages.nix
{ pkgs, llvmPackages }:

{
  # Build-time tools only
  nativeBuildInputs = [
    pkgs.gnumake
    pkgs.pkg-config
    pkgs.bison
    pkgs.flex
    llvmPackages.llvm.dev
  ];

  # Libraries needed at build and runtime
  buildInputs = [
    llvmPackages.llvm
    llvmPackages.libclang
    pkgs.elfutils
    pkgs.libbpf
    pkgs.boost
    pkgs.libpcap
    pkgs.libelf
  ];

  # Extra tools for development only
  devTools = [
    pkgs.gdb
    pkgs.valgrind
    pkgs.strace
    pkgs.ltrace
    pkgs.shellcheck
    pkgs.graphviz
  ];
}
```

#### `nix/llvm.nix`
Centralizes all LLVM/Clang configuration.

```nix
# nix/llvm.nix
{ pkgs, lib }:

let
  # Use default llvmPackages - can be overridden
  llvmPackages = pkgs.llvmPackages;
in
{
  inherit llvmPackages;

  # Environment variables for LLVM
  envVars = {
    XDP2_CLANG_VERSION = "${llvmPackages.llvm.dev}/bin/llvm-config --version";
    HOST_LLVM_CONFIG = "${llvmPackages.llvm.dev}/bin/llvm-config";
    LIBCLANG_PATH = "${llvmPackages.libclang.lib}/lib";
  };

  # Paths for substituteInPlace
  paths = {
    llvmConfig = "${llvmPackages.llvm.dev}/bin/llvm-config";
    clangInclude = "${llvmPackages.libclang.dev}/include";
    llvmLib = "${llvmPackages.llvm.lib}/lib";
  };
}
```

#### `nix/env-vars.nix`
All environment variable definitions.

```nix
# nix/env-vars.nix
{ pkgs, llvmConfig, packages }:

''
  # Compiler settings
  export CC=${pkgs.gcc}/bin/gcc
  export CXX=${pkgs.gcc}/bin/g++
  export HOST_CC=${pkgs.gcc}/bin/gcc
  export HOST_CXX=${pkgs.gcc}/bin/g++

  # LLVM/Clang settings
  export HOST_LLVM_CONFIG="${llvmConfig.paths.llvmConfig}"
  export LIBCLANG_PATH="${llvmConfig.envVars.LIBCLANG_PATH}"

  # Build configuration
  export PKG_CONFIG_PATH=${pkgs.lib.makeSearchPath "lib/pkgconfig" packages.buildInputs}
''
```

#### `nix/shell-functions/build.nix`
Build-related shell functions.

```nix
# nix/shell-functions/build.nix
{ }:

''
  build-cppfront() {
    echo "Building cppfront-compiler..."
    navigate-to-repo-root || return 1
    clean-cppfront
    navigate-to-component "thirdparty/cppfront" || return 1

    # Apply header fix
    sed -i '1i#include <functional>\n#include <unordered_map>\n' include/cpp2util.h

    if HOST_CXX="$CXX" HOST_CC="$CC" make -j"$NIX_BUILD_CORES"; then
      echo "cppfront make completed successfully"
    else
      echo "ERROR: cppfront make failed"
      return 1
    fi

    navigate-to-repo-root || return 1
    add-to-path "$PWD/thirdparty/cppfront"
  }

  build-xdp2-compiler() {
    # ... similar structure
  }

  build-xdp2() {
    # ... similar structure
  }

  build-all() {
    echo "Building all XDP2 components..."
    build-cppfront && build-xdp2-compiler && build-xdp2
    echo "All components built successfully"
  }
''
```

#### `nix/devshell.nix`
Development shell configuration.

```nix
# nix/devshell.nix
{ pkgs, packages, envVars, shellFunctions }:

pkgs.mkShell {
  packages = packages.nativeBuildInputs
           ++ packages.buildInputs
           ++ packages.devTools;

  shellHook = ''
    ${envVars}
    ${shellFunctions}

    echo "XDP2 Development Shell"
    echo "Run 'xdp2-help' for available commands"
  '';
}
```

#### `nix/derivation.nix`
The actual package derivation (NEW).

```nix
# nix/derivation.nix
{ pkgs, lib, llvmPackages, packages }:

pkgs.stdenv.mkDerivation {
  pname = "xdp2";
  version = "0.1.0";

  src = ./..;

  inherit (packages) nativeBuildInputs buildInputs;

  postPatch = ''
    # Patch hardcoded paths
    substituteInPlace src/configure.sh \
      --replace '/usr/bin/llvm-config' '${llvmPackages.llvm.dev}/bin/llvm-config'
  '';

  configurePhase = ''
    cd src
    ./configure.sh --build-opt-parser --installdir $out
    cd ..
  '';

  buildPhase = ''
    # Build cppfront first
    make -C thirdparty/cppfront -j$NIX_BUILD_CORES

    # Build xdp2-compiler
    make -C src/tools/compiler -j$NIX_BUILD_CORES

    # Build main project
    make -C src -j$NIX_BUILD_CORES
  '';

  installPhase = ''
    make -C src install DESTDIR=$out
  '';

  meta = {
    description = "XDP2 packet processing framework";
    platforms = lib.platforms.linux;
  };
}
```

### Refactored flake.nix

After modularization, `flake.nix` becomes minimal:

```nix
# flake.nix - Minimal after modularization
{
  description = "XDP2 - High-performance packet processing";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        lib = nixpkgs.lib;

        # Import modules
        llvmConfig = import ./nix/llvm.nix { inherit pkgs lib; };
        packages = import ./nix/packages.nix {
          inherit pkgs;
          inherit (llvmConfig) llvmPackages;
        };
        envVars = import ./nix/env-vars.nix {
          inherit pkgs packages;
          inherit llvmConfig;
        };

        # Import shell functions
        shellFunctions = builtins.concatStringsSep "\n" [
          (import ./nix/shell-functions/navigation.nix { })
          (import ./nix/shell-functions/clean.nix { })
          (import ./nix/shell-functions/build.nix { })
          (import ./nix/shell-functions/configure.nix { inherit pkgs; })
          (import ./nix/shell-functions/validation.nix { inherit pkgs; })
        ];

      in {
        packages.default = import ./nix/derivation.nix {
          inherit pkgs lib packages;
          inherit (llvmConfig) llvmPackages;
        };

        devShells.default = import ./nix/devshell.nix {
          inherit pkgs packages envVars shellFunctions;
        };

        # Debug shell with extra verbosity
        devShells.debug = import ./nix/devshell.nix {
          inherit pkgs packages shellFunctions;
          envVars = envVars + ''
            export XDP2_NIX_DEBUG=7
          '';
        };
      });
}
```

### Benefits of Modularization

| Benefit | Description |
|---------|-------------|
| **Readability** | Each file has a single responsibility |
| **Maintainability** | Changes isolated to relevant modules |
| **Testability** | Modules can be tested independently |
| **Reusability** | Modules can be shared across projects |
| **Code review** | Smaller files are easier to review |
| **Documentation** | Each module can have focused docs |

---

## Phased Implementation Plan

This section provides a detailed, incremental approach to refactoring the flake.nix.

### Phase 0: Preparation (Prerequisites)

**Goal:** Set up the module structure without breaking existing functionality.

**Tasks:**
1. Create `./nix/` directory
2. Create placeholder files for each module
3. Document the current working state (if any)
4. Set up a test environment

**Deliverables:**
```bash
mkdir -p nix/shell-functions
touch nix/{packages,llvm,env-vars,devshell,derivation}.nix
touch nix/shell-functions/{build,clean,navigation,configure,validation}.nix
```

**Validation:**
- `nix flake check` still passes (or fails the same way)
- No functional changes yet

---

### Phase 1: Extract Package Definitions

**Goal:** Move package lists to `nix/packages.nix`.

**Changes:**
1. Create `nix/packages.nix` with package definitions
2. Update `flake.nix` to import packages
3. Remove package definitions from `flake.nix`

**Before (flake.nix lines 74-127):**
```nix
corePackages = with pkgs; [
  gnumake pkg-config bison flex
  # ... 30+ packages
];
buildInputs = with pkgs; [ ... ];
nativeBuildInputs = [ ... ];
```

**After (nix/packages.nix):**
```nix
{ pkgs, llvmPackages }:
{
  nativeBuildInputs = [ ... ];
  buildInputs = [ ... ];
  devTools = [ ... ];
}
```

**After (flake.nix):**
```nix
packages = import ./nix/packages.nix {
  inherit pkgs;
  llvmPackages = pkgs.llvmPackages;
};
```

**Validation:**
- `nix develop` enters shell with same packages
- Package versions unchanged

**Estimated complexity:** Low

---

### Phase 2: Extract LLVM Configuration

**Goal:** Centralize all LLVM/Clang configuration in `nix/llvm.nix`.

**Changes:**
1. Create `nix/llvm.nix` with LLVM configuration
2. Remove `llvmP` hardcoding from `flake.nix`
3. Remove `llvm-config-wrapped` from `flake.nix`
4. Update imports in `flake.nix`

**Key improvements:**
- Replace hardcoded `llvmPackages_20` with `llvmPackages` parameter
- Remove custom wrapper script (use `substituteInPlace` later)
- Centralize LLVM paths for reuse

**Validation:**
- LLVM tools accessible in dev shell
- `llvm-config --version` returns expected version

**Estimated complexity:** Medium (wrapper removal may cause issues)

---

### Phase 3: Extract Environment Variables

**Goal:** Move environment variable definitions to `nix/env-vars.nix`.

**Changes:**
1. Create `nix/env-vars.nix`
2. Move `sharedEnvVars` content to new file
3. Update `flake.nix` to import and use

**Before (flake.nix lines 145-190):**
```nix
sharedEnvVars = ''
  export CC=...
  export HOST_LLVM_CONFIG=...
  # ... many exports
'';
```

**After (nix/env-vars.nix):**
```nix
{ pkgs, llvmConfig, packages }:
''
  export CC=${pkgs.gcc}/bin/gcc
  # ... structured exports
''
```

**Validation:**
- All environment variables set correctly
- `echo $HOST_LLVM_CONFIG` shows correct path

**Estimated complexity:** Low

---

### Phase 4: Extract Shell Functions (Incremental)

**Goal:** Move shell functions to `nix/shell-functions/` directory.

This phase is split into sub-phases to minimize risk.

#### Phase 4a: Navigation Functions

Move to `nix/shell-functions/navigation.nix`:
- `navigate-to-repo-root`
- `navigate-to-component`
- `add-to-path`
- `detect-repository-root`

#### Phase 4b: Clean Functions

Move to `nix/shell-functions/clean.nix`:
- `clean-cppfront`
- `clean-xdp2-compiler`
- `clean-xdp2`
- `clean-all`

#### Phase 4c: Build Functions

Move to `nix/shell-functions/build.nix`:
- `build-cppfront`
- `check-cppfront-age`
- `build-xdp2-compiler`
- `build-xdp2`
- `build-all`

#### Phase 4d: Configure Functions

Move to `nix/shell-functions/configure.nix`:
- `smart-configure`

#### Phase 4e: Validation Functions

Move to `nix/shell-functions/validation.nix`:
- `run-shellcheck`
- `check-platform-compatibility`
- `setup-locale-support`
- `xdp2-help`

**Validation (after each sub-phase):**
- Run each function manually
- Verify function dependencies work

**Estimated complexity:** Medium-High (function interdependencies)

---

### Phase 5: Create Development Shell Module

**Goal:** Move devShell configuration to `nix/devshell.nix`.

**Changes:**
1. Create `nix/devshell.nix`
2. Move shell configuration from `flake.nix`
3. Add debug shell variant

**After (nix/devshell.nix):**
```nix
{ pkgs, packages, envVars, shellFunctions }:

pkgs.mkShell {
  packages = packages.nativeBuildInputs
           ++ packages.buildInputs
           ++ packages.devTools;

  shellHook = ''
    ${envVars}
    ${shellFunctions}
    echo "XDP2 Development Shell Ready"
  '';
}
```

**Validation:**
- `nix develop` works as before
- All shell functions available

**Estimated complexity:** Low

---

### Phase 6: Create Package Derivation (NEW)

**Goal:** Add proper `stdenv.mkDerivation` for `nix build` support.

**Changes:**
1. Create `nix/derivation.nix`
2. Add `postPatch` to fix hardcoded paths
3. Implement proper build phases
4. Add to flake outputs

**Key tasks:**
- Patch `configure.sh` to use Nix paths
- Build cppfront, xdp2-compiler, xdp2 in correct order
- Create proper install phase

**After (nix/derivation.nix):**
```nix
{ pkgs, lib, llvmPackages, packages }:

pkgs.stdenv.mkDerivation {
  pname = "xdp2";
  version = "0.1.0";
  src = ./..;

  inherit (packages) nativeBuildInputs buildInputs;

  postPatch = ''
    substituteInPlace src/configure.sh \
      --replace '/usr/bin/llvm-config' \
                '${llvmPackages.llvm.dev}/bin/llvm-config'
  '';

  # ... build phases
}
```

**Validation:**
- `nix build` produces output
- Built binaries work correctly
- `nix develop` still works via `inputsFrom`

**Estimated complexity:** High (new functionality)

---

### Phase 7: Remove Impurities

**Goal:** Make the flake fully pure/reproducible.

**Changes:**
1. Remove `builtins.getEnv` usage
2. Add debug shell as separate output
3. Remove any other impure operations

**Before:**
```nix
nixDebug = let
  envDebug = builtins.getEnv "XDP2_NIX_DEBUG";
in
  if envDebug == "" then 0 else builtins.fromJSON envDebug;
```

**After:**
```nix
# In flake.nix outputs:
devShells.default = import ./nix/devshell.nix { debug = false; ... };
devShells.debug = import ./nix/devshell.nix { debug = true; ... };
```

**Usage:**
```bash
nix develop        # Normal shell
nix develop .#debug  # Debug shell with XDP2_NIX_DEBUG=7
```

**Validation:**
- `nix flake check` passes with `--pure-eval`
- Both shell variants work correctly

**Estimated complexity:** Medium

---

### Phase 8: Cleanup and Documentation

**Goal:** Final cleanup and documentation updates.

**Tasks:**
1. Remove unused code from `flake.nix`
2. Update `documentation/nix/nix.md`
3. Add module-level documentation
4. Update README with new commands
5. Add `nix flake check` to CI (if applicable)

**Documentation updates:**
- How to use `nix build`
- How to use debug shell
- Module structure explanation
- Contributing guidelines for Nix code

**Estimated complexity:** Low

---

### Implementation Timeline

| Phase | Description | Complexity | Dependencies |
|-------|-------------|------------|--------------|
| 0 | Preparation | Low | None |
| 1 | Extract packages | Low | Phase 0 |
| 2 | Extract LLVM config | Medium | Phase 1 |
| 3 | Extract env vars | Low | Phase 2 |
| 4a-e | Extract shell functions | Medium-High | Phase 3 |
| 5 | Create devshell module | Low | Phase 4 |
| 6 | Create package derivation | High | Phase 5 |
| 7 | Remove impurities | Medium | Phase 6 |
| 8 | Cleanup & docs | Low | Phase 7 |

### Risk Mitigation

1. **Version control:** Commit after each successful phase
2. **Testing:** Run `nix develop` and test functions after each change
3. **Rollback plan:** Keep backup of original `flake.nix`
4. **Incremental:** Each phase should be deployable independently
5. **Documentation:** Update docs as changes are made

---

## References

- bpftrace package: `/home/das/Downloads/nixpkgs/pkgs/by-name/bp/bpftrace/package.nix`
- bcc package: `/home/das/Downloads/nixpkgs/pkgs/by-name/bc/bcc/package.nix`
- xdp2 flake.nix: `/home/das/Downloads/xdp2/flake.nix`
- Nix manual on derivations: https://nixos.org/manual/nix/stable/language/derivations
- nixpkgs manual on stdenv: https://nixos.org/manual/nixpkgs/stable/#chap-stdenv
- Nix flakes: https://nixos.wiki/wiki/Flakes
