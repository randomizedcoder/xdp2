# Nix challenges

## Introduction

This document describes how to use nix to develop for this project.

This should make xdp2 very easy to get started with on many systems.


## Summary of xdp2's toolchain and libary requirements

Based on the `README.md`, `configure` script, and various Makefiles, the `xdp2` project has the following dependencies:

### Build-time Tools
These tools are required to configure and build the project from source.

*   **Core Build System**: `make`, `pkg-config`
*   **C/C++ Compilers**: A standard C/C++ toolchain (`build-essential` on Debian). The project specifically uses both `gcc` and `clang`/`llvm`.
*   **Parser Generators**: `bison` and `flex` are used for generating parser code.
*   **Scripting & Utilities**: `bash`, `sed`, `awk`, `install`, `cat`, `tar`, `xz` for scripting and file manipulation.
*   **Version Control**: `git` is needed for versioning information.
*   **Python**: `python3` is used for packet generation scripts.

### Libraries
These libraries need to be available for linking.

*   **Boost**: A significant dependency, used heavily in the `xdp2-compiler`. The required components include `program_options`, `graph`, `wave`, `thread`, `filesystem`, and `system`.
*   **LLVM & Clang**: The `xdp2-compiler` links against LLVM and Clang libraries for AST parsing and code generation.
*   **libpcap**: Used for packet capture in test utilities like `parse_dump`.
*   **libelf**: Required for processing ELF files, particularly for BPF-related tasks.
*   **libbpf**: Essential for interacting with the Linux kernel's BPF subsystem, used in the XDP samples.

### Optional Tools

*   **Graphviz**: Needed to generate visual graphs of the parser structure from `.dot` files.
*   **bpftool**: Part of `linux-tools`, used for inspecting and managing BPF programs and maps after they are loaded.


## Mapping of toolchain and library requirements to Nix packages (nixpkgs)

Here is a detailed mapping of the identified requirements to their corresponding packages in the Nixpkgs collection. This mapping is crucial for creating a reproducible `flake.nix` development environment.

### Core Build Tools

| Requirement | Nix Package(s) | Purpose |
|---|---|---|
| `build-essential` | `stdenv.cc` | Provides the standard C/C++ compiler toolchain (GCC). |
| `make` | `gnumake` | The build automation tool. |
| `pkg-config` | `pkg-config` | Manages library compile/link flags. |
| `bison` | `bison` | The GNU parser generator. |
| `flex` | `flex` | A tool for generating lexical analyzers. |

### Compilers (Dual Toolchain)

| Requirement | Nix Package(s) | Purpose |
|---|---|---|
| GCC Toolchain | `gcc` | The primary compiler for most libraries and applications. |
| Clang/LLVM Toolchain | `llvmPackages.clang`, `llvmPackages.llvm`, `llvmPackages.llvm.dev` | Used to build the `xdp2-compiler` and for BPF code generation. `llvm.dev` provides `llvm-config`. |

### Libraries

| Requirement | Nix Package(s) | Purpose |
|---|---|---|
| `libboost-all-dev` | `boost` | Provides all required Boost C++ libraries. |
| `libpcap-dev` | `libpcap` | Packet capture library. |
| `libelf-dev` | `libelf` | Library for working with ELF files. |
| `libbpf-dev` | `libbpf` | Core library for BPF applications. |

### Utilities and Runtimes

| Requirement | Nix Package(s) | Purpose |
|---|---|---|
| `bash`, `sh` | `bash` | The shell used to run configure scripts. |
| `sed`, `awk`, `install`, `cat` | `gnused`, `gawk`, `coreutils` | Standard GNU text and file utilities. |
| `python3` | `python3` | Python interpreter for helper scripts. |
| `graphviz` | `graphviz` | For optional parser graph visualization. |
| `linux-tools-*` | `linuxPackages.bpftool` | For inspecting loaded BPF programs and maps. |


## Proposed changes to flake.nix



## Proposed changes to flake.nix

Based on the dual-compiler requirement, the current `flake.nix` needs to be updated. It is currently configured to *only* use Clang/LLVM from `llvmPackages_19`, but the project requires both GCC for the main build and Clang for the `xdp2-compiler`.

The following changes will create a more robust and correct build environment:

1.  **Use the standard `stdenv`**: The derivation should use the default `pkgs.stdenv`, which is based on GCC. This aligns with the `xdp2` project's default compiler choice.
2.  **Add GCC to `devPackages`**: The development shell needs access to the GCC toolchain.
3.  **Add Clang/LLVM to `nativeBuildInputs`**: The build derivation needs the Clang/LLVM toolchain available to build the `xdp2-compiler`.
4.  **Set `HOST_CXX` to `clang++`**: The `configure` script uses the `HOST_CXX` variable to build host-side tools like the `xdp2-compiler`. We will set this to `clang++` to ensure the compiler is built with the correct toolchain.
5.  **Set `HOST_LLVM_CONFIG`**: The `configure` script needs this variable to find the correct `llvm-config` for the Clang toolchain.

Here is the suggested `flake.nix` incorporating these changes:

```nix
{
  description = "XDP2 development environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        llvmP = pkgs.llvmPackages_19;

        devPackages = with pkgs; [
          # Build tools
          gnumake pkg-config bison flex
          # Core utilities
          bash coreutils gnused gawk gnutar xz git
          # Libraries
          boost libpcap libelf libbpf python3
          # Development tools
          graphviz bpftools
          # Compilers for the dual-toolchain environment
          gcc llvmP.clang llvmP.llvm.dev
        ];

        xdp2-build = pkgs.stdenv.mkDerivation {
          pname = "xdp2-build";
          version = "dev";
          src = ./.;

          nativeBuildInputs = [
            pkg-config
            llvmP.clang # For HOST_CXX
            llvmP.llvm.dev # For llvm-config
          ];

          buildInputs = with pkgs; [
            boost libpcap libelf libbpf zlib ncurses python3
          ];

          # Ensure configure uses the right compilers for the right jobs
          configurePhase = ''
            export HOST_CXX=clang++
            export HOST_LLVM_CONFIG=${llvmP.llvm.dev}/bin/llvm-config
            ./configure --build-opt-parser --installdir "$out"
          '';

          buildPhase = "make";
          installPhase = "make install";
        };
      in
      {
        devShells.default = pkgs.mkShell {
          packages = devPackages;

          shellHook = ''
            export XDP2DIR=${xdp2-build}
            export BUILD_OPT_PARSER=y
            export PYTHON_VER=3
            export PKG_CONFIG_PATH=${pkgs.lib.makeSearchPath "lib/pkgconfig" devPackages}

            echo "=== XDP2 Development Shell ==="
            echo "GCC and Clang are available in the environment."
            echo "Run 'make' in 'src/' to build the project."
          '';
        };
      });
}
```


