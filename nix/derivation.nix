# nix/derivation.nix
#
# Package derivation for XDP2
#
# This module defines the actual XDP2 package using stdenv.mkDerivation.
# It enables `nix build` support and follows nixpkgs conventions.
#
# Build order:
# 1. Patch source files (postPatch)
# 2. Run configure script (configurePhase)
# 3. Build cppfront, xdp2-compiler, then xdp2 (buildPhase)
# 4. Install binaries and libraries (installPhase)
#
# Usage in flake.nix:
#   packages.default = import ./nix/derivation.nix {
#     inherit pkgs lib llvmConfig;
#     inherit (import ./nix/packages.nix { inherit pkgs llvmPackages; }) nativeBuildInputs buildInputs;
#   };
#

{ pkgs
, lib
, llvmConfig
, nativeBuildInputs
, buildInputs
  # Enable XDP2 assertions (for debugging/testing)
  # Default: false (production build, zero overhead)
, enableAsserts ? false
}:

let
  llvmPackages = llvmConfig.llvmPackages;

  # Wrapper scripts for HOST_CC/HOST_CXX that include Boost paths
  # The configure script calls these directly to test Boost availability
  host-gcc = pkgs.writeShellApplication {
    name = "host-gcc";
    runtimeInputs = [ pkgs.gcc ];
    text = ''
      exec gcc -I${pkgs.boost.dev}/include -L${pkgs.boost}/lib "$@"
    '';
  };

  host-gxx = pkgs.writeShellApplication {
    name = "host-g++";
    runtimeInputs = [ pkgs.gcc ];
    text = ''
      exec g++ -I${pkgs.boost.dev}/include -L${pkgs.boost}/lib "$@"
    '';
  };
in
pkgs.stdenv.mkDerivation rec {
  pname = if enableAsserts then "xdp2-debug" else "xdp2";
  version = "0.1.0";

  src = ./..;

  # Nix-specific patches for xdp2-compiler
  #
  # NOTE: Most Nix compatibility is now handled directly in the source code:
  # - System include paths: src/tools/compiler/src/clang-tool-config.cpp
  # - Null checks: src/tools/compiler/include/xdp2gen/ast-consumer/proto-tables.h
  # - Assertions: src/tools/compiler/include/xdp2gen/assert.h
  #
  # See documentation/nix/clang-tool-refactor-plan.md for details.
  patches = [
    # No patches currently required - fixes are in source code
  ];

  inherit nativeBuildInputs buildInputs;

  # Disable hardening flags that interfere with XDP/BPF code
  hardeningDisable = [ "all" ];

  # Set up environment variables for the build
  HOST_CC = "${pkgs.gcc}/bin/gcc";
  HOST_CXX = "${pkgs.gcc}/bin/g++";
  HOST_LLVM_CONFIG = "${llvmConfig.llvm-config-wrapped}/bin/llvm-config";
  XDP2_CLANG_VERSION = llvmConfig.version;
  XDP2_CLANG_RESOURCE_PATH = llvmConfig.paths.clangResourceDir;

  # Add LLVM/Clang libs to library path
  LD_LIBRARY_PATH = lib.makeLibraryPath [
    llvmPackages.llvm
    llvmPackages.libclang.lib
    pkgs.boost
  ];

  # Compiler flags - enable assertions for debug builds
  NIX_CFLAGS_COMPILE = lib.optionalString enableAsserts "-DXDP2_ENABLE_ASSERTS=1";

  # Post-patch phase: Fix paths and apply Nix-specific patches
  postPatch = ''
    # Fix cppfront Makefile to use source directory path
    substituteInPlace thirdparty/cppfront/Makefile \
      --replace-fail 'include ../../src/config.mk' '# config.mk not needed for standalone build'

    # Add functional header to cppfront (required for newer GCC)
    sed -i '1i#include <functional>\n#include <unordered_map>\n' thirdparty/cppfront/include/cpp2util.h
  '';

  # Configure phase: Generate config.mk
  configurePhase = ''
    runHook preConfigure

    cd src

    # Set up environment for configure using the Boost-aware wrapper scripts
    export CC="${host-gcc}/bin/host-gcc"
    export CXX="${host-gxx}/bin/host-g++"
    export HOST_CC="$CC"
    export HOST_CXX="$CXX"
    export HOST_LLVM_CONFIG="${llvmConfig.llvm-config-wrapped}/bin/llvm-config"

    # Set clang resource path BEFORE configure runs so it gets written to config.mk
    # This is critical for xdp2-compiler to find clang headers at runtime
    export XDP2_CLANG_VERSION="${llvmConfig.version}"
    export XDP2_CLANG_RESOURCE_PATH="${llvmConfig.paths.clangResourceDir}"
    export XDP2_C_INCLUDE_PATH="${llvmConfig.paths.clangResourceDir}/include"

    # Run configure script with debug output
    export CONFIGURE_DEBUG_LEVEL=7
    bash configure.sh --build-opt-parser

    # Fix PATH_ARG for Nix environment (remove hardcoded paths)
    if grep -q 'PATH_ARG="--with-path=' config.mk; then
      sed -i 's|PATH_ARG="--with-path=.*"|PATH_ARG=""|' config.mk
    fi

    cd ..

    runHook postConfigure
  '';

  # Build phase: Build all components in order
  buildPhase = ''
    runHook preBuild

    # Set up environment
    export HOST_CC="${pkgs.gcc}/bin/gcc"
    export HOST_CXX="${pkgs.gcc}/bin/g++"
    export HOST_LLVM_CONFIG="${llvmConfig.llvm-config-wrapped}/bin/llvm-config"
    export NIX_BUILD_CORES=$NIX_BUILD_CORES
    export XDP2_CLANG_VERSION="${llvmConfig.version}"
    export XDP2_CLANG_RESOURCE_PATH="${llvmConfig.paths.clangResourceDir}"

    # Include paths for xdp2-compiler's libclang usage
    # These are needed because ClangTool bypasses the Nix clang wrapper
    export XDP2_C_INCLUDE_PATH="${llvmConfig.paths.clangResourceDir}/include"
    export XDP2_GLIBC_INCLUDE_PATH="${pkgs.stdenv.cc.libc.dev}/include"
    export XDP2_LINUX_HEADERS_PATH="${pkgs.linuxHeaders}/include"

    # 1. Build cppfront compiler
    echo "Building cppfront..."
    cd thirdparty/cppfront
    $HOST_CXX -std=c++20 source/cppfront.cpp -o cppfront-compiler
    cd ../..

    # 2. Build xdp2-compiler
    echo "Building xdp2-compiler..."
    cd src/tools/compiler
    make -j$NIX_BUILD_CORES
    cd ../../..

    # 3. Build main xdp2 project
    echo "Building xdp2..."
    cd src

    # NOTE: parse_dump was previously skipped due to a std::optional assertion failure
    # in LLVM pattern matching. Fixed in main.cpp by adding null check for next_proto_data.
    # See documentation/nix/clang-tool-refactor-log.md for details.

    make -j$NIX_BUILD_CORES
    cd ..

    runHook postBuild
  '';

  # Install phase: Install binaries and libraries
  installPhase = ''
    runHook preInstall

    # Create output directories
    mkdir -p $out/bin
    mkdir -p $out/lib
    mkdir -p $out/include
    mkdir -p $out/share/xdp2

    # Install xdp2-compiler
    install -m 755 src/tools/compiler/xdp2-compiler $out/bin/

    # Install cppfront-compiler (useful for development)
    install -m 755 thirdparty/cppfront/cppfront-compiler $out/bin/

    # Install libraries (if any are built as shared)
    find src/lib -name "*.so" -exec install -m 755 {} $out/lib/ \; 2>/dev/null || true
    find src/lib -name "*.a" -exec install -m 644 {} $out/lib/ \; 2>/dev/null || true

    # Install headers (use -L to dereference symlinks like arch -> platform/...)
    cp -rL src/include/* $out/include/ 2>/dev/null || true

    # Install templates
    cp -r src/templates $out/share/xdp2/ 2>/dev/null || true

    runHook postInstall
  '';

  meta = with lib; {
    description = "XDP2 packet processing framework";
    longDescription = ''
      XDP2 is a high-performance packet processing framework that uses
      eBPF/XDP for fast packet handling in the Linux kernel.
    '';
    homepage = "https://github.com/xdp2/xdp2";
    license = licenses.mit;  # Update if different
    platforms = platforms.linux;
    maintainers = [ ];
  };
}
