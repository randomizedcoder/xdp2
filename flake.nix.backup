#
# flake.nix for XDP2
#
# This flake.nix is used to develop the XDP2 project
#
# To enter the development environment:
# nix develop
#
# If flakes are not enabled, use the following command to enter the development environment:
# nix --extra-experimental-features 'nix-command flakes' develop .
#
# To enable flakes, you may need to enable them in your system configuration:
# test -d /etc/nix || sudo mkdir /etc/nix
# echo 'experimental-features = nix-command flakes' | sudo tee -a /etc/nix/nix.conf
#
# Debugging:
# XDP2_NIX_DEBUG=7 nix develop --verbose --print-build-logs
# nix develop --option eval-cache false
#
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
        lib = nixpkgs.lib;
        llvmP = pkgs.llvmPackages_20;  #pkgs.llvmPackages_21 is available

        # Create a Python environment with scapy included.
        # This is the idiomatic Nix way to handle Python dependencies.
        pythonWithScapy = pkgs.python3.withPackages (ps: [ ps.scapy ]);

        sharedConfig = let
          useClang = builtins.getEnv "XDP2_USE_CLANG" == "true";
          useGCC = !useClang;
        in {
          # Debug configuration
          nixDebug = let
            envDebug = builtins.getEnv "XDP2_NIX_DEBUG";
          in
            if envDebug == "" then 0 else builtins.fromJSON envDebug;

          # Compiler selection
          inherit useClang useGCC;

          selectedCCPkgs = if useGCC then pkgs.gcc else pkgs.clang;
          selectedCXXPkgs = if useGCC then pkgs.gcc else pkgs.clang;
          selectedCCBin = if useGCC then "gcc" else "clang";
          selectedCXXBin = if useGCC then "g++" else "clang++";
          compilerInfo = if useGCC then "GCC" else "Clang";

          # https://nixos.wiki/wiki/C#Hardening_flags
          # hardeningDisable = [ "fortify" "fortify3" "stackprotector" "strictoverflow" ];
          # Disable all hardening flags for now, but might restore some later
          hardeningDisable = [ "all" ];

          # Library packages
          corePackages = with pkgs; [
            # Build tools
            gnumake pkg-config bison flex
            # Core utilities
            bash coreutils gnused gawk gnutar xz git
            # Libraries
              boost # boost189 is available and solves the deprecation warnings, but configure can't find it
            libpcap
            libelf
            libbpf
            pythonWithScapy
            # Development tools
            graphviz
            bpftools
            # Compilers for the dual-toolchain environment
            gcc # https://search.nixos.org/packages?channel=unstable&query=gcc gcc15 is available
            llvmP.clang llvmP.llvm.dev llvmP.clang-unwrapped
            # Debugging tools for linking analysis
            glibc_multi.bin # Provides ldd for dynamic library inspection
              # Debugging
            gdb # GNU Debugger for core dump analysis
            valgrind # Memory debugging and profiling
            strace # System call tracer
            ltrace # Library call tracer
            # REMOVED: cppfront - we build cppfront v0.3.0 from source in preBuild
          ];

          buildInputs = with pkgs; [
            boost
            libpcap
            libelf
            libbpf
            pythonWithScapy
            llvmP.llvm llvmP.clang-unwrapped
            llvmP.libclang
            llvmP.lld
          ];

          nativeBuildInputs = [
            pkgs.pkg-config
            llvmP.clang
            llvmP.llvm.dev # For llvm-config
          ];
        };

        # Create a wrapper for llvm-config to include clang paths.
        # The xdp2-compiler needs clang headers/libs, but the default llvm-config
        # from the llvm package only knows about llvm paths.
        llvm-config-wrapped = pkgs.runCommand "llvm-config-wrapped" { } ''
          mkdir -p $out/bin
          cat > $out/bin/llvm-config <<EOF
          #!${pkgs.bash}/bin/bash
          if [[ "\$1" == "--includedir" ]]; then
            echo "${llvmP.clang-unwrapped.dev}/include"
          elif [[ "\$1" == "--libdir" ]]; then
            echo "${lib.getLib llvmP.clang-unwrapped}/lib"
          else
            ${llvmP.llvm.dev}/bin/llvm-config "\$@"
          fi
          EOF
          chmod +x $out/bin/llvm-config
        '';

        sharedEnvVars = ''
          # Compiler settings
          export CC=${sharedConfig.selectedCCPkgs}/bin/${sharedConfig.selectedCCBin}
          export CXX=${sharedConfig.selectedCXXPkgs}/bin/${sharedConfig.selectedCXXBin}
          export HOST_CC=${sharedConfig.selectedCCPkgs}/bin/${sharedConfig.selectedCCBin}
          export HOST_CXX=${sharedConfig.selectedCXXPkgs}/bin/${sharedConfig.selectedCXXBin}

          # Clang environment variables for xdp2-compiler (using clang dev package)
          # ./src/tools/compiler/src/main.cpp and Makefile reference these variables
          export XDP2_CLANG_VERSION="$(${llvmP.llvm.dev}/bin/llvm-config --version)"
          export XDP2_C_INCLUDE_PATH="${llvmP.clang-unwrapped.dev}/include/clang"
          export XDP2_CLANG_RESOURCE_PATH="${llvmP.clang-unwrapped.dev}/include/clang"

          # Python environment
          export CFLAGS_PYTHON="$(pkg-config --cflags python3-embed)"
          export LDFLAGS_PYTHON="$(pkg-config --libs python3-embed)"
          export PYTHON_VER=3
          export PYTHONPATH="${pkgs.python3}/lib/python3.13/site-packages:$PYTHONPATH"

          # LLVM/Clang settings
          export HOST_LLVM_CONFIG="${llvm-config-wrapped}/bin/llvm-config"
          export LLVM_LIBS="-L${llvmP.llvm}/lib"
          export CLANG_LIBS="-lclang -lLLVM -lclang-cpp"

          # libclang configuration
          #export LIBCLANG_PATH="${lib.getLib llvmP.clang-unwrapped}/lib"
          export LIBCLANG_PATH=${llvmP.libclang.lib}/lib
          export LD_LIBRARY_PATH=${llvmP.libclang.lib}/lib:$LD_LIBRARY_PATH

          # Boost libraries
          export BOOST_LIBS="-lboost_wave -lboost_thread -lboost_filesystem -lboost_system -lboost_program_options"

          # Other libraries
          export LIBS="-lpthread -ldl -lutil"
          export PATH_ARG=""

          # Build configuration
          export PKG_CONFIG_PATH=${pkgs.lib.makeSearchPath "lib/pkgconfig" sharedConfig.corePackages}
          export XDP2_COMPILER_DEBUG=1
        '';

        # SHARED BUILD FUNCTIONS
        # NOTE: This is a hack to fix the PATH_ARG issue
        sharedBuildSteps = {
          # Configure script execution
          runConfigure = installDir: ''
            cd src
            rm -f config.mk
            ./configure --build-opt-parser --installdir "${installDir}"
            # Verify PATH_ARG fix
            if grep -q 'PATH_ARG="--with-path=' config.mk; then
              echo "ERROR: PATH_ARG still contains --with-path, applying manual fix"
              sed -i 's|PATH_ARG="--with-path=.*"|PATH_ARG=""|' config.mk
            fi
            echo "PATH_ARG in config.mk: $(grep '^PATH_ARG=' config.mk)"

            # Debug output: Print config.mk contents when debug level > 5
            if [ ${toString sharedConfig.nixDebug} -gt 5 ]; then
              echo "=== config.mk contents ==="
              cat config.mk
              echo "=== End config.mk ==="
            fi
            cd ..
          '';

          # Build cppfront-compiler
          # There is a cppfront binary in the thirdparty/cppfront directory, but we build it from source
          # to ensure it is nix compatible.
          #( I did try upgrading this to latest nix package, but the syntax changed and the code didn't compile)
          buildCppfront = ''
            echo "=== Building cppfront-compiler ==="
            cd thirdparty/cppfront

            # Build cppfront with error checking
            if HOST_CXX=${sharedConfig.selectedCXXPkgs}/bin/${sharedConfig.selectedCXXBin} \
               HOST_CC=${sharedConfig.selectedCCPkgs}/bin/${sharedConfig.selectedCCBin} make; then
              echo "=== cppfront make completed successfully ==="
            else
              echo "=== ERROR: cppfront make failed ==="
              exit 1
            fi

            cd ../..

            # Ensure cppfront is available in PATH for the main build
            # Create a symlink so the main build can find 'cppfront' (it expects this name)
            ln -sf cppfront-compiler ./thirdparty/cppfront/cppfront
            export PATH="$PWD/thirdparty/cppfront:$PATH"

            # Test the binary and check return code
            if ./thirdparty/cppfront/cppfront-compiler -version; then
              echo "=== cppfront-compiler built successfully and added to PATH ==="
            else
              echo "=== ERROR: cppfront-compiler failed to run ==="
              exit 1
            fi
          '';

          buildXdp2Compiler = ''
            echo "=== Building xdp2-compiler ==="
            echo "Current environment variables:"
            echo "CFLAGS_PYTHON: $CFLAGS_PYTHON"
            echo "LDFLAGS_PYTHON: $LDFLAGS_PYTHON"
            echo "CC: $CC"
            echo "CXX: $CXX"
            echo "HOST_CC: $HOST_CC"
            echo "HOST_CXX: $HOST_CXX"
            echo "XDP2_CLANG_VERSION: $XDP2_CLANG_VERSION"
            echo "XDP2_C_INCLUDE_PATH: $XDP2_C_INCLUDE_PATH"
            echo "XDP2_CLANG_RESOURCE_PATH: $XDP2_CLANG_RESOURCE_PATH"

            # Pre-build validation: Check that all required libraries and headers exist
            echo "=== Pre-build validation: Checking required libraries and headers ==="

            # Check Clang headers directory
            if [ ! -d "$XDP2_C_INCLUDE_PATH" ]; then
              echo "=== ERROR: Clang headers directory not found: $XDP2_C_INCLUDE_PATH ==="
              exit 1
            fi
            echo "=== ✓ Clang headers directory exists: $XDP2_C_INCLUDE_PATH ==="

            # Check Clang resource path
            if [ ! -d "$XDP2_CLANG_RESOURCE_PATH" ]; then
              echo "=== ERROR: Clang resource path not found: $XDP2_CLANG_RESOURCE_PATH ==="
              exit 1
            fi
            echo "=== ✓ Clang resource path exists: $XDP2_CLANG_RESOURCE_PATH ==="

            # Check key header files that xdp2-compiler needs
            key_headers=(
              "$XDP2_C_INCLUDE_PATH/AST/Type.h"
              "$XDP2_C_INCLUDE_PATH/AST/Decl.h"
              "$XDP2_C_INCLUDE_PATH/AST/DeclGroup.h"
              "$XDP2_C_INCLUDE_PATH/AST/ASTTypeTraits.h"
              "$XDP2_C_INCLUDE_PATH/Basic/SourceLocation.h"
              "$XDP2_C_INCLUDE_PATH/Frontend/CompilerInstance.h"
            )

            for header in "''${key_headers[@]}"; do
              if [ ! -f "$header" ]; then
                echo "=== ERROR: Required header file not found: $header ==="
                exit 1
              fi
              echo "=== ✓ Header file exists: $header ==="
            done

            # Check that required libraries exist (these will be linked at runtime)
            # Note: We can't check the exact library paths since they're determined by the linker,
            # but we can verify that the Clang and LLVM packages are available
            if ! command -v llvm-config >/dev/null 2>&1; then
              echo "=== ERROR: llvm-config not found in PATH ==="
              exit 1
            fi
            echo "=== ✓ llvm-config found: $(which llvm-config) ==="

            # Verify llvm-config can find the libraries
            llvm_libdir="$(${llvmP.llvm.dev}/bin/llvm-config --libdir)"
            if [ ! -d "$llvm_libdir" ]; then
              echo "=== ERROR: LLVM lib directory not found: $llvm_libdir ==="
              exit 1
            fi
            echo "=== ✓ LLVM lib directory exists: $llvm_libdir ==="

            # Check for key LLVM/Clang libraries
            key_libs=(
              "$llvm_libdir/libLLVM.so.20.1"
              "${llvmP.clang-unwrapped.lib}/lib/libclang.so.20.1"
              "${llvmP.clang-unwrapped.lib}/lib/libclang-cpp.so.20.1"
            )

            for lib in "''${key_libs[@]}"; do
              if [ ! -f "$lib" ]; then
                echo "=== ERROR: Required library not found: $lib ==="
                exit 1
              fi
              echo "=== ✓ Library exists: $lib ==="
            done

            echo "=== ✓ All required libraries and headers validated ==="
            cd src

            # Clean previous build to ensure fresh environment
            echo "=== Cleaning previous build ==="
            make clean -C tools/compiler || true  # Don't fail if clean fails

            # Debug: Show what llvm-config returns
            echo "=== DEBUG: llvm-config output ==="
            echo "llvm-config --includedir: $($HOST_LLVM_CONFIG --includedir)"
            echo "llvm-config --libdir: $($HOST_LLVM_CONFIG --libdir)"
            echo "=== END DEBUG ==="

            # Build xdp2-compiler with error checking
            if CFLAGS_PYTHON="$CFLAGS_PYTHON" LDFLAGS_PYTHON="$LDFLAGS_PYTHON" make -C tools; then
              echo "=== xdp2-compiler make completed successfully ==="
            else
              echo "=== ERROR: xdp2-compiler make failed ==="
              exit 1
            fi

            # Test the binary exists and is executable
            if [ -x "./tools/compiler/xdp2-compiler" ]; then
              echo "=== xdp2-compiler binary found and executable ==="

              # Test the binary with --help and verify it works
              echo "=== Testing xdp2-compiler --help ==="
              set +e  # Temporarily disable exit on error
              ./tools/compiler/xdp2-compiler --help
              help_exit_code=$?
              set -e  # Re-enable exit on error
              echo "=== xdp2-compiler help returned exit code: $help_exit_code ==="

              # Check if help command worked (we expect exit code 1 for help)
              if [ $help_exit_code -eq 1 ]; then
                echo "=== xdp2-compiler built successfully (help returned expected exit code: 1) ==="
              elif [ $help_exit_code -eq 0 ]; then
                echo "=== xdp2-compiler built successfully (help returned exit code: 0) ==="
              else
                echo "=== WARNING: xdp2-compiler help returned unexpected exit code: $help_exit_code ==="
                echo "=== But binary exists and is executable, continuing... ==="
              fi
            else
              echo "=== ERROR: xdp2-compiler binary not found or not executable ==="
              exit 1
            fi
            cd ..
          '';

          buildXdp2 = ''
            echo "=== Building xdp2 project ==="
            cd src

            # Ensure xdp2-compiler is available in PATH for the main build
            export PATH="$PWD/tools/compiler:$PATH"
            echo "=== Added tools/compiler to PATH: $PATH ==="

            # Build the main xdp2 project (this will use cppfront and xdp2-compiler)
            if make; then
              echo "=== xdp2 project make completed successfully ==="
            else
              echo "=== ERROR: xdp2 project make failed ==="
              exit 1
            fi

            # Test that the build completed successfully
            echo "=== xdp2 project built successfully ==="
            echo "=== Note: xdp2-compiler was built in previous step ==="
            echo "=== Build completed without segfaults ==="
            cd ..
          '';

          buildDevelopShell = ''
            echo "=== Development shell setup ==="
            mkdir -p $out/bin
            echo "#!/bin/sh" > $out/bin/xdp2-dev-shell
            echo "echo 'XDP2 Development Shell - use nix develop to enter'" >> $out/bin/xdp2-dev-shell
            chmod +x $out/bin/xdp2-dev-shell
            echo "=== Development shell setup completed ==="
          '';
        };

        xdp2-build = pkgs.stdenv.mkDerivation {
          pname = "xdp2-build";
          version = "dev";
          src = ./.;

          hardeningDisable = sharedConfig.hardeningDisable;

          nativeBuildInputs = sharedConfig.nativeBuildInputs;
          buildInputs = sharedConfig.buildInputs;

          patchPhase = ''
            echo "=== PATCHPHASE STARTING ==="
            echo "=== PATCHPHASE: This should appear in build logs ==="

            # bash fix for nix
            substituteInPlace src/configure --replace-fail '#!/bin/bash' '#!${pkgs.bash}/bin/bash'

            # bash fix for nix, note that run-tests.sh does have the extra space
            substituteInPlace src/test/parser/run-tests.sh --replace-fail '#! /bin/bash' '#!${pkgs.bash}/bin/bash'

            # Keep essential header fix for cppfront
            sed -i '1i#include <functional>\n#include <unordered_map>\n' thirdparty/cppfront/include/cpp2util.h

            # Keep essential pkg-config fix - Nix environment detection
            # Simple fix: replace the problematic PATH_ARG line with empty PATH_ARG
            sed -i 's|echo "PATH_ARG="--with-path=$PKG_CONFIG_PATH""|echo "PATH_ARG=\"\""|' src/configure

            # Keep essential C++ standard fix
            substituteInPlace src/tools/compiler/src/main.cpp --replace-fail 'if (include_paths.has_value())' 'if (include_paths)'

            # Debug: Check if Makefile exists and show its content
            echo "=== DEBUG: Checking Makefile before patching ==="
            ls -la src/tools/compiler/Makefile || echo "Makefile not found"
            echo "=== Current LLVM_INCLUDE and LLVM_LIBS lines ==="
            grep -E "LLVM_INCLUDE|LLVM_LIBS" src/tools/compiler/Makefile || echo "Lines not found"
            echo "=== END DEBUG ==="

            # Debug: Check if patches were applied
            echo "=== DEBUG: Checking Makefile (no patches applied for LLVM paths) ==="
            echo "=== Updated LLVM_INCLUDE and LLVM_LIBS lines ==="
            grep -E "LLVM_INCLUDE|LLVM_LIBS" src/tools/compiler/Makefile || echo "Lines not found"
            echo "=== END DEBUG ==="

            # REMOVED: Makefile patches for cppfront - we build cppfront v0.3.0 from source in preBuild

            echo "=== PATCHPHASE COMPLETED ==="
          '';

          configurePhase = ''
            # Set shared environment variables
            ${sharedEnvVars}

            # Debug output: Show compiler selection when debug level > 4
            if [ ${toString sharedConfig.nixDebug} -gt 4 ]; then
            echo "=== COMPILER SELECTION ==="
              echo "Using compiler: ${sharedConfig.compilerInfo}"
            echo "HOST_CC: $HOST_CC"
            echo "HOST_CXX: $HOST_CXX"
            echo "=== End compiler selection ==="
            fi

            # Debug output: Print all environment variables when debug level > 5
            if [ ${toString sharedConfig.nixDebug} -gt 5 ]; then
              echo "=== Environment Variables ==="
              env
              echo "=== End Environment Variables ==="
            fi

            # Run shared configure step
            ${sharedBuildSteps.runConfigure "$out"}
          '';

          # Build phase: build cppfront first, because xdp2 make depends on it, then main project
          buildPhase = ''
            echo "=== buildPhase - Building cppfront-compiler first ==="
            ${sharedBuildSteps.buildCppfront}

            echo "=== buildPhase -Building xdp2-compiler ==="
            ${sharedBuildSteps.buildXdp2Compiler}

            echo "=== buildPhase -Building xdp2 project ==="
            ${sharedBuildSteps.buildXdp2}

            echo "=== buildPhase -Setting up development shell ==="
            ${sharedBuildSteps.buildDevelopShell}
          '';

          # DEVELOPMENT SHELL: Skip install phase
          installPhase = ''
            echo "=== Development shell - skipping install phase ==="
            echo "=== Installation will be handled manually when needed ==="
          '';
        };
      in
      {
        devShells.default = pkgs.mkShell {

          packages = sharedConfig.corePackages;

          shellHook = ''
            ${sharedEnvVars}

            export XDP2DIR=${xdp2-build}

            if [ ${toString sharedConfig.nixDebug} -gt 4 ]; then
              echo "=== COMPILER SELECTION ==="
              echo "Using compiler: ${sharedConfig.compilerInfo}"
              echo "HOST_CC: $HOST_CC"
              echo "HOST_CXX: $HOST_CXX"
              ${sharedConfig.selectedCCPkgs}/bin/${sharedConfig.selectedCCBin} --version
              ${sharedConfig.selectedCXXPkgs}/bin/${sharedConfig.selectedCXXBin} --version
              echo "=== End compiler selection ==="
            fi

            # Debug: Show what llvm-config returns
            echo "=== DEBUG: llvm-config output ==="
            echo "llvm-config --includedir: $($HOST_LLVM_CONFIG --includedir)"
            echo "llvm-config --libdir: $($HOST_LLVM_CONFIG --libdir)"
            echo "=== END DEBUG ==="

            if [ ${toString sharedConfig.nixDebug} -gt 5 ]; then
              echo "=== Environment Variables ==="
              env
              echo "=== End Environment Variables ==="
            fi

            if [ ${toString sharedConfig.nixDebug} -gt 5 ]; then
              echo "=== Python environment debugging ==="
              echo "Python version: $(python3 --version)"
              echo "CFLAGS_PYTHON: $CFLAGS_PYTHON"
              echo "LDFLAGS_PYTHON: $LDFLAGS_PYTHON"
              echo "=== End Python debugging ==="
            fi

            # Run shared build steps
            echo "=== Running configure script to generate config.mk with Nix fixes ==="
            ${sharedBuildSteps.runConfigure "/tmp/xdp2-install"}
            echo "=== config.mk generated successfully with Nix fixes ==="

            # Note: cppfront and xdp2-compiler are now built in the derivation's buildPhase
            # This shellHook only sets up the development environment

            # Environment validation: Check that all required libraries and headers exist
            echo "=== Environment validation: Checking required libraries and headers ==="

            # Check Clang headers directory
            if [ ! -d "$XDP2_C_INCLUDE_PATH" ]; then
              echo "=== ERROR: Clang headers directory not found: $XDP2_C_INCLUDE_PATH ==="
              echo "=== This may cause segfaults in xdp2-compiler ==="
            else
              echo "=== ✓ Clang headers directory exists: $XDP2_C_INCLUDE_PATH ==="
            fi

            # Check Clang resource path
            if [ ! -d "$XDP2_CLANG_RESOURCE_PATH" ]; then
              echo "=== ERROR: Clang resource path not found: $XDP2_CLANG_RESOURCE_PATH ==="
              echo "=== This may cause segfaults in xdp2-compiler ==="
            else
              echo "=== ✓ Clang resource path exists: $XDP2_CLANG_RESOURCE_PATH ==="
            fi

            # Check key header files that xdp2-compiler needs
            key_headers=(
              "$XDP2_C_INCLUDE_PATH/AST/Type.h"
              "$XDP2_C_INCLUDE_PATH/AST/Decl.h"
              "$XDP2_C_INCLUDE_PATH/AST/DeclGroup.h"
            )

            missing_headers=0
            for header in "''${key_headers[@]}"; do
              if [ ! -f "$header" ]; then
                echo "=== ERROR: Required header file not found: $header ==="
                missing_headers=1
              else
                echo "=== ✓ Header file exists: $header ==="
              fi
            done

            if [ $missing_headers -eq 1 ]; then
              echo "=== WARNING: Some required headers are missing - this may cause segfaults ==="
            fi

            # Check if xdp2-compiler exists and show its library dependencies
            if [ -x "src/tools/compiler/xdp2-compiler" ]; then
              echo "=== ✓ xdp2-compiler binary exists and is executable ==="
              echo "=== xdp2-compiler library dependencies:"
              ldd src/tools/compiler/xdp2-compiler | grep -E "(clang|llvm)" || echo "=== No clang/llvm libraries found in dependencies ==="
            else
              echo "=== WARNING: xdp2-compiler binary not found or not executable ==="
            fi

            echo "=== Environment validation completed ==="
            echo ""

            echo "=== XDP2 Development Shell ==="
            echo "Compiler: ${sharedConfig.compilerInfo}"
            echo "GCC and Clang are available in the environment."
            echo "Debugging tools: gdb, valgrind, strace, ltrace"
            echo ""
            echo "COMPILER SELECTION:"
            echo "  Default: GCC (Ubuntu-like environment)"
            echo "  XDP2_USE_CLANG=true - Use Clang (for testing)"
            echo ""
            echo "DEBUGGING:"
            echo "  XDP2_NIX_DEBUG=5 - Show compiler selection and config.mk"
            echo "  XDP2_NIX_DEBUG=6 - Show all debug output including environment variables"
            echo ""
            echo "To build the project, 'cd src' and then 'make'"
            echo ""

            # Custom prompt shows we're in XDP2 dev shell
            export PS1="[XDP2-${sharedConfig.compilerInfo}] [\u@\h:\w]\$ "
          '';
        };
      });
}