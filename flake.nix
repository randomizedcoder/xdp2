#
# flake.nix for XDP2 - Development Shell Only
#
# This flake.nix provides a fast development environment for the XDP2 project
#
# To enter the development environment:
# nix develop

# If flakes are not enabled, use the following command to enter the development environment:
# nix --extra-experimental-features 'nix-command flakes' develop .
#
# To enable flakes, you may need to enable them in your system configuration:
# test -d /etc/nix || sudo mkdir /etc/nix
# echo 'experimental-features = nix-command flakes' | sudo tee -a /etc/nix/nix.conf
#
# Debugging:
# XDP2_NIX_DEBUG=7 nix develop --verbose --print-build-logs
#
# Not really sure what the difference between the two is, but the second one is faster
# nix --extra-experimental-features 'nix-command flakes' --option eval-cache false develop
# nix --extra-experimental-features 'nix-command flakes' develop --no-write-lock-file
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
        llvmP = pkgs.llvmPackages_20;

        # Create a Python environment with scapy
        pythonWithScapy = pkgs.python3.withPackages (ps: [ ps.scapy ]);

        sharedConfig = {

          # Debug configuration
          nixDebug = let
            envDebug = builtins.getEnv "XDP2_NIX_DEBUG";
          in
            if envDebug == "" then 0 else builtins.fromJSON envDebug;

          # GCC-only configuration.  These variables could be used to select clang
          useGCC = true;
          selectedCCPkgs = pkgs.gcc;
          selectedCXXPkgs = pkgs.gcc;
          selectedCCBin = "gcc";
          selectedCXXBin = "g++";
          compilerInfo = "GCC";

          configAgeWarningDays = 14;  # Configurable threshold for stale config warnings

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
            boost
            libpcap
            libelf
            libbpf
            pythonWithScapy
            # Development tools
            graphviz
            bpftools
            # Compilers
            gcc
            llvmP.clang llvmP.llvm.dev llvmP.clang-unwrapped
            # Debugging tools
            glibc_multi.bin
            gdb
            valgrind
            strace
            ltrace
            # Code quality
            shellcheck
            # ASCII art generator for logo display
            jp2a
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
            llvmP.llvm.dev
          ];
        };

        # Create a wrapper for llvm-config to include clang paths (for libclang)
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

        # Environment variables for development shell
        sharedEnvVars = ''
          # Compiler settings (GCC-only)
          export CC=${sharedConfig.selectedCCPkgs}/bin/${sharedConfig.selectedCCBin}
          export CXX=${sharedConfig.selectedCXXPkgs}/bin/${sharedConfig.selectedCXXBin}
          export HOST_CC=${sharedConfig.selectedCCPkgs}/bin/${sharedConfig.selectedCCBin}
          export HOST_CXX=${sharedConfig.selectedCXXPkgs}/bin/${sharedConfig.selectedCXXBin}

          # Clang environment variables for xdp2-compiler
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

          # Configuration management
          export CONFIG_AGE_WARNING_DAYS=${toString sharedConfig.configAgeWarningDays}
        '';

        # Smart configure script execution with age checking
        # This simply includes a check to see if the config.mk file exists, and
        # it generates a warning if the file is older than the threshold
        smart-configure = ''
          # Smart configuration management with age-based warnings
          smart-configure() {
            local config_file="./src/config.mk"
            local warning_days=${toString sharedConfig.configAgeWarningDays}

            # Check if config.mk exists
            if [ -f "$config_file" ]; then
              echo "✓ config.mk found, skipping configure step"

              # Check age of config.mk
              local file_time
              file_time=$(stat -c %Y "$config_file")
              local current_time
              current_time=$(date +%s)
              local age_days=$(( (current_time - file_time) / 86400 ))

              if [ "$age_days" -gt "$warning_days" ]; then
                echo "⚠️  WARNING: config.mk is $age_days days old (threshold: $warning_days days)"
                echo "   Consider running 'configure' manually if you've made changes to:"
                echo "   • Build configuration"
                echo "   • Compiler settings"
                echo "   • Library paths"
                echo "   • Platform-specific settings"
                echo ""
              else
                echo "✓ config.mk is up to date ($age_days days old)"
              fi
            else
              echo "config.mk not found, running configure script..."
              # Run the actual configure script
              cd src || return 1
              rm -f config.mk
              ./configure --build-opt-parser --installdir "/tmp/xdp2-install"

              # Apply PATH_ARG fix for Nix environment
              if grep -q 'PATH_ARG="--with-path=' config.mk; then
                echo "Applying PATH_ARG fix for Nix environment..."
                sed -i 's|PATH_ARG="--with-path=.*"|PATH_ARG=""|' config.mk
              fi
              echo "PATH_ARG in config.mk: $(grep '^PATH_ARG=' config.mk)"

              cd .. || return 1
              echo "✓ config.mk generated successfully"
            fi
          }
        '';

        # Individual build function definitions
        build-cppfront-fn = ''
          # Build cppfront-compiler
          build-cppfront() {
            if [ -n "$XDP2_NIX_DEBUG" ]; then
              local debug_level=$XDP2_NIX_DEBUG
            else
              local debug_level=0
            fi
            local start_time=""
            local end_time=""

            if [ "$debug_level" -gt 3 ]; then
              start_time=$(date +%s)
              echo "[DEBUG] build-cppfront started at $(date)"
            fi

            # Level 1: Function start
            if [ "$debug_level" -ge 1 ]; then
              echo "[DEBUG] Starting build-cppfront function"
            fi

            # Clean
            if [ "$debug_level" -ge 2 ]; then
              echo "[DEBUG] Cleaning cppfront build directory"
            fi
            echo "Cleaning and building cppfront-compiler..."

            # Navigate to repository root first
            local repo_root
            repo_root=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
            if [ "$debug_level" -gt 3 ]; then
              echo "[DEBUG] Repository root: $repo_root"
            fi

            if ! cd "$repo_root"; then
              echo "✗ ERROR: Cannot navigate to repository root: $repo_root"
              return 1
            fi

            # Debug output for directory change
            if [ "$debug_level" -gt 3 ]; then
              echo "[DEBUG] About to run: cd thirdparty/cppfront"
            fi
            if ! cd thirdparty/cppfront; then
              echo "✗ ERROR: Cannot navigate to thirdparty/cppfront directory from $repo_root"
              echo "   Please ensure you're in a valid XDP2 repository"
              return 1
            fi

            # Debug output for clean command
            if [ "$debug_level" -gt 3 ]; then
              echo "[DEBUG] About to run: make clean"
            fi
            make clean || true  # Don't fail if clean fails

            # Apply essential header fix for cppfront
            if [ "$debug_level" -ge 3 ]; then
              echo "[DEBUG] Applying cppfront header fix"
              echo "sed -i '1i#include <functional>\n#include <unordered_map>\n' include/cpp2util.h"
            fi
            sed -i '1i#include <functional>\n#include <unordered_map>\n' include/cpp2util.h

            # Level 3: Build step details
            if [ "$debug_level" -ge 3 ]; then
              echo "[DEBUG] Building cppfront-compiler with make"
            fi

            # Build cppfront with error checking
            if HOST_CXX="$CXX" HOST_CC="$CC" make; then
              echo "✓ cppfront make completed successfully"
            else
              echo "✗ ERROR: cppfront make failed"
              return 1
            fi

            # Return to repository root
            if ! cd "$repo_root"; then
              echo "⚠ WARNING: Could not return to repository root"
            fi

            # Add to the PATH
            export PATH="$PWD/thirdparty/cppfront:$PATH"

            # Level 2: Validation step
            if [ "$debug_level" -ge 2 ]; then
              echo "[DEBUG] Validating cppfront-compiler binary"
            fi

            # Validate binary was created
            if [ -x "./thirdparty/cppfront/cppfront-compiler" ]; then
              echo "✓ cppfront-compiler binary created and executable"

              # Test the binary runs correctly
              echo "Testing cppfront-compiler..."
              set +e  # Temporarily disable exit on error

              # Debug output for validation command
              if [ "$debug_level" -gt 3 ]; then
                echo "[DEBUG] About to run: ./thirdparty/cppfront/cppfront-compiler -version"
              fi
              ./thirdparty/cppfront/cppfront-compiler -version
              test_exit_code=$?
              set -e  # Re-enable exit on error

              if [ "$test_exit_code" -eq 0 ] || [ "$test_exit_code" -eq 1 ]; then
                echo "✓ cppfront-compiler runs correctly (exit code: $test_exit_code)"
              else
                echo "⚠ WARNING: cppfront-compiler returned unexpected exit code: $test_exit_code"
                echo "But binary exists and is executable, continuing..."
              fi
            else
              echo "✗ ERROR: cppfront-compiler binary not found or not executable"
              return 1
            fi

            # End timing for debug levels > 3
            if [ "$debug_level" -gt 3 ]; then
              end_time=$(date +%s)
              local duration=$((end_time - start_time))
              echo "[DEBUG] build-cppfront completed in $duration seconds"
            fi

            echo "cppfront-compiler built and validated successfully"
          }
        '';

        check-cppfront-age-fn = ''
          # Check cppfront age and rebuild if needed
          check-cppfront-age() {
            if [ -n "$XDP2_NIX_DEBUG" ]; then
              local debug_level=$XDP2_NIX_DEBUG
            else
              local debug_level=0
            fi
            local start_time=""
            local end_time=""

            # Start timing for debug levels > 3
            if [ "$debug_level" -gt 3 ]; then
              start_time=$(date +%s)
              echo "[DEBUG] check-cppfront-age started at $(date)"
            fi

            # Level 1: Function start
            if [ "$debug_level" -ge 1 ]; then
              echo "[DEBUG] Starting check-cppfront-age function"
            fi

            local cppfront_binary="thirdparty/cppfront/cppfront-compiler"

            # Level 2: File check
            if [ "$debug_level" -ge 2 ]; then
              echo "[DEBUG] Checking cppfront binary: $cppfront_binary"
            fi

            if [ -f "$cppfront_binary" ]; then
              local file_time
              file_time=$(stat -c %Y "$cppfront_binary")
              local current_time
              current_time=$(date +%s)
              local age_days=$(( (current_time - file_time) / 86400 ))

              # Level 3: Age calculation details
              if [ "$debug_level" -ge 3 ]; then
                echo "[DEBUG] File modification time: $file_time"
                echo "[DEBUG] Current time: $current_time"
                echo "[DEBUG] Calculated age: $age_days days"
              fi

              if [ "$age_days" -gt 7 ]; then
                echo "cppfront is $age_days days old, rebuilding..."
                build-cppfront
              else
                echo "cppfront is up to date ($age_days days old)"
              fi
            else
              echo "cppfront not found, building..."
              build-cppfront
            fi

            # End timing for debug levels > 3
            if [ "$debug_level" -gt 3 ]; then
              end_time=$(date +%s)
              local duration=$((end_time - start_time))
              echo "[DEBUG] check-cppfront-age completed in $duration seconds"
            fi
          }
        '';

        build-xdp2-compiler-fn = ''
          # Build xdp2-compiler
          build-xdp2-compiler() {
            if [ -n "$XDP2_NIX_DEBUG" ]; then
              local debug_level=$XDP2_NIX_DEBUG
            else
              local debug_level=0
            fi
            local start_time=""
            local end_time=""

            # Start timing for debug levels > 3
            if [ "$debug_level" -gt 3 ]; then
              start_time=$(date +%s)
              echo "[DEBUG] build-xdp2-compiler started at $(date)"
            fi

            # Level 1: Function start
            if [ "$debug_level" -ge 1 ]; then
              echo "[DEBUG] Starting build-xdp2-compiler function"
            fi

            # Level 2: Clean step
            if [ "$debug_level" -ge 2 ]; then
              echo "[DEBUG] Cleaning xdp2-compiler build directory"
            fi
            echo "Cleaning and building xdp2-compiler..."

            # Navigate to repository root first
            local repo_root
            repo_root=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
            if [ "$debug_level" -gt 3 ]; then
              echo "[DEBUG] Repository root: $repo_root"
            fi

            if ! cd "$repo_root"; then
              echo "✗ ERROR: Cannot navigate to repository root: $repo_root"
              return 1
            fi

            # Debug output for directory change
            if [ "$debug_level" -gt 3 ]; then
              echo "[DEBUG] About to run: cd src/tools/compiler"
            fi
            if ! cd src/tools/compiler; then
              echo "✗ ERROR: Cannot navigate to src/tools/compiler directory from $repo_root"
              echo "   Please ensure you're in a valid XDP2 repository"
              return 1
            fi

            # Debug output for clean command
            if [ "$debug_level" -gt 3 ]; then
              echo "[DEBUG] About to run: make clean"
            fi
            make clean || true  # Don't fail if clean fails

            # Level 3: Build step details
            if [ "$debug_level" -ge 3 ]; then
              echo "[DEBUG] Building xdp2-compiler with make"
            fi

            # Build xdp2-compiler with error checking
            if CFLAGS_PYTHON="$CFLAGS_PYTHON" LDFLAGS_PYTHON="$LDFLAGS_PYTHON" make; then
              echo "✓ xdp2-compiler make completed successfully"
            else
              echo "✗ ERROR: xdp2-compiler make failed"
              return 1
            fi

            # Level 2: Validation step
            if [ "$debug_level" -ge 2 ]; then
              echo "[DEBUG] Validating xdp2-compiler binary"
            fi

            # Validate binary was created
            if [ -x "./xdp2-compiler" ]; then
              echo "✓ xdp2-compiler binary created and executable"

              # Test the binary runs correctly
              echo "Testing xdp2-compiler..."
              set +e  # Temporarily disable exit on error

              # Debug output for validation command
              if [ "$debug_level" -gt 3 ]; then
                echo "[DEBUG] About to run: ./xdp2-compiler --help"
              fi
              ./xdp2-compiler --help
              test_exit_code=$?
              set -e  # Re-enable exit on error

              if [ "$test_exit_code" -eq 0 ] || [ "$test_exit_code" -eq 1 ]; then
                echo "✓ xdp2-compiler runs correctly (exit code: $test_exit_code)"
              else
                echo "⚠ WARNING: xdp2-compiler returned unexpected exit code: $test_exit_code"
                echo "But binary exists and is executable, continuing..."
              fi
            else
              echo "✗ ERROR: xdp2-compiler binary not found or not executable"
              return 1
            fi

            # Return to repository root
            if ! cd "$repo_root"; then
              echo "⚠ WARNING: Could not return to repository root"
            fi

            # End timing for debug levels > 3
            if [ "$debug_level" -gt 3 ]; then
              end_time=$(date +%s)
              local duration=$((end_time - start_time))
              echo "[DEBUG] build-xdp2-compiler completed in $duration seconds"
            fi

            echo "xdp2-compiler built and validated successfully"
          }
        '';

        build-xdp2-fn = ''
          # Build xdp2 project
          build-xdp2() {
            if [ -n "$XDP2_NIX_DEBUG" ]; then
              local debug_level=$XDP2_NIX_DEBUG
            else
              local debug_level=0
            fi
            local start_time=""
            local end_time=""

            # Start timing for debug levels > 3
            if [ "$debug_level" -gt 3 ]; then
              start_time=$(date +%s)
              echo "[DEBUG] build-xdp2 started at $(date)"
            fi

            # Level 1: Function start
            if [ "$debug_level" -ge 1 ]; then
              echo "[DEBUG] Starting build-xdp2 function"
            fi

            # Level 2: Clean step
            if [ "$debug_level" -ge 2 ]; then
              echo "[DEBUG] Cleaning xdp2 project build directory"
            fi
            echo "Cleaning and building xdp2 project..."

            # Navigate to repository root first
            local repo_root
            repo_root=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
            if [ "$debug_level" -gt 3 ]; then
              echo "[DEBUG] Repository root: $repo_root"
            fi

            if ! cd "$repo_root"; then
              echo "✗ ERROR: Cannot navigate to repository root: $repo_root"
              return 1
            fi

            # Debug output for directory change
            if [ "$debug_level" -gt 3 ]; then
              echo "[DEBUG] About to run: cd src"
            fi
            if ! cd src; then
              echo "✗ ERROR: Cannot navigate to src/ directory from $repo_root"
              echo "   Please ensure you're in a valid XDP2 repository"
              return 1
            fi

            # Debug output for clean command
            if [ "$debug_level" -gt 3 ]; then
              echo "[DEBUG] About to run: make clean"
            fi
            make clean || true  # Don't fail if clean fails

            # Ensure xdp2-compiler is available in PATH
            export PATH="$PWD/tools/compiler:$PATH"
            echo "Added tools/compiler to PATH"

            # Level 3: Build step details
            if [ "$debug_level" -ge 3 ]; then
              echo "[DEBUG] Building xdp2 project with make"
            fi

            # Build the main xdp2 project
            if make; then
              echo "✓ xdp2 project make completed successfully"
            else
              echo "✗ ERROR: xdp2 project make failed"
              echo "   Check the error messages above for details"
              return 1
            fi

            # Return to repository root
            if ! cd "$repo_root"; then
              echo "⚠ WARNING: Could not return to repository root"
            fi

            # End timing for debug levels > 3
            if [ "$debug_level" -gt 3 ]; then
              end_time=$(date +%s)
              local duration=$((end_time - start_time))
              echo "[DEBUG] build-xdp2 completed in $duration seconds"
            fi

            echo "xdp2 project built successfully"
          }
        '';

        build-all-fn = ''
          # Build all components
          build-all() {
            echo "Building all XDP2 components..."

            if [ "$debug_level" -ge 3 ]; then
              echo "[DEBUG] Building cppfront: build-cppfront"
            fi
            build-cppfront

            if [ "$debug_level" -ge 3 ]; then
              echo "[DEBUG] Building xdp2-compiler: build-xdp2-compiler"
            fi
            build-xdp2-compiler

            if [ "$debug_level" -ge 3 ]; then
              echo "[DEBUG] Building xdp2: build-xdp2"
            fi
            build-xdp2

            echo "✓ All components built successfully"
          }
        '';

        clean-build-fn = ''
          # Clean all build artifacts
          clean-build() {
            echo "Cleaning all build artifacts..."

            if [ "$debug_level" -ge 3 ]; then
              echo "[DEBUG] Cleaning cppfront: cd thirdparty/cppfront && make clean"
            fi
            cd thirdparty/cppfront && make clean || true && cd ../..

            if [ "$debug_level" -ge 3 ]; then
              echo "[DEBUG] Cleaning xdp2-compiler: cd src/tools/compiler && make clean"
            fi
            cd src/tools/compiler && make clean || true && cd ../..

            if [ "$debug_level" -ge 3 ]; then
              echo "[DEBUG] Cleaning xdp2: cd src && make clean"
            fi
            cd src && make clean || true && cd ..

            echo "✓ All build artifacts cleaned"
          }
        '';

        run-shellcheck-fn = ''
          # Run shellcheck validation on all shell functions
          run-shellcheck() {
            if [ -n "$XDP2_NIX_DEBUG" ]; then
              local debug_level=$XDP2_NIX_DEBUG
            else
              local debug_level=0
            fi
            local start_time=""
            local end_time=""

            # Start timing for debug levels > 3
            if [ "$debug_level" -gt 3 ]; then
              start_time=$(date +%s)
              echo "[DEBUG] run-shellcheck started at $(date)"
            fi

            # Level 1: Function start
            if [ "$debug_level" -ge 1 ]; then
              echo "[DEBUG] Starting run-shellcheck function"
            fi

            # Level 2: Check shellcheck availability
            if [ "$debug_level" -ge 2 ]; then
              echo "[DEBUG] Checking shellcheck availability"
            fi

            if ! command -v shellcheck >/dev/null 2>&1; then
              echo "✗ ERROR: shellcheck not found in PATH"
              echo "Please install shellcheck to validate bash code"
              return 1
            fi

            echo "✓ shellcheck found: $(which shellcheck)"

            # Level 3: Define function list
            if [ "$debug_level" -ge 3 ]; then
              echo "[DEBUG] Defining list of functions to check"
            fi

            echo "Running shellcheck validation on shell functions..."

            # Check each function individually
            echo "Checking build-cppfront..."
            if type "build-cppfront" 2>/dev/null | shellcheck -s bash -; then
              echo "✓ build-cppfront passed shellcheck validation"
            else
              echo "✗ build-cppfront failed shellcheck validation"
            fi

            echo "Checking build-xdp2-compiler..."
            if type "build-xdp2-compiler" 2>/dev/null | shellcheck -s bash -; then
              echo "✓ build-xdp2-compiler passed shellcheck validation"
            else
              echo "✗ build-xdp2-compiler failed shellcheck validation"
            fi

            echo "Checking build-xdp2..."
            if type "build-xdp2" 2>/dev/null | shellcheck -s bash -; then
              echo "✓ build-xdp2 passed shellcheck validation"
            else
              echo "✗ build-xdp2 failed shellcheck validation"
            fi

            echo "Checking build-all..."
            if type "build-all" 2>/dev/null | shellcheck -s bash -; then
              echo "✓ build-all passed shellcheck validation"
            else
              echo "✗ build-all failed shellcheck validation"
            fi

            echo "Checking clean-build..."
            if type "clean-build" 2>/dev/null | shellcheck -s bash -; then
              echo "✓ clean-build passed shellcheck validation"
            else
              echo "✗ clean-build failed shellcheck validation"
            fi

            echo "Checking check-cppfront-age..."
            if type "check-cppfront-age" 2>/dev/null | shellcheck -s bash -; then
              echo "✓ check-cppfront-age passed shellcheck validation"
            else
              echo "✗ check-cppfront-age failed shellcheck validation"
            fi

            echo "Checking run-shellcheck..."
            if type "run-shellcheck" 2>/dev/null | shellcheck -s bash -; then
              echo "✓ run-shellcheck passed shellcheck validation"
            else
              echo "✗ run-shellcheck failed shellcheck validation"
            fi

            echo ""
            echo "=== Shellcheck Validation Complete ==="
            echo "All functions have been checked for shellcheck compliance"

            # End timing for debug levels > 3
            if [ "$debug_level" -gt 3 ]; then
              end_time=$(date +%s)
              local duration=$((end_time - start_time))
              echo "[DEBUG] run-shellcheck completed in $duration seconds"
            fi

            echo "✓ Shellcheck validation completed"
            return 0
          }
        '';

        xdp2-help-fn = ''
          # Comprehensive help function using single echo with heredoc
          xdp2-help() {
            echo "🚀 === XDP2 Development Shell Help ===

📦 Compiler: GCC
🔧 GCC and Clang are available in the environment.
🐛 Debugging tools: gdb, valgrind, strace, ltrace

🔍 DEBUGGING:
  XDP2_NIX_DEBUG=5 - Show compiler selection and config.mk
  XDP2_NIX_DEBUG=6 - Show all debug output including environment variables

⚙️  BUILD COMMANDS:
  build-cppfront     - Build cppfront compiler
  build-xdp2-compiler - Build xdp2 compiler
  build-xdp2         - Build main XDP2 project
  build-all          - Build all components
  clean-build        - Clean all build artifacts
  check-cppfront-age - Check and rebuild cppfront if needed
  run-shellcheck     - Validate all shell functions

💡 QUICK START:
  • Run 'build-all' to build everything
  • Run 'clean-build' to clean all artifacts
  • Run 'run-shellcheck' to validate shell functions

🚀 CONVENIENT ALIASES:
  • xdp2-build        - Alias for 'build-all'
  • xdp2-clean        - Alias for 'clean-build'
  • xdp2-check        - Alias for 'run-shellcheck'
  • xdp2-help         - Show this help message
  • xdp2-src          - Navigate to src/ directory
  • xdp2-samples      - Navigate to samples/ directory
  • xdp2-docs         - Navigate to documentation/ directory
  • xdp2-cppfront     - Navigate to cppfront directory

📁 PROJECT STRUCTURE:
  • src/              - Main XDP2 source code
  • thirdparty/cppfront/ - Cppfront compiler
  • samples/          - Example code and parsers
  • documentation/    - Project documentation

🎯 Ready to develop! 'xdp2-help' for help"
          }
        '';

        shell-aliases = ''
          # Add useful aliases and shortcuts
          alias ll='ls -la'
          alias la='ls -A'
          alias l='ls -CF'
          alias ..='cd ..'
          alias ...='cd ../..'
          alias ....='cd ../../..'
          alias grep='grep --color=auto'
          alias fgrep='fgrep --color=auto'
          alias egrep='egrep --color=auto'

          # XDP2-specific aliases
          alias xdp2-build='build-all'
          alias xdp2-clean='clean-build'
          alias xdp2-check='run-shellcheck'
          alias xdp2-help='xdp2-help'

          # Quick navigation aliases
          alias xdp2-src='cd src'
          alias xdp2-samples='cd samples'
          alias xdp2-docs='cd documentation'
          alias xdp2-cppfront='cd thirdparty/cppfront'
        '';

        colored-prompt = ''
          # Set colored prompt with XDP2 branding
          export PS1="\[\033[0;32m\][XDP2-${sharedConfig.compilerInfo}] \[\033[01;34m\][\u@\h:\w]\$ \[\033[0m\]"
        '';

        ascii-art-logo = ''
          # Display ASCII art logo with fallback
          if command -v jp2a >/dev/null 2>&1 && [ -f "./documentation/images/xdp2-big.png" ]; then
            echo "$(jp2a --colors ./documentation/images/xdp2-big.png)"
            echo ""
          else
            echo "🚀 === XDP2 Development Shell ==="
          fi
        '';

        minimal-shell-entry = ''
          # Minimal shell entry information
          echo "🚀 === XDP2 Development Shell ==="
          echo "📦 Compiler: ${sharedConfig.compilerInfo}"
          echo "🔧 GCC and Clang are available in the environment"
          echo "🐛 Debugging tools: gdb, valgrind, strace, ltrace"
          echo "🎯 Ready to develop! 'xdp2-help' for help"
        '';

        # Debug output functions
        debug-compiler-selection = ''
            # Debug output: Show compiler selection when debug level > 4
            if [ ${toString sharedConfig.nixDebug} -gt 4 ]; then
            echo "=== COMPILER SELECTION ==="
              echo "Using compiler: ${sharedConfig.compilerInfo}"
            echo "HOST_CC: $HOST_CC"
            echo "HOST_CXX: $HOST_CXX"
            $HOST_CC --version
            $HOST_CXX --version
            echo "=== End compiler selection ==="
            fi
        '';

        debug-environment-vars = ''
            # Debug output: Print all environment variables when debug level > 5
            if [ ${toString sharedConfig.nixDebug} -gt 5 ]; then
              echo "=== Environment Variables ==="
              env
              echo "=== End Environment Variables ==="
            fi
        '';

        # Combined build functions
        build-functions = ''
          ${build-cppfront-fn}
          ${check-cppfront-age-fn}
          ${build-xdp2-compiler-fn}
          ${build-xdp2-fn}
          ${build-all-fn}
          ${clean-build-fn}
          ${run-shellcheck-fn}
          ${xdp2-help-fn}
        '';

      in
      {
        devShells.default = pkgs.mkShell {
          packages = sharedConfig.corePackages;

          shellHook = ''
            ${sharedEnvVars}

            # Debug output functions
            ${debug-compiler-selection}
            ${debug-environment-vars}

            # Display ASCII art logo
            ${ascii-art-logo}

            # Define smart configure function
            ${smart-configure}

            # Run smart configure script with age checking
            smart-configure

            # Define build command functions
            ${build-functions}

            # Set up shell aliases
            ${shell-aliases}

            # Set colored prompt
            ${colored-prompt}

            # Display minimal shell entry information
            ${minimal-shell-entry}
          '';
        };
      });
}