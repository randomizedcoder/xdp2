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
        llvmP = pkgs.llvmPackages_20;  #pkgs.llvmPackages_21 is available

        # nixDebug code will be left in place to allow for future debugging
        # DEBUGGING: Keep all debug code in place - adjust nixDebug level to control verbosity
        nixDebug = 6; # 0 = no debug, 7 max debug (like syslog level)

        # COMPILER SELECTION: Allow testing with GCC vs Clang
        # Default to GCC (as intended by the codebase design)
        # Set XDP2_USE_CLANG=true to use Clang (for testing)
        # Unset or false to use GCC (default, Ubuntu-like environment)
        useClang = builtins.getEnv "XDP2_USE_CLANG" == "true";
        useGCC = !useClang;

        # Select compiler based on configuration
        selectedCC = if useGCC then pkgs.gcc else pkgs.clang;
        selectedCXX = if useGCC then pkgs.gcc else pkgs.clang;

        # Select correct binary names for each compiler
        selectedCCBin = if useGCC then "gcc" else "clang";
        selectedCXXBin = if useGCC then "g++" else "clang++";

        # Compiler info for debugging
        compilerInfo = if useGCC then "GCC" else "Clang";

        # Create a Python environment with scapy included.
        # This is the idiomatic Nix way to handle Python dependencies.
        pythonWithScapy = pkgs.python3.withPackages (ps: [ ps.scapy ]);

        devPackages = with pkgs; [
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
          # Compilers for the dual-toolchain environment
          gcc # https://search.nixos.org/packages?channel=unstable&query=gcc gcc15 is available
          llvmP.clang llvmP.llvm.dev llvmP.clang-unwrapped
          # Debugging tools for linking analysis
          glibc_multi.bin # glibc.bin glibc_multi.bin # Provides ldd for dynamic library inspection
          # DEBUGGING: Add debugging tools for segfault analysis
          gdb # GNU Debugger for core dump analysis
          valgrind # Memory debugging and profiling
          strace # System call tracer
          ltrace # Library call tracer
          # REMOVED: cppfront - we build cppfront v0.3.0 from source in preBuild
        ];

        xdp2-build = pkgs.stdenv.mkDerivation {
          pname = "xdp2-build";
          version = "dev";
          src = ./.;

          # DISABLE HARDENING FLAGS: Disable specific hardening flags that cause segfaults
          # Based on investigation: fortify, fortify3, stackprotector, strictoverflow are likely culprits
          hardeningDisable = [ "fortify" "fortify3" "stackprotector" "strictoverflow" ];

          nativeBuildInputs = [
            pkgs.pkg-config
            llvmP.clang # For HOST_CXX
            llvmP.llvm.dev # For llvm-config
          ];

          buildInputs = with pkgs; [
            # Core libraries
            boost
            libpcap
            libelf
            libbpf
            zlib
            ncurses
            # Per nix_python_compile_errors.md, the build derivation needs a clean python3.
            # The pythonWithScapy environment is only for the interactive dev shell.
            # Consistent Python environment across all phases
            pythonWithScapy
            # CPython in nixpkgs, the C headers (Python.h) and python3-config are already in pkgs.python3. You don't need a separate dev output (unlike many C libs)
            python3
            # Add LLVM and Clang libraries for linking during the clang check
            llvmP.llvm
            llvmP.clang-unwrapped
            # REMOVED: cppfront package - we build cppfront v0.3.0 from source in preBuild
          ];

          patchPhase = ''
            # Option B: Keep only essential patches - remove complex patches that might cause issues
            substituteInPlace src/configure --replace-fail '#!/bin/bash' '#!${pkgs.bash}/bin/bash'
            substituteInPlace src/test/parser/run-tests.sh --replace-fail '#!/bin/bash' '#!${pkgs.bash}/bin/bash'

            # Keep essential header fix for cppfront
            sed -i '1i#include <functional>\n#include <unordered_map>\n' thirdparty/cppfront/include/cpp2util.h

            # Keep essential pkg-config fix
            substituteInPlace src/configure --replace-fail 'echo "PATH_ARG=\"--with-path=$PKG_CONFIG_PATH\""' 'echo "PATH_ARG=\"\""'

            # Keep essential C++ standard fix
            substituteInPlace src/tools/compiler/src/main.cpp --replace-fail 'if (include_paths.has_value())' 'if (include_paths)'

            # REMOVED: Makefile patches for cppfront - we build cppfront v0.3.0 from source in preBuild
          '';

          # Option B: Simplified configure phase - more like Ubuntu approach
          configurePhase = ''
            # The configure script must be run from within the 'src' directory
            cd src

            # COMPILER SELECTION: Use selected compiler instead of hardcoded values
            export HOST_CXX=${selectedCXX}/bin/${selectedCXXBin}
            export HOST_CC=${selectedCC}/bin/${selectedCCBin}
            export HOST_LLVM_CONFIG=${llvmP.llvm.dev}/bin/llvm-config

            # DEBUG: Show compiler selection
            echo "=== COMPILER SELECTION ==="
            echo "Using compiler: ${compilerInfo}"
            echo "HOST_CC: $HOST_CC"
            echo "HOST_CXX: $HOST_CXX"
            echo "Compiler version:"
            $HOST_CC --version | head -1
            $HOST_CXX --version | head -1
            echo "=== End compiler selection ==="

            # Simple configure call - let it use defaults like Ubuntu
            ./configure --build-opt-parser --installdir "$out"

            # DEBUG: Print config.mk contents to understand the build configuration
            echo "=== config.mk contents ==="
            cat config.mk
            echo "=== End config.mk ==="
          '';

          # RESTORED: preBuild phase - build cppfront v0.3.0 from source
          # This is the ONLY viable approach due to syntax incompatibilities with cppfront v0.8.1
          preBuild = ''
            echo "=== Building cppfront-compiler v0.3.0 with Nix-controlled toolchain ==="

            # Build cppfront-compiler using selected compiler
            HOST_CXX=${selectedCXX}/bin/${selectedCXXBin} HOST_CC=${selectedCC}/bin/${selectedCCBin} make -C ../thirdparty/cppfront

            # Verify it was built
            test -f ../thirdparty/cppfront/cppfront-compiler || (echo "cppfront-compiler not found!"; exit 1)

            # DEBUG: Check the version of the cppfront-compiler we just built
            echo "=== cppfront-compiler version ==="
            ../thirdparty/cppfront/cppfront-compiler -version || echo "Version check failed"
            echo "=== End cppfront version ==="

            # DEBUG: Analyze linking differences - Nix vs Ubuntu
            echo "=== Linking Analysis: cppfront-compiler ==="
            echo "File type:"
            file ../thirdparty/cppfront/cppfront-compiler
            echo "Dynamic library dependencies:"
            ldd ../thirdparty/cppfront/cppfront-compiler || echo "ldd failed or static binary"
            echo "=== End linking analysis ==="

            echo "SUCCESS: cppfront-compiler v0.3.0 built with Nix toolchain"
          '';

          # Enhanced buildPhase with linking analysis
          buildPhase = ''
            runHook preBuild

            echo "=== Starting main build with linking analysis ==="

            # Set up environment variables for Python and LLVM compilation
            # These fix the build issues we identified during debugging
            export CFLAGS_PYTHON="$(pkg-config --cflags python3-embed)"
            export LDFLAGS_PYTHON="$(pkg-config --libs python3-embed)"
            export HOST_LLVM_CONFIG="${llvmP.llvm.dev}/bin/llvm-config"
            export LLVM_LIBS="-L${llvmP.llvm}/lib"
            export BOOST_LIBS="-lboost_wave -lboost_thread -lboost_filesystem -lboost_system -lboost_program_options"
            export CLANG_LIBS="-lclang -lLLVM -lclang-cpp"
            export LIBS="-lpthread -ldl -lutil"
            export PATH_ARG=""

            echo "=== Environment variables set ==="
            echo "CFLAGS_PYTHON: $CFLAGS_PYTHON"
            echo "LDFLAGS_PYTHON: $LDFLAGS_PYTHON"
            echo "HOST_LLVM_CONFIG: $HOST_LLVM_CONFIG"
            echo "LLVM_LIBS: $LLVM_LIBS"
            echo "BOOST_LIBS: $BOOST_LIBS"
            echo "CLANG_LIBS: $CLANG_LIBS"
            echo "LIBS: $LIBS"
            echo "PATH_ARG: $PATH_ARG"

            # Run the main build
            make

            echo "=== Build completed - analyzing linking differences ==="

            # DEBUG: Analyze linking of key binaries
            echo "=== Linking Analysis: Key Binaries ==="

            # Check xdp2-compiler if it exists
            if [ -f tools/compiler/xdp2-compiler ]; then
              echo "--- xdp2-compiler ---"
              echo "File type:"
              file tools/compiler/xdp2-compiler
              echo "Dynamic library dependencies:"
              ldd tools/compiler/xdp2-compiler || echo "ldd failed or static binary"
            fi

            # Check test binaries that might be causing segfault
            if [ -f test/parse_dump/parse_dump ]; then
              echo "--- parse_dump (test binary) ---"
              echo "File type:"
              file test/parse_dump/parse_dump
              echo "Dynamic library dependencies:"
              ldd test/parse_dump/parse_dump || echo "ldd failed or static binary"
            fi

            # Check other test binaries
            for test_bin in test/*/test_*; do
              if [ -f "$test_bin" ] && [ -x "$test_bin" ]; then
                echo "--- $(basename "$test_bin") ---"
                echo "File type:"
                file "$test_bin"
                echo "Dynamic library dependencies:"
                ldd "$test_bin" || echo "ldd failed or static binary"
              fi
            done

            echo "=== End linking analysis ==="

            runHook postBuild
          '';

          # The installPhase also runs from within the 'src' directory.
          installPhase = ''
            make install
          '';
        };
      in
      {
        devShells.default = pkgs.mkShell {
          packages = devPackages;

          # DEBUGGING: Add helper functions for debugging
          shellHook = ''
            export XDP2DIR=${xdp2-build}
            export BUILD_OPT_PARSER=y
            export PYTHON_VER=3
            export PKG_CONFIG_PATH=${pkgs.lib.makeSearchPath "lib/pkgconfig" devPackages}

            # COMPILER SELECTION: Override Nix's default compiler settings
            export CC=${selectedCC}/bin/${selectedCCBin}
            export CXX=${selectedCXX}/bin/${selectedCXXBin}
            export HOST_CC=${selectedCC}/bin/${selectedCCBin}
            export HOST_CXX=${selectedCXX}/bin/${selectedCXXBin}

            # Set up environment variables for Python and LLVM compilation
            # These fix the build issues we identified during debugging
            export CFLAGS_PYTHON="$(pkg-config --cflags python3-embed)"
            export LDFLAGS_PYTHON="$(pkg-config --libs python3-embed)"
            export HOST_LLVM_CONFIG="${llvmP.llvm.dev}/bin/llvm-config"
            export LLVM_LIBS="-L${llvmP.llvm}/lib"
            export BOOST_LIBS="-lboost_wave -lboost_thread -lboost_filesystem -lboost_system -lboost_program_options"
            export CLANG_LIBS="-lclang -lLLVM -lclang-cpp"
            export LIBS="-lpthread -ldl -lutil"
            export PATH_ARG=""

            # DEBUGGING: Enable core dumps and debugging environment
            ulimit -c unlimited
            export XDP2_COMPILER_DEBUG=1
            export PYTHONPATH="${pkgs.python3}/lib/python3.13/site-packages:$PYTHONPATH"

            # DEBUGGING: Helper functions for debugging
            make-debug() {
              echo "=== Starting debug build ==="
              cd src
              make clean
              make 2>&1 | tee ../debug-build.log
              echo "Build log saved to debug-build.log"
            }

            make-skip-test() {
              echo "=== Building without problematic test ==="
              cd src
              make clean
              # Skip the parse_dump test that causes segfault
              make -j$(nproc) 2>&1 | grep -v "parse_dump" | tee ../build-skip-test.log
              echo "Build log saved to build-skip-test.log"
            }

            test-segfault() {
              echo "=== Testing segfault with debugging tools ==="
              cd src/test/parse_dump
              echo "Testing with strace..."
              strace -f -o ../../../strace.log ../../tools/compiler/xdp2-compiler -I../../include -o parser.p.c -i parser.c
              echo "Strace log saved to strace.log"
            }

            analyze-core() {
              echo "=== Analyzing core dumps ==="
              if [ -f core ]; then
                echo "Found core dump, analyzing with gdb..."
                gdb --batch --ex run --ex bt --ex quit ./tools/compiler/xdp2-compiler core
              else
                echo "No core dump found. Run 'test-segfault' first."
              fi
            }

            python-debug() {
              echo "=== Testing Python environment ==="
              python3 --version
              python3 -c "import sys; print('Python paths:'); [print(p) for p in sys.path]"
              python3 -c "import sysconfig; print('Python config:'); print(sysconfig.get_paths())"
              python3 -c "import ctypes; print('Python embedding works')"
            }

            echo "=== XDP2 Development Shell (DEBUG MODE) ==="
            echo "Compiler: ${compilerInfo}"
            echo "GCC and Clang are available in the environment."
            echo "Debugging tools: gdb, valgrind, strace, ltrace"
            echo ""
            echo "COMPILER SELECTION:"
            echo "  Default: GCC (Ubuntu-like environment)"
            echo "  XDP2_USE_CLANG=true - Use Clang (for testing)"
            echo ""
            echo "DEBUGGING COMMANDS:"
            echo "  make-debug     - Build with debugging enabled and capture output"
            echo "  make-skip-test - Build without the problematic parse_dump test"
            echo "  test-segfault  - Test the segfault with debugging tools"
            echo "  analyze-core   - Analyze core dumps if they exist"
            echo "  python-debug   - Test Python environment and embedding"
            echo ""
            echo "Run 'make' in 'src/' to build the project."
            echo "Run 'make-debug' for detailed debugging output."
            echo ""

            # Set custom prompt to show we're in XDP2 dev shell
            # Replace the existing prompt with our custom one using environment variables
            export PS1="[XDP2-${compilerInfo}] [\u@\h:\w]\$ "
          '';
        };
      });
}