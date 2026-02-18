#
# flake.nix for XDP2
#
# This flake provides:
# - Development environment: nix develop
# - Package build: nix build
#
# To enter the development environment:
# nix develop
#
# To build the package:
# nix build .#xdp2
#
# If flakes are not enabled, use the following command:
# nix --extra-experimental-features 'nix-command flakes' develop .
# nix --extra-experimental-features 'nix-command flakes' build .
#
# To enable flakes, you may need to enable them in your system configuration:
# test -d /etc/nix || sudo mkdir /etc/nix
# echo 'experimental-features = nix-command flakes' | sudo tee -a /etc/nix/nix.conf
#
# Debugging:
# XDP2_NIX_DEBUG=7 nix develop --verbose --print-build-logs
#
# Alternative commands:
# nix --extra-experimental-features 'nix-command flakes' --option eval-cache false develop
# nix --extra-experimental-features 'nix-command flakes' develop --no-write-lock-file
# nix --extra-experimental-features 'nix-command flakes' print-dev-env --json
#
# Recommended term:
# export TERM=xterm-256color
#
# To run the sample test:
# nix build .#tests.simple-parser
# ./result/bin/xdp2-test-simple-parser
#
{
  description = "XDP2 packet processing framework";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";

    # MicroVM for eBPF testing (Phase 1)
    # See: documentation/nix/microvm-implementation-phase1.md
    microvm = {
      url = "github:astro/microvm.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, flake-utils, microvm }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        lib = nixpkgs.lib;

        # Import LLVM configuration module
        # Use default LLVM version from nixpkgs (no pinning required)
        llvmConfig = import ./nix/llvm.nix { inherit pkgs lib; };
        llvmPackages = llvmConfig.llvmPackages;

        # Import packages module
        packagesModule = import ./nix/packages.nix { inherit pkgs llvmPackages; };

        # Compiler configuration
        compilerConfig = {
          cc = pkgs.gcc;
          cxx = pkgs.gcc;
          ccBin = "gcc";
          cxxBin = "g++";
        };

        # Import environment variables module
        envVars = import ./nix/env-vars.nix {
          inherit pkgs llvmConfig compilerConfig;
          packages = packagesModule;
          configAgeWarningDays = 14;
        };

        # Import package derivation (production build, assertions disabled)
        xdp2 = import ./nix/derivation.nix {
          inherit pkgs lib llvmConfig;
          inherit (packagesModule) nativeBuildInputs buildInputs;
          enableAsserts = false;
        };

        # Debug build with assertions enabled
        xdp2-debug = import ./nix/derivation.nix {
          inherit pkgs lib llvmConfig;
          inherit (packagesModule) nativeBuildInputs buildInputs;
          enableAsserts = true;
        };

        # Import development shell module
        devshell = import ./nix/devshell.nix {
          inherit pkgs lib llvmConfig compilerConfig envVars;
          packages = packagesModule;
        };

        # Import tests module (uses debug build for assertion support)
        tests = import ./nix/tests {
          inherit pkgs;
          xdp2 = xdp2-debug;  # Tests use debug build with assertions
        };

        # Convenience target to run all sample tests
        run-sample-tests = pkgs.writeShellApplication {
          name = "run-sample-tests";
          runtimeInputs = [];
          text = ''
            echo "========================================"
            echo "  XDP2 Sample Tests Runner"
            echo "========================================"
            echo ""

            # Run all tests via the combined test runner
            ${tests.all}/bin/xdp2-test-all
          '';
        };

        # =====================================================================
        # Phase 1: Packaging (x86_64 .deb only)
        # See: documentation/nix/microvm-implementation-phase1.md
        # =====================================================================
        packaging = import ./nix/packaging {
          inherit pkgs lib;
          xdp2 = xdp2;  # Use production build for distribution
        };

        # =====================================================================
        # Phase 1: MicroVM infrastructure (x86_64 only)
        # See: documentation/nix/microvm-implementation-phase1.md
        # =====================================================================
        microvms = import ./nix/microvms {
          inherit pkgs lib microvm nixpkgs;
        };

      in
      {
        # Package outputs
        packages = {
          default = xdp2;
          xdp2 = xdp2;
          xdp2-debug = xdp2-debug;  # Debug build with assertions

          # Tests (build with: nix build .#tests.simple-parser)
          tests = tests;

          # Convenience aliases for individual tests
          simple-parser-test = tests.simple-parser;
          offset-parser-test = tests.offset-parser;
          ports-parser-test = tests.ports-parser;
          flow-tracker-combo-test = tests.flow-tracker-combo;
          xdp-build-test = tests.xdp-build;

          # Run all sample tests in one go
          # Usage: nix run .#run-sample-tests
          inherit run-sample-tests;

          # ===================================================================
          # Phase 1: Packaging outputs (x86_64 .deb only)
          # See: documentation/nix/microvm-implementation-phase1.md
          # ===================================================================

          # Staging directory (for inspection/debugging)
          # Usage: nix build .#deb-staging
          deb-staging = packaging.staging.x86_64;

          # Debian package
          # Usage: nix build .#deb-x86_64
          deb-x86_64 = packaging.deb.x86_64;

          # ===================================================================
          # Phase 1: MicroVM outputs (x86_64 only)
          # See: documentation/nix/microvm-implementation-phase1.md
          # ===================================================================

          # MicroVM for x86_64 testing
          # Usage: nix build .#microvm-x86_64
          #        ./result/bin/microvm-run
          microvm-x86_64 = microvms.vms.x86_64;

          # Test runner (builds and runs VM, checks self-test)
          # Usage: nix run .#xdp2-test-phase1
          xdp2-test-phase1 = microvms.testRunner;

          # Helper scripts
          # Usage: nix run .#xdp2-vm-console
          xdp2-vm-console = microvms.connectConsole;
          xdp2-vm-serial = microvms.connectSerial;
          xdp2-vm-status = microvms.vmStatus;

          # Login helpers (interactive, with proper terminal handling)
          # Usage: nix run .#xdp2-vm-login-serial
          xdp2-vm-login-serial = microvms.loginSerial;
          xdp2-vm-login-virtio = microvms.loginVirtio;

          # Command execution helpers (run command and capture output)
          # Usage: nix run .#xdp2-vm-run-serial -- 'uname -a'
          xdp2-vm-run-serial = microvms.runCommandSerial;
          xdp2-vm-run-virtio = microvms.runCommandVirtio;

          # Expect-based helpers (reliable terminal interaction)
          # Usage: nix run .#xdp2-vm-expect-run -- 'uname -a'
          xdp2-vm-expect-run = microvms.expectRunCommand;
          xdp2-vm-debug-expect = microvms.debugVmExpect;
          xdp2-vm-expect-verify-service = microvms.expectVerifyService;

          # ===================================================================
          # Lifecycle check scripts
          # Usage: nix run .#xdp2-lifecycle-0-build
          # ===================================================================
          xdp2-lifecycle-0-build = microvms.lifecycle.checkBuild;
          xdp2-lifecycle-1-check-process = microvms.lifecycle.checkProcess;
          xdp2-lifecycle-2-check-serial = microvms.lifecycle.checkSerial;
          xdp2-lifecycle-2b-check-virtio = microvms.lifecycle.checkVirtio;
          xdp2-lifecycle-3-verify-ebpf-loaded = microvms.lifecycle.verifyEbpfLoaded;
          xdp2-lifecycle-4-verify-ebpf-running = microvms.lifecycle.verifyEbpfRunning;
          xdp2-lifecycle-5-shutdown = microvms.lifecycle.shutdown;
          xdp2-lifecycle-6-wait-exit = microvms.lifecycle.waitExit;
          xdp2-lifecycle-force-kill = microvms.lifecycle.forceKill;

          # Full lifecycle test (runs all phases)
          # Usage: nix run .#xdp2-lifecycle-full-test
          xdp2-lifecycle-full-test = microvms.lifecycle.fullTest;
        };

        # Development shell
        devShells.default = devshell;
      });
}
