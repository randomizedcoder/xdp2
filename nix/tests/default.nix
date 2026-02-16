# nix/tests/default.nix
#
# Test definitions for XDP2 samples
#
# This module exports test derivations that verify XDP2 samples work correctly.
# Tests are implemented as writeShellApplication scripts that can be run
# after building with `nix build`.
#
# Usage:
#   nix build .#tests.simple-parser && ./result/bin/xdp2-test-simple-parser
#   nix build .#tests.all && ./result/bin/xdp2-test-all
#
# Future: VM-based tests for XDP samples that require kernel access
#

{ pkgs, xdp2 }:

{
  # Parser sample tests (userspace, no root required)
  simple-parser = import ./simple-parser.nix { inherit pkgs xdp2; };
  offset-parser = import ./offset-parser.nix { inherit pkgs xdp2; };
  ports-parser = import ./ports-parser.nix { inherit pkgs xdp2; };

  # Debug test for diagnosing optimized parser issues
  simple-parser-debug = import ./simple-parser-debug.nix { inherit pkgs xdp2; };

  # XDP sample tests
  flow-tracker-combo = import ./flow-tracker-combo.nix { inherit pkgs xdp2; };

  # XDP build verification (compile-only, no runtime test)
  xdp-build = import ./xdp-build.nix { inherit pkgs xdp2; };

  # Combined test runner
  all = pkgs.writeShellApplication {
    name = "xdp2-test-all";
    runtimeInputs = [];
    text = ''
      echo "=== Running all XDP2 tests ==="
      echo ""

      # Phase 1: Parser sample tests
      echo "=== Phase 1: Parser Samples ==="
      echo ""

      # Run simple-parser test
      ${import ./simple-parser.nix { inherit pkgs xdp2; }}/bin/xdp2-test-simple-parser

      echo ""

      # Run offset-parser test
      ${import ./offset-parser.nix { inherit pkgs xdp2; }}/bin/xdp2-test-offset-parser

      echo ""

      # Run ports-parser test
      ${import ./ports-parser.nix { inherit pkgs xdp2; }}/bin/xdp2-test-ports-parser

      echo ""

      # Phase 2: XDP sample tests
      echo "=== Phase 2: XDP Samples ==="
      echo ""

      # Run flow-tracker-combo test (userspace + XDP build)
      ${import ./flow-tracker-combo.nix { inherit pkgs xdp2; }}/bin/xdp2-test-flow-tracker-combo

      echo ""

      # Run XDP build verification tests
      ${import ./xdp-build.nix { inherit pkgs xdp2; }}/bin/xdp2-test-xdp-build

      echo ""
      echo "=== All tests completed ==="
    '';
  };
}
