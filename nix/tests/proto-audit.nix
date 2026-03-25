# nix/tests/proto-audit.nix
#
# Test derivation for proto-audit.
#
# Runs cargo test inside a Nix build to validate IR types, extractors,
# comparator, and generator.
#
# Usage:
#   nix build .#tests.proto-audit
#

{ pkgs, proto-audit-src ? ../../samples/proto_audit }:

pkgs.rustPlatform.buildRustPackage {
  pname = "proto-audit-test";
  version = "0.1.0";

  src = proto-audit-src;

  # Set to pkgs.lib.fakeHash on first build
  cargoHash = pkgs.lib.fakeHash;

  # Run tests instead of building
  checkPhase = ''
    cargo test --release
  '';

  # Don't install anything — this is test-only
  installPhase = ''
    mkdir -p $out
    echo "proto-audit: all tests passed" > $out/result.txt
  '';

  meta = {
    description = "Proto-audit test suite";
  };
}
