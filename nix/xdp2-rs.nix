# nix/xdp2-rs.nix
#
# Rust reimplementation of XDP2 — build, test, and analysis targets.
#
# Provides first-class Nix targets for the xdp2-rs Cargo workspace:
#   nix build .#xdp2-rs                  — production build
#   nix build .#xdp2-rs-test             — cargo test (unit + integration)
#   nix build .#xdp2-rs-clippy           — cargo clippy (lint, deny warnings)
#   nix build .#xdp2-rs-fmt-check        — cargo fmt --check (formatting)
#   nix build .#xdp2-rs-doc              — cargo doc (documentation build)
#   nix build .#xdp2-rs-golden           — golden tests vs C parser output
#
# Development:
#   cd xdp2-rs && cargo check --workspace
#   cargo test --workspace
#   cargo clippy --workspace --all-targets -- -D warnings
#

{ pkgs, xdp2 ? null }:

let
  src = ../xdp2-rs;

  # Base hash — set to lib.fakeHash and build to get correct hash
  cargoHash = "sha256-xhqc7DrgucPNyVY+T06Pr7wRhREfqCzDgU+NPu8oYHs=";

  commonArgs = {
    pname = "xdp2-rs";
    version = "0.1.0";
    inherit src cargoHash;
    nativeBuildInputs = [ pkgs.pkg-config ];
    meta = {
      description = "Rust reimplementation of the XDP2 packet parsing framework";
      license = pkgs.lib.licenses.bsd2;
    };
  };
in
{
  # ── Production build ─────────────────────────────────────────────
  build = pkgs.rustPlatform.buildRustPackage commonArgs;

  # ── cargo test — full test suite ─────────────────────────────────
  test = pkgs.rustPlatform.buildRustPackage (commonArgs // {
    pname = "xdp2-rs-test";
    # Pass paths to C test data for golden/integration tests
    XDP2_C_HEADERS = "${../src/include}";
    XDP2_TEST_DATA = "${../src/test/parser}";
    # doCheck defaults to true — runs `cargo test` in checkPhase
  });

  # ── cargo clippy — lint with deny warnings ───────────────────────
  clippy = pkgs.rustPlatform.buildRustPackage (commonArgs // {
    pname = "xdp2-rs-clippy";
    nativeBuildInputs = commonArgs.nativeBuildInputs ++ [ pkgs.clippy ];
    buildPhase = ''
      export HOME=$(mktemp -d)
      cargo clippy --workspace --all-targets -- -D warnings
    '';
    installPhase = ''
      mkdir -p $out
      echo "clippy: all checks passed" > $out/clippy.txt
    '';
    doCheck = false;
  });

  # ── cargo fmt --check — formatting verification ──────────────────
  fmt-check = pkgs.rustPlatform.buildRustPackage (commonArgs // {
    pname = "xdp2-rs-fmt-check";
    nativeBuildInputs = commonArgs.nativeBuildInputs ++ [ pkgs.rustfmt ];
    buildPhase = ''
      export HOME=$(mktemp -d)
      cargo fmt --check --all
    '';
    installPhase = ''
      mkdir -p $out
      echo "fmt: all files formatted" > $out/fmt.txt
    '';
    doCheck = false;
  });

  # ── cargo doc — build documentation ──────────────────────────────
  doc = pkgs.rustPlatform.buildRustPackage (commonArgs // {
    pname = "xdp2-rs-doc";
    buildPhase = ''
      export HOME=$(mktemp -d)
      cargo doc --workspace --no-deps
    '';
    installPhase = ''
      mkdir -p $out
      cp -r target/doc $out/
    '';
    doCheck = false;
  });

  # ── Golden tests — compare Rust vs C parser output ───────────────
  # This will be fully implemented in Phase 2 when protocol definitions
  # are complete enough to parse real packets.
  golden = pkgs.runCommand "xdp2-rs-golden" {
    nativeBuildInputs = [
      # Phase 2: add xdp2-rs test binary and xdp2 C test binaries here
    ];
  } ''
    mkdir -p $out

    # Phase 2 implementation:
    # 1. Run C parser on test-in.raw / test-in.pcap
    # 2. Run Rust parser on same inputs
    # 3. diff outputs
    echo "Golden test placeholder — Phase 2" > $out/golden-diff.txt
    echo "PASS (placeholder)" > $out/summary.txt
  '';
}
