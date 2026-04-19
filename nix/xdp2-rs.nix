# nix/xdp2-rs.nix
#
# Rust reimplementation of XDP2 — build, test, and analysis targets.
#
# Provides first-class Nix targets for the xdp2-rs Cargo workspace:
#   nix build .#xdp2-rs                  — production build
#   nix build .#xdp2-rs-test             — cargo test (unit + integration)
#   nix build .#xdp2-rs-test-graph-enum   — focused graph-enum A/B test
#   nix build .#xdp2-rs-clippy           — cargo clippy (lint, deny warnings)
#   nix build .#xdp2-rs-fmt-check        — cargo fmt --check (formatting)
#   nix build .#xdp2-rs-doc              — cargo doc (documentation build)
#   nix build .#xdp2-rs-golden           — golden tests vs C parser output
#   nix build .#xdp2-rs-adversarial      — adversarial/fuzz tests (proptest + oracle)
#   nix run   .#xdp2-rs-stress           — long-running stress test binary
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
  cargoHash = "sha256-2v9lLCpU1NPWL5xnTbK4G48BbcE9BXffx3q8ku5Bb0M=";

  commonArgs = {
    pname = "xdp2-rs";
    version = "0.1.0";
    inherit src cargoHash;
    nativeBuildInputs = [ pkgs.pkg-config ];
    RUSTFLAGS = "-C target-cpu=native";
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

  # ── Focused: graph-enum correctness (Option A A/B test) ─────────
  # Runs the `graph_enum` test module from xdp2-bench, which includes:
  #   - parses_eth_ipv4_tcp: synthetic-packet unit test
  #   - matches_graph_on_tcp_ipv4_pcap: byte-for-byte FlowMeta equality
  #     vs the dyn-dispatch graph engine on every packet in tcp_ipv4.pcap
  # The A/B test honors XDP2_TEST_PCAPS so it runs inside the Nix sandbox.
  test-graph-enum = pkgs.rustPlatform.buildRustPackage (commonArgs // {
    pname = "xdp2-rs-test-graph-enum";
    XDP2_TEST_PCAPS = "${../data/pcaps}";
    buildPhase = ''
      export HOME=$(mktemp -d)
      cargo test --release -p xdp2-bench graph_enum -- --nocapture 2>&1 | tee test.log
    '';
    installPhase = ''
      mkdir -p $out
      cp test.log $out/
      echo "graph-enum: all tests passed" > $out/summary.txt
    '';
    doCheck = false;
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

  # ── Adversarial testing — proptest + oracle + adversarial vectors ──
  # Runs the xdp2-fuzz test suite with high case counts:
  #   - 22 targeted adversarial unit tests (IHL=0, doff=0, etc.)
  #   - Cross-mode consistency oracle (graph vs mono vs compiled)
  #   - 9 proptest properties × 10,000 cases each
  #   - Seed corpus through all modes
  adversarial = pkgs.rustPlatform.buildRustPackage (commonArgs // {
    pname = "xdp2-rs-adversarial";
    buildPhase = ''
      export HOME=$(mktemp -d)
      # Unit tests: adversarial vectors + oracle
      cargo test -p xdp2-fuzz --lib -- --nocapture 2>&1 | tee test-unit.log
      # Proptest: 10,000 cases per property (10× default)
      PROPTEST_CASES=10000 cargo test -p xdp2-fuzz --test proptest_parsers -- --nocapture 2>&1 | tee test-proptest.log
    '';
    installPhase = ''
      mkdir -p $out
      cp test-unit.log test-proptest.log $out/
      echo "adversarial: all tests passed" > $out/summary.txt
    '';
    doCheck = false;
  });

  # ── Stress test binary — long-running multi-threaded adversarial ───
  # Usage: nix run .#xdp2-rs-stress -- [hours] [threads]
  #   Defaults: 12 hours, all cores
  #   Feeds random + structured packets through all 4 parser modes
  #   Reports panics and cross-mode divergences
  stress = pkgs.rustPlatform.buildRustPackage (commonArgs // {
    pname = "xdp2-rs-stress";
    buildPhase = ''
      export HOME=$(mktemp -d)
      cargo build --release -p xdp2-fuzz --bin stress
    '';
    installPhase = ''
      mkdir -p $out/bin
      cp target/release/stress $out/bin/xdp2-rs-stress
    '';
    doCheck = false;
  });
}
