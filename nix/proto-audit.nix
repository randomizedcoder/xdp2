# nix/proto-audit.nix
#
# Build the proto-audit Rust tool using nixpkgs' rustPlatform.
#
# Usage:
#   nix build .#proto-audit
#   ./result/bin/proto-audit list
#   ./result/bin/proto-audit scan --proto-defs-dir src/include/xdp2/proto_defs
#
# Development:
#   cd samples/proto_audit && cargo build
#   cargo test
#

{ pkgs, protoAuditSources }:

pkgs.rustPlatform.buildRustPackage {
  pname = "proto-audit";
  version = "0.1.0";

  src = ../../samples/proto_audit;

  # Set to pkgs.lib.fakeHash on first build to get the real hash
  cargoHash = pkgs.lib.fakeHash;

  nativeBuildInputs = [ pkgs.pkg-config ];

  # Make external sources available at runtime
  postInstall = ''
    mkdir -p $out/share/proto-audit

    # Install the scapy helper script
    cp ${../../samples/proto_audit/helpers/scapy_dump.py} $out/share/proto-audit/scapy_dump.py

    # Create wrapper scripts that include runtime dependencies
    mkdir -p $out/libexec

    # Scapy extraction wrapper
    cat > $out/libexec/proto-audit-scapy <<'WRAPPER'
    #!/bin/sh
    exec ${protoAuditSources.scapyPython}/bin/python3 \
      $out/share/proto-audit/scapy_dump.py "$@"
    WRAPPER
    chmod +x $out/libexec/proto-audit-scapy
  '';

  meta = {
    description = "Multi-source protocol definition audit and generation tool for XDP2";
    license = pkgs.lib.licenses.bsd2;
  };
}
