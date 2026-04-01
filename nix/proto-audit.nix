# nix/proto-audit.nix
#
# Build the proto-audit Rust tool using nixpkgs' rustPlatform.
#
# Usage:
#   nix build .#proto-audit
#   nix run .#proto-audit -- list
#   nix run .#proto-audit -- scan --proto-defs-dir src/include/xdp2/proto_defs
#
# Development:
#   cd samples/proto_audit && cargo build
#   cargo test
#

{ pkgs, protoAuditSources }:

pkgs.rustPlatform.buildRustPackage {
  pname = "proto-audit";
  version = "0.1.0";

  src = ../samples/proto_audit;

  cargoHash = "sha256-twQAUSdqZs+NGsYvRN54r1y5cQMZRHwsMxGK57thBmY=";

  nativeBuildInputs = [ pkgs.pkg-config ];

  postInstall = ''
    mkdir -p $out/share/proto-audit
    cp ${../samples/proto_audit/helpers/scapy_dump.py} $out/share/proto-audit/scapy_dump.py
    cp ${../samples/proto_audit/helpers/tshark_registry.py} $out/share/proto-audit/tshark_registry.py
    cp ${../samples/proto_audit/helpers/kernel_scan.py} $out/share/proto-audit/kernel_scan.py
    cp ${../samples/proto_audit/helpers/gen_pcap_templates.py} $out/share/proto-audit/gen_pcap_templates.py
  '';

  meta = {
    description = "Multi-source protocol definition audit and generation tool for XDP2";
    license = pkgs.lib.licenses.bsd2;
  };
}
