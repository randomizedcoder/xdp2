# nix/proto-audit-sources.nix
#
# Pinned external sources for proto-audit.
#
# Provides:
#   - Linux kernel UAPI headers (for struct parsing)
#   - Scapy Python environment (for runtime introspection)
#   - tshark binary (wireshark-cli)
#
# Usage:
#   let sources = import ./proto-audit-sources.nix { inherit pkgs; };
#   sources.kernelSrc   # → /nix/store/.../linux-kernel-src (include/ only)
#   sources.scapyPython # → /nix/store/.../bin/python3  (with scapy)
#   sources.tshark      # → /nix/store/.../bin/tshark
#

{ pkgs }:

let
  kernelVersion = "6.12";
in
{
  # Linux kernel source (include/ tree only, for UAPI header parsing)
  # Uses the same kernel source as nixpkgs linux_6_12, avoiding manual hash management.
  kernelSrc = pkgs.runCommand "linux-kernel-src-${kernelVersion}" {
    src = pkgs.linuxKernel.kernels.linux_6_12.src;
  } ''
    mkdir -p $out
    tar xf $src --strip-components=1 -C $out --wildcards '*/include/*'
  '';

  # Scapy Python package (for runtime introspection via helper)
  scapyPython = pkgs.python314.withPackages (ps: [ ps.scapy ]);

  # tshark binary (Wireshark CLI)
  tshark = pkgs.wireshark-cli;
}
