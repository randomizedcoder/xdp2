# nix/proto-audit-sources.nix
#
# Pinned external sources for proto-audit.
#
# Provides:
#   - Linux kernel UAPI headers (for struct parsing)
#   - Scapy source (tracks nixpkgs version)
#   - tshark binary (wireshark-cli)
#   - Wireshark dissector source (for deep analysis)
#
# Usage:
#   let sources = import ./proto-audit-sources.nix { inherit pkgs; };
#   sources.kernelSrc   # → /nix/store/.../linux-6.12.tar.xz
#   sources.scapySrc    # → /nix/store/.../scapy-src
#   sources.tshark      # → /nix/store/.../bin/tshark
#
# To update kernel version:
#   1. Change kernelVersion below
#   2. Set kernelHash to pkgs.lib.fakeHash
#   3. Run `nix build .#proto-audit` — fails with real hash
#   4. Replace kernelHash with the real hash
#

{ pkgs }:

let
  kernelVersion = "6.12";
in
{
  # Linux kernel source (for UAPI header parsing)
  # Follows the same pattern as kern-bpf-flow.nix
  kernelSrc = pkgs.fetchurl {
    url = "mirror://kernel/linux/kernel/v6.x/linux-${kernelVersion}.tar.xz";
    # Set to pkgs.lib.fakeHash to get real hash on first build
    hash = pkgs.lib.fakeHash;
  };

  # Scapy source — tracks whatever version nixpkgs provides
  scapySrc = pkgs.python314Packages.scapy.src;

  # Scapy Python package (for runtime introspection via helper)
  scapyPython = pkgs.python314.withPackages (ps: [ ps.scapy ]);

  # tshark binary (Wireshark CLI)
  tshark = pkgs.wireshark-cli;

  # Wireshark source (optional, for dissector source analysis)
  # Uncomment and set hash when needed:
  # wiresharkSrc = pkgs.fetchFromGitLab {
  #   repo = "wireshark";
  #   owner = "wireshark";
  #   tag = "v${pkgs.wireshark-cli.version}";
  #   hash = pkgs.lib.fakeHash;
  # };
}
