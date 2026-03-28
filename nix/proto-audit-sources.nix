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

  # etherparse Rust crate source (for struct parsing)
  etherparseSrc = pkgs.fetchFromGitHub {
    owner = "JulianSchmid";
    repo = "etherparse";
    rev = "f87e17057d64cd8ba4f08e4f1a37d22e6df6d870";
    hash = "sha256-5Ng3OFI4/OcLGlNJpfJamJwzA9xNQdwu5bUUGB4m6Ic=";
  };

  # libpcap source (for gencode.c offsets and pcap/*.h struct parsing)
  libpcapSrc = pkgs.fetchFromGitHub {
    owner = "the-tcpdump-group";
    repo = "libpcap";
    rev = "ccc5817bd24fd4d6c477507b5f5a0b4194bb0058";
    hash = "sha256-V+ofdQ0jlSY85XM+6c36XV/ghGDVNkhoEN+s7KItH1M=";
  };
}
