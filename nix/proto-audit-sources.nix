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

  scapyPython = pkgs.python314.withPackages (ps: [ ps.scapy ]);
  tshark = pkgs.wireshark-cli;

  # Linux kernel source (include/ tree only, for UAPI header parsing)
  kernelSrc = pkgs.runCommand "linux-kernel-src-${kernelVersion}" {
    src = pkgs.linuxKernel.kernels.linux_6_12.src;
  } ''
    mkdir -p $out
    tar xf $src --strip-components=1 -C $out --wildcards '*/include/*'
  '';

  # Helper: collect all .patch files from a directory.
  patchesIn = dir:
    map (f: dir + "/${f}")
      (builtins.filter (f: pkgs.lib.hasSuffix ".patch" f)
        (builtins.attrNames (builtins.readDir dir)));
in
{
  # Linux kernel source (include/ tree only)
  inherit kernelSrc;

  # Scapy Python package (for runtime introspection via helper)
  inherit scapyPython;

  # tshark binary (Wireshark CLI)
  inherit tshark;

  # etherparse Rust crate source (for struct parsing)
  # Patched with per-protocol struct overlays (one patch per protocol)
  # for cross-source comparison. Each patch adds a single .rs file.
  etherparseSrc = pkgs.applyPatches {
    src = pkgs.fetchFromGitHub {
      owner = "JulianSchmid";
      repo = "etherparse";
      rev = "f87e17057d64cd8ba4f08e4f1a37d22e6df6d870";
      hash = "sha256-5Ng3OFI4/OcLGlNJpfJamJwzA9xNQdwu5bUUGB4m6Ic=";
    };
    patches = patchesIn ../samples/proto_audit/patches/etherparse;
  };

  # libpcap source (for gencode.c offsets and pcap/*.h struct parsing)
  # Patched with per-protocol header overlays (one patch per protocol)
  # for cross-source comparison. Each patch adds a single .h file.
  libpcapSrc = pkgs.applyPatches {
    src = pkgs.fetchFromGitHub {
      owner = "the-tcpdump-group";
      repo = "libpcap";
      rev = "ccc5817bd24fd4d6c477507b5f5a0b4194bb0058";
      hash = "sha256-V+ofdQ0jlSY85XM+6c36XV/ghGDVNkhoEN+s7KItH1M=";
    };
    patches = patchesIn ../samples/proto_audit/patches/libpcap;
  };

  # ── Auto-discovery registries (Phase 1-4) ──

  # tshark protocol registry: auto-discovered from tshark -G metadata
  # Provides ~500+ protocol entries with decode table routing information
  tsharkRegistry = pkgs.runCommand "tshark-registry" {
    nativeBuildInputs = [ tshark pkgs.python314 ];
  } ''
    mkdir -p $out
    python3 ${../samples/proto_audit/helpers/tshark_registry.py} \
      --tshark ${tshark}/bin/tshark \
      --output $out/tshark_registry.json
  '';

  # Scapy protocol registry: all Packet subclasses from scapy.contrib + scapy.layers
  # Provides ~300+ protocol class→module mappings
  scapyRegistry = pkgs.runCommand "scapy-registry" {
    nativeBuildInputs = [ scapyPython ];
  } ''
    mkdir -p $out
    python3 ${../samples/proto_audit/helpers/scapy_dump.py} \
      --discover-all > $out/scapy_registry.json
  '';

  # Kernel UAPI struct registry: protocol header structs from include/uapi/linux/
  # Provides ~50+ struct definitions with header file paths
  kernelRegistry = pkgs.runCommand "kernel-registry" {
    nativeBuildInputs = [ pkgs.python314 ];
    inherit kernelSrc;
  } ''
    mkdir -p $out
    python3 ${../samples/proto_audit/helpers/kernel_scan.py} \
      --kernel-src $kernelSrc \
      --output $out/kernel_registry.json
  '';

  # PCAP templates for edge-case protocols (TLS, HTTP/2, etc.)
  # These protocols can't be auto-routed via standard dispatch tables.
  pcapTemplates = pkgs.runCommand "pcap-templates" {
    nativeBuildInputs = [ pkgs.python314 ];
  } ''
    mkdir -p $out
    python3 ${../samples/proto_audit/helpers/gen_pcap_templates.py} \
      --output-dir $out
  '';
}
