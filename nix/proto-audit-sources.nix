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
  # ── Source Version Tracking (Phase 6.1) ──
  # Update these when bumping upstream sources.
  kernelVersion = "6.12";
  etherparseRev = "f87e17057d64cd8ba4f08e4f1a37d22e6df6d870";  # etherparse git rev
  libpcapRev = "ccc5817bd24fd4d6c477507b5f5a0b4194bb0058";  # libpcap git rev
  packetlifeRev = "4a77a47e71d48b40faafac6a84589fdcc496fab1";  # packetlife-backup git rev

  scapyPython = pkgs.python314.withPackages (ps: [ ps.scapy ]);
  tshark = pkgs.wireshark-cli;

  # Linux kernel source (include/ tree only, for UAPI header parsing)
  kernelSrc = pkgs.runCommand "linux-kernel-src-${kernelVersion}" {
    src = pkgs.linuxKernel.kernels.linux_6_12.src;
  } ''
    mkdir -p $out
    tar xf $src --strip-components=1 -C $out --wildcards '*/include/*'
  '';

  # PacketLife.net captures: ~100 single-protocol PCAPs (clean, one protocol each)
  packetlifePcaps = pkgs.fetchFromGitHub {
    owner = "epiecs";
    repo = "packetlife-backup";
    rev = packetlifeRev;
    hash = "sha256-9ruDO6fB/Smtx5tsHXCHF/EUPI7/Y0naxgrrJH1PFI8=";
  };

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
      rev = etherparseRev;
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
      rev = libpcapRev;
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

  # ── IANA registries for dispatch table validation ──

  ianaProtocolNumbers = pkgs.fetchurl {
    url = "https://www.iana.org/assignments/protocol-numbers/protocol-numbers-1.csv";
    hash = "sha256-5wTuFOaTR2gbOmJxrwIZWpdBI2B0/DEUSeuwMhAb3yw=";
  };

  ianaEthertypes = pkgs.fetchurl {
    url = "https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers-1.csv";
    hash = "sha256-O0yeuvYiUB+LjvDsDSLBQziyDPatkTF/AJN3ceiCz0w=";
  };

  # Note: service-name-port-numbers CSV is ~7MB and URL may change.
  # Pass --service-names only when available.

  # Parse IANA CSVs into unified JSON at build time
  ianaRegistries = pkgs.runCommand "iana-registries" {
    nativeBuildInputs = [ pkgs.python314 ];
    inherit ianaProtocolNumbers ianaEthertypes;
  } ''
    mkdir -p $out
    python3 ${../samples/proto_audit/helpers/parse_iana.py} \
      --protocol-numbers $ianaProtocolNumbers \
      --ethertypes $ianaEthertypes \
      --output-dir $out
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

  # ── Public PCAP collections for cross-source audit ──

  # Merged PCAP corpus: runs tshark -T pdml over all public PCAPs at build time,
  # producing a pre-extracted JSON cache of protocol fields for cross-source audit.
  pcapCorpus = pkgs.runCommand "pcap-corpus" {
    nativeBuildInputs = [ tshark pkgs.python314 ];
    inherit packetlifePcaps;
  } ''
    mkdir -p $out/pdml

    echo "Extracting PDML from PacketLife PCAPs..."
    found=0
    extracted=0
    for f in $packetlifePcaps/captures/*.cap \
             $packetlifePcaps/captures/*.pcap \
             $packetlifePcaps/captures/*.pcapng; do
      [ -f "$f" ] || continue
      found=$((found + 1))
      base=$(basename "$f" | sed 's/\.[^.]*$//')
      # Extract up to 5 packets per file, ignore errors (some files may be malformed)
      if ${tshark}/bin/tshark -r "$f" -T pdml -c 5 > "$out/pdml/$base.xml" 2>/dev/null; then
        if [ -s "$out/pdml/$base.xml" ]; then
          extracted=$((extracted + 1))
        else
          rm -f "$out/pdml/$base.xml"
        fi
      else
        rm -f "$out/pdml/$base.xml"
      fi
    done
    echo "PacketLife: found $found files, extracted $extracted PDML files"

    # Build summary: list all unique dissector names found across all PDML files
    echo "Building protocol summary..."
    python3 ${../samples/proto_audit/helpers/summarize_corpus.py} \
      --pdml-dir $out/pdml \
      --output $out/corpus_summary.json
  '';

  # Source version metadata (for regression tracking and audit reports)
  sourceVersions = {
    kernel = kernelVersion;
    etherparse = etherparseRev;
    libpcap = libpcapRev;
    packetlife = packetlifeRev;
    tshark = tshark.version or "unknown";
    scapy = scapyPython.version or "unknown";
  };
}
