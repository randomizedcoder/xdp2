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
  wiresharkSamplesRev = "4131f845f5b2d319a2cb2014fe2738889adcd889";  # briliant-ben/SampleCaptures git rev
  kaitaiFormatsRev = "07429db0a5c73dbedf207c8ea8d6a7ad82cb53be";  # kaitai-io/kaitai_struct_formats git rev
  omiCStructsRev = "9d6db5270847c60cefefc2bd7e1238d828701545";  # Open-Markets-Initiative/c-structs git rev
  omiDataPacketsRev = "5e0dfb113c7c7160b685b6a6d52ce19917915c8f";  # Open-Markets-Initiative/omi-data-packets git rev
  omiWiresharkLuaRev = "ab009faf449b245a4d140d1b0d09fe9cc38ba65c";  # Open-Markets-Initiative/wireshark-lua git rev

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

  # Wireshark sample captures: community-curated collection from the Wireshark wiki
  # Covers ~200+ protocols including DHCP, DNS, RTP, SIP, MQTT, Modbus, etc.
  wiresharkSamples = pkgs.fetchFromGitHub {
    owner = "briliant-ben";
    repo = "SampleCaptures";
    rev = wiresharkSamplesRev;
    hash = "sha256-ROsdhlOMS8+zEeP1yO1ZxHxUvtUzvcHRCL6QUEO7g1k=";
  };

  # Kaitai Struct format specifications: independent protocol definitions in YAML
  # Covers ~25 network protocols (Ethernet, IPv4, IPv6, TCP, UDP, ICMP, DNS, TLS, RTP, etc.)
  # Licensed CC0-1.0, truly independent source for cross-verification
  kaitaiFormats = pkgs.fetchFromGitHub {
    owner = "kaitai-io";
    repo = "kaitai_struct_formats";
    rev = kaitaiFormatsRev;
    hash = "sha256-CP75xJjU/uD+f6/htodGtiywqcac2bbkUKpeHPvagcU=";
  };

  # Open Markets Initiative c-structs: auto-generated packed C struct headers for
  # 231 financial exchange binary protocols (ITCH, OUCH, PITCH, SBE, EOBI, etc.)
  # across 22 exchange directories (Nasdaq, CME, CBOE, NYSE, Eurex, ...).
  # Independent ninth source for proto-audit's trading-protocol coverage.
  omiCStructs = pkgs.fetchFromGitHub {
    owner = "Open-Markets-Initiative";
    repo = "c-structs";
    rev = omiCStructsRev;
    hash = "sha256-7HvigLQDStLMoQEpE59iEgeH7kJ9Cf1Z8xSpzwHaFPg=";
  };

  # Open Markets Initiative data packets: 370 real Ethernet/UDP/TCP PCAPs covering
  # 66 exchange protocol feeds and 275 unique message types. Used (in a later
  # phase) as corpus input once OMI Lua dissectors are loaded into tshark.
  omiDataPackets = pkgs.fetchFromGitHub {
    owner = "Open-Markets-Initiative";
    repo = "omi-data-packets";
    rev = omiDataPacketsRev;
    hash = "sha256-A793fPDAdKQObWFsST6vXClHk3Tsr5QH4nhRmBs3Oac=";
  };

  # Open Markets Initiative Wireshark Lua dissectors: 459 Lua dissector scripts
  # that let tshark parse OMI trading protocols from real PCAPs. Required to
  # produce meaningful PDML (without them, OMI payloads are opaque "data").
  omiWiresharkLua = pkgs.fetchFromGitHub {
    owner = "Open-Markets-Initiative";
    repo = "wireshark-lua";
    rev = omiWiresharkLuaRev;
    hash = "sha256-ez8WqldfJKiqNAe9YKmxEQOQUNeZGFuyHZPDjst0yFs=";
  };

  # Helper: collect all .patch files from a directory.
  patchesIn = dir:
    map (f: dir + "/${f}")
      (builtins.filter (f: pkgs.lib.hasSuffix ".patch" f)
        (builtins.attrNames (builtins.readDir dir)));

  # IANA registry CSVs (fetched at eval time, used by ianaRegistries derivation)
  ianaProtocolNumbers = pkgs.fetchurl {
    url = "https://www.iana.org/assignments/protocol-numbers/protocol-numbers-1.csv";
    hash = "sha256-5wTuFOaTR2gbOmJxrwIZWpdBI2B0/DEUSeuwMhAb3yw=";
  };

  ianaEthertypes = pkgs.fetchurl {
    url = "https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers-1.csv";
    hash = "sha256-O0yeuvYiUB+LjvDsDSLBQziyDPatkTF/AJN3ceiCz0w=";
  };
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

  # Kaitai Struct format specs (network/ directory has protocol definitions)
  inherit kaitaiFormats;

  # Open Markets Initiative c-structs (231 packed C headers for trading protocols)
  inherit omiCStructs;

  # Open Markets Initiative data packets (370 real PCAPs for trading protocols)
  inherit omiDataPackets;

  # Open Markets Initiative Wireshark Lua dissectors (459 scripts)
  inherit omiWiresharkLua;

  # Suricata Rust app-layer parsers: independent protocol definitions
  # Covers ~40 protocols (DNS, HTTP, TLS, SSH, DHCP, NTP, MQTT, etc.)
  # Extracted from Suricata's Rust source tree (rust/src/<proto>/)
  suricataSrc = pkgs.runCommand "suricata-rust-src" {
    src = pkgs.suricata.src;
  } ''
    tar xf $src --strip-components=1 suricata-*/rust/src
    mkdir -p $out
    cp -r rust/src/* $out/
  '';

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
  # Uses --discover-all-rich for field names, bind_layers, and docstrings
  scapyRegistry = pkgs.runCommand "scapy-registry" {
    nativeBuildInputs = [ scapyPython ];
  } ''
    mkdir -p $out
    python3 ${../samples/proto_audit/helpers/scapy_dump.py} \
      --discover-all-rich > $out/scapy_registry.json
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

  inherit ianaProtocolNumbers ianaEthertypes;

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
    inherit packetlifePcaps wiresharkSamples omiDataPackets;
  } ''
    mkdir -p $out/pdml

    # Helper: extract PDML from a set of PCAP files
    extract_pdml() {
      local label="$1"; shift
      local found=0 extracted=0
      for f in "$@"; do
        [ -f "$f" ] || continue
        found=$((found + 1))
        base=$(basename "$f" | sed 's/\.[^.]*$//')
        # Prefix with source to avoid collisions between corpora
        local outname="''${label}_''${base}"
        # Extract up to 5 packets per file, ignore errors (some files may be malformed)
        if ${tshark}/bin/tshark -r "$f" -T pdml -c 5 > "$out/pdml/$outname.xml" 2>/dev/null; then
          if [ -s "$out/pdml/$outname.xml" ]; then
            extracted=$((extracted + 1))
          else
            rm -f "$out/pdml/$outname.xml"
          fi
        else
          rm -f "$out/pdml/$outname.xml"
        fi
      done
      echo "$label: found $found files, extracted $extracted PDML files"
    }

    echo "Extracting PDML from PacketLife PCAPs..."
    extract_pdml "packetlife" $packetlifePcaps/pcaps/*.cap \
                              $packetlifePcaps/pcaps/*.pcap \
                              $packetlifePcaps/pcaps/*.pcapng

    echo "Extracting PDML from Wireshark sample captures..."
    # Wireshark samples are organized in subdirectories
    find $wiresharkSamples -type f \( -name '*.pcap' -o -name '*.pcapng' -o -name '*.cap' \) > /tmp/ws_files.txt
    echo "  Found $(wc -l < /tmp/ws_files.txt) files in Wireshark samples"
    extract_pdml "wireshark" $(cat /tmp/ws_files.txt)

    echo "Extracting PDML from OMI trading PCAPs..."
    # OMI sample PCAPs (Ethernet/UDP/TCP framing — trading payload stays opaque
    # without Lua dissectors). Each OMI protocol is extracted with its matching
    # Lua dissector on-demand by `extract --source tshark` in Phase 2; here we
    # just get network-layer PDML for corpus stats and ensure reproducible
    # coverage of real exchange traffic framing.
    find $omiDataPackets -type f \( -name '*.pcap' -o -name '*.pcapng' \) > /tmp/omi_files.txt
    echo "  Found $(wc -l < /tmp/omi_files.txt) files in OMI data packets"
    extract_pdml "omi" $(cat /tmp/omi_files.txt)

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
    wiresharkSamples = wiresharkSamplesRev;
    omiCStructs = omiCStructsRev;
    omiDataPackets = omiDataPacketsRev;
    omiWiresharkLua = omiWiresharkLuaRev;
    tshark = tshark.version or "unknown";
    scapy = scapyPython.version or "unknown";
  };
}
