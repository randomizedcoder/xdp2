# nix/proto-audit-sources.nix
#
# Pinned external sources for proto-audit.
#
# Each source provides packed C structs, protocol definitions, or runtime
# tools that proto-audit uses for multi-source cross-verification of
# protocol field definitions.
#
# ── How to add a new source ──
#
# Adding a new external source requires changes in three places:
#
# 1. THIS FILE (nix/proto-audit-sources.nix):
#    - Add a derivation that extracts the relevant source files from a
#      nixpkgs package. Use `pkgs.runCommand` to extract only what's
#      needed (e.g., header files), not the full source tree.
#    - Export the derivation in the `in { ... }` block at the bottom.
#    - Add a version entry to `sourceVersions` for tracking.
#
# 2. flake.nix (the writeShellApplication wrapper):
#    - Add a `PROTO_AUDIT_<NAME>` env var export that points to the
#      nix store path, following the existing pattern:
#        export PROTO_AUDIT_FOO_SRC="''${PROTO_AUDIT_FOO_SRC:-${protoAuditSources.fooSrc}}"
#    - This allows local override via env var, with nix default.
#
# 3. samples/proto_audit/src/main.rs (SourcePaths struct):
#    - Add a field with `#[arg(long, env = "PROTO_AUDIT_FOO_SRC")]`
#    - This makes the path available to all Rust extractors.
#
# Optionally, if the source contains C structs parseable by the kernel
# extractor (packed structs with standard C types):
#
# 4. samples/proto_audit/src/name_mapping/table.rs:
#    - Add `.dpdk("struct_name", "header.h")` or similar method chain
#      entries mapping canonical protocol names to source-specific
#      struct names and header file paths.
#
# 5. samples/proto_audit/src/commands.rs (extract/build_rich_ir):
#    - Add an extraction path that reads headers from the new source,
#      reusing the kernel C struct parser where possible.
#
# Example: adding DPDK as a source
#   1. Here: dpdkSrc extracts lib/net/*.h from pkgs.dpdk.src
#   2. flake.nix: export PROTO_AUDIT_DPDK_SRC=...
#   3. main.rs: dpdk_src: Option<PathBuf> with env = "PROTO_AUDIT_DPDK_SRC"
#   4. table.rs: .dpdk("rte_gre_hdr", "rte_gre.h") on the GRE entry
#   5. commands.rs: "dpdk" extractor path using kernel::parse_kernel_struct
#
# Provides:
#   - Linux kernel source (include/ + drivers/net/ for struct parsing)
#   - DPDK net headers (packed protocol structs for ~28 protocols)
#   - nDPI headers (deep packet inspection, ~25 packed protocol structs)
#   - pppd source (PPP control protocol headers and constants)
#   - Scapy Python environment (for runtime introspection)
#   - tshark binary (wireshark-cli)
#   - etherparse, libpcap, kaitai, suricata, OMI sources
#
# Usage:
#   let sources = import ./proto-audit-sources.nix { inherit pkgs; };
#   sources.kernelSrc   # → /nix/store/.../linux-kernel-src
#   sources.dpdkSrc     # → /nix/store/.../dpdk-net-headers
#   sources.ndpiSrc     # → /nix/store/.../ndpi-headers
#   sources.pppdSrc     # → /nix/store/.../pppd-src
#   sources.scapyPython # → /nix/store/.../bin/python3  (with scapy)
#   sources.tshark      # → /nix/store/.../bin/tshark
#

{ pkgs }:

let
  # ── Source Version Tracking (Phase 6.1) ──
  # Update these when bumping upstream sources.
  kernelVersion = "7.0";
  etherparseRev = "f87e17057d64cd8ba4f08e4f1a37d22e6df6d870";  # etherparse git rev
  libpcapRev = "ccc5817bd24fd4d6c477507b5f5a0b4194bb0058";  # libpcap git rev
  packetlifeRev = "4a77a47e71d48b40faafac6a84589fdcc496fab1";  # packetlife-backup git rev
  wiresharkSamplesRev = "4131f845f5b2d319a2cb2014fe2738889adcd889";  # briliant-ben/SampleCaptures git rev
  kaitaiFormatsRev = "07429db0a5c73dbedf207c8ea8d6a7ad82cb53be";  # kaitai-io/kaitai_struct_formats git rev
  omiCStructsRev = "9d6db5270847c60cefefc2bd7e1238d828701545";  # Open-Markets-Initiative/c-structs git rev
  omiDataPacketsRev = "5e0dfb113c7c7160b685b6a6d52ce19917915c8f";  # Open-Markets-Initiative/omi-data-packets git rev
  omiWiresharkLuaRev = "ab009faf449b245a4d140d1b0d09fe9cc38ba65c";  # Open-Markets-Initiative/wireshark-lua git rev
  xtcp2Rev = "a52e2f46e106f5c64e996b76c110d315a6ddacf7";  # randomizedcoder/xtcp2 git rev

  scapyPython = pkgs.python314.withPackages (ps: [ ps.scapy ]);
  tshark = pkgs.wireshark-cli;

  # Linux kernel source (include/ + drivers/net/ for protocol struct parsing)
  #
  # include/uapi/linux/ has the primary UAPI header structs (iphdr, tcphdr, etc.)
  # include/linux/ has internal structs sometimes needed for field resolution
  # drivers/net/ has additional protocol structs used by network drivers:
  #   - drivers/net/vxlan/ (VXLAN implementation structs)
  #   - drivers/net/geneve/ (Geneve tunnel structs)
  #   - drivers/net/macsec.c (MACsec wire format structs)
  #   - drivers/net/bonding/ (LACP, bonding structs)
  #   - drivers/net/ppp/ (PPP channel/unit structs)
  #   - drivers/net/can/ (CAN protocol structs)
  # net/ has protocol implementation structs:
  #   - net/bridge/br_stp.c (STP BPDU structs)
  #   - net/ipv4/ip_gre.c, net/ipv6/ip6_gre.c
  #   - net/mpls/, net/nsh/, net/openvswitch/
  kernelSrc = pkgs.runCommand "linux-kernel-src-${kernelVersion}" {
    src = pkgs.linuxKernel.kernels.linux_7_0.src;
  } ''
    mkdir -p $out
    tar xf $src --strip-components=1 -C $out \
      --wildcards '*/include/*' '*/drivers/net/*' '*/net/*'
  '';

  # ── Userland protocol sources (packed C struct libraries) ──

  # DPDK net headers: high-quality packed protocol structs from the
  # Data Plane Development Kit. Covers ~28 protocols including eCPRI,
  # L2TPv2, MACsec, PDCP, TLS/DTLS wire headers, HiGig, PPP, and
  # standard protocols (Ethernet, IP, TCP, UDP, GRE, VXLAN, Geneve, etc.)
  # These use __rte_packed and standard C types — parseable by the
  # kernel C struct extractor with minor type mapping additions.
  dpdkSrc = pkgs.runCommand "dpdk-net-headers" {
    src = pkgs.dpdk.src;
  } ''
    mkdir -p $out/lib/net
    tar xf $src --strip-components=1 -C $out --wildcards '*/lib/net/*.h'
  '';

  # nDPI (ntop Deep Packet Inspection) headers: ~25 packed protocol wire
  # format structs in ndpi_typedefs.h, covering CHDLC, SLARP, CDP, DHCP,
  # DNS, Radiotap, IEEE 802.11, LLC/SNAP, MPLS, IP, TCP, UDP, ICMP,
  # ICMPv6, VXLAN, GRE, and ARP. Uses PACK_ON/PACK_OFF macros around
  # struct definitions. The kernel C struct parser handles these with
  # minor preprocessing (strip PACK_ON/PACK_OFF, map u_int*_t types).
  # Also has 474 protocol ID constants in ndpi_protocol_ids.h.
  ndpiSrc = pkgs.runCommand "ndpi-headers" {
    src = pkgs.ndpi.src;
  } ''
    mkdir -p $out
    cp -r $src/src/include/* $out/
  '';

  # pppd source: PPP daemon implementation with protocol headers for
  # LCP (lcp.h), IPCP (ipcp.h), IPv6CP (ipv6cp.h), CCP (ccp.h),
  # CHAP (chap.h), EAP (eap.h), ECP (ecp.h), PAP (upap.h), and
  # PPPoE plugin (plugins/pppoe/pppoe.h). Wire format is defined via
  # #define constants (HEADERLEN=4, CONFREQ=1, CONFACK=2, etc.) rather
  # than packed structs, but the headers are authoritative for field
  # names and protocol constants used in cross-verification.
  pppdSrc = pkgs.runCommand "pppd-src" {
    src = pkgs.ppp.src;
  } ''
    mkdir -p $out/include
    cp -r $src/pppd/* $out/
    cp -r $src/include/* $out/include/
  '';

  # rdma-core headers: libibverbs and libibmad InfiniBand protocol structs.
  # Provides ibv_grh (GRH wire format, 40 bytes) in infiniband/verbs.h
  # and umad_hdr (MAD header, 24 bytes) in infiniband/umad_types.h.
  # Uses standard C types (__be16, __be32, uint8_t) — parseable by the
  # kernel C struct extractor with rdma-specific type mappings.
  rdmaSrc = pkgs.rdma-core.dev;

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

  # xtcp2 Go netlink parsers: rich Go struct definitions for inet_diag
  # attributes (tcp_info, bbr_info, meminfo, skmeminfo, vegasinfo, dctcpinfo,
  # prague_info, inet_diag_msg, inet_diag_req_v2, inet_diag_sockid).
  # Includes kernel-versioned TCPInfo variants (4.19 → 6.10) and tests
  # against real PCAPs from multiple kernel versions.
  xtcp2Src = pkgs.fetchFromGitHub {
    owner = "randomizedcoder";
    repo = "xtcp2";
    rev = xtcp2Rev;
    hash = "sha256-fXno6qclmovlsCcVJr/3fjsqTNAxt0ti7C9eW27X88I=";
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
  # Linux kernel source (include/ + drivers/net/ + net/)
  inherit kernelSrc;

  # DPDK net headers (packed protocol structs for ~28 protocols)
  inherit dpdkSrc;

  # nDPI headers (deep packet inspection, ~25 packed protocol structs)
  inherit ndpiSrc;

  # pppd source (PPP control protocol headers and constants)
  inherit pppdSrc;

  # rdma-core headers (libibverbs/libibmad IB protocol structs)
  inherit rdmaSrc;

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

  # xtcp2 Go netlink parsers (inet_diag attribute structs)
  inherit xtcp2Src;

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
    dpdk = pkgs.dpdk.version or "unknown";
    ndpi = pkgs.ndpi.version or "unknown";
    pppd = pkgs.ppp.version or "unknown";
    etherparse = etherparseRev;
    libpcap = libpcapRev;
    packetlife = packetlifeRev;
    wiresharkSamples = wiresharkSamplesRev;
    omiCStructs = omiCStructsRev;
    omiDataPackets = omiDataPacketsRev;
    omiWiresharkLua = omiWiresharkLuaRev;
    tshark = tshark.version or "unknown";
    scapy = scapyPython.version or "unknown";
    xtcp2 = xtcp2Rev;
  };
}
