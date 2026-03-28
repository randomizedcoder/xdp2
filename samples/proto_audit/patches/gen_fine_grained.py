#!/usr/bin/env python3
"""Generate fine-grained per-protocol patch files.

Rewrites overlay struct definitions to split coarse combined fields
(e.g., flags_version: u16) into individual sub-fields per RFC specs.
"""

import os

PATCH_DIR = os.path.dirname(os.path.abspath(__file__))


# ── Etherparse struct definitions (Rust) ──
# Each entry: (filename, struct_name, module_doc, fields_as_lines)
# Fields use: bool (1 bit), BitsN (N bits), u8/u16/u32/u64, [u8; N]

ETHERPARSE = [
    # ── Tunneling ──
    ("gre", "GreHeader", "GRE header (RFC 2784/2890) — 4 bytes minimum.", [
        ("/// Checksum data present.", "pub checksum_present: bool,"),
        ("/// Reserved (must be 0).", "pub reserved0: bool,"),
        ("/// Key field present (RFC 2890).", "pub key_present: bool,"),
        ("/// Sequence number present (RFC 2890).", "pub sequence_present: bool,"),
        ("/// Reserved.", "pub reserved1: Bits9,"),
        ("/// GRE version.", "pub version: Bits3,"),
        ("/// Encapsulated protocol type (EtherType).", "pub protocol_type: u16,"),
    ]),
    ("vxlan", "VxlanHeader", "VXLAN header (RFC 7348) — 8 bytes.", [
        ("/// Reserved flags.", "pub reserved_flags0: Bits4,"),
        ("/// VNI valid (I flag).", "pub vni_valid: bool,"),
        ("/// Reserved flags.", "pub reserved_flags1: Bits3,"),
        ("/// Reserved.", "pub reserved1: [u8; 3],"),
        ("/// VXLAN Network Identifier (24 bits).", "pub vni: [u8; 3],"),
        ("/// Reserved.", "pub reserved2: u8,"),
    ]),
    ("geneve", "GeneveHeader", "Geneve header (RFC 8926) — 8 bytes minimum.", [
        ("/// Version.", "pub version: Bits2,"),
        ("/// Options length (in 4-byte units).", "pub options_length: Bits6,"),
        ("/// OAM packet.", "pub oam: bool,"),
        ("/// Critical options present.", "pub critical: bool,"),
        ("/// Reserved.", "pub reserved0: Bits6,"),
        ("/// Encapsulated protocol type (EtherType).", "pub protocol_type: u16,"),
        ("/// Virtual Network Identifier (24 bits).", "pub vni: [u8; 3],"),
        ("/// Reserved.", "pub reserved1: u8,"),
    ]),
    ("mpls", "MplsHeader", "MPLS label stack entry (RFC 3032) — 4 bytes.", [
        ("/// Label value (20 bits).", "pub label: Bits20,"),
        ("/// Traffic Class (formerly Experimental).", "pub traffic_class: Bits3,"),
        ("/// Bottom of Stack.", "pub bottom_of_stack: bool,"),
        ("/// Time to Live.", "pub ttl: u8,"),
    ]),
    ("nvgre", "NvgreHeader", "NVGRE header (RFC 7637) — 8 bytes.", [
        ("/// Checksum present (must be 0 for NVGRE).", "pub checksum_present: bool,"),
        ("/// Reserved.", "pub reserved0: bool,"),
        ("/// Key present (must be 1 for NVGRE).", "pub key_present: bool,"),
        ("/// Sequence present.", "pub sequence_present: bool,"),
        ("/// Reserved.", "pub reserved1: Bits9,"),
        ("/// GRE version.", "pub version: Bits3,"),
        ("/// Protocol type (0x6558 = transparent Ethernet bridging).", "pub protocol_type: u16,"),
        ("/// Virtual Subnet ID (24 bits).", "pub vsid: [u8; 3],"),
        ("/// Flow ID.", "pub flow_id: u8,"),
    ]),
    ("ppp", "PppHeader", "PPP header (RFC 1661) — 2 bytes (protocol field only).", [
        ("/// PPP protocol number.", "pub protocol: u16,"),
    ]),
    ("pppoe", "PppoeHeader", "PPPoE header (RFC 2516) — 6 bytes.", [
        ("/// Version (must be 1).", "pub version: Bits4,"),
        ("/// Type (must be 1).", "pub pppoe_type: Bits4,"),
        ("/// Code (Discovery or Session).", "pub code: u8,"),
        ("/// Session ID.", "pub session_id: u16,"),
        ("/// Payload length.", "pub length: u16,"),
    ]),
    ("l2tp", "L2tpHeader", "L2TP header (RFC 2661) — 6 bytes minimum.", [
        ("/// Message type (0=data, 1=control).", "pub msg_type: bool,"),
        ("/// Length field present.", "pub length_present: bool,"),
        ("/// Reserved.", "pub reserved0: Bits2,"),
        ("/// Sequence fields present.", "pub sequence_present: bool,"),
        ("/// Reserved.", "pub reserved1: bool,"),
        ("/// Offset field present.", "pub offset_present: bool,"),
        ("/// Priority.", "pub priority: bool,"),
        ("/// Reserved.", "pub reserved2: Bits4,"),
        ("/// Protocol version (must be 2).", "pub version: Bits4,"),
        ("/// Tunnel ID.", "pub tunnel_id: u16,"),
        ("/// Session ID.", "pub session_id: u16,"),
    ]),
    ("erspan", "ErspanHeader", "ERSPAN Type II header (Cisco) — 8 bytes.", [
        ("/// Version.", "pub version: Bits4,"),
        ("/// VLAN ID.", "pub vlan: Bits12,"),
        ("/// Class of Service.", "pub cos: Bits3,"),
        ("/// BSO (bad/short/oversized).", "pub bso: Bits2,"),
        ("/// Truncated.", "pub truncated: bool,"),
        ("/// ERSPAN session ID.", "pub session_id: Bits10,"),
        ("/// Reserved.", "pub reserved: Bits12,"),
        ("/// Port index.", "pub index: Bits20,"),
    ]),
    ("nsh", "NshHeader", "NSH header (RFC 8300) — 8 bytes.", [
        ("/// Version.", "pub version: Bits2,"),
        ("/// OAM flag.", "pub oam: bool,"),
        ("/// Unused.", "pub unused0: bool,"),
        ("/// TTL.", "pub ttl: Bits6,"),
        ("/// Length (in 4-byte units).", "pub length: Bits6,"),
        ("/// Unused.", "pub unused1: Bits4,"),
        ("/// Metadata type.", "pub md_type: Bits4,"),
        ("/// Next protocol.", "pub next_protocol: u8,"),
        ("/// Service Path Identifier (24 bits).", "pub spi: [u8; 3],"),
        ("/// Service Index.", "pub si: u8,"),
    ]),
    ("hsr", "HsrHeader", "HSR tag (IEC 62439-3) — 6 bytes.", [
        ("/// Network ID / Path indicator.", "pub path: Bits4,"),
        ("/// LSDU size.", "pub lsdu_size: Bits12,"),
        ("/// Sequence number.", "pub seq_nr: u16,"),
        ("/// Encapsulated protocol (EtherType).", "pub ether_type: u16,"),
    ]),
    ("vxlan_gpe", "VxlanGpeHeader", "VXLAN-GPE header (draft-ietf-nvo3-vxlan-gpe) — 8 bytes.", [
        ("/// Flags.", "pub flags: u8,"),
        ("/// Reserved.", "pub reserved1: u16,"),
        ("/// Next protocol.", "pub next_protocol: u8,"),
        ("/// Virtual Network Identifier (24 bits).", "pub vni: [u8; 3],"),
        ("/// Reserved.", "pub reserved2: u8,"),
    ]),
    ("wire_guard", "WireGuardHeader", "WireGuard message header — 4 bytes.", [
        ("/// Message type (1=init, 2=response, 3=cookie, 4=data).", "pub msg_type: u8,"),
        ("/// Reserved (3 bytes, must be zero).", "pub reserved: [u8; 3],"),
    ]),
    # ── Layer 2 ──
    ("llc", "LlcHeader", "IEEE 802.2 LLC header — 3 bytes.", [
        ("/// Destination Service Access Point.", "pub dsap: u8,"),
        ("/// Source Service Access Point.", "pub ssap: u8,"),
        ("/// Control field.", "pub ctrl: u8,"),
    ]),
    ("snap", "SnapHeader", "IEEE 802.2 SNAP header — 5 bytes.", [
        ("/// Organizationally Unique Identifier.", "pub oui: [u8; 3],"),
        ("/// Protocol ID (EtherType when OUI=0).", "pub protocol_id: u16,"),
    ]),
    ("eapol", "EapolHeader", "EAPOL header (IEEE 802.1X) — 4 bytes.", [
        ("/// Protocol version.", "pub version: u8,"),
        ("/// Packet type.", "pub packet_type: u8,"),
        ("/// Body length.", "pub length: u16,"),
    ]),
    ("stp", "StpHeader", "STP BPDU header (IEEE 802.1D) — 35 bytes.", [
        ("/// Protocol Identifier (always 0x0000).", "pub protocol_id: u16,"),
        ("/// Protocol Version Identifier.", "pub version: u8,"),
        ("/// BPDU Type.", "pub bpdu_type: u8,"),
        ("/// Topology Change flags.", "pub flags: u8,"),
        ("/// Root Bridge Identifier.", "pub root_id: [u8; 8],"),
        ("/// Root Path Cost.", "pub root_cost: u32,"),
        ("/// Bridge Identifier.", "pub bridge_id: [u8; 8],"),
        ("/// Port Identifier.", "pub port_id: u16,"),
        ("/// Message Age (in 256ths of a second).", "pub message_age: u16,"),
        ("/// Max Age.", "pub max_age: u16,"),
        ("/// Hello Time.", "pub hello_time: u16,"),
        ("/// Forward Delay.", "pub forward_delay: u16,"),
    ]),
    # ── Layer 3 / Multicast ──
    ("igmp", "IgmpHeader", "IGMP header (RFC 2236) — 8 bytes.", [
        ("/// Message type.", "pub msg_type: u8,"),
        ("/// Max response time.", "pub max_resp_time: u8,"),
        ("/// Checksum.", "pub checksum: u16,"),
        ("/// Group address.", "pub group_address: [u8; 4],"),
    ]),
    # ── Layer 4 ──
    ("sctp", "SctpHeader", "SCTP common header (RFC 9260) — 12 bytes.", [
        ("/// Source port.", "pub source_port: u16,"),
        ("/// Destination port.", "pub destination_port: u16,"),
        ("/// Verification tag.", "pub verification_tag: u32,"),
        ("/// Checksum.", "pub checksum: u32,"),
    ]),
    ("dccp", "DccpHeader", "DCCP header (RFC 4340) — 12 bytes minimum.", [
        ("/// Source port.", "pub source_port: u16,"),
        ("/// Destination port.", "pub destination_port: u16,"),
        ("/// Data offset (in 32-bit words).", "pub data_offset: u8,"),
        ("/// CCVal.", "pub ccval: Bits4,"),
        ("/// Checksum coverage.", "pub cscov: Bits4,"),
        ("/// Checksum.", "pub checksum: u16,"),
        ("/// Reserved.", "pub reserved: Bits3,"),
        ("/// DCCP packet type.", "pub dccp_type: Bits4,"),
        ("/// Extended sequence numbers.", "pub x: bool,"),
        ("/// Sequence number high byte (short sequence).", "pub seq_hi: u8,"),
        ("/// Sequence number low bytes (short sequence).", "pub seq_lo: u16,"),
    ]),
    # ── Security ──
    ("esp", "EspHeader", "ESP header (RFC 4303) — 8 bytes.", [
        ("/// Security Parameters Index.", "pub spi: u32,"),
        ("/// Sequence number.", "pub seq_number: u32,"),
    ]),
    ("ah", "AhHeader", "AH header (RFC 4302) — 12 bytes minimum.", [
        ("/// Next header (IP protocol number).", "pub next_header: u8,"),
        ("/// Payload length (in 32-bit words, minus 2).", "pub payload_len: u8,"),
        ("/// Reserved.", "pub reserved: u16,"),
        ("/// Security Parameters Index.", "pub spi: u32,"),
        ("/// Sequence number.", "pub seq_number: u32,"),
    ]),
    ("macsec", "MacsecHeader", "MACsec SecTAG (IEEE 802.1AE) — 8 bytes.", [
        ("/// Version.", "pub version: bool,"),
        ("/// End Station.", "pub end_station: bool,"),
        ("/// SCI present.", "pub sci_present: bool,"),
        ("/// Single Copy Broadcast.", "pub scb: bool,"),
        ("/// Encryption.", "pub encryption: bool,"),
        ("/// Changed Text.", "pub changed_text: bool,"),
        ("/// Association Number.", "pub association_number: Bits2,"),
        ("/// Short Length.", "pub short_length: u8,"),
        ("/// Packet Number.", "pub packet_number: u32,"),
        ("/// Secure Channel Identifier high bytes.", "pub sci_hi: u16,"),
    ]),
    # ── Application Binary Protocols ──
    ("dns", "DnsHeader", "DNS header (RFC 1035) — 12 bytes.", [
        ("/// Transaction ID.", "pub id: u16,"),
        ("/// Flags (QR, Opcode, AA, TC, RD, RA, Z, RCODE).", "pub flags: u16,"),
        ("/// Question count.", "pub qd_count: u16,"),
        ("/// Answer count.", "pub an_count: u16,"),
        ("/// Authority count.", "pub ns_count: u16,"),
        ("/// Additional count.", "pub ar_count: u16,"),
    ]),
    ("ntp", "NtpHeader", "NTP header (RFC 5905) — 48 bytes.", [
        ("/// Leap Indicator.", "pub leap_indicator: Bits2,"),
        ("/// Version Number.", "pub version: Bits3,"),
        ("/// Mode.", "pub mode: Bits3,"),
        ("/// Stratum.", "pub stratum: u8,"),
        ("/// Poll interval.", "pub poll: u8,"),
        ("/// Precision.", "pub precision: u8,"),
        ("/// Root delay.", "pub root_delay: u32,"),
        ("/// Root dispersion.", "pub root_dispersion: u32,"),
        ("/// Reference ID.", "pub reference_id: u32,"),
        ("/// Reference timestamp.", "pub reference_ts: [u8; 8],"),
        ("/// Origin timestamp.", "pub origin_ts: [u8; 8],"),
        ("/// Receive timestamp.", "pub receive_ts: [u8; 8],"),
        ("/// Transmit timestamp.", "pub transmit_ts: [u8; 8],"),
    ]),
    ("rtp", "RtpHeader", "RTP header (RFC 3550) — 12 bytes.", [
        ("/// Version.", "pub version: Bits2,"),
        ("/// Padding.", "pub padding: bool,"),
        ("/// Extension.", "pub extension: bool,"),
        ("/// CSRC count.", "pub csrc_count: Bits4,"),
        ("/// Marker.", "pub marker: bool,"),
        ("/// Payload type.", "pub payload_type: Bits7,"),
        ("/// Sequence number.", "pub sequence_number: u16,"),
        ("/// Timestamp.", "pub timestamp: u32,"),
        ("/// Synchronization source.", "pub ssrc: u32,"),
    ]),
    ("radius", "RadiusHeader", "RADIUS header (RFC 2865) — 20 bytes.", [
        ("/// Code (Access-Request, etc.).", "pub code: u8,"),
        ("/// Identifier.", "pub identifier: u8,"),
        ("/// Total length.", "pub length: u16,"),
        ("/// Authenticator.", "pub authenticator: [u8; 16],"),
    ]),
    ("bfd", "BfdHeader", "BFD header (RFC 5880) — 24 bytes.", [
        ("/// Protocol version.", "pub version: Bits3,"),
        ("/// Diagnostic code.", "pub diagnostic: Bits5,"),
        ("/// Session state.", "pub state: Bits2,"),
        ("/// Poll.", "pub poll: bool,"),
        ("/// Final.", "pub final_flag: bool,"),
        ("/// Control Plane Independent.", "pub control_plane_independent: bool,"),
        ("/// Authentication Present.", "pub authentication_present: bool,"),
        ("/// Demand mode.", "pub demand: bool,"),
        ("/// Multipoint.", "pub multipoint: bool,"),
        ("/// Detect multiplier.", "pub detect_mult: u8,"),
        ("/// Length.", "pub length: u8,"),
        ("/// My Discriminator.", "pub my_discriminator: u32,"),
        ("/// Your Discriminator.", "pub your_discriminator: u32,"),
        ("/// Desired Min TX Interval.", "pub min_tx_interval: u32,"),
        ("/// Required Min RX Interval.", "pub min_rx_interval: u32,"),
        ("/// Required Min Echo RX Interval.", "pub min_echo_rx_interval: u32,"),
    ]),
    ("ptp", "PtpHeader", "PTP header (IEEE 1588) — 34 bytes.", [
        ("/// Transport specific.", "pub transport_specific: Bits4,"),
        ("/// Message type.", "pub message_type: Bits4,"),
        ("/// PTP version.", "pub version_ptp: Bits4,"),
        ("/// Minor version.", "pub minor_version: Bits4,"),
        ("/// Message length.", "pub message_length: u16,"),
        ("/// Domain number.", "pub domain_number: u8,"),
        ("/// Minor SDO ID.", "pub minor_sdo_id: u8,"),
        ("/// Flags.", "pub flags: u16,"),
        ("/// Correction field.", "pub correction: [u8; 8],"),
        ("/// Message type specific.", "pub msg_type_specific: u32,"),
        ("/// Source port identity.", "pub source_port_identity: [u8; 10],"),
        ("/// Sequence ID.", "pub sequence_id: u16,"),
        ("/// Control field.", "pub control: u8,"),
        ("/// Log message interval.", "pub log_message_interval: u8,"),
    ]),
    # ── CAN Bus ──
    ("can", "CanHeader", "CAN frame header (socketcan) — 16 bytes.", [
        ("/// CAN identifier (29 bits for EFF, 11 for SFF).", "pub can_id: Bits29,"),
        ("/// Error frame flag.", "pub err_flag: bool,"),
        ("/// Remote transmission request.", "pub rtr_flag: bool,"),
        ("/// Extended frame format.", "pub eff_flag: bool,"),
        ("/// Data length code.", "pub len: u8,"),
        ("/// Flags.", "pub flags: u8,"),
        ("/// Reserved.", "pub reserved: u8,"),
        ("/// Length to DLC.", "pub len8_dlc: u8,"),
        ("/// Data payload.", "pub data: [u8; 8],"),
    ]),
    ("can_fd", "CanFdHeader", "CAN FD frame header (socketcan) — 72 bytes.", [
        ("/// CAN identifier (29 bits for EFF, 11 for SFF).", "pub can_id: Bits29,"),
        ("/// Error frame flag.", "pub err_flag: bool,"),
        ("/// Remote transmission request.", "pub rtr_flag: bool,"),
        ("/// Extended frame format.", "pub eff_flag: bool,"),
        ("/// Data length.", "pub len: u8,"),
        ("/// Flags (BRS, ESI).", "pub flags: u8,"),
        ("/// Reserved.", "pub reserved: u8,"),
        ("/// Length to DLC.", "pub len8_dlc: u8,"),
        ("/// Data payload (up to 64 bytes).", "pub data: [u8; 64],"),
    ]),
]


# ── Libpcap struct definitions (C with bitfields) ──

LIBPCAP = [
    ("gre", "gre_header", "GRE header (RFC 2784/2890) — 4 bytes minimum", [
        "uint16_t gre_checksum_present:1;",
        "uint16_t gre_reserved0:1;",
        "uint16_t gre_key_present:1;",
        "uint16_t gre_sequence_present:1;",
        "uint16_t gre_reserved1:9;",
        "uint16_t gre_version:3;",
        "uint16_t gre_protocol_type;",
    ]),
    ("vxlan", "vxlan_header", "VXLAN header (RFC 7348) — 8 bytes", [
        "uint8_t  vxlan_reserved_flags0:4;",
        "uint8_t  vxlan_vni_valid:1;",
        "uint8_t  vxlan_reserved_flags1:3;",
        "uint8_t  vxlan_reserved1[3];",
        "uint8_t  vxlan_vni[3];",
        "uint8_t  vxlan_reserved2;",
    ]),
    ("geneve", "geneve_header", "Geneve header (RFC 8926) — 8 bytes minimum", [
        "uint8_t  geneve_version:2;",
        "uint8_t  geneve_options_length:6;",
        "uint8_t  geneve_oam:1;",
        "uint8_t  geneve_critical:1;",
        "uint8_t  geneve_reserved0:6;",
        "uint16_t geneve_protocol_type;",
        "uint8_t  geneve_vni[3];",
        "uint8_t  geneve_reserved1;",
    ]),
    ("mpls", "mpls_header", "MPLS label stack entry (RFC 3032) — 4 bytes", [
        "uint32_t mpls_label:20;",
        "uint32_t mpls_traffic_class:3;",
        "uint32_t mpls_bottom_of_stack:1;",
        "uint32_t mpls_ttl:8;",
    ]),
    ("ppp", "ppp_header", "PPP header (RFC 1661) — 2 bytes", [
        "uint16_t ppp_protocol;",
    ]),
    ("pppoe", "pppoe_header", "PPPoE header (RFC 2516) — 6 bytes", [
        "uint8_t  pppoe_version:4;",
        "uint8_t  pppoe_type:4;",
        "uint8_t  pppoe_code;",
        "uint16_t pppoe_session_id;",
        "uint16_t pppoe_length;",
    ]),
    ("esp", "esp_header", "ESP header (RFC 4303) — 8 bytes", [
        "uint32_t esp_spi;",
        "uint32_t esp_seq;",
    ]),
    ("ah", "ah_header", "AH header (RFC 4302) — 12 bytes minimum", [
        "uint8_t  ah_next_header;",
        "uint8_t  ah_payload_len;",
        "uint16_t ah_reserved;",
        "uint32_t ah_spi;",
        "uint32_t ah_seq;",
    ]),
    ("l2tp", "l2tp_header", "L2TP header (RFC 2661) — 6 bytes minimum", [
        "uint16_t l2tp_msg_type:1;",
        "uint16_t l2tp_length_present:1;",
        "uint16_t l2tp_reserved0:2;",
        "uint16_t l2tp_sequence_present:1;",
        "uint16_t l2tp_reserved1:1;",
        "uint16_t l2tp_offset_present:1;",
        "uint16_t l2tp_priority:1;",
        "uint16_t l2tp_reserved2:4;",
        "uint16_t l2tp_version:4;",
        "uint16_t l2tp_tunnel_id;",
        "uint16_t l2tp_session_id;",
    ]),
    ("erspan", "erspan_header", "ERSPAN Type II header (Cisco) — 8 bytes", [
        "uint16_t erspan_version:4;",
        "uint16_t erspan_vlan:12;",
        "uint16_t erspan_cos:3;",
        "uint16_t erspan_bso:2;",
        "uint16_t erspan_truncated:1;",
        "uint16_t erspan_session_id:10;",
        "uint32_t erspan_reserved:12;",
        "uint32_t erspan_index:20;",
    ]),
    ("nsh", "nsh_header", "NSH header (RFC 8300) — 8 bytes", [
        "uint16_t nsh_version:2;",
        "uint16_t nsh_oam:1;",
        "uint16_t nsh_unused0:1;",
        "uint16_t nsh_ttl:6;",
        "uint16_t nsh_length:6;",
        "uint16_t nsh_unused1:4;",
        "uint16_t nsh_md_type:4;",
        "uint8_t  nsh_next_protocol;",
        "uint8_t  nsh_spi[3];",
        "uint8_t  nsh_si;",
    ]),
    ("hsr", "hsr_header", "HSR tag (IEC 62439-3) — 6 bytes", [
        "uint16_t hsr_path:4;",
        "uint16_t hsr_lsdu_size:12;",
        "uint16_t hsr_seq_nr;",
        "uint16_t hsr_ether_type;",
    ]),
    ("llc", "llc_header", "LLC header (IEEE 802.2) — 3 bytes", [
        "uint8_t llc_dsap;",
        "uint8_t llc_ssap;",
        "uint8_t llc_ctrl;",
    ]),
    ("eapol", "eapol_header", "EAPOL header (IEEE 802.1X) — 4 bytes", [
        "uint8_t  eapol_version;",
        "uint8_t  eapol_type;",
        "uint16_t eapol_length;",
    ]),
    ("igmp", "igmp_header", "IGMP header (RFC 2236) — 8 bytes", [
        "uint8_t  igmp_type;",
        "uint8_t  igmp_max_resp;",
        "uint16_t igmp_checksum;",
        "uint8_t  igmp_group[4];",
    ]),
    ("sctp", "sctp_header", "SCTP common header (RFC 9260) — 12 bytes", [
        "uint16_t sctp_src_port;",
        "uint16_t sctp_dst_port;",
        "uint32_t sctp_vtag;",
        "uint32_t sctp_checksum;",
    ]),
    ("dns", "dns_header", "DNS header (RFC 1035) — 12 bytes", [
        "uint16_t dns_id;",
        "uint16_t dns_flags;",
        "uint16_t dns_qd_count;",
        "uint16_t dns_an_count;",
        "uint16_t dns_ns_count;",
        "uint16_t dns_ar_count;",
    ]),
    ("ntp", "ntp_header", "NTP header (RFC 5905) — 48 bytes", [
        "uint8_t  ntp_leap_indicator:2;",
        "uint8_t  ntp_version:3;",
        "uint8_t  ntp_mode:3;",
        "uint8_t  ntp_stratum;",
        "uint8_t  ntp_poll;",
        "uint8_t  ntp_precision;",
        "uint32_t ntp_root_delay;",
        "uint32_t ntp_root_dispersion;",
        "uint32_t ntp_reference_id;",
        "uint8_t  ntp_reference_ts[8];",
        "uint8_t  ntp_origin_ts[8];",
        "uint8_t  ntp_receive_ts[8];",
        "uint8_t  ntp_transmit_ts[8];",
    ]),
]


def gen_etherparse_patch(filename, struct_name, module_doc, fields):
    """Generate a Rust overlay struct patch file."""
    lines = [f"//! {module_doc}"]
    lines.append("")
    lines.append(f"/// {module_doc}")
    lines.append(f"pub struct {struct_name} {{")
    for doc, field in fields:
        lines.append(f"    {doc}")
        lines.append(f"    {field}")
    lines.append("}")

    rs_path = f"src/proto_audit/{filename}.rs"
    n = len(lines)
    patch = f"--- /dev/null\n+++ b/{rs_path}\n@@ -0,0 +1,{n} @@\n"
    for line in lines:
        patch += f"+{line}\n"
    return patch


def gen_libpcap_patch(filename, struct_name, comment, fields):
    """Generate a C header overlay struct patch file."""
    guard = f"PROTO_AUDIT_{filename.upper()}_H"
    lines = [
        "/*",
        f" * {filename}.h — {struct_name} definition for proto-audit comparison.",
        " */",
        "",
        f"#ifndef {guard}",
        f"#define {guard}",
        "",
        "#include <stdint.h>",
        "",
        f"/* {comment} */",
        f"struct {struct_name} {{",
    ]
    for field in fields:
        lines.append(f"    {field}")
    lines.append("};")
    lines.append("")
    lines.append(f"#endif /* {guard} */")

    h_path = f"pcap/proto_audit/{filename}.h"
    n = len(lines)
    patch = f"--- /dev/null\n+++ b/{h_path}\n@@ -0,0 +1,{n} @@\n"
    for line in lines:
        patch += f"+{line}\n"
    return patch


def main():
    # Generate etherparse patches
    ep_dir = os.path.join(PATCH_DIR, "etherparse")
    os.makedirs(ep_dir, exist_ok=True)
    for filename, struct_name, doc, fields in ETHERPARSE:
        patch = gen_etherparse_patch(filename, struct_name, doc, fields)
        path = os.path.join(ep_dir, f"{filename}.patch")
        with open(path, "w") as f:
            f.write(patch)
    print(f"Generated {len(ETHERPARSE)} etherparse patches")

    # Generate libpcap patches
    lp_dir = os.path.join(PATCH_DIR, "libpcap")
    os.makedirs(lp_dir, exist_ok=True)
    for filename, struct_name, comment, fields in LIBPCAP:
        patch = gen_libpcap_patch(filename, struct_name, comment, fields)
        path = os.path.join(lp_dir, f"{filename}.patch")
        with open(path, "w") as f:
            f.write(patch)
    print(f"Generated {len(LIBPCAP)} libpcap patches")


if __name__ == "__main__":
    main()
