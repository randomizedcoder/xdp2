# proto-audit Status

## Current State (2026-04-06)

206 curated protocols audited across 8 sources (XDP2, kernel, Scapy, tshark, etherparse, libpcap, Kaitai Struct, Suricata).
8,358 total protocols tracked (206 curated + 8,152 discovered from tshark/Scapy registries).
400 unit tests including roundtrip, cross-source, PCAP generation, cross-generator, and exhaustive TOML coverage validation.
36 protocols with Silver-tier structural agreement (2+ independent sources agree on field layout).
112 protocols with Gold-tier round-trip validation (IR → PCAP → tshark → IR).
205 protocols routable through PCAP generation (all except TPLINK_SMARTHOME).
62 PCAP templates with valid protocol content for round-trip validation.

### Source Coverage Summary

| Source | Coverage |
|--------|----------|
| XDP2 proto_defs | 222 (206 curated) |
| Etherparse structs | 206/206 curated |
| Libpcap overlays | 206/206 curated |
| Scapy classes | 5,798 (109 curated) |
| tshark filters | 3,753 (3,155 protocols) |
| Kernel structs | 74 (173 in registry) |
| Kaitai Struct | ~20 protocols (12 curated) |
| Suricata parsers | ~15 protocols (20 curated) |
| Multi-source (2+) | 1,198 |

### Validation Tier Breakdown

| Tier | Count | Meaning |
|------|-------|---------|
| Gold | 112 | Round-trip validated (IR → PCAP → tshark → IR matches) |
| Silver | 36 | 2+ independent sources agree on field layout |
| Bronze | 27 | Single source, self-consistent |
| Unvalidated | 13 + ~8,100 discovered | Discovered but not yet verified |

### Gold-Validated Protocols (112)

Round-trip validated through wire bytes — IR serialized to PCAP, parsed by tshark, extracted back to IR, field-by-field comparison passes:

AH, ARP, AoE, BACnet, BFD, BGP, CAN, CAN_FD, CAN_XL, CoAP, DCCP, DHCP,
DHCPv6, DNS, DTLS, Diameter, EAPOL, EIGRP, ERSPAN, ESP, Ethernet, GRE,
GRE_PPTP, GTP_C, GTP_U, Geneve, HCI_ACL, HCI_CMD, HCI_Event, HCI_ISO,
HCI_SCO, HSR, HTTP, HomePlug_AV, ICMPv4, ICMPv6, IEC_MMS, IEEE802154,
IGMP, IGMPv3_Query, IGMPv3_Report, IKEv2, IMAP, IPFIX, IP_in_IP, IPv4,
IPv6, IPv6_DestOpts, IPv6_EH, IPv6_Fragment, IPv6_ND, IPv6_Routing, ISIS,
Kafka, Kerberos, L2TP, LACP, LDAP, LDP, LLC, LLMNR, MAC_Control, MLD,
MLDv2_Query, MODBUS_TCP, MPLS, MQTT, Memcache, NBNS, NTP, NetFlow_v5,
NetFlow_v9, ONC_RPC, OPC_UA, OSPF, PIM, PPP, PPPoE, PPPoED, QUIC, QinQ,
RADIUS, RARP, RIP, RSVP, RTCP, RTSP, Redis, SCTP, SIP, SLL, SLL2, SNAP,
SNMP, SSH, STP, STUN, Skinny, Slow_Protocols, Syslog, TCP, TFTP, TLS,
UDP, UDPLite, VLAN, VRRP, VXLAN, VXLAN_GPE, WireGuard, iSCSI, mDNS

### Recent Changes

#### Kaitai & Suricata Curated Integration (8 Sources)

Added Kaitai Struct and Suricata as first-class curated sources with fields in `ProtocolNames`:
- 12 protocols with curated Kaitai mappings (Ethernet, IPv4, IPv6, TCP, UDP, ARP, ICMPv4, DNS, VLAN, RTP, RTCP)
- 20 protocols with curated Suricata mappings (DNS, NTP, SNMP, DHCP, QUIC, HTTP2, SSH, MQTT, etc.)
- Builder methods `.kaitai(id, file)` and `.suricata(module, struct_name)` on `ProtocolNames`
- Curated lookup functions `find_by_kaitai_id()` and `find_by_suricata_struct()`
- `try_extract()` uses curated lookups with dynamic fallback for non-curated protocols

#### Cross-Generator Round-Trip (`crossgen` command)

New `crossgen` command closes the generate→re-extract loop for all code generators:
- **etherparse round-trip**: generate Rust struct → parse struct → compare to IR
- **C round-trip**: generate C header → parse struct → compare to IR
- **Scapy round-trip**: generate Python class → run through scapy_dump.py → compare
- **PCAP round-trip**: delegates to existing `validate` infrastructure
- Batch mode: `crossgen --proto all --target all` runs all combinations
- 9 new cross-generator tests in `crossgen_tests.rs`

#### Corpus Cross-Source Parsing (`corpus-parse` command)

New `corpus-parse` command parses the same PCAP through tshark and Scapy, comparing field values:
- Value-level comparison with hex/integer normalization (`compare_field_values()`)
- Per-layer agreement/disagreement reporting
- Supports single PCAP or directory of PCAPs

#### PCAP Template Expansion (48 → 62)

Added 14 new PCAP templates: LLDP, CDP, STP, EAPOL, EAP, CoAP, HSRP, PTP, TFTP, Syslog, NBNS, MGCP, OpenFlow, BFD.

#### Gold Promotion (85 → 112)

27 additional protocols promoted to Gold through PCAP template additions and tshark name mapping fixes.

#### Earlier Changes

##### Round-Trip Validation Fixes (Gold: 2 → 36)

Fixed two bugs preventing PCAP round-trip validation for most protocols:

1. **Canonical naming**: Scapy/tshark extractors returned ProtocolDef with source-native names (e.g., "IP" instead of "IPv4"). Stack route lookups failed because STACK_ROUTES uses canonical names. Fix: set `def.name = proto.to_string()` after extraction.

2. **Embedded proto priority**: `resolve_proto` in pcap.rs preferred extracted IR (kernel Ethernet with `h_proto` field) over embedded protos (with `ether_type` field matching STACK_ROUTES dispatch). Fix: prefer embedded protos.

##### Scapy Batch Cache for Curated Audits

Enabled the Scapy batch cache (`--dump-all`, 4,970 classes) for curated protocol audits. Previously only used for discovered-tier audits, leaving curated Scapy extraction to per-protocol subprocess calls that silently failed.

##### Scapy Class Name Fixes

- WireGuard: `WireGuard` → `Wireguard` (case mismatch in Scapy)
- HTTP2: `HTTP2` → `H2Frame` (actual Scapy class name)

##### Scapy Contrib Imports

Added missing imports for GTP, HomePlug_AV, HTTP2, and TLS record layer — enabling field extraction for 4 more protocols.

### Iteration History

| Iter | Key Change | Protocols | Tests |
|------|------------|-----------|-------|
| 22 | Cross-generator round-trip + corpus cross-parse commands | 206 | 400 |
| 21 | Kaitai & Suricata curated integration (8 sources) | 206 | 400 |
| 20 | Gold promotion campaign (Gold 85→112), 62 PCAP templates | 206 | 400 |
| 19 | Suricata as 8th source, 48 PCAP templates, 390 tests | 206 | 390 |
| 18 | Round-trip validation fixes (Gold 2→36) | 206 | 378 |
| 17 | Scapy batch cache + class name fixes | 206 | 378 |
| 16 | Universal PCAP generation (205/206 routable) | 206 | 321 |
| 15 | PCAP route expansion (12→120 routable) | 206 | 293 |
| 14 | PCAP generation + validate command | 206 | 172 |
| 13 | Comprehensive Scapy coverage (109/113) | 113 | 122 |
| 12 | Storage & network storage protocols | 114 | 110 |
| 11 | Multicast, media, embedded structs | 105 | 110 |
| 10 | UDP application protocols | 97 | 109 |
| 9 | Bluetooth + InfiniBand extended | 90 | 109 |
| 8 | Routing & redundancy | 77 | 107 |
| 7 | 28 protocols: UAPI, BT, industrial, legacy | 69 | 107 |
| 6 | etherparse as 5th source | 41 | 107 |
| 5 | Roundtrip & cross-mapping tests | 41 | 93 |
| 4 | Expanded type overrides, cross-source tests | 41 | 71 |
| 3 | TOML-based type mapping system | 41 | — |
| 2 | Zero-field filtering, scapy contrib imports | 41 | — |
| 1 | Structural vs semantic separation, matrix CLI | 41 | — |

### Known Remaining Issues

**Scapy field sizes for ARP** — Scapy's ARP uses `FieldLenField` with a default
hardware address length of 2 bytes (16 bits) rather than 6, since the field
length is protocol-dependent (`ar_hln`). This causes `hwsrc`/`hwdst` to show as
16 bits vs tshark's 48 bits. Not a bug — it reflects ARP's variable-length design.

**tshark combined fields** — tshark sometimes reports combined fields (e.g.,
`ip.version` as 8 bits covering both version and IHL, `tcp.flags` as 16 bits
covering data offset + reserved + flags). These are display artifacts of PDML's
byte-aligned output, not real protocol disagreements.

**IEEE 802.11 offset drift** — kernel's `ieee80211_hdr` and scapy's `Dot11`
disagree on field offsets because scapy includes sub-byte fields (subtype, type,
proto) that the kernel packs into `frame_control`. The cumulative offset drift
causes all subsequent MAC address fields to misalign.

**ICMPv4 scapy extra fields** — Scapy defines 17 fields for ICMP (including
message-type-specific payload fields like `id`, `seq`, `ts_ori`, etc.) vs
kernel's 4-field `icmphdr`. This is expected — the kernel struct is minimal
and message-specific fields are handled elsewhere.

**TLS stays Bronze** — Despite having Scapy fields, tshark reports a single
`tls.record` field at offset 0 spanning 840 bits that overlaps with all
individual fields. No structural agreement possible.
