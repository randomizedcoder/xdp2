# proto-audit Status

## Current State (2026-04-03)

206 curated protocols audited across 7 sources (XDP2, kernel, Scapy, tshark, etherparse, libpcap, Kaitai Struct).
8,358 total protocols tracked (206 curated + 8,152 discovered from tshark/Scapy registries).
378 unit tests including roundtrip, cross-source, PCAP generation, and exhaustive TOML coverage validation.
132 protocols with Silver-tier structural agreement (2+ independent sources agree on field layout).
36 protocols with Gold-tier round-trip validation (IR → PCAP → tshark → IR).
205 protocols routable through PCAP generation (all except TPLINK_SMARTHOME).

### Source Coverage Summary

| Source | Coverage |
|--------|----------|
| XDP2 proto_defs | 222 (206 curated) |
| Etherparse structs | 206/206 curated |
| Libpcap overlays | 206/206 curated |
| Scapy classes | 5,798 (109 curated) |
| tshark filters | 3,753 (3,155 protocols) |
| Kernel structs | 74 (173 in registry) |
| Kaitai Struct | ~20 protocols |
| Multi-source (2+) | 1,198 |

### Validation Tier Breakdown

| Tier | Count | Meaning |
|------|-------|---------|
| Gold | 36 | Round-trip validated (IR → PCAP → tshark → IR matches) |
| Silver | 132 | 2+ independent sources agree on field layout |
| Bronze | 48 | Single source, self-consistent |
| Unvalidated | ~8,100 | Discovered but not yet verified |

### Gold-Validated Protocols (36)

Round-trip validated through wire bytes — IR serialized to PCAP, parsed by tshark, extracted back to IR, field-by-field comparison passes:

Ethernet, STP, ARP, UDP, SCTP, ICMPv4, IGMP, ESP, AH, EAPOL, LLC, SNAP,
Slow_Protocols, MAC_Control, IEC_GOOSE, IEC_SV, NBNS, TFTP, ICMPv6, UDPLite,
MLD, IPv6_ND, HCI_CMD, HCI_Event, HCI_SCO, HCI_ISO, CAN_FD, IEEE802154,
SLL, SLL2, ERSPAN, ERF

### Recent Changes

#### Round-Trip Validation Fixes (Gold: 2 → 36)

Fixed two bugs preventing PCAP round-trip validation for most protocols:

1. **Canonical naming**: Scapy/tshark extractors returned ProtocolDef with source-native names (e.g., "IP" instead of "IPv4"). Stack route lookups failed because STACK_ROUTES uses canonical names. Fix: set `def.name = proto.to_string()` after extraction.

2. **Embedded proto priority**: `resolve_proto` in pcap.rs preferred extracted IR (kernel Ethernet with `h_proto` field) over embedded protos (with `ether_type` field matching STACK_ROUTES dispatch). Fix: prefer embedded protos.

#### Scapy Batch Cache for Curated Audits

Enabled the Scapy batch cache (`--dump-all`, 4,970 classes) for curated protocol audits. Previously only used for discovered-tier audits, leaving curated Scapy extraction to per-protocol subprocess calls that silently failed.

#### Scapy Class Name Fixes

- WireGuard: `WireGuard` → `Wireguard` (case mismatch in Scapy)
- HTTP2: `HTTP2` → `H2Frame` (actual Scapy class name)

#### Scapy Contrib Imports

Added missing imports for GTP, HomePlug_AV, HTTP2, and TLS record layer — enabling field extraction for 4 more protocols.

### Iteration History

| Iter | Key Change | Protocols | Tests |
|------|------------|-----------|-------|
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
