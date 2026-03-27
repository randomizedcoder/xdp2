# proto-audit Status

## Current State (Iteration 11)

105 protocols audited across 5 sources (XDP2, kernel, scapy, tshark, etherparse).
9 protocols have etherparse coverage (Ethernet, VLAN, IPv4, IPv6, ARP, TCP, UDP, ICMPv4, ICMPv6).
110 unit tests including roundtrip, cross-source, and exhaustive TOML coverage validation.

### Iteration 11b: Kernel Extractor — Embedded Struct Support

Enhanced the kernel C struct parser to handle embedded `struct X` fields
(e.g., `struct icmp6hdr mld_hdr;`) instead of silently skipping them.

**Core change:** When the parser encounters `struct X name;`, it now treats
the struct name as a type and looks it up in a new `[struct_sizes]` TOML table.

**New TOML section** (`kernel.toml`):
```toml
[struct_sizes]
icmp6hdr = 64    # 8 bytes
in6_addr = 128   # 16 bytes
in_addr = 32     # 4 bytes
```

**Files modified:**
- `mappings/kernel.toml`: Added `[struct_sizes]` table
- `src/type_mapping.rs`: Added `struct_sizes` field to `KernelMappings`, extended `type_bits()`
- `src/extractors/kernel.rs`: Changed `struct` handling from skip to parse-as-type

**Impact:** MLD structs (`mld_msg`, `mld2_query`, `mld2_report`) now produce
fields instead of empty results. Any future kernel struct with embedded
`struct in6_addr` or `struct icmp6hdr` fields will also work.

Test count: 109 → 110 (+1 test: `test_mld_msg_embedded_structs`).

### Iteration 11: Multicast & Media/Streaming Protocols (97 → 105)

Added **8 protocols** for multicast and media streaming.

**Multicast (5):** IGMPv3_Query, IGMPv3_Report, MLD, MLDv2_Query, MLDv2_Report
- IGMPv3 has kernel structs in `linux/igmp.h` + Scapy classes in `scapy.contrib.igmpv3`
- MLD/MLDv2 have kernel structs in `net/mld.h` (internal, not UAPI)
- MLD maps to `ICMPv6MLQuery` in Scapy; MLDv2 has no Scapy support
- Existing `IGMP` entry covers v1/v2 (`igmphdr`)

**Media/Streaming (3):** RTP, MPEG_TS, SRT
- RTP has Scapy class (`scapy.layers.rtp`) + tshark
- MPEG_TS is tshark-only (`mp2t`), fixed 188-byte packets
- SRT is tshark-only (UDP-based low-latency streaming)

**Supporting changes:**
- `scapy_dump.py`: Added `scapy.contrib.igmpv3` import

### Iteration 10: UDP Application Protocols (91 → 97)

Added **6 UDP application-layer protocols** — none have XDP2 parsers or kernel
structs, but all are fundamental network protocols with broad Scapy and/or
tshark coverage.

**Added:** DNS, NTP, SNMP, DHCP (BOOTP-based), DHCPv6, QUIC
- DNS, NTP, SNMP, DHCP, DHCPv6 have Scapy classes (all in standard `scapy.layers.*`)
- QUIC is tshark-only (no Scapy support yet)
- MoQ (Media over QUIC) skipped — still a draft protocol with no dissector support

### Iteration 9: Bluetooth & InfiniBand Upper Layers (77 → 90)

Added **13 protocols** to deepen Bluetooth and InfiniBand family coverage beyond
the base headers already mapped.

**Bluetooth upper layers (6):** BT_ATT, BT_SMP, BT_RFCOMM, BT_BNEP, BT_SDP, BT_AVDTP
- ATT and SMP have Scapy classes (`ATT_Hdr`, `SM_Hdr` in `scapy.layers.bluetooth`)
- RFCOMM, BNEP, SDP, AVDTP are tshark-only (no Scapy core classes)
- None have XDP2 parsers — these operate above L2CAP

**InfiniBand extended transport headers (7):** IB_DETH, IB_RETH, IB_AETH, IB_RDETH,
IB_AtomicETH, IB_ImmDt, IB_MAD
- All tshark-only (Scapy's `scapy.contrib.roce` only covers BTH/GRH)
- These are the per-operation headers that follow BTH in IB packets

### Iteration 8: Routing & Redundancy Protocols (69 → 77)

Added **8 scapy+tshark protocols** with no XDP2 or kernel coverage — these are
higher-layer routing and redundancy protocols that XDP2 doesn't parse but are
valuable for understanding cross-source coverage gaps.

**Redundancy (2):** VRRP (VRRPv3), HSRP
**Discovery (1):** CDP
**Routing (5):** RIP, OSPF, ISIS, BGP, EIGRP

**Supporting changes:**
- `scapy_dump.py`: Added 5 contrib imports (cdp, ospf, isis, bgp, eigrp)
- VRRP, HSRP, RIP are in standard `scapy.layers` (loaded by `scapy.all`)

These protocols highlight the audit matrix's value: they show where XDP2 has
no coverage while Scapy and tshark both do — useful for prioritizing future
XDP2 parser development.

### Iteration 7: Expanded Protocol Coverage (41 → 69)

Added **28 new protocols** to the audit matrix, making it a near-complete inventory
of XDP2's protocol coverage. The additions span UAPI kernel protocols, Bluetooth
variants, management/industrial protocols, and legacy/niche protocols.

**Batch 1 — UAPI Kernel Protocols (8):**
IPv6_EH, IPv6_ND, IEEE802154, MCTP, Phonet, GenNetlink, NLAttr, TIPC

**Batch 2 — Bluetooth Variants + EAPOL + CAN_XL (7):**
HCI_CMD, HCI_ACL, HCI_Event, HCI_SCO, HCI_ISO, EAPOL, CAN_XL

**Batch 3 — Management & Industrial (10):**
TRILL, BATMAN, DSA, EDSA, CFM, FIP, MAC_Control, MVRP, NC_SI, Slow_Protocols

**Batch 4 — Legacy/Niche (3):**
PROFINET, X25, ATM

**Supporting changes:**
- `kernel.toml`: Added `__be32:4` array_endian_override for TIPC
- `scapy_dump.py`: Added `dot15d4`, `bluetooth`, `eap` imports
- 2 new cross-source tests (IPv6_EH kernel+scapy, IEEE802154 kernel+scapy)

**Protocols deliberately excluded:** version dispatchers (`xdp2_parse_ip`),
encap duplicates (`ipv4ip`/`ipv6ip`), sub-parsers (`l2tp_v0_*`, `ipv6_routing_hdr`),
generic wrappers (`ports`, `protobufs`).

Test count: 107 → 109 (+2 tests).

### Iteration 6: Etherparse Source + "Adding a Source" Guide

Added **etherparse** as a 5th protocol definition source, proving the architecture
is extensible across languages (Rust vs C vs Python vs XML). Shipped alongside a
comprehensive guide document (`docs/adding-a-source.md`) using etherparse as the
worked example.

**New modules:**
- `src/extractors/etherparse.rs` — Rust struct parser + IR conversion (~320 lines + ~210 lines tests)
- `mappings/etherparse.toml` — type/endian/field/implicit-field/flag mappings

**Key design decisions:**
- Wire-accurate bit widths in TOML (e.g., `IpDscp` → 6 bits, not 8)
- Implicit field handling via TOML `start_offset_bits` and `gaps` (IPv4 version/IHL, IPv6 version, TCP data_offset/reserved)
- TCP flag wire ordering via `flag_bit_offsets` table (struct order ≠ wire order)
- `EtherparseMappings` struct with extra sections beyond `KernelMappings`

**New type mapping structs:**
- `EtherparseMappings` — extends base with `implicit_fields` and `flag_bit_offsets`
- `ImplicitFieldConfig` — start_offset_bits + gaps
- `GapEntry` — after field name + skip_bits

**Name mapping extensions:**
- Added `etherparse_struct` and `etherparse_file` fields to `ProtocolNames`
- Populated 9 protocols, `find_by_etherparse_struct()` lookup

**Tests added:**
- 7 extractor unit tests (parsing, array fields, non-pub field skipping, offset calculations)
- 5 roundtrip tests (Ethernet, UDP, IPv4, TCP, IPv6)
- 2 four-way cross-source tests (Ethernet: kernel+scapy+tshark+etherparse, UDP: same)

**Nix integration:**
- `etherparseSrc` in `nix/proto-audit-sources.nix` (fetchFromGitHub, pinned hash)
- `PROTO_AUDIT_ETHERPARSE_SRC` env var in proto-audit wrapper
- `--etherparse-src` flag in `protoAuditFlags`

Test count: 93 → 107 (+14 tests).

### Iteration 5: Roundtrip & Cross-Mapping Tests

Added bidirectional verification of the TOML translation layer — proving that
source → IR → reverse-lookup is consistent, and that different sources agree
when mapped through the IR.

**New modules:**
- `src/test_data.rs` — shared test constants (7 kernel structs, 5 Scapy JSON, 2 tshark PDML)
- `src/roundtrip_tests.rs` — 14 roundtrip golden-output tests (kernel×7, scapy×4, tshark×3)

**Reverse lookup methods** added to `type_mapping.rs`:
- `KernelMappings::field_names_for_type()` — invert field_type_overrides
- `KernelMappings::c_types_for()` — find C types matching bit width + endian
- `ScapyMappings::classes_for_type()` — invert field_types table
- `TsharkMappings::matches_for()` — check if a type+bits combo is reachable

**Cross-source tests upgraded** (comparator.rs):
- IPv4, Ethernet, UDP upgraded from 2-way → 3-way (kernel+scapy+tshark)
- ARP (kernel+scapy) and TCP (kernel+scapy) added as new cross-source tests

**Exhaustive TOML coverage tests** (type_mapping.rs):
- `test_kernel_all_field_overrides_roundtrip` — every kernel override is forward+reverse consistent
- `test_scapy_all_field_types_roundtrip` — every scapy class mapping is forward+reverse consistent
- `test_tshark_all_patterns_exercised` — every tshark pattern produces the declared type

Test count: 71 → 93 (+22 tests).

### Iteration 4: Expanded Translations & Cross-Source Testing

**Kernel field type overrides added:**

| Field | Type | Rationale |
|-------|------|-----------|
| `code` | Enum | ICMP/IGMP code (IANA sub-type registry) |
| `icmp6_code` | Enum | ICMPv6 code (IANA sub-type registry) |
| `h_vlan_encapsulated_proto` | Enum | VLAN encapsulated EtherType (IEEE 802) |
| `h_vlan_TCI` | Flags | VLAN tag control info (PCP + DEI + VID packed) |

**Scapy class mappings added:**

| Class | Type | Rationale |
|-------|------|-----------|
| `EnumField` | Enum | Generic Scapy enum field |
| `XShortEnumField` | Enum | Hex-display enum (EtherType fields in Ether/VLAN) |
| `LongEnumField` | Enum | 64-bit enum field |
| `MultiEnumField` | Enum | Multi-value enum field |

**Key distinction**: `XShortEnumField` → Enum (used for EtherType — closed registry),
but `ShortEnumField` stays Uint (used for ports — open namespace).

**tshark patterns added:**
- `.code` at ≤8 bits → Enum (ICMP/ICMPv6 code)
- `.addr` at 128 bits → Ipv6Addr
- Extended blocklist: `.stream`, `.segment`, `.analysis`, `.reassembled_in`, `.reassembled.length`

**Cross-source agreement tests:**
- IPv4: kernel `iphdr` + scapy `IP` — validates `protocol`/`proto` both Enum, `saddr`/`src` both Ipv4Addr
- Ethernet: kernel `ethhdr` + scapy `Ether` — validates MAC types and `h_proto`/`type` both Enum
- UDP: kernel `udphdr` + scapy `UDP` — validates all 4 fields agree (ShortEnumField→Uint fix)

### Iteration 3: Extensible Type Mapping System

**Core change**: Replaced hardcoded type inference logic in all three extractors
(kernel, scapy, tshark) with an extensible TOML-based mapping system. Developers
can now add or correct type mappings by editing `mappings/*.toml` — no Rust code
changes needed.

#### Type Mapping System

- **`mappings/kernel.toml`** — C type → bit width/endianness, field name overrides
  (e.g., `protocol` → Enum, `h_proto` → Enum, `nexthdr` → Enum)
- **`mappings/scapy.toml`** — Scapy field class → IR type, with documented
  rationale for deliberate non-mappings (e.g., `ShortEnumField` stays Uint)
- **`mappings/tshark.toml`** — tshark field name patterns → IR type, blocklist
- **`src/type_mapping.rs`** — TOML loader with embedded defaults via `include_str!()`
- Mappings are overridable via `--mappings-dir` or `PROTO_AUDIT_MAPPINGS_DIR`

#### Kernel field type overrides (new Enum/address classifications)

| Field | Type | Rationale |
|-------|------|-----------|
| `protocol` | Enum | IPv4 protocol number (IANA registry) |
| `h_proto` | Enum | EtherType (IEEE 802 registry) |
| `nexthdr` | Enum | IPv6/extension header next-header (IANA) |
| `ar_hrd` | Enum | ARP hardware type (IANA) |
| `ar_pro` | Enum | ARP protocol type (EtherType) |
| `ar_op` | Enum | ARP operation code (IANA) |
| `type` | Enum | ICMP/IGMP message type (IANA) |
| `icmp6_type` | Enum | ICMPv6 message type (IANA) |
| `group` | Ipv4Addr | IGMP multicast group address (32-bit only) |

#### Scapy ShortEnumField → Uint (not Enum)

Scapy uses `ShortEnumField` for TCP/UDP ports because it has a well-known-port
lookup table. But kernel headers declare ports as `__be16` (Uint). Ports are an
open 16-bit namespace, not a closed enumeration like EtherType. This eliminates
false type-diff findings for TCP/UDP port fields.

#### tshark operator precedence fix

Fixed `name.contains("proto") || name.contains("type") && bits <= 16` →
proper parenthesization via the TOML mapping system. The `enum_patterns` table
applies `max_bits` to each pattern independently.

#### Scapy helper improvements

- **5 new contrib imports**: `macsec`, `lldp`, `erspan`, `nsh`, `hsr` — enables
  extraction of these protocols from Scapy
- **Recursive subclass search**: replaced 2-level search with full recursive
  `search(Packet)` function, catching deeply nested packet classes

#### Comparator fix

- **Pairwise endian comparison**: compares all pairs in a field slot, not just
  against the first source. Catches B-vs-C disagreements even when A agrees
  with both individually.

### Expected Impact

| Protocol | Before (Agree/TDiff) | After (Agree/TDiff) | Key change |
|----------|---------------------|---------------------|------------|
| Ethernet | 2/1 | 3/0 | `h_proto` → Enum |
| IPv4 | 7/1 | 8/0 | `protocol` → Enum |
| IPv6 | 2/1 | 3/0 | `nexthdr` → Enum |
| UDP | 2/2 | 4/0 | ShortEnumField → Uint |
| TCP | 5/2 | 7/0 | ShortEnumField → Uint |
| ARP | 1/4 | 5/0 | `ar_hrd`/`ar_pro`/`ar_op` → Enum |
| IGMP | 2/2 | 4/0 | `type` → Enum, `group` → Ipv4Addr |
| ICMPv4 | 3/1 | 4/0 | `type` → Enum |
| ICMPv6 | 2/1 | 3/0 | `icmp6_type` → Enum |
| AH | 4/1 | 5/0 | `nexthdr` → Enum |
| SRv6 | 5/1 | 6/0 | `nexthdr` → Enum |

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

## Iteration 2 Changes

1. Zero-field source filtering (XDP2 excluded from field comparison)
2. Scapy contrib imports (igmp, geneve)
3. tshark non-header field filtering (payload/padding/trailer blocklist)
4. Kernel `__sum16` endian fix → Big
5. Kernel MAC address endian fix → Big
6. Scapy `Emph`/`ConditionalField` unwrapping

## Iteration 1 Changes

- Structural vs semantic agreement separation
- Unified field map (no reference-source bias)
- Kernel inline `/* ... */` comment handling
- Kernel `#if 0` dead-code block skipping
- Kernel `__struct_group()` macro unwrapping
- IGMP PCAP packet generation
- Geneve→scapy name mapping
- `matrix` and `findings` CLI commands
