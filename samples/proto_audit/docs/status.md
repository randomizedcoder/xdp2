# proto-audit Status

## Current State (Iteration 16)

113 protocols audited across 6 sources (XDP2, kernel, scapy, tshark, etherparse, libpcap).
109 protocols have Scapy coverage (up from ~71). 9 have etherparse coverage.
321 unit tests including roundtrip, cross-source, PCAP generation, and exhaustive TOML coverage validation.
79 protocols with full cross-source agreement, 28 with field splits.
205 protocols routable through PCAP validation (up from ~120). Only TPLINK_SMARTHOME remains unsupported.

### Iteration 16: Universal PCAP Generation — All 207 Protocols (120 → 205)

Extended the PCAP generator from ~120 Ethernet-rooted protocols to **205/206**
by adding multi-DLT support, allowing non-Ethernet link types (Bluetooth,
InfiniBand, CAN, 802.15.4, Netlink, etc.) and a Wireshark Upper PDU fallback.

**Multi-DLT architecture:**
- `LINK_ROOTS` table maps 18 root protocols to their PCAP Data Link Types
- `build_protocol_stack` now terminates at any root, not just Ethernet
- `pcap_global_header` parameterized with `link_type` from the root
- `PcapOutput` carries `link_type` for downstream consumers
- `is_root()` and `stack_route_for()` exported for dynamic stack walking

**New protocol families:**
- **Bluetooth** (+13): HCI root (DLT=187) → HCI_CMD/ACL/SCO/Event/ISO → L2CAP → BT_ATT/SMP; BT_RFCOMM/BNEP/SDP/AVDTP via UpperPDU
- **InfiniBand** (+10): IB_LRH root (DLT=247) → IB_GRH/BTH → DETH/RETH/AETH/RDETH/AtomicETH/ImmDt/MAD
- **CAN bus** (+3): CAN/CAN_FD/CAN_XL as standalone roots (DLT=227)
- **802.2 LLC/SNAP** (+5): Ethernet_802_3 → LLC → STP/ISIS; LLC → SNAP → CDP
- **Standalone roots** (+17): IEEE802.11, IEEE802154, SLL, SLL2, Netlink, PPP, ATM, FC, ERF, MPEG_TS + children (Zigbee, GenNetlink)
- **UpperPDU fallback** (+12): DLT=252 with TLV dissector preamble for SCSI, iSER, NTLMSSP, OCSP, Phonet, MCTP, X25, DSA, BT_RFCOMM/BNEP/SDP/AVDTP

**Easy route additions** (+23): WOL, LLTD, EDSA, CARP, RSVP, BACnet, GLBP, GUE, HSRP, MGCP, MPLS_OAM, Teredo, NetFlow_v9, ONC_RPC, HTTP2, IEC_MMS, SMB2, STT, ZeroMQ, LDP, iSCSI, NFS, NVMe

**Sub-protocol dispatch** (+9): IGMPv3_Query/Report (via IGMP type), IPv6_ND/MLD/MLDv2_Query/MLDv2_Report (via ICMPv6 type), SCTP_Chunk, EAP, CIP

**New embedded protocol definitions** (~30): IGMP, ICMPv6, SCTP, EAPOL, ENIP, HCI, HCI_ACL, L2CAP, IB_LRH, IB_GRH, IB_BTH, CAN, CAN_FD, CAN_XL, IEEE802.11, IEEE802154, SLL, SLL2, Netlink, GenNetlink, PPP, ATM, FC, ERF, MPEG_TS, Zigbee_NWK, Ethernet_802_3, LLC, SNAP, UpperPDU

**Dynamic `build_proto_map`** walks STACK_ROUTES from target to root, extracting only the protocols actually needed for the stack.

**Tests:** 321 total (up from 293). New tests: per-family stack verification, multi-DLT integration (BT_ATT DLT=187, STP 802.3 framing, SCSI UpperPDU DLT=252), link type verification for all roots, UpperPDU preamble format, `is_root` helper.

### Iteration 15: PCAP Route Expansion (12 → ~120 protocols)

Expanded `STACK_ROUTES` from 12 to ~120 protocols across 5 dispatch layers,
making the PCAP generator and `validate` command usable for the vast majority
of Ethernet-routable protocols.

**STACK_ROUTES expansion:**
- **Phase 1 (L2):** +31 Ethernet-direct protocols (RARP, MPLS, PPPoE, LLDP, PTP, EAPOL, MACsec, QinQ, PBB, TRILL, EtherCAT, PROFINET, FCoE, FIP, Slow_Protocols, LACP, MAC_Control, CFM, HSR, BATMAN, NSH, HomePlug_AV, AoE, MVRP, NC_SI, IEC_GOOSE, IEC_SV, IPX, AppleTalk, TIPC, PPPoED)
- **Phase 2 (L3):** +15 IPv4/IPv6 protocols (OSPF, VRRP, PIM, L2TP, ESP, AH, IP_in_IP, DCCP, UDPLite, EIGRP, IPv6_EH, IPv6_DestOpts, IPv6_Routing, IPv6_Fragment, SRv6)
- **Phase 3 (L4):** +35 UDP-routed, +23 TCP-routed, +3 GRE-tunneled protocols

**New embedded protocol definitions:**
- UDP (64-bit, 4 fields, dispatches on `dst_port`)
- TCP (160-bit, 10 fields, dispatches on `dst_port`)
- GRE (32-bit, 2 fields, dispatches on `protocol_type`)

**New fixup functions:**
- `fixup_ipv6()`: sets IPv6 `payload_length` after serialization
- `fixup_udp_length()`: sets UDP `length` after serialization

**`build_proto_map` expanded** to resolve UDP, TCP, and GRE as intermediate
stack protocols (commands.rs).

**Documentation:** PCAP_UNSUPPORTED list (~30 unreachable protocols), updated
validation.md with full route table and unreachable protocol documentation.

**Tests:** 121 new tests (293 total, up from 172). Includes per-route stack
verification, embedded protocol serialization, fixup validation, full PCAP
generation for UDP/TCP/GRE multi-layer stacks, and a comprehensive
`test_all_stack_routes_resolve` sweep.

### Iteration 14: PCAP Generation & Round-Trip Validation

Added PCAP as the **4th code generation target** and `validate` as the **9th
CLI command**, enabling true round-trip IR validation through wire bytes.

**PCAP generator (`src/generator/pcap.rs`):**
- Generates a complete PCAP file containing one minimal packet for a target protocol
- Builds full encapsulation stack via `STACK_ROUTES` dispatch table (child → parent → dispatch field → value)
- Covers Ethernet-rooted L2–L4 protocols (IPv4, IPv6, ARP, VLAN, TCP, UDP, ICMP, GRE, SCTP, IGMP)
- Embedded fallback `ProtocolDef` for Ethernet, IPv4, IPv6 when extracted IR unavailable
- Field-level bitpacking serializer with type-based defaults (addresses, version, TTL)
- IPv4 `total_length` and header checksum fixup (RFC 791 ones-complement)
- Hex dump output via `--dry-run`

**Validate command:**
- Full round-trip: IR → PCAP → tshark → IR → compare
- Uses standard comparator for field-by-field agreement analysis
- `--keep-pcap` to save generated PCAP for manual inspection
- Text and JSON output formats

**Tests:** 27 new tests (22 PCAP unit tests + 5 round-trip validation tests).
Total: 145 → 172.

See [Round-Trip Validation](validation.md) for usage and design details.

### Iteration 13: Comprehensive Scapy Coverage

Expanded Scapy coverage from ~71 to **109 out of 113 protocols**, eliminating
all `scapy: None` entries from the name mapping table.

**Category A — Wired 11 existing Scapy classes:**
RARP (`ARP`), PTP, AoE (`AOE`), EtherCAT (`EtherCat`), Slow_Protocols
(`SlowProtocol`), PROFINET (`ProfinetIO`), MAC_Control (`MACControlPause`),
MLDv2_Query (`ICMPv6MLQuery2`), MLDv2_Report (`ICMPv6MLReport2`), ONC_RPC
(`RPC`), QUIC (`QUIC_Initial`).

**Category B — Created 27 new Scapy protocol modules (19 new files):**

*New contrib files:*
- `pbb.py` (PBB), `trill.py` (TRILL), `mpeg_ts.py` (MPEG_TS), `srt.py` (SRT)
- `dsa.py` (DSA + EDSA), `batman.py` (BATMAN_OGM), `cfm.py` (CFM)
- `ncsi.py` (NCSI), `fip.py` (FIP), `mvrp.py` (MVRP)
- `netlink_proto.py` (NetlinkHeader + GenlMsgHdr + NLAttr)
- `ipx.py` (IPX), `appletalk.py` (DDP), `x25.py` (X25), `atm.py` (ATM)
- `iscsi.py` (iSCSI_BHS), `nvme.py` (NVMe_Command), `scsi.py` (SCSI_LUN), `iser.py` (iSER_Ctrl)

*Extended existing files:*
- `infiniband.py`: Added IB_RDETH, IB_AtomicETH, IB_ImmDt, IB_MAD
- `bluetooth.py`: Added HCI_ISO_Hdr, RFCOMM_Hdr, BNEP, SDP_Hdr, AVDTP_Hdr

**Zero-field mapping fixes (3):**
- ERSPAN: `ERSPAN` (0 fields) → `ERSPAN_II` (8 fields)
- QUIC: `QUIC` (0 fields, dispatch-only) → `QUIC_Initial` (14 fields)
- MAC_Control: `MACControl` (0 fields) → `MACControlPause` (2 fields)

**Remaining 4 without Scapy (pre-existing):**
- HSR: `scapy.contrib.hsr` does not exist in this Scapy version
- CAN/CAN_FD: CAN classes require SocketCAN, not importable in standard context
- HCI_SCO: HCI_SCO_Hdr is socket-level, not a Packet subclass

**Matrix results after this iteration:**
- 113 protocols, 109 with Scapy coverage
- 79 with full cross-source agreement (up from 76)
- 28 with field splits (unchanged)

Test count: 122 (unchanged — no new Rust tests, but all existing pass).

### Iteration 12: Storage & Network Storage Protocols (105 → 114)

Added **9 protocols** for storage and network storage.

**Storage (5):** iSCSI, NVMe, FC (Fibre Channel), SCSI, iSER
- iSCSI, SCSI, iSER have kernel structs in `scsi/` headers (internal)
- NVMe has kernel structs in `linux/nvme.h` (internal)
- FC has UAPI kernel structs in `uapi/scsi/fc/fc_fs.h`
- All have tshark dissectors; none have Scapy support

**Network Storage (4):** NFS, SMB, SMB2, ONC_RPC
- NFS has Scapy class (`NFS_Call` in `scapy.contrib.nfs`)
- SMB/SMB2 have Scapy classes (`SMB_Header`, `SMB2_Header` in `scapy.layers.smb*`)
- ONC_RPC is tshark-only (`rpc`)

### Iteration 11: Multicast, Media, Embedded Structs (97 → 105)

Added **8 protocols** (IGMPv3_Query, IGMPv3_Report, MLD, MLDv2_Query,
MLDv2_Report, RTP, MPEG_TS, SRT). Enhanced kernel extractor to handle
embedded `struct X name;` fields via `[struct_sizes]` TOML table, fixing
MLD struct extraction.

Test count: 107 → 110.

### Iterations 1–10 Summary

| Iter | Protocols | Key Change | Tests |
|------|-----------|------------|-------|
| 10 | 91 → 97 | UDP application protocols (DNS, NTP, SNMP, DHCP, DHCPv6, QUIC) | 109 |
| 9 | 77 → 90 | Bluetooth upper layers (6) + InfiniBand extended headers (7) | 109 |
| 8 | 69 → 77 | Routing & redundancy (VRRP, HSRP, CDP, RIP, OSPF, ISIS, BGP, EIGRP) | 107 |
| 7 | 41 → 69 | 28 protocols: UAPI kernel, Bluetooth, management/industrial, legacy | 107 |
| 6 | — | etherparse as 5th source + "Adding a Source" guide | 93 → 107 |
| 5 | — | Roundtrip & cross-mapping tests, reverse lookup methods | 71 → 93 |
| 4 | — | Expanded kernel/scapy/tshark type overrides, cross-source tests | 71 |
| 3 | — | TOML-based type mapping system (replaced hardcoded inference) | — |
| 2 | — | Zero-field filtering, scapy contrib imports, tshark blocklist | — |
| 1 | — | Structural vs semantic separation, unified field map, matrix/findings CLI | — |

### Expected Impact (from iteration 3)

| Protocol | Before (Agree/TDiff) | After (Agree/TDiff) | Key change |
|----------|---------------------|---------------------|------------|
| Ethernet | 2/1 | 3/0 | `h_proto` → Enum |
| IPv4 | 7/1 | 8/0 | `protocol` → Enum |
| IPv6 | 2/1 | 3/0 | `nexthdr` → Enum |
| UDP | 2/2 | 4/0 | ShortEnumField → Uint |
| TCP | 5/2 | 7/0 | ShortEnumField → Uint |
| ARP | 1/4 | 5/0 | `ar_hrd`/`ar_pro`/`ar_op` → Enum |

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
