# Zero-Field Protocols Analysis

**Last updated:** 2026-04-16  
**Count:** 278 protocols at 0/8 in pipeline-matrix (zero IR fields from all extractors)

## Root Cause

These protocols are defined in the name_mapping table but all extractors
return zero fields. The pipeline can't generate meaningful PCAPs without
field definitions. 92.4% (257) have tshark dissectors defined — the
bottleneck is not source coverage but PCAP data and extraction depth.

## Source Coverage Breakdown

| Source Combination | Count | % |
|-------------------|-------|---|
| xdp2 + tshark + etherparse + libpcap | 118 | 42.4% |
| xdp2 + tshark only | 65 | 23.4% |
| xdp2 + scapy + tshark + etherparse + libpcap | 43 | 15.5% |
| xdp2 + tshark + scapy | 3 | 1.1% |
| xdp2 + omi only (SoupBinTCP) | 5 | 1.8% |
| Other combinations | 44 | 15.8% |

## Categories

### Bucket 1: Simple Fixed-Header with RFCs (52 protocols) -- HIGH PRIORITY

These have well-defined RFCs and fixed binary headers (5-20 fields).
Best candidates for hand-written IR definitions.

| Protocol | RFC/Spec | Header Size | Notes |
|----------|----------|-------------|-------|
| CARP | RFC 5798 | 20 bytes | Common Address Redundancy |
| DCCP | RFC 4340 | 12-28 bytes | Datagram Congestion Control |
| UDPLite | RFC 3828 | 8 bytes | UDP-Lite (checksum coverage) |
| IPComp | RFC 3173 | 4 bytes | IP Payload Compression |
| GRE6 | RFC 7619 | 24+ bytes | GRE over IPv6 |
| GRE_Cisco | RFC 1701 | 24+ bytes | Cisco GRE extensions |
| GUE | RFC 8926 | 4-8 bytes | Generic UDP Encapsulation |
| LISP | RFC 6830 | 8+ bytes | Locator/ID Separation |
| LISP_Control | RFC 6833 | 24+ bytes | LISP control messages |
| SixInFour | RFC 4213 | minimal | IPv6-in-IPv4 tunnel |
| SixToFour | RFC 3056 | minimal | 6to4 tunnel |
| IPv6_HopByHop | RFC 2460 | 8+ bytes | IPv6 extension header |
| IPv6_MobileIP | RFC 6275 | variable | IPv6 mobility |
| RIPng | RFC 2080 | 4+ bytes | RIPng for IPv6 |
| OSPFv3 | RFC 5340 | 16+ bytes | OSPF version 3 |
| PIM | RFC 4601 | 8+ bytes | Protocol Independent Multicast |
| PIM_Assert | RFC 4601 | 20 bytes | PIM assertion messages |
| PIM_BSR | RFC 4601 | ~25 bytes | Bootstrap router |
| PIMv6 | RFC 3973 | 8+ bytes | PIM for IPv6 |
| MSDP | RFC 3618 | 40+ bytes | Multicast Source Discovery |
| PCP | RFC 6887 | 24 bytes | Port Control Protocol |
| PFCP | 3GPP TS 29.244 | 16+ bytes | Packet Forwarding Control |
| GTP_U_V1 | 3GPP TS 29.281 | 8-12 bytes | GTP User plane v1 |
| GTP_V0 | 3GPP TS 09.60 | 20 bytes | GTP v0 (legacy) |
| GTPv2_C | 3GPP TS 29.274 | 16 bytes | GTP v2 Control |
| HSRP | RFC 2281 | 20 bytes | Hot Standby Router |
| OWAMP | RFC 4656 | 80 bytes | One-way Active Measurement |
| TWAMP | RFC 5357 | 40+ bytes | Two-way Active Measurement |
| MPLS_Echo | RFC 4379 | 8+ bytes | MPLS Ping/Traceroute |
| MPLS_TP | RFC 5960 | 4+ bytes | MPLS Transport Profile |
| Y1731 | IEEE 802.1ag | 8+ bytes | Ethernet OAM |
| ERF | Endace DAG | 16 bytes | Extensible Record Format |
| DNP3 | IEEE 1815 | 10+ bytes | SCADA control |
| DoIP | ISO 13400-2 | 8 bytes | Diagnostics over IP |
| AIS | ITU-R M.1371 | 30 bytes | Ship identification |
| DNS_TCP | RFC 1035 | 12+ bytes | DNS over TCP wrapper |
| DoT | RFC 7858 | TLS+DNS | DNS over TLS |
| ECHO | RFC 862 | minimal | Echo service |
| DISCARD | RFC 863 | minimal | Discard service |
| CHARGEN | RFC 864 | minimal | Character generation |
| DAYTIME | RFC 867 | minimal | Daytime service |
| PTP_V1 | IEEE 1588 v1 | 68 bytes | Precision Time v1 |
| gPTP | IEEE 802.1AS | 60+ bytes | Generalized PTP |
| EDSA | Marvell DSA | 4 bytes | EtherType DSA tagging |
| IPX | Novell spec | 30 bytes | Internetwork Packet Exchange |
| FCoE | T11 FC-BB-5 | 14+ bytes | Fibre Channel over Ethernet |
| STT | draft-davie-stt | 18 bytes | Stateless Transport Tunneling |
| NVGRE | RFC 7637 | 8 bytes | Network Virtualization using GRE |
| EtherIP | RFC 3378 | 2 bytes | Ethernet-in-IP |
| AVTP | IEEE 1722 | 12+ bytes | Audio/Video Transport |
| L2TPv3 | RFC 3931 | 12 bytes | L2TP version 3 |
| VXLAN_GPE | draft-ietf-nvo3 | 8 bytes | VXLAN Generic Protocol Extension |

### Bucket 2: Variable-Length/Complex Protocols (78 protocols) -- LOW PRIORITY

ASN.1, TLV-based, or text-based formats hard to define as fixed IR.

| Category | Protocols | Count |
|----------|-----------|-------|
| ASN.1-encoded | SNMP_Trap, SNMPv3, CMP, TCAP, ISUP, NAS_5GS, NAS_EPS, NGAP, S1AP | ~15 |
| TLV/attribute-based | DHCP_Option, DHCPv6_Option, LLDP extensions, RADIUS variants, EAP variants, PROFINET_DCP, MCTP | ~20 |
| Text/HTTP-based | HTTP2, HTTP3, DoH, gRPC, IRC, NATS, NETCONF, XMPP, NNTP, POP3, SMTP | ~18 |
| Binary frame-based | EtherCAT, PROFINET, IEC_104, Matter, SOME_IP, NVMe, S7COMM | ~12 |
| Financial/exchange | ITCH_v5_* (11), SoupBinTCP_* (5), PITCH_v2_* (3), SBE_MDP3_*, EOBI_* | ~25 |

### Bucket 3: Sub-Protocols/Message-Types (28 protocols) -- MEDIUM PRIORITY

Sub-types of already-passing parent protocols. Could inherit parent IR.

| Parent | Sub-protocols |
|--------|--------------|
| CAN (8/8) | CAN_FD, CAN_J1939, CAN_OBD2, CAN_TP |
| Bluetooth (HCI 8/8) | BT_ATT, BT_AVDTP, BT_RFCOMM, BT_SDP, BT_SMP, HCI_ISO, HCI_SCO, L2CAP, LMP |
| InfiniBand | IB_AETH, IB_AtomicETH, IB_BTH, IB_DETH, IB_GRH, IB_ImmDt, IB_LRH, IB_MAD, IB_RDETH, IB_RETH |
| PPP (8/8) | PPP_CCP, PPP_CHAP, PPP_IPCP, PPP_IPv6CP, PPP_LCP |

### Bucket 4: Proprietary/Obscure (80 protocols) -- VERY LOW PRIORITY

No public spec or very niche use.

AppleTalk, ASTERIX, Babel, Collectd, Cassandra, Elasticsearch,
MongoDB, MySQL, PostgreSQL, Thread, Zigbee variants, LoRaWAN,
Matter, Phonet, TIPC, XCP, 6LoWPAN, RPL, and others.

### Bucket 5: Already in Tshark (Mapping Issue) (40 protocols) -- MEDIUM PRIORITY

Tshark has dissectors but extraction returned 0 fields. Possible
dissector name mismatch or PCAP routing issue.

TACACS, SOCKS, SDP, IRC, NFS, NFSv4, SCSI, sFlow, GVRP, MMRP,
MSTP, PVST, RSTP, DNP3, IEC_104, ERSPAN, VXLAN_GBP, and others.

## Strategy: Hand-Write IR for 2 Extractor Types

The user's proposed approach: manually define IR for ~2 source types
(e.g., tshark field mappings + kernel-style C struct definitions),
then let the crossgen pipeline auto-generate the remaining 6 outputs.

### Recommended approach for Bucket 1 (52 protocols):

1. **Define tshark field mappings** — map canonical field names to
   tshark PDML field names (e.g., `src_port` -> `udp.srcport`).
   This enables tshark extraction from real PCAPs.

2. **Define kernel-style C struct** — write a packed C struct with
   field sizes/offsets matching the RFC. The kernel extractor already
   parses these to IR. Example:
   ```c
   struct dccp_hdr {
       uint16_t src_port;    /* Source port */
       uint16_t dst_port;    /* Destination port */
       uint8_t  data_offset; /* Data offset (4-bit) */
       uint8_t  ccval_cscov; /* CCVal(4) + CsCov(4) */
       uint16_t checksum;    /* Checksum */
       uint8_t  res_type;    /* Res(3) + Type(4) + X(1) */
       uint8_t  seq_high;    /* Sequence number (high 8) */
       uint16_t seq_low;     /* Sequence number (low 16) */
   };
   ```

3. **Generate PCAP template** from the IR using `generate-templates`.

4. **Run pipeline** — the 6 remaining generators (etherparse, scapy,
   kaitai, libpcap, omi, suricata) are auto-produced via crossgen.

### Priority order within Bucket 1:

1. **Encapsulation protocols** (GUE, NVGRE, STT, VXLAN_GPE, EtherIP,
   L2TPv3, SixInFour) — simple headers, high utility
2. **Routing protocols** (OSPFv3, RIPng, PIM, MSDP) — RFC-defined
3. **Redundancy** (CARP, HSRP) — small fixed headers
4. **Transport** (DCCP, UDPLite, IPComp) — well-standardized
5. **3GPP** (GTP variants) — important for telecom
6. **Measurement** (OWAMP, TWAMP, MPLS_Echo) — fixed formats
