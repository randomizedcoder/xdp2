# Proto-Audit Protocol Coverage Report

> Generated 2026-03-27 | 206 protocols | 6 sources
>
> Note: Parts of this document are generated from proto-audit report output.
> Reproduce with `nix run .#proto-audit -- matrix` and `nix run .#proto-audit -- findings`.

## Overview

The proto-audit tool cross-references protocol header definitions across six independent sources to find discrepancies in field layout, byte ordering, type classification, and header size. This document captures the current coverage state: which protocols are tracked, which sources know about each one, and where the sources disagree.

### Sources

| Source | What it provides | Coverage |
|--------|-----------------|----------|
| **XDP2** | In-tree parser struct definitions (`xdp2_parse_*`) | 69 protocols |
| **Linux kernel** | UAPI struct definitions (`iphdr`, `tcphdr`, ...) | 48 protocols |
| **Scapy** | Python packet class field descriptors | 109 protocols |
| **tshark** | Wireshark dissector PDML field output | 113 protocols |
| **etherparse** | Rust crate struct definitions | 8 protocols |
| **libpcap** | BPF gencode offsets + pcap/*.h structs | 11 protocols |

### Audit Summary

Of the 206 registered protocols, 127 had at least one source yield extractable field definitions:

| Metric | Count |
|--------|-------|
| Protocols with extractable fields | 127 |
| Protocols with 2+ external sources (cross-checkable) | 38 |
| Full agreement (all sources agree on all fields) | 75 |
| Field splits detected (sources disagree on sub-field granularity) | 22 |

## Source Coverage Matrix

Each cell shows the number of fields that source extracted for the protocol.
`0*` means the source has a definition but extracted zero usable fields (struct reference only).
`-` means the source has no definition for that protocol.

### Core Protocols (L2-L4)

These are the most-covered protocols, typically present in 4-6 sources.

| Protocol | kernel | scapy | tshark | xdp2 | etherparse | libpcap | Agree | Notes |
|----------|--------|-------|--------|------|------------|---------|-------|-------|
| Ethernet | 3 | 3 | 3 | 0* | Y | - | 3 | Perfect 3-way match |
| VLAN | - | 4 | 2 | 0* | Y | Y | 0 | SPLIT, TYPE_DIFF: scapy splits TCI |
| IPv4 | 11 | 13 | 11 | 0* | Y | Y | 3 | SPLIT: scapy splits flags/frag_off |
| IPv6 | 8 | 8 | 8 | 0* | Y | Y | 2 | SPLIT, TYPE_DIFF |
| ARP | 5 | 9 | 9 | 0* | Y | Y | 0 | SPLIT: scapy/tshark split hw/proto addrs |
| TCP | 17 | 11 | 9 | 0* | Y | Y | 2 | SPLIT: kernel has bitfield flags |
| UDP | 4 | 4 | 4 | 0* | Y | Y | 2 | Clean agreement on 4 fields |
| ICMPv4 | 4 | 17 | - | 0* | Y | - | 1 | SPLIT: scapy enumerates all subtypes |
| ICMPv6 | 6 | 4 | - | 0* | Y | - | 0 | SPLIT |
| IGMP | 4 | 4 | - | 0* | - | - | 3 | TYPE_DIFF on one field |
| SCTP | - | 4 | - | - | - | Y | 2 | New; kernel struct + libpcap gencode |
| DCCP | 11 | - | - | - | - | - | 11 | New; kernel-only extraction |

### Tunneling & Encapsulation

| Protocol | kernel | scapy | tshark | xdp2 | Agree | Notes |
|----------|--------|-------|--------|------|-------|-------|
| GRE | - | 13 | - | 0* | 13 | Scapy covers all optional fields |
| VXLAN | - | 8 | 4 | 0* | 0 | SPLIT: tshark merges flag+reserved |
| Geneve | - | 9 | - | 0* | 9 | |
| MPLS | 1 | 4 | - | 0* | 0 | SPLIT: scapy exposes label/tc/s/ttl |
| NSH | - | 12 | - | 0* | 12 | |
| ERSPAN | - | 8 | - | 0* | 8 | |
| L2TP | - | 8 | - | 0* | 8 | |
| PPPoE | - | 5 | - | 0* | 5 | |
| PPP | - | 1 | - | 0* | 1 | |
| WireGuard | - | Y | Y | - | - | New; scapy + tshark |
| NVGRE | - | Y | Y | - | - | New |
| LISP | - | Y | Y | - | - | New |
| VXLAN_GPE | - | - | 4 | - | 4 | New; tshark-only extraction |
| IP_in_IP | - | - | Y | - | - | New; tshark-only |
| STT | - | - | Y | - | - | New; tshark-only |
| Teredo | - | - | Y | - | - | New; tshark-only |
| GUE | - | - | Y | - | - | New; tshark-only |

### Security

| Protocol | kernel | scapy | tshark | xdp2 | Agree | Notes |
|----------|--------|-------|--------|------|-------|-------|
| ESP | 2 | 3 | - | 0* | 2 | |
| AH | 5 | 7 | 6 | 0* | 4 | SPLIT, TYPE_DIFF |
| MACsec | - | 2 | - | 0* | 2 | |
| TLS | - | Y | Y | - | - | New |
| DTLS | - | Y | Y | - | - | New |
| IKEv2 | - | Y | Y | - | - | New |
| EAP | - | 7 | 3 | 0* | 3 | New |
| EAPOL | - | 3 | 3 | 0* | 2 | TYPE_DIFF |

### IPv6 Extensions

| Protocol | kernel | scapy | xdp2 | Agree | Notes |
|----------|--------|-------|------|-------|-------|
| IPv6_EH (HopByHop) | 2 | 4 | 0* | 2 | |
| IPv6_Fragment | - | 6 | - | 6 | New |
| IPv6_DestOpts | 2 | 4 | - | 2 | New |
| IPv6_Routing | 4 | 6 | 0* | 3 | New; TYPE_DIFF |
| SRv6 | 7 | 14 | 0* | 5 | SPLIT, TYPE_DIFF |

### Wireless & IoT

| Protocol | kernel | scapy | tshark | xdp2 | Agree | Notes |
|----------|--------|-------|--------|------|-------|-------|
| IEEE802.11 | 7 | 13 | - | - | 0 | SPLIT: bitfield disagreement |
| IEEE802154 | - | 11 | - | 0* | 11 | |
| Zigbee_NWK | - | 13 | Y | - | 13 | New |
| Zigbee_APS | - | 12 | Y | - | 12 | New |
| MQTT | - | 5 | Y | - | 5 | New |
| CoAP | - | 8 | Y | - | 8 | New |

### Industrial / SCADA

| Protocol | scapy | tshark | Agree | Notes |
|----------|-------|--------|-------|-------|
| MODBUS_TCP | Y | Y | - | New |
| DNP3 | Y | Y | - | New |
| IEC_GOOSE | Y | Y | - | New |
| BACnet | - | Y | - | New; tshark-only |
| ENIP | - | Y | - | New; tshark-only |
| CIP | - | Y | - | New; tshark-only |
| OPC_UA | - | Y | - | New; tshark-only |
| IEC_SV | - | Y | - | New; tshark-only |
| IEC_MMS | - | Y | - | New; tshark-only |
| EtherCAT | - | 3 | 0* | 3 | |
| PROFINET | - | 1 | 0* | 1 | |

### Bluetooth

| Protocol | kernel | scapy | xdp2 | Agree | Notes |
|----------|--------|-------|------|-------|-------|
| HCI | 2 | 1 | 0* | 0 | SPLIT |
| HCI_CMD | 2 | 3 | 0* | 1 | SPLIT |
| HCI_ACL | 2 | 4 | 0* | 1 | SPLIT |
| HCI_Event | 2 | 2 | 0* | 2 | |
| HCI_SCO | 2 | - | 0* | 2 | |
| HCI_ISO | 2 | - | 0* | 2 | |
| L2CAP | 2 | 2 | 0* | 2 | |
| BT_ATT | - | 1 | - | 1 | |
| BT_SMP | - | 1 | - | 1 | |

### InfiniBand

| Protocol | scapy | tshark | xdp2 | Agree | Notes |
|----------|-------|--------|------|-------|-------|
| IB_LRH | - | Y | 0* | 0 | |
| IB_GRH | - | Y | 0* | 0 | |
| IB_BTH | - | Y | 0* | 0 | |
| IB_DETH | Y | Y | - | - | |
| IB_RETH | Y | Y | - | - | |
| IB_AETH | Y | Y | - | - | |
| IB_RDETH | Y | Y | - | - | |
| IB_AtomicETH | Y | Y | - | - | |
| IB_ImmDt | Y | Y | - | - | |
| IB_MAD | Y | Y | - | - | |

### Multicast

| Protocol | kernel | scapy | Agree | Notes |
|----------|--------|-------|-------|-------|
| IGMPv3_Query | 9 | 3 | 2 | TYPE_DIFF |
| IGMPv3_Report | 5 | 3 | 1 | SPLIT, TYPE_DIFF |
| MLD | 2 | 6 | 0 | SPLIT, TYPE_DIFF |
| MLDv2_Query | 7 | 12 | 5 | SPLIT, TYPE_DIFF |
| MLDv2_Report | 1 | 6 | 0 | SPLIT |

### Routing

| Protocol | scapy | tshark | Agree | Notes |
|----------|-------|--------|-------|-------|
| OSPF | 12 | Y | 12 | |
| BGP | 3 | Y | 3 | |
| EIGRP | 8 | Y | 8 | |
| ISIS | 8 | Y | 8 | |
| RIP | 3 | Y | 3 | |
| BFD | 12 | Y | 12 | New |
| LDP | - | Y | - | New; tshark-only |
| RSVP | - | Y | - | New; tshark-only |
| MPLS_OAM | - | Y | - | New; tshark-only |

### Network Management

| Protocol | scapy | tshark | Agree | Notes |
|----------|-------|--------|-------|-------|
| RADIUS | 5 | Y | 5 | New |
| TACACS | Y | Y | - | New |
| Syslog | Y | Y | - | New |
| TFTP | 1 | Y | 1 | New |
| NetFlow_v5 | 8 | Y | 8 | New |
| NetFlow_v9 | 5 | - | 5 | New; scapy-only |
| IPFIX | Y | - | - | New; scapy-only |
| Diameter | - | Y | - | New; tshark-only |

### Application Protocols

| Protocol | scapy | tshark | Agree | Notes |
|----------|-------|--------|-------|-------|
| DNS | 20 | Y | 20 | |
| NTP | 14 | Y | 14 | |
| SNMP | 3 | Y | 3 | |
| DHCP | 15 | Y | 15 | |
| DHCPv6 | 2 | Y | 2 | |
| QUIC | 14 | Y | 14 | |
| HTTP | 0* | Y | 0 | New; scapy yields no fixed fields |
| HTTP2 | Y | Y | - | New |
| SIP | Y | Y | - | New |
| MQTT | 5 | Y | 5 | New |
| CoAP | 8 | Y | 8 | New |
| Kerberos | 1 | Y | 1 | New |

### Storage & RPC

| Protocol | kernel | scapy | tshark | Agree | Notes |
|----------|--------|-------|--------|-------|-------|
| iSCSI | 7 | Y | Y | 7 | |
| NVMe | 11 | Y | Y | 11 | |
| FC | 12 | Y | Y | 12 | |
| SCSI | 1 | Y | Y | 1 | |
| iSER | 6 | Y | Y | 6 | |
| NFS | - | Y | Y | - | |
| SMB | - | 12 | Y | 12 | |
| SMB2 | - | 14 | Y | 14 | |
| ONC_RPC | - | 2 | Y | 2 | |

### Capture Layer

| Protocol | scapy | tshark | libpcap | Agree | Notes |
|----------|-------|--------|---------|-------|-------|
| SLL | 5 | Y | Y | 2 | New; TYPE_DIFF on 3 fields |
| SLL2 | 7 | Y | Y | 3 | New; TYPE_DIFF on 4 fields |
| ERF | Y | Y | - | - | New |

### Layer 2 Additions

| Protocol | kernel | scapy | tshark | Agree | Notes |
|----------|--------|-------|--------|-------|-------|
| LLC | Y | 3 | 5 | 3 | New |
| SNAP | - | 2 | 5 | 0 | New; SPLIT |
| STP | - | 14 | Y | 14 | New |
| LACP | - | 1 | Y | 1 | New |
| QinQ | - | 4 | 2 | 0 | New; SPLIT, TYPE_DIFF |
| WOL | - | - | Y | - | New; tshark-only |
| HomePlug_AV | - | Y | Y | - | New |

### Redundancy & Discovery

| Protocol | scapy | tshark | Agree | Notes |
|----------|-------|--------|-------|-------|
| VRRP | 9 | Y | 9 | |
| HSRP | 10 | Y | 10 | |
| CDP | 4 | Y | 4 | |
| CARP | - | Y | - | New; tshark-only |
| GLBP | - | Y | - | New; tshark-only |
| NBNS | 5 | Y | 5 | New |
| PPPoED | 5 | Y | 5 | New |
| mDNS | - | Y | - | New; tshark-only |
| LLMNR | - | Y | - | New; tshark-only |
| LLTD | - | Y | - | New; tshark-only |

### VoIP / Telephony

| Protocol | scapy | tshark | Agree | Notes |
|----------|-------|--------|-------|-------|
| RTP | 10 | Y | 10 | |
| RTCP | Y | Y | - | New |
| SIP | Y | Y | - | New |
| STUN | Y | Y | - | New |
| RTSP | - | Y | - | New; tshark-only |
| Skinny | - | Y | - | New; tshark-only |
| MGCP | - | Y | - | New; tshark-only |

### Protocols with tshark-only or no-source coverage

These protocols are registered for tracking purposes but currently have only a tshark dissector name or no extractable source at all. They serve as placeholders for future source expansion.

| Protocol | tshark | Notes |
|----------|--------|-------|
| UDPLite | udplite | No scapy/kernel definitions available |
| IP_in_IP | ipip | Inner header is standard IPv4 |
| STT | stt | Stateless Transport Tunneling |
| Teredo | teredo | IPv6 tunneling over UDP |
| GUE | gue | Generic UDP Encapsulation |
| mDNS | mdns | Uses DNS packet format |
| LLMNR | llmnr | Uses DNS packet format |
| LLTD | lltd | Link Layer Topology Discovery |
| RTSP | rtsp | Text-based, no fixed header |
| Skinny | skinny | Cisco proprietary |
| MGCP | mgcp | Text-based |
| BACnet | bacnet | Building automation |
| ENIP | enip | EtherNet/IP industrial |
| CIP | cip | Common Industrial Protocol |
| OPC_UA | opcua | OPC Unified Architecture |
| IEC_SV | sv | IEC 61850 Sampled Values |
| IEC_MMS | mms | Manufacturing Message Specification |
| Diameter | diameter | AAA protocol |
| LDAP | ldap | ASN.1/BER encoded |
| NTLMSSP | ntlmssp | NT LAN Manager |
| OCSP | ocsp | Certificate status |
| FTP | ftp | Text-based |
| SSH | ssh | Encrypted after handshake |
| Telnet | telnet | Text-based |
| SMTP | smtp | Text-based |
| IMAP | imap | Text-based |
| AMQP | amqp | Advanced Message Queuing |
| Kafka | kafka | Apache Kafka wire protocol |
| ZeroMQ | zmtp | ZeroMQ Transport Protocol |
| Memcache | memcache | Memcached binary protocol |
| Redis | resp | Redis Serialization Protocol |
| LDP | ldp | Label Distribution Protocol |
| RSVP | rsvp | Resource Reservation Protocol |
| MPLS_OAM | mpls-echo | MPLS LSP Ping/Traceroute |
| CARP | carp | Common Address Redundancy |
| GLBP | glbp | Gateway Load Balancing |
| OpenFlow | openflow_v4 | SDN control protocol |
| TZSP | tzsp | TaZmen Sniffer Protocol |
| GRE_PPTP | pptp | GRE-encapsulated PPTP |
| CAPWAP | capwap | Wireless AP control |
| LWAPP | lwapp | Lightweight AP Protocol |
| WOL | wol | Wake-on-LAN magic packet |
| TPLINK_SMARTHOME | - | TP-Link smart home (no public source) |

## Field Split Details

A "split" occurs when one source represents a header region as a single field while another source breaks it into sub-fields. These are the most common discrepancy type and are usually not bugs -- they reflect different levels of granularity.

### Most significant splits

| Protocol | Splits | Primary Root Cause | Description |
|----------|--------|--------------------|-------------|
| IPv4 | 12 | Granularity choice | Kernel `frag_off` (16b) vs scapy `flags` (3b) + `frag` (13b); version+IHL handling |
| TCP | 15 | Granularity choice | Kernel per-flag bitfields vs scapy packed `flags` (8b); tshark merges data_offset+reserved |
| ARP | 9 | Protocol design ambiguity | Kernel: 5 fixed fields (variable-length addrs excluded); scapy/tshark: 9 fields with hardcoded Ethernet/IPv4 sizes |
| IEEE802.11 | 20 | Granularity choice | Kernel: 7-field struct; scapy: 13 fields with FC bitfield breakdown |
| VLAN / QinQ | 4 each | Granularity choice | Scapy splits TCI into priority (3b) + DEI (1b) + VID (12b); tshark/kernel keep single field |

See [Inconsistency Analysis](inconsistency-analysis.md) for detailed
field-by-field walkthroughs and the full root-cause taxonomy.

## Type Difference Details

Type differences occur when sources agree on a field's bit position and size but classify it differently (e.g., `Uint` vs `Enum`, `Uint` vs `Flags`).

| Protocol | Field | Source A | Source B | Root Cause | Notes |
|----------|-------|---------|---------|------------|-------|
| VLAN | h_vlan_TCI | kernel: Flags | scapy: Uint | Semantic classification | PCP+DEI+VID packed |
| IPv6 | nexthdr | kernel: Enum | scapy: Uint | Semantic classification | Next header lookup |
| IGMP | type | kernel: Enum | scapy: Uint | Semantic classification | Message type |
| AH | nexthdr | kernel: Enum | scapy/tshark: Uint | Semantic classification | IP protocol number |
| SRv6 | nexthdr | kernel: Enum | scapy: Uint | Semantic classification | Next header |
| EAPOL | type | scapy: Uint | tshark: Enum | Semantic classification | EAPOL frame type |
| SLL | sll_protocol | libpcap: Enum | scapy: Uint | Semantic classification | EtherType |
| SLL2 | sll2_protocol | libpcap: Enum | scapy: Uint | Semantic classification | EtherType |
| QinQ | tci | kernel: Flags | scapy: Uint | Semantic classification | Same as VLAN |
| IGMPv3_Query | type | kernel: Enum | scapy: Uint | Semantic classification | Message type |
| MLDv2_Query | nexthdr | kernel: Enum | scapy: Uint | Semantic classification | Same pattern |

See [Inconsistency Analysis](inconsistency-analysis.md) for the full
root-cause taxonomy and worked protocol examples.

## Source Gap Analysis

### Expected gaps (by design)

| Source | Why it's missing protocols | Examples |
|--------|---------------------------|----------|
| **Kernel** | No structs for L7 application protocols | HTTP, TLS, DNS, SSH |
| **etherparse** | Focused Rust crate; only common L2-L4 | 8 protocols by design |
| **libpcap** | BPF compiler only needs ~8 core protocols | IPv4, IPv6, TCP, UDP, ARP, SCTP |
| **XDP2** | In-tree parsers; not all protocols have XDP2 parsers yet | Most new L7 protocols |

### Potential upstream enhancements

**Scapy contrib opportunities** (protocols with tshark but no scapy class):
- ICS/SCADA: BACnet, ENIP, CIP, OPC_UA, IEC_SV, IEC_MMS
- VoIP: Skinny, MGCP, RTSP
- Network: DCCP, UDPLite, Diameter, LDP, RSVP

**tshark gaps** (protocols with scapy but no tshark dissector name assigned):
- NetFlow_v9, IPFIX -- both use tshark's `cflow` dissector, not separately tracked

## Reproducing This Report

```bash
# List all 206 protocols with source mappings
nix run .#proto-audit -- list

# Full cross-source coverage matrix
nix run .#proto-audit -- matrix

# Extract a specific protocol from a specific source
nix run .#proto-audit -- extract --proto IPv4 --source scapy
nix run .#proto-audit -- extract --proto TCP --source kernel

# Full audit of a protocol across all sources
nix run .#proto-audit -- audit --proto IPv4
```

## Etherparse Protocol Coverage

| Protocol | Fields Extracted | Missing vs Wire |
|----------|-----------------|-----------------|
| Ethernet | 3 (source, destination, ether_type) | None |
| UDP | 4 (source_port, destination_port, length, checksum) | None |
| IPv4 | 12 (dscp through destination) | version, ihl (implicit) |
| TCP | 16 (ports, seq/ack, 9 flags, window, checksum, urgent_pointer) | data_offset, reserved (implicit) |
| IPv6 | 7 (traffic_class through destination) | version (implicit) |
| VLAN | 4 (pcp, drop_eligible_indicator, vlan_id, ether_type) | None |
| ARP | 3 (hw_addr_type, proto_addr_type, operation) | hw/proto addr sizes (private) |
| ICMPv4 | 2 (icmp_type, checksum) | code embedded in type enum |
| ICMPv6 | 2 (icmp_type, checksum) | code embedded in type enum |

## History

| Date | Protocols | Change |
|------|-----------|--------|
| 2026-03-27 | 206 | Added 92 protocols (phases 1-15: L1 capture through routing/misc) |
| 2026-03-27 | 114 | Added libpcap as 6th source |
| 2026-03-26 | 113 | Comprehensive Scapy coverage + code gen |
| 2026-03-25 | 105 | Added multicast & media/streaming protocols |
