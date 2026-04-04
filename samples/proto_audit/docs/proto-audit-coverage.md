# Proto-Audit Protocol Coverage Report

> Updated 2026-04-03 | 206 curated protocols | 7 sources | 8,358 total tracked
>
> Note: Parts of this document are generated from proto-audit report output.
> Reproduce with `nix run .#proto-audit -- matrix` and `nix run .#proto-audit -- stats`.

## Overview

The proto-audit tool cross-references protocol header definitions across seven independent sources to find discrepancies in field layout, byte ordering, type classification, and header size. This document captures the current coverage state: which protocols are tracked, which sources know about each one, and where the sources disagree.

### Sources

| Source | What it provides | Coverage |
|--------|-----------------|----------|
| **XDP2** | In-tree parser struct definitions (`xdp2_parse_*`) | 222 proto_defs (206 curated) |
| **Linux kernel** | UAPI struct definitions (`iphdr`, `tcphdr`, ...) | 74 protocols (173 in registry) |
| **Scapy** | Python packet class field descriptors | 5,798 classes (109 curated) |
| **tshark** | Wireshark dissector PDML field output | 3,155 protocols (305 from corpus) |
| **etherparse** | Rust crate structs + overlay patches | 206/206 curated |
| **libpcap** | BPF gencode + C struct overlay patches | 206/206 curated |
| **Kaitai Struct** | Format specification files (.ksy) | ~20 protocols |

### Audit Summary

| Metric | Count |
|--------|-------|
| Total protocols tracked | 8,358 |
| Curated (Tier 1) | 206 |
| Discovered (Tier 2) | 8,152 |
| Gold (round-trip validated) | 36 |
| Silver (2+ sources agree) | 132 |
| Bronze (single source) | 48 |
| PCAP-routable | 205/206 |
| Multi-source (2+) | 1,198 |

## Source Coverage Matrix

Each cell shows the number of fields that source extracted for the protocol.
`0*` means the source has a definition but extracted zero usable fields (struct reference only).
`-` means the source has no definition for that protocol.

### Core Protocols (L2-L4)

These are the most-covered protocols, typically present in 4-7 sources.

| Protocol | kernel | scapy | tshark | xdp2 | etherparse | libpcap | Agree | Validation | Notes |
|----------|--------|-------|--------|------|------------|---------|-------|------------|-------|
| Ethernet | 3 | 3 | 3 | 0* | Y | Y | 3 | Gold | Perfect 3-way match |
| VLAN | - | 4 | 2 | 0* | Y | Y | 0 | Silver | SPLIT: scapy splits TCI |
| IPv4 | 11 | 13 | 11 | 0* | Y | Y | 3 | Silver | SPLIT: scapy splits flags/frag_off |
| IPv6 | 8 | 8 | 8 | 0* | Y | Y | 2 | Silver | SPLIT, TYPE_DIFF |
| ARP | 5 | 9 | 9 | 0* | Y | Y | 0 | Gold | SPLIT: scapy/tshark split hw/proto addrs |
| TCP | 17 | 11 | 9 | 0* | Y | Y | 2 | Silver | SPLIT: kernel has bitfield flags |
| UDP | 4 | 4 | 4 | 0* | Y | Y | 2 | Gold | Clean agreement on 4 fields |
| ICMPv4 | 4 | 17 | - | 0* | Y | Y | 1 | Gold | SPLIT: scapy enumerates all subtypes |
| ICMPv6 | 6 | 4 | - | 0* | Y | Y | 0 | Gold | SPLIT |
| IGMP | 4 | 4 | - | 0* | Y | Y | 3 | Gold | TYPE_DIFF on one field |
| SCTP | - | 4 | - | 0* | Y | Y | 2 | Gold | |
| DCCP | 11 | - | - | - | Y | Y | 11 | Silver | kernel-only extraction + patches |

### Tunneling & Encapsulation

| Protocol | kernel | scapy | tshark | xdp2 | Agree | Validation | Notes |
|----------|--------|-------|--------|------|-------|------------|-------|
| GRE | - | 13 | - | 0* | 13 | Silver | Scapy covers all optional fields |
| VXLAN | - | 8 | 4 | 0* | 0 | Silver | SPLIT: tshark merges flag+reserved |
| Geneve | - | 9 | - | 0* | 9 | Silver | |
| MPLS | 1 | 4 | - | 0* | 0 | Silver | SPLIT: scapy exposes label/tc/s/ttl |
| NSH | - | 12 | - | 0* | 12 | Silver | |
| ERSPAN | - | 8 | - | 0* | 8 | Gold | |
| L2TP | - | 8 | - | 0* | 8 | Silver | |
| PPPoE | - | 5 | - | 0* | 5 | Silver | |

### Security

| Protocol | kernel | scapy | tshark | xdp2 | Agree | Validation | Notes |
|----------|--------|-------|--------|------|-------|------------|-------|
| ESP | 2 | 3 | - | 0* | 2 | Gold | |
| AH | 5 | 7 | 6 | 0* | 4 | Gold | SPLIT, TYPE_DIFF |
| MACsec | - | 2 | - | 0* | 2 | Silver | |
| EAPOL | - | 3 | 3 | 0* | 2 | Gold | TYPE_DIFF |
| EAP | - | 7 | 3 | 0* | 3 | Silver | |

### Bluetooth

| Protocol | kernel | scapy | xdp2 | Agree | Validation | Notes |
|----------|--------|-------|------|-------|------------|-------|
| HCI | 2 | 1 | 0* | 0 | Silver | SPLIT |
| HCI_CMD | 2 | 3 | 0* | 1 | Gold | SPLIT |
| HCI_Event | 2 | 2 | 0* | 2 | Gold | |
| HCI_SCO | 2 | - | 0* | 2 | Gold | |
| HCI_ISO | 2 | - | 0* | 2 | Gold | |
| L2CAP | 2 | 2 | 0* | 2 | Silver | |

### Layer 2

| Protocol | kernel | scapy | tshark | Agree | Validation | Notes |
|----------|--------|-------|--------|-------|------------|-------|
| LLC | Y | 3 | 5 | 3 | Gold | |
| SNAP | - | 2 | 5 | 0 | Gold | SPLIT |
| STP | - | 14 | Y | 14 | Gold | |
| Slow_Protocols | - | 1 | Y | 1 | Gold | |
| MAC_Control | - | Y | Y | - | Gold | |
| IEC_GOOSE | - | Y | Y | - | Gold | |
| IEC_SV | - | Y | Y | - | Gold | |

### Capture Layer

| Protocol | scapy | tshark | libpcap | Agree | Validation | Notes |
|----------|-------|--------|---------|-------|------------|-------|
| SLL | 5 | Y | Y | 2 | Gold | TYPE_DIFF on 3 fields |
| SLL2 | 7 | Y | Y | 3 | Gold | TYPE_DIFF on 4 fields |
| ERF | Y | Y | - | - | Gold | |
| CAN_FD | Y | - | - | - | Gold | |
| IEEE802154 | 11 | - | 0* | 11 | Gold | |

### Application Protocols

| Protocol | scapy | tshark | Agree | Validation | Notes |
|----------|-------|--------|-------|------------|-------|
| DNS | 20 | Y | 20 | Silver | |
| NTP | 14 | Y | 14 | Silver | |
| SNMP | 3 | Y | 3 | Silver | |
| DHCP | 15 | Y | 15 | Silver | |
| QUIC | 14 | Y | 14 | Silver | |
| NBNS | 5 | Y | 5 | Gold | |
| TFTP | 1 | Y | 1 | Gold | |

### Protocols by Validation Tier

**Gold (36):** Ethernet, STP, ARP, UDP, SCTP, ICMPv4, IGMP, ESP, AH, EAPOL, LLC, SNAP, Slow_Protocols, MAC_Control, IEC_GOOSE, IEC_SV, NBNS, TFTP, ICMPv6, UDPLite, MLD, IPv6_ND, HCI_CMD, HCI_Event, HCI_SCO, HCI_ISO, CAN_FD, IEEE802154, SLL, SLL2, ERSPAN, ERF

**Silver (132):** IPv4, IPv6, TCP, VLAN, GRE, VXLAN, Geneve, MPLS, DNS, NTP, DHCP, SNMP, QUIC, BGP, OSPF, and 117 more with 2+ independent sources agreeing on field layout.

**Bronze (48):** Protocols with single-source extraction only. Many are tshark-only or Scapy-only without cross-source verification.

## Source Gap Analysis

### Expected gaps (by design)

| Source | Why it's missing protocols | Examples |
|--------|---------------------------|----------|
| **Kernel** | No structs for L7 application protocols | HTTP, TLS, DNS, SSH |
| **etherparse** | Native crate covers ~9 core protocols; rest via overlay patches | All 206 via patches |
| **libpcap** | BPF compiler needs ~8 core protocols; rest via overlay patches | All 206 via patches |
| **XDP2** | In-tree parsers; not all protocols have XDP2 parsers yet | Some L7 protocols |

### Next coverage targets

1. **Kaitai field extraction**: Wire up Kaitai Struct field definitions as a 7th field-level source for ~20 protocols
2. **Scapy version updates**: ~22 curated protocols have Scapy class names that don't exist in the current version
3. **Corpus expansion**: Add more PCAP sources to increase tshark extraction coverage beyond 305 dissectors

## Field Split Details

A "split" occurs when one source represents a header region as a single field while another source breaks it into sub-fields. These are the most common discrepancy type and are usually not bugs — they reflect different levels of granularity.

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

## Reproducing This Report

```bash
# System-wide statistics
nix run .#proto-audit -- stats

# List all 206 curated protocols with source mappings
nix run .#proto-audit -- list

# Full cross-source coverage matrix
nix run .#proto-audit -- matrix

# Extract a specific protocol from a specific source
nix run .#proto-audit -- extract --proto IPv4 --source scapy
nix run .#proto-audit -- extract --proto TCP --source kernel

# Full audit of a protocol across all sources
nix run .#proto-audit -- audit --proto IPv4

# Per-source coverage with gap analysis
nix run .#proto-audit -- coverage --tier curated
```

## History

| Date | Protocols | Change |
|------|-----------|--------|
| 2026-04-03 | 206 | Gold 2→36 (round-trip validation fixes), 7 sources, 8,358 total tracked |
| 2026-03-29 | 206 | Kaitai Struct as 7th source, batch-generated libpcap patches (206) |
| 2026-03-28 | 206 | PCAP corpus (624 files, 305 dissectors), auto-match, tshark registry |
| 2026-03-27 | 206 | Added 92 protocols (phases 1-15: L1 capture through routing/misc) |
| 2026-03-27 | 114 | libpcap as 6th source |
| 2026-03-26 | 113 | Comprehensive Scapy coverage + code gen |
| 2026-03-25 | 105 | Added multicast & media/streaming protocols |
