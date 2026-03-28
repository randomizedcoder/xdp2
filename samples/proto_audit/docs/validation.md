# Round-Trip Validation

## Overview

The `validate` command performs the strongest possible IR validation: it
generates wire bytes from the IR, feeds the PCAP to tshark, extracts the
dissection back to IR, and compares the two. Any field that survives the
round-trip through actual wire encoding and an independent dissector is
confirmed correct at the bit level.

## Usage

```bash
# Round-trip validate a protocol (IR → PCAP → tshark → IR → compare)
nix run .#proto-audit -- validate --proto TCP

# Keep the generated PCAP for inspection
nix run .#proto-audit -- validate --proto IPv4 --keep-pcap /tmp/ipv4.pcap

# Machine-readable JSON output
nix run .#proto-audit -- validate --proto UDP --json

# Generate a PCAP file directly (without tshark round-trip)
nix run .#proto-audit -- generate --proto TCP --target pcap -o tcp.pcap

# Preview packet hex dump without writing a file
nix run .#proto-audit -- generate --proto TCP --target pcap --dry-run
```

## How It Works

1. **Build rich IR** — reuses `build_rich_ir` to extract the best available
   `ProtocolDef` from kernel, scapy, tshark, or etherparse sources.

2. **Build protocol stack** — the `STACK_ROUTES` dispatch table maps each
   protocol to its parent and the dispatch field value that selects it
   (e.g., TCP → IPv4 via `protocol=6`). The generator walks from the target
   back to Ethernet, building the full encapsulation chain.

3. **Serialize headers** — each layer is serialized with field-level
   bitpacking. Override values (dispatch fields) are set from the stack
   route; remaining fields use `default_value`, type-based defaults, or zero.

4. **Write PCAP** — a PCAP file is assembled: global header (magic, v2.4,
   linktype from root DLT) + record header (timestamp=0, length) + packet bytes.
   Post-serialization fixups: IPv4 `total_length` + header checksum, IPv6
   `payload_length`, UDP `length`, and 802.3 `length`. For UpperPDU roots
   (DLT=252), a TLV dissector-name preamble replaces the root header.

5. **Feed to tshark** — the generated PCAP is passed to `tshark -T pdml`.
   The PDML XML output is parsed and the target protocol layer is extracted
   back to a `ProtocolDef`.

6. **Compare** — the original IR and the tshark round-trip IR are compared
   using the standard comparator (field matching by offset+size), producing
   an `AuditResult` with agreement/mismatch counts.

## Protocol Stack Construction

The `STACK_ROUTES` table and `LINK_ROOTS` define encapsulation paths for **205
protocols** across multiple link types and dispatch layers.

### Link-Layer Roots (18 DLTs)

| Root | DLT | Protocols Rooted Here |
|------|-----|-----------------------|
| Ethernet | 1 | ~120 (L2/L3/L4/tunnel) |
| Ethernet_802_3 | 1 | LLC → STP, ISIS; SNAP → CDP |
| HCI | 187 | HCI_CMD, HCI_ACL → L2CAP → BT_ATT, BT_SMP |
| IB_LRH | 247 | IB_GRH, IB_BTH → DETH, RETH, AETH, RDETH, AtomicETH, ImmDt, MAD |
| CAN / CAN_FD / CAN_XL | 227 | Standalone leaf roots |
| IEEE802.11 | 105 | Standalone leaf root |
| IEEE802154 | 195 | Zigbee_NWK → Zigbee_APS |
| Netlink | 253 | GenNetlink → NLAttr |
| SLL / SLL2 | 113 / 276 | Standalone leaf roots |
| PPP / ATM / FC / ERF / MPEG_TS | 9/11/224/197/243 | Standalone leaf roots |
| UpperPDU | 252 | BT_RFCOMM, BT_BNEP, BT_SDP, BT_AVDTP, SCSI, iSER, NTLMSSP, OCSP, Phonet, MCTP, X25, DSA |

### Ethernet-Rooted Routes

**L2 — Ethernet-direct** (38 protocols via `ether_type`):
IPv4, IPv6, ARP, VLAN, RARP, MPLS, PPPoE, PPPoED, LLDP, PTP, EAPOL, MACsec,
QinQ, PBB, TRILL, EtherCAT, PROFINET, FCoE, FIP, Slow_Protocols, LACP,
MAC_Control, CFM, HSR, BATMAN, NSH, HomePlug_AV, AoE, MVRP, NC_SI,
IEC_GOOSE, IEC_SV, IPX, AppleTalk, TIPC, WOL, LLTD, EDSA

**L3 — IPv4** (19 protocols via `protocol`):
TCP, UDP, ICMPv4, ICMP, GRE, SCTP, IGMP, OSPF, VRRP, PIM, L2TP, ESP, AH,
IP_in_IP, DCCP, UDPLite, EIGRP, CARP, RSVP

**L3 — IPv6** (6 protocols via `next_header`):
ICMPv6, IPv6_EH, IPv6_DestOpts, IPv6_Routing, IPv6_Fragment, SRv6

**L4 — UDP port dispatch** (44 protocols via `dst_port`, stack: Eth → IPv4 → UDP → target):
DNS, mDNS, LLMNR, NBNS, DHCP, DHCPv6, NTP, SNMP, TFTP, SIP, RADIUS,
GTP_U, GTP_C, VXLAN, Geneve, WireGuard, BFD, RTP, RTCP, STUN, QUIC, RIP,
VXLAN_GPE, LISP, CAPWAP, LWAPP, Syslog, NetFlow_v5, IPFIX, MQTT, CoAP,
DTLS, IKEv2, TZSP, OpenFlow, SRT, BACnet, GLBP, GUE, HSRP, MGCP,
MPLS_OAM, Teredo, NetFlow_v9, ONC_RPC

**L4 — TCP port dispatch** (32 protocols via `dst_port`, stack: Eth → IPv4 → TCP → target):
HTTP, TLS, BGP, SSH, Telnet, FTP, SMTP, IMAP, SMB, LDAP, Diameter, AMQP,
Kafka, Redis, Memcache, Kerberos, MODBUS_TCP, DNP3, ENIP, OPC_UA, RTSP,
Skinny, TACACS, HTTP2, IEC_MMS, SMB2, STT, ZeroMQ, LDP, iSCSI, NFS, NVMe

**Tunnels over GRE** (3 protocols via `protocol_type`, stack: Eth → IPv4 → GRE → target):
NVGRE, ERSPAN, GRE_PPTP

**Sub-protocol dispatch** (9 protocols):
IGMPv3_Query, IGMPv3_Report (via IGMP type); IPv6_ND, MLD, MLDv2_Query,
MLDv2_Report (via ICMPv6 type); SCTP_Chunk (via SCTP); EAP (via EAPOL);
CIP (via ENIP)

The generator resolves protocol definitions from extracted IR when available,
falling back to ~30 embedded minimal definitions for stack construction.

## Unsupported Protocols

Only **1 protocol** cannot be PCAP-generated:

- **TPLINK_SMARTHOME**: no tshark dissector

## Field Value Defaults

When serializing, fields are assigned values in priority order:

| Priority | Source | Example |
|----------|--------|---------|
| 1 | Stack route override | `ether_type=0x0800` for IPv4 child |
| 2 | `default_value` on FieldDef | `version=4` on IPv4 |
| 3 | Type-based default | `Ipv4Addr` src → `10.0.0.1`, dst → `10.0.0.2` |
| 4 | Type-based default | `MacAddr` src → `02:00:00:00:00:01`, dst → `02:00:00:00:00:02` |
| 5 | Type-based default | `Ipv6Addr` src → `fd00::1`, dst → `fd00::2` |
| 6 | Zero | All other fields |

## Limitations

- **Minimum fixed headers only** — variable-length options (TCP options,
  IPv4 options) are not generated; only the minimum header is serialized.
- **TCP/UDP checksums left at zero** — tshark still dissects the packet
  correctly; it flags the checksum as invalid but parses all fields.
- **Not all protocols have tshark dissectors** — if tshark cannot dissect
  the target layer, `validate` reports an error rather than a false pass.
  Only TPLINK_SMARTHOME has no known tshark dissector.
- **UpperPDU dissection quality varies** — protocols routed via DLT=252
  rely on Wireshark's Upper PDU TLV preamble; tshark may not dissect all
  fields as richly as it would from a native encapsulation.

## Output Formats

**Text (default):**
```
Round-trip validation: TCP
  Stack: Ethernet → IPv4 → TCP
  PCAP:  94 bytes
  IR fields:     10
  tshark fields: 10
  Agreement:     8/10 fields
  Status:        PASS
```

**JSON (`--json`):**
```json
{
  "protocol": "TCP",
  "status": "pass",
  "stack": ["Ethernet", "IPv4", "TCP"],
  "pcap_bytes": 94,
  "ir_fields": 10,
  "tshark_fields": 10,
  "audit": { ... }
}
```

## Further Reading

- [Code Generation](code-generation.md) — all four generator targets (C, Rust, Scapy, PCAP)
- [Architecture](architecture.md) — system overview and data flow
- [Extractors](extractors.md) — tshark extractor that powers the round-trip
