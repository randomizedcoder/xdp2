# Pipeline Coverage Tracker

**Last updated:** 2026-04-16  
**Baseline commit:** `85d57a5` (fix comparator + IPv4/IPv6 fixups)

## Summary

| Metric | Value |
|--------|-------|
| Total cells (protocol x target) | 3424 |
| PASS | 1105 (32.3%) |
| FAIL | 72 (2.1%) |
| ERR (no PCAP template / extractor gap) | 2247 (65.6%) |
| Protocols at 8/8 | 105 |
| Protocols at 7/8 | 37 |
| Protocols at 6/8 | 1 |
| Protocols at 0/8 | 285 |

## Per-Target Totals

| Target | PASS | Notes |
|--------|------|-------|
| etherparse | 143 | |
| c | 143 | |
| scapy | 142 | IEEE802.11 ERR |
| kaitai | 143 | |
| pcap | 143 | |
| libpcap | 143 | |
| omi | 143 | |
| suricata | 105 | 38 ERR (narrower extractor coverage) |

## Score Distribution

```
8/8:  105 protocols  (perfect round-trip across all 8 generators)
7/8:   37 protocols  (all but suricata in most cases)
6/8:    1 protocol   (IEEE802.11 — scapy + suricata ERR)
0/8:  285 protocols  (no PCAP template or all-ERR)
```

## Protocols at 8/8 (105)

Ethernet, VLAN, PBB, IPv4, IPv6, ARP, RARP, ICMPv4, ICMPv6, IGMP, TCP,
UDP, GRE, VXLAN, Geneve, MPLS, PPP, PPPoE, L2TP, NSH, ESP, AH, LLDP,
PTP, AoE, CAN, HCI, EAPOL, TRILL, BATMAN, CFM, MVRP, VRRP, CDP, RIP,
ISIS, BGP, EIGRP, MLD, RTP, SRT, DNS, NTP, SNMP, DHCP, DHCPv6, QUIC,
iSCSI, FC, SMB, SMB2, SLL, SLL2, LLC, SNAP, STP, LACP, QinQ, SCTP,
WireGuard, IKEv2, EAP, mDNS, LLMNR, NBNS, PPPoED, LLTD, SIP, RTCP,
RTSP, STUN, Skinny, MGCP, MQTT, CoAP, BACnet, ENIP, CIP, RADIUS,
Diameter, Syslog, TFTP, IPFIX, Kerberos, NTLMSSP, HTTP, FTP, SSH,
Telnet, IMAP, Kafka, ZeroMQ, Memcache, BFD, LDP, RSVP, OpenFlow, TZSP,
LWAPP, PPTP, VRRP3, BSSGP, RANAP, WebSocket, Radiotap

## Protocols at 7/8 (37 — typically suricata ERR)

IPv6_EH, IPv6_ND, HCI_CMD, HCI_ACL, HCI_Event, CAN_XL, MAC_Control,
NC_SI, Slow_Protocols, BT_BNEP, IGMPv3_Query, IGMPv3_Report,
MLDv2_Query, MLDv2_Report, MPEG_TS, ONC_RPC, GTP_U, GTP_C,
IPv6_Fragment, IPv6_DestOpts, IPv6_Routing, IP_in_IP, MODBUS_TCP,
OPC_UA, IEC_GOOSE, IEC_SV, NetFlow_v5, NetFlow_v9, MPLS_OAM,
GRE_PPTP, SCTP_Init, WPA_EAPOL_Key, MLD_Report_v1, SCTP_Data,
SCTP_Sack, L2TP_AVP, GENEVE_OPT

## Protocols with FAIL (9 — have PCAP template but comparison fails)

| Protocol | Score | Root Cause |
|----------|-------|------------|
| OSPF | 0/8 | Variable-length TLVs, no fixup |
| HomePlug_AV | 0/8 | Missing embedded definition (suricata ERR) |
| TLS | 0/8 | Crypto handshake structure lost in round-trip |
| DTLS | 0/8 | Same as TLS |
| IEC_MMS | 0/8 | ASN.1 BER encoding not preserved (suricata ERR) |
| LDAP | 0/8 | ASN.1 BER encoding not preserved |
| OCSP | 0/8 | Minimal DER skeleton too small |
| Redis | 0/8 | RESP text protocol, binary serialization fails |
| CAPWAP | 0/8 | Minimal 4-byte stub insufficient |

## Protocols at 0/8 ERR (285 — no usable PCAP template)

These protocols either lack PCAP templates, have no IR fields, or the
generated template doesn't produce a valid PCAP that tshark can dissect.
127 PCAP templates now exist in `pcap_templates/`, but ~285 protocols
still produce no IR fields or have no tshark dissector path.

**Breakdown of 0/8 ERR root causes:**
- 289 protocols: no fields in IR (extractors return empty field sets)
- 12 protocols: tshark doesn't dissect the generated PCAP
- 1 protocol: tshark parses 0 fields (ERSPAN)

## Progress History

| Date | PASS | Total | % | Key Changes |
|------|------|-------|---|-------------|
| 2026-04-15 (baseline) | 711 | 3424 | 20.8% | Initial pipeline-matrix |
| 2026-04-16 | 1097 | 3424 | 32.0% | Comparator key fix (name,pos,size), IPv4/IPv6 fixups, scapy keyword escaping |
| 2026-04-16 | 1105 | 3424 | 32.3% | Parallel matrix (rayon), auto-generate 65 templates, ICMPv4 fixed |

## Next Steps (priority order)

1. **Fix 9 FAIL protocols** — targeted fixes for OSPF, TLS, DTLS,
   LDAP, IEC_MMS, OCSP, Redis, HomePlug_AV, CAPWAP.

2. **Promote 37 protocols from 7/8 to 8/8** — expand suricata extractor
   coverage for these protocols.

3. **Expand IR coverage for 289 no-field protocols** — most 0/8 ERR
   protocols have zero IR fields. Need to improve extractors or add
   source coverage.

4. **IEEE802.11 scapy ERR** — fix scapy generation for 802.11.

## How to Run

```bash
# Full matrix (~30 min with 10 workers)
PROTO_AUDIT_PCAP_TEMPLATES=$(pwd)/pcap_templates \
  nix develop ../..#default --command \
  ./target/release/proto-audit pipeline-matrix --workers 10

# Subset (faster)
PROTO_AUDIT_PCAP_TEMPLATES=$(pwd)/pcap_templates \
  nix develop ../..#default --command \
  ./target/release/proto-audit pipeline-matrix \
  --protos IPv4,TCP,UDP,ICMPv4 --workers 4

# Auto-generate templates for missing protocols
PROTO_AUDIT_PCAP_TEMPLATES=$(pwd)/pcap_templates \
  nix develop ../..#default --command \
  ./target/release/proto-audit generate-templates --workers 10

# Dry-run to see what would be generated
PROTO_AUDIT_PCAP_TEMPLATES=$(pwd)/pcap_templates \
  nix develop ../..#default --command \
  ./target/release/proto-audit generate-templates --dry-run --workers 10

# Single protocol pipeline
PROTO_AUDIT_PCAP_TEMPLATES=$(pwd)/pcap_templates \
  nix develop ../..#default --command \
  ./target/release/proto-audit pipeline --proto ICMPv4 --target pcap
```

## Pipeline Architecture

```
PCAP_in → tshark → IR_baseline → generator(X) → code(X)
                                                    ↓
                                             re-extractor(X)
                                                    ↓
                                              IR_roundtrip
                                                    ↓
                                            pcap generator
                                                    ↓
                                               PCAP_out
                                                    ↓
                              compare_pdml(PCAP_in, PCAP_out) → PASS/FAIL
```
