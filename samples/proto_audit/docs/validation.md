# Validation Strategy

## Validation Approaches

Proto-audit has access to protocol definitions from 6 independent sources and
a PCAP corpus of 600+ real-world packet captures. This creates a matrix of
validation approaches, from lightweight cross-source checks to full round-trip
wire-level verification. The table below enumerates all approaches, which are
implemented, and what each proves.

### Overview Matrix

| # | Approach | Direction | What it proves | Status |
|---|----------|-----------|---------------|--------|
| 1 | Cross-source field agreement | — | Multiple independent implementations agree on field layout | **Implemented** |
| 2 | Synthetic round-trip | IR → PCAP → tshark → IR | Generated wire bytes parse back to same IR (bit-level correctness) | **Implemented** |
| 3 | Corpus PDML extraction | corpus PCAP → tshark → IR | tshark's dissection of real traffic produces fields matching our IR | **Implemented** |
| 4 | Corpus cross-source parse | corpus PCAP → {tshark, scapy, libpcap, ...} → IR | Multiple parsers agree on real traffic (strongest agreement signal) | **Partial** |
| 5 | Generated vs corpus PCAP | IR → PCAP vs corpus PCAP | Our generated packets are structurally valid (same framing as real traffic) | Not implemented |
| 6 | Corpus round-trip | corpus PCAP → IR → PCAP → compare | Real traffic survives IR round-trip (lossless representation) | Not implemented |
| 7 | Per-source PCAP parse | corpus PCAP → source parser → verify | Each extractor correctly parses real packets (extractor fidelity) | Not implemented |
| 8 | Generated PCAP multi-parse | IR → PCAP → {tshark, scapy, ...} → IR | Generated packets are valid across multiple dissectors | Not implemented |

### Approach Details

#### 1. Cross-Source Field Agreement (Implemented)

**Command:** `proto-audit audit --sources tshark,libpcap,kernel,scapy`

Extracts the same protocol from multiple independent sources and compares
field definitions by (offset, size). No PCAP needed — purely structural.

- **Structural match**: same bit offset + size (field position agreement)
- **Semantic match**: also same type and endianness
- **Split**: overlapping but different field boundaries
- **Missing**: field in one source but not another

See [Field Matching](field-matching.md) for details on the comparison algorithm.

**What it proves:** Independent implementations agree on where fields are.
When tshark, libpcap, and the kernel all place `src_port` at offset 0 with
16 bits, we have high confidence that's correct.

**Validation tier:** Silver (2+ sources agree on at least one field).

#### 2. Synthetic Round-Trip (Implemented)

**Command:** `proto-audit validate --proto TCP`

The strongest single-source validation. Generates a PCAP from the IR, feeds
it to tshark (an independent dissector), extracts the result back to IR,
and compares.

```
IR  ──→  serialize  ──→  PCAP file  ──→  tshark -T pdml  ──→  IR'
                                                                │
                          comparator  ←─────────────────────────┘
```

**What it proves:** Our IR field definitions are bit-level correct — the wire
encoding we produce is parsed identically by an independent implementation.

**Validation tier:** Gold (round-trip validated).

**Coverage:** 205 of 206 curated protocols across 18 link types (DLTs).

See sections below for protocol stack construction, field defaults, and
limitations.

#### 3. Corpus PDML Extraction (Implemented)

**Command:** `proto-audit audit --sources tshark --tier curated`
(with `PROTO_AUDIT_PCAP_CORPUS` set)

Extracts protocol fields from real-world PCAPs via tshark PDML, then
compares against our IR from other sources.

```
corpus PCAP  ──→  tshark -T pdml  ──→  IR  ──→  compare with libpcap/kernel/scapy IR
```

**What it proves:** tshark's dissection of real traffic matches our
structural understanding from other sources.

**Current corpus:** 624 PCAPs (166 PacketLife + 458 Wireshark samples),
covering 305 unique dissectors. Pre-extracted to PDML XML at Nix build time.

**Fallback chain for curated tshark audit:**
1. `combo.pcap` PDML (generated test traffic — highest fidelity, limited protocols)
2. Corpus PDML (real traffic — broad coverage)
3. tshark registry (field metadata from `tshark -G fields` — approximate offsets)

#### 4. Corpus Cross-Source Parse (Partial)

Parse the same corpus PCAP with multiple tools and compare their output.

```
                 ┌──→  tshark   ──→  IR_tshark   ──┐
corpus PCAP  ────┼──→  scapy    ──→  IR_scapy    ──┼──→  comparator
                 └──→  libpcap  ──→  IR_libpcap  ──┘
```

**What it proves:** Multiple independent parsers agree on the same real
traffic — the strongest possible cross-verification signal.

**Status:** Partially implemented. tshark corpus extraction works. Scapy
and libpcap corpus parsing not yet wired (they extract from source code,
not from PCAPs). Scapy could parse PCAPs via `rdpcap()`, libpcap could
parse via its BPF filter engine.

#### 5. Generated vs Corpus PCAP Comparison (Not Implemented)

Compare our IR-generated PCAPs against real-world corpus PCAPs at the
wire level.

```
IR  ──→  PCAP_generated
                          ──→  structural comparison (framing, encapsulation)
corpus  ──→  PCAP_real
```

**What it proves:** Our generated packets have valid framing — same
link-layer encapsulation, correct checksums, proper length fields.

**Implementation sketch:** For each protocol found in both generated and
corpus PCAPs, compare: link type, encapsulation stack, header byte offsets,
field value ranges. Not a byte-for-byte match (field values differ), but
a structural equivalence check.

#### 6. Corpus Round-Trip (Not Implemented)

Take a real-world PCAP, parse it to IR, re-generate a PCAP from that IR,
and compare the two PCAPs.

```
corpus PCAP  ──→  parse to IR  ──→  IR  ──→  serialize to PCAP  ──→  PCAP'
     │                                                                  │
     └──────────────────→  byte-level comparison  ←─────────────────────┘
```

**What it proves:** The IR is a lossless representation — real traffic
survives a full round-trip through our intermediate format. This is the
ultimate fidelity test.

**Implementation challenges:**
- Variable-length fields (TCP options, DHCP options) are not yet generated
- Checksums and lengths would need recomputation
- Only fixed-header bytes should be compared (payload may differ)
- Need to align on which header bytes to compare (ignore padding/options)

#### 7. Per-Source PCAP Parse (Not Implemented)

Feed corpus PCAPs to each source's parser and verify it produces the
expected IR fields.

```
corpus PCAP  ──→  source extractor  ──→  IR  ──→  validate against expected
```

**What it proves:** Each extractor correctly handles real traffic, not just
source code definitions. Catches bugs where source code defines a field but
the parser mishandles it in practice.

**Implementation sketch:** For each source that can parse PCAPs (tshark,
scapy), run extraction on corpus PCAPs and verify output matches the IR
derived from structural analysis.

#### 8. Generated PCAP Multi-Parse (Not Implemented)

Generate a PCAP from IR, then parse it with multiple tools (not just tshark).

```
IR  ──→  PCAP  ──→  tshark  ──→  IR_tshark
                ──→  scapy   ──→  IR_scapy     ──→  all must agree
                ──→  tcpdump ──→  IR_tcpdump
```

**What it proves:** Our generated packets are valid across multiple
independent dissectors — not just tshark-compatible but universally parseable.

**Implementation sketch:** Extend `validate` to optionally also run
`scapy.rdpcap()` on the generated PCAP and compare the resulting IR.

---

## Implementation Status Summary

| Approach | Protocols | Tier | Quality |
|----------|-----------|------|---------|
| Cross-source agreement | 24 Silver-tier (tshark+libpcap) | Silver | High confidence on agreed fields |
| Synthetic round-trip | 205 protocols | Gold | Bit-level correct |
| Corpus PDML (tshark) | 255 from corpus (305 dissectors) | Silver | Real traffic, single parser |
| Corpus cross-source | — | — | Not yet implemented |
| Generated vs corpus | — | — | Not yet implemented |
| Corpus round-trip | — | — | Not yet implemented |

---

## Validation Tiers

The system assigns a quality tier to each protocol based on the strongest
validation it has passed:

| Tier | Criteria | Count | Meaning |
|------|----------|-------|---------|
| **Gold** | Synthetic round-trip passes | 205 | Wire-level bit-correct |
| **Silver** | 2+ sources agree on fields | 24 | Independent structural agreement |
| **Bronze** | Single source, self-consistent | ~150 | Offsets monotonic, no gaps |
| **Unvalidated** | No extractable fields yet | ~8,000 | Discovered but not verified |

A protocol can hold multiple tiers simultaneously (e.g., Gold from round-trip
AND Silver from cross-source). The displayed tier is the highest achieved.

---

## Synthetic Round-Trip Details

### Protocol Stack Construction

The `STACK_ROUTES` table and `LINK_ROOTS` define encapsulation paths for **205
protocols** across multiple link types and dispatch layers.

#### Link-Layer Roots (18 DLTs)

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

#### Ethernet-Rooted Routes

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

**L4 — UDP port dispatch** (44 protocols):
DNS, mDNS, LLMNR, NBNS, DHCP, DHCPv6, NTP, SNMP, TFTP, SIP, RADIUS,
GTP_U, GTP_C, VXLAN, Geneve, WireGuard, BFD, RTP, RTCP, STUN, QUIC, RIP,
VXLAN_GPE, LISP, CAPWAP, LWAPP, Syslog, NetFlow_v5, IPFIX, MQTT, CoAP,
DTLS, IKEv2, TZSP, OpenFlow, SRT, BACnet, GLBP, GUE, HSRP, MGCP,
MPLS_OAM, Teredo, NetFlow_v9, ONC_RPC

**L4 — TCP port dispatch** (32 protocols):
HTTP, TLS, BGP, SSH, Telnet, FTP, SMTP, IMAP, SMB, LDAP, Diameter, AMQP,
Kafka, Redis, Memcache, Kerberos, MODBUS_TCP, DNP3, ENIP, OPC_UA, RTSP,
Skinny, TACACS, HTTP2, IEC_MMS, SMB2, STT, ZeroMQ, LDP, iSCSI, NFS, NVMe

**Tunnels over GRE** (3 protocols):
NVGRE, ERSPAN, GRE_PPTP

**Sub-protocol dispatch** (9 protocols):
IGMPv3_Query, IGMPv3_Report (via IGMP type); IPv6_ND, MLD, MLDv2_Query,
MLDv2_Report (via ICMPv6 type); SCTP_Chunk (via SCTP); EAP (via EAPOL);
CIP (via ENIP)

### Unsupported Protocols

Only **1 protocol** cannot be PCAP-generated:

- **TPLINK_SMARTHOME**: no tshark dissector

### Field Value Defaults

When serializing, fields are assigned values in priority order:

| Priority | Source | Example |
|----------|--------|---------|
| 1 | Stack route override | `ether_type=0x0800` for IPv4 child |
| 2 | `default_value` on FieldDef | `version=4` on IPv4 |
| 3 | Type-based default | `Ipv4Addr` src → `10.0.0.1`, dst → `10.0.0.2` |
| 4 | Type-based default | `MacAddr` src → `02:00:00:00:00:01`, dst → `02:00:00:00:00:02` |
| 5 | Type-based default | `Ipv6Addr` src → `fd00::1`, dst → `fd00::2` |
| 6 | Zero | All other fields |

### Limitations

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

---

## PCAP Corpus

The corpus is built at Nix evaluation time from hash-pinned sources:

| Source | Files | Protocols | Notes |
|--------|-------|-----------|-------|
| PacketLife.net | 166 | ~80 | Clean single-protocol captures |
| Wireshark SampleCaptures | 458 | ~250 | Community-curated from Wireshark wiki |
| **Total** | **624** | **305 unique** | Pre-extracted to PDML at build time |

Nix pinning ensures reproducibility: each source is fetched via
`fetchFromGitHub` with a commit hash and NAR hash. The corpus derivation
(`pcap-corpus`) runs `tshark -T pdml -c 5` on each file and stores the
XML output, plus a `corpus_summary.json` index.

### Adding More PCAP Sources

To add a new corpus source:

1. Add a `fetchFromGitHub` or `fetchurl` in `nix/proto-audit-sources.nix`
   with a pinned rev and hash
2. Add the source to the `pcapCorpus` derivation's `extract_pdml` calls
3. Rebuild: `nix build .#proto-audit`

Candidate sources for future expansion:
- Netresec public datasets (5-10 GB, industrial/ICS protocols)
- Wireshark test captures (from the official repo)
- Self-generated PCAPs from the `validate` command

---

## Usage

```bash
# Synthetic round-trip validate a single protocol
nix run .#proto-audit -- validate --proto TCP

# Round-trip validate all 205 routable protocols
nix run .#proto-audit -- validate --proto all

# Keep the generated PCAP for inspection
nix run .#proto-audit -- validate --proto IPv4 --keep-pcap /tmp/ipv4.pcap

# Cross-source audit (uses corpus PDML + registry fallback)
nix run .#proto-audit -- audit --sources tshark,libpcap --tier curated --compact

# Generate a PCAP file directly (without round-trip)
nix run .#proto-audit -- generate --proto TCP --target pcap -o tcp.pcap

# Preview packet hex dump
nix run .#proto-audit -- generate --proto TCP --target pcap --dry-run

# Machine-readable JSON output
nix run .#proto-audit -- validate --proto UDP --json
```

## Further Reading

- [Code Generation](code-generation.md) — all four generator targets (C, Rust, Scapy, PCAP)
- [Architecture](architecture.md) — system overview and data flow
- [Extractors](extractors.md) — tshark extractor that powers the round-trip
- [Field Matching](field-matching.md) — comparison algorithm details
