# Validation Strategy

## Validation Approaches

Proto-audit has access to protocol definitions from 9 independent sources and
a PCAP corpus of 624 real-world packet captures. This creates a matrix of
validation approaches, from lightweight cross-source checks to full round-trip
wire-level verification. The table below enumerates all approaches, which are
implemented, and what each proves.

### Overview Matrix

| # | Approach | Direction | What it proves | Status |
|---|----------|-----------|---------------|--------|
| 1 | Cross-source field agreement | — | Multiple independent implementations agree on field layout | **Implemented** |
| 2 | Synthetic round-trip | IR → PCAP → tshark → IR | Generated wire bytes parse back to same IR (bit-level correctness) | **Implemented** |
| 3 | Corpus PDML extraction | corpus PCAP → tshark → IR | tshark's dissection of real traffic produces fields matching our IR | **Implemented** |
| 4 | Corpus cross-source parse | corpus PCAP → {tshark, scapy} → compare values | Multiple parsers agree on real traffic (strongest agreement signal) | **Implemented** |
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

**Coverage:** 205 of 206 curated protocols are routable (have PCAP generation
paths). 85 currently pass Gold validation. Split-aware comparison tolerates
tshark's byte-aligned PDML merging sub-byte fields. The remaining fail due to
tshark dissection issues (NO_DISSECT) or field comparison tolerance (FAIL).

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

#### 4. Corpus Cross-Source Parse (Implemented)

**Command:** `proto-audit corpus-parse --pcap <file.pcap>`

Parses the same PCAP through both tshark (PDML XML) and Scapy (`rdpcap()`),
then compares field values at the value level for each protocol layer.

```
corpus PCAP  ──→  tshark -T pdml  ──→  field values  ──┐
                                                        ├── compare_field_values()
corpus PCAP  ──→  scapy rdpcap   ──→  field values  ──┘
```

**What it proves:** Two independent dissectors agree on actual parsed values
from real traffic — the strongest cross-verification signal.

Value comparison uses normalization: hex values (0x prefix) are parsed to
integers, case is ignored, and integer representations are unified before
comparison. Reports per-layer agreement/disagreement.

**Validation tier:** Strengthens Silver confidence (2+ sources agree on values,
not just layout).

#### 5. Cross-Generator Round-Trip (Implemented)

**Command:** `proto-audit crossgen --proto TCP --target all`

Generates code from IR through each code generator, re-extracts from the
generated code through the corresponding extractor, and compares to the
original IR.

```
IR  ──→  generate_etherparse()  ──→  Rust struct  ──→  parse_etherparse_struct()  ──→  IR'
IR  ──→  generate_proto_def()   ──→  C header     ──→  parse_kernel_struct()      ──→  IR'
IR  ──→  generate_scapy()      ──→  Python class  ──→  scapy_dump.py --extra     ──→  IR'
                                                                                       │
                                         comparator  ←─────────────────────────────────┘
```

**What it proves:** Code generators produce output that parses back to the
same IR — verifying generator fidelity without external tools (for C and
etherparse targets).

Targets: `etherparse` (pure Rust, no runtime), `c` (pure text, no runtime),
`scapy` (requires Python), `pcap` (delegates to `validate`), `all`.

Batch mode: `crossgen --proto all` runs across all curated protocols.

#### 6–8. Not Yet Implemented

See sections below for implementation sketches.

---

## Implementation Status Summary

| Approach | Protocols | Tier | Quality |
|----------|-----------|------|---------|
| Cross-source agreement | 36 Silver-tier | Silver | High confidence on agreed fields |
| Synthetic round-trip | 112 Gold-validated (205 routable) | Gold | Bit-level correct |
| Corpus PDML (tshark) | 305 dissectors from 624 PCAPs | Silver | Real traffic, single parser |
| Corpus cross-source | tshark + Scapy value comparison | Silver+ | Real traffic, two parsers |
| Cross-generator round-trip | C, etherparse, Scapy, PCAP | Gold | Generator fidelity verified |
| Generated vs corpus | — | — | Not yet implemented |
| Corpus round-trip | — | — | Not yet implemented |

---

## Validation Tiers

The system assigns a quality tier to each protocol based on the strongest
validation it has passed:

| Tier | Criteria | Count | Meaning |
|------|----------|-------|---------|
| **Gold** | Synthetic round-trip passes (uncovered_mismatches == 0 && total_fields > 0) | 112 | Wire-level bit-correct |
| **Silver** | 2+ independent sources agree on field layout | 36 | Independent structural agreement |
| **Bronze** | Single source, self-consistent (offsets monotonic, no gaps) | 27 | Extractable but unverified |
| **Unvalidated** | No extractable fields yet | 13 + ~8,100 discovered | Discovered but not verified |

A protocol can hold multiple tiers simultaneously (e.g., Gold from round-trip
AND Silver from cross-source). The displayed tier is the highest achieved.

**Important distinction:** "Routable" (205 protocols have PCAP generation paths)
is not the same as "Gold-validated" (112 protocols pass round-trip comparison).
The gap is due to tshark dissection failures and field comparison tolerance
issues. Split-aware comparison allows Gold when tshark merges sub-byte fields
but the wire bytes round-trip correctly.

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

#### Gold-Validated Protocols (112)

These protocols have been round-trip validated (IR → PCAP → tshark → IR). Split-aware
comparison tolerates tshark merging sub-byte fields into byte-aligned PDML fields:

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

#### Why Some Routable Protocols Aren't Gold

- **NO_DISSECT**: tshark can't dissect the target protocol layer — needs prior negotiation, specific ports, TCP handshake, or context from earlier packets
- **FAIL**: tshark dissects the packet but field comparison finds uncovered structural differences

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

### Embedded Protocol Definitions

The PCAP generator uses embedded `ProtocolDef` structs for encapsulation
protocols (Ethernet, IPv4, IPv6, UDP, TCP, GRE, etc.). These have field names
matching `STACK_ROUTES` dispatch field names (e.g., `ether_type` not `h_proto`).
Embedded protos take priority over extracted IR to ensure stack construction works.

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

# Cross-generator round-trip verification
nix run .#proto-audit -- crossgen --proto IPv4 --target all
nix run .#proto-audit -- crossgen --proto all --target etherparse

# Corpus cross-source parsing (tshark vs Scapy)
nix run .#proto-audit -- corpus-parse --pcap templates/dns.pcap
```

## Further Reading

- [Code Generation](code-generation.md) — all four generator targets (C, Rust, Scapy, PCAP)
- [Architecture](architecture.md) — system overview and data flow
- [Extractors](extractors.md) — tshark extractor that powers the round-trip
- [Field Matching](field-matching.md) — comparison algorithm details
