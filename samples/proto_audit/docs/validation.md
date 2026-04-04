# Validation Strategy

## Validation Approaches

Proto-audit has access to protocol definitions from 7 independent sources and
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

**Coverage:** 205 of 206 curated protocols are routable (have PCAP generation
paths). 36 currently pass Gold validation. The remaining fail due to tshark
dissection issues (NO_DISSECT) or field comparison tolerance (FAIL).

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

#### 4–8. Not Yet Implemented

See sections below for implementation sketches.

---

## Implementation Status Summary

| Approach | Protocols | Tier | Quality |
|----------|-----------|------|---------|
| Cross-source agreement | 132 Silver-tier | Silver | High confidence on agreed fields |
| Synthetic round-trip | 36 Gold-validated (205 routable) | Gold | Bit-level correct |
| Corpus PDML (tshark) | 305 dissectors from 624 PCAPs | Silver | Real traffic, single parser |
| Corpus cross-source | — | — | Not yet implemented |
| Generated vs corpus | — | — | Not yet implemented |
| Corpus round-trip | — | — | Not yet implemented |

---

## Validation Tiers

The system assigns a quality tier to each protocol based on the strongest
validation it has passed:

| Tier | Criteria | Count | Meaning |
|------|----------|-------|---------|
| **Gold** | Synthetic round-trip passes (fields_mismatch == 0 && total_fields > 0) | 36 | Wire-level bit-correct |
| **Silver** | 2+ independent sources agree on field layout | 132 | Independent structural agreement |
| **Bronze** | Single source, self-consistent (offsets monotonic, no gaps) | 48 | Extractable but unverified |
| **Unvalidated** | No extractable fields yet | ~8,100 | Discovered but not verified |

A protocol can hold multiple tiers simultaneously (e.g., Gold from round-trip
AND Silver from cross-source). The displayed tier is the highest achieved.

**Important distinction:** "Routable" (205 protocols have PCAP generation paths)
is not the same as "Gold-validated" (36 protocols pass round-trip comparison).
The gap is due to tshark dissection failures and field comparison tolerance issues.

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

#### Gold-Validated Protocols (36)

These protocols have been round-trip validated (IR → PCAP → tshark → IR, zero field mismatches):

Ethernet, STP, ARP, UDP, SCTP, ICMPv4, IGMP, ESP, AH, EAPOL, LLC, SNAP,
Slow_Protocols, MAC_Control, IEC_GOOSE, IEC_SV, NBNS, TFTP, ICMPv6, UDPLite,
MLD, IPv6_ND, HCI_CMD, HCI_Event, HCI_SCO, HCI_ISO, CAN_FD, IEEE802154,
SLL, SLL2, ERSPAN, ERF

#### Why Some Routable Protocols Aren't Gold

- **NO_DISSECT**: tshark can parse the packet but doesn't dissect the target layer (e.g., needs prior negotiation, specific PCAP templates, or context from earlier packets)
- **FAIL**: tshark dissects the packet but field comparison fails due to split tolerance (e.g., tshark reports `flags_version` as one field vs IR's separate `flags` + `version`)
- **IPv4/TCP/VLAN**: Common protocols that fail due to tshark's byte-aligned PDML combining sub-byte fields

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
```

## Further Reading

- [Code Generation](code-generation.md) — all four generator targets (C, Rust, Scapy, PCAP)
- [Architecture](architecture.md) — system overview and data flow
- [Extractors](extractors.md) — tshark extractor that powers the round-trip
- [Field Matching](field-matching.md) — comparison algorithm details
