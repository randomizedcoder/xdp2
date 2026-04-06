# Proto-Audit Roadmap

## Context

The proto-audit tool (`samples/proto_audit/`) compares protocol header definitions
across 8 independent sources (XDP2, Linux kernel, Scapy, tshark, etherparse,
libpcap, Kaitai Struct, Suricata), normalizes them into a common IR, and generates code
for all targets.

The goal is to scale beyond **1,000 protocols** with extreme correctness, making
proto-audit the best and largest single source of packet parsing definitions —
with XDP2 as the primary beneficiary.

---

## Current State (2026-04-06)

| Metric | Count |
|--------|-------|
| Total protocols tracked | 8,358 (206 curated + 8,152 discovered) |
| Curated protocols | 206 |
| Gold (round-trip validated) | 112 |
| Silver (2+ sources agree) | 36 |
| Bronze (single source) | 27 |
| Independent sources | 8 (XDP2, kernel, Scapy, tshark, etherparse, libpcap, Kaitai, Suricata) |
| XDP2 proto_defs | 222 (206 curated) |
| Etherparse structs | 206/206 curated |
| Libpcap overlays | 206/206 curated |
| Kaitai curated | 12 protocols |
| Suricata curated | 20 protocols |
| Overlay patches | 206 etherparse + 206 libpcap (batch-generated from PDML corpus) |
| Unit tests | 400 |
| PCAP templates | 62 |
| PCAP corpus | 624 files covering 305 dissectors |
| Decode table entries | 217 |
| RFC references (curated) | 97 protocols, 181 total RFCs |
| CLI commands | 19 |

## Completed Phases

### Phase 0: Foundation Hardening (DONE)

- `data/auto_mappings.json` + `auto_table.rs` for data-driven name mapping
- IR extensions: `StandardRef`, `StandardBody`, `ProtocolLayer`
- ProtocolNames builder: `.rfcs()`, `.ieee()`, `.iana_registry()`
- RFC/IEEE/IANA metadata on all 206 curated protocols

### Phase 1: Automated Cross-Source Matching (DONE)

- `auto_matcher.rs` with tiered matching (exact, decode_table, long_name, abbreviation, containment)
- `scapy_dump.py --discover-all-rich` for fields_desc, bind_layers, docstrings
- `auto-match` CLI command
- `gen_auto_mappings.py` bulk generator (939 entries)
- 52 auto-mapped protocols have Scapy class mappings

### Phase 2: PCAP Corpus & tshark Extraction Scaling (DONE)

- PacketLife.net + Wireshark SampleCaptures PCAP corpus (624 files, 305 dissectors)
- PDML extraction pipeline in Nix (pre-extracted at build time)
- `corpus` command for coverage inspection
- Batch-generated 206 libpcap overlay patches from corpus PDML
- `generate-libpcap-patches` command for automated patch generation

### Phase 3: Quality Assurance Framework (DONE)

- Gold/Silver/Bronze/Unvalidated validation tiers
- Validation cache persistence
- `validate --proto all` for batch round-trip testing
- Regression testing Nix derivation (`proto-audit-validate-all`)
- Protocol prioritization engine (`prioritize`)
- 6-source coverage matrix with gap analysis (`coverage`)

### Phase 4: RFC/IANA Standards Integration (DONE)

- IANA registry fetching in Nix
- `parse_iana.py` + `extractors/iana.rs` for dispatch table validation
- `standards` command with per-protocol and summary views

### Phase 5: Scale to 1,000+ & XDP2 Code Generation (DONE)

- Batch C code generation (`generate-all --target c`)
- Synthetic struct generation for protocols without kernel structs
- 217 decode table entries (up from 12)
- 8,358 protocols tracked
- `search` command across all protocols

### Phase 6: 7th Source — Kaitai Struct (DONE)

- Added Kaitai Struct as independent protocol source
- `kaitai_id` field on `DiscoveredProtocol`
- ~20 protocols gain truly independent 7th source

### Phase 7: 8th Source — Suricata (DONE)

- Added Suricata as 8th independent source
- Rust app-layer parser extraction via regex
- ~15 protocols with struct-level field extraction
- 48 PCAP templates for round-trip validation
- 390 unit tests

### Phase 8: Curated Integration & Verification Expansion (DONE)

- **Kaitai & Suricata curated**: Added `kaitai_id`/`kaitai_file` and `suricata_module`/`suricata_struct` fields to `ProtocolNames`, populated 12 Kaitai + 20 Suricata curated mappings
- **Cross-generator round-trip**: `crossgen` command generates code (C, Rust, Scapy) → re-extracts → compares to original IR. 9 cross-generator tests.
- **Corpus cross-parsing**: `corpus-parse` command parses same PCAP through tshark + Scapy, compares field values with hex/int normalization
- **PCAP template expansion**: 48 → 62 templates (added LLDP, CDP, STP, EAPOL, EAP, CoAP, HSRP, PTP, TFTP, Syslog, NBNS, MGCP, OpenFlow, BFD)
- **Gold promotion**: 85 → 112 Gold protocols
- **Value-level comparator**: `compare_field_values()` in comparator.rs
- **scapy_dump.py extensions**: `--dissect-pcap` and `--extra` modes
- 400 unit tests

---

## Next Steps

### Near-Term: Continue Gold Promotion (112 → 150+)

112 protocols are Gold-validated. The main blockers for the remaining ~90 routable protocols:

1. **Fix NO_DISSECT protocols**: tshark can't dissect the generated PCAP because it needs proper encapsulation context (e.g., PCAP templates, pre-negotiation state). Solutions:
   - Generate more PCAP templates with protocol-specific link types
   - Use corpus PCAPs as templates where available
   - Add protocol-specific fixups for complex encapsulations

2. **Fix FAIL protocols**: Round-trip comparison fails due to field split tolerance issues. Solutions:
   - Extend split-aware comparison for remaining edge cases
   - Handle tshark's byte-aligned PDML rounding

### Near-Term: Bronze → Silver Promotion

27 Bronze protocols have only single-source extraction. Paths to Silver:

1. **Kaitai field extraction**: Wire up Kaitai Struct field extraction to produce ProtocolDefs. ~20 protocols gain a 2nd independent source.

2. **Scapy version gaps**: ~22 curated protocols have Scapy class names in table.rs that don't exist in the current Scapy version. Track Scapy releases and update.

3. **Suricata field extraction improvement**: Enhance Suricata parser to extract more field-level detail from app-layer parsers.

### Medium-Term: Coverage Expansion

1. **Curated protocol expansion**: Add 50-100 more curated protocols from the discovered tier (8,152 discovered protocols, many with tshark + Scapy coverage).

2. **Corpus expansion**: Add more PCAP sources (Netresec, Wireshark test captures, self-generated) to increase tshark extraction coverage.

3. **Cross-generator coverage**: Expand `crossgen` to cover all 206 curated protocols across all generator targets.

### Long-Term: CI & Maintenance

1. **CI pipeline**: Nix-based CI that rebuilds registries, runs regression tests, generates coverage reports on every commit.

2. **Source version tracking**: Automated updates when upstream sources (kernel, Scapy, tshark, etherparse) release new versions.

3. **Replace patches with code generation**: Generate overlay patches from IR rather than maintaining them by hand (Phase 5.4 from original roadmap).
