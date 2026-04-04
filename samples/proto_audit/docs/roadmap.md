# Proto-Audit Roadmap

## Context

The proto-audit tool (`samples/proto_audit/`) compares protocol header definitions
across 7 independent sources (XDP2, Linux kernel, Scapy, tshark, etherparse,
libpcap, Kaitai Struct), normalizes them into a common IR, and generates code
for all targets.

The goal is to scale beyond **1,000 protocols** with extreme correctness, making
proto-audit the best and largest single source of packet parsing definitions —
with XDP2 as the primary beneficiary.

---

## Current State (2026-04-03)

| Metric | Count |
|--------|-------|
| Total protocols tracked | 8,358 (206 curated + 8,152 discovered) |
| Curated protocols | 206 |
| Gold (round-trip validated) | 36 |
| Silver (2+ sources agree) | 132 |
| Bronze (single source) | 48 |
| XDP2 proto_defs | 222 (206 curated) |
| Etherparse structs | 206/206 curated |
| Libpcap overlays | 206/206 curated |
| Overlay patches | 206 etherparse + 206 libpcap (batch-generated from PDML corpus) |
| Unit tests | 378 |
| PCAP corpus | 624 files covering 305 dissectors |
| Decode table entries | 217 |
| RFC references (curated) | 97 protocols, 181 total RFCs |
| CLI commands | 17 |

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

---

## Next Steps

### Near-Term: Increase Gold Count (36 → 100+)

The PCAP round-trip infrastructure is proven for 36 protocols. The main blockers for the remaining ~170 routable protocols:

1. **Fix NO_DISSECT protocols** (~40): tshark can't dissect the generated PCAP because it needs proper encapsulation context (e.g., PCAP templates, pre-negotiation state). Solutions:
   - Generate PCAP templates with protocol-specific link types
   - Use corpus PCAPs as templates where available
   - Add protocol-specific fixups for complex encapsulations

2. **Fix FAIL protocols** (~30): Round-trip comparison fails due to field split tolerance issues. Solutions:
   - Add split-aware comparison mode (e.g., tshark reports combined `flags_version` vs IR's separate `flags` + `version`)
   - Handle tshark's byte-aligned PDML rounding

3. **Fix embedded proto definitions** (~20): Some embedded protocol definitions have field names that don't match tshark's PDML field names. Solutions:
   - Add field name aliases to embedded protos
   - Auto-derive embedded protos from tshark PDML

### Near-Term: Bronze → Silver Promotion

48 Bronze protocols have only single-source extraction. Paths to Silver:

1. **Kaitai as field source**: Wire up Kaitai Struct field extraction to produce ProtocolDefs. ~20 protocols gain a 2nd independent source.

2. **Scapy version gaps**: ~22 curated protocols have Scapy class names in table.rs that don't exist in the current Scapy version. Track Scapy releases and update.

3. **Etherparse batch patches**: Add `generate-etherparse-patches` command (modeled on `generate-libpcap-patches`) to batch-generate Rust struct patches from PDML corpus, promoting Bronze protocols that have corpus coverage.

### Medium-Term: Coverage Expansion

1. **Curated protocol expansion**: Add 50-100 more curated protocols from the discovered tier (8,152 discovered protocols, many with tshark + Scapy coverage).

2. **Corpus expansion**: Add more PCAP sources (Netresec, Wireshark test captures, self-generated) to increase tshark extraction coverage.

3. **Corpus cross-source parse**: Parse the same corpus PCAPs with Scapy (`rdpcap()`) in addition to tshark for the strongest cross-verification signal.

### Long-Term: CI & Maintenance

1. **CI pipeline**: Nix-based CI that rebuilds registries, runs regression tests, generates coverage reports on every commit.

2. **Source version tracking**: Automated updates when upstream sources (kernel, Scapy, tshark, etherparse) release new versions.

3. **Replace patches with code generation**: Generate overlay patches from IR rather than maintaining them by hand (Phase 5.4 from original roadmap).
