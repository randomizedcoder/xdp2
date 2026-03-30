# Proto-Audit: Scaling to 1,000+ Protocols with Maximum Fidelity

## Context

The proto-audit tool (`samples/proto_audit/`) compares protocol header definitions
across 6 independent sources (XDP2, Linux kernel, Scapy, tshark, etherparse,
libpcap), normalizes them into a common IR, and generates code for all targets.

The goal is to scale beyond **1,000 protocols** with extreme correctness, making
proto-audit the best and largest single source of packet parsing definitions --
with XDP2 as the primary beneficiary.

---

## Current State

| Metric | Count |
|--------|-------|
| Total protocols tracked | 1,447 (207 curated + 1,240 auto-mapped) + discovered (tshark ~3,000) |
| Protocols with extractable fields | 127 |
| Cross-checkable (2+ sources) | 38 |
| Round-trip validated (Gold) | 205 |
| Overlay patches | 49 (31 etherparse, 18 libpcap) |
| XDP2 proto_defs | ~69 |
| Unit tests | 376 |
| Decode table entries | 228 |
| RFC references (curated) | 207 protocols annotated |
| CLI commands | 17 (audit, compare, corpus, coverage, extract, generate, generate-all, list, matrix, findings, quality, search, validate, auto-match, prioritize, standards, stats) |

## Architecture Bottlenecks

1. **Name mapping table** (`src/name_mapping/table.rs`): 206 hand-curated entries.
   Cannot scale to 1,000+ by hand.
2. **PCAP corpus**: tshark PDML extraction requires PCAPs. Only PacketLife.net
   corpus currently fetched.
3. **C target blocked**: `cmd_generate_all` rejects `target == "c"`, so XDP2
   proto_defs can't be batch-generated.
4. **No kernel structs for most protocols**: Only ~48 have UAPI structs. The rest
   need synthetic struct definitions for XDP2 code generation.
5. **No authoritative standard references**: When sources disagree, there's no
   ground-truth arbiter.
6. **12 decode tables mapped**: `DECODE_TABLE_MAP` covers only 12 of tshark's 100+
   decode table types.

---

## Phase Overview

| Phase | Focus | Target Count | Timeline |
|-------|-------|-------------|----------|
| 0 | Foundation & IR extensions | 207 (infrastructure) | Week 1 |
| 1 | Automated cross-source matching | ~400 | Weeks 2-3 |
| 2 | PCAP corpus & tshark extraction scaling | ~500 | Weeks 3-5 |
| 3 | Quality assurance framework | ~500 validated | Weeks 5-7 |
| 4 | RFC/IANA standards integration | ~600 | Weeks 7-9 |
| 5 | Scale to 1,000+ & XDP2 code gen | 1,000+ | Weeks 9-12 |
| 6 | Continuous maintenance | Ongoing | Ongoing |

---

## Phase 0: Foundation Hardening (DONE)

Infrastructure changes that enable scaling without changing protocol counts.

### 0.1 Data-Driven Name Mapping

- `data/auto_mappings.json` -- supplementary protocol mappings (initially empty)
- `src/name_mapping/auto_table.rs` -- JSON loader via `include_str!()`
- Loaded alongside the hand-curated `table.rs`

### 0.2 IR Extensions for Standards & Confidence

Added to `ir.rs`:
- `StandardRef` struct with `id`, `body`, `section`, `url`, `relationship`
- `StandardBody` enum: `Rfc`, `Ieee`, `Iana`, `Other`
- `StandardRelationship` enum: `Defines`, `Updates`, `Obsoletes`, `Registry`
- `ProtocolLayer` enum: `L2`, `L3`, `L4`, `L7`, `Tunnel`, `Security`, etc.

Added to `ProtocolDef`:
- `standards: Vec<StandardRef>`
- `iana_registries: BTreeMap<String, String>`
- `layer: Option<ProtocolLayer>`

Added to `DiscoveredProtocol`:
- `match_confidence: Option<f32>`
- `match_method: Option<String>`

### 0.3 ProtocolNames Builder Extensions

Added to `ProtocolNames`:
- `.rfcs(&[791, 2474, 3168, 6864])` -- list of RFCs (first = defines, rest = updates)
- `.ieee(&["802.1Q-2022"])` -- list of IEEE standards
- `.iana_registry("protocol-numbers")` -- IANA registry name

Populated RFC/IEEE/IANA metadata for all 207 curated protocols.

---

## Phase 1: Automated Cross-Source Matching (DONE)

Scaled from 207 to 1,146 protocols via automated name resolution + batch generation.

- [x] New module `src/name_mapping/auto_matcher.rs` with tiered matching (exact, decode_table, long_name, abbreviation, containment)
- [x] Extended `helpers/scapy_dump.py` with `--discover-all-rich` for fields_desc, bind_layers, docstrings
- [x] New CLI: `proto-audit auto-match --min-confidence 0.8`
- [x] Created `helpers/gen_auto_mappings.py` — bulk protocol generator (939 entries across 40+ categories)
- [x] 52 auto-mapped protocols have Scapy class mappings

## Phase 2: PCAP Corpus & tshark Extraction Scaling (PARTIAL)

- [x] PacketLife.net PCAP corpus in Nix (single-protocol PCAPs)
- [x] PDML extraction pipeline (`tshark -T pdml` in Nix derivation)
- [x] `proto-audit corpus` command for PCAP coverage inspection
- [ ] Multi-source PCAP corpus (Wireshark samples, self-generated)
- [ ] PDML cache derivation for batch extraction
- [ ] Batch tshark extraction from cache

## Phase 3: Quality Assurance Framework (DONE)

- [x] Gold/Silver/Bronze/Unvalidated validation tiers in `DiscoveredProtocol`
- [x] Validation cache persistence (`PROTO_AUDIT_VALIDATION_CACHE`)
- [x] `proto-audit validate --proto all` for batch round-trip testing
- [x] Regression testing Nix derivation (`proto-audit-validate-all`)
- [x] Protocol prioritization engine (`proto-audit prioritize`)
- [x] `proto-audit coverage` — 6-source coverage matrix with gap analysis
- [x] Validation tier display in `list`, `stats`, `findings` output

## Phase 4: RFC/IANA Standards Integration (DONE)

- [x] IANA registry fetching in Nix (protocol-numbers, ethertypes)
- [x] `helpers/parse_iana.py` — IANA CSV parser
- [x] `src/extractors/iana.rs` — dispatch table validation
- [x] RFC/IEEE/IANA metadata on all 207 curated protocols
- [x] `proto-audit standards` — per-protocol and summary views
- [x] `proto-audit standards --validate` — IANA dispatch validation

## Phase 5: Scale to 1,000+ & XDP2 Code Generation (DONE)

- [x] Enable batch C code generation (`generate-all --target c`)
- [x] Synthetic struct generation (`generate_proto_def_synthetic`)
- [x] Expanded DECODE_TABLE_MAP from 12 to 217 entries
- [x] 1,146 protocols tracked (207 curated + 939 auto-mapped)
- [x] `proto-audit search` — keyword search across 1,146 protocols
- [ ] Replace patches with code generation (Phase 5.4)
- [ ] XDP2 proto_def compile-test Nix derivation

## Phase 6: Continuous Maintenance (PARTIAL)

- [x] Source version tracking in `nix/proto-audit-sources.nix`
- [ ] CI pipeline (Nix-based: rebuild registries, regression, report)
