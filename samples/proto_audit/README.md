# proto-audit: Multi-Source Protocol Definition Audit & Generation

A Rust tool that compares protocol definitions across four authoritative sources
to audit correctness, find bugs, and auto-generate new XDP2 proto_def headers.

## Sources

| Source | Format | Access |
|---|---|---|
| **XDP2** | C headers (`xdp2_proto_def` structs) | Local repo parse |
| **Linux kernel** | C structs (UAPI headers) | Nix-pinned source |
| **Scapy** | Python classes (`fields_desc`) | Runtime introspection → JSON |
| **tshark** | PDML XML (`<proto>`/`<field>`) | `tshark -T pdml` subprocess |

## Intermediate Representation

All sources are normalized into a canonical IR (`ProtocolDef`) with:

- **Fields**: name, bit offset, bit size, semantic type, endianness, dispatch/length roles
- **Dispatch tables**: maps field values to next protocols
- **Source names**: preserves each source's original naming
- **Cross-source metadata**: per-source file paths, field counts, notes

See `src/ir.rs` for the full type definitions.

## Architecture

```
                    ┌──────────────────────────────┐
                    │     Rust: proto-audit CLI     │
                    │  (clap, serde, roxmltree)     │
                    └──────┬───────────────────────┘
                           │
           ┌───────────────┼───────────────┐
           │               │               │
    ┌──────▼──────┐ ┌──────▼──────┐ ┌──────▼──────┐
    │  XDP2       │ │  Kernel     │ │  tshark     │
    │  Extractor  │ │  Extractor  │ │  Extractor  │
    │ (regex C)   │ │ (regex C)   │ │ (PDML XML)  │
    └─────────────┘ └─────────────┘ └──────┬──────┘
                                           │
                                    tshark subprocess
    ┌─────────────┐                        │
    │  Scapy      │ ◄── JSON ──── Python helper
    │  Extractor  │
    └─────────────┘
           │
           ▼
    ┌─────────────────────┐     ┌──────────────────┐
    │  Comparator         │ ──► │  Report          │
    │  (field matching)   │     │  (text / JSON)   │
    └─────────────────────┘     └──────────────────┘
           │
           ▼
    ┌─────────────────────┐
    │  Generator          │
    │  (IR → C headers)   │
    └─────────────────────┘
```

## Usage

```bash
# Extract from a single source
proto-audit extract --source scapy --proto IPv4
proto-audit extract --source kernel --proto IPv4 --kernel-src /path/to/linux

# Compare across sources
proto-audit compare --proto IPv4

# Audit all XDP2 proto_defs
proto-audit audit --all

# Generate a new proto_def from IR
proto-audit generate --proto VRRP --dry-run

# List known protocols
proto-audit list
```

## Building

```bash
# Via Nix (recommended)
nix build .#proto-audit

# Via Cargo directly
cd samples/proto_audit
cargo build --release
```

## Field Matching Strategy

Fields from different sources are matched by **offset+size first**, then name:

1. **Exact match**: Same `offset_bits` AND `size_bits` → same field
2. **Overlap match**: Overlapping bit ranges → likely same field split differently
3. **Name similarity**: Levenshtein distance as tiebreaker
4. **Unmatched**: Fields in one source but not another → coverage gap

## Phases

- [x] Phase 1: Project skeleton and design
- [x] Phase 2: Nix integration
- [x] Phase 3: IR core types and name mapping
- [ ] Phase 4: Extractors (scapy, kernel, xdp2, tshark)
- [ ] Phase 5: Comparison and audit engine
- [ ] Phase 6: C header generation
