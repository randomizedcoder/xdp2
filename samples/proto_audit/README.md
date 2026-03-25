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

The Nix wrapper pre-configures all external source paths (kernel, Scapy, tshark, pcap):

```bash
# List all 41 known protocols
nix run .#proto-audit -- list

# Extract from a single source
nix run .#proto-audit -- extract --source kernel --proto IPv4
nix run .#proto-audit -- extract --source scapy --proto TCP
nix run .#proto-audit -- extract --source xdp2 --proto IPv4
nix run .#proto-audit -- extract --source tshark --proto UDP

# Compare a protocol across all sources
nix run .#proto-audit -- compare --proto IPv4

# Audit all protocols
nix run .#proto-audit -- audit

# Audit specific protocols
nix run .#proto-audit -- audit --protos IPv4,TCP,UDP

# Source × protocol coverage matrix
nix run .#proto-audit -- matrix

# Detailed cross-source disagreements and findings
nix run .#proto-audit -- findings

# Scan XDP2 proto_defs directory
nix run .#proto-audit -- scan

# Generate a new proto_def from IR
nix run .#proto-audit -- generate --proto VRRP --dry-run

# Build full cached audit report (all formats)
nix build .#proto-audit-report
cat result/matrix.txt      # Source × protocol coverage matrix
cat result/findings.txt    # Detailed cross-source disagreements
cat result/audit.txt       # Full per-protocol audit
cat result/audit.json      # Machine-readable audit
cat result/protocols.txt   # Protocol list
cat result/xdp2-scan.txt   # XDP2 proto_defs scan
```

### Environment Variable Overrides

The wrapper sets defaults via `PROTO_AUDIT_*` env vars. Override any source path:

```bash
PROTO_AUDIT_KERNEL_SRC=/custom/linux nix run .#proto-audit -- extract --source kernel --proto IPv4
```

| Variable | Description |
|---|---|
| `PROTO_AUDIT_PROTO_DEFS_DIR` | XDP2 proto_defs directory |
| `PROTO_AUDIT_KERNEL_SRC` | Linux kernel source tree |
| `PROTO_AUDIT_PCAP` | PCAP file for tshark |
| `PROTO_AUDIT_SCAPY_HELPER` | Path to scapy_dump.py |
| `PROTO_AUDIT_PYTHON` | Python binary (with scapy) |
| `PROTO_AUDIT_TSHARK_BIN` | tshark binary |

## Building

```bash
# Via Nix (recommended) — wrapped with all sources
nix build .#proto-audit

# Raw binary without source defaults
nix build .#proto-audit-bin

# Development (Rust tests)
nix develop --command cargo test
```

## Tests

43 unit tests covering all extractors, comparator, and generator:

```bash
nix develop --command cargo test
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
- [x] Phase 3: IR core types and name mapping (41 protocols)
- [x] Phase 4: Extractors (scapy, kernel, xdp2, tshark)
- [x] Phase 5: Comparison and audit engine
- [x] Phase 6: C header generation
