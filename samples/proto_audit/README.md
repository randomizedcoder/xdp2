# proto-audit: Cross-Source Protocol Definition Audit

Extracts protocol header definitions from six independent sources, normalizes
them to a common intermediate representation indexed by wire bit offset, and
compares to find layout disagreements, coverage gaps, and type differences.

**207 protocols** across every network layer, code generation in 3 languages, 145 unit tests.

## Highlights

- **207 protocols** across 6 independent sources (XDP2, kernel, Scapy, tshark, etherparse, libpcap)
- Field-level comparison by wire bit offset — not name — catches real layout disagreements
- Structural and semantic agreement detection with pairwise cross-source scoring
- Code generation from IR to C headers, Rust structs, and Scapy packet classes
- Extensible TOML-based type mappings — add or correct types without touching Rust code
- Nix-reproducible builds with pinned external sources and cached report derivation
- 145 unit tests covering roundtrip serialization and cross-source validation
- JSON output on every command for machine-readable pipelines

## Quick Start

```bash
# Source x protocol coverage matrix
nix run .#proto-audit -- matrix

# Detailed cross-source findings
nix run .#proto-audit -- findings

# Extract a single protocol from one source
nix run .#proto-audit -- extract --source kernel --proto ARP

# Compare a protocol across all available sources
nix run .#proto-audit -- compare --proto IPv4

# Generate code from IR
nix run .#proto-audit -- generate --proto IPv4 --target c
nix run .#proto-audit -- generate --proto UDP --target scapy
nix run .#proto-audit -- generate --proto TCP --target etherparse

# Full cached report (all formats)
nix build .#proto-audit-report
cat result/matrix.txt
cat result/findings.txt
```

## Sources

| Source | What It Provides | Access Method | Coverage |
|---|---|---|---|
| `xdp2` | Proto_def metadata (struct refs, no fields) | Local repo C header parse | All 207 |
| `kernel` | Linux UAPI struct field definitions | Nix-pinned source, regex C parse | ~80 protocols |
| `scapy` | Scapy `fields_desc` with dispatch/length | Python runtime introspection (JSON) | 109+ protocols |
| `tshark` | Wireshark protocol dissection fields | `tshark -T pdml` subprocess (XML) | ~60 protocols |
| `etherparse` | Rust packet parsing crate structs | Nix-pinned source, regex Rust parse | 9 core protocols |
| `libpcap` | BPF gencode struct definitions | Nix-pinned source, C header parse | ~20 protocols |

All external sources are Nix-pinned for reproducibility. See [Architecture](docs/architecture.md) for details.

## How It Works

**Extraction.** Each source has a dedicated extractor that parses native definitions
(C structs, Python field descriptors, Rust types, XML dissections) and normalizes
them into a common IR. Every field is indexed by its wire bit offset and size,
producing a source-independent representation of header layout.

**Comparison.** The comparison engine matches fields across sources by `(offset, size)`
tuples, not by name. This catches real disagreements: when two sources define the same
protocol but place a field at different offsets, or split a field differently, the
engine reports a structural mismatch. Semantic agreement is scored separately — do
the type annotations agree?

**Generation.** From the canonical IR, code generators produce C headers with parse
nodes and dispatch functions, Rust structs with derives and `from_slice()` skeletons,
and Scapy packet classes with `fields_desc` and `bind_layers`. Each target is driven
by its own TOML mapping file.

See also: [IR Format](docs/ir-format.md), [Field Matching](docs/field-matching.md)

## Commands

| Command | Description |
|---|---|
| `list` | List all 207 known protocols (`--json` for machine output) |
| `extract --source S --proto P` | Extract one protocol from one source |
| `compare --proto P` | Compare a protocol across all available sources |
| `audit [--protos P1,P2]` | Audit all (or specific) protocols across all sources |
| `matrix` | Source x protocol coverage matrix (field counts, agreement stats) |
| `findings` | Detailed cross-source disagreements and coverage gaps |
| `scan --proto-defs-dir DIR` | Scan XDP2 proto_defs directory for protocol metadata |
| `generate --proto P [--target T]` | Generate code from IR (targets: `c`, `etherparse`, `scapy`) |

All commands accept `--json` for machine-readable output.
Filtering: `--protos P1,P2` and `--sources S1,S2` narrow scope on audit/matrix/findings.

## Type Mapping System

Type inference is driven by TOML mapping files in `mappings/`, embedded in the
binary via `include_str!()`. Each file maps between source-native types and the
canonical IR. To add a new C type or correct a field classification, edit the
appropriate TOML — no Rust code changes needed.

| File | Direction | Purpose |
|---|---|---|
| `kernel.toml` | Source -> IR | C type -> bit width/endianness, field name overrides, embedded struct sizes |
| `scapy.toml` | Source -> IR | Scapy field class -> IR type, endian prefixes, name-pattern fallbacks |
| `tshark.toml` | Source -> IR | tshark field name patterns -> IR type, blocklist suffixes |
| `etherparse.toml` | Source -> IR | Rust type -> wire bit width, implicit fields, flag bit offsets |
| `libpcap.toml` | Source -> IR | libpcap C type/macro -> IR type, BPF gencode struct mappings |
| `etherparse_gen.toml` | IR -> Source | IR type+size -> Rust type, newtypes, derives, skip fields |
| `scapy_gen.toml` | IR -> Source | IR type+size -> Scapy field class, name overrides, LE prefixes |

Override the embedded mappings at runtime with `PROTO_AUDIT_MAPPINGS_DIR`.
See [Architecture](docs/architecture.md) for the full type mapping pipeline.

## Extending

**Adding a protocol.** Add a row to the `PROTOCOLS` table in `name_mapping.rs`
with the canonical name and each source's identifier. Add any needed type
overrides to the relevant TOML mapping files.

**Adding a source.** Implement the `Extractor` trait, add a TOML mapping file,
wire it into the CLI, and update the name table. See
[Adding a Source](docs/adding-a-source.md) for the 11-step walkthrough using
etherparse as a worked example.

**Correcting types.** Edit the appropriate `mappings/*.toml` file. Each override
entry includes a `reason` field documenting the rationale. No Rust changes needed.

## Building & Testing

```bash
# Nix build (recommended — wrapped with all source paths)
nix build .#proto-audit

# Raw binary (no env var defaults)
nix build .#proto-audit-bin

# Run tests (145 unit tests)
nix develop --command cargo test

# Run with custom PYTHONPATH for local Scapy development
PYTHONPATH=~/Downloads/scapy nix run .#proto-audit -- matrix
```

The Nix wrapper sets all `PROTO_AUDIT_*` variables automatically; use `--help` for CLI overrides.

### Nix Outputs

| Output | Description |
|---|---|
| `.#proto-audit` | `writeShellApplication` wrapper with all `PROTO_AUDIT_*` env vars set |
| `.#proto-audit-bin` | Raw Rust binary without env var defaults |
| `.#proto-audit-report` | Cached derivation producing `matrix.txt`, `findings.txt`, `audit.json` |

## Documentation

| Document | Description |
|---|---|
| [Architecture](docs/architecture.md) | System overview, extractors, type mapping pipeline, component diagram |
| [IR Format](docs/ir-format.md) | Complete IR schema, JSON examples, code generation mappings |
| [Field Matching](docs/field-matching.md) | Structural vs semantic agreement, audit algorithm, report interpretation |
| [Adding a Source](docs/adding-a-source.md) | Step-by-step guide using etherparse as a worked example |
| [Status](docs/status.md) | Iteration history, expected impact, known issues |
| [Coverage](docs/proto-audit-coverage.md) | Per-protocol source coverage analysis |

## Project Layout

```
samples/proto_audit/
  src/
    main.rs              CLI entry point (8 commands, source path resolution)
    ir.rs                IR types: ProtocolDef, FieldDef, AuditResult
    name_mapping.rs      207-protocol canonical name table (6 sources)
    type_mapping.rs      TOML loading + type inference accessors
    comparator.rs        Cross-source field matching engine
    report.rs            Text/JSON output formatting
    generator.rs         IR -> C/Rust/Python code generation
    extractors/
      mod.rs             Module index
      kernel.rs          Linux kernel C struct parser
      scapy.rs           Scapy JSON consumer
      tshark.rs          tshark PDML XML parser
      etherparse.rs      etherparse Rust struct parser
      libpcap.rs         libpcap C header/gencode parser
      xdp2.rs            XDP2 proto_def metadata extractor
    test_data.rs         Embedded test fixtures
    roundtrip_tests.rs   Roundtrip golden-output tests
  helpers/
    scapy_dump.py        Python helper for Scapy introspection
  mappings/
    kernel.toml          Kernel C type -> IR mappings
    scapy.toml           Scapy field class -> IR mappings
    tshark.toml          tshark field pattern -> IR mappings
    etherparse.toml      etherparse Rust type -> IR mappings
    libpcap.toml         libpcap C type/gencode -> IR mappings
    etherparse_gen.toml  IR -> etherparse Rust type mappings
    scapy_gen.toml       IR -> Scapy field class mappings
  docs/                  6 detailed reference documents (see Documentation)
```

## Status & Vision

proto-audit currently covers 207 protocols across 6 independent sources with
145 unit tests. The comparison engine performs field-level structural matching
by wire bit offset, the type mapping system is fully extensible via TOML, and
code generation produces working output in C, Rust, and Python.

The project is building toward a comprehensive, machine-readable protocol header
database — a "Rosetta Stone" for packet formats. Each new source adds
cross-validation depth, each corrected type mapping improves fidelity, and the
canonical IR grows into a single reference that protocol tooling can build on.

See [Status](docs/status.md) and [Coverage](docs/proto-audit-coverage.md) for details.
