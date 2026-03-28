# proto-audit: Cross-Source Protocol Definition Audit

Extracts protocol header definitions from six independent sources, normalizes
them to a common intermediate representation indexed by wire bit offset, and
compares to find layout disagreements, coverage gaps, and type differences.

**207 protocols** across every network layer, code generation in 3 languages + PCAP wire output, 49 per-protocol overlay patches for fine-grained RFC-level field comparison, 330 unit tests.

## Highlights

- **207 protocols** across 6 independent sources (XDP2, kernel, Scapy, tshark, etherparse, libpcap)
- **49 per-protocol overlay patches** (31 etherparse + 18 libpcap) with RFC-level sub-field granularity
- Field-level comparison by wire bit offset — not name — catches real layout disagreements
- Code generation from IR to C headers, Rust structs, Scapy packet classes, and PCAP packets
- Extensible TOML-based type mappings — no Rust code changes needed
- Nix-reproducible builds with pinned external sources and cached report derivation
- 330 unit tests, JSON output on every command

## Vision

The IETF has never specified a machine-readable format for protocol header
definitions. proto-audit demonstrates that 6 independent implementations of
the same RFCs diverge measurably — and that a common IR can reconcile them.
See [IR as Standard](docs/ir-as-standard.md).

## Quick Start

```bash
nix run .#proto-audit -- matrix                              # coverage matrix
nix run .#proto-audit -- findings                            # cross-source disagreements
nix run .#proto-audit -- extract --source kernel --proto ARP # single protocol
nix run .#proto-audit -- compare --proto IPv4                # cross-source compare
nix run .#proto-audit -- generate --proto IPv4 --target c    # code generation
nix run .#proto-audit -- generate --proto TCP --target pcap  # PCAP wire output
nix run .#proto-audit -- validate --proto IPv4               # round-trip validation
nix build .#proto-audit-report && cat result/matrix.txt      # cached report
```

## Sources

| Source | What It Provides | Access Method | Coverage |
|---|---|---|---|
| `xdp2` | Proto_def metadata (struct refs, no fields) | Local repo C header parse | All 207 |
| `kernel` | Linux UAPI struct field definitions | Nix-pinned source, regex C parse | ~80 protocols |
| `scapy` | Scapy `fields_desc` with dispatch/length | Python runtime introspection (JSON) | 109+ protocols |
| `tshark` | Wireshark protocol dissection fields | `tshark -T pdml` subprocess (XML) | ~60 protocols |
| `etherparse` | Rust packet parsing crate structs | Nix-pinned + 31 overlay patches | 9 core + 31 overlay |
| `libpcap` | BPF gencode + C struct definitions | Nix-pinned + 18 overlay patches | ~6 native + 18 overlay |

All external sources are Nix-pinned for reproducibility. etherparse and libpcap
are extended with per-protocol overlay patches for cross-source comparison of
49 additional protocols. See [Source Patching](docs/patching.md) for details.

## How It Works

**Extraction.** Each source has a dedicated extractor that normalizes native
definitions into a common IR indexed by wire bit offset.
**Comparison.** Fields are matched across sources by `(offset, size)` tuples,
not by name, catching real layout disagreements.
**Generation.** Code generators produce C headers, Rust structs, Scapy
packet classes, and PCAP packets from the canonical IR.
**Validation.** The `validate` command generates a PCAP from the IR, feeds it
to tshark, extracts the result back to IR, and compares — a true round-trip
through wire bytes.

**Patching.** etherparse and libpcap are extended with 49 per-protocol overlay
patches that add RFC-level struct definitions for protocols beyond their native
coverage. Each patch splits coarse combined fields into individual sub-fields
(e.g., GRE `flags_version:u16` becomes 6 separate bit-level fields).

See [Architecture](docs/architecture.md), [Source Patching](docs/patching.md),
[IR Format](docs/ir-format.md), [Field Matching](docs/field-matching.md) for details.

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
| `generate --proto P [--target T]` | Generate code from IR (targets: `c`, `etherparse`, `scapy`, `pcap`) |
| `validate --proto P` | Round-trip validation: IR → PCAP → tshark → IR → compare |

All commands accept `--json` for machine-readable output.
Filtering: `--protos P1,P2` and `--sources S1,S2` narrow scope on audit/matrix/findings.

## Type Mapping System

Type inference is driven by TOML mapping files in `mappings/`, embedded in the
binary via `include_str!()`. Each file maps between source-native types and the
canonical IR. To add a new C type or correct a field classification, edit the
appropriate TOML — no Rust code changes needed. 7 mapping files cover all 6
sources plus 2 generation targets.

Override the embedded mappings at runtime with `PROTO_AUDIT_MAPPINGS_DIR`.
See [Architecture](docs/architecture.md) for the full type mapping pipeline.

## Extending

**Adding a protocol.** Add a row to the `PROTOCOLS` table in `name_mapping/table.rs`
with the canonical name and each source's identifier. Add any needed type
overrides to the relevant TOML mapping files.

**Adding a source.** Implement the `Extractor` trait, add a TOML mapping file,
wire it into the CLI, and update the name table. See
[Adding a Source](docs/adding-a-source.md) for the 11-step walkthrough using
etherparse as a worked example.

**Correcting types.** Edit the appropriate `mappings/*.toml` file. Each override
entry includes a `reason` field documenting the rationale. No Rust changes needed.

**Adding an overlay patch.** To add a protocol to etherparse or libpcap, add
the struct definition to `gen_fine_grained.py`, run it, and drop the `.patch`
file into `patches/etherparse/` or `patches/libpcap/`. See
[Source Patching](docs/patching.md).

## Understanding Field Coverage

### Why XDP2 Shows 0 Fields

XDP2 is an eBPF/XDP packet processing framework. Its `xdp2_proto_def` structs
define metadata only — protocol name, `sizeof()` for minimum length, dispatch
and length functions. They reference kernel structs directly (e.g.,
`#include <linux/ip.h>`) and provide type-safe accessor functions. XDP2 shows
`0*` in the matrix (metadata present, zero extracted fields) because field-level
definitions live in the kernel UAPI headers, extracted separately by the kernel
extractor. This is by design — XDP2 focuses on protocol graph traversal and
BPF program generation, not field-level reflection.

### Why Kernel Fields Can Be Coarser

The Linux kernel UAPI headers are authoritative upstream definitions. Some
kernel fields are deliberately coarser than what Scapy or tshark extract.
For example, IPv4's `frag_off` is a single `__be16` combining 3-bit flags and
13-bit fragment offset, while Scapy splits these into separate fields. Similarly,
VLAN's `h_vlan_TCI` combines priority, CFI, and VLAN ID into one `__be16`.
These are intentional kernel design choices for fast BPF access — proto-audit
documents these granularity differences as findings rather than patching them.

### Where Overlay Patches Add Coverage

The 49 overlay patches extend etherparse (31 protocols) and libpcap (18
protocols) with struct definitions for protocols beyond their native coverage.
These use RFC-level granularity, splitting coarse combined fields into
individual sub-fields. See [Source Patching](docs/patching.md) for the
complete list and before/after examples.

## Building & Testing

```bash
nix build .#proto-audit          # wrapped with all source paths
nix build .#proto-audit-bin      # raw binary (no env var defaults)
nix develop --command cargo test  # 330 unit tests
```

The Nix wrapper sets all `PROTO_AUDIT_*` variables automatically.
See [Nix Packaging](docs/nix-packaging.md) for flake outputs and source pinning.

## Documentation

| Document | Description |
|---|---|
| [Architecture](docs/architecture.md) | System overview, component diagram, data flow, type mapping |
| [Extractors](docs/extractors.md) | Per-source extractor details, TOML mapping usage |
| [IR Format](docs/ir-format.md) | Complete IR schema, JSON examples |
| [Code Generation](docs/code-generation.md) | Generator targets (C, Rust, Python, PCAP), TOML schemas |
| [Field Matching](docs/field-matching.md) | Structural vs semantic agreement, audit algorithm, report interpretation |
| [Source Patching](docs/patching.md) | Overlay patches, fine-grained analysis, sub-byte types, upstream PR workflow |
| [Adding a Source](docs/adding-a-source.md) | Step-by-step guide using etherparse as a worked example |
| [Nix Packaging](docs/nix-packaging.md) | Build, source pinning, `applyPatches`, flake outputs |
| [Round-Trip Validation](docs/validation.md) | IR → PCAP → tshark round-trip verification |
| [Status](docs/status.md) | Iteration history, expected impact, known issues |
| [Coverage](docs/proto-audit-coverage.md) | Per-protocol source coverage analysis |
| [Mapping Pipeline](docs/mapping-pipeline.md) | Bidirectional extraction/generation pipeline, per-source fidelity |
| [Inconsistency Analysis](docs/inconsistency-analysis.md) | Root causes of cross-source disagreements, worked examples |
| [IR as Standard](docs/ir-as-standard.md) | Positioning the IR as a universal protocol header format |

## Project Layout

```
samples/proto_audit/
  src/
    main.rs, commands.rs   CLI entry point + subcommands
    ir.rs, comparator.rs   IR types + cross-source field matching
    name_mapping/          207-protocol canonical name table (6 sources)
    type_mapping/          TOML loading + per-source type inference (7 modules)
    report/                Text/JSON output (matrix, findings)
    generator/             IR → C / Rust / Scapy / PCAP code generation
    extractors/            6 source-specific parsers (kernel, scapy, tshark, etherparse, libpcap, xdp2)
  helpers/scapy_dump.py    Python helper for Scapy introspection
  mappings/                7 TOML files (5 extraction + 2 generation)
  patches/
    gen_fine_grained.py    Generator script for overlay struct patches
    etherparse/            31 per-protocol Rust overlay patches
    libpcap/               18 per-protocol C header overlay patches
  docs/                    14 reference documents (see Documentation)
```

## Status

See [Status](docs/status.md) and [Coverage](docs/proto-audit-coverage.md) for
iteration history, known issues, and per-protocol source coverage.
