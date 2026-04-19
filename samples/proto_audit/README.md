# proto-audit: Cross-Source Protocol Definition Audit

Extracts protocol header definitions from twelve independent sources, normalizes
them to a common intermediate representation indexed by wire bit offset, and
compares to find layout disagreements, coverage gaps, and type differences.

**428 curated protocols** across every network layer (including trading protocols from OMI), code generation in 3 languages + PCAP wire output, 332 per-protocol overlay patches each for etherparse and libpcap, 196 PCAP templates for round-trip validation, 420 unit tests.

## Highlights

- **12 independent sources** (XDP2, kernel, DPDK, nDPI, pppd, Scapy, tshark, etherparse, libpcap, Kaitai Struct, Suricata, OMI)
- **428 curated protocols** with hand-verified cross-source mappings
- **Trading protocol coverage** (ITCH v5, PITCH v2, SBE MDP3, EOBI, SoupBinTCP) sourced from Open Markets Initiative c-structs + Wireshark Lua dissectors
- **212+ Gold-validated** protocols (round-trip IR → PCAP → tshark → IR with split-aware comparison)
- **62 PCAP templates** with valid protocol content for round-trip validation
- Field-level comparison by wire bit offset — not name — catches real layout disagreements
- Code generation from IR to C headers, Rust structs, Scapy packet classes, and PCAP packets
- 624-file PCAP corpus covering 305 unique dissectors
- Extensible TOML-based type mappings — no Rust code changes needed
- Nix-reproducible builds with pinned external sources and cached report derivation
- Cross-generator round-trip verification (generate code → re-extract → compare to IR)
- Corpus cross-source parsing (same PCAP through tshark + Scapy, value-level comparison)
- 420 unit tests, JSON output on every command

## Vision

The IETF has never specified a machine-readable format for protocol header
definitions. proto-audit demonstrates that 12 independent implementations of
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
nix run .#proto-audit -- crossgen --proto IPv4 --target all  # cross-generator round-trip
nix run .#proto-audit -- stats                               # system-wide statistics
nix build .#proto-audit-report && cat result/matrix.txt      # cached report
```

## Sources

| Source | What It Provides | Access Method | Coverage |
|---|---|---|---|
| `xdp2` | Proto_def metadata (struct refs, no fields) | Local repo C header parse | 238 proto_defs (incl. 16 trading) |
| `kernel` | Linux UAPI + driver/net struct definitions | Nix-pinned source (include/ + drivers/net/ + net/), regex C parse | 74 protocols (173 in registry) |
| `dpdk` | DPDK packed protocol header structs | Nix-pinned `pkgs.dpdk.src`, lib/net/*.h | ~28 protocols (eCPRI, L2TPv2, MACsec, PDCP, TLS/DTLS, HiGig, PPP, etc.) |
| `ndpi` | nDPI deep packet inspection wire structs | Nix-pinned `pkgs.ndpi.src`, ndpi_typedefs.h | ~25 packed structs + 474 protocol IDs |
| `pppd` | PPP daemon protocol headers and constants | Nix-pinned `pkgs.ppp.src`, pppd/*.h | LCP, IPCP, IPv6CP, CCP, CHAP, EAP, ECP, PAP |
| `scapy` | Scapy `fields_desc` with dispatch/length | Python runtime introspection (JSON) | 5,798 classes (109 curated) |
| `tshark` | Wireshark protocol dissection fields | `tshark -T pdml` subprocess (XML) | 3,155 protocols (3,753 with filters) |
| `etherparse` | Rust packet parsing crate structs | Nix-pinned + 332 overlay patches | 332/428 curated |
| `libpcap` | BPF gencode + C struct definitions | Nix-pinned + 332 overlay patches | 332/428 curated |
| `kaitai` | Kaitai Struct format specifications | Nix-pinned .ksy files | ~20 protocols (12 curated) |
| `suricata` | Rust app-layer parser struct definitions | Nix-pinned source, regex Rust parse | ~15 protocols (20 curated) |
| `omi` | Open Markets Initiative c-structs + Wireshark Lua dissectors | Nix-pinned c-structs + wireshark-lua trees | ~27 trading msgs (ITCH v5, PITCH v2, SBE MDP3, EOBI, SoupBinTCP) |

All external sources are Nix-pinned for reproducibility via
`nix/proto-audit-sources.nix`. See the comments in that file for the full
guide on adding new sources. etherparse and libpcap are extended with
per-protocol overlay patches for cross-source comparison.
See [Source Patching](docs/patching.md) for details.

## How It Works

**Extraction.** Each source has a dedicated extractor that normalizes native
definitions into a common IR indexed by wire bit offset.
**Comparison.** Fields are matched across sources by `(offset, size)` tuples,
not by name, catching real layout disagreements.
**Generation.** Code generators produce C headers, Rust structs, Scapy
packet classes, and PCAP packets from the canonical IR.
**Validation.** The `validate` command generates a PCAP from the IR, feeds it
to tshark, extracts the result back to IR, and compares — a true round-trip
through wire bytes. 112 protocols achieve Gold (zero field mismatches).
**Cross-Generator Verification.** The `crossgen` command generates code from IR
(C, Rust, Scapy), re-extracts from the generated code through the corresponding
extractor, and compares to the original IR — closing the generate→extract loop.
**Corpus Cross-Parsing.** The `corpus-parse` command feeds the same PCAP through
both tshark and Scapy, comparing parsed field values at the value level.

## Commands

| Command | Description |
|---|---|
| `list` | List all 428 curated protocols (`--json` for machine output) |
| `extract --source S --proto P` | Extract one protocol from one source |
| `compare --proto P` | Compare a protocol across all available sources |
| `audit [--protos P1,P2]` | Audit all (or specific) protocols across all sources |
| `matrix` | Source x protocol coverage matrix (field counts, agreement stats) |
| `findings` | Detailed cross-source disagreements and coverage gaps |
| `scan --proto-defs-dir DIR` | Scan XDP2 proto_defs directory for protocol metadata |
| `generate --proto P [--target T]` | Generate code from IR (targets: `c`, `etherparse`, `scapy`, `pcap`) |
| `validate --proto P` | Round-trip validation: IR → PCAP → tshark → IR → compare |
| `stats` | System-wide statistics (protocols, sources, validation tiers) |
| `coverage` | Per-source coverage matrix with gap analysis |
| `search` | Keyword search across all 8,358 tracked protocols |
| `standards` | RFC/IEEE/IANA standards references per protocol |
| `auto-match` | Automated cross-source name matching |
| `prioritize` | Protocol prioritization for coverage expansion |
| `crossgen --proto P [--target T]` | Cross-generator round-trip: generate → re-extract → compare (targets: `etherparse`, `c`, `scapy`, `pcap`, `all`) |
| `corpus-parse --pcap F` | Parse PCAP through tshark + Scapy, compare field values across parsers |
| `corpus` | PCAP corpus coverage inspection |
| `quality` | Validation quality analysis |
| `generate-libpcap-patches` | Generate libpcap overlay patches from corpus PDML data |
| `generate-etherparse-patches` | Generate etherparse Rust overlay patches from corpus PDML data |
| `gen-patches --target T --source S` | Generate overlay patches from IR (targets: `libpcap`, `etherparse`; source: `omi`) |

All commands accept `--json` for machine-readable output.
Filtering: `--protos P1,P2` and `--sources S1,S2` narrow scope on audit/matrix/findings.

## Type Mapping System

Type inference is driven by TOML mapping files in `mappings/`, embedded in the
binary via `include_str!()`. Each file maps between source-native types and the
canonical IR. To add a new C type or correct a field classification, edit the
appropriate TOML — no Rust code changes needed. 7 mapping files cover all 9
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

## Building & Testing

```bash
nix build .#proto-audit          # wrapped with all source paths
nix build .#proto-audit-bin      # raw binary (no env var defaults)
nix develop --command cargo test  # 420 unit tests
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
| [Round-Trip Validation](docs/validation.md) | IR → PCAP → tshark round-trip verification, validation tiers |
| [Status](docs/status.md) | Iteration history, current metrics, known issues |
| [Coverage](docs/proto-audit-coverage.md) | Per-protocol source coverage analysis |
| [Roadmap](docs/roadmap.md) | Scaling plan, completed phases, next steps |
| [Mapping Pipeline](docs/mapping-pipeline.md) | Bidirectional extraction/generation pipeline, per-source fidelity |
| [Inconsistency Analysis](docs/inconsistency-analysis.md) | Root causes of cross-source disagreements, worked examples |
| [IR as Standard](docs/ir-as-standard.md) | Positioning the IR as a universal protocol header format |
| [Upstream Contribution](docs/upstream-contribution.md) | Trading protocol contribution guide (Scapy, Kaitai, Wireshark targets) |

## Project Layout

```
samples/proto_audit/
  src/
    main.rs, commands.rs   CLI entry point + subcommands
    ir.rs, comparator.rs   IR types + cross-source field matching
    name_mapping/          428-protocol canonical name table (12 sources)
    type_mapping/          TOML loading + per-source type inference (7 modules)
    report/                Text/JSON output (matrix, findings)
    generator/             IR → C / Rust / Scapy / PCAP code generation
    extractors/            9 source-specific parsers (kernel, scapy, tshark, etherparse, libpcap, xdp2, kaitai, suricata, omi)
    discovery/             Two-tier protocol discovery (curated + auto-discovered)
    crossgen_tests.rs      Cross-generator round-trip tests (9 tests)
  helpers/
    scapy_dump.py          Python helper for Scapy introspection + PCAP dissection
    gen_pcap_templates.py  Generate 62 PCAP templates with valid protocol content
  mappings/                7 TOML files (5 extraction + 2 generation)
  patches/
    gen_fine_grained.py    Generator script for overlay struct patches
    etherparse/            332 per-protocol Rust overlay patches (incl. 27 trading_*.patch)
    libpcap/               332 per-protocol C header overlay patches (incl. 27 trading_*.patch)
    scapy/                 27 trading Scapy Packet class patches (gen-patches --target scapy)
    kaitai/                27 trading Kaitai .ksy format patches (gen-patches --target kaitai)
  docs/                    16 reference documents (see Documentation)
```

## Status

See [Status](docs/status.md), [Roadmap](docs/roadmap.md), and
[Coverage](docs/proto-audit-coverage.md) for current metrics, next steps,
and per-protocol source coverage.
