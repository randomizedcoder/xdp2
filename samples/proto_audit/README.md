# proto-audit: Multi-Source Protocol Definition Audit & Generation

Compares protocol header definitions across five authoritative sources —
XDP2, Linux kernel UAPI headers, Scapy, tshark, and etherparse — to find
layout disagreements, coverage gaps, and type annotation differences.

**113 protocols** audited, **109 with Scapy coverage**, spanning:
Ethernet through tunneling (GRE, VXLAN, Geneve, MPLS), security (ESP, AH,
MACsec), management (LLDP, PTP, IGMP), Bluetooth (HCI variants, L2CAP,
ATT, SMP, RFCOMM, BNEP, SDP, AVDTP), InfiniBand (LRH, GRH, BTH, DETH,
RETH, AETH, RDETH, AtomicETH, ImmDt, MAD), industrial (EtherCAT, PROFINET,
CAN/CAN_FD/CAN_XL), routing (OSPF, BGP, RIP, ISIS, EIGRP), redundancy
(VRRP, HSRP), multicast (IGMPv3, MLD/MLDv2), media/streaming (RTP,
MPEG-TS, SRT), UDP applications (DNS, NTP, SNMP, DHCP, DHCPv6, QUIC),
storage (iSCSI, NVMe, FC, SCSI, iSER), network storage (NFS, SMB, SMB2,
ONC-RPC), and legacy (IPX, AppleTalk, X.25, ATM).

Etherparse provides cross-language Rust validation for 9 core protocols.

Type inference across sources is driven by an extensible TOML-based mapping
system (`mappings/*.toml`) — add or correct type mappings without touching
Rust code.

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

## Commands

| Command | Description |
|---|---|
| `list` | List all 113 known protocols (`--json` for machine output) |
| `extract --source S --proto P` | Extract one protocol from one source |
| `compare --proto P` | Compare a protocol across all available sources |
| `audit [--protos P1,P2]` | Audit all (or specific) protocols across all sources |
| `matrix` | Source x protocol coverage matrix (field counts, agreement stats) |
| `findings` | Detailed cross-source disagreements and coverage gaps |
| `scan --proto-defs-dir DIR` | Scan XDP2 proto_defs directory for protocol metadata |
| `generate --proto P [--target T]` | Generate code from IR (targets: `c`, `etherparse`, `scapy`) |

All commands accept `--json` for machine-readable output.
Filtering: `--protos P1,P2` and `--sources S1,S2` narrow scope on audit/matrix/findings.

### Sources

The `extract` command accepts these source names:

| Source | Description | Access Method |
|---|---|---|
| `xdp2` | XDP2 proto_def metadata (struct refs, no fields) | Local repo C header parse |
| `kernel` | Linux kernel UAPI struct definitions | Nix-pinned source, regex C parse |
| `scapy` | Scapy Packet class `fields_desc` | Python runtime introspection (JSON) |
| `tshark` | Wireshark protocol dissection | `tshark -T pdml` subprocess (PDML XML) |
| `etherparse` | Rust packet parsing crate structs | Nix-pinned source, regex Rust parse |

### Code Generation Targets

The `generate` command produces source code from the IR:

| Target | Output | Config |
|---|---|---|
| `c` (default) | XDP2 `proto_def` C header with parse node, dispatch, length functions | Built-in templates |
| `etherparse` | Rust struct with derives and `from_slice()` skeleton | `mappings/etherparse_gen.toml` |
| `scapy` | Python Scapy Packet class with `fields_desc` and `bind_layers` | `mappings/scapy_gen.toml` |

## Intermediate Representation

All sources are normalized into a canonical IR (`ProtocolDef` in `src/ir.rs`).
The IR captures:

- **Fields**: name, bit offset, bit size, semantic type (`Uint`, `Enum`,
  `Ipv4Addr`, `Flags`, etc.), endianness, dispatch/length roles
- **Dispatch tables**: maps field values to next-layer protocols
- **Source names**: preserves each source's original naming (`saddr` vs `src`
  vs `ip.src`)
- **Per-source metadata**: file paths, field counts, header sizes, notes

See [IR Format Reference](docs/ir-format.md) for the complete schema
documentation with JSON examples, field matching semantics, and code
generation mappings.

## Environment Variables

The Nix wrapper (`nix run .#proto-audit`) sets all paths automatically.
Override any source path via env var or CLI flag:

| Variable | CLI Flag | Description |
|---|---|---|
| `PROTO_AUDIT_PROTO_DEFS_DIR` | `--proto-defs-dir` | XDP2 proto_defs directory |
| `PROTO_AUDIT_KERNEL_SRC` | `--kernel-src` | Linux kernel source tree (include/uapi/) |
| `PROTO_AUDIT_SCAPY_HELPER` | `--scapy-helper` | Path to `helpers/scapy_dump.py` |
| `PROTO_AUDIT_PYTHON` | `--python` | Python binary (must have scapy installed) |
| `PROTO_AUDIT_TSHARK_BIN` | `--tshark-bin` | tshark binary path |
| `PROTO_AUDIT_PCAP` | `--pcap` | PCAP file for tshark dissection |
| `PROTO_AUDIT_ETHERPARSE_SRC` | `--etherparse-src` | etherparse crate source tree |
| `PROTO_AUDIT_MAPPINGS_DIR` | `--mappings-dir` | Override directory for TOML mapping files |

## Building & Testing

```bash
# Nix build (recommended — wrapped with all source paths)
nix build .#proto-audit

# Raw binary (no env var defaults)
nix build .#proto-audit-bin

# Run tests (122 unit tests)
nix develop --command cargo test

# Run with custom PYTHONPATH for local Scapy development
PYTHONPATH=~/Downloads/scapy nix run .#proto-audit -- matrix
```

### Nix Outputs

| Output | Description |
|---|---|
| `.#proto-audit` | `writeShellApplication` wrapper with all `PROTO_AUDIT_*` env vars set |
| `.#proto-audit-bin` | Raw Rust binary without env var defaults |
| `.#proto-audit-report` | Cached derivation producing `matrix.txt`, `findings.txt`, `audit.json` |

## Type Mapping System

Each extractor's type inference is driven by TOML mapping files in `mappings/`:

| File | Direction | Purpose |
|---|---|---|
| `kernel.toml` | Source → IR | C type → bit width/endianness, field name → IR type overrides, embedded struct sizes |
| `scapy.toml` | Source → IR | Scapy field class → IR type, endian prefixes, name-pattern fallbacks |
| `tshark.toml` | Source → IR | tshark field name patterns → IR type, blocklist suffixes |
| `etherparse.toml` | Source → IR | Rust type → wire bit width, implicit fields, flag bit offsets |
| `etherparse_gen.toml` | IR → Source | IR type+size → Rust type, newtypes, derives, skip fields |
| `scapy_gen.toml` | IR → Source | IR type+size → Scapy field class, name overrides, LE prefixes |

Mappings are **embedded** in the binary via `include_str!()`, so the tool
works without external files. To override, set `PROTO_AUDIT_MAPPINGS_DIR`
to a directory containing replacement TOML files.

To add a new kernel C type or correct a field classification, edit the
appropriate TOML file — no Rust code changes needed. Each override entry
includes a `reason` field documenting the rationale.

## Project Layout

```
samples/proto_audit/
  src/
    main.rs              CLI (8 commands, SourcePaths, try_extract)
    ir.rs                IR types: ProtocolDef, FieldDef, AuditResult
    name_mapping.rs      113-protocol canonical name table (5 sources)
    type_mapping.rs      TOML loading + type inference accessors
    comparator.rs        Cross-source field matching engine
    report.rs            Text/JSON output formatting
    generator.rs         IR → C/Rust/Python code generation
    extractors/
      mod.rs             Module index
      kernel.rs          Linux kernel C struct parser
      scapy.rs           Scapy JSON consumer
      tshark.rs          tshark PDML XML parser
      etherparse.rs      etherparse Rust struct parser
      xdp2.rs            XDP2 proto_def metadata extractor
    test_data.rs         Embedded test fixtures
    roundtrip_tests.rs   Roundtrip golden-output tests
  helpers/
    scapy_dump.py        Python helper for Scapy introspection
  mappings/
    kernel.toml          Kernel C type → IR mappings
    scapy.toml           Scapy field class → IR mappings
    tshark.toml          tshark field pattern → IR mappings
    etherparse.toml      etherparse Rust type → IR mappings
    etherparse_gen.toml  IR → etherparse Rust type mappings (generation)
    scapy_gen.toml       IR → Scapy field class mappings (generation)
  docs/
    ir-format.md         IR schema reference (types, JSON, code gen)
    architecture.md      System overview, component diagram, extractors
    adding-a-source.md   Step-by-step guide (etherparse worked example)
    field-matching.md    Structural vs semantic agreement, audit algorithm
    status.md            Iteration history, known issues
```

## Documentation

- [IR Format Reference](docs/ir-format.md) — complete IR schema, JSON examples, code generation mappings
- [Architecture](docs/architecture.md) — extractors, type mapping system, report pipeline, component diagram
- [Adding a Source](docs/adding-a-source.md) — step-by-step guide using etherparse as worked example
- [Field Matching](docs/field-matching.md) — structural vs semantic agreement, audit algorithm, report interpretation
- [Status](docs/status.md) — iteration history, expected impact, known issues

## Project Status

- [x] IR core types and name mapping (113 protocols)
- [x] Five extractors (kernel, scapy, tshark, xdp2, etherparse)
- [x] Extensible TOML-based type mapping system (6 mapping files)
- [x] Comparison engine (structural + semantic matching, pairwise)
- [x] Report generation (matrix, findings, audit — text and JSON)
- [x] Code generation from IR (C headers, etherparse Rust, Scapy Python)
- [x] Comprehensive Scapy coverage (109/113 protocols, 27 new contrib modules)
- [x] 122 unit tests (roundtrip, cross-source, TOML validation)
- [x] Etherparse source (5th source, 9 protocols, cross-language Rust validation)
- [x] "Adding a Source" guide (`docs/adding-a-source.md`)
- [x] Nix integration with cached report derivation
