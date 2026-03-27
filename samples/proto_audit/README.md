# proto-audit: Multi-Source Protocol Definition Audit & Generation

Compares protocol header definitions across five authoritative sources —
XDP2, Linux kernel UAPI headers, Scapy, tshark, and etherparse — to find
layout disagreements, coverage gaps, and type annotation differences.

Supports 77 protocols from Ethernet through tunneling (GRE, VXLAN, Geneve,
MPLS), security (ESP, AH, MACsec), management (LLDP, PTP, IGMP), Bluetooth
(HCI variants, L2CAP), industrial (EtherCAT, PROFINET, CAN/CAN_FD/CAN_XL),
routing (OSPF, BGP, RIP, ISIS, EIGRP), redundancy (VRRP, HSRP),
and legacy (IPX, AppleTalk, X.25, ATM).
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

# Full cached report (all formats)
nix build .#proto-audit-report
cat result/matrix.txt
cat result/findings.txt
```

## Commands

| Command | Description |
|---|---|
| `list` | List all 77 known protocols |
| `extract --source S --proto P` | Extract one protocol from one source |
| `compare --proto P` | Compare a protocol across all sources |
| `audit [--protos P1,P2]` | Audit all (or specific) protocols |
| `matrix` | Source x protocol coverage matrix |
| `findings` | Detailed cross-source disagreements |
| `scan` | Scan XDP2 proto_defs directory |
| `generate --proto P` | Generate C header from IR |

All commands accept `--json` for machine-readable output.

## Building & Testing

```bash
# Nix build (recommended — wrapped with all source paths)
nix build .#proto-audit

# Raw binary (no env var defaults)
nix build .#proto-audit-bin

# Run tests (109 unit tests)
nix develop --command cargo test
```

## Type Mapping System

Each extractor's type inference is driven by TOML mapping files in `mappings/`:

| File | Purpose |
|---|---|
| `mappings/kernel.toml` | C type → bit width/endianness, field name → IR type overrides |
| `mappings/scapy.toml` | Scapy field class → IR type, endian prefixes, name-pattern fallbacks |
| `mappings/tshark.toml` | tshark field name patterns → IR type, blocklist suffixes |
| `mappings/etherparse.toml` | Rust type → wire bit width, implicit fields, flag bit offsets |

Mappings are **embedded** in the binary via `include_str!()`, so the tool works
without external files. To override, set `PROTO_AUDIT_MAPPINGS_DIR` to a
directory containing replacement TOML files.

To add a new kernel C type or correct a field classification, edit the
appropriate TOML file — no Rust code changes needed. Each override entry
includes a `reason` field documenting the rationale.

## Documentation

- [Architecture](docs/architecture.md) — extractors, IR, type mapping system, report pipeline
- [Adding a Source](docs/adding-a-source.md) — step-by-step guide using etherparse as worked example
- [Field Matching](docs/field-matching.md) — structural vs semantic agreement, audit algorithm, report interpretation
- [Status](docs/status.md) — iteration history, expected impact, known issues

## Project Status

- [x] IR core types and name mapping (77 protocols)
- [x] Extractors (kernel, scapy, tshark, xdp2, etherparse)
- [x] Extensible TOML-based type mapping system (`mappings/*.toml`)
- [x] Comparison engine (structural + semantic matching, pairwise)
- [x] Report generation (matrix, findings, audit)
- [x] C header generation from IR
- [x] Roundtrip & cross-mapping tests for TOML translation layer
- [x] Etherparse source (5th source, 9 protocols, cross-language Rust validation)
- [x] "Adding a Source" guide (`docs/adding-a-source.md`)
- [x] Nix integration with cached report derivation
