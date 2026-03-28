# Architecture

## Overview

proto-audit extracts protocol definitions from six independent sources,
normalizes them into a common IR, then compares, reports, and generates code.

```
                    ┌──────────────────────────────┐
                    │     Rust: proto-audit CLI     │
                    │  (clap, serde, roxmltree)     │
                    └──────┬───────────────────────┘
                           │
       ┌───────────┬───────┼───────┬───────────┬───────────┐
       │           │       │       │           │           │
┌──────▼──────┐ ┌──▼───────▼──┐ ┌──▼──────┐ ┌──▼──────────┐ ┌──────────┐
│  XDP2       │ │  Kernel     │ │ Scapy   │ │ etherparse  │ │ libpcap  │
│  Extractor  │ │  Extractor  │ │ Extract.│ │ Extractor   │ │ Extract. │
│ (regex C)   │ │ (regex C)   │ │ (JSON)  │ │ (regex Rust)│ │ (C/TOML) │
└─────────────┘ └─────────────┘ └────┬────┘ └─────────────┘ └──────────┘
       │               │             │             │               │
       │        ┌──────▼──────┐  ┌───▼────────┐   │               │
       │        │  Type       │  │  tshark    │   │               │
┌──────▼──────┐ │  Mappings   │  │  Extractor │   │               │
│  Python     │ │  (TOML)     │  │ (PDML XML) │   │               │
│  helper     │ └─────────────┘  └────────────┘   │               │
└──────┬──────┘                                    │               │
       │          ═══ MAPPING IN (Extraction) ═══  │               │
       └───────────────────┬───────────────────────┘───────────────┘
                           ▼
                  ┌─────────────────┐
                  │       IR        │
                  │  (ProtocolDef)  │
                  └────────┬────────┘
                           │
              ┌────────────┼────────────┐
              ▼            ▼            ▼
    ┌─────────────┐ ┌───────────┐ ┌───────────┐
    │ Comparator  │ │  Report   │ │ Generator │
    │ (field      │ │ (text /   │ │ (IR → C / │
    │  matching)  │ │  JSON)    │ │Rust/Py/PCAP│
    └─────────────┘ └───────────┘ └───────────┘
                                  ═ MAPPING OUT ═
                                  ═ (Generation)═
```

See [Mapping Pipeline](mapping-pipeline.md) for a detailed walkthrough of
both directions, per-source fidelity tables, and a worked IPv4 example.

## Data Flow

1. **Extraction**: Each extractor reads its source format and produces a
   `ProtocolDef` in the IR. Type inference is driven by per-source TOML
   mapping files. See [Extractors](extractors.md) for per-source details.

2. **Comparison**: The comparator takes multiple `ProtocolDef` instances
   (one per source) and matches fields by (offset, size). It produces
   `AuditResult` with structural and semantic agreement metrics.

3. **Reporting**: The report module (`src/report/`) formats `AuditResult`
   as text tables (matrix, findings, audit) or JSON for machine consumption.

4. **Generation**: The generator converts a `ProtocolDef` into source code
   for C, Rust, or Python, or into wire bytes as PCAP. See [Code Generation](code-generation.md).

5. **Validation**: The `validate` command generates a PCAP from the IR,
   feeds it to tshark, extracts the result back to IR, and compares — a
   true round-trip through wire bytes. See [Round-Trip Validation](validation.md).

## Sources

| Source | Format | Access | Protocols |
|---|---|---|---|
| **XDP2** | C headers (`xdp2_proto_def` structs) | Local repo parse | ~70 (metadata only, no fields) |
| **Linux kernel** | C structs (UAPI headers) | Nix-pinned source tree | ~48 with field definitions |
| **Scapy** | Python classes (`fields_desc`) | Runtime introspection via JSON | 109 protocols |
| **tshark** | PDML XML (`<proto>`/`<field>`) | `tshark -T pdml` subprocess | ~80 with PCAP packets |
| **etherparse** | Rust structs (`pub struct`) | Nix-pinned source (regex parse) | 9 core protocols |
| **libpcap** | C structs + BPF gencode offsets | Nix-pinned source (C parse + TOML) | ~20 protocols |

## Intermediate Representation

All sources are normalized into a canonical IR (`ProtocolDef` in `src/ir.rs`).
See [IR Format Reference](ir-format.md) for the complete schema.

Key design choices:
- **Fields indexed by bit offset**: enables cross-source matching without name normalization
- **Semantic types** (`Uint`, `Enum`, `Ipv4Addr`, `Flags`, etc.): separate from structural layout
- **Per-source names preserved**: `source_names` map tracks original naming for traceability
- **Dispatch and length roles annotated**: enables protocol graph traversal and code generation

## Type Mapping System

`src/type_mapping/` loads TOML mapping files from `mappings/` that define
how each source's type system translates to (and from) the IR.

### Extraction Mappings (Source → IR)

| File | Purpose |
|---|---|
| `kernel.toml` | C type → bit width, endianness; field name → IR type overrides; embedded struct sizes |
| `scapy.toml` | Scapy field class → IR type; name-pattern fallbacks |
| `tshark.toml` | tshark field name patterns → IR type; blocklist suffixes |
| `etherparse.toml` | Rust type → wire bit width; implicit fields, flag bit offsets |
| `libpcap.toml` | libpcap C type/macro → IR type; BPF gencode struct mappings |

### Generation Mappings (IR → Source)

| File | Purpose |
|---|---|
| `etherparse_gen.toml` | IR type+size → Rust type; newtypes, derives, skip fields |
| `scapy_gen.toml` | IR type+size → Scapy field class; name overrides, LE prefixes |

### How it works

Mappings are **embedded** in the binary via `include_str!()`, so the tool
works without external files. For extensibility, override with:
- `--mappings-dir <path>` CLI flag
- `PROTO_AUDIT_MAPPINGS_DIR` environment variable

No Rust code changes needed for type mapping extensions — edit the
appropriate `mappings/*.toml` file.

## Name Mapping

`src/name_mapping/` maintains a table of protocols with canonical names
and per-source identifiers (e.g., IPv4 maps to kernel's `iphdr`, Scapy's
`IP`, tshark's `ip`, etherparse's `Ipv4Header`, libpcap's `ipv4`). This
enables cross-source correlation without relying on naming conventions.

## Report Outputs

The report module (`src/report/`) produces:

| Format | Command | Description |
|---|---|---|
| Text matrix | `matrix` | Source x protocol coverage matrix with field counts and agreement stats |
| Text findings | `findings` | Cross-source disagreements, coverage gaps, annotations |
| Text audit | `audit` | Per-protocol detailed field comparison tables |
| JSON | any `--json` | Machine-readable output for all commands |

## Further Reading

- [Extractors](extractors.md) — per-source extractor details
- [Code Generation](code-generation.md) — generator targets and TOML schemas
- [Mapping Pipeline](mapping-pipeline.md) — bidirectional pipeline walkthrough with fidelity tables
- [IR as Standard](ir-as-standard.md) — positioning the IR as a universal protocol header format
- [Round-Trip Validation](validation.md) — IR → wire → tshark → IR round-trip verification
- [Nix Packaging](nix-packaging.md) — build, source pinning, flake outputs
