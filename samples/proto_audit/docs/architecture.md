# Architecture

## Overview

proto-audit extracts protocol definitions from eight independent sources,
normalizes them into a common IR, then compares, reports, and generates code.

```
                    ┌──────────────────────────────┐
                    │     Rust: proto-audit CLI     │
                    │  (clap, serde, roxmltree)     │
                    └──────┬───────────────────────┘
                           │
       ┌───────────┬───────┼───────┬───────────┬───────────┬────────────┬───────────┐
       │           │       │       │           │           │            │           │
┌──────▼──────┐ ┌──▼───────▼──┐ ┌──▼──────┐ ┌──▼──────────┐ ┌──────────┐ ┌─────────┐ ┌──────────┐
│  XDP2       │ │  Kernel     │ │ Scapy   │ │ etherparse  │ │ libpcap  │ │ Kaitai  │ │ Suricata │
│  Extractor  │ │  Extractor  │ │ Extract.│ │ Extractor   │ │ Extract. │ │ Extract.│ │ Extract. │
│ (regex C)   │ │ (regex C)   │ │ (JSON)  │ │ (regex Rust)│ │ (C/TOML) │ │ (.ksy)  │ │(regex Rs)│
└─────────────┘ └─────────────┘ └────┬────┘ └─────────────┘ └──────────┘ └─────────┘ └──────────┘
       │               │             │             │               │          │           │
       │        ┌──────▼──────┐  ┌───▼────────┐   │               │          │           │
       │        │  Type       │  │  tshark    │   │               │          │           │
┌──────▼──────┐ │  Mappings   │  │  Extractor │   │               │          │           │
│  Python     │ │  (TOML)     │  │ (PDML XML) │   │               │          │           │
│  helper     │ └─────────────┘  └────────────┘   │               │          │           │
└──────┬──────┘                                    │               │          │           │
       │          ═══ MAPPING IN (Extraction) ═══  │               │          │           │
       └───────────────────┬───────────────────────┘───────────────┘──────────┘───────────┘
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

Note: etherparse and libpcap sources are patched with per-protocol overlay
structs before extraction. See [Source Patching](patching.md) for details.

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
| **tshark** | PDML XML (`<proto>`/`<field>`) | `tshark -T pdml` subprocess + corpus + registry | 255 from corpus, 1872 from registry |
| **etherparse** | Rust structs (`pub struct`) | Nix-pinned + 31 overlay patches | 9 core + 31 overlay |
| **libpcap** | C structs + BPF gencode offsets | Nix-pinned + overlay patches | ~6 native + overlays |
| **Kaitai Struct** | Format specification files (.ksy) | Nix-pinned .ksy files | ~20 protocols (12 curated) |
| **Suricata** | Rust app-layer parser structs | Nix-pinned source, regex Rust parse | ~15 protocols (20 curated) |

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
`IP`, tshark's `ip`, etherparse's `Ipv4Header`, libpcap's `ipv4`,
Kaitai's `ipv4_packet`, Suricata's `DnsHeader`). This enables cross-source
correlation without relying on naming conventions.

## Report Outputs

The report module (`src/report/`) produces:

| Format | Command | Description |
|---|---|---|
| Text matrix | `matrix` | Source x protocol coverage matrix with field counts and agreement stats |
| Text findings | `findings` | Cross-source disagreements, coverage gaps, annotations |
| Text audit | `audit` | Per-protocol detailed field comparison tables |
| JSON | any `--json` | Machine-readable output for all commands |

## Further Reading

- [Source Patching](patching.md) — overlay patches, fine-grained analysis, upstream PR workflow
- [Extractors](extractors.md) — per-source extractor details
- [Code Generation](code-generation.md) — generator targets and TOML schemas
- [Mapping Pipeline](mapping-pipeline.md) — bidirectional pipeline walkthrough with fidelity tables
- [IR as Standard](ir-as-standard.md) — positioning the IR as a universal protocol header format
- [Round-Trip Validation](validation.md) — IR → wire → tshark → IR round-trip verification
- [Nix Packaging](nix-packaging.md) — build, source pinning, flake outputs
