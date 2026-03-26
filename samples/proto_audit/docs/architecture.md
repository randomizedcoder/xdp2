# Architecture

## Overview

proto-audit extracts protocol definitions from four independent sources,
normalizes them into a common IR, then compares and reports on agreement.

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
           │               │               │
           │        ┌──────▼──────┐  tshark subprocess
           │        │  Type       │        │
    ┌──────▼──────┐ │  Mappings   │ ┌──────▼──────┐
    │  Scapy      │ │  (TOML)     │ │  Python     │
    │  Extractor  │ └─────────────┘ │  helper     │
    └─────────────┘                 └─────────────┘
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

## Sources

| Source | Format | Access |
|---|---|---|
| **XDP2** | C headers (`xdp2_proto_def` structs) | Local repo parse |
| **Linux kernel** | C structs (UAPI headers) | Nix-pinned source |
| **Scapy** | Python classes (`fields_desc`) | Runtime introspection via JSON |
| **tshark** | PDML XML (`<proto>`/`<field>`) | `tshark -T pdml` subprocess |

## Intermediate Representation

All sources are normalized into a canonical IR (`ProtocolDef` in `src/ir.rs`) with:

- **Fields**: name, bit offset, bit size, semantic type, endianness, dispatch/length roles
- **Dispatch tables**: maps field values to next protocols
- **Source names**: preserves each source's original naming (e.g., kernel's `saddr` vs scapy's `src`)
- **Cross-source metadata**: per-source file paths, field counts, notes

## Type Mapping System

`src/type_mapping.rs` loads TOML mapping files from `mappings/` that define
how each source's type system translates to the IR. This replaces hardcoded
type inference logic with an extensible, documented configuration.

### Mapping files

| File | Purpose |
|---|---|
| `mappings/kernel.toml` | C type → bit width, endianness; field name → IR type overrides |
| `mappings/scapy.toml` | Scapy field class → IR type; name-pattern fallbacks |
| `mappings/tshark.toml` | tshark field name patterns → IR type; blocklist suffixes |

### How it works

Mappings are **embedded** in the binary via `include_str!()`, so the tool
works without external files. For extensibility, override with:
- `--mappings-dir <path>` CLI flag
- `PROTO_AUDIT_MAPPINGS_DIR` environment variable

The TOML format supports native comments, so each mapping can document its
rationale inline:

```toml
[field_type_overrides.protocol]
type = "Enum"
reason = "IPv4 protocol number (IANA registry)"
```

### Extending mappings

To add a new kernel C type, edit `mappings/kernel.toml`:
```toml
[type_bits]
__be128 = 128

[type_endian]
"prefix:__be" = "Big"  # already covers __be128
```

To add a new Scapy field class, edit `mappings/scapy.toml`:
```toml
[field_types]
NewEnumField = "Enum"
```

No Rust code changes needed for type mapping extensions.

## Extractors

### Kernel (`src/extractors/kernel.rs`)

Parses C struct definitions from Linux UAPI headers. Handles:
- Regular fields, bitfields, arrays
- `#if defined(__BIG_ENDIAN_BITFIELD)` conditional sections (picks network byte order)
- `__struct_group()` macro unwrapping
- Inline `/* ... */` comment stripping
- `#if 0` dead-code block skipping

Type inference uses `mappings/kernel.toml`:
- `type_bits`: C type → bit width
- `type_endian`: C type prefix/exact → endianness (e.g., `__sum16` → Big)
- `field_type_overrides`: field name → semantic type (e.g., `protocol` → Enum)
- `array_endian_overrides`: C type + array size → endianness (e.g., `unsigned char[6]` → Big for MAC)

### Scapy (`src/extractors/scapy.rs`)

Consumes JSON output from `helpers/scapy_dump.py`, which introspects Scapy's
`fields_desc` at runtime. The helper imports contrib modules
(`scapy.contrib.igmp`, `scapy.contrib.geneve`, `scapy.contrib.macsec`,
`scapy.contrib.lldp`, `scapy.contrib.erspan`, `scapy.contrib.nsh`,
`scapy.contrib.hsr`) and uses recursive subclass search for full coverage.

Type inference uses `mappings/scapy.toml`:
- `field_types`: class name → IR type (e.g., `IPField` → Ipv4Addr)
- `endian_prefixes`: class name prefix → endianness (e.g., `LE` → Little)
- `name_patterns`: field name substring fallback (e.g., `flags` → Flags)

Note: `ShortEnumField` is deliberately **not** mapped to Enum — it's used
for TCP/UDP ports, which are an open namespace, not a closed enumeration.

### tshark (`src/extractors/tshark.rs`)

Runs `tshark -T pdml` on a test PCAP and parses the XML output. Each
`<proto>` element becomes a protocol, each `<field>` with `pos` and `size`
attributes becomes a field definition.

Type inference uses `mappings/tshark.toml`:
- `suffix_types`: unconditional suffix → type (e.g., `.src_hw` → MacAddr)
- `suffix_types_by_size`: suffix + bit width → type (e.g., `.src` at 32 bits → Ipv4Addr)
- `contains_types`: substring → type (e.g., `flags` → Flags)
- `enum_patterns`: substring + max bits → Enum (e.g., `proto` at ≤16 bits)
- `blocklist_suffixes`: filtered out (`.payload`, `.padding`, `.trailer`, etc.)

### XDP2 (`src/extractors/xdp2.rs`)

Scans XDP2's `proto_defs/` directory for `xdp2_proto_def` struct
initializations. Extracts kernel struct references, dispatch table entries,
and length field metadata.

## Name Mapping

`src/name_mapping.rs` maintains a table of 41 protocols with canonical names
and per-source identifiers (XDP2 function name, kernel struct, Scapy class,
tshark filter). This enables cross-source correlation without relying on
naming conventions.

## Report Outputs

The report module (`src/report.rs`) produces:

| Format | Command | Description |
|---|---|---|
| `matrix.txt` | `matrix` | Source x protocol coverage matrix with field counts |
| `findings.txt` | `findings` | Cross-source disagreements, coverage gaps, annotations |
| `audit.txt` | `audit` | Per-protocol detailed field comparison |
| `audit.json` | `audit --json` | Machine-readable audit results |

## Generator

`src/generator.rs` can produce new XDP2 `proto_def` C headers from the IR,
using templates in `templates/`. This enables auto-generating protocol support
from cross-source consensus.
