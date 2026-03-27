# Architecture

## Overview

proto-audit extracts protocol definitions from five independent sources,
normalizes them into a common IR, then compares, reports, and generates code.

```
                    ┌──────────────────────────────┐
                    │     Rust: proto-audit CLI     │
                    │  (clap, serde, roxmltree)     │
                    └──────┬───────────────────────┘
                           │
       ┌───────────┬───────┼───────────┬───────────┐
       │           │       │           │           │
┌──────▼──────┐ ┌──▼───────▼──┐ ┌──────▼──────┐ ┌──▼──────────┐
│  XDP2       │ │  Kernel     │ │  tshark     │ │ etherparse  │
│  Extractor  │ │  Extractor  │ │  Extractor  │ │ Extractor   │
│ (regex C)   │ │ (regex C)   │ │ (PDML XML)  │ │ (regex Rust)│
└─────────────┘ └─────────────┘ └──────┬──────┘ └─────────────┘
       │               │               │               │
       │        ┌──────▼──────┐  tshark subprocess     │
       │        │  Type       │        │               │
┌──────▼──────┐ │  Mappings   │ ┌──────▼──────┐        │
│  Scapy      │ │  (TOML)     │ │  Python     │        │
│  Extractor  │ └─────────────┘ │  helper     │        │
└──────┬──────┘                 └─────────────┘        │
       │                                               │
       └───────────────────┬───────────────────────────┘
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
    │  matching)  │ │  JSON)    │ │ Rust / Py)│
    └─────────────┘ └───────────┘ └───────────┘
```

## Data Flow

1. **Extraction**: Each extractor reads its source format and produces a
   `ProtocolDef` in the IR. Type inference is driven by per-source TOML
   mapping files.

2. **Comparison**: The comparator takes multiple `ProtocolDef` instances
   (one per source) and matches fields by (offset, size). It produces
   `AuditResult` with structural and semantic agreement metrics.

3. **Reporting**: The report module formats `AuditResult` as text tables
   (matrix, findings, audit) or JSON for machine consumption.

4. **Generation**: The generator converts a `ProtocolDef` into source code
   for C (XDP2 proto_def headers), Rust (etherparse structs), or Python
   (Scapy Packet classes). Reverse type mappings are in `*_gen.toml` files.

## Sources

| Source | Format | Access | Protocols |
|---|---|---|---|
| **XDP2** | C headers (`xdp2_proto_def` structs) | Local repo parse | ~70 (metadata only, no fields) |
| **Linux kernel** | C structs (UAPI headers) | Nix-pinned source tree | ~45 with field definitions |
| **Scapy** | Python classes (`fields_desc`) | Runtime introspection via JSON | 109 protocols |
| **tshark** | PDML XML (`<proto>`/`<field>`) | `tshark -T pdml` subprocess | ~80 with PCAP packets |
| **etherparse** | Rust structs (`pub struct`) | Nix-pinned source (regex parse) | 9 core protocols |

## Intermediate Representation

All sources are normalized into a canonical IR (`ProtocolDef` in `src/ir.rs`).
See [IR Format Reference](ir-format.md) for the complete schema.

Key design choices:
- **Fields indexed by bit offset**: enables cross-source matching without name normalization
- **Semantic types** (`Uint`, `Enum`, `Ipv4Addr`, `Flags`, etc.): separate from structural layout
- **Per-source names preserved**: `source_names` map tracks original naming for traceability
- **Dispatch and length roles annotated**: enables protocol graph traversal and code generation

## Type Mapping System

`src/type_mapping.rs` loads TOML mapping files from `mappings/` that define
how each source's type system translates to (and from) the IR.

### Extraction Mappings (Source → IR)

| File | Purpose |
|---|---|
| `kernel.toml` | C type → bit width, endianness; field name → IR type overrides; embedded struct sizes |
| `scapy.toml` | Scapy field class → IR type; name-pattern fallbacks |
| `tshark.toml` | tshark field name patterns → IR type; blocklist suffixes |
| `etherparse.toml` | Rust type → wire bit width; implicit fields, flag bit offsets |

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
- Embedded `struct X name;` fields via `[struct_sizes]` TOML table

Type inference uses `mappings/kernel.toml`:
- `type_bits`: C type → bit width (includes `__be16`, `__u8`, etc.)
- `type_endian`: C type prefix/exact → endianness (e.g., `__sum16` → Big)
- `field_type_overrides`: field name → semantic type (e.g., `protocol` → Enum)
- `array_endian_overrides`: C type + array size → endianness (e.g., `unsigned char[6]` → Big for MAC)
- `struct_sizes`: embedded struct name → bit width (e.g., `icmp6hdr` → 64)

### Scapy (`src/extractors/scapy.rs`)

Consumes JSON output from `helpers/scapy_dump.py`, which introspects Scapy's
`fields_desc` at runtime. The helper imports ~40 contrib modules covering
all 109 Scapy-mapped protocols, including custom modules for PBB, TRILL,
MPEG-TS, SRT, DSA/EDSA, BATMAN, CFM, NC-SI, FIP, MVRP, Netlink, IPX,
AppleTalk, X.25, ATM, iSCSI, NVMe, SCSI, and iSER.

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

### etherparse (`src/extractors/etherparse.rs`)

Parses Rust `pub struct` definitions from etherparse source files. Handles:
- Array fields (`[u8; 6]` for MAC addresses)
- Non-pub field filtering (ARP private fields skipped)
- Newtype wrappers mapped to wire bit widths via TOML
- Implicit wire fields (IPv4 version/IHL, IPv6 version, TCP data_offset/reserved)
- TCP flag reordering (struct order ≠ wire order)

Type inference uses `mappings/etherparse.toml`:
- `type_bits`: Rust type → wire bit width (including newtype wrappers)
- `field_type_overrides`: field name → semantic type
- `implicit_fields`: start_offset_bits + gaps for missing wire fields
- `flag_bit_offsets`: field name → absolute wire bit position
- `array_endian_overrides`: Rust type + array size → endianness

Covers 9 protocols: Ethernet, VLAN, IPv4, IPv6, ARP, TCP, UDP, ICMPv4, ICMPv6.

See [Adding a Source](adding-a-source.md) for the complete guide using
etherparse as a worked example.

### XDP2 (`src/extractors/xdp2.rs`)

Scans XDP2's `proto_defs/` directory for `xdp2_proto_def` struct
initializations. Extracts:
- Variable name (e.g., `xdp2_parse_ipv4`)
- Display name from `.name` field
- Kernel struct reference (via `sizeof(struct ...)`)
- Dispatch function (`.ops.next_proto`) and length function (`.ops.len`)
- TLV vs regular protocol flag, overlay flag

XDP2 proto_defs don't define fields directly — they reference kernel structs.
The extractor yields metadata (`present: true`, `field_count: 0`), shown as
`0*` in the matrix. Field-level comparison uses the kernel extractor instead.

## Name Mapping

`src/name_mapping.rs` maintains a table of 113 protocols with canonical names
and per-source identifiers:

| Field | Example (IPv4) |
|---|---|
| `canonical` | `"IPv4"` |
| `xdp2` | `"xdp2_parse_ipv4"` |
| `kernel_struct` | `"iphdr"` |
| `kernel_header` | `"linux/ip.h"` |
| `scapy` | `"IP"` |
| `tshark` | `"ip"` |
| `etherparse_struct` | `"Ipv4Header"` |
| `etherparse_file` | `"etherparse/src/net/ipv4_header.rs"` |

This enables cross-source correlation without relying on naming conventions.
Lookup functions: `find_by_canonical()`, `find_by_xdp2_name()`,
`find_by_kernel_struct()`, `find_by_scapy_name()`, `find_by_tshark_name()`,
`find_by_etherparse_struct()`, `source_to_canonical_map()`.

## Report Outputs

The report module (`src/report.rs`) produces:

| Format | Command | Description |
|---|---|---|
| Text matrix | `matrix` | Source x protocol coverage matrix with field counts and agreement stats |
| Text findings | `findings` | Cross-source disagreements, coverage gaps, annotations |
| Text audit | `audit` | Per-protocol detailed field comparison tables |
| Text extract | `extract` | Single protocol from one source, field table |
| Text scan | `scan` | XDP2 proto_defs directory scan |
| JSON matrix | `matrix --json` | Machine-readable coverage matrix |
| JSON findings | `findings --json` | Machine-readable disagreements |
| JSON audit | `audit --json` | Machine-readable per-protocol audit results |

### Matrix Columns

| Column | Meaning |
|---|---|
| kernel/scapy/tshark/xdp2/etherparse | Number of fields extracted from this source |
| Agree | Fields where all present sources fully agree (structural + semantic) |
| TDiff | Fields with structural match but type/endian annotation differences |
| Split | Fields where sources disagree on boundaries (genuine structural difference) |
| Miss. | Fields present in some sources but absent in others |

## Generator

`src/generator.rs` converts `ProtocolDef` instances into source code for
three targets:

| Target | Function | Output |
|---|---|---|
| C | `generate_proto_def()` | XDP2 `proto_def` C header with parse node, dispatch, length |
| etherparse | `generate_etherparse()` | Rust struct with `#[derive(...)]` and `from_slice()` skeleton |
| Scapy | `generate_scapy()` | Python Packet class with `fields_desc` and `bind_layers` |

Generation uses reverse type mappings from `mappings/etherparse_gen.toml`
and `mappings/scapy_gen.toml`. See [IR Format Reference](ir-format.md)
for details on the generation TOML schemas.

## Scapy Helper

`helpers/scapy_dump.py` is a Python script that introspects Scapy Packet
classes at runtime:

```bash
python3 scapy_dump.py IP      # dump one protocol as JSON
python3 scapy_dump.py --list  # list all available Packet classes
```

Output JSON:
```json
{
  "name": "IP",
  "module": "scapy.layers.inet",
  "min_bytes": 20,
  "fields": [
    {"name": "version", "field_class": "BitField", "size_bits": 4, "default": "4"},
    ...
  ]
}
```

The helper imports ~40 Scapy contrib/layers modules to ensure full coverage.
19 of these are custom modules created for proto-audit (PBB, TRILL, MPEG-TS,
etc.) living in the local Scapy tree at `~/Downloads/scapy/scapy/contrib/`.

## Nix Packaging

### nix/proto-audit.nix

Rust package build using `rustPlatform.buildRustPackage`. The `cargoHash`
must be updated when `Cargo.lock` changes (set to `pkgs.lib.fakeHash`,
build, copy hash from error).

### nix/proto-audit-sources.nix

External source pinning and provisioning:

| Output | Source |
|---|---|
| `kernelSrc` | Linux 6.12 `include/` tree |
| `scapyPython` | Python 3.14 + scapy |
| `tshark` | wireshark-cli binary |
| `etherparseSrc` | GitHub-pinned etherparse crate source |

### Flake Outputs

| Output | Description |
|---|---|
| `proto-audit` | Shell wrapper setting all `PROTO_AUDIT_*` env vars |
| `proto-audit-bin` | Raw Rust binary (no env defaults) |
| `proto-audit-report` | Cached derivation producing report files |
