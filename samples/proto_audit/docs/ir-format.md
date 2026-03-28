# Intermediate Representation (IR) Format

proto-audit normalizes protocol definitions from all six sources (XDP2,
Linux kernel, Scapy, tshark, etherparse, libpcap) into a common IR defined
in `src/ir.rs`. This document is the authoritative reference for the IR
schema.

The IR is also positioned as a candidate for a universal machine-readable
protocol header format — a gap that the IETF has never filled. See
[IR as Standard](ir-as-standard.md) for the rationale and evidence.

All IR types implement `Serialize` and `Deserialize` via serde. The
canonical serialization is JSON, produced by any command with `--json`.

## ProtocolDef

Top-level protocol definition. One per protocol per extraction.

```rust
struct ProtocolDef {
    name: String,                              // Canonical name: "IPv4", "TCP", "Ethernet"
    min_header_bits: u32,                      // Minimum header size in bits
    is_variable_length: bool,                  // Can header exceed minimum? (options, TLVs)
    fields: Vec<FieldDef>,                     // Ordered by bit offset
    dispatch_field: Option<String>,            // Field carrying next-protocol ID (None for leaf)
    dispatch_table: Vec<DispatchEntry>,        // Next-protocol value mappings
    identifiers: BTreeMap<String, Vec<u32>>,   // How parent protocols identify this one
    sources: BTreeMap<String, SourceInfo>,      // Per-source extraction metadata
}
```

### JSON example (abbreviated)

```json
{
  "name": "IPv4",
  "min_header_bits": 160,
  "is_variable_length": true,
  "fields": [ ... ],
  "dispatch_field": "protocol",
  "dispatch_table": [
    { "value": 6, "protocol": "TCP", "sources": ["kernel", "scapy"] }
  ],
  "identifiers": { "ethertype": [2048] },
  "sources": {
    "kernel": { "present": true, "source_name": "iphdr", "field_count": 12, ... },
    "scapy":  { "present": true, "source_name": "IP",    "field_count": 13, ... }
  }
}
```

## FieldDef

A single protocol header field. Fields are ordered by `offset_bits` within
their parent `ProtocolDef`.

```rust
struct FieldDef {
    name: String,                          // Canonical field name
    offset_bits: u32,                      // Bit offset from protocol header start
    size_bits: u32,                        // Field width in bits
    field_type: FieldType,                 // Semantic type classification
    endian: Endian,                        // Byte order
    description: String,                   // Human-readable description
    is_dispatch: bool,                     // True if this field carries next-protocol ID
    is_length: bool,                       // True if this field controls variable header length
    length_multiplier: Option<u32>,        // actual_bytes = field_value * multiplier
    source_names: BTreeMap<String, String>, // How each source names this field
    default_value: Option<String>,         // Default from source (e.g., "4", "0x0800")
    flag_names: Option<Vec<String>>,       // Names for individual flag bits
}
```

### Field identification

Fields are matched across sources by **(offset_bits, size_bits)**, not by
name. This is because names vary across sources: kernel's `saddr`, Scapy's
`src`, tshark's `ip.src`, and etherparse's `source` all refer to the same
32-bit field at offset 96.

The `source_names` map preserves each source's original naming for
traceability.

### Dispatch and length roles

- **`is_dispatch`**: Marks the field used to determine the next protocol
  layer. For IPv4, this is `protocol` (offset 72, 8 bits). The
  `dispatch_table` on the parent `ProtocolDef` maps field values to
  protocol names.

- **`is_length`**: Marks the field that determines variable header length.
  For IPv4, this is `ihl` (offset 4, 4 bits) with `length_multiplier: 4`
  meaning `actual_header_bytes = ihl_value * 4`.

## FieldType

Semantic classification of a field's purpose. The type does not affect
structural matching (which uses offset + size only) but is compared for
semantic agreement.

```rust
enum FieldType {
    Uint,       // Unsigned integer (counters, lengths, generic values)
    Sint,       // Signed integer
    Bytes,      // Raw byte sequence (opaque payload)
    Ipv4Addr,   // IPv4 address (32 bits)
    Ipv6Addr,   // IPv6 address (128 bits)
    MacAddr,    // MAC address (48 bits)
    Flags,      // Individual bit flags (DF, MF, SYN, ACK, etc.)
    Enum,       // Enumerated value from a closed registry (EtherType, IP protocol)
    Pad,        // Reserved / padding (should be zero on wire)
}
```

### Enum vs Uint

The distinction between `Enum` and `Uint` is semantic: both are unsigned
integers on the wire. `Enum` means the field selects from a closed,
IANA-registered set (EtherType, IP protocol number, ICMP type). `Uint`
means the field is an open namespace or a numeric value (port numbers,
sequence numbers, lengths).

This distinction matters because:
- Scapy uses `ShortEnumField` for ports (has a lookup table) but we
  classify ports as `Uint` since they are an open namespace
- Kernel headers use `__be16` for both EtherType and port fields;
  field-name overrides in `mappings/kernel.toml` disambiguate

## Endian

Byte order annotation. Only meaningful for multi-byte fields.

```rust
enum Endian {
    Big,     // Network byte order (most network protocols)
    Little,  // Little-endian (Netlink, USB, some L2 protocols)
    Na,      // Not applicable: sub-byte or single-byte field
}
```

Rules applied by extractors:
- Fields <= 8 bits: always `Na`
- Array fields (MAC, IPv4/IPv6 addresses): checked against
  `array_endian_overrides` in TOML
- Otherwise: inferred from C type prefix (`__be` → Big, `__le` → Little),
  Scapy class prefix (`LE` → Little), or default Big for network protocols

## DispatchEntry

Maps a dispatch field value to a next-layer protocol.

```rust
struct DispatchEntry {
    value: u32,           // Field value (e.g., 0x0800 for IPv4, 6 for TCP)
    protocol: String,     // Target protocol canonical name
    sources: Vec<String>, // Which sources define this binding
}
```

## SourceInfo

Metadata about one source's definition of a protocol.

```rust
struct SourceInfo {
    present: bool,                   // Does this source define the protocol?
    file_path: Option<String>,       // Path to the source file
    source_name: String,             // Source-specific name ("iphdr", "IP", "ip")
    field_count: u32,                // Number of fields extracted
    min_header_bytes: u32,           // Minimum header size in bytes
    notes: Vec<String>,              // Additional context
}
```

A source may be `present: true` with `field_count: 0`. This happens for
XDP2, which references protocols (via kernel struct `sizeof()`) but does
not define fields directly. In the matrix output, these appear as `0*`.

## Comparison Types

These types are produced by the comparator, not by individual extractors.

### AuditResult

Overall comparison result for a protocol across all available sources.

```rust
struct AuditResult {
    protocol: String,
    sources_present: Vec<String>,               // Sources that have a definition
    sources_missing: Vec<String>,               // Sources that lack a definition
    field_comparisons: Vec<FieldComparison>,     // Per-field cross-source comparison
    total_fields: u32,                           // Union of all fields across sources
    fields_agree: u32,                           // Full agreement (structural + semantic)
    fields_type_differ: u32,                     // Structural match, type/endian differ
    fields_mismatch: u32,                        // Structural disagreement (splits)
    fields_missing: u32,                         // Present in some sources, absent in others
}
```

### FieldComparison

Cross-source comparison result for a single field slot (identified by
offset + size).

```rust
struct FieldComparison {
    name: String,                       // Canonical field name (from first source)
    offset_bits: u32,                   // Bit offset
    size_bits: u32,                     // Bit width
    sources_agree: Vec<String>,         // Full semantic agreement
    sources_structural: Vec<String>,    // Layout match (offset + size only)
    mismatches: Vec<FieldMismatch>,     // Specific disagreements
}
```

### FieldMismatch

A specific disagreement between sources for a field.

```rust
struct FieldMismatch {
    source: String,    // Source with the difference
    field: String,     // Which aspect differs
    expected: String,  // Value from the consensus/first source
    actual: String,    // Value from this source
}
```

## Serialization

All IR types use serde with these conventions:

- Default values are omitted from JSON output (`skip_serializing_if`)
- `Option<T>` fields serialize as `null` when `None`
- `BTreeMap` produces sorted JSON keys for deterministic output
- `Vec<T>` serializes as JSON arrays
- Enums serialize as their variant name (e.g., `"Uint"`, `"Big"`)

### Producing JSON

```bash
# Single protocol from one source
nix run .#proto-audit -- extract --source kernel --proto IPv4 --json

# Full audit across all sources
nix run .#proto-audit -- audit --json

# Coverage matrix
nix run .#proto-audit -- matrix --json

# Cross-source findings
nix run .#proto-audit -- findings --json
```

### Consuming JSON

The IR is designed for machine consumption. Example with `jq`:

```bash
# Count fields with full cross-source agreement
nix run .#proto-audit -- audit --json | jq '.[] | select(.fields_agree > 0) | .protocol'

# Find protocols with structural disagreements
nix run .#proto-audit -- audit --json | jq '.[] | select(.fields_mismatch > 0)'
```

## Code Generation from IR

See [Code Generation](code-generation.md) for full details on the three
generator targets (C, etherparse, Scapy), their TOML mapping schemas,
and the reverse type mapping pipeline.
