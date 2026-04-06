# IR as a Potential Standard Format

The IETF has never specified a machine-readable format for protocol header
definitions. proto-audit's IR is a candidate to fill that gap — not because
it was designed as a standard, but because it emerged from the practical
requirement of reconciling eight independent implementations of the same RFCs.

## The IETF Gap

RFCs describe protocol headers in prose and ASCII art diagrams. There is no
machine-readable equivalent — no schema language for "this protocol has a
4-bit version field at offset 0, followed by a 4-bit IHL field at offset 4."

The consequence: every codebase that needs to parse network packets
independently translates RFC prose into code. proto-audit has measured the
result across six such codebases:

- **207 protocols** modeled, **127** with extractable field definitions
- **38** protocols with 2+ external sources (cross-checkable)
- **22** field-granularity splits, **11** type-classification differences
- Only **75** of 127 auditable protocols achieve full cross-source agreement

These are not bugs. They are the natural result of independent
interpretation. A machine-readable standard would make most of them
unnecessary.

## What the IR Captures

The IR (`ProtocolDef` in `src/ir.rs`) captures four categories of
information about a protocol header:

### Structural (wire layout)

| Field | Purpose |
|-------|---------|
| `offset_bits` | Bit position from header start |
| `size_bits` | Field width in bits |
| `min_header_bits` | Minimum header size |
| `is_variable_length` | Whether header can exceed minimum (options, TLVs) |

These are sufficient to generate correct parsers and serializers for any
fixed-layout protocol header.

### Semantic (type classification)

| Field | Purpose |
|-------|---------|
| `field_type` | One of 9 types: Uint, Sint, Bytes, Ipv4Addr, Ipv6Addr, MacAddr, Flags, Enum, Pad |
| `endian` | Big, Little, or Na (sub-byte) |
| `is_dispatch` | Marks the next-protocol selector field |
| `is_length` | Marks the header-length field |
| `length_multiplier` | Scale factor for length fields (e.g., IPv4 IHL × 4) |

Semantic types enable code generators to select appropriate language-native
types (e.g., `Enum:8` → Rust's `u8` vs Scapy's `ByteEnumField`).

### Provenance (traceability)

| Field | Purpose |
|-------|---------|
| `source_names` | Per-source field name (kernel's `saddr`, Scapy's `src`, tshark's `ip.src`) |
| `sources` | Per-source metadata: file path, field count, notes |
| `default_value` | Source-provided default (e.g., IPv4 version = 4) |

Provenance allows round-tripping: a generated C header can use kernel-style
names while a generated Scapy class uses Scapy-style names, both from the
same IR.

### Protocol graph (layer binding)

| Field | Purpose |
|-------|---------|
| `dispatch_field` | Which field determines the next layer |
| `dispatch_table` | Value → protocol mappings (e.g., EtherType 0x0800 → IPv4) |
| `identifiers` | How parent protocols identify this one (e.g., `{"ethertype": [2048]}`) |

The dispatch mechanism is sufficient to construct a full protocol stack
graph from individual protocol definitions.

## What the IR Does NOT Capture

The IR was designed for fixed-layout protocol headers. Several areas are
acknowledged limitations:

- **Variable-length options and TLVs.** The IR has `is_variable_length` as a
  boolean flag but no schema for the variable portion. IPv4 options, TCP
  options, and TLV-based protocols (LLDP, RADIUS) need an extension.

- **Conditional fields.** ARP's address fields change size based on
  `ar_hln` and `ar_pln`. The IR cannot express "this field is 6 bytes when
  hardware type is Ethernet."

- **Checksum and encoding algorithms.** The IR marks checksum fields
  (`Uint` type) but does not specify which checksum algorithm applies.
  Similarly, ASN.1/BER-encoded protocols (SNMP, LDAP) are beyond scope.

- **Stateful protocols.** Text-based protocols (HTTP, SIP, SMTP) and
  encrypted protocols (TLS post-handshake, SSH) have no fixed wire layout
  to model.

These limitations are explicit design choices, not oversights. A future
standard could extend the IR with optional schemas for variable-length
regions, conditional logic, and checksum specifications.

## Empirical Evidence

proto-audit's own data serves as evidence that the IR is expressive enough
to be useful:

- **207 protocols modeled** across L2–L7, including tunneling, security,
  Bluetooth, InfiniBand, industrial/SCADA, and routing protocols.

- **Code generation round-trips** to three languages (C, Rust, Scapy)
  prove the IR captures enough information to produce compilable code.

- **Cross-source comparison** of 206 protocols demonstrates that the IR
  can represent all eight sources' definitions precisely enough to detect
  real disagreements (not just formatting differences).

- **TOML-driven extensibility**: 7 mapping files with 200+ entries were
  sufficient to map all eight sources without modifying the IR schema itself.

## Comparison with Prior Art

| Approach | Scope | Status | Difference from IR |
|----------|-------|--------|--------------------|
| **P4** | Programmable parser actions | Active standard | Defines *parsing behavior*, not *header structure*. P4 programs are imperative; the IR is declarative. |
| **NetPDL** | XML protocol description | Abandoned (~2008) | Similar goals but XML-based and never adopted. No active implementations. |
| **IETF CDDL** | Data modeling (RFC 8610) | Active RFC | Models *data structures* (CBOR/JSON), not *wire protocol headers*. No bit-offset concept. |
| **YANG** | Network config modeling | Active RFC | Models *configuration and state*, not *wire formats*. |
| **Kaitai Struct** | Binary format description | Active project | Closest match — declarative binary format description. Focused on file formats; less protocol-graph support. |

The IR is narrower than P4 (no parsing actions) and broader than YANG (wire
layout, not configuration). Its closest relative is Kaitai Struct, but the
IR adds protocol-graph features (dispatch tables, identifiers) and
cross-source provenance tracking.

## Path Forward

1. **JSON Schema publication.** Formalize the IR as a versioned JSON Schema
   so external tools can validate and consume protocol definitions.

2. **Variable-length extension.** Add an optional `options_schema` field
   to `ProtocolDef` for TLV and options parsing.

3. **Community feedback.** Publish the 127 extractable protocol definitions
   as a dataset for the networking community to evaluate.

4. **Cross-project adoption.** If other projects (packet generators,
   fuzzers, documentation tools) consume the IR, its value as a standard
   increases.

## Further Reading

- [IR Format](ir-format.md) — complete IR schema reference
- [Mapping Pipeline](mapping-pipeline.md) — how the IR is populated and consumed
- [Inconsistency Analysis](inconsistency-analysis.md) — the divergence data
  that motivates a standard format
- [Code Generation](code-generation.md) — round-trip evidence for IR sufficiency
