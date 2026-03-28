# Mapping Pipeline

proto-audit operates as a bidirectional mapping pipeline: extraction ("mapping
in") normalizes six heterogeneous source formats into a common IR, while
generation ("mapping out") converts the IR back into compilable source code.

## Pipeline Diagram

```
         MAPPING IN (Extraction)                 MAPPING OUT (Generation)
   ═══════════════════════════════       ════════════════════════════════

   ┌──────────┐                                              ┌──────────┐
   │  kernel  │──┐  kernel.toml                         ┌───▶│ C header │
   ├──────────┤  │                                      │    │ (no TOML)│
   │  scapy   │──┤  scapy.toml                         │    ├──────────┤
   ├──────────┤  │                    ┌──────────┐      │    │ Rust     │
   │  tshark  │──┤  tshark.toml      │          │      ├───▶│ ether-   │
   ├──────────┤  ├──────────────────▶ │    IR    │──────┤    │ parse_gen│
   │  ether-  │──┤  etherparse.toml  │ (Proto-  │      │    │ .toml    │
   │  parse   │  │                    │  colDef) │      │    ├──────────┤
   ├──────────┤  │  libpcap.toml     │          │      ├───▶│ Scapy    │
   │  libpcap │──┤                    └────┬────┘      │    │ scapy_gen│
   ├──────────┤  │  (no TOML)              │           │    │ .toml    │
   │  xdp2    │──┘                         │           │    ├──────────┤
   └──────────┘                            │           └───▶│ PCAP     │
                                           ▼                │ (no TOML)│
                                     ┌───────────┐         └──────────┘
    5 extraction TOMLs               │Comparator │     ┌──────────┐
                                     └─────┬─────┘     │  Report  │
                                           └──────────▶└──────────┘
                                                     2 generation TOMLs
```

Left: six sources feed through five TOML-driven extractors into the IR.
Right: four generators read the IR and produce compilable output or wire bytes.
Center: the comparator branches off the IR for cross-source analysis.

## Per-Source Extraction Fidelity

Each extraction TOML captures a different slice of its source's type system.
More entries means richer type inference without Rust code changes.

| Source | TOML Entries | Field Overrides | Protocols | Richness |
|--------|-------------|-----------------|-----------|----------|
| kernel | 23 type_bits, 3 struct_sizes, 5 endian rules | 14 (12 with IANA reasons) | ~48 | Highest |
| scapy | 24 class→type mappings, 4 name patterns | 0 (class names carry type) | 109 | Medium |
| etherparse | 30 type_bits (14 newtypes + 11 sub-byte), 3 implicit field defs | 12 + flag_bit_offsets | 9 + 31 overlay | High |
| libpcap | 4 type_bits, 7 gencode protocols, 21 struct defs | 12 | 6 + 18 overlay | Medium |
| tshark | 0 type_bits (pure heuristics: suffixes, patterns) | 0 | ~80 | Lowest |
| xdp2 | No TOML (metadata-only extraction) | N/A | ~70 | Metadata only |

**Richness** reflects how precisely the TOML maps source types to IR types.
Kernel is highest because it maps 23 C types with endian prefixes and 14
semantic overrides. tshark is lowest because PDML carries no explicit type
information — the extractor infers types from field name patterns alone.

## Per-Generator Coverage

| Generator | TOML | Type Mappings | Special Handling |
|-----------|------|--------------|-----------------|
| C | None | Direct from IR field names | Uses kernel struct naming conventions |
| etherparse | `etherparse_gen.toml` | 34 (type,size)→Rust entries | 11 newtypes, 3 skip-field lists |
| Scapy | `scapy_gen.toml` | 34 (type,size)→class entries | 11 name overrides, 7 LE prefixes |
| PCAP | None | Direct from IR FieldDefs | Protocol stack construction + IPv4 checksum |

## Asymmetry: 5 Extraction TOMLs, 2 Generation TOMLs

Extraction requires per-source TOMLs because each source has a unique type
system: kernel uses `__be16`/`__le16` C types, Scapy uses Python field
classes like `XShortEnumField`, etherparse uses Rust newtypes like `IpDscp`.
Each needs its own mapping to reach the common IR.

Generation is simpler. The C generator maps directly from IR field names
(which already use kernel-style naming), so no TOML is needed. The PCAP
generator also needs no TOML — it serializes IR `FieldDef` values directly
to wire bytes. Only etherparse and Scapy generators need reverse mappings
because their type systems diverge from the IR's naming conventions.

## Worked Example: IPv4 Through the Pipeline

### Extraction (kernel → IR)

The kernel defines IPv4 in `include/uapi/linux/ip.h` as `struct iphdr` with
12 fields. Here's how three representative fields are mapped:

| Kernel field | C type | kernel.toml rule | IR result |
|---|---|---|---|
| `protocol` | `__u8` | type_bits: 8, override: `Enum` (IANA) | `Enum`, 8 bits, offset 72 |
| `saddr` | `__be32` | type_bits: 32, endian: `prefix:__be`→Big | `Ipv4Addr`, 32 bits, Big |
| `frag_off` | `__be16` | type_bits: 16, endian: Big | `Uint`, 16 bits, Big |

The `field_type_overrides.protocol` entry in `kernel.toml` upgrades the
default `Uint` to `Enum` because `protocol` selects from the IANA IP
protocol number registry — a closed enumeration, not an open namespace.

### The IR pivot (from `src/ir.rs` test data)

The resulting `ProtocolDef` has 12 fields indexed by bit offset. Each field
preserves per-source naming via `source_names`:

```
Field: src_addr  offset=96  size=32  type=Ipv4Addr  endian=Big
  kernel: "saddr"    scapy: "src"    tshark: "ip.src"    xdp2: "saddr"
```

### Generation (IR → Scapy)

The Scapy generator reads the same IR and applies `scapy_gen.toml`:

| IR field | Type + Size | scapy_gen.toml rule | Scapy output |
|---|---|---|---|
| `src_addr` | `Ipv4Addr:32` | field_classes → `IPField`, name_override `src_addr` → `SourceIPField` | `SourceIPField("src_addr")` |
| `protocol` | `Enum:8` | field_classes → `ByteEnumField` | `ByteEnumField("protocol", ...)` |
| `checksum` | `Uint:16` | field_classes → `ShortField`, name_override `checksum` → `XShortField` | `XShortField("checksum")` |

### Generation (IR → C)

The C generator needs no TOML — it maps IR types directly to C:

```c
struct ipv4_header {
    uint8_t  version;           // Uint:4 → packed bitfield
    uint8_t  ihl;               // Uint:4 → packed bitfield
    uint8_t  tos;               // Uint:8
    uint16_t total_length;      // Uint:16, Big → __be16
    // ...
    uint32_t src_addr;          // Ipv4Addr:32
    uint32_t dst_addr;          // Ipv4Addr:32
};
```

### Comparator (cross-source analysis)

The comparator matches fields by `(offset_bits, size_bits)`, not by name.
For IPv4, it finds that `flags` (offset 48, 3 bits) and `fragment_offset`
(offset 51, 13 bits) in the IR don't match kernel's single `frag_off`
(offset 48, 16 bits) — producing a SPLIT finding. See
[Inconsistency Analysis](inconsistency-analysis.md) for root causes.

## Further Reading

- [Architecture](architecture.md) — system overview and component diagram
- [Source Patching](patching.md) — overlay patches, fine-grained analysis, upstream PR workflow
- [Extractors](extractors.md) — per-source extractor implementation details
- [Code Generation](code-generation.md) — generator targets and TOML schemas
- [Inconsistency Analysis](inconsistency-analysis.md) — why sources disagree
- [IR as Standard](ir-as-standard.md) — the IR as a potential universal format
