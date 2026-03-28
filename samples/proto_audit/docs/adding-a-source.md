# Adding a Source to proto-audit

This guide walks through adding a new protocol definition source to proto-audit,
using **etherparse** (a Rust packet parsing crate) as the worked example.

## Prerequisites

- Nix flakes (`nix develop`, `nix build`)
- `cargo test` from `samples/proto_audit/`

## Checklist

| # | File | Action |
|---|------|--------|
| 1 | `nix/proto-audit-sources.nix` | Pin external source |
| 2 | `mappings/<source>.toml` | Create type mappings |
| 3 | `src/type_mapping/<source>.rs` + `mod.rs` | Add mappings struct + loader |
| 4 | `src/name_mapping/mod.rs` + `table.rs` | Add fields to `ProtocolNames`, populate table |
| 5 | `src/extractors/<source>.rs` | Create extractor module |
| 6 | `src/extractors/mod.rs` | Register module |
| 7 | `src/main.rs` | Wire into CLI (SourcePaths, try_extract, ALL_SOURCES) |
| 8 | `src/test_data.rs` | Embed struct text for tests |
| 9 | `src/roundtrip_tests.rs` | Roundtrip extraction tests |
| 10 | `src/comparator.rs` | Cross-source agreement tests |
| 11 | `flake.nix` | Add env var to wrapper + flags |

## Step 1: Pin the Source

External sources are pinned in `nix/proto-audit-sources.nix` so builds are
reproducible. For a GitHub project:

```nix
etherparseSrc = pkgs.fetchFromGitHub {
  owner = "JulianSchmid";
  repo = "etherparse";
  rev = "f87e17057d64cd8ba4f08e4f1a37d22e6df6d870";
  hash = "";  # build once to get the hash from the error
};
```

Set `hash = ""` initially, run `nix build .#proto-audit`, copy the hash from
the error message, and paste it back.

If your source needs overlay patches (to add protocol structs beyond its
native coverage), use `pkgs.applyPatches` with the `patchesIn` helper:

```nix
etherparseSrc = pkgs.applyPatches {
  src = pkgs.fetchFromGitHub { ... };
  patches = patchesIn ../samples/proto_audit/patches/etherparse;
};
```

See [Source Patching](patching.md) and [Nix Packaging](nix-packaging.md)
for details on the patching system.

## Step 2: Inventory the Protocols

Before writing code, catalogue every protocol your source defines:

| Protocol | Struct/Class | Source File | Public Fields | Wire Size |
|----------|-------------|-------------|---------------|-----------|
| Ethernet | `Ethernet2Header` | `etherparse/src/link/ethernet2_header.rs` | source, destination, ether_type | 14B |
| UDP | `UdpHeader` | `etherparse/src/transport/udp_header.rs` | source_port, destination_port, length, checksum | 8B |
| IPv4 | `Ipv4Header` | `etherparse/src/net/ipv4_header.rs` | dscp, ecn, total_len, ... | 20B min |
| TCP | `TcpHeader` | `etherparse/src/transport/tcp_header.rs` | source_port, ..., ns, fin, syn, ... | 20B min |
| IPv6 | `Ipv6Header` | `etherparse/src/net/ipv6_header.rs` | traffic_class, flow_label, ... | 40B |
| VLAN | `SingleVlanHeader` | `etherparse/src/link/single_vlan_header.rs` | pcp, drop_eligible_indicator, vlan_id, ether_type | 4B |
| ARP | `ArpPacket` | `etherparse/src/net/arp_packet.rs` | hw_addr_type, proto_addr_type, operation | 8B fixed |
| ICMPv4 | `Icmpv4Header` | `etherparse/src/transport/icmpv4_header.rs` | icmp_type, checksum | 8B |
| ICMPv6 | `Icmpv6Header` | `etherparse/src/transport/icmpv6_header.rs` | icmp_type, checksum | 8B |

Note which fields are public (extractable) and which are private. ARP's
`hw_addr_size` and `proto_addr_size` are private in etherparse, so they
can't be extracted.

## Step 3: Create TOML Mappings

Create `mappings/<source>.toml`. The TOML maps your source's type system to
the proto-audit IR.

### 3.1: Type Bits

Map each type to its **wire** bit width, not its Rust/C storage size:

```toml
[type_bits]
u8 = 8
u16 = 16
u32 = 32
bool = 1
EtherType = 16
IpDscp = 6        # 6 bits on wire, stored in u8
IpEcn = 2         # 2 bits on wire
IpFragOffset = 13  # 13 bits on wire
Ipv6FlowLabel = 20 # 20 bits on wire
VlanPcp = 3
VlanId = 12
TcpOptions = 0    # variable length, skip
Ipv4Options = 0   # variable length, skip
```

### 3.2: Field Type Overrides

Override the default `Uint` inference for semantically meaningful fields:

```toml
[field_type_overrides]
ether_type = { type = "Enum", reason = "EtherType (IEEE 802)" }
protocol = { type = "Enum", reason = "IPv4 protocol number (IANA)" }
next_header = { type = "Enum", reason = "IPv6 next header (IANA)" }
```

### 3.3: Implicit Fields

Some sources omit wire fields that are implicit (e.g., IPv4 version/IHL).
Use `implicit_fields` to account for the missing bits:

```toml
[implicit_fields.Ipv4Header]
start_offset_bits = 8    # version(4) + ihl(4) are implicit
gaps = [{ after = "identification", skip_bits = 1 }]  # reserved flag bit

[implicit_fields.Ipv6Header]
start_offset_bits = 4    # version(4) is implicit

[implicit_fields.TcpHeader]
gaps = [{ after = "acknowledgment_number", skip_bits = 7 }]  # data_offset(4) + reserved(3)
```

### 3.4: Flag Bit Offsets

When struct field order doesn't match wire order (TCP flags), map each flag
to its absolute wire bit position:

```toml
[flag_bit_offsets.TcpHeader]
ns = 103
cwr = 104
ece = 105
urg = 106
ack = 107
psh = 108
rst = 109
syn = 110
fin = 111
```

### 3.5: Array Endian Overrides

Multi-byte arrays like MAC and IP addresses need explicit endian annotation:

```toml
[array_endian_overrides."u8:6"]
endian = "Big"
reason = "MAC address"

[array_endian_overrides."u8:4"]
endian = "Big"
reason = "IPv4 address"

[array_endian_overrides."u8:16"]
endian = "Big"
reason = "IPv6 address"
```

## Step 4: Register in Type Mapping

In `src/type_mapping/` (create a new `<source>.rs` module and register it in `mod.rs`):

1. Add `const DEFAULT_<SOURCE>_TOML: &str = include_str!("../mappings/<source>.toml");`

2. Define a mappings struct. If your TOML has extra sections (like
   `implicit_fields`, `flag_bit_offsets`), create a new struct:

```rust
#[derive(Debug, Deserialize)]
pub struct EtherparseMappings {
    pub type_bits: HashMap<String, u32>,
    pub type_endian: HashMap<String, String>,
    pub field_type_overrides: HashMap<String, FieldTypeOverride>,
    pub array_endian_overrides: HashMap<String, ArrayEndianOverride>,
    pub implicit_fields: HashMap<String, ImplicitFieldConfig>,
    pub flag_bit_offsets: HashMap<String, HashMap<String, u32>>,
}
```

3. Implement accessor methods (type_bits, field_type_override, etc.)

4. Add a loader: `pub fn load_<source>_mappings(dir: Option<&Path>) -> Result<T>`

## Step 5: Write the Extractor

Create `src/extractors/<source>.rs`. The extractor needs:

1. **Parsing**: Read source text and extract struct field definitions
2. **IR Conversion**: Convert parsed fields to `Vec<FieldDef>` using mappings
3. **Protocol Extraction**: Convenience wrapper producing `ProtocolDef`

Key considerations:

- **Implicit fields**: Check `implicit_fields` for start_offset_bits and gaps
- **Flag fields**: If `flag_bit_offsets` maps a field, use the explicit
  position instead of the running offset counter
- **Flag region tracking**: After processing flag fields, advance the offset
  counter past the entire flag region
- **Zero-bit types**: Skip variable-length fields (TcpOptions, etc.)
- **Endianness**: `<=8 bits → Na`, arrays → check overrides, else Big
- **Field type inference**: check overrides first, then name-based heuristics

The etherparse extractor uses regex to find `pub struct Name { ... }` blocks,
then parses `pub field: Type,` and `pub field: [Type; N],` lines.

## Step 6: Wire into CLI

In `src/main.rs`:

1. Add to `SourcePaths`:
   ```rust
   #[arg(long, env = "PROTO_AUDIT_ETHERPARSE_SRC")]
   etherparse_src: Option<PathBuf>,
   ```

2. Add to `ALL_SOURCES`:
   ```rust
   const ALL_SOURCES: &[&str] = &["xdp2", "kernel", "scapy", "tshark", "etherparse"];
   ```

3. Add match arm in `try_extract()`:
   ```rust
   "etherparse" => {
       let src = paths.etherparse_src.as_ref()?;
       let names = name_mapping::find_by_canonical(proto)?;
       let struct_name = names.etherparse_struct?;
       let source_file = names.etherparse_file?;
       let file_path = src.join(source_file);
       let content = std::fs::read_to_string(&file_path).ok()?;
       let mut def = extractors::etherparse::extract_protocol(
           &content, struct_name, source_file,
       ).ok().flatten()?;
       def.name = names.canonical.to_string();
       def.is_variable_length = names.variable_length;
       Some(def)
   }
   ```

4. Update `cmd_list()` to show the new column

## Step 7: Add Name Mappings

In `src/name_mapping/` (`table.rs` for the protocol table, `mod.rs` for lookup functions):

1. Add two fields to `ProtocolNames`:
   ```rust
   pub etherparse_struct: Option<&'static str>,
   pub etherparse_file: Option<&'static str>,
   ```

2. Set values for supported protocols in `protocol_table()`. Set `None` for
   protocols your source doesn't cover.

3. Add a lookup function:
   ```rust
   pub fn find_by_etherparse_struct(name: &str) -> Option<ProtocolNames>
   ```

4. Update `source_to_canonical_map()` with a new match arm.

## Step 8: Add Roundtrip Tests

In `src/test_data.rs`, embed representative struct definitions as constants:

```rust
pub const ETHERPARSE_UDP_HEADER: &str = r#"
pub struct UdpHeader {
    pub source_port: u16,
    pub destination_port: u16,
    pub length: u16,
    pub checksum: u16,
}
"#;
```

In `src/roundtrip_tests.rs`, verify extraction + IR conversion:

```rust
#[test]
fn roundtrip_etherparse_udp() {
    let mappings = type_mapping::load_etherparse_mappings(None).unwrap();
    let es = etherparse::parse_etherparse_struct(ETHERPARSE_UDP_HEADER, "UdpHeader")
        .unwrap().unwrap();
    let fields = etherparse::to_field_defs_with(&es, &mappings);

    assert_eq!(fields.len(), 4);
    assert_field(&fields, "source_port", 0, 16, FieldType::Uint, Endian::Big);
    assert_field(&fields, "destination_port", 16, 16, FieldType::Uint, Endian::Big);
    assert_field(&fields, "length", 32, 16, FieldType::Uint, Endian::Big);
    assert_field(&fields, "checksum", 48, 16, FieldType::Uint, Endian::Big);
}
```

## Step 9: Cross-Source Verification

In `src/comparator.rs`, add tests that compare your source against existing
sources to validate agreement:

```rust
#[test]
fn test_cross_source_udp_four_way() {
    // Extract from kernel, scapy, tshark, etherparse
    // Audit all four together
    // Assert all 4 fields agree across all 4 sources
    let result = audit_protocol("UDP", &[
        ("kernel", &k_proto), ("scapy", &s_proto),
        ("tshark", &t_proto), ("etherparse", &e_proto),
    ]);
    assert_eq!(result.fields_agree, 4);
}
```

## Step 10: Nix Integration

In `flake.nix`:

1. Add env var to the `proto-audit` wrapper:
   ```nix
   export PROTO_AUDIT_ETHERPARSE_SRC="''${PROTO_AUDIT_ETHERPARSE_SRC:-${protoAuditSources.etherparseSrc}}"
   ```

2. Add flag to `protoAuditFlags`:
   ```nix
   "--etherparse-src ${protoAuditSources.etherparseSrc}"
   ```

## Design Decisions

### Wire vs Storage Sizes

Etherparse uses newtype wrappers that store values in larger types. For
example, `IpDscp` is 6 bits on the wire but stored in a `u8`. The TOML
maps to **wire** sizes, not storage sizes, because proto-audit compares
field layouts at the wire level.

### Implicit Fields

Some sources omit wire fields that are always constant or computed. IPv4's
version (always 4) and IHL (computed from options length) aren't in
etherparse's struct. The `implicit_fields` TOML section accounts for these
missing bits so offset calculations stay correct.

### Flag Ordering

TCP flags appear in a different order in etherparse's struct (ns, fin, syn,
rst, psh, ack, urg, ece, cwr) than on the wire (ns, cwr, ece, urg, ack,
psh, rst, syn, fin). The `flag_bit_offsets` table maps each flag to its
absolute wire position.

### Limitations

- **ARP**: Only 3 public fields extractable (hw_addr_type, proto_addr_type,
  operation). Address fields use private `MaybeUninit<u8>` buffers.
- **ICMPv4/v6**: Only icmp_type + checksum extractable. The code field is
  embedded inside the type enum.
- **Variable-length fields**: TcpOptions and Ipv4Options map to 0 bits
  and are skipped.

## Appendix: Etherparse Protocol Coverage

See the [etherparse coverage table](proto-audit-coverage.md#etherparse-protocol-coverage)
in the coverage doc.
