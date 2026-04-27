# Code Generation

The generator (`src/generator/`) converts `ProtocolDef` instances into source
code or wire-format output for five targets. Each target has its own module
and (for etherparse and Scapy) a TOML configuration file for reverse type
mapping — translating IR types back to target-language types.

```bash
nix run .#proto-audit -- generate --proto IPv4 --target c
nix run .#proto-audit -- generate --proto UDP --target scapy
nix run .#proto-audit -- generate --proto TCP --target etherparse
nix run .#proto-audit -- generate --proto TCP --target pcap -o tcp.pcap
```

## Targets

| Target | Module | Config | Output |
|--------|--------|--------|--------|
| C (XDP2 proto_def) | `src/generator/c.rs` | — | C header with `xdp2_proto_def` struct, parse node, dispatch, length |
| Rust (etherparse) | `src/generator/etherparse.rs` | `mappings/etherparse_gen.toml` | Rust struct with `#[derive(...)]` and `from_slice()` skeleton |
| Python (Scapy) | `src/generator/scapy.rs` | `mappings/scapy_gen.toml` | Scapy Packet class with `fields_desc` and `bind_layers` |
| PCAP | `src/generator/pcap.rs` | — | PCAP file with one minimal packet for the target protocol |
| Kaitai Struct | `src/generator/kaitai.rs` | — | `.ksy` YAML format spec with `meta`, `seq`, and field-level types |

Generation uses reverse type mappings from `mappings/etherparse_gen.toml`
and `mappings/scapy_gen.toml`. The C, PCAP, and Kaitai targets generate
directly from IR without a TOML mapping file.

## etherparse_gen.toml

Maps IR `(FieldType, size_bits)` to Rust types:

```toml
[rust_types]
"Uint:16" = "u16"
"Ipv4Addr:32" = "[u8; 4]"
"MacAddr:48" = "[u8; 6]"

[newtypes]
ether_type = "EtherType"     # field-name → newtype override
protocol = "IpNumber"

[derives]
default = ["Debug", "Clone", "PartialEq", "Eq"]

[skip_fields]
Ipv4Header = ["version", "ihl"]   # implicit in etherparse
```

## scapy_gen.toml

Maps IR `(FieldType, size_bits)` to Scapy field classes:

```toml
[field_classes]
"Uint:16" = "ShortField"
"Ipv4Addr:32" = "IPField"
"Enum:16" = "ShortEnumField"

[name_overrides]
src_addr = "SourceIPField"   # field-name → class override
checksum = "XShortField"

[le_prefixes]
ShortField = "LEShortField"  # Little-endian variant
```

## Type mapping direction

The generation TOML files map in the **opposite direction** from extraction
TOMLs:

| Phase | Direction | Example |
|-------|-----------|---------|
| Extraction | Source → IR | `scapy.toml`: `IPField` → `Ipv4Addr` |
| Generation | IR → Source | `scapy_gen.toml`: `Ipv4Addr:32` → `IPField` |

The type mapping module (`src/type_mapping/scapy_gen.rs`) loads the generation
TOML and provides lookup methods for the generator.

## PCAP Target

The PCAP generator (`src/generator/pcap.rs`) produces binary wire output
rather than source code. It builds a full encapsulation stack (e.g.,
Ethernet → IPv4 → TCP) using the `STACK_ROUTES` dispatch table, serializes
each layer with field-level bitpacking, and wraps the result in a PCAP file.

Key features:
- **Protocol stack construction**: walks `STACK_ROUTES` from target back to
  Ethernet, setting dispatch field overrides at each layer
- **Embedded fallback ProtocolDefs**: for Ethernet, IPv4, IPv6 when
  extracted IR is unavailable
- **Field value defaults**: type-based defaults for addresses, version, TTL;
  dispatch values from stack routes
- **IPv4 checksum**: computes RFC 791 ones-complement checksum after fixup
  of `total_length`
- **Hex dump**: `--dry-run` prints the packet as a formatted hex dump
  without writing a file

No TOML mapping file is needed — the generator works directly from IR
`FieldDef` values.

See [Round-Trip Validation](validation.md) for how the PCAP output feeds
back through tshark for IR verification.

## Cross-Generator Round-Trip Verification

The `crossgen` command verifies generator fidelity by closing the
generate→extract loop for all targets:

```bash
nix run .#proto-audit -- crossgen --proto IPv4 --target all
nix run .#proto-audit -- crossgen --proto all --target etherparse
```

For each target, the command:
1. Builds a rich IR from available sources
2. Generates code through the target generator
3. Re-extracts from the generated code through the corresponding extractor
4. Compares the re-extracted IR to the original

| Target | Re-extraction Path | Runtime |
|--------|-------------------|---------|
| etherparse | `generate_etherparse()` → `parse_etherparse_struct()` | Pure Rust (no external tools) |
| C | `generate_proto_def()` → `parse_kernel_struct()` | Pure Rust (no external tools) |
| Scapy | `generate_scapy()` → `scapy_dump.py --extra` | Requires Python + Scapy |
| PCAP | Delegates to `validate` command | Requires tshark |

9 cross-generator unit tests in `src/crossgen_tests.rs` verify etherparse
and C round-trips for core protocols (IPv4, UDP, Ethernet, TCP, ARP).
