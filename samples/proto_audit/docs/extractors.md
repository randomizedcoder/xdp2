# Extractors

Each of the 9 sources has a dedicated extractor that reads native definitions
(C structs, Python field descriptors, Rust types, XML dissections, BPF gencode
offsets, OMI Lua dissectors) and normalizes them into the common IR (`ProtocolDef`). Every field is indexed by
its wire bit offset and size. Type inference is driven by per-source TOML
mapping files in `mappings/`.

See [IR Format](ir-format.md) for the full schema, [Field Matching](field-matching.md)
for how extracted fields are compared across sources.

## Kernel (`src/extractors/kernel.rs`)

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

## Scapy (`src/extractors/scapy.rs`)

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

### Scapy Helper (`helpers/scapy_dump.py`)

```bash
python3 scapy_dump.py IP                           # dump one protocol as JSON
python3 scapy_dump.py --list                       # list all available Packet classes
python3 scapy_dump.py --discover-all               # discover all Packet subclasses
python3 scapy_dump.py --discover-all-rich          # discover with enriched metadata
python3 scapy_dump.py --dump-all                   # dump ALL protocols in one call
python3 scapy_dump.py --dissect-pcap file.pcap     # dissect PCAP, output per-layer fields
python3 scapy_dump.py --extra file.py ClassName    # load external module, dump named class
```

The helper imports ~40 Scapy contrib/layers modules to ensure full coverage.
19 of these are custom modules created for proto-audit (PBB, TRILL, MPEG-TS,
etc.) living in the local Scapy tree at `~/Downloads/scapy/scapy/contrib/`.

The `--dissect-pcap` mode reads a PCAP file with `rdpcap()`, dissects each
packet layer by layer, and outputs per-layer field values as JSON. Used by
the `corpus-parse` command for cross-source value comparison.

The `--extra` mode loads an external Python file and dumps a named Scapy
Packet class from it. Used by the `crossgen` command for Scapy round-trip
verification — the generated Scapy class is written to a temp file, then
re-extracted through this mode.

## tshark (`src/extractors/tshark.rs`)

Runs `tshark -T pdml` on a test PCAP and parses the XML output. Each
`<proto>` element becomes a protocol, each `<field>` with `pos` and `size`
attributes becomes a field definition.

Type inference uses `mappings/tshark.toml`:
- `suffix_types`: unconditional suffix → type (e.g., `.src_hw` → MacAddr)
- `suffix_types_by_size`: suffix + bit width → type (e.g., `.src` at 32 bits → Ipv4Addr)
- `contains_types`: substring → type (e.g., `flags` → Flags)
- `enum_patterns`: substring + max bits → Enum (e.g., `proto` at ≤16 bits)
- `blocklist_suffixes`: filtered out (`.payload`, `.padding`, `.trailer`, etc.)

## etherparse (`src/extractors/etherparse.rs`)

Parses Rust `pub struct` definitions from etherparse source files. Handles:
- Array fields (`[u8; 6]` for MAC addresses)
- Non-pub field filtering (ARP private fields skipped)
- Newtype wrappers mapped to wire bit widths via TOML
- Sub-byte types (`Bits2`–`Bits29`) for fine-grained overlay struct fields
- Implicit wire fields (IPv4 version/IHL, IPv6 version, TCP data_offset/reserved)
- TCP flag reordering (struct order ≠ wire order)

Type inference uses `mappings/etherparse.toml`:
- `type_bits`: Rust type → wire bit width (including newtypes and sub-byte types)
- `field_type_overrides`: field name → semantic type
- `implicit_fields`: start_offset_bits + gaps for missing wire fields
- `flag_bit_offsets`: field name → absolute wire bit position
- `array_endian_overrides`: Rust type + array size → endianness

Covers 9 native protocols (Ethernet, VLAN, IPv4, IPv6, ARP, TCP, UDP,
ICMPv4, ICMPv6) plus 31 overlay protocols added via per-protocol patches
(GRE, VXLAN, MPLS, Geneve, NSH, NTP, BFD, etc.). Overlay structs use
RFC-level field granularity with sub-byte types for individual bit-fields.
See [Source Patching](patching.md) for details.

See [Adding a Source](adding-a-source.md) for the complete guide using
etherparse as a worked example.

## libpcap (`src/extractors/libpcap.rs`)

Dual-path extractor for libpcap's protocol knowledge:

- **Gencode offsets**: Protocol field offsets from `gencode.c`'s BPF compiler,
  captured declaratively in TOML (`[gencode_protocols]` tables). These offsets
  are derived from RFCs, independent of kernel structs.
- **C struct parsing**: For protocols defined as structs in `pcap/*.h` headers
  (SLL, SLL2, VLAN) and overlay headers in `pcap/proto_audit/*.h`.
- **C bitfield support**: Parses `uint16_t field:N;` bitfield syntax for
  fine-grained sub-field extraction in overlay structs.

The extractor dispatches based on the `libpcap_file` hint in the name mapping
table — `gencode.c` triggers TOML-declared offset extraction, while a
`pcap/*.h` path triggers C struct parsing using regex.

Type inference uses `mappings/libpcap.toml`:
- `type_bits`: C type → bit width (`uint8_t`, `uint16_t`, etc.)
- `type_endian`: type prefix → endianness (big-endian for multi-byte network fields)
- `field_type_overrides`: field name → semantic type (e.g., `sll_protocol` → Enum)
- `gencode_protocols`: declarative field offset tables per protocol (byte offset, size, optional type)
- `struct_protocols`: struct name → source file + struct name for C header parsing

Covers 6 gencode protocols (IPv4, IPv6, TCP, UDP, ARP, SCTP), 3 native
struct protocols (SLL, SLL2, VLAN), and 18 overlay protocols added via
per-protocol patches (GRE, VXLAN, MPLS, etc.). Overlay structs use C
bitfields for RFC-level field granularity.
See [Source Patching](patching.md) for details.

## XDP2 (`src/extractors/xdp2.rs`)

Scans XDP2's `proto_defs/` directory for `xdp2_proto_def` struct
initializations. Extracts:
- Variable name (e.g., `xdp2_parse_ipv4`)
- Display name from `.name` field
- Kernel struct reference (via `sizeof(struct ...)`)
- Dispatch function (`.ops.next_proto`) and length function (`.ops.len`)
- TLV vs regular protocol flag, overlay flag

XDP2 proto_defs don't define fields directly — they reference kernel structs
via `#include <linux/ip.h>` and provide type-safe accessor functions (e.g.,
`ipv4_proto()`, `ipv4_len()`) for BPF packet processing. The extractor yields
metadata (`present: true`, `field_count: 0`), shown as `0*` in the matrix.
Field-level comparison uses the kernel extractor instead.

This is by design: XDP2's role is protocol graph traversal and eBPF program
generation, not field-level reflection. The field definitions live in the
kernel UAPI headers, which proto-audit extracts separately.

## Kaitai Struct (`src/extractors/kaitai.rs`)

Parses Kaitai Struct `.ksy` files (YAML format) to extract protocol field
definitions. The extractor reads `seq:` entries from the format specification,
mapping Kaitai types (`u1`, `u2be`, `u4be`, etc.) to IR field types and sizes.

12 protocols have curated Kaitai mappings in the name table (`kaitai_id` +
`kaitai_file`): Ethernet, VLAN, IPv4, IPv6, ARP, ICMPv4, TCP, UDP, DNS,
RTP, RTCP. For non-curated protocols, the extractor falls back to dynamic
matching using `ksy_id_to_display_name` heuristics.

No TOML mapping file is needed — Kaitai's type system maps straightforwardly
to the IR.

## Suricata (`src/extractors/suricata.rs`)

Parses Rust struct definitions from Suricata's app-layer parser source files.
The extractor uses regex to find `pub struct` blocks in Suricata's
`rust/src/` directory tree, extracting field names, types, and sizes.

20 protocols have curated Suricata mappings in the name table
(`suricata_module` + `suricata_struct`): DNS, NTP, SNMP, DHCP, QUIC, ENIP,
FTP, HTTP2, IKEv2, Kerberos, LDAP, MODBUS_TCP, MQTT, SIP, SMB, SSH,
Telnet, TFTP, mDNS, WebSocket. For non-curated protocols, the extractor
uses a `PROTO_MAP` table for module→struct lookup.

No TOML mapping file is needed — Rust types map directly to IR types.

## OMI (`src/extractors/omi.rs`)

The Open Markets Initiative ships (a) canonical C-struct definitions for
exchange trading protocols and (b) Wireshark Lua dissectors for those same
feeds. proto-audit treats these as two halves of a 9th independent source.

- **C-struct half**: Parses packed `typedef struct ... T` definitions from
  OMI feed headers (e.g., `nasdaq/Nasdaq.Equities.TotalView.Itch.v5.0.h`,
  `eurex/Eurex.Derivatives.Eobi.T7.v3.0.h`). Produces IR fields with wire
  sizes sourced from the c-struct, pinned by Nix.
- **Wireshark Lua half**: When a name table entry supplies an
  `.omi_tshark(lua, pcap, field)` triple, the extractor runs the referenced
  sample PCAP through tshark with the OMI Lua dissector preloaded, then
  extracts only the per-message leaf fields (via
  `extract_field_as_proto`) — avoiding the outer-packet superset that plain
  tshark would return.

Covers ~27 trading protocol messages across ITCH v5, PITCH v2, SBE MDP3,
EOBI, and SoupBinTCP. Wired into the name table via builder methods
`.omi(struct_name, header_file)`, `.omi_tshark(lua, pcap, field)`, and
`.xdp2(parse_node_var)` when a matching XDP2 `trading/proto_*.h` leaf exists.

See [Source Patching](patching.md) for the `gen-patches` pipeline that
converts OMI IR into upstream libpcap / etherparse overlay patches.
