# proto-audit Status

## Current State (2026-04-29)

567 curated protocols audited across 16 sources (XDP2, kernel, DPDK, nDPI, pppd, Scapy, tshark, etherparse, libpcap, Kaitai Struct, Suricata, OMI, xtcp2, RDMA, xdp2_headers, UE spec).
517 unit tests including roundtrip, cross-source, PCAP generation, cross-generator, OMI triangle roundtrip, DPDK/nDPI/pppd extractor tests, nested struct/union resolution tests, xtcp2 Go struct parser tests, and exhaustive TOML coverage validation.
333 protocols with Gold-tier round-trip validation (IR → PCAP → tshark → IR).
378 PCAP templates with valid protocol content for round-trip validation.
529 Rust ProtocolOps in xdp2-rs — 100% coverage of all Gold (333), Silver (41), and Bronze (63) tiers.
332 libpcap + 332 etherparse per-protocol overlay patches (incl. 27 trading `trading_*.patch` each).

### Source Coverage Summary

| Source | Coverage |
|--------|----------|
| XDP2 proto_defs | 459 (incl. 16 trading leaf proto_defs) |
| Etherparse structs | 332 overlay patches |
| Libpcap overlays | 332 overlay patches |
| Scapy classes | 5,798 (109 curated) |
| tshark filters | 3,753 (3,155 protocols) |
| Kernel structs | 109 (190 in registry, nested struct/union resolution, 17 netlink subsystem messages) |
| DPDK headers | 24 protocols (rte_*_hdr structs from lib/net/) |
| nDPI headers | 13 protocols (ndpi_* structs from ndpi_typedefs.h) |
| pppd headers | 7 protocols (PPP control protocol structs) |
| Kaitai Struct | ~20 protocols (12 curated) |
| Suricata parsers | ~15 protocols (20 curated) |
| OMI trading msgs | ~27 (ITCH v5, PITCH v2, SBE MDP3, EOBI, SoupBinTCP) |
| xtcp2 Go structs | 11 protocols (TCPInfo 59 fields, BBRInfo, MemInfo, SkMemInfo, VegasInfo, DCTCPInfo, PragueInfo, SockID, ReqV2) |

### Validation Tier Breakdown

| Tier | Count | Meaning |
|------|-------|---------|
| Gold | 333 | Round-trip validated (IR → PCAP → tshark → IR matches) |
| Silver | 41 | 2+ independent sources agree on field layout |
| Bronze | 63 | Single source, self-consistent |
| Unvalidated | 22 + ~8,100 discovered | Discovered but not yet verified |

### Gold-Validated Protocols (333)

Round-trip validated through wire bytes — IR serialized to PCAP, parsed by tshark, extracted back to IR, field-by-field comparison passes.

See `docs/pipeline-coverage.md` for the full list of 8/8 and 7/8 protocols.

### Recent Changes

#### Full Rust Protocol Coverage — 529 ProtocolOps (2026-04-29)

Achieved 100% parity between C proto_defs and Rust ProtocolOps across all validation tiers:
- **333 Gold** protocols — all have Rust ProtocolOps
- **41 Silver** protocols — all have Rust ProtocolOps
- **63 Bronze** protocols — all have Rust ProtocolOps
- **check-rs CI gate** passes with zero C-only protocols
- Fixed 16 ITCH v5/PITCH v2 NAME constant spacing mismatches
- Aligned 73 canonical names in table.rs to match C/Rust conventions
- Added 204 new ProtocolOps across 29 new module files
- Curated protocols: 459→567, unit tests: 467→517, Rust ProtocolOps: 325→529

#### SCSI/SAS/FC Storage + ML/HPC Protocols (2026-04-28)

50 SCSI/SAS/FC storage protocols (iSCSI PDUs, SRP, FCP, FC ELS, FC GS/NS, SAS/ATA) and 23 ML/HPC protocols (Falcon, NVMe/TCP, NVMe/RDMA, RoCEv2, eCPRI, PFC) added as curated entries.

#### xtcp2 Source Addition — Go Netlink Parser Structs (2026-04-20)

Added xtcp2 (github.com/randomizedcoder/xtcp2) as 13th source — a Go-based netlink parser with rich struct definitions for `inet_diag` attributes (the data behind `ss --tcp --info`):

- **Go struct extractor** (`src/extractors/xtcp2.rs`): Parses Go struct definitions with `// bytes:N [start:end]` and `// N = M` byte offset comments. Handles type aliases (`type TCPInfo TCPInfo6_10_3`), array types (`[16]byte`), size constants (`BBRInfoSizeCst = 20`). Walks `pkg/xtcpnl/*.go` files.
- **9 new protocols**: NL_Diag_TCPInfo (59 fields, 248 bytes, versioned across 6 kernel variants), NL_Diag_BBRInfo (5 fields), NL_Diag_MemInfo (4 fields), NL_Diag_SkMemInfo (9 fields), NL_Diag_VegasInfo (4 fields), NL_Diag_DCTCPInfo (4 fields), NL_Diag_PragueInfo (9 fields), NL_Diag_SockID (6 fields), NL_Diag_ReqV2 (7 fields)
- **2 existing protocols updated**: Netlink + NL_Diag_Inet get `.xtcp2()` cross-source mappings
- **TOML mappings** (`mappings/xtcp2.toml`): Go type → bit size, endianness (all Little Endian), struct sizes
- **Nix-pinned** to commit `a52e2f4` via `fetchFromGitHub`
- **15 new tests**: struct parsing for all 9 protocol types, type alias resolution, size constant extraction, snake_case conversion, array type handling, endianness mapping
- Curated protocols: 450→459, unit tests: 452→467, sources: 12→13→16

#### Netlink Message Coverage + Parser Fix (2026-04-20)

17 netlink message header structs mapped as curated protocols across 5 subsystems:

- **Route netlink** (8 protocols): NL_Route (rtmsg), NL_Link (ifinfomsg), NL_Addr (ifaddrmsg), NL_Neigh (ndmsg), NL_TC (tcmsg), NL_Rule (fib_rule_hdr), NL_Nexthop (nhmsg), NL_Prefix (prefixmsg)
- **Netfilter** (1): NL_Netfilter (nfgenmsg)
- **Diagnostics** (3): NL_Diag_Netlink, NL_Diag_Unix, NL_Diag_Inet (with nested inet_diag_sockid)
- **Bridge/DCB/Stats** (3): NL_Bridge_Port, NL_DCB, NL_IfStats
- **XFRM/IPsec** (2): NL_XFRM_SA (xfrm_usersa_info, 12 fields, 217 bytes with 6 nested structs/unions), NL_XFRM_Policy (xfrm_userpolicy_info, 9 fields, 164 bytes)
- **TOML expansion**: 7 new `[struct_sizes]` entries (xfrm_selector, xfrm_lifetime_cfg, xfrm_lifetime_cur, xfrm_stats, xfrm_id, inet_diag_sockid, ifla_bridge_id) + 1 new `[union_sizes]` entry (xfrm_address_t)
- **C type coverage**: Added `unsigned`, `unsigned int`, `int`, `unsigned short`, `short` to kernel.toml `[type_bits]`
- **Parser bug fix**: Step 0b comment-semicolon bug — semicolons inside `/* ... */` comments were triggering newline insertion in the body normalizer, splitting comment text into orphan lines that were parsed as fields. Fixed by tracking comment state in Step 0b. This affected all kernel structs with comments containing semicolons (e.g., `/* Routing protocol; see below */`).
- **2 new tests**: `test_strip_inline_comments_with_semicolon`, `test_rtmsg_all_fields_parsed` (9-field struct with inline comments containing semicolons)
- Kernel total: 92→109 structs, 450 curated protocols

#### Nested Struct/Union Expansion in Kernel Parser (2026-04-19)

The kernel C struct parser now handles nested types that were previously skipped:

- **Named union fields**: `union ib_gid sgid;` — resolved via content lookup or TOML `[union_sizes]` table. Previously skipped entirely (`if c_type == "union" { continue; }`).
- **Named struct fields**: `struct gre_base_hdr gre_hd;` — resolved from definition in same file content, falling back to TOML `[struct_sizes]`. Previously produced 0-bit fields that were silently dropped.
- **Anonymous inline unions**: `union { struct { ... } echo; __be32 gateway; } un;` — parsed inline with recursive field extraction, size computed as max of variants. Used by `icmphdr` and `icmp6hdr`.
- **Typedef support**: `typedef struct lacpdu { ... }` pattern now matched by `parse_kernel_struct()`.
- **Brace-aware parsing**: `parse_kernel_struct()` uses brace-counting instead of non-greedy regex (handles nested braces). Statement accumulator tracks brace depth so semicolons inside anonymous bodies don't split outer statements.
- **Content-aware resolution**: `resolve_nested_size()` recursively finds struct/union definitions in file content. `to_field_defs_with_content()` used by kernel, DPDK, and nDPI extractors. Max depth=4 prevents infinite recursion.
- **3 new kernel mappings**: IB_GRH (`ib_grh` with `union ib_gid`), PPTP (`pptp_gre_header` with nested `struct gre_base_hdr`), LACP (`lacpdu` via typedef with nested `struct mac_addr`). Kernel total: 84→92.
- **TOML expansion**: 4 new `[struct_sizes]` entries (gre_base_hdr, scsi_lun, port_identity, mac_addr) and new `[union_sizes]` section (ib_gid, nvme_data_ptr).
- **8 new tests**: nested struct resolution, nested union resolution, anonymous inline union, TOML fallback, recursion depth limit, unknown type skipping, typedef parsing, union via TOML.
- **Improved extraction for 5 existing protocols**: GRE_Cisco (+gre_hd 32 bits), iSCSI (+lun 64 bits), PTP (+source_port_id 80 bits), ICMPv4 (+un 32 bits), ICMPv6 (+icmp6_dataun 32 bits).

#### DPDK, nDPI, pppd Extractors + Kernel Expansion (2026-04-18)

Three new authoritative sources added as first-class extractors:

- **DPDK extractor** (`src/extractors/dpdk.rs`): Parses `rte_*_hdr` packed structs from DPDK `lib/net/` headers. Preprocessor normalizes `__rte_packed_begin/end`, `__rte_aligned(N)`, `__extension__`, and anonymous union/struct wrappers (drops aggregate members, keeps bitfield decompositions). 24 protocols mapped with `.dpdk(struct, file)` builder. Type mappings in `mappings/dpdk.toml`.
- **nDPI extractor** (`src/extractors/ndpi.rs`): Parses `ndpi_*` packed structs from `ndpi_typedefs.h`. Preprocessor normalizes `PACK_ON/OFF`, `__attribute__((packed))`, and BSD-style endian macros. 13 protocols mapped with `.ndpi(struct, file)` builder. Type mappings in `mappings/ndpi.toml`.
- **pppd extractor** (`src/extractors/pppd.rs`): Parses PPP control protocol structs from pppd source (LCP, IPCP, IPv6CP, CCP, CHAP, PAP). 7 protocols mapped with `.pppd(struct, file)` builder.
- **Kernel expansion**: 12 new kernel struct mappings added from Linux 6.12 source: CAN_XL, BATMAN, CFM, PPPoED, VXLAN_GPE, VXLAN_GBP, ERSPAN_V3, GENEVE_OPT, GRE_Cisco, BT_RFCOMM, IPv6_MobileIP, SCTP_Init. Kernel total: 74→84.
- **3 new DPDK-only protocols**: eCPRI, HiGig2, PDCP (protocols only defined in DPDK headers, not other sources).

Memory policy: prefer authoritative sources (kernel, DPDK, nDPI, pppd) over hand-written `embedded_proto` definitions.

#### Pipeline Expansion (2026-04-15 → 2026-04-18)

Pipeline coverage grew from 711/3424 (20.8%) to 1456/3448 (42.2%):
- Parallel matrix execution (rayon, `--workers N`)
- Auto-generate PCAP templates (65→196 templates)
- Hand-written embedded IR for 52 Bucket 1 protocols
- Bucket 3 sub-protocols (HCI, PPP, IB, CAN, BT variants)
- Bucket 5 tshark mapping fixes (TACACS, sFlow, SOCKS)
- STP variants (RSTP, PVST, MSTP)
- pdml_name_alias refactor for tshark dissector name normalization

#### Trading Protocol Expansion (3 Workstreams, 2026-04-13)

Three parallel expansions built on the OMI IR:

- **W1: OMI tshark coverage** — 3 EOBI v3 entries (OrderAdd, SnapshotOrder, Heartbeat) wired with the full `.omi()` + `.tshark()` + `.omi_tshark(lua, pcap, field)` triangle; per-entry roundtrip tests verify all 7 slots. Remaining ITCH v5 / PITCH v2 messages are blocked on missing sample PCAPs in omi-data-packets.
- **W2: IR → upstream patches** — New `gen-patches --target <libpcap|etherparse> --source omi` subcommand pipes OMI IR through the existing `generate_libpcap_patch` / `generate_etherparse_patch` generators. Produced 27 libpcap + 27 etherparse `trading_*.patch` files.
- **W3: XDP2 trading parse-nodes** — 16 leaf `proto_def`s added under `src/include/xdp2/proto_defs/trading/` (13 ITCH v5 + 3 PITCH v2). `trading` added to proto_defs Makefile SUBDIRS. `xdp2` extractor now prefers the curated `.xdp2()` name-table var before falling back to fuzzy matching, so canonical names like `ITCH_v5_AddOrder` resolve. Field lists remain empty (Phase A); char-based dispatch DSL (Phase B) and OMI-sourced field layouts (Phase C) are deferred.

#### OMI as 9th Source (earlier, 2026-04)

- Added OMI extractor (`src/extractors/omi.rs`) consuming Open Markets Initiative c-structs and Wireshark Lua dissectors.
- Name-table builders `.omi(struct, file)`, `.tshark(lua_file)`, `.omi_tshark(lua, pcap, field)`.
- OMI PCAPs added to `pcapCorpus`; OMI Lua dissectors loaded into tshark for per-message field extraction.

#### Kaitai & Suricata Curated Integration (8 Sources)

Added Kaitai Struct and Suricata as first-class curated sources with fields in `ProtocolNames`:
- 12 protocols with curated Kaitai mappings (Ethernet, IPv4, IPv6, TCP, UDP, ARP, ICMPv4, DNS, VLAN, RTP, RTCP)
- 20 protocols with curated Suricata mappings (DNS, NTP, SNMP, DHCP, QUIC, HTTP2, SSH, MQTT, etc.)
- Builder methods `.kaitai(id, file)` and `.suricata(module, struct_name)` on `ProtocolNames`
- Curated lookup functions `find_by_kaitai_id()` and `find_by_suricata_struct()`
- `try_extract()` uses curated lookups with dynamic fallback for non-curated protocols

#### Cross-Generator Round-Trip (`crossgen` command)

New `crossgen` command closes the generate→re-extract loop for all code generators:
- **etherparse round-trip**: generate Rust struct → parse struct → compare to IR
- **C round-trip**: generate C header → parse struct → compare to IR
- **Scapy round-trip**: generate Python class → run through scapy_dump.py → compare
- **PCAP round-trip**: delegates to existing `validate` infrastructure
- Batch mode: `crossgen --proto all --target all` runs all combinations
- 9 new cross-generator tests in `crossgen_tests.rs`

#### Corpus Cross-Source Parsing (`corpus-parse` command)

New `corpus-parse` command parses the same PCAP through tshark and Scapy, comparing field values:
- Value-level comparison with hex/integer normalization (`compare_field_values()`)
- Per-layer agreement/disagreement reporting
- Supports single PCAP or directory of PCAPs

#### PCAP Template Expansion (48 → 62)

Added 14 new PCAP templates: LLDP, CDP, STP, EAPOL, EAP, CoAP, HSRP, PTP, TFTP, Syslog, NBNS, MGCP, OpenFlow, BFD.

#### Gold Promotion (85 → 112)

27 additional protocols promoted to Gold through PCAP template additions and tshark name mapping fixes.

#### Earlier Changes

##### Round-Trip Validation Fixes (Gold: 2 → 36)

Fixed two bugs preventing PCAP round-trip validation for most protocols:

1. **Canonical naming**: Scapy/tshark extractors returned ProtocolDef with source-native names (e.g., "IP" instead of "IPv4"). Stack route lookups failed because STACK_ROUTES uses canonical names. Fix: set `def.name = proto.to_string()` after extraction.

2. **Embedded proto priority**: `resolve_proto` in pcap.rs preferred extracted IR (kernel Ethernet with `h_proto` field) over embedded protos (with `ether_type` field matching STACK_ROUTES dispatch). Fix: prefer embedded protos.

##### Scapy Batch Cache for Curated Audits

Enabled the Scapy batch cache (`--dump-all`, 4,970 classes) for curated protocol audits. Previously only used for discovered-tier audits, leaving curated Scapy extraction to per-protocol subprocess calls that silently failed.

##### Scapy Class Name Fixes

- WireGuard: `WireGuard` → `Wireguard` (case mismatch in Scapy)
- HTTP2: `HTTP2` → `H2Frame` (actual Scapy class name)

##### Scapy Contrib Imports

Added missing imports for GTP, HomePlug_AV, HTTP2, and TLS record layer — enabling field extraction for 4 more protocols.

### Iteration History

| Iter | Key Change | Protocols | Tests |
|------|------------|-----------|-------|
| 33 | Full Rust coverage: 529 ProtocolOps (100% Gold/Silver/Bronze), 73 canonical name fixes, check-rs CI gate passes | 567 | 517 |
| 32 | 50 SCSI/SAS/FC storage protocols, 23 ML/HPC protocols | 542 | 509 |
| 31 | xtcp2 Go structs, 17 netlink messages, PCAP template expansion, Gold 206→333 | 459 | 467 |
| 30 | 17 netlink message structs (5 subsystems), comment-semicolon parser fix, C type coverage expansion | 450 | 452 |
| 29 | Nested struct/union expansion, 3 new kernel mappings (IB_GRH, PPTP, LACP), typedef support | 431 | 450 |
| 28 | DPDK/nDPI/pppd extractors, 12 new kernel mappings, 3 DPDK-only protos | 431 | 442 |
| 27 | Bucket 3 sub-protocols, Bucket 5 mapping fixes, STP variants, pipeline 42.2% | 428 | 420 |
| 26 | Batch 2 embedded_proto defs, tshark alias hints, 182 templates | 428 | 420 |
| 25 | Hand-written IR Batch 1 (26 protocols), embedded_proto fallback | 428 | 420 |
| 24 | Parallel matrix (rayon), auto-generate 65 templates, ICMPv4 fixed | 428 | 420 |
| 23 | Pipeline-matrix + comparator, IPv4/IPv6 fixups, Gold 112→206 | 428 | 420 |
| 22 | Cross-generator round-trip + corpus cross-parse commands | 206 | 400 |
| 21 | Kaitai & Suricata curated integration (8 sources) | 206 | 400 |
| 20 | Gold promotion campaign (Gold 85→112), 62 PCAP templates | 206 | 400 |
| 19 | Suricata as 8th source, 48 PCAP templates, 390 tests | 206 | 390 |
| 18 | Round-trip validation fixes (Gold 2→36) | 206 | 378 |
| 17 | Scapy batch cache + class name fixes | 206 | 378 |
| 16 | Universal PCAP generation (205/206 routable) | 206 | 321 |
| 15 | PCAP route expansion (12→120 routable) | 206 | 293 |
| 14 | PCAP generation + validate command | 206 | 172 |
| 13 | Comprehensive Scapy coverage (109/113) | 113 | 122 |
| 12 | Storage & network storage protocols | 114 | 110 |
| 11 | Multicast, media, embedded structs | 105 | 110 |
| 10 | UDP application protocols | 97 | 109 |
| 9 | Bluetooth + InfiniBand extended | 90 | 109 |
| 8 | Routing & redundancy | 77 | 107 |
| 7 | 28 protocols: UAPI, BT, industrial, legacy | 69 | 107 |
| 6 | etherparse as 5th source | 41 | 107 |
| 5 | Roundtrip & cross-mapping tests | 41 | 93 |
| 4 | Expanded type overrides, cross-source tests | 41 | 71 |
| 3 | TOML-based type mapping system | 41 | — |
| 2 | Zero-field filtering, scapy contrib imports | 41 | — |
| 1 | Structural vs semantic separation, matrix CLI | 41 | — |

### Known Remaining Issues

**Scapy field sizes for ARP** — Scapy's ARP uses `FieldLenField` with a default
hardware address length of 2 bytes (16 bits) rather than 6, since the field
length is protocol-dependent (`ar_hln`). This causes `hwsrc`/`hwdst` to show as
16 bits vs tshark's 48 bits. Not a bug — it reflects ARP's variable-length design.

**tshark combined fields** — tshark sometimes reports combined fields (e.g.,
`ip.version` as 8 bits covering both version and IHL, `tcp.flags` as 16 bits
covering data offset + reserved + flags). These are display artifacts of PDML's
byte-aligned output, not real protocol disagreements.

**IEEE 802.11 offset drift** — kernel's `ieee80211_hdr` and scapy's `Dot11`
disagree on field offsets because scapy includes sub-byte fields (subtype, type,
proto) that the kernel packs into `frame_control`. The cumulative offset drift
causes all subsequent MAC address fields to misalign.

**ICMPv4 scapy extra fields** — Scapy defines 17 fields for ICMP (including
message-type-specific payload fields like `id`, `seq`, `ts_ori`, etc.) vs
kernel's 4-field `icmphdr`. This is expected — the kernel struct is minimal
and message-specific fields are handled elsewhere.

**TLS stays Bronze** — Despite having Scapy fields, tshark reports a single
`tls.record` field at offset 0 spanning 840 bits that overlaps with all
individual fields. No structural agreement possible.
