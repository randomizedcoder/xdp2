# Upstream Contribution Guide for Trading Protocols

proto-audit generates trading-protocol definitions from OMI (Open Markets
Initiative) c-structs and can emit artifacts suitable for upstream
contribution to multiple open-source projects. This document describes the
contribution targets, generated artifacts, and submission workflow for each.

## Source Coverage

The OMI IR currently covers ~27 trading protocol messages across 5 feeds:

| Feed | Messages | Endianness |
|------|----------|------------|
| Nasdaq ITCH v5.0 | 13 (SystemEvent, StockDirectory, AddOrder, OrderExecuted, ...) | Big |
| CBOE PITCH v2.x | 3 (AddOrderShort, AddOrderLong, OrderExecuted) | Big |
| CME SBE MDP3 v1.12 | 2 (MessageHeader, BinaryPacketHeader) | Little |
| Eurex EOBI v3.0 | 4 (TradeReport, OrderAdd, SnapshotOrder, Heartbeat) | Little |
| SoupBinTCP | 5 (PacketHeader, LoginRequest, LoginAccepted, LoginRejected, SequencedData) | Big |

## Generating Artifacts

### Internal overlay patches (already in tree)

```bash
# libpcap C header overlays (332 total, 27 trading)
nix run .#proto-audit -- gen-patches --target libpcap --source omi

# etherparse Rust struct overlays (332 total, 27 trading)
nix run .#proto-audit -- gen-patches --target etherparse --source omi

# Scapy Python Packet classes (27 trading)
nix run .#proto-audit -- gen-patches --target scapy --source omi

# Kaitai Struct .ksy files (27 trading)
nix run .#proto-audit -- gen-patches --target kaitai --source omi
```

These write to `patches/{libpcap,etherparse,scapy,kaitai}/trading_*.patch`.

### Cross-generator round-trip verification

Before contributing upstream, verify that the generated code round-trips:

```bash
# Scapy: generate class → load in Scapy → re-extract fields → compare to IR
nix run .#proto-audit -- cross-gen --proto ITCH_v5_AddOrder --target scapy

# Kaitai: generate .ksy → parse YAML → re-extract fields → compare to IR
nix run .#proto-audit -- cross-gen --proto ITCH_v5_AddOrder --target kaitai

# All targets at once
nix run .#proto-audit -- cross-gen --proto ITCH_v5_AddOrder --target all
```

## Upstream Target: Scapy

**Repository**: [secdev/scapy](https://github.com/secdev/scapy)
**Fit**: Strong. Scapy's `contrib/` directory carries many niche/industry
protocols (CAN, OPC-UA, ENIP, etc.). Trading protocol dissectors are a
natural addition.

### What to submit

A contrib module (e.g., `scapy/contrib/itch_v5.py`) containing:
- Module-level metadata comments required by Scapy:
  ```python
  # SPDX-License-Identifier: GPL-2.0-only
  # scapy.contrib.description = Nasdaq ITCH v5.0 Protocol
  # scapy.contrib.status = loads
  ```
- Packet classes for each message type (AddOrder, SystemEvent, etc.)
- `bind_layers()` calls linking SoupBinTCP → ITCH message dispatch (if
  the SoupBinTCP wrapper is also contributed)
- Unit tests in `test/contrib/test_itch_v5.py`

### Preparation steps

1. Copy generated classes from `patches/scapy/trading_itch_v5_*.patch`
2. Combine per-message classes into one `contrib/itch_v5.py` module
3. Add Scapy-style metadata headers and GPLv2 license
4. Add `bind_layers()` for SoupBinTCP → ITCH message type dispatch
5. Write tests using `scapy.utils.rdpcap()` with OMI sample PCAPs
6. Submit PR to secdev/scapy following their contribution guide

## Upstream Target: Kaitai Struct Formats

**Repository**: [kaitai-io/kaitai_struct_formats](https://github.com/kaitai-io/kaitai_struct_formats)
**Fit**: Strong. The repository's `network/` directory already has Ethernet,
IPv4, TCP, UDP, DNS, and many others. Adding trading-protocol .ksy files
follows the same pattern.

### What to submit

Individual `.ksy` files per protocol message, e.g.,
`network/itch_v5_add_order.ksy`, with:
- `meta.license: CC0-1.0` (matching the repo standard)
- `meta.xref` pointing to the OMI specification or relevant exchange docs
- `doc-ref` with URLs to specification PDFs where available
- Field-level `doc:` annotations explaining each wire field

### Preparation steps

1. Copy generated .ksy files from `patches/kaitai/trading_*.patch`
   (extract the content after `+++ b/` lines)
2. Add `meta.xref` and `doc-ref` sections pointing to exchange specs
3. Verify with `kaitai-struct-compiler --target python <file>.ksy`
4. Submit PR to kaitai-io/kaitai_struct_formats

## Upstream Target: Wireshark / tshark

**Repository**: [wireshark/wireshark](https://gitlab.com/wireshark/wireshark)
**Fit**: Plausible but more complex. Wireshark accepts new protocol
dissectors as C code in `epan/dissectors/`.

### Current state

OMI already ships Wireshark Lua dissectors for all 5 feeds. These are
loadable by tshark and proto-audit uses them via the `.omi_tshark()` pipeline.
Two possible contribution paths exist:

1. **Advocate for OMI Lua inclusion** — The OMI project owns the Lua
   dissectors. Getting them included in Wireshark's Lua plugin distribution
   (or listed in the wiki's third-party plugin page) is the simplest path.
   This is an OMI-project action, not a proto-audit action.

2. **Convert Lua to C epan dissectors** — For highest performance and
   deeper integration (display filters, statistics, etc.), converting OMI's
   Lua dissectors to C is the gold standard. This is substantially more
   work: each dissector needs `proto_register_*()`, `dissect_*()`,
   preference settings, and test captures. A future `gen-patches --target
   wireshark-c` could produce skeleton C dissectors from IR, but
   field-by-field registration requires manual work.

### Not recommended for upstream

- **libpcap**: Focuses on L2–L4 capture-level parsing. Trading protocols
  are application-layer; libpcap maintainers are unlikely to accept them
  without a dedicated `contrib/` directory conversation.
- **etherparse**: Focuses on L2–L4 Rust packet parsing. Same scope
  constraint as libpcap.
- **Linux kernel UAPI**: Trading protocols are user-space only.
- **Suricata**: IDS/IPS engine; trading protocols don't fit the threat
  detection model unless for market surveillance use cases.

## Regenerating After IR Changes

When new trading protocols are added to the name-mapping table or OMI
c-struct parsing is improved:

```bash
# Regenerate all trading patches
for target in libpcap etherparse scapy kaitai; do
  nix run .#proto-audit -- gen-patches --target $target --source omi \
      --out samples/proto_audit/patches/$target/
done

# Verify round-trips still pass
for proto in ITCH_v5_AddOrder SBE_MDP3_MessageHeader EOBI_v3_OrderAdd; do
  nix run .#proto-audit -- cross-gen --proto $proto --target all
done
```
