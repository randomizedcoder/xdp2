# Fix Plan: Update Samples to Current XDP2 API

## Overview

This document provides a detailed, line-by-line plan to update the parser samples
to use the current XDP2 API.

## API Mapping

### Old API → New API

| Old Symbol | New Symbol | Location |
|------------|------------|----------|
| `struct xdp2_packet_data` | `struct xdp2_ctrl_data` | `parser_types.h:184` |
| `XDP2_SET_BASIC_PDATA_LEN_SEQNO(pdata, pkt, plen, pkt, len, seq)` | `XDP2_CTRL_SET_BASIC_PKT_DATA(&ctrl, pkt, plen, seq)` | `parser.h:328` |
| `xdp2_parse(parser, &pdata, &metadata, flags)` | `xdp2_parse(parser, packet, plen, &metadata, &ctrl, flags)` | `parser.h:296` |

### New Function Signature

```c
// parser.h:296-300
static inline int xdp2_parse(const struct xdp2_parser *parser,
                             void *hdr,           // packet data pointer
                             size_t len,          // packet length
                             void *metadata,      // metadata structure
                             struct xdp2_ctrl_data *ctrl,  // control data
                             unsigned int flags)  // flags
```

### New Macro Signature

```c
// parser.h:328-335
#define XDP2_CTRL_SET_BASIC_PKT_DATA(CTRL, PACKET, LENGTH, SEQNO)
```

Note: The new macro takes 4 arguments vs the old 6 arguments. The old API had
redundant packet/length parameters.

---

## File-by-File Fix Plan

### File 1: `samples/parser/simple_parser/run_parser.h`

#### Change 1: Line 35 - Replace struct declaration

**Before:**
```c
struct xdp2_packet_data pdata;
```

**After:**
```c
struct xdp2_ctrl_data ctrl;
```

#### Change 2: Lines 46-47 - Replace macro call

**Before:**
```c
XDP2_SET_BASIC_PDATA_LEN_SEQNO(pdata, packet, plen,
                               packet, len, i);
```

**After:**
```c
XDP2_CTRL_SET_BASIC_PKT_DATA(&ctrl, packet, plen, i);
```

#### Change 3: Line 49 - Replace xdp2_parse call

**Before:**
```c
xdp2_parse(parser, &pdata, &metadata, 0);
```

**After:**
```c
xdp2_parse(parser, packet, plen, &metadata, &ctrl, 0);
```

---

### File 2: `samples/parser/offset_parser/parser.c`

#### Change 1: Line 111 - Replace struct declaration

**Before:**
```c
struct xdp2_packet_data pdata;
```

**After:**
```c
struct xdp2_ctrl_data ctrl;
```

#### Change 2: Lines 122-123 - Replace macro call

**Before:**
```c
XDP2_SET_BASIC_PDATA_LEN_SEQNO(pdata, packet, plen,
                               packet, len, i);
```

**After:**
```c
XDP2_CTRL_SET_BASIC_PKT_DATA(&ctrl, packet, plen, i);
```

#### Change 3: Line 125 - Replace xdp2_parse call

**Before:**
```c
xdp2_parse(parser, &pdata, &metadata, 0);
```

**After:**
```c
xdp2_parse(parser, packet, plen, &metadata, &ctrl, 0);
```

---

### File 3: `samples/parser/ports_parser/parser.c`

#### Change 1: Line 112 - Replace struct declaration

**Before:**
```c
struct xdp2_packet_data pdata;
```

**After:**
```c
struct xdp2_ctrl_data ctrl;
```

#### Change 2: Lines 123-124 - Replace macro call

**Before:**
```c
XDP2_SET_BASIC_PDATA_LEN_SEQNO(pdata, packet, plen,
                               packet, len, i);
```

**After:**
```c
XDP2_CTRL_SET_BASIC_PKT_DATA(&ctrl, packet, plen, i);
```

#### Change 3: Line 126 - Replace xdp2_parse call

**Before:**
```c
xdp2_parse(my_parser, &pdata, &metadata, 0);
```

**After:**
```c
xdp2_parse(my_parser, packet, plen, &metadata, &ctrl, 0);
```

---

### File 4: `samples/xdp/flow_tracker_combo/flow_parser.c`

#### Change 1: Line 53 - Replace struct declaration

**Before:**
```c
struct xdp2_packet_data pdata;
```

**After:**
```c
struct xdp2_ctrl_data ctrl;
```

#### Change 2: Lines 64-65 - Replace macro call

**Before:**
```c
XDP2_SET_BASIC_PDATA_LEN_SEQNO(pdata, packet, len, packet,
                               len, seqno++);
```

**After:**
```c
XDP2_CTRL_SET_BASIC_PKT_DATA(&ctrl, packet, len, seqno++);
```

Note: This file uses `len` for both packet length arguments (looks like a bug
in the original - should probably use `plen` for wire length).

#### Change 3: Line 66 - Replace xdp2_parse call

**Before:**
```c
xdp2_parse(parser, &pdata, metadata, 0);
```

**After:**
```c
xdp2_parse(parser, packet, len, metadata, &ctrl, 0);
```

---

## Summary of Changes

| File | Lines Changed | Changes |
|------|---------------|---------|
| `samples/parser/simple_parser/run_parser.h` | 35, 46-47, 49 | 3 changes |
| `samples/parser/offset_parser/parser.c` | 111, 122-123, 125 | 3 changes |
| `samples/parser/ports_parser/parser.c` | 112, 123-124, 126 | 3 changes |
| `samples/xdp/flow_tracker_combo/flow_parser.c` | 53, 64-65, 66 | 3 changes |
| **Total** | | **12 changes in 4 files** |

## Verification Steps

After applying fixes:

1. Build simple_parser:
   ```bash
   cd samples/parser/simple_parser
   make clean
   make XDP2DIR=../../../src
   ```

2. Run test:
   ```bash
   export LD_LIBRARY_PATH=../../../src/lib
   ./parser_notmpl ../../../data/pcaps/tcp_ipv6.pcap
   ```

3. Expected output should include:
   - `IPv6: ::1:51648->::1:631`
   - `TCP timestamps value: ...`
   - `Hash ...`

4. Repeat for offset_parser and ports_parser.

## Implementation Order

1. Fix `run_parser.h` first (shared by simple_parser)
2. Fix `offset_parser/parser.c`
3. Fix `ports_parser/parser.c`
4. Fix `flow_tracker_combo/flow_parser.c`
5. Test each after fixing
