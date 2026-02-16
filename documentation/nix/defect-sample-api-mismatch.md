# Defect: Sample Code API Mismatch with XDP2 Headers

**Status:** RESOLVED
**Severity:** High (samples do not compile)
**Date:** 2026-02-09
**Found By:** Nix sample test development
**Resolved:** 2026-02-11 - Samples updated to use current XDP2 API

## Summary

The sample code in `samples/parser/` and `samples/xdp/flow_tracker_combo/` uses an
outdated XDP2 API that no longer exists in the current header files. The samples
reference structures, macros, and function signatures that are not defined anywhere
in the codebase.

## Affected Files

### Sample Files Using Outdated API

| File | Line | Issue |
|------|------|-------|
| `samples/parser/simple_parser/run_parser.h` | 35 | `struct xdp2_packet_data pdata;` - struct not defined |
| `samples/parser/simple_parser/run_parser.h` | 46-47 | `XDP2_SET_BASIC_PDATA_LEN_SEQNO()` - macro not defined |
| `samples/parser/simple_parser/run_parser.h` | 49 | `xdp2_parse(parser, &pdata, &metadata, 0);` - wrong signature (4 args vs 6) |
| `samples/parser/offset_parser/parser.c` | 111 | `struct xdp2_packet_data pdata;` |
| `samples/parser/offset_parser/parser.c` | 122-123 | `XDP2_SET_BASIC_PDATA_LEN_SEQNO()` |
| `samples/parser/offset_parser/parser.c` | 125 | `xdp2_parse(parser, &pdata, &metadata, 0);` |
| `samples/parser/ports_parser/parser.c` | 112 | `struct xdp2_packet_data pdata;` |
| `samples/parser/ports_parser/parser.c` | 123-124 | `XDP2_SET_BASIC_PDATA_LEN_SEQNO()` |
| `samples/parser/ports_parser/parser.c` | 126 | `xdp2_parse(my_parser, &pdata, &metadata, 0);` |
| `samples/xdp/flow_tracker_combo/flow_parser.c` | 53 | `struct xdp2_packet_data pdata;` |
| `samples/xdp/flow_tracker_combo/flow_parser.c` | 64-65 | `XDP2_SET_BASIC_PDATA_LEN_SEQNO()` |
| `samples/xdp/flow_tracker_combo/flow_parser.c` | 66 | `xdp2_parse(parser, &pdata, metadata, 0);` |

### Header File with Current API

| File | Line | Current Definition |
|------|------|-------------------|
| `src/include/xdp2/parser.h` | 296-300 | `xdp2_parse()` function signature |
| `src/include/xdp2/parser.h` | 328-334 | `XDP2_CTRL_SET_BASIC_PKT_DATA()` macro |

## Missing Symbols

### 1. `struct xdp2_packet_data`

**Used in samples:** Lines 35, 111, 112, 53 (see table above)

**Status:** Not defined anywhere in `src/include/`

**Search performed:**
```bash
grep -rn "struct xdp2_packet_data" src/include/
# Returns: no results
```

### 2. `XDP2_SET_BASIC_PDATA_LEN_SEQNO` macro

**Used in samples:** Lines 46, 122, 123, 64 (see table above)

**Status:** Not defined anywhere in `src/include/`

**Search performed:**
```bash
grep -rn "XDP2_SET_BASIC_PDATA" src/include/
# Returns: no results
```

**Possibly replaced by:** `XDP2_CTRL_SET_BASIC_PKT_DATA` (parser.h:328)

### 3. `xdp2_parse()` function signature mismatch

**Sample code expects (4 arguments):**
```c
// samples/parser/simple_parser/run_parser.h:49
xdp2_parse(parser, &pdata, &metadata, 0);
```

**Current API requires (6 arguments):**
```c
// src/include/xdp2/parser.h:296-300
static inline int xdp2_parse(const struct xdp2_parser *parser,
                             void *hdr, size_t len,
                             void *metadata,
                             struct xdp2_ctrl_data *ctrl,
                             unsigned int flags)
```

## Compiler Errors

When building `samples/parser/simple_parser`:

```
run_parser.h:35:33: error: storage size of 'pdata' isn't known
   35 |         struct xdp2_packet_data pdata;
      |                                 ^~~~~

run_parser.h:46:17: error: implicit declaration of function 'XDP2_SET_BASIC_PDATA_LEN_SEQNO'
   46 |                 XDP2_SET_BASIC_PDATA_LEN_SEQNO(pdata, packet, plen,
      |                 ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

run_parser.h:49:44: error: passing argument 3 of 'xdp2_parse' makes integer from pointer without a cast
   49 |                 xdp2_parse(parser, &pdata, &metadata, 0);
      |                                            ^~~~~~~~~

run_parser.h:49:17: error: too few arguments to function 'xdp2_parse'; expected 6, have 4
   49 |                 xdp2_parse(parser, &pdata, &metadata, 0);
      |                 ^~~~~~~~~~
```

## Git History Analysis

### Timeline

| Date | Commit | Description |
|------|--------|-------------|
| 2025-09-05 | `f1d1d1c` | `samples: Simple parser example` - sample added |
| 2025-09-05 | `4616620` | `samples: Offset parser example` - sample added |
| 2025-09-09 | `704fe84` | `samples: Fixe typo in simple parser sample` |
| 2025-09-15 | `aa85c51` | `samples: Ports parser example` - sample added |
| **2025-09-30** | **`4e14212`** | **`parser: Updates and API changes to parser`** - API CHANGED |
| 2025-10-02 | `d3cbba4` | `samples: Add Makefile support for outputting json` - Makefile only |
| 2025-10-11 | `09fbcb5` | `samples: Add README.md in smaples` - README only |

### Key Finding

**The samples were created BEFORE the API change and were never updated afterward.**

- Samples added: September 5-15, 2025
- API changed: September 30, 2025 (commit `4e14212`)
- No C code changes to samples after API change

### The API Change Commit

Commit `4e14212` by Tom Herbert on 2025-09-30:

```
parser: Updates and API changes to parser

- Remove op.len_maxlen protocol definition argument
- Change arguments of __xdp2_parse to include a hdr pointer
  and length (as opposed to these being in control data
- Add xdp2_parse_fast
- Add xdp2_parse_validate_fast to test if xdp_parse_fast can
  be called for a parser
- Change parser_entry_point arguments to include a header pointer
  and headers length (as opposed to those being in control data)
- Change metadata and handler functions to take header pointer,
  header length, and an offset in lieue of those being in
  control data
- Add metadata argumrent to internal parser functions that
  take a frame argument
- Take hdr_len and hdr_offest out of the control data structure,
  these are now passed as explicit function arguments
```

Files changed:
- `src/include/xdp2/flag_fields.h`
- `src/include/xdp2/parser.h` (62 lines changed)
- `src/include/xdp2/parser_types.h` (64 lines changed)
- `src/include/xdp2/tlvs.h`
- `src/lib/xdp2/parser.c` (358 lines changed)

## Hypotheses

### Hypothesis 1: API Refactoring Not Applied to Samples — CONFIRMED

The XDP2 parser API was refactored in commit `4e14212` (2025-09-30):
- `struct xdp2_packet_data` → replaced with `struct xdp2_ctrl_data` and separate packet data
- `XDP2_SET_BASIC_PDATA_LEN_SEQNO()` → replaced with `XDP2_CTRL_SET_BASIC_PKT_DATA()`
- `xdp2_parse(parser, pdata, metadata, flags)` → `xdp2_parse(parser, hdr, len, metadata, ctrl, flags)`

**The samples were added 25 days before the API change and were never updated afterward.**

**Evidence:**
- Git history shows samples added September 5-15, 2025
- API change commit `4e14212` dated September 30, 2025
- Only Makefile and README changes to samples after API change (no C code updates)
- `XDP2_CTRL_SET_BASIC_PKT_DATA` exists in parser.h:328 as the replacement macro

### Hypothesis 2: Samples From Different Branch/Version — RULED OUT

The samples were created in the same repository timeline, just before the API change.
They are not from a different branch or version.

### Hypothesis 3: Missing Header File — RULED OUT

There is no missing header file. The old API was simply replaced by the new API,
and the samples were not updated to use the new API.

## Recommended Fix

Update all affected sample files to use the current API:

1. Replace `struct xdp2_packet_data pdata;` with:
   ```c
   struct xdp2_ctrl_data ctrl;
   ```

2. Replace `XDP2_SET_BASIC_PDATA_LEN_SEQNO(pdata, packet, plen, packet, len, i);` with:
   ```c
   XDP2_CTRL_SET_BASIC_PKT_DATA(&ctrl, packet, plen, i);
   ```

3. Replace `xdp2_parse(parser, &pdata, &metadata, 0);` with:
   ```c
   xdp2_parse(parser, packet, plen, &metadata, &ctrl, 0);
   ```

## Impact

- **All userspace parser samples are broken** and cannot be compiled
- **flow_tracker_combo XDP sample** has same issue in userspace portion
- **Nix sample tests** cannot be implemented until this is fixed
- **Documentation** shows expected output that cannot be reproduced

## Test to Verify Fix

After fixing, samples should compile and produce output matching README examples:

```bash
cd samples/parser/simple_parser
make XDP2DIR=~/xdp2/src
./parser_notmpl ~/xdp2/data/pcaps/tcp_ipv6.pcap
# Should output: "IPv6: ...", "TCP timestamps value: ...", "Hash ..."
```
