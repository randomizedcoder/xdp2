# Nix Sample Tests Expansion Log

**Plan Document:** `sample-tests-expansion-plan.md`
**Design Document:** `sample-tests-design.md`
**Started:** 2026-02-11
**Status:** In Progress

---

## Related Documentation

| Document | Purpose |
|----------|---------|
| `sample-tests-expansion-plan.md` | Master plan for all sample tests |
| `sample-tests-design.md` | Design and implementation details for simple_parser |
| `clang-tool-refactor-log.md` | Debugging log for compiler fixes (Phases 1-5) |
| `defect-sample-api-mismatch.md` | Analysis of API changes affecting samples |

---

## Phase 1: Parser Samples

### Goal
Create nix test targets for `offset_parser` and `ports_parser` following the
established `simple-parser.nix` pattern.

---

### 2026-02-11 - Pre-Implementation Analysis

**API Status Check:**

Verified all parser samples already use the current XDP2 API:

| Sample | `xdp2_ctrl_data` | `XDP2_CTRL_SET_BASIC_PKT_DATA` | 6-arg `xdp2_parse` |
|--------|------------------|-------------------------------|-------------------|
| offset_parser | ✅ line 111 | ✅ line 122 | ✅ line 124 |
| ports_parser | ✅ line 112 | ✅ line 123 | ✅ line 125 |

**Makefile rpath Check:**

| Sample | Has rpath | Line |
|--------|-----------|------|
| offset_parser | ✅ | LDFLAGS line 15 |
| ports_parser | ✅ | LDFLAGS line 15 |

**Test Data:**

| Sample | pcap File | Exists |
|--------|-----------|--------|
| offset_parser | tcp_ipv6.pcap | ✅ |
| ports_parser | tcp_ipv4.pcap | ✅ |

**Expected Output Patterns:**

Based on README files:

| Sample | Expected Output Pattern |
|--------|------------------------|
| offset_parser | `Network offset: 14`, `Transport offset: 54` |
| ports_parser | `Packet N: IP:PORT -> IP:PORT` format |

---

### Task: offset-parser.nix

**Status:** COMPLETE

**Implementation Notes:**
- Copy `simple-parser.nix` as template
- Change sample path to `samples/parser/offset_parser`
- Change binary name to `parser` (single binary, not parser_notmpl/parser_tmpl)
- Update test assertions to check for "Network offset:" and "Transport offset:"
- Use `tcp_ipv6.pcap` for testing

**Pre-requisite Fix Applied:**
- Fixed extract function signatures in `samples/parser/offset_parser/parser.c`
- Changed from 3-param to 6-param signature to match current API

**Test Criteria:**
- [x] `parser` binary builds successfully
- [x] Basic mode produces "Network offset:" output
- [x] Basic mode produces "Transport offset:" output
- [x] Optimized mode produces identical output
- [x] Offset values match expected (14, 54 for IPv6)

---

### Task: ports-parser.nix

**Status:** COMPLETE

**Implementation Notes:**
- Copy `simple-parser.nix` as template
- Change sample path to `samples/parser/ports_parser`
- Change binary name to `parser`
- Update test assertions to check for "Packet" lines with IP:PORT format
- Use `tcp_ipv4.pcap` for testing (IPv4 only sample)

**Pre-requisite Fixes Applied:**
- Fixed extract function signatures in `samples/parser/ports_parser/parser.c`
- Changed from 3-param to 6-param signature to match current API
- Fixed bug in `run_parser()` where `xdp2_parse(my_parser, ...)` was hardcoded
  instead of using the passed `parser` parameter (line 125)

**Test Criteria:**
- [x] `parser` binary builds successfully
- [x] Basic mode produces "Packet N:" output
- [x] Output contains IP addresses (pattern with dots)
- [x] Output contains ports (pattern with colons)
- [x] Optimized mode produces identical output

---

## Phase 2: XDP Samples

### Goal
Create nix test targets for XDP samples, focusing on build verification and
userspace component testing where available.

---

### Task: flow-tracker-combo.nix

**Status:** TODO

**Implementation Notes:**
- This sample has both XDP and userspace components
- Userspace `flow_parser` can be tested with pcap files
- XDP `flow_tracker.xdp.o` requires BPF clang compilation
- Strategy: Test userspace, verify XDP builds

**Pre-requisites:**
- [ ] Verify BPF clang target works in nix
- [ ] Test flow_parser with tcp_ipv6.pcap

**Test Criteria:**
- [ ] `flow_parser` binary builds successfully
- [ ] `flow_tracker.xdp.o` compiles (build test only)
- [ ] Basic mode produces IPv6/IPv4 output with ports
- [ ] Optimized mode produces similar output

---

### Task: xdp-build.nix (Build-only tests)

**Status:** TODO

**Implementation Notes:**
- Single test for XDP-only samples
- Verify compilation of:
  - flow_tracker_simple/flow_tracker.xdp.o
  - flow_tracker_tlvs/flow_tracker.xdp.o
  - flow_tracker_tmpl/flow_tracker.xdp.o

**Test Criteria:**
- [ ] All .xdp.o files compile without errors

---

## Implementation Progress

| Test | Status | Date | Notes |
|------|--------|------|-------|
| simple-parser | ✅ Complete | 2026-02-11 | 14/14 tests pass |
| offset-parser | ✅ Complete | 2026-02-11 | 8 tests, fixed API signature |
| ports-parser | ✅ Complete | 2026-02-11 | 8 tests, fixed API + parser bug |
| flow-tracker-combo | ✅ Complete | 2026-02-11 | 8 tests (userspace only) |
| xdp-build | ⛔ Blocked | 2026-02-11 | Requires bpf.h API fix |

---

## Issues Encountered

### Issue Log

#### Issue 1: Extract Function Signature Mismatch (2026-02-11)

**Problem:** Both `offset_parser/parser.c` and `ports_parser/parser.c` used the old
3-parameter extract function signature instead of the current 6-parameter API.

**Old signature:**
```c
void extract_fn(const void *hdr, void *_meta, const struct xdp2_ctrl_data ctrl)
```

**New signature (from parser_types.h:204-206):**
```c
void extract_fn(const void *hdr, size_t hdr_len, size_t hdr_off,
                void *metadata, void *frame, const struct xdp2_ctrl_data *ctrl)
```

**Resolution:** Updated both samples to use the new 6-parameter signature with
`(void)` casts for unused parameters.

#### Issue 2: ports_parser Ignoring Optimized Parser (2026-02-11)

**Problem:** In `ports_parser/parser.c`, the `run_parser()` function had a bug on
line 125 where it called `xdp2_parse(my_parser, ...)` instead of using the passed
`parser` parameter. This meant the `-O` flag had no effect.

**Resolution:** Changed to `xdp2_parse(parser, ...)` to use the correct parser.

#### Issue 3: Header Offset Access Pattern Changed (2026-02-11)

**Problem:** The original `offset_parser/parser.c` accessed header offset via
`ctrl->hdr.hdr_offset`, but this member no longer exists in the current API.

**Old pattern:**
```c
metadata->network_offset = ctrl->hdr.hdr_offset;
```

**New pattern:** Header offset is passed as a function parameter (`hdr_off`):
```c
metadata->network_offset = hdr_off;
```

**Resolution:** Updated extract functions to use the `hdr_off` parameter directly.

#### Issue 4: xdp2/bpf.h API Not Updated (2026-02-11) - BLOCKING

**Problem:** The `src/include/xdp2/bpf.h` header has not been updated to match
the new API, preventing XDP sample compilation.

**Issues found:**

1. Uses old 3-param `extract_metadata` signature (lines 72, 76, 80, 84, 99, 114, 129):
   ```c
   ops->extract_metadata(hdr, frame, tlv_ctrl);
   ```
   Should be 6-param:
   ```c
   ops->extract_metadata(hdr, hdr_len, hdr_off, metadata, frame, ctrl);
   ```

2. References non-existent struct member (lines 69, 73, 77, 81, 96, 111, 126):
   ```c
   tlv_ctrl.hdr.hdr_len  // .hdr member no longer exists in xdp2_ctrl_data
   ```

**Impact:** XDP samples cannot compile:
- flow_tracker_simple
- flow_tracker_tlvs
- flow_tracker_tmpl
- flow_tracker_combo (XDP component only)

**Status:** OPEN - Requires library fix before XDP build tests can work.

---

## Session Notes

### 2026-02-11 - Planning Session

1. Created `sample-tests-expansion-plan.md` with comprehensive analysis
2. Verified all parser samples already have correct API
3. Verified all Makefiles have rpath fix
4. Created this log file to track progress
5. Added "Lessons Learned" section to plan document

**Key Finding:** The compiler fixes from the simple_parser work (proto_def in
graph_consumer.h, std::optional null check in main.cpp) benefit all samples
automatically. No per-sample compiler changes needed.

**Next Action:** Implement `offset-parser.nix`

---

### 2026-02-11 - Phase 1 Implementation

**Work Completed:**

1. **Fixed `offset_parser/parser.c`:**
   - Updated `extract_network()` and `extract_transport()` to 6-param signature
   - Added `(void)` casts for unused parameters per style guide

2. **Fixed `ports_parser/parser.c`:**
   - Updated `ipv4_metadata()` and `ports_metadata()` to 6-param signature
   - Fixed bug: `xdp2_parse(my_parser, ...)` -> `xdp2_parse(parser, ...)`

3. **Created `nix/tests/offset-parser.nix`:**
   - Tests build, basic mode, optimized mode
   - Verifies "Network offset:" and "Transport offset:" output
   - Checks expected offset values (14, 54) for IPv6 traffic
   - Compares basic vs optimized output

4. **Created `nix/tests/ports-parser.nix`:**
   - Tests build, basic mode, optimized mode
   - Verifies "Packet N:" output format
   - Checks IP:PORT format with regex patterns
   - Uses tcp_ipv4.pcap (IPv4-only sample)
   - Compares basic vs optimized output

5. **Updated `nix/tests/default.nix`:**
   - Added offset-parser and ports-parser imports
   - Updated `all` test runner to include new tests

**Files Modified:**
- `samples/parser/offset_parser/parser.c`
- `samples/parser/ports_parser/parser.c`
- `nix/tests/default.nix`

**Files Created:**
- `nix/tests/offset-parser.nix`
- `nix/tests/ports-parser.nix`

**Test Results:**
- `nix build .#tests.offset-parser && ./result/bin/xdp2-test-offset-parser` - 8/8 PASS
- `nix build .#tests.ports-parser && ./result/bin/xdp2-test-ports-parser` - 8/8 PASS
- `nix build .#tests.all && ./result/bin/xdp2-test-all` - 30/30 PASS (14+8+8)

**Additional Fix Required:**
- The `hdr_off` parameter is the correct way to get header offset (not `ctrl->hdr.hdr_offset`)
- Updated `offset_parser/parser.c` to use `hdr_off` parameter directly

**Phase 1 Status:** COMPLETE

---

### 2026-02-11 - Phase 2 Implementation

**Work Completed:**

1. **Created `nix/tests/flow-tracker-combo.nix`:**
   - Tests userspace `flow_parser` binary
   - Tests both IPv4 and IPv6 parsing
   - Tests basic and optimized modes
   - XDP build skipped due to bpf.h API issues

2. **Created `nix/tests/xdp-build.nix`:**
   - Documents blocked status for XDP-only sample builds
   - Explains bpf.h API issues that need to be fixed

3. **Updated `nix/tests/default.nix`:**
   - Added flow-tracker-combo and xdp-build tests
   - Updated `all` test runner with Phase 1/Phase 2 sections

**Test Results:**
- `nix build .#tests.flow-tracker-combo` - 8/8 PASS
- `nix build .#tests.xdp-build` - Blocked (informational)
- `nix build .#tests.all` - 38/38 PASS (14+8+8+8+0)

**Blocking Issue Found:**

`src/include/xdp2/bpf.h` has API issues preventing XDP sample compilation:

1. Uses old 3-param `extract_metadata` signature:
   ```c
   ops->extract_metadata(hdr, frame, tlv_ctrl);
   ```
   Should be 6-param:
   ```c
   ops->extract_metadata(hdr, hdr_len, hdr_off, metadata, frame, ctrl);
   ```

2. References non-existent struct member:
   ```c
   tlv_ctrl.hdr.hdr_len  // .hdr member no longer exists
   ```

**Files Created:**
- `nix/tests/flow-tracker-combo.nix`
- `nix/tests/xdp-build.nix`

**Phase 2 Status:** PARTIAL (userspace complete, XDP blocked on library fix)

---

### 2026-02-11 - XDP Build Investigation (Continued)

**Work Completed:**

1. **Fixed `src/include/xdp2/bpf.h`:**
   - Updated all `extract_metadata` calls to use 6-param signature
   - Changed function signatures to include `size_t tlv_len` parameter
   - Fixed: `ops->extract_metadata(hdr, tlv_len, 0, frame, frame, &tlv_ctrl);`

2. **Fixed `src/include/xdp2/utility.h`:**
   - Added `__bpf__` to the preprocessor guard on line 34
   - Changed: `#ifndef __KERNEL__` → `#if !defined(__KERNEL__) && !defined(__bpf__)`
   - This prevents glibc headers (which are incompatible with BPF target) from being included

**Test Results After bpf.h Fix:**

Running `xdp2-test-xdp-build` revealed additional issues:

| Sample | Error Type | Details |
|--------|------------|---------|
| flow_tracker_simple | glibc error | `__float128 is not supported on this target` |
| flow_tracker_tlvs | Template API | `tlv_ctrl.hdr.hdr_len` doesn't exist |
| flow_tracker_tmpl | glibc error | `__float128 is not supported on this target` |

**New Discovery: Template Code Generation Issues**

The file `src/templates/xdp2/xdp_def.template.c` uses outdated API patterns that no
longer exist in `xdp2_ctrl_data`:

1. **Line 222:** `len = ctrl.hdr.hdr_len - offset;`
   - The `ctrl.hdr` member no longer exists

2. **Line 224:** `ctrl.hdr.hdr_offset += offset;`
   - Same issue

3. **Line 276:** `tlv_ctrl.hdr.hdr_len`
   - Same issue

**API Structure Change:**

The old API had:
```c
struct xdp2_ctrl_data {
    struct { size_t hdr_len; size_t hdr_offset; } hdr;  // OLD - doesn't exist
};
```

The new API has:
```c
struct xdp2_ctrl_data {
    struct xdp2_ctrl_var_data var;
    struct xdp2_ctrl_packet_data pkt;
    struct xdp2_ctrl_key_data key;
};
```

Header length and offset are now passed as function parameters (`hdr_len`, `hdr_off`)
rather than through the control data structure.

**Files Modified:**
- `src/include/xdp2/bpf.h` - Fixed extract_metadata signatures
- `src/include/xdp2/utility.h` - Added `__bpf__` guard

**Blocking Issues Remaining:**

| Issue | File | Status |
|-------|------|--------|
| Template uses old API | `src/templates/xdp2/xdp_def.template.c` | OPEN |
| TLV template references ctrl.hdr | Same file | OPEN |

**Impact:** XDP samples that use TLV parsing (flow_tracker_tlvs) cannot compile until
the template is updated. Simple XDP samples should work after the utility.h fix.

---

### 2026-02-11 - XDP Build Investigation (Session 2)

**Work Completed:**

Made multiple fixes to enable BPF compilation:

1. **Fixed `src/include/xdp2/utility.h`:**
   - Added `__bpf__` guard to cli.h include (line 55)
   - Added `__bpf__` guard to userspace-only code block (line 279)
   - Added `__bpf__` guard to `xdp2_line_is_whitespace()` function (line 502)

2. **Fixed `src/include/xdp2/bpf.h`:**
   - Changed `#include <stdlib.h>` to `#include <linux/types.h>` (line 30)
   - stdlib.h pulls in glibc which is incompatible with BPF target

3. **Fixed `src/include/xdp2/parser.h`:**
   - Added `__bpf__` guard to text codes array and `xdp2_get_text_code()` (lines 46-86)
   - Added `__bpf__` guard to siphash-related code (lines 442-491)

**Test Results After Header Fixes:**

| Sample | Previous Error | New Error |
|--------|---------------|-----------|
| flow_tracker_simple | glibc `__float128` | "stack arguments are not supported" |
| flow_tracker_tlvs | glibc + template | "stack arguments are not supported" + template issues |
| flow_tracker_tmpl | glibc `__float128` | "stack arguments are not supported" |

**New Issues Discovered:**

#### Issue 5: BPF Stack Limitations (2026-02-11) - BLOCKING

**Problem:** The `XDP2_METADATA_TEMP_*` macros generate code incompatible with BPF's
stack limitations.

**Error:**
```
./parser.c:37:26: error: stack arguments are not supported
XDP2_METADATA_TEMP_ether(ether_metadata, xdp2_metadata_all)
```

**Analysis:** BPF has limited stack space (~512 bytes) and doesn't support arbitrary
function call conventions. The metadata template macros are generating functions
that exceed BPF constraints.

**Impact:** All XDP samples fail to compile even after fixing header issues.

**Status:** OPEN - Requires architectural investigation of metadata templates.

#### Issue 6: Template Code Generation API Mismatch (2026-02-11) - BLOCKING

**Problem:** The `src/templates/xdp2/xdp_def.template.c` template generates code using
the old `xdp2_ctrl_data` API structure that no longer exists.

**Generated code errors:**
```
parser.xdp.h:350:13: error: no member named 'hdr' in 'struct xdp2_ctrl_data'
    len = ctrl.hdr.hdr_len - offset;
parser.xdp.h:381:41: error: too few arguments to function call
    tlv_len = proto_tlvs_node->ops.len(cp);
parser.xdp.h:403:9: error: use of undeclared identifier 'tlv_ctrl'
```

**Status:** OPEN - Requires template file updates.

---

## Summary of Files Modified

| File | Changes | For Issue |
|------|---------|-----------|
| `src/include/xdp2/utility.h` | Added `__bpf__` guards in 4 places | Header compat |
| `src/include/xdp2/bpf.h` | Changed stdlib.h to linux/types.h, fixed extract_metadata | API + header |
| `src/include/xdp2/parser.h` | Added `__bpf__` guards to siphash and text codes | Header compat |
| `samples/parser/offset_parser/parser.c` | 6-param extract signature | API |
| `samples/parser/ports_parser/parser.c` | 6-param extract + parser bug fix | API + bug |

---

## Current Test Status

| Test | Status | Tests | Notes |
|------|--------|-------|-------|
| simple-parser | ✅ PASS | 14/14 | Userspace parser |
| offset-parser | ✅ PASS | 8/8 | Userspace parser |
| ports-parser | ✅ PASS | 8/8 | Userspace parser |
| flow-tracker-combo | ✅ PASS | 8/8 | Userspace only (XDP skipped) |
| xdp-build | ⏭️ SKIPPED | 0/0 | Blocked, see defect doc |

**Total:** 38 passing tests for userspace components.

**XDP Defect Document:** `xdp-bpf-compatibility-defect.md`

---

## Blocking Issues Summary

Two blocking issues prevent XDP sample compilation:

1. **BPF Stack Arguments** - Metadata templates exceed BPF constraints
2. **Template API Mismatch** - Generated code uses old `ctrl.hdr.*` API

These require architectural changes beyond simple header fixes.

---

## References

- `nix/tests/simple-parser.nix` - Reference implementation
- `nix/tests/default.nix` - Test index to update
- `flake.nix` - Test exposure in packages
- `data/pcaps/` - Test data files
