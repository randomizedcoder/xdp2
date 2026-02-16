# XDP/BPF Compatibility Defect Analysis

**Status:** OPEN
**Severity:** Blocking
**Discovered:** 2026-02-11
**Related:** `sample-tests-expansion-log.md`

---

## Executive Summary

XDP sample compilation to BPF bytecode is blocked by two architectural issues:

1. **BPF Stack Limitation** - Metadata template macros generate functions that exceed BPF's stack constraints
2. **Template API Mismatch** - Code generation template uses obsolete `xdp2_ctrl_data` API structure

Both issues require significant refactoring to resolve.

---

## Issue 1: BPF Stack Arguments Not Supported

### Symptom

When compiling XDP samples with `-target bpf`, clang reports:

```
parser.c:37:26: error: stack arguments are not supported
XDP2_METADATA_TEMP_ether(ether_metadata, xdp2_metadata_all)
                         ^
```

### Root Cause

BPF (Berkeley Packet Filter) has strict constraints:
- Maximum stack size: 512 bytes
- No support for variable-length stack allocations
- Limited function call conventions (max 5 arguments in registers)

The `XDP2_METADATA_TEMP_*` macros defined in `src/include/xdp2/parser_metadata.h` expand to functions that:
1. Take large struct arguments by value
2. May exceed the 5-register argument limit
3. Require stack spilling that BPF doesn't support

### Example Problematic Code

```c
// From src/include/xdp2/parser_metadata.h
#define XDP2_METADATA_TEMP_ether(NAME, TYPE)                    \
static void NAME(const void *hdr, size_t hdr_len, size_t hdr_off,  \
                 void *_meta, void *_frame,                      \
                 const struct xdp2_ctrl_data *ctrl)              \
{                                                                 \
    TYPE *metadata = _meta;                                       \
    // ... extract ether metadata                                 \
}
```

The generated function signature is compatible with the API, but when the `TYPE` struct is large, operations on it may require stack space BPF cannot provide.

### Affected Samples

| Sample | Template Macros Used |
|--------|---------------------|
| flow_tracker_simple | `XDP2_METADATA_TEMP_ether`, `ipv4`, `ports` |
| flow_tracker_tmpl | Same |
| flow_tracker_tlvs | Same + TCP option templates |
| flow_tracker_combo | Same (XDP component) |

### Potential Solutions

1. **Pointer-based metadata extraction**
   - Pass metadata by pointer instead of copying
   - Modify macros to work with pre-allocated metadata buffers

2. **Inline assembly for BPF**
   - Use BPF-specific intrinsics for metadata extraction
   - Avoid function calls entirely in hot path

3. **Simplified BPF-only metadata path**
   - Create separate, BPF-compatible metadata macros
   - Use `#ifdef __bpf__` to select appropriate implementation

---

## Issue 2: Template API Mismatch

### Symptom

Generated `parser.xdp.h` contains references to non-existent struct members:

```
parser.xdp.h:350:13: error: no member named 'hdr' in 'struct xdp2_ctrl_data'
    len = ctrl.hdr.hdr_len - offset;
          ~~~~ ^
```

### Root Cause

The code generation template `src/templates/xdp2/xdp_def.template.c` uses an obsolete API for `xdp2_ctrl_data`.

#### Old API (no longer exists)
```c
struct xdp2_ctrl_data {
    struct {
        size_t hdr_len;
        size_t hdr_offset;
    } hdr;
    // ...
};
```

#### New API (current)
```c
struct xdp2_ctrl_data {
    struct xdp2_ctrl_var_data var;
    struct xdp2_ctrl_packet_data pkt;
    struct xdp2_ctrl_key_data key;
};
```

Header length and offset are now passed as function parameters (`hdr_len`, `hdr_off`) rather than through the control structure.

### Template Code Requiring Updates

In `src/templates/xdp2/xdp_def.template.c`:

| Line | Old Code | Issue |
|------|----------|-------|
| 222 | `len = ctrl.hdr.hdr_len - offset;` | `ctrl.hdr` doesn't exist |
| 224 | `ctrl.hdr.hdr_offset += offset;` | Same |
| 276 | `tlv_ctrl.hdr.hdr_len` | Same |
| 362 | `ctrl.hdr.hdr_offset++;` | Same |
| 370 | `ctrl.hdr.hdr_offset++;` | Same |
| 403+ | `tlv_ctrl.hdr.hdr_len` (multiple) | Same |

### Additional Template Issues

1. **Variable redefinition (line 344):**
   ```
   parser.xdp.h:344:9: error: redefinition of 'offset'
           size_t offset, len;
   ```
   The template declares `offset` but the function parameter already has `offset`.

2. **Undeclared `tlv_ctrl` variable:**
   ```
   parser.xdp.h:403:9: error: use of undeclared identifier 'tlv_ctrl'
   ```
   The template uses `tlv_ctrl` without declaring it.

3. **Wrong function arity:**
   ```
   parser.xdp.h:381:41: error: too few arguments to function call, expected 2, have 1
           tlv_len = proto_tlvs_node->ops.len(cp);
   ```
   The `len` function now requires 2 arguments.

### Required Template Updates

1. Remove `ctrl.hdr.*` references and use function parameters instead
2. Fix variable shadowing (`offset` redefinition)
3. Declare `tlv_ctrl` properly or pass it through function parameters
4. Update function call arities to match current API signatures

---

## Files Requiring Modification

| File | Priority | Changes Needed |
|------|----------|----------------|
| `src/templates/xdp2/xdp_def.template.c` | High | API migration |
| `src/include/xdp2/parser_metadata.h` | High | BPF-compatible macros |
| `src/include/xdp2/bpf.h` | Done | Already fixed |
| `src/include/xdp2/parser.h` | Done | Already fixed |
| `src/include/xdp2/utility.h` | Done | Already fixed |

---

## Header Fixes Already Completed

During investigation, the following header compatibility fixes were made:

### src/include/xdp2/utility.h
- Added `__bpf__` guard to cli.h include
- Added `__bpf__` guard to userspace-only code blocks
- Added `__bpf__` guard to `xdp2_line_is_whitespace()` function

### src/include/xdp2/bpf.h
- Changed `#include <stdlib.h>` to `#include <linux/types.h>`
- Fixed `extract_metadata` function signatures (6-param API)

### src/include/xdp2/parser.h
- Added `__bpf__` guards to text codes array
- Added `__bpf__` guards to `xdp2_get_text_code()` function
- Added `__bpf__` guards to siphash-related code

---

## Testing Status

| Test | Status | Notes |
|------|--------|-------|
| simple-parser | PASS | Userspace, not affected |
| offset-parser | PASS | Userspace, not affected |
| ports-parser | PASS | Userspace, not affected |
| flow-tracker-combo | PASS | Userspace component only |
| xdp-build | BLOCKED | Architectural issues |

---

## Recommended Next Steps

1. **Phase 1: Template API Migration** (Estimated: Medium effort)
   - Update `xdp_def.template.c` to use new `xdp2_ctrl_data` structure
   - Fix variable declarations and function arities
   - Test with flow_tracker_tlvs sample

2. **Phase 2: BPF Stack Compatibility** (Estimated: High effort)
   - Analyze metadata template macro expansions
   - Design BPF-compatible metadata extraction approach
   - May require significant macro refactoring

3. **Phase 3: Integration Testing**
   - Verify all XDP samples compile to BPF
   - Load-test on real network interfaces (requires VM/hardware)

---

## References

- [BPF and XDP Reference Guide](https://docs.cilium.io/en/stable/bpf/)
- [Linux BPF/XDP Documentation](https://www.kernel.org/doc/html/latest/bpf/)
- XDP2 source: `src/templates/xdp2/xdp_def.template.c`
- Parser types: `src/include/xdp2/parser_types.h`
