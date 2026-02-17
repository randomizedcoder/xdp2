# XDP Samples Status

**Last Updated:** 2026-02-16
**Branch:** feature/nix-sample-tests

---

## Overview

This document tracks the build and test status of samples in `samples/xdp/` and `samples/parser/` directories within the Nix development environment.

---

## Recent Fixes

### 1. Template Segfault Fix (commit d685a14)

**File:** `src/templates/xdp2/common_parser.template.c`

The optimized parser (`-O` flag) was segfaulting due to incorrect pointer passing in the template.

**Root Cause:** Line 53 passed `frame` (a `void *`) instead of `&frame` to a function expecting `void **frame`. When the internal function dereferenced `*frame`, it read zeroed metadata bytes as a pointer address, resulting in NULL.

**Fix:**
```c
// Before (broken):
ret = __@!parser_name!@_@!root_name!@_xdp2_parse(
        parser, hdr, len, metadata, frame, 0, ctrl, flags);

// After (fixed):
ret = __@!parser_name!@_@!root_name!@_xdp2_parse(
        parser, hdr, len, metadata, &frame, 0, ctrl, flags);
```

### 2. XDP2DIR Environment Variable (commit acb3054)

**File:** `nix/shell-functions/navigation.nix`

The development shell now automatically sets `XDP2DIR` to point to the local install directory when entering `nix develop`:

```
XDP2DIR=$XDP2_REPO_ROOT/install/$arch
```

This allows samples to build correctly using `make` after running `make install` in `src/`.

### 3. Convenience Test Targets (commit dd08822)

**File:** `flake.nix`

Added convenience targets for running sample tests:

```bash
# Run all tests
nix run .#run-sample-tests

# Build individual tests
nix build .#simple-parser-test
nix build .#offset-parser-test
nix build .#ports-parser-test
nix build .#flow-tracker-combo-test
```

---

## Parser Samples Status (samples/parser/)

| Sample | Basic Mode | Optimized Mode (-O) | Nix Test |
|--------|------------|---------------------|----------|
| simple_parser | PASS | PASS | `nix build .#simple-parser-test` |
| offset_parser | PASS | PASS | `nix build .#offset-parser-test` |
| ports_parser | PASS | PASS | `nix build .#ports-parser-test` |

All parser samples pass with both basic and optimized modes after the template fix.

---

## XDP Samples Status (samples/xdp/)

| Sample | Userspace Build | BPF Build | Notes |
|--------|-----------------|-----------|-------|
| flow_tracker_combo | PASS | BLOCKED | `flow_parser` binary works |
| flow_tracker_simple | PASS | BLOCKED | Builds but BPF fails |
| flow_tracker_tlvs | UNTESTED | BLOCKED | May have additional TLV issues |
| flow_tracker_tmpl | UNTESTED | BLOCKED | Template-based sample |

### Userspace Build Instructions

```bash
# Enter development shell
nix develop

# Ensure install directory is populated
cd src && make install && cd ..

# Build userspace component only
cd samples/xdp/flow_tracker_combo
make flow_parser

# Test
./flow_parser ../../../data/pcaps/tcp_ipv4.pcap
```

---

## BPF Compilation Blocker

### Symptom

When compiling XDP programs with `-target bpf`, the nix-wrapped clang fails:

```
clang: error: unsupported option '-fzero-call-used-regs=used-gpr' for target 'bpf'
clang: warning: ignoring '-fstack-protector-strong' option as it is not currently supported for target 'bpf'
```

### Root Cause

The Nix cc-wrapper adds security hardening flags that are incompatible with BPF compilation:
- `-fzero-call-used-regs=used-gpr` - Not supported by BPF target
- `-fstack-protector-strong` - Ignored but warns

### Potential Solutions

1. **Use unwrapped clang for BPF builds:**
   ```nix
   llvmPackages.clang-unwrapped
   ```

2. **Create a BPF-specific clang wrapper** that strips incompatible flags

3. **Modify Makefiles** to use `clang` directly with explicit paths

### Related Documentation

See `documentation/nix/xdp-bpf-compatibility-defect.md` for additional architectural issues affecting XDP/BPF compilation.

---

## Test Commands

### Quick Verification

```bash
# Run all sample tests (parser samples only, XDP userspace skipped in CI)
nix run .#run-sample-tests

# Expected output:
# simple_parser: 14 tests passed
# offset_parser: 8 tests passed
# ports_parser: 8 tests passed
# flow_tracker_combo: 8 tests passed
# xdp-build: SKIPPED
```

### Manual Testing in Development Shell

```bash
nix develop

# Parser samples
cd samples/parser/simple_parser
make clean && make
./parser_tmpl ../../../data/pcaps/tcp_ipv4.pcap
./parser_tmpl -O ../../../data/pcaps/tcp_ipv4.pcap  # Optimized mode

# XDP samples (userspace only)
cd samples/xdp/flow_tracker_combo
make clean && make flow_parser
./flow_parser ../../../data/pcaps/tcp_ipv4.pcap
./flow_parser -O ../../../data/pcaps/tcp_ipv4.pcap  # Optimized mode
```

---

## Files Modified

| File | Change |
|------|--------|
| `src/templates/xdp2/common_parser.template.c` | Fixed `frame` -> `&frame` |
| `nix/shell-functions/navigation.nix` | Added XDP2DIR auto-detection |
| `flake.nix` | Added convenience test targets |

---

## Next Steps

1. **Fix BPF compilation** - Use unwrapped clang or create BPF-specific wrapper
2. **Test remaining XDP samples** - flow_tracker_tlvs, flow_tracker_tmpl
3. **Address xdp_def.template.c issues** - API mismatch documented in xdp-bpf-compatibility-defect.md
4. **Add XDP userspace tests to CI** - Currently only parser tests run

---

## References

- `documentation/nix/xdp-bpf-compatibility-defect.md` - Detailed BPF compatibility analysis
- `documentation/nix/sample-tests-design.md` - Test infrastructure design
- `nix/tests/` - Nix test definitions
