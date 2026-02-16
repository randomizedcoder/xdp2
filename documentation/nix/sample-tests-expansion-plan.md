# Nix Sample Tests Expansion Plan

**Status:** Planning
**Date:** 2026-02-11
**Author:** Claude Code (assisted)

## Overview

This document outlines the plan to create nix test targets for all XDP2 samples,
building on the successful `tests.simple-parser` implementation.

## Current State

### Completed
- `nix build .#tests.simple-parser` - Working
  - Builds `parser_notmpl` and `parser_tmpl`
  - Tests basic and optimized (-O) modes
  - Verifies IPv6 parsing, TCP timestamps, hash computation
  - Compares basic vs optimized output for consistency

### Sample Inventory

```
samples/
├── parser/                    # Userspace parser samples (can test with pcap files)
│   ├── simple_parser/         ✅ DONE
│   ├── offset_parser/         ⏳ TODO
│   └── ports_parser/          ⏳ TODO
└── xdp/                       # XDP/BPF samples (kernel + userspace components)
    ├── flow_tracker_combo/    ⏳ TODO (has userspace flow_parser)
    ├── flow_tracker_simple/   ⏳ TODO (XDP only)
    ├── flow_tracker_tlvs/     ⏳ TODO (XDP only)
    └── flow_tracker_tmpl/     ⏳ TODO (XDP only)
```

## Sample Analysis

### Parser Samples (Priority 1 - Easy)

These are userspace-only samples that read pcap files. They can be tested
similarly to `simple_parser`.

#### 1. offset_parser

| Attribute | Value |
|-----------|-------|
| **Purpose** | Parse UDP/TCP in IPv4/IPv6, extract network and transport layer offsets |
| **Binary** | `parser` |
| **Modes** | Basic and optimized (-O) |
| **Test Data** | `tcp_ipv6.pcap` |
| **Expected Output** | `Network offset: 14`, `Transport offset: 54` |
| **Complexity** | Low - similar to simple_parser |

**Test Criteria:**
- [ ] Binary builds successfully
- [ ] Basic mode produces "Network offset:" and "Transport offset:"
- [ ] Optimized mode produces identical output
- [ ] Both modes produce expected offset values (14, 54 for IPv6)

#### 2. ports_parser

| Attribute | Value |
|-----------|-------|
| **Purpose** | Parse UDP/TCP in IPv4, extract 4-tuple (addresses + ports) |
| **Binary** | `parser` |
| **Modes** | Basic and optimized (-O) |
| **Test Data** | `tcp_ipv4.pcap` |
| **Expected Output** | `Packet N: IP:PORT -> IP:PORT` format |
| **Complexity** | Low - similar to simple_parser |

**Test Criteria:**
- [ ] Binary builds successfully
- [ ] Basic mode produces "Packet" lines with IP:PORT format
- [ ] Optimized mode produces identical output
- [ ] IP addresses are valid (contains dots, like `10.0.2.15`)

### XDP Samples (Priority 2 - More Complex)

These samples build both userspace binaries and XDP/BPF programs. They present
additional challenges:

1. **BPF Compilation**: Requires clang with BPF target (`-target bpf`)
2. **Runtime Testing**: XDP programs need root privileges and network interfaces
3. **Partial Testing**: We can test userspace components without loading XDP programs

#### 3. flow_tracker_combo (Recommended Next)

| Attribute | Value |
|-----------|-------|
| **Purpose** | Demonstrates same parser in userspace and XDP |
| **Binaries** | `flow_parser` (userspace), `flow_tracker.xdp.o` (XDP) |
| **Modes** | Basic and optimized (-O) for flow_parser |
| **Test Data** | `tcp_ipv6.pcap` |
| **Expected Output** | `IPv6: ::1:PORT->::1:PORT` format |
| **Complexity** | Medium - userspace testable, XDP build-only |

**Test Criteria:**
- [ ] `flow_parser` binary builds successfully
- [ ] `flow_tracker.xdp.o` compiles (build test only, no load)
- [ ] Basic mode produces IPv6 output with ports
- [ ] Optimized mode produces identical/similar output

**Implementation Note:** This sample has a userspace `flow_parser` binary that
reads pcap files, making it testable like the parser samples. The XDP component
can be tested for successful compilation only.

#### 4. flow_tracker_simple

| Attribute | Value |
|-----------|-------|
| **Purpose** | Simple XDP flow tracker (tracks flows with source port 22) |
| **Binaries** | `flow_tracker.xdp.o` (XDP only) |
| **Test Data** | N/A (XDP only) |
| **Complexity** | Medium - build test only |

**Test Criteria:**
- [ ] `flow_tracker.xdp.o` compiles successfully
- [ ] No userspace binary to test (XDP build verification only)

#### 5. flow_tracker_tlvs

| Attribute | Value |
|-----------|-------|
| **Purpose** | XDP flow tracker with TCP TLV option parsing |
| **Binaries** | `flow_tracker.xdp.o` (XDP only) |
| **Test Data** | N/A (XDP only) |
| **Complexity** | Medium - build test only, exercises TLV parsing |

**Test Criteria:**
- [ ] `flow_tracker.xdp.o` compiles successfully
- [ ] Tests TLV parsing codepath in xdp2-compiler

#### 6. flow_tracker_tmpl

| Attribute | Value |
|-----------|-------|
| **Purpose** | XDP flow tracker using XDP2_XDP_MAKE_PARSER_PROGRAM template |
| **Binaries** | `flow_tracker.xdp.o` (XDP only) |
| **Test Data** | N/A (XDP only) |
| **Complexity** | Medium - build test only |

**Test Criteria:**
- [ ] `flow_tracker.xdp.o` compiles successfully

## Implementation Plan

### Phase 1: Parser Samples (Immediate)

Create test scripts following the `simple-parser.nix` pattern.

#### File Structure
```
nix/tests/
├── default.nix              # Test index (update to include new tests)
├── simple-parser.nix        # ✅ Existing
├── offset-parser.nix        # New
└── ports-parser.nix         # New
```

#### offset-parser.nix Template

```nix
# nix/tests/offset-parser.nix
{ pkgs, xdp2 }:
let
  testData = ../..;
  llvmConfig = import ../llvm.nix { inherit pkgs; lib = pkgs.lib; };
in
pkgs.writeShellApplication {
  name = "xdp2-test-offset-parser";
  runtimeInputs = [ pkgs.gnumake pkgs.gcc pkgs.coreutils pkgs.gnugrep
                    pkgs.libpcap pkgs.libpcap.lib pkgs.linuxHeaders ];
  text = ''
    # Similar structure to simple-parser.nix
    # Copy offset_parser sources
    # Build with make
    # Test basic mode: ./parser $PCAP
    # Test optimized mode: ./parser -O $PCAP
    # Verify output contains "Network offset:" and "Transport offset:"
    # Compare basic vs optimized output
  '';
}
```

#### ports-parser.nix Template

```nix
# nix/tests/ports-parser.nix
{ pkgs, xdp2 }:
# Similar to offset-parser but uses tcp_ipv4.pcap
# Verifies output contains "Packet" lines with IP:PORT format
```

#### Update default.nix

```nix
# nix/tests/default.nix
{ pkgs, xdp2 }:
{
  simple-parser = import ./simple-parser.nix { inherit pkgs xdp2; };
  offset-parser = import ./offset-parser.nix { inherit pkgs xdp2; };
  ports-parser = import ./ports-parser.nix { inherit pkgs xdp2; };
  # Phase 2:
  # flow-tracker-combo = import ./flow-tracker-combo.nix { inherit pkgs xdp2; };
}
```

### Phase 2: XDP Samples (After Phase 1)

XDP samples require additional nix infrastructure:

#### Required Changes

1. **BPF Compilation Support**
   - Need clang with BPF target support
   - Already have llvmPackages in nix config
   - Add compilation step: `clang -target bpf -O2 -c flow_tracker.xdp.c`

2. **Test Strategy for XDP**
   - **Build Test**: Verify .xdp.o files compile without errors
   - **Userspace Test**: For samples with userspace binaries (flow_tracker_combo)
   - **Skip Runtime**: Don't attempt to load XDP programs (requires root/interfaces)

#### flow-tracker-combo.nix Template

```nix
# nix/tests/flow-tracker-combo.nix
{ pkgs, xdp2 }:
let
  testData = ../..;
  llvmConfig = import ../llvm.nix { inherit pkgs; lib = pkgs.lib; };
in
pkgs.writeShellApplication {
  name = "xdp2-test-flow-tracker-combo";
  runtimeInputs = [
    pkgs.gnumake pkgs.gcc pkgs.coreutils pkgs.gnugrep
    pkgs.libpcap pkgs.libpcap.lib pkgs.linuxHeaders
    llvmConfig.llvmPackages.clang  # For BPF compilation
  ];
  text = ''
    # 1. Build XDP component (compile test only)
    #    clang -target bpf ... -c flow_tracker.xdp.c -o flow_tracker.xdp.o
    # 2. Build userspace flow_parser
    # 3. Test flow_parser basic mode
    # 4. Test flow_parser optimized mode
    # 5. Compare outputs
  '';
}
```

### Phase 3: XDP Build-Only Tests

For XDP-only samples (flow_tracker_simple, flow_tracker_tlvs, flow_tracker_tmpl),
create minimal build verification tests.

```nix
# nix/tests/xdp-build.nix
{ pkgs, xdp2 }:
# Single test that builds all XDP samples to verify compilation
pkgs.writeShellApplication {
  name = "xdp2-test-xdp-build";
  runtimeInputs = [ ... ];
  text = ''
    # For each XDP sample:
    # 1. Copy source to temp dir
    # 2. Run make to build .xdp.o
    # 3. Verify .xdp.o exists
    # Report pass/fail for each
  '';
}
```

## Test Data Requirements

| Sample | pcap File | Protocol |
|--------|-----------|----------|
| simple_parser | tcp_ipv6.pcap | IPv6 + TCP |
| offset_parser | tcp_ipv6.pcap | IPv6 + TCP |
| ports_parser | tcp_ipv4.pcap | IPv4 + TCP |
| flow_tracker_combo | tcp_ipv6.pcap | IPv6 + TCP |

All required pcap files already exist in `data/pcaps/`.

## Flake.nix Updates

After implementing tests, expose them in flake.nix:

```nix
packages = {
  # ... existing packages ...
  tests = tests;  # Already exposes tests.simple-parser
  # New tests automatically available as:
  # - tests.offset-parser
  # - tests.ports-parser
  # - tests.flow-tracker-combo
  # - tests.xdp-build
};
```

Usage:
```bash
# Run individual tests
nix build .#tests.offset-parser && ./result/bin/xdp2-test-offset-parser
nix build .#tests.ports-parser && ./result/bin/xdp2-test-ports-parser
nix build .#tests.flow-tracker-combo && ./result/bin/xdp2-test-flow-tracker-combo

# Build all tests
nix build .#tests
```

## Priority Order

1. **offset-parser** (Immediate) - Simplest, similar to simple_parser
2. **ports-parser** (Immediate) - Simple, tests IPv4 path
3. **flow-tracker-combo** (Short-term) - Has testable userspace component
4. **xdp-build** (Medium-term) - Build verification for XDP-only samples

## Estimated Effort

| Test | Effort | Dependencies |
|------|--------|--------------|
| offset-parser | 1 hour | None (copy simple-parser pattern) |
| ports-parser | 1 hour | None (copy simple-parser pattern) |
| flow-tracker-combo | 2-3 hours | BPF clang setup |
| xdp-build | 2 hours | BPF clang setup |

## Open Questions

1. **IPv4 Test Coverage**: Should we add IPv4 tests to simple_parser as well?
   Currently it only tests with tcp_ipv6.pcap.

2. **XDP Runtime Testing**: Is there value in creating integration tests that
   actually load XDP programs? This would require:
   - Root/sudo access
   - Network namespace setup
   - More complex test infrastructure

3. **CI Integration**: How should these tests integrate with CI/CD?
   - Run parser tests on every PR
   - Run XDP build tests on every PR
   - Skip XDP runtime tests in CI (requires privileges)

## Lessons Learned from simple_parser

The following issues were encountered and fixed while implementing the simple_parser
test. These same issues may apply to other samples.

### Issue 1: Sample API Mismatch (ALREADY FIXED)

**Status:** All samples have been updated to current API.

The XDP2 parser API was refactored in commit `4e14212` (2025-09-30). The samples
were originally created with the old API and needed updates:

| Old API | New API |
|---------|---------|
| `struct xdp2_packet_data pdata;` | `struct xdp2_ctrl_data ctrl;` |
| `XDP2_SET_BASIC_PDATA_LEN_SEQNO(...)` | `XDP2_CTRL_SET_BASIC_PKT_DATA(&ctrl, packet, plen, i);` |
| `xdp2_parse(parser, &pdata, &metadata, 0);` | `xdp2_parse(parser, packet, plen, &metadata, &ctrl, 0);` |

**Verified:** `offset_parser`, `ports_parser`, and `flow_tracker_combo` already use the new API.

See: `documentation/nix/defect-sample-api-mismatch.md`

### Issue 2: Extract Function Signature Mismatch

**Status:** May need fixing in other samples.

The metadata extract functions in some samples had outdated signatures:

```c
// Old signature (3 parameters):
void extract_fn(const void *hdr, void *meta, const struct xdp2_ctrl_data ctrl)

// New signature (6 parameters):
void extract_fn(const void *hdr, size_t offset, size_t length,
                void *meta, void *ctx, const struct xdp2_ctrl_data *ctrl)
```

**Check:** Verify each sample's extract functions match the expected signature.

See: `documentation/nix/sample-tests-design.md` (Fixes Applied section)

### Issue 3: Optimized Parser Graph Building

**Status:** Fixed in compiler - applies to all samples.

The xdp2-compiler was missing `proto_def` in the `is_cur_field_of_interest` check
in `graph_consumer.h`. This caused the optimized parser to generate incomplete code.

**Fix applied to:** `src/tools/compiler/include/xdp2gen/ast-consumer/graph_consumer.h`

This fix is in the compiler, so it benefits all samples automatically.

See: `documentation/nix/clang-tool-refactor-log.md` (Phase 3)

### Issue 4: parse_dump std::optional Crash

**Status:** Fixed in compiler.

When building `parser.json` for samples with certain graph structures, the compiler
crashed with a `std::optional` assertion failure.

**Fix applied to:** `src/tools/compiler/src/main.cpp` (line ~1405)

Added null check for `next_proto_data` before accessing it.

See: `documentation/nix/clang-tool-refactor-log.md` (Phase 5)

### Issue 5: Makefile rpath

**Status:** Already fixed in all sample Makefiles.

Binaries need rpath set to find shared libraries without manual `LD_LIBRARY_PATH`:

```makefile
LDFLAGS= -L$(LIBDIR) -Wl,-rpath,$(LIBDIR)
```

**Verified:** All sample Makefiles already have this fix.

### Issue 6: Nix libpcap Split Outputs

**Status:** Template in simple-parser.nix handles this.

In Nix, libpcap has split outputs:
- Headers: `pkgs.libpcap`
- Libraries: `pkgs.libpcap.lib`

The test template handles this correctly.

### Issue 7: ClangTool Include Paths

**Status:** Template in simple-parser.nix handles this.

xdp2-compiler's ClangTool needs explicit include paths in Nix:
- `XDP2_C_INCLUDE_PATH` - Clang resource dir
- `XDP2_GLIBC_INCLUDE_PATH` - glibc headers
- `XDP2_LINUX_HEADERS_PATH` - Linux kernel headers

The test template sets these environment variables.

## Checklist for New Sample Tests

When adding a new sample test, verify:

- [ ] Sample uses current API (`xdp2_ctrl_data`, `XDP2_CTRL_SET_BASIC_PKT_DATA`, 6-arg `xdp2_parse`)
- [ ] Extract functions have correct 6-parameter signature
- [ ] Makefile has rpath in LDFLAGS
- [ ] Test script sets `XDP2_*_INCLUDE_PATH` environment variables
- [ ] Test script uses `pkgs.libpcap.lib` for library path
- [ ] Appropriate pcap test file exists in `data/pcaps/`
- [ ] Test verifies both basic and optimized (-O) modes
- [ ] Test compares basic vs optimized output for consistency

## Next Steps

1. [ ] Create `offset-parser.nix` following simple-parser pattern
2. [ ] Create `ports-parser.nix` following simple-parser pattern
3. [ ] Update `nix/tests/default.nix` to include new tests
4. [ ] Verify new tests pass: `nix build .#tests.offset-parser`
5. [ ] Document in flake.nix comments
6. [ ] Plan Phase 2 (XDP samples) implementation

---

## Appendix: Sample README Summaries

### offset_parser
Parses UDP/TCP over IPv4/IPv6, extracts network and transport layer offsets.
Expected output: `Network offset: 14` and `Transport offset: 54` for IPv6 traffic.

### ports_parser
Parses UDP/TCP over IPv4 only, extracts 4-tuple (source/dest IP and ports).
Expected output: `Packet N: IP:PORT -> IP:PORT` format.

### flow_tracker_combo
Demonstrates using the same XDP2 parser in both userspace and XDP.
Has `flow_parser` binary for userspace testing with pcap files.
Expected output: `IPv6: ::1:PORT->::1:PORT` format.

### flow_tracker_simple
XDP-only flow tracker that tracks flows with source port 22.
No userspace component - build verification only.

### flow_tracker_tlvs
XDP flow tracker with TCP TLV option parsing.
No userspace component - build verification only.

### flow_tracker_tmpl
XDP flow tracker using XDP2_XDP_MAKE_PARSER_PROGRAM template.
No userspace component - build verification only.
