# Nix Sample Tests Design

## Overview

This document describes the design for adding automated tests of the XDP2 samples
to the Nix build system using `pkgs.writeShellApplication`.

## Implementation Status

**Status: FULLY WORKING** (2025-02-11)

The simple_parser test is now fully working via `nix build .#tests.simple-parser`.
Both basic and optimized (`-O`) modes produce identical, correct output.

### Fixes Applied

1. **libpcap.lib output** - In Nix, `pkgs.libpcap` has separate outputs. The library
   files are in `pkgs.libpcap.lib`, not `pkgs.libpcap`.

2. **Sample API mismatch** - Updated `samples/parser/simple_parser/parser_notmpl.c`
   extract functions to match the current xdp2 API signature:
   ```c
   // Old signature (3 parameters):
   void extract_fn(const void *hdr, void *meta, const struct xdp2_ctrl_data ctrl)

   // New signature (6 parameters):
   void extract_fn(const void *hdr, size_t offset, size_t length,
                   void *meta, void *ctx, const struct xdp2_ctrl_data *ctrl)
   ```

3. **Optimized parser fix (2025-02-11)** - Fixed missing `proto_def` in
   `is_cur_field_of_interest` check in `graph_consumer.h`. This was preventing
   `parser_node` from being populated, breaking graph edge creation and
   protocol routing switch statement generation. See `clang-tool-refactor-log.md`.

4. **rpath in Makefile** - Added `-Wl,-rpath,$(LIBDIR)` to LDFLAGS so binaries
   can find shared libraries without setting LD_LIBRARY_PATH manually.

## Testing on NixOS

### Running the Test

```bash
# Build and run the simple-parser test
nix build .#tests.simple-parser
./result/bin/xdp2-test-simple-parser
```

### Test Output (Passing)

```
=== XDP2 simple_parser Test ===

Work directory: /tmp/tmp.XXXXXX

XDP2DIR: /nix/store/...-xdp2-0.1.0
LD_LIBRARY_PATH: /nix/store/...-xdp2-0.1.0/lib:/nix/store/...-libpcap-1.10.6-lib/lib

--- Building simple_parser ---
gcc -I.../include ...
.../xdp2-compiler -I.../include -i parser_tmpl.c -o parser_tmpl.p.c
struct __attribute__((aligned(64))) __attribute__((packed)) xdp2_parse_node { ... }
...

PASS: parser_notmpl binary created
PASS: parser_tmpl binary created

--- Test 1: parser_notmpl basic ---
PASS: parser_notmpl produced IPv6 output
PASS: parser_notmpl parsed TCP timestamps
PASS: parser_notmpl computed hash values

--- Test 2: parser_notmpl optimized ---
PASS: parser_notmpl -O ran and computed hashes

--- Test 3: parser_tmpl basic ---
PASS: parser_tmpl produced IPv6 output

--- Test 4: parser_tmpl optimized ---
PASS: parser_tmpl -O ran and computed hashes

===================================
All simple_parser tests passed!
===================================
```

## Testing on Ubuntu (Native)

### Prerequisites

Build and install xdp2:
```bash
cd ~/xdp2/src
./configure
make
make install
```

### Running the Sample

```bash
cd samples/parser/simple_parser
make clean
make XDP2DIR=../../../install/x86_64

# Set library path and run tests
export LD_LIBRARY_PATH=../../../install/x86_64/lib:$LD_LIBRARY_PATH

./parser_notmpl ../../../data/pcaps/tcp_ipv6.pcap
./parser_tmpl ../../../data/pcaps/tcp_ipv6.pcap
./parser_notmpl -O ../../../data/pcaps/tcp_ipv6.pcap
./parser_tmpl -O ../../../data/pcaps/tcp_ipv6.pcap
```

### Test Output (Ubuntu - All Tests Pass)

```
=== parser_notmpl ===
IPv6: ::1:51648->::1:631
	TCP timestamps value: 1887522685, echo 0
	Hash d3f87531
IPv6: ::1:631->::1:51648
	TCP timestamps value: 1887522685, echo 1887522685
	Hash ca63a2de
...

=== parser_notmpl -O ===
IPv6: ::1:51648->::1:631
	TCP timestamps value: 1887522685, echo 0
	Hash d3f87531
...
```

On Ubuntu, all four tests produce identical output including full IPv6 parsing,
TCP timestamp extraction, and hash computation.

## Known Issues

### Optimized Parser on Nix - RESOLVED

**Status: FIXED** (2025-02-11)

The optimized parser issue has been resolved. Both basic and `-O` modes now
produce identical correct output on Nix.

**Root Cause (found and fixed):**

In `graph_consumer.h`, the `is_cur_field_of_interest` check was missing `proto_def`.
This prevented the `parser_node` field from being populated during graph construction,
which in turn caused:
- Graph edges to not be created (no source/target matching)
- Protocol routing switch statements to not be generated
- Only `return XDP2_STOP_OKAY;` instead of actual protocol routing

**The Fix:**

Added `proto_def` to the `is_cur_field_of_interest` list in `graph_consumer.h`:
```cpp
bool is_cur_field_of_interest =
    (field_name == "text_name" ||
     field_name == "proto_table" ||
     field_name == "proto_def" ||  // <-- This was missing!
     field_name == "wildcard_node" ||
     ...
```

**Verification:**

After the fix:
- Generated code: **681 lines** (was 601)
- Switch statements: **4** (was 1)
- Both modes produce identical output with correct IPv6 parsing and hash values

See `clang-tool-refactor-log.md` for full debugging details.

---

## Goals

1. Verify that samples build correctly after `nix build`
2. Verify that parser samples produce correct output when run against test pcap files
3. Verify that XDP samples produce valid BPF bytecode
4. Provide a simple `nix flake check` or `nix build .#tests` command to run all tests

## Sample Categories

### Parser Samples (Userspace)

Location: `samples/parser/`

| Sample | Output | Testable |
|--------|--------|----------|
| `simple_parser` | `parser_tmpl`, `parser_notmpl` binaries | Yes - run against pcap, check output |
| `ports_parser` | Parser binary | Yes - run against pcap |
| `offset_parser` | Parser binary | Yes - run against pcap |

**Test approach:** Build the sample, run against known pcap files, verify output
contains expected patterns (e.g., "IPv6:", "Hash", "TCP timestamps").

### XDP Samples (BPF)

Location: `samples/xdp/`

| Sample | Output | Testable |
|--------|--------|----------|
| `flow_tracker_simple` | `flow_tracker.xdp.o` | Partial - build only, verify BPF bytecode |
| `flow_tracker_tmpl` | `flow_tracker.xdp.o` | Partial - build only |
| `flow_tracker_tlvs` | `flow_tracker.xdp.o` | Partial - build only |
| `flow_tracker_combo` | `flow_tracker.xdp.o` | Partial - build only |

**Test approach:** Build the sample, use `bpftool prog load` (dry-run) or
`llvm-objdump` to verify the .xdp.o contains valid BPF bytecode. Full runtime
testing requires root/kernel access which is not available in Nix sandbox.

## Implementation

### Test File Location

Tests are in `nix/tests/`:
```
nix/
├── tests/
│   ├── default.nix          # Exports all tests
│   └── simple-parser.nix    # simple_parser test (IMPLEMENTED)
```

### Flake Integration

In `flake.nix`:
```nix
tests = {
  simple-parser = import ./nix/tests/simple-parser.nix {
    inherit pkgs;
    xdp2 = packages.xdp2;
  };
};
```

### Key Implementation Details

1. **libpcap paths:** Use `pkgs.libpcap.lib` for library, `pkgs.libpcap` for headers
2. **Include paths for ClangTool:** Set environment variables for xdp2-compiler:
   - `XDP2_C_INCLUDE_PATH` - Clang resource dir includes
   - `XDP2_GLIBC_INCLUDE_PATH` - glibc headers
   - `XDP2_LINUX_HEADERS_PATH` - Linux kernel headers
3. **Runtime library path:** Set `LD_LIBRARY_PATH` for xdp2 and libpcap libraries

## Test Verification Criteria

### simple_parser Test

| Check | Expected | Nix Status | Ubuntu Status |
|-------|----------|------------|---------------|
| Build succeeds | Exit code 0, binaries exist | ✅ | ✅ |
| Basic parsing | Output contains "IPv6:" | ✅ | ✅ |
| TCP option parsing | Output contains "TCP timestamps" | ✅ | ✅ |
| Hash computation | Output contains "Hash" | ✅ | ✅ |
| Optimized mode IPv6 | `-O` produces "IPv6:" | ✅ | ✅ |
| Optimized mode Hash | `-O` produces "Hash" | ✅ | ✅ |
| Basic/Optimized match | Both modes produce identical output | ✅ | ✅ |

## Environment Requirements

For parser tests:
- `LD_LIBRARY_PATH` must include xdp2's lib directory and libpcap.lib
- xdp2-compiler must be in PATH
- For Nix: XDP2_*_INCLUDE_PATH environment variables must be set

For XDP build tests:
- clang with BPF target support
- Linux headers
