# XDP2 Sample Tests Status - x86_64

**Date:** 2026-03-10
**Platform:** x86_64 Linux
**Branch:** bpf-compat-and-nix-samples

## Summary

All x86_64 parser sample tests pass. XDP BPF bytecode compilation now works via Nix.

## Test Results

### Parser Sample Tests

| Test Suite | Tests Passed | Tests Failed | Status |
|------------|--------------|--------------|--------|
| simple_parser | 14 | 0 | PASS |
| offset_parser | 8 | 0 | PASS |
| ports_parser | 8 | 0 | PASS |
| flow_tracker_combo | 8 | 0 | PASS |
| **Total** | **38** | **0** | **PASS** |

### XDP BPF Compilation

| Sample | Size | Status |
|--------|------|--------|
| flow_tracker_simple.xdp.o | 49KB | PASS |
| flow_tracker_combo.xdp.o | 77KB | PASS |
| flow_tracker_tmpl.xdp.o | 53KB | PASS |

## Build Commands

```bash
# Run all parser tests
nix build .#tests.all && ./result/bin/xdp2-test-all

# Build XDP samples (BPF bytecode)
nix build .#xdp-samples
```

## Changes Required for BPF Compatibility

The following changes were made to enable BPF compilation:

### New Files

- `src/include/xdp2/bpf_compat.h` - BPF compatibility header providing:
  - libbpf's `bpf_endian.h` for byte-order functions
  - Maps `htons/ntohs/htonl/ntohl` to `bpf_*` versions
  - `linux/in.h` for `IPPROTO_*` constants
  - Falls back to `arpa/inet.h` for userspace

### Modified Files

| File | Change |
|------|--------|
| `proto_gre.h` | Use `bpf_compat.h` instead of `arpa/inet.h` |
| `proto_ipv4.h` | Use `bpf_compat.h` instead of `arpa/inet.h` |
| `proto_ipv6.h` | Use `bpf_compat.h` instead of `arpa/inet.h` |
| `proto_ipv6_eh.h` | Use `bpf_compat.h` instead of `arpa/inet.h` |
| `proto_arp_rarp.h` | BPF-compatible ARP definitions, use `bpf_compat.h` |
| `proto_icmp.h` | Minimal BPF-compatible ICMP struct definitions |
| `proto_ipv6_nd.h` | BPF guards for include ordering |
| `parser_types.h` | Added `stdint.h` for `uintptr_t` in BPF |
| `bpf.h` | Guarded `stdlib.h` with `#ifndef __bpf__` |

### Nix Infrastructure

- `nix/xdp-samples.nix` - Derivation for building XDP BPF programs
- Uses unwrapped clang to avoid Nix cc-wrapper hardening flags
- Sets proper include paths for libbpf and linux headers

## Known Limitations

1. **XDP Runtime Tests Skipped** - BPF stack limitations and template API mismatches prevent some XDP samples from running in the kernel
2. **flow_tracker_tlvs** - Not yet building due to additional dependencies

## Next Steps

- Test same samples on RISC-V platform
- Address BPF stack limitations in XDP2_METADATA_TEMP_* macros
- Update xdp_def.template.c to use current ctrl API

---

# RISC-V Testing Plan

## Current State

- RISC-V MicroVM is built: `result-riscv64`
- VM runs with QEMU TCG (software emulation)
- VM has `/nix/store` mounted via virtio-9p

## Running RISC-V Tests

To run the XDP2 sample tests on RISC-V, we need to:

1. **Cross-compile xdp2-debug for riscv64**
2. **Cross-compile the test derivations for riscv64**
3. **Run tests inside the RISC-V VM**

### Option A: Manual Testing via VM Console

```bash
# Start the RISC-V VM
./result-riscv64/bin/microvm-run

# In another terminal, connect to VM console
nc localhost 23521

# Inside VM, tests would need to be pre-built for riscv64
```

### Option B: Automated Cross-Compilation (WIP)

Cross-compilation infrastructure exists in:
- `nix/cross-tests.nix` - Cross-compilation module

Build cross-compiled tests (WIP):
```bash
# Not yet implemented - needs flake.nix integration
nix build .#riscv64-tests.all
```

## Architecture-Specific Considerations

| Aspect | x86_64 | RISC-V |
|--------|--------|--------|
| Build Time | Native | Cross-compiled |
| Runtime | Native | QEMU TCG |
| Performance | Fast | Slow (emulated) |
| KVM | Yes | No (requires rv64 host) |
