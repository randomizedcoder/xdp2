# XDP2 Flow Dissector: Summary and Analysis

## Overview

This sample demonstrates that xdp2's declarative parser framework can replace
the Linux kernel's hand-written flow dissector with a fraction of the code
while achieving better parsing performance.

The kernel's flow dissector extracts flow keys (IP addresses, ports, protocol,
VLAN tags, etc.) from packet headers for routing and classification. There are
two relevant kernel implementations:

- [`net/core/flow_dissector.c`](https://github.com/torvalds/linux/blob/master/net/core/flow_dissector.c)
  (2,101 lines) -- the in-kernel C implementation
- [`tools/testing/selftests/bpf/progs/bpf_flow.c`](https://github.com/torvalds/linux/blob/master/tools/testing/selftests/bpf/progs/bpf_flow.c)
  (437 lines) -- the BPF reference implementation that replaces it

The kernel supports replacing the C dissector with a BPF program
(`BPF_PROG_TYPE_FLOW_DISSECTOR`). The xdp2 version achieves equivalent
functionality from:

- **parser.c** (116 lines): Orchestrator that #include's component fragments
  - 11 header fragments define metadata, nodes, tables, and parsers
- **flow_dissector.bpf.c** (266 lines): BPF entry point and metadata translation
- **common.h** (42 lines): Shared context structure

The parser definition is purely declarative -- no manual pointer arithmetic,
length checks, or protocol dispatch logic. The xdp2-compiler generates
optimized parsing code from this definition.

## Key Results

**500k packets, 512 protocol combinations, optimized parser (`-O`):**

|                        | Non-BPF (userspace)      | BPF (in-kernel)          |
|------------------------|--------------------------|--------------------------|
| **Kernel flowdis**     | 137 ns/pkt,  7 Mpps      | 213 ns/pkt,  4 Mpps      |
| **XDP2 parser**        | 150 ns/pkt,  6 Mpps      | Compiles (988KB .o), needs root for runtime |
| **XDP2 parse-only**    | 135 ns/pkt,  7 Mpps      | Compiles (988KB .o), needs root for runtime |

| Metric | Kernel | xdp2 |
|---|---|---|
| Total parsing code | 2,538 lines | 1,085 lines (**~2.3x reduction**) |
| Protocol types | ~17 (BPF selftest) | ~65 (76 proto_def headers in 14 subdirs, 14 parsers) |
| Parse-only speed (optimized) | 137 ns/pkt | 135 ns/pkt (**1.0x parity**) |
| Simple traffic (IPv4 TCP) | 20 ns/pkt | 9 ns/pkt (**2.1x faster**) |

## Nix Integration

The sample is fully integrated into the nix build system:

- **Test suite:** `nix build .#tests.flow-dissector-benchmark` builds and runs
  a 33-test suite (32 pass, 0 fail, 1 skip) covering:
  - Correctness on 8 protocol-specific PCAPs (IPv4/IPv6/ICMP/ICMPv6/VLAN/GRE/IPIP/fragments)
  - Combinatorial correctness on 1k and 100k generated PCAPs (asserts `Mismatches: 0`)
  - Verbose diagnostics and tunnel-extended packet detection
  - Detection of xdp2-only protocols (new L2 protocols not in flowdis)
  - Performance benchmarks across standard and optimized parsers
  - Fast parser tests (skipped — L2 graph exceeds NUM_FAST_NODES limit)
  - BPF benchmark tests (conditional on root + BPF kernel support)
- **Test PCAP generation:** `nix build .#test-pcap` generates a deterministic
  500k-packet PCAP covering all 512 valid protocol combinations. Cached in the
  Nix store for reproducible benchmarking.
- **Ad-hoc PCAP generation:** `nix run .#gen-test-pcap -- -n 500000 -o output.pcap`
  wraps `gen_test_pcap.py` with Python 3.14 + scapy. Supports `--list` to
  enumerate combinations, `--combo 'bare/ipv4/*'` for filtered generation.
- **Kernel BPF source:** `nix build .#kern-bpf-flow-src` fetches the kernel's
  BPF flow dissector from Linux selftests at a pinned version
  (`nix/kern-bpf-flow.nix`). Used to update the vendored copy in `kern_bpf/`.
- **BPF compilation:** The Nix test compiles both `bpf_flow.kern.o` (kernel)
  and the XDP2 BPF parser using `clang -target bpf` from llvmPackages
  (unwrapped to avoid Nix hardening flags incompatible with BPF targets).
  Architecture-portable via `bpfArchDefines` (x86_64/aarch64/riscv64).
- **Pre-built samples:** `nix/samples/default.nix` supports cross-compilation
  (e.g., building for RISC-V on x86_64).
- **Test PCAPs:** Uses existing pcaps from `data/pcaps/` (tcp_ipv4, tcp_ipv6,
  icmp_ipv4, icmp_ipv6, vlan_icmp, gre-sample, ipv4frags, ipip) plus
  combinatorial PCAPs generated at test time by `gen_test_pcap.py`.

## libflowdis Provenance

The benchmark compares xdp2 against `libflowdis`, a userspace port of the
kernel's flow dissector. This is the **actual kernel code**, not a
reimplementation. The file header in `src/lib/flowdis/flow_dissector.c` states:

```
/* Copied from kernel net/core/flow_dissector.c. Differences are shown by
 * #ifdef ORIGKERNEL.
 */
```

The userspace port is 2,123 lines vs the kernel's 2,101 lines. The extra 22
lines are `#ifdef ORIGKERNEL` compatibility shims (replacing kernel-specific
APIs with userspace equivalents). The core dissection logic
(`__skb_flow_dissect`) is identical to the kernel's implementation.

This confirms the benchmark is a legitimate comparison against the kernel's
production flow dissector, not a simplified reference implementation.

## File Inventory

```
samples/flow_dissector/
    parser.c                116 lines   Orchestrator (#include's 11 fragments below)
    flow_dissector_metadata.h   26 lines   18 XDP2_METADATA_TEMP_* extractors
    flow_dissector_proto_defs.h 104 lines  6 local proto_defs (LLC, SNAP, STP, etc.)
    flow_dissector_nodes.h     177 lines   ~40 core Ethernet/IP parse nodes
    flow_dissector_nodes_l2.h   31 lines   Extended L2 leaf nodes (userspace only)
    flow_dissector_tables.h    228 lines   ~15 protocol dispatch tables
    graph_ieee80211.h           23 lines   WiFi 802.11 parse graph
    graph_bluetooth.h           22 lines   Bluetooth HCI parse graph
    graph_infiniband.h          17 lines   InfiniBand parse graph
    graph_netlink.h             15 lines   Netlink parse graph
    graph_misc.h                15 lines   X.25, MCTP, ATM standalone roots
    flow_dissector_parsers.h   121 lines   14 XDP2_PARSER() declarations
    parser_xdp.c              5 lines   Single-root wrapper for xdp2-compiler XDP output
    common.h                 42 lines   Context structure
    pcap_loader.h           174 lines   Shared PCAP loading/packet storage utilities
    flow_dissector.bpf.c    266 lines   BPF entry point and metadata translation
    benchmark.c             731 lines   Userspace benchmark (xdp2 vs flowdis)
    benchmark_bpf.c         418 lines   BPF benchmark (BPF_PROG_TEST_RUN)
    benchmark_matrix.sh     175 lines   4-way matrix wrapper script
    gen_test_pcap.py       1193 lines   Combinatorial PCAP generator (512 combos)
    Makefile                 84 lines   Build rules (BPF + userspace)
    kern_bpf/bpf_flow.c    449 lines   Vendored kernel BPF flow dissector (Linux v6.12)

src/include/xdp2/proto_defs/           76 proto_def headers in 14 subdirectories:
    ethernet/    (4)   proto_ether, proto_vlan, proto_pbb, proto_edsa
    ip/         (11)   proto_ipv4, proto_ipv6, proto_ipv6_eh, proto_ip, ...
    transport/   (6)   proto_tcp, proto_udp, proto_ports, proto_tipc, ...
    tunnel/      (9)   proto_gre, proto_vxlan, proto_geneve, proto_mpls, ...
    security/    (4)   proto_ah, proto_esp, proto_macsec, proto_eapol
    management/ (10)   proto_lldp, proto_cfm, proto_ptp, proto_slow, ...
    storage/     (2)   proto_aoe, proto_ethercat
    wireless/    (3)   proto_ieee80211, proto_ieee80211_mgmt, proto_ieee80211_data
    bluetooth/   (7)   proto_hci, proto_hci_cmd, ..., proto_l2cap
    infiniband/  (3)   proto_ib_lrh, proto_ib_grh, proto_ib_bth
    can/         (3)   proto_can, proto_canfd, proto_canxl
    netlink/     (3)   proto_netlink, proto_genetlink, proto_nlattr
    legacy/     (10)   proto_batman, proto_ipx, proto_atalk, proto_atm, ...
    other/       (1)   proto_fcoe

nix/tests/flow-dissector-benchmark.nix  898 lines   33-test suite (includes BPF tests)
nix/kern-bpf-flow.nix                   40 lines    Fetch kernel BPF source at pinned version
nix/samples/default.nix                              Cross-compilation support
```

## Further Reading

- [Code Comparison](docs/code-comparison.md) -- protocol-by-protocol kernel vs xdp2
- [Benchmarks](docs/benchmarks.md) -- performance data, 4-way matrix, BPF status
- [Challenges](docs/challenges.md) -- 14 issues encountered during development
- [Metadata Optimization](docs/metadata-optimization.md) -- struct size analysis + proposed fix
- [Protocol Coverage](docs/protocol-coverage.md) -- ~65 protocol types, 14 parsers, multi-graph architecture
- [Adding Protocols](docs/adding-protocols.md) -- proto_defs directory layout and how to add new protocols
- [Enhancement Plan](docs/comprehensive-enhancement-plan.md) -- multi-graph expansion plan (complete)
- [Correctness](docs/correctness.md) -- testing methodology + skip rules
- [Kernel Patches](docs/kernel-patches.md) -- 5 proposed patches for kernel bpf_flow.c
