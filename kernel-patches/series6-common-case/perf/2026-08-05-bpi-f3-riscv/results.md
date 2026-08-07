# flow-menu-bench — bpi-f3 (RISC-V) — BLOCKED by DUT kernel

Date: 2026-08-05. Host: **bpi-f3** (Banana Pi BPI-F3, SpacemiT K1, 8× X60
rv64gcv), kernel 7.2.0-rc1 riscv64. The riscv64 cross build succeeded
(`nix build .#flow-menu-bench-riscv64`, closure copied to the board), but the
**benchmark could not run: the kernel rejects flow_dissector BPF programs**.

## What happened

`benchmark_bpf`/`parity_test` load each object via libbpf; on bpi-f3 the verifier
rejects with `-EACCES`:

```
libbpf: prog 'flow_dissector_eth_ipv4_tcp': BPF program load failed: -EACCES
...
21: (61) r1 = *(u32 *)(r5 +12)     # read iph->saddr, within the 20 bytes
                                   # just bounds-checked at insn 11
libbpf: prog 'flow_dissector_eth_ipv4_tcp': failed to load: -EACCES
```

## This is the DUT kernel, not our objects

Two controls prove it:
1. **The in-tree kernel reference dissector fails identically** —
   `bpf_flow.kern.o` (the kernel's own selftest flow dissector) also returns
   `-EACCES` on `_dissect` on bpi-f3.
2. **The x86-built object fails the same way** — copying the x86-compiled
   `fast_flow_eth_ip.bpf.o` to bpi-f3 and loading it with the RISC-V
   `benchmark_bpf` gives the same `-EACCES`, so it is not a cross-compilation
   bytecode difference (our objects use no CO-RE; the bytecode is identical
   across arches and loads fine on x86 and ARM).

The same bytecode loads + verifies on x86 (hp5, net-next 7.2.0-rc1) and ARM
(pi5-2, 6.18) but not on this RISC-V kernel. `CONFIG_BPF_JIT=y` is **absent**
from bpi-f3's `/proc/config.gz` (only `CONFIG_HAVE_EBPF_JIT=y`); the board runs
the BPF interpreter, and this kernel's verifier rejects the packet-access
pattern that the x86/ARM kernels accept.

## Status

RISC-V microbench via `BPF_PROG_TEST_RUN` is **blocked on bpi-f3's current
kernel** — for every flow_dissector BPF program, including the kernel's own.
Unblocking needs a bpi-f3 kernel rebuilt with `CONFIG_BPF_JIT=y` (and whatever
verifier fix the x86/ARM kernels carry). Cross-ISA correctness for RISC-V is
therefore pending a kernel rebuild, not a code change. The userspace C ways
(non-BPF) do run on RISC-V and were exercised in prior matrix runs.

x86 (Zen 2, Zen 1) and ARM (Cortex-A76) all show GOLD parity + ~2–4× on the
five in-tree-oracle shapes; see the sibling `perf/` dirs and `../../PERFORMANCE.md`.
