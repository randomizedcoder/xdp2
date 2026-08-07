# flow-menu-bench — pi5-2 (ARM Cortex-A76) microbench

Date: 2026-08-05. Host: **pi5-2** (Broadcom BCM2712, 4× Cortex-A76, ARMv8),
kernel 6.18.34, 16 KiB pages. Built by **cross-compiling on `l`** (flake
`pkgsCrossAarch64` + `xdp2-debug-aarch64`, `nix build .#flow-menu-bench-aarch64`),
closure `nix copy`'d to the Pi and run there. Same harness/corpus as x86.

## Results (ns/pkt, lower is better)

| shape | fast | in-tree | speedup | parity |
|---|---:|---:|---|---|
| eth_ip | 42 | 123 | 2.9× | **GOLD** |
| vlan   | 36 | 111 | 3.1× | **GOLD** |
| qinq   | 35 | 146 | 4.2× | **GOLD** |
| ipip   | 49 | 163 | 3.3× | **GOLD** |
| gre    | 64 | 197 | 3.1× | **GOLD** |
| mpls   | 38 | 154 | — (in-tree stub) | c-dissector |
| pppoe  | 36 | 136 | — (in-tree drops) | series2 |
| vxlan  | 57 | 157 | descends | c-dissector |
| geneve | 59 | 137 | descends | c-dissector |
| gtpu   | 56 | 167 | descends | c-dissector |

**GOLD parity on all five in-tree-oracle shapes on ARM**, ~3–4× faster than the
in-tree BPF dissector — the same story as x86, confirming the objects are correct
and fast across ISAs. (BPF is portable bytecode; the object built the same, the
kernel JITs for A76 at load.)

Notes:
- OOM fix: the loader's `calloc(MAX_PACKETS, 64 KiB)` was ~32 GiB (fine on big-RAM
  x86, OOM on the 8 GB Pi); `MAX_PACKETS` is now `#ifndef`-guarded and the
  flow-menu-bench build passes `-DMAX_PACKETS=4096` (corpus pcaps are ≤40 pkts).
- Cross-compiled on `l` (many cores) rather than natively on the Pi — no qemu.
