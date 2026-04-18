# xdp2-flow-ebpf — production-quality BPF flow dissector (fast-path)

This directory contains the BPF programs that together implement
`xdp2-flow-ebpf`, the production-bound eBPF flow dissector described in
[`super-flow-dissector-plan.md`](../docs/super-flow-dissector-plan.md) §5.

The design is:

- A minimal entry program (`_dissect`) gates packets on a 16-byte
  signature match and dispatches via `bpf_tail_call` into a
  `BPF_MAP_TYPE_PROG_ARRAY` (`jmp_table`).
- Each tail-call slot is a specialised program that does fixed-offset
  reads only — no loops, no switch — for one top-N chain
  (ETH/IPv4/TCP, ETH/IPv6/TCP, …). Verifier-trivial.
- Packets that don't hit the fast path fall through to a slow-path
  dissector that preserves full protocol coverage.

## Current status (D1–D3 skeleton)

Tracked in [`../docs/super-flow-dissector-implementation.md`](../docs/super-flow-dissector-implementation.md).

- **D1** — directory + Makefile target ✅
- **D2** — entry program with signature match ✅ (partial: IPv4 fast-path
  gate only; IPv6/VLAN fast-path gates are TODO)
- **D3** — one specialised program: ETH/IPv4/TCP ✅
- **D4** — coverage parity test vs slow-path ⏳
- **D5** — remaining 7 fast-path slots ⏳
- **D6** — slow-path fallback ⏳ (currently drops non-fast-path packets)

## Build

```bash
nix develop --command make -C samples/flow_dissector bpf
```

Produces `fast_bpf/fast_flow.bpf.o`. Load and benchmark via:

```bash
./benchmark_bpf -b fast_bpf/fast_flow.bpf.o <pcap_file>
```

The existing [`benchmark_bpf.c`](../benchmark_bpf.c) loader auto-detects the
`jmp_table` PROG_ARRAY and populates it with all non-entry programs.

## File layout

- `fast_flow.bpf.c` — entry program + all specialised programs (will be
  split into per-chain files once D5 lands).

## Chain ID allocation

Keep `CHAIN_*` defines in this file in sync with
[`super-flow-dissector-plan.md`](../docs/super-flow-dissector-plan.md) §5.
The dynamic slot (`CHAIN_DYNAMIC`) is reserved for the §5a
listening-socket control plane.
