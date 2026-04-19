# xdp2-flow-loader

Userspace loader + control plane for
[`xdp2-flow-ebpf`](../../../samples/flow_dissector/fast_bpf/), the
production-quality fast-path BPF flow dissector described in
[`super-flow-dissector-plan.md`](../../../samples/flow_dissector/docs/super-flow-dissector-plan.md)
§5.

## Responsibilities

1. Open a fast-path BPF object (`fast_flow.bpf.o`).
2. Load its programs and populate the `jmp_table` PROG_ARRAY with every
   non-entry program in declaration order (matching the `CHAIN_*`
   indices in `fast_flow.bpf.c`).
3. Optionally install a slow-path program into `CHAIN_DYNAMIC` so
   fast-path misses tail-call into a full dissector instead of returning
   `BPF_FLOW_DISSECTOR_CONTINUE` (plan milestone D6).
4. Attach the entry program to a network namespace's `flow_dissector`
   hook.
5. (Future) Consume template updates from `xdp2-fastpath-control` (plan
   §5a) and refresh the `CHAIN_DYNAMIC` slot at runtime.

## Status

**D7a skeleton.** The API surface is frozen and the CLI parses all the
documented arguments; every operation returns
`LoaderError::NotImplemented`. D7b will add the libbpf-backed
implementation, mirroring the existing C loaders in
`samples/flow_dissector/fast_bpf/parity_test.c` and
`samples/flow_dissector/benchmark_bpf.c`.

## Usage (once D7b lands)

```bash
xdp2-flow-loader \
    --bpf fast_flow.bpf.o \
    --slow-path flow_dissector.bpf.o \
    --netns /proc/self/ns/net
```
