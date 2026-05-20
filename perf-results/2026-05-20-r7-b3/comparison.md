# R7-B3 — Typed-store metadata transfers — null result

Run: 2026-05-20, hp2-hp5-x710, full 6-workload non-smoke sweep.
Build: post-R7-B1 (commit with hot-edge shortcut) + B3 template
change to emit `*(__u16/__u32/__u64 *)` typed stores in place
of `memcpy()` for power-of-2 sized transfers.

## TL;DR

**Null result on perf, kept for codegen clarity.** Every cell
within ±2 ns of R7-B1 baseline. gcc -O3 -march=native -flto was
already lowering `memcpy(dst, src, 2/4/8)` to the same `mov`
instructions a typed store produces.

## Change

`mono_def.template.c:366` — replace unconditional `memcpy()` emit
with size-cased typed store:

```c
<!--(if t['length'] == 16)-->
*(__u16 *)((char *)metadata + dst_off / 8) =
    *(const __u16 *)((const char *)hdr + src_off / 8);
<!--(elif t['length'] == 32)-->
*(__u32 *)((char *)metadata + dst_off / 8) =
    *(const __u32 *)((const char *)hdr + src_off / 8);
<!--(elif t['length'] == 64)-->
*(__u64 *)((char *)metadata + dst_off / 8) =
    *(const __u64 *)((const char *)hdr + src_off / 8);
<!--(else)-->
memcpy(...);  /* 96-bit eth_addrs, 128/256-bit v6_addrs */
<!--(end)-->
```

Generated parser.mono.c emit counts:
- 28 typed `__u16` stores
- 196 typed `__u32` stores
- 0 typed `__u64` stores (no 8-byte exact transfers in flow-dissector graph)
- 60 `memcpy()` fallbacks (12-byte eth_addrs, 16-byte v6 addr, 32-byte addrs.v6_addrs)

## Perf delta vs R7-B1 (hp5)

| workload | R7-B1 | R7-B3 | Δ |
|---|---:|---:|---:|
| https-web | 72 | 72 | 0 |
| k8s-microservices | 132 | 131 | -1 (noise) |
| nfs-server | 71 | 70 | -1 (noise) |
| pppoe-isp | 73 | 74 | +1 (noise) |
| vlan-tcp-mix | 72 | 70 | -2 (edge of noise) |
| vxlan-k8s-pure | 135 | 136 | +1 (noise) |

All within smoke noise band (±2 ns).

## Perf delta vs R7-B1 (hp2)

| workload | R7-B1 | R7-B3 | Δ |
|---|---:|---:|---:|
| https-web | 71 | 70 | -1 |
| k8s-microservices | 135 | 135 | 0 |
| nfs-server | 71 | 70 | -1 |
| pppoe-isp | 75 | 75 | 0 |
| vlan-tcp-mix | 71 | 73 | +2 |
| vxlan-k8s-pure | 139 | 138 | -1 |

Same picture on hp2 — no measurable change.

## Why null?

gcc -O3 with `-flto` (which we ship since R6) recognises
`memcpy(dst, src, SMALL_CONSTANT)` as a builtin pattern and
lowers it to typed loads/stores when both pointers are aligned
to the access size. For our common cases:

- `memcpy(metadata+24, hdr+12, 2)` → `movzwl 12(%rsi), %eax; mov %ax, 24(%rdi)`
- `memcpy(metadata+44, hdr+22, 4)` → `mov 22(%rsi), %eax; mov %eax, 44(%rdi)`

The typed-store template emit produces literally the same
assembly. No instruction-count change, no perf change.

The R3.3.4 inline-memcpy emit (introduced 2026-05-17) was
already paying off because it replaced indirect-call
`ops.extract_metadata(...)` with inline copies. The COPY
shape (memcpy vs typed) doesn't matter at gcc -O3.

## Decision: keep the change

The typed-store emit is correctness-clean (4914-cell matrix
0/0/0, parity-gate 32/32 OK, mono-perf ceiling 0 violations)
and slightly more readable in the generated `parser.mono.c`.
Reviewers can see "this is a 32-bit field copy" instead of
"this is a memcpy of 4 bytes".

No perf cost, marginal documentation benefit, structurally
unifies the metadata-write idiom with what rust-mono does
(direct typed field stores).

## What R7-B3 confirms about the gap

The 280 instr/pkt c-xdp2-mono vs rust-mono gap on tunnels is
**not in the memcpy() emit shape** — gcc was already lowering
optimally. The remaining gap must be in:

1. **Per-node function structure** (R7-B2 candidate, ~150 LoC).
   Rust-mono splits dispatch and extraction into per-protocol
   functions; c-xdp2-mono uses one giant function with `goto`
   labels. The LLVM/gcc backends may exploit smaller function
   scopes differently.

2. **Engine-level overhead** — `xdp2_core::engine::parse` is
   4.75% of rust-mono cycles per R7-A. The C-mono equivalent
   could be smaller, but the always_inline already inlines
   the dispatcher away.

3. **Branch prediction quality** — c-mono has 1.5× more
   branch-misses. Could be due to the binary-search switch
   trees (B1 partially addressed) or the per-node return-flow.

## Mono-perf ceiling

`mono-perf.md`: 12 cells, 0 violations.

## Files

- `comparison.md` — this file
- `sweep.md` — full hp2+hp5 matrix
- `mono-perf.md` — parity ceiling

## Recommendation

**Ship R7-B3 as a code-quality / readability improvement, not
a perf change.** The change is small (12 lines in the template),
correctness-clean, and produces more honest generated output.
But don't expect ns/pkt benefit — gcc already produced this
shape.

**Next perf headroom is R7-B2** (per-protocol functions). If
the user wants to keep pushing the tunnel gap, B2 is the
remaining lever. If R7-B1's 4-ns win on tunnels + the existing
4/6 cross-impl ties is sufficient for the kernel-team deliverable,
R7-B3 is a reasonable stopping point.
