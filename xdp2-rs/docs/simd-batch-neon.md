# `simd_batch` NEON port — aarch64 path for the userspace batch parser

**Status (2026-06-14)**: shipped. `xdp2-bench --mode simd` now runs on
both `x86_64` (AVX2) and `aarch64` (NEON). FlowMeta output is
byte-identical across arches; `cargo test --release -p xdp2-bench`
passes 93/93 on both. Cortex-A76 measurements in
[`perf-results/2026-06-14-rust-neon-pi5/`](../../perf-results/2026-06-14-rust-neon-pi5/).

## At a glance

[`simd_batch.rs`](../crates/xdp2-bench/src/simd_batch.rs) is the
batch-of-8 packet parser used by `--mode simd`. Before this port it
was AVX2-only; on aarch64 it silently degraded to a scalar fallback
that was indistinguishable from `--mode compiled`. That made
cross-arch SIMD claims for xdp2-rs impossible — the kernel
`series3-flowdis-fastpath` patch has measured wins on Cortex-A76
(see `perf-results/2026-06-10-series3-non-fast-path/` etc.) but the
userspace bench couldn't mirror that coverage.

This port closes the gap. The aarch64 path uses NEON intrinsics
(`vceqq_u32`, `vandq_u32`, `vaddvq_u32`) over two 128-bit Q registers
to do the same classification work the AVX2 path does in one
256-bit YMM. Same fast-path coverage (Eth → IPv4 [IHL=5, not
fragmented] → TCP/UDP/ICMPv4/SCTP), same scalar fallback contract,
same `FlowMeta` writes.

## Why a NEON path

The xdp2-rs benchmark matrix wants to publish cross-arch numbers.
Before this port, the picture was:

| arch | scalar best (graph-enum) | SIMD path | result |
|---|---|---|---|
| x86_64 | ~104 ns/pkt (hp5 / fast workload) | AVX2 batch → ~40 ns/pkt | 2.6× SIMD win |
| aarch64 | ~22-79 ns/pkt (workload-dependent) | scalar fallback only | **no SIMD comparison possible** |

The kernel-side `series3-flowdis-fastpath` patch is portable C and
runs equivalently on x86 and ARM (measured -42% to -55% on A53 /
A72 / A76 testbeds). The userspace bench should be able to do the
same kind of cross-arch comparison; this port lets it.

The kernel patch deliberately stays scalar — per-skb invocation +
`kernel_fpu_begin/end` overhead would erase the SIMD win in-kernel —
so the lesson the patch took from this work was "skip the graph walk
for common shapes," not the batched-classification trick. That
remains correct. This NEON port is purely about the **userspace
benchmark** lining up across arches.

## How NEON differs from AVX2 in this code

The interesting observation, after reading the file in detail: of
the six pipeline stages in `parse_8_avx2`, **only stage 3 (the
ethertype compare) actually uses AVX2 intrinsics**. The other five
stages are scalar code that compiles unchanged on aarch64.

| stage | work | x86_64 implementation | aarch64 implementation |
|---|---|---|---|
| 1 | length check (≥ 42 B) | scalar loop | identical scalar loop |
| 2 | ethertype gather (8× be16 reads) | scalar loop | identical scalar loop |
| **3** | **compare 8 ethertypes == 0x0800** | `_mm256_set_epi32` + `_mm256_cmpeq_epi32` + `_mm256_movemask_epi8` + `compress_byte_mask_to_lanes` | `vld1q_u32` × 2 + `vceqq_u32` × 2 + AND-with-`[1,2,4,8]` + `vaddvq_u32` × 2 |
| 4 | IHL == 5 check | scalar loop | identical scalar loop |
| 5 | protocol + L4 min-length check | scalar loop | identical scalar loop |
| 6 | metadata extract | scalar `extract_fast_path_meta` | identical scalar |

So the diff is small (~120 lines), and the AVX2 hot path is
untouched — zero risk of regressing the x86 numbers.

### The width problem

NEON's Q registers are 128 bits (4× u32 lanes); AVX2's YMM registers
are 256 bits (8× u32 lanes). The natural NEON batch size is 4
packets per compare, not 8.

To keep the 8-packet batch API (so `bench.rs` calls a single
`parse_batch` entry across arches with no extra dispatcher), the
NEON path issues **two** 4-lane `vceqq_u32` ops in sequence. LLVM
can — and does — schedule them on independent issue ports on modern
Arm cores, so the cost is much less than 2× a single compare.

### The gather problem

AVX2 has `vpgatherdd` (one 256-bit gather instruction reads 8 lanes
from 8 independent pointers). The `simd_batch.rs` doc comments
describe this as the theoretical speedup mechanism, but the actual
implementation uses *scalar* per-packet reads to fill the
`ethertypes` array, then loads it into a YMM via `_mm256_set_epi32`.
That means even on x86 the gather isn't actually being used — the
"compare 8 lanes at once" win comes from the parallel compare, not
the gather.

Baseline NEON (Armv8.2-A on Pi 5 / A76) has no equivalent of
`vpgatherdd`. Apple's SVE2 (Armv9.0+, Neoverse V2, Cortex-X2+) does
have gather loads, but no hardware in the current xdp2 testbed
exposes it. So the NEON port doesn't lose anything by not having
gather — there's nothing to give up.

### Lane-mask reduction

AVX2: `_mm256_movemask_epi8` returns 32 bits (one bit per byte). A
small helper (`compress_byte_mask_to_lanes`) collapses every 4-bit
group to a single lane bit → 8-bit mask.

NEON has no direct movemask. The idiom used here:

```rust
let bit_pos_arr: [u32; 4] = [1, 2, 4, 8];
let bit_pos = vld1q_u32(bit_pos_arr.as_ptr());
let bits_lo = vandq_u32(cmp_lo, bit_pos);   // lane i: 0 or bit_pos[i]
let mask_lo = vaddvq_u32(bits_lo) as u8;    // horizontal-sum → 0..15
```

After the AND, lanes that matched contribute their bit position
value (1, 2, 4, or 8); lanes that didn't contribute 0. Horizontal-add
across the Q register produces a 4-bit mask in a single instruction
(`addv`). Two of these — one for lanes 0-3, one for lanes 4-7 —
produce a u8 lane-mask exactly matching what `compress_byte_mask_to_lanes`
produces on x86.

## Measurements

Pi 5 (Cortex-A76, 2.4 GHz max, `schedutil` governor, kernel 6.12.87,
`taskset -c 3`, rustc 1.91.1, release + fat LTO + `target-cpu=native`).
5 trials each, medians shown.

### tcp_ipv4.pcap (11 packets, 100% fast-path eligible) — 5000 iter

| mode | ns/pkt | Mpps | vs simd |
|---|---:|---:|---:|
| template | 18 | 55.6 | template wins on this workload |
| mono | 26 | 38.5 | -33% vs simd |
| compiled | 26 | 38.5 | -33% vs simd |
| **simd (NEON)** | **39** | **25.6** | — |
| graph-enum | 74 | 13.5 | **simd wins 1.9×** |
| graph | 261 | 3.8 | **simd wins 6.7×** |

### broad-coverage.pcap (5200 packets, mixed shapes) — 500 iter

| mode | ns/pkt | Mpps | vs simd |
|---|---:|---:|---:|
| **graph-enum** | **22** | **45.5** | graph-enum wins 2.5× vs simd |
| template-simd | 43 | 23.3 | |
| mono | 46 | 21.7 | |
| compiled | 46 | 21.7 | |
| template | 49 | 20.4 | |
| **simd (NEON)** | **56** | **17.9** | — |
| graph | 317 | 3.2 | simd wins 5.7× |

### Cross-arch (fast-path-eligible workload only)

| arch | host | ISA | ns/pkt @ simd |
|---|---|---|---:|
| x86_64 | hp5 (Zen 1, Ryzen 5 PRO 2400G) | AVX2 (256-bit, 8-lane compare) | 29 |
| x86_64 | 3945WX (Zen 2, Threadripper) | AVX2 (256-bit, 8-lane compare) | 38–40 |
| aarch64 | pi5-1 (Cortex-A76) | NEON (128-bit, 2× 4-lane compare) | 39 |

The Pi 5 result is in the same absolute band as the Zen 2 — despite
the A76 being ~10× slower than the 3945WX on typical scalar
workloads. That points at memory-access latency dominating ALU
throughput in this parser, which is consistent with the
classification-then-scalar-extract structure: the SIMD compare is
~1 cycle of the per-packet budget, the rest is dependent loads on
the packet bytes.

## What this port does not change

- **Coverage**: still Eth → IPv4 (IHL=5, no fragments) →
  TCP/UDP/ICMPv4/SCTP. Anything with VLAN, IPv6, IP options, IP
  fragments, or other transports gets the scalar fallback per
  packet. This is the same restriction the AVX2 path has and
  matches what the kernel `series3-flowdis-fastpath` patch
  accelerates.
- **Per-packet metadata extraction**: still scalar. The SIMD stages
  *classify*; `extract_fast_path_meta` (shared between arches)
  writes the per-packet FlowMeta fields.
- **AVX2 path**: untouched. The refactor renamed the public entry
  from `parse_batch_avx2` to `parse_batch` and split the cfg gates,
  but the body of `parse_8_avx2` is byte-for-byte the same.

## When `--mode simd` wins, when it doesn't

Empirical rule from the cross-arch matrix:

- **Wins on workloads where every batch lights up.** Single-stack
  Eth+IPv4 (tcp_ipv4, https-web, vxlan-k8s-pure) — the 8-packet
  batch processes all 8 packets through the fast path.
- **Loses on mixed-shape workloads.** broad-coverage,
  combo.pcap, mixed-real — most packets fall through to scalar
  fallback per batch, and the batch bookkeeping is pure overhead.
- **Always loses to `template` on tiny pcaps.** With only 11
  packets in `tcp_ipv4.pcap`, the per-batch setup cost
  (initializing the 8-pointer / 8-length arrays) isn't amortized.
  `--mode template` is the right choice for very small workloads.

The honest framing: `--mode simd` is a *workload-specific* win,
not a universal one. It's most useful as evidence that
"the SIMD batch classification technique works" — which the
`series3-flowdis-fastpath` kernel patch then leverages in its
scalar-but-shape-specialized form.

## Future tiers

| ISA | width | gather | status | when to revisit |
|---|---|---|---|---|
| AVX2 | 256-bit | yes (`vpgatherdd`, but not actually used here) | shipped | — |
| NEON (Armv8.2-A) | 128-bit | no | shipped 2026-06-14 | — |
| SVE2 (Armv9.0+) | 128–2048-bit (impl-defined) | yes (`sv*gather*`) | deferred | when Neoverse V2 / Cortex-X2 hardware joins the testbed |
| AVX-512 | 512-bit | yes | deferred | mentioned in `deep-performance-analysis.md` as projected 1-2 cyc/pkt on Zen 4+; needs Zen 4 hardware |

SVE2 is the next interesting tier on aarch64: vector length is
implementation-defined (typically 128 or 256 bits — Apple M4 has
128, Neoverse V2 has 128), and unlike baseline NEON it has
real gather loads. The lane-mask reduction also gets easier
(`whilelt` / `ptrue` predicates eliminate the AND-with-bit-position
trick). When the testbed gains an SVE2-capable ARM host, copying
the structure from `parse_8_neon` to `parse_8_sve2` should be a
small diff, parallel to what this port did.

## Reproducing the measurements

See [`perf-results/2026-06-14-rust-neon-pi5/summary.md`](../../perf-results/2026-06-14-rust-neon-pi5/summary.md)
for the exact rsync + nix-shell + cargo build + bench-loop
sequence used here.

## Files touched

- `xdp2-rs/crates/xdp2-bench/src/simd_batch.rs` — added the NEON
  pipeline (`parse_batch` + `parse_8_neon` under `#[cfg(target_arch = "aarch64")]`),
  renamed the public entry from `parse_batch_avx2` to `parse_batch`,
  widened the scalar fallback's cfg gate
- `xdp2-rs/crates/xdp2-bench/src/bench.rs` — three call-sites
  updated, "AVX2 not available" warning generalized
- `xdp2-rs/docs/deep-performance-analysis.md`,
  `xdp2-rs/docs/adding-protocol-support.md`,
  `xdp2-rs/docs/performance-by-platform.md`,
  `xdp2-rs/README.md` — text updates indicating the NEON path's
  existence and pointing here
