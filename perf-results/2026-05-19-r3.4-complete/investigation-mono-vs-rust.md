# Why is `c-xdp2-mono` 50 ns slower than `rust-mono` on vxlan-k8s-pure?

hp5 numbers from `summary.md` (2026-05-19 sweep):

| parser | vxlan-k8s-pure | https-web |
|---|---:|---:|
| c-xdp2-mono | 141 ns/pkt | 73 ns/pkt |
| rust-mono | **93 ns/pkt** | 72 ns/pkt |
| gap | **+48 ns** | +1 ns (noise) |

On the plain TCP workload the two are within noise. On the tunnel
workload (mono walks the full slow-path graph; the R3.4 fast-path
correctly bails on UDP-tunnel ports) rust is 50 ns faster.

## Hypotheses I tested

### H1: rust-mono extracts less metadata (= less work) ❌ DISPROVED

Per-packet parity records on a vxlan-k8s-pure packet:

```
c-xdp2-mono fields: addr_type, ip_proto, ipv4_src, ipv4_dst, sport,
                    dport, eth_proto, l2_off, l3_off, l4_off
                    (10 fields)

rust-mono   fields: addr_type, ip_proto, ipv4_src, ipv4_dst, sport,
                    dport, eth_proto, eth_dst, eth_src, ip_ttl,
                    tcp_flags
                    (11 fields)
```

**Rust extracts MORE fields than c-xdp2-mono** (eth_dst, eth_src,
ip_ttl, tcp_flags; misses l2_off/l3_off/l4_off). And the 20K-pkt
parity-check showed **0 field disagreements** between them on the
6 fields they both populate (addr_type, ip_proto, ipv4_src/dst,
sport, dport, eth_proto).

So rust is doing strictly more work in less time. H1 falsified.

### H2: c-xdp2-mono has lots of indirect ops calls (≈30 cycles each) ❌ DISPROVED

The slow-path mono codegen emits per-node:

```c
if (parse_node->ops.extract_metadata)
    parse_node->ops.extract_metadata(...)
if (parse_node->ops.handler)
    parse_node->ops.handler(...)
type = proto_def->ops.next_proto(hdr);
```

— three ops loads per node × 6-7 nodes on a vxlan walk ≈ 20+ indirect
calls per packet. At 4-8 cycles each that's ~120 cycles = 38 ns. That
would explain the gap.

But objdump on the compiled `xdp2_parser_flow_dissector_l2_xdp2_parse_mono`
shows **zero `call *` (indirect-call) instructions** in the function
body. Every `call` is a direct `call <symbol>` (vxlan_proto,
gre_v0_proto, icmp_metadata.constprop.0, etc).

gcc's `-O2` already devirtualises the ops calls because the
`parse_node` and `proto_def` structs are `static const` with
known addresses — the compiler folds `parse_node->ops.next_proto`
to a direct call to the underlying function. H2 falsified.

### H3: `__mono_check_pkt_len` per-node call overhead ❌ DISPROVED

The static-inline helper compiles into 1-2 `cmp` + branch per
node body — there's no `__mono_check_pkt_len` symbol in the binary
(fully inlined) and no references to it in the function asm.

### H4: Compile-flag asymmetry ✅ THE LIKELY CAUSE

Comparing build configurations:

|  | C (`samples/flow_dissector/Makefile`) | Rust (`xdp2-rs/Cargo.toml` + `nix/xdp2-rs.nix`) |
|---|---|---|
| optimisation | `-O2` | `release` (= `-O3` equivalent) |
| LTO | none | `lto = "fat"` (cross-crate inlining + DCE) |
| codegen-units | default (per-TU) | `codegen-units = 1` (single global unit) |
| target tuning | generic x86_64 | `RUSTFLAGS="-C target-cpu=native"` (uses Zen 1 ISA) |
| debug info | `-g` | release-default (slimmer) |

This is a non-trivial asymmetry. On parsing-heavy code, going from
`-O2` to `-O3 -march=native -flto -fno-plt` typically yields 10-20 %
speedup. On a 141 ns function, that's 14-28 ns of headroom — a
plausible majority of the 48 ns gap.

The remaining 20-30 ns is probably:
- **Code-size / icache**: the L2 mono entry is one 10,388-instruction
  function. Different packet paths hit different ~200-line slices.
  Cold-path icache misses add 10s of ns at full memory latency.
- **Metadata-struct layout**: `xdp2_metadata_all` (~200 B) vs
  rust's `FlowMeta` (likely smaller). One extra cacheline of metadata
  writes ≈ 4-8 ns.
- **Per-node bookkeeping**: `ctrl->var.last_node = parse_node`
  store happens at every node entry; rust's monomorphic dispatch
  doesn't have a parallel.

## What this is NOT

- **Not a codegen issue**: the mono codegen is producing
  reasonable straight-line goto-state code; gcc devirtualises
  what's devirtualisable.
- **Not a metadata-correctness issue**: zero field disagreements
  on 20K packets across 6 shared fields.
- **Not a wrong-tuned-parser issue**: rust does more, gets more,
  faster.

## Recommended next steps (in order of leverage)

### A. Validate H4 empirically (1 commit, ~10 min)

Rebuild C with `-O3 -march=native -flto` and re-measure on hp5.
If `c-xdp2-mono` drops from 141 to ~110-115 ns/pkt, H4 is confirmed
as the dominant factor. If it drops to ~95 ns/pkt, that closes the
entire gap and the investigation ends.

```diff
- XCFLAGS+= -std=gnu11 -g -O2
+ XCFLAGS+= -std=gnu11 -g -O3 -march=native -flto
- CFLAGS+= -std=gnu11 -g -O2
+ CFLAGS+= -std=gnu11 -g -O3 -march=native -flto
```

**Caveat**: kernel flowdis is also compiled with kernel `-O2`
(no LTO, no `-march=native`). Reporting `c-xdp2-mono` with
`-O3 -march=native -flto` against flowdis `-O2` would be ANOTHER
apples-to-oranges — the "best" comparison frame depends on what
you want to communicate:

- **Apples-to-apples vs kernel flowdis**: keep C at `-O2 -g`,
  accept the 50 ns gap as a build-flag tax in the rust comparison.
- **Best-case XDP2 perf**: re-build at `-O3 -march=native -flto`
  to show the codegen's ceiling.
- **Both**: build twice, report both numbers (this is what the
  targets doc's Mode-A/Mode-B sketch hints at).

### B. Code-size / icache investigation (deeper)

The L2 mono entry function is 10,388 asm instructions = ~62 KB
(estimated, 6 B/instr avg). That's much larger than L1i (32 KB
on Zen 1). Cold paths take icache misses on first hit; warm paths
sit in L2.

Possible mitigations:
- Split per-chain entry functions (one per fast-path chain)
- Use `__attribute__((hot))` / `cold` to bias layout
- Add per-chain `inline-always` annotations

This is a larger investigation — probably worth it AFTER
confirming H4 isn't the whole story.

### C. Rust extraction parity (out of scope for the perf question)

Separately: c-xdp2-mono should match rust-mono's metadata field
set (extract eth_src, eth_dst, ip_ttl, tcp_flags) for a fair
parity. That's a R5-class extension to the C metadata extractors,
not a fix to the perf gap.

## TL;DR

The 50 ns gap is *probably* mostly compile-flag asymmetry
(`-O2 -g` vs `release + lto=fat + codegen-units=1 + target-cpu=native`),
not a codegen or correctness issue. Recommend re-building C with
`-O3 -march=native -flto` on hp5 to validate. If it doesn't close
the gap to ≤10 ns, investigate code-size / icache effects.

What the gap is NOT:
- Not indirect-call overhead (gcc devirtualises at `-O2` already)
- Not extraction-work asymmetry (rust does MORE work)
- Not metadata-divergence (parity records match on shared fields)

The R3.4 series is complete; this gap is now in the "build tuning +
maybe code-size" bucket, not in the "more codegen work" bucket.
