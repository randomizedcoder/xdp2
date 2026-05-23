# XDP2 → Linux upstream options

Date: 2026-05-23. Honest assessment of what's shippable to
Linux kernel developers given the current state of the XDP2
work (post-R8 + Option C phase 1+2-a.1+2-a.2).

## What we actually have

**Measured wins (post-R8 final, hp5 canonical)**:

- c-xdp2-mono is **35-42 % faster than `__skb_flow_dissect_err`**
  on flat workloads (4 of 6)
- Ties or beats rust-mono on 4 of 6 workloads
- Walks full inner-5-tuple on VXLAN (kernel flow_dissector
  doesn't)
- Correctness: 32/32 parity-gate, 4914-cell matrix 0/0/0
- 7 fast-path chains cover every workload in our sweep

## What's NOT shippable as-is

- XDP2's output struct is `xdp2_metadata_all` (192 B post-R6),
  not the kernel's `struct flow_keys`. Drop-in replacement
  would need an output adapter or shared-layout work.
- The codegen framework requires libclang + Python templates
  at build time. Out-of-tree tooling unfamiliar to the kernel
  build system.
- The runtime engine assumes XDP2's parse-node graph +
  encap-walking model. The kernel flow_dissector has its own
  state machine.
- Our `c-bpf-xdp2` (BPF backend) has verifier issues
  (REJ-verifier on several pcaps in the matrix) — not
  production-ready as an eBPF flow_dissector replacement.

## Realistic upstream paths, ranked

### 1. Targeted patch to `bpf_flow.c` for PPPoE (small, concrete) — ~1 day

The kernel's in-tree BPF flow_dissector at
`tools/testing/selftests/bpf/progs/bpf_flow.c:147-150`
**rejects PPPoE packets entirely** — we discovered this in the
bpf-pppoe-investigation. Adding `ETH_P_PPP_SES` dispatch +
a PPP sub-program would be a ~50-line patch.

**Lowest controversy, real gap fixed.** But it's a selftest
reference, not production. Useful for credibility-building
with the BPF maintainers.

### 2. LWN-style article / LSF/MM talk (medium, influential) — ~3-5 days

Title direction: "Faster flow dissection via codegen — lessons
from XDP2." Distill:
- The 35-42 % gap and why (R3.3 IR-coverage devirt + R3.4
  fast-paths + gcc full-LTO inlining)
- Why the kernel's flow_dissector can't easily adopt these
  (BPF-translatable constraint, generic across callers,
  no per-callsite specialisation)
- The XDP2 codegen architecture as one possible answer
- Honest tradeoffs (build complexity, out-of-tree tooling,
  multi-CPU portability work)

This **influences direction** without requiring patch
acceptance. Talks at LSF/MM have moved kernel networking
direction before (XDP itself started this way).

### 3. Backport TECHNIQUES to existing `__skb_flow_dissect_err` (medium-large) — ~2-3 weeks

Apply XDP2's R3.4 fast-path pattern to the kernel's C
flow_dissector directly:

- Add a "common-case fast-path" at the entry: detect
  eth+ipv4+tcp at L2 offset, extract 5-tuple, return. ~80 lines.
- Same for VLAN+IPv4+TCP, IPv6+TCP.
- Each is a small patch in a small series. ~5-10 patches total.

Kernel maintainers would likely accept these if benchmarks
show clear wins on representative skbs. We'd need to port our
benchmark to a kernel-module/selftest harness (~1 week effort).

**This is the realistic path to actual in-kernel performance
improvement.** It doesn't require XDP2 upstream; just applies
the techniques.

### 4. Submit XDP2 as out-of-tree, propose as in-tree later (long game) — multi-year

Tom Herbert has been pushing XDP2 (formerly PANDA) for years.
Current state is "out-of-tree experimental." In-tree work
would require:

- Removing libclang / Python build dependencies (rewrite
  codegen in pure C?)
- Stable kernel C API for parse-node declarations
- Integration with `struct flow_keys` for existing callers
- Buy-in from netdev maintainers (Jakub Kicinski, etc.)

Not session-scale or even sprint-scale.

### 5. NOT viable: drop-in replacement of `__skb_flow_dissect_err`

Even with 100 % parity on field-content level, the function
signature, output struct, integration with `skb_get_hash`,
BPF dissector compatibility — all differ. Drop-in replacement
is **not realistic** without substantial wrapper / shim work.

## Recommendation

**Combine paths 1 + 2**:

- **Send the PPPoE patch upstream** (path 1). Self-contained,
  small, real gap. Builds credibility.
- **Write the LWN article** (path 2). Uses our data + analysis.
  Influences direction without requiring code acceptance.

If those land well, **path 3** (port techniques to vanilla
flow_dissector) becomes the natural follow-up.

Path 4 requires Tom + broader community commitment; not
something to drive solo.
