# Flow-keys-compatible `xdp2_metadata_all_v2` reorder — plan

Branch: `flow-keys-compat-reorder` (forked from
`merge/matrix-physical-testbed` at `e970334`).
PR-create link: `https://github.com/randomizedcoder/xdp2/pull/new/flow-keys-compat-reorder`.

## TL;DR

Reorder XDP2's metadata struct so the first 80 bytes match
the kernel's `struct flow_keys` byte-exact. Then
`(struct flow_keys *)xdp2_meta` is a valid kernel-side cast
with **zero data copy and zero translation function** at
runtime. XDP2 extras (`eth_addrs`, `tcp_options`, `arp`, etc.)
move to the tail at offset 80+, invisible to kernel callers.

- **Cost on hp5 (Zen 1)**: predicted null within ±2 ns
  (R6 layout pattern repeats — store buffer absorbs scatter
  writes)
- **Struct size**: 192 B → ~208 B (+16 B for flow_keys
  alignment)
- **Implementation**: 1 focused session (~5-8 hours, 5 phases)
- **Backward compat**: v1 struct unchanged; v2 opt-in via
  `.use_flow_keys_layout = 1` parser config field
- **Re-test required**: yes — standard R6/R8 protocol below

## Quick-reference re-test protocol

After implementation, verify with the standard gates:

| gate | requirement | wall time |
|---|---|---|
| Parity gate | 32/32 OK | ~3 min |
| Protocol-coverage matrix | 4914 cells, 0 OK!N / 0 REJ-undeclared / 0 REJ-unexpected | ~5 min |
| Mono-perf ceiling | 0 violations on 12 cells | included in sweep |
| hp2-hp5 sweep (6 workloads × 2 hosts) | cells within ±2 ns of baseline (`e970334`) | ~30 min |

**If hp5 moves >3 ns**: investigate per the R6/R8 playbook
(cacheline boundary, hash content change, gcc layout
sensitivity).

**Total verification cycle**: ~40 minutes.

## Branch state (current)

- Parent: `merge/matrix-physical-testbed` @ `e970334` (full
  R3-R8 work + kernel comparison docs + upstream-options
  analysis + flow_keys-vs-xdp2 layout analysis)
- Current: `flow-keys-compat-reorder` @ `3e38ce1` (this
  planning doc only; no code change yet)
- Pushed: yes, tracking `origin/flow-keys-compat-reorder`

## Goal

Reorder `struct xdp2_metadata_all` so its first 80 bytes are
byte-exact compatible with the Linux kernel's
`struct flow_keys`. After the reorder, a
`(struct flow_keys *)xdp2_meta` cast gives kernel callers a
fully usable `flow_keys` without any data copy or translation.

XDP2's extra fields (`eth_addrs`, `l2_off`, `l3_off`,
`tcp_options`, `arp`, `gre`, `gre_pptp`, `mpls`) move to the
tail (bytes 80+) where they're invisible to kernel callers
but available to XDP2 consumers that want them.

Background analysis: `docs/flow-keys-vs-xdp2-metadata.md`
(committed on the parent branch).

## Will this impact performance?

**Yes — performance must be re-tested.** Any change to the
metadata struct layout potentially affects:

1. **Cacheline distribution of writes** — where each per-node
   metadata write lands in the struct's cachelines
2. **Total struct size** — current 192 B → proposed ~208 B
3. **Hash-region content** — the hashed bytes change with
   the new layout (since field offsets change)
4. **gcc's codegen** — store-buffer scheduling depends on
   write addresses

### What we expect on hp5 (Zen 1)

Based on R6 findings:
- Zen 1 store buffer absorbs scatter writes — layout shape
  is mostly invisible to ns/pkt at this microarchitecture
- The 16-byte struct growth (192→208 B) keeps the struct
  in 4 cachelines — no new cacheline boundary crossed for
  the common-write set
- Hash compute time scales with `XDP2_HASH_LENGTH` (now
  bounded by `addrs` end via R6's macro fix) — the hashed
  byte range is the same (~80 bytes)

**Predicted Zen 1 delta: null within ±2 ns** (the R6 / R7-B3
pattern repeats).

### What we expect on smaller cores (no testbed yet)

Per the user's portability concern:
- In-order ARM (Cortex-A53), embedded RISC-V, older Intel:
  smaller store buffers → scatter writes more visible.
- The flow_keys layout puts the HASH REGION at offsets 8-80
  (contiguous), good for cache locality.
- The XDP2-extra tail (eth_addrs, tcp_options, etc.) is only
  written on packets that need those fields — for the common
  TCP/IPv4 5-tuple case, no writes hit the tail.

**Predicted small-CPU effect: marginal improvement or null.**
Worth testing when we get a smaller testbed.

### Re-test requirements

The standard R6 / R8 verification protocol:

1. **Parity gate**: 32 pcaps, all-fields comparison vs other parsers.
   Any field-content disagreement = blocker.
2. **Protocol-coverage matrix**: 4914 cells × 13 parsers,
   pairwise field comparison. Must stay 0 OK!N / 0 REJ-undeclared
   / 0 REJ-unexpected.
3. **Mono-perf ceiling**: c-xdp2-mono ≤ c-xdp2-usp × 1.10
   across all 12 cells.
4. **Full hp2-hp5 sweep**: 6 workloads × 2 hosts, full
   iteration count. Compare cell-by-cell with the
   pre-reorder baseline (`e970334`).

If hp5 cells move within ±2 ns: ship the reorder.
If any cell moves >3 ns: investigate (could be cacheline
boundary issue, hash content change, gcc layout pick).

### Cost of re-testing

~30 minutes for the full hp2/hp5 sweep + 5 minutes for matrix.
Standard cycle we've used throughout R5/R6/R7/R8.

## Plan

### Phase 1: design + struct definition

1. Read kernel `include/net/flow_dissector.h` for current
   layout (already done — captured in
   `docs/flow-keys-vs-xdp2-metadata.md`)
2. Design `xdp2_metadata_all_v2` with the flow_keys-prefix
   layout
3. Decide on flag-bit mapping:
   - `is_fragment` bitfield → `FLOW_DIS_IS_FRAGMENT` bit in
     `control.flags`
   - `first_frag` bitfield → `FLOW_DIS_FIRST_FRAG` bit
   - `vlan_count` bitfield → derivable from vlan/cvlan slot
     usage, no flag bit needed
4. Decide on VLAN layout:
   - Kernel: separate `vlan` (outer) + `cvlan` (inner) slots
   - XDP2: array `vlan[2]`
   - Choose: drop the array, use `vlan` + `cvlan` matching
     kernel layout exactly

### Phase 2: code change

1. Add `xdp2_metadata_all_v2` struct definition in
   `parser_metadata.h` (additive — keep v1 for backward compat)
2. Update XDP2_METADATA_TEMP_* macros to write to the v2
   layout (these are field-name based, so reorder is
   automatic if the field NAMES stay the same)
3. Update parsers that opt into v2 to set
   `.frame_size = sizeof(struct xdp2_metadata_all_v2)`
4. Update flow-dissector parser specifically to use v2

### Phase 3: verify

1. Build + parity-gate (single-host)
2. Full protocol-coverage matrix (378 protocols × 13 parsers)
3. hp2-hp5 sweep (6 workloads, full iter)
4. Compare hp5 cells to baseline; expect ±2 ns within noise

### Phase 4: kernel-call demonstration

1. Write a small C program that:
   - Allocates an `xdp2_metadata_all_v2`
   - Invokes XDP2 mono parser on a sample packet
   - Casts the result to `struct flow_keys *`
   - Calls kernel-style consumers (e.g.
     `__flow_hash_consistentify`)
2. Verify the cast yields valid `flow_keys` data

### Phase 5: writeup

`perf-results/<date>-flow-keys-compat-reorder/` with:
- `comparison.md` — pre/post perf table
- `sweep.md` — full hp2/hp5 numbers
- `mono-perf.md` — ceiling gate
- `cast-demo.md` — kernel-style consumer demonstration

## Risk areas

| risk | likelihood | mitigation |
|---|---|---|
| Hash output changes (kernel callers may compare hashes) | high | The hash region IS the flow_keys hash region after this change; output should match what kernel flow_dissector would produce |
| Field-write count changes (codegen emit count) | low | R5.C IR pipeline handles offset changes; field NAMES don't change |
| Parity-gate failures from new field offsets | low | Matrix gate caught all previous reorder issues; same protection applies |
| Perf regression on hp5 from new layout | medium | R6 was null; expect same. Re-test definitively |
| Perf regression on smaller CPUs | unknown | No testbed today; document expectation, ship code, await testbed |
| ABI break for existing XDP2 users | medium | Keep v1 as legacy; new code uses v2 |

## What's NOT in this branch

- Removing libclang/Python build dependencies (Path 3 work)
- Fixing BPF backend verifier issues
- Backporting techniques to vanilla `__skb_flow_dissect_err`
- The PPPoE BPF patch (separate branch / submission)

These are deferred. This branch's scope is ONLY the
output-struct compatibility work.

## Backward-compatibility strategy

`struct xdp2_metadata_all` (v1) stays as-is for backward
compatibility with existing XDP2 users. New
`xdp2_metadata_all_v2` opts-in via per-parser config
(similar to `enable_fast_paths` and `used_field_mask`).

```c
struct xdp2_parser_config {
    ...
    __u8 enable_fast_paths;
    __u64 used_field_mask;
    __u8 use_flow_keys_layout;  /* NEW — set 1 for v2 layout */
};
```

Codegen reads `use_flow_keys_layout` and emits writes to the
v2-layout offsets for parsers that opt in. v1-using parsers
keep current behavior.

## Success criteria

- [ ] `xdp2_metadata_all_v2` defined; first 80 bytes match
  `struct flow_keys` byte-exact
- [ ] Parity gate green on flow-dissector with v2
- [ ] Protocol-coverage matrix green (4914/4914)
- [ ] Mono-perf ceiling 0 violations
- [ ] hp5 ns/pkt within ±2 ns of pre-reorder baseline
- [ ] Demo: `(struct flow_keys *)xdp2_meta` cast yields valid
  hash via kernel-style consumer

## What this enables for upstream

Once shipped:

- **Path 5 becomes feasible**: drop-in replacement for specific
  `__skb_flow_dissect_err` use-sites (those that don't care
  about the BPF dissector ABI or tunnel-flag granularity)
- **Path 2 article gains a concrete demo**: "Here's an
  XDP2-generated parser whose output is flow_keys — call it
  from your kernel code"
- **Path 3 (technique backports) becomes optional**: if the
  drop-in works, the techniques themselves are less urgent to
  port

## Timeline estimate

- Phase 1 (design): 1-2 hours
- Phase 2 (code): 2-4 hours
- Phase 3 (verify): 30 minutes wall + 30 min review
- Phase 4 (cast demo): 1-2 hours
- Phase 5 (writeup): 30 minutes

**Total: 1 focused session** (~5-8 hours).
