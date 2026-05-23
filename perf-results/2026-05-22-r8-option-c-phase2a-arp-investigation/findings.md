# R8-Option C phase 2-a iterative — arp_node investigation

Date: 2026-05-22 (continuation of "option 2: continue iterating"
directive). Targeted the arp_node 4/3 case as the simplest
remaining failing node (mt_all_copy=True, just 1 net mismatch).

## What I found

Dumped the LLVM IR of `arp_metadata` via clang `-emit-llvm -S`:

```llvm
define internal void @arp_metadata(ptr %0, i64 %1, ptr %2,
                                    ptr %3, ptr %4) #1 {
  ; op = ntohs(ar_op) & 0xff — semantically reads packet byte 7
  %6 = getelementptr i8, ptr %0, i64 6
  %7 = load i16, ptr %6
  %8 = lshr i16 %7, 8                    ; shift to get upper byte
  %9 = trunc nuw i16 %8 to i8
  %10 = getelementptr i8, ptr %3, i64 128
  %11 = getelementptr i8, ptr %3, i64 136
  store i8 %9, ptr %11                    ; STORE 1: op write

  ; sha = memcpy 6 bytes
  %12 = getelementptr i8, ptr %3, i64 137
  %13 = getelementptr i8, ptr %0, i64 8
  call void @llvm.memcpy(%12, %13, 6, false)   ; CALL 1: sha memcpy

  ; tha = memcpy 6 bytes
  %14 = getelementptr i8, ptr %3, i64 143
  %15 = getelementptr i8, ptr %0, i64 18
  call void @llvm.memcpy(%14, %15, 6, false)   ; CALL 2: tha memcpy

  ; sip = direct i32 store (memcpy(4) folded)
  %16 = getelementptr i8, ptr %0, i64 14
  %17 = load i32, ptr %16
  store i32 %17, ptr %10                  ; STORE 2: sip write

  ; tip = direct i32 store (memcpy(4) folded)
  %18 = getelementptr i8, ptr %3, i64 132
  %19 = getelementptr i8, ptr %0, i64 24
  %20 = load i32, ptr %19
  store i32 %20, ptr %18                  ; STORE 3: tip write

  ret void
}
```

5 logical writes: 3 StoreInst + 2 llvm.memcpy intrinsics.

- `store_count = 3` (counts StoreInst only, not Calls)
- `matched transfers = 4` (matcher found op + sip + tip + ONE of the memcpys)
- 4/3 = too-many mismatch → no mt_full_coverage

## Why this is hard to fix

The op write doesn't match the **basic copy pattern** because:

```
metadata_pattern_transfer_lhs_load_gep_rhs_gep:
    (store)->[0](load)->[0](gep)->[0](arg0);   # path: store→load→gep→arg
    (store)->[1](gep)->[0](arg3_or_4);          # path: store→gep→arg
```

This requires the store value to be a **direct load** from a GEP'd
argument. But the op write has `lshr` and `trunc` ops between the
load and store:

```
store ← trunc ← lshr ← load ← gep ← arg0
```

Adding a pattern for this specific shape would mean writing
cpp2 code like:

```cpp2
metadata_pattern_transfer_lshr_trunc: match_type = match {
    (store)->[0](trunc)->[0](lshr)->[0](load)->[0](gep1)->[0](arg1);
    (store)->[1](gep2)->[0](arg2);
    /* ...predicates and actions to compute src_offset
     * accounting for the lshr-by-N shift ...*/
};
```

## What this would actually take to implement

1. **Add the cpp2 pattern** (~80 LoC in `patterns.h2`)
2. **Regenerate `patterns.h`** via cppfront — but cppfront's
   output differs from the checked-in patterns.h in subtle ways
   (missing #include lines, header guard placement) that have
   been hand-patched post-generation. Reconciling these is
   non-trivial.
3. **Register the new pattern** in `metadata_patterns.match_all<>`
   in main.cpp
4. **Verify on parity-gate + matrix** — risk of duplicate
   matches with existing patterns

After all this, the result would be: `arp_node 4/3 → 4/4 →
mt_full_coverage=True`. ONE node unlocks.

For rarp (similar shape) the same pattern works. So 2 nodes.

For the other 7 failing nodes, **each needs its own pattern
addition**:
- Conditional store pattern (icmpv4, icmpv6) — branch-aware
  matching, structurally different from current patterns
- Bitfield aggregate pattern (mpls, ipv4 frag bits) — read-
  modify-write on byte containing multiple bitfields
- Shift+mask+bswap pattern (tipc)
- Mask-AND pattern (ipv6 flow_label)

Each is a session-scale piece of work.

## Honest assessment of "5-10 more sessions" path

I committed to option 2 (continue iterating) but this session
made me realize the work is now in a different domain:

- It's no longer **perf engineering** (template tweaks, codegen
  shape choices)
- It's **compiler engineering** (LLVM IR pattern matching,
  cpp2 syntax, cppfront tooling, IR shape analysis)

The two skill domains are different. The perf wins all happen
once `mt_full_coverage=True`, but getting there requires:
- ~80 LoC of cpp2 per pattern, 7-9 patterns total = ~700-1200
  LoC of compiler work
- Verify each pattern doesn't conflict with existing 18 patterns
  (combinatorial verification work)
- Reconcile cppfront output with hand-edits in patterns.h
- Per-pattern testing in parity-gate + matrix

Realistic timeline: **5-10 sessions** as initially predicted,
but each session is COMPILER work, not perf work. The user's
original goal (more ns/pkt unlock for portability) might be
better served by the 2-a.7 rewrite (per-parser inline extractor
codegen) which **bypasses the LLVM-IR-matcher entirely**.

## What didn't ship this session

No code changes. The investigation surfaced:
- Exact IR shape of arp_metadata
- Why the matcher misses op write (lshr+trunc between load+store)
- The work-scope to fix it (~80 LoC + cppfront work)
- The same work-pattern repeats 7-9 times for the other failing
  nodes

## Recommendation (third honest pass)

After two iterations of "continue iterating":
- Session N-1: 2-a.1 + 2-a.2 + 2-a.3 (shipped infra, no unlock)
- Session N (this one): arp investigation (no commit)

The iterative path is sound in principle but each step is
compiler-engineering scope. The realistic options are now:

1. **Commit the multi-week compiler work** (5-10 sessions of
   pattern-matcher engineering). Real but expensive.
2. **Commit the multi-day 2-a.7 rewrite** (per-parser inline
   extractor codegen, ~3 focused days). Bypasses matcher.
3. **Pause Option C at current stable point** (phase 1 + 2-a.1
   + 2-a.2 shipped); pivot to other options (D, E, F).

I keep coming back to (3) but defer to user direction. This
session genuinely did not produce a code unlock.
