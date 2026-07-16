# Patch 0001 BPF static-key refcount — hardware verification (2026-07-14)

Patch 0001 (net_namespace.c) gates the netns BPF flow-dissector program
lookup behind a static key (netns_bpf_flow_dissector_enabled), threading
static_branch_inc/dec through the attach / detach / replace / netns-exit
paths. The correctness question: does the refcount stay balanced across
those paths on the real kernel?

## What covers it

- Our KUnit suite: does NOT (never attaches a BPF program).
- Upstream BPF selftests flow_dissector.c + flow_dissector_reattach.c DO
  exercise these paths, but building test_progs on this nix toolchain
  fought three separate issues (libbpf -Werror under gcc-15, fortify vs
  -O0, clang-21 across the whole prog suite) — not worth the yak-shave.
- So: a targeted reproducer (fd_refcount_repro.c, ~150 lines, plain gcc,
  raw bpf() syscall, no libbpf/clang) that hammers exactly the modified
  paths and watches for the detectable failure mode — a static_key
  underflow WARN.

## Reproducer coverage

  [1] 2000x attach -> query==1 -> detach -> query==0   (inc/dec balance)
  [2] 2000x attach pf, attach pf2 (replace), detach     (the
      'attached != NULL -> skip need()' branch stays count-correct)
  [3]  500x fork; child unshare(CLONE_NEWNET); attach; exit WITHOUT
      detach   (the pre_exit prog-path unneed this patch adds — the
      thinnest-covered path; a missing dec here would leak, a double
      dec would WARN)
  final: query==0 in the root netns

## Result: PASS on both machines

| host  | kernel state | uname       | reproducer | new WARN/refcount dmesg lines |
|-------|--------------|-------------|------------|-------------------------------|
| hp5   | series5-rfc  | 7.2.0-rc1   | ALL PASSED | 0                             |
| hp2   | series5-b    | 7.2.0-rc1   | ALL PASSED | 0                             |

(patch 0001 is identical across all series5 states — base commit of
series5-a — so both hosts test the same net_namespace.c change; the two
states just differ in the later fast-path/descent patches.)

## Honest residual

- A pure refcount *leak* (key stuck on after everything detached) is
  output-identical and not directly observable from userspace; neither
  the reproducer nor the upstream functional test can assert it. It is
  benign (forfeits the optimization, no correctness effect).
- The consumer-side guard (static_branch_unlikely in __skb_flow_dissect
  skipping the lookup when off) is the same pattern as the proven
  bpf_sk_lookup_enabled; a query-confirmed fresh attach structurally
  implies need() ran (same function, no skip branch), so the ON
  direction is covered by construction.

Build: gcc -O2 -static -I <net-next>/tools/include/uapi ; run as root.
