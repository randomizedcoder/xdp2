# series5-fastpath — status

## SEND-READY (2026-07-15) — rebased onto net-next v7.2-rc2 (f6f3b36c15ed)

All three series rebased from the old b73bc9ca base onto current net-next
v7.2-rc2 (range-diff: every commit '=' unchanged; clean apply, upstream
touched none of our files). Patch files regenerated with the correct
base-commit. KUnit re-run on the rebased tree: A 55 / B 63 / RFC 56.
net-next confirmed OPEN. This session's polish: humanized covers, two
external-LLM review rounds + fixes, tentative-definition cleanup (single
__read_mostly def), fou hook comment terse, iphdr comment reworded,
/proc/net/flow_dissector_stats example added to the counters patch,
BPF static-key refcount verified on hp5+hp2 (perf-results/
2026-07-14-bpf-refcount-verify/), full 3-ISA + mlx5 hardware matrix
(perf-results/2026-07-12-series5-hw-matrix/, 12/12).

Remaining before the real send: final Cc list (get_maintainer + Tom
Herbert + Willem de Bruijn), rehearsal send to the runpod test address,
then send fastpath first; fill its lore link into the descent + RFC
covers (SERIES-A-LORE-LINK) and send those.


## CURRENT STATE (2026-07-11) — code-complete, fully verified, ready to send

Series A of the two-series split (supersedes `../series4-flowdis-fastpath/`;
that dir's STATUS holds the full audit trail through series4-final-v4 and the
external-LLM review in `../series4-flowdis-fastpath/reviews/2026-07-11-ext-llm/`
whose triage drove this restructure).

**[PATCH net-next v1 00/11]** "opt-in byte-identical fast paths for common
shapes" — net-next branch `series5-a` (base b73bc9ca3686). Pure transparent
optimisation: BPF-lookup static key, 6 shape patches, counters, recursion
bound, KUnit (53 tests, shapes only), docs. No behaviour change anywhere.

Split rationale (external review r1): patches that change behaviour
(UDP-tunnel descents) are a separate policy discussion → `../series5-descent/`
(6 patches, applies on top, prerequisite-patch-ids in its cover).

**Changes vs series4-final-v4** (all from the triaged external review):
- dead TCP/UDP guard removal folded into the IPIP patch (was a drive-by in
  the old VXLAN patch; killed the dead-code window)
- KUnit accessors moved from the old VXLAN patch into the KUnit patch
- stale "v3-namespace" refs and static_branch_likely-vs-unlikely message
  errors fixed; counter overhead now cited (+0.74%, +0.44 sigma, in noise)
- auto mode documented as separate-RFC-only (was presented as existing)
- cover perf section states the two instruments' 7-uarch sets precisely
  (allshapes has Zen 1, isolated has Haswell; union = 8)
- partial-writes test comment replaced with the structural argument

**Hardware matrix (2026-07-12): PASS on 3 ISAs** — build/boot/dmesg/
engagement (x86 2.66B, ARM 508M, RISC-V 352M fast_hits) + x86 Phase G
same-boot N=3 in the noise floor on BOTH i40e (X710 10G) and mlx5
(CX-4 25G) NICs. perf-results/2026-07-12-series5-hw-matrix/.

**Verification — all green (2026-07-11):**
- KUnit 55/55 at series tip (UML; +gre_ipv6/gre6_ipv6 corpus); per-commit compile ×11
- checkpatch --strict: 0 errors, 0 checks; 3 benign warnings (const-ctl_table
  false positive — register_net_sysctl_sz takes non-const; 2 MAINTAINERS
  new-file notices)
- All hardware results (3 ISAs / 8 uarches, Phase G, 2h soak, BPF precedence)
  carry over: tree content vs series4-final-v4 differs only in the
  dead-guard fold, comments and messages.

**Remaining before send:** same send-day list as series4 STATUS (lore Cc
check, net-next open, optional rebase to tip), then send this series FIRST;
series B second (its cover needs this series' lore link at
SERIES-A-LORE-LINK); auto-RFC rebases onto `series5-a`.
