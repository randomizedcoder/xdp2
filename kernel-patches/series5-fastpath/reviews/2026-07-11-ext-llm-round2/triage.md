# Triage: round-2 external-LLM review of series A+B (2026-07-11)

Same model, fresh eyes, over the post-split two-series stack. r3 (combined
deep-dive) exhausted its budget on reasoning with no output; re-split into
per-series deep dives (r3a/r3b, results pending). Every claim verified
against the tree before classification.

## VERIFIED REAL — fixed in this round

R1. STOP-flag attribution error (r2.S3, plus fallout the reviewer did not
    see): STOP_AT_ENCAP is passed by ECMP multipath (route.c), xfrm and
    tc-flower — NOT by RPS/RFS (skb_get_hash passes STOP_AT_FLOW_LABEL).
    Fixed: cover B's "(RPS/RFS, tunnel drivers)" replaced with the real
    caller list + explicit statement that the descent reaches exactly the
    skb_get_hash() family; fib_multipath removed from all three descent
    benefit lists in net.rst (multipath dissects for itself and stops at
    encap — a gate never affects it); cover A's consumer paragraph
    rewritten (ECMP/tc-flower/xfrm never take the fast path; hardware RSS
    doesn't use the kernel dissector).
R2. Stale "only IPv4 outer" exclusion claims in B02/B03 sysctl docs
    (r1.B-S1 + r2.S2, unanimous) — removed.
R3. A02 sysctl doc named "VXLAN inner descent" as part of this series
    (r2.S1, split-stale) — replaced with the actual shape list.
R4. A05 sysctl doc referenced "the v3-namespace series" (r2.S5) — fixed.
R5. RST structure at the descent-section insertions (r2.S6/P1): gre lost
    its "Default: 0", missing blank lines before vxlan_inner/gtpu_inner
    headers — restored.
R6. IPIP/GRE occurrence counters fired before the STOP_BEFORE_ENCAP check
    (r2.P2) — moved below, with a comment.
R7. eligible% is an upper bound (r2.S4) — documented honestly in the A08
    message, the stats-file doc, and the auto-RFC doc ("hysteresis margins
    absorb the overestimate"); plus the standing rationale for
    unconditional counters (they must observe while gates are OFF) baked
    into the A08 message as the answer to the recurring counter-tax
    objection (r1.A-B2, round-1 r1.1).
R8. FOU/GUE gates silently inert without the fou module (r1.B-B1) —
    enabling now fails with -ENODEV when no ops provider is registered
    (corrective disable + summary-key recompute); disabling always allowed.
R9. Cover A now enumerates the seven knobs (r2.P4).

## DEBUNKED (verified against tree)

D1. r1.A-B1 "uninitialized key_control deref" — same as round-1 r2.B2:
    skb_flow_dissector_init() BUG_ONs unless CONTROL+BASIC present;
    key_control is fetched unconditionally at the top of
    __skb_flow_dissect().
D2. r2 blocker B1 "recursion bound three patches late" — round-1 J4:
    deliberate, default-off gates leave no reachable bisect window;
    rationale stands.
D3. A-S5 "STOP_AT_FLOW_LABEL contract needs a comment" — the dispatcher
    comment already says verbatim that the flag is admitted and subsumed.
D4. A-S4 DEBUG_NET_WARN move — the patch-1 message already carries the
    justification the reviewer asked for.
D5. B-S4 fou_release RCU-writer safety — both call sites hold fn->fou_lock
    (verified at net/ipv4/fou_core.c).
D6. A-P1 Assisted-by format (third occurrence), A-P2 tentative definition
    (required for file-scope static), r2.P3 proc_do_static_key on .key
    (kernel/sysctl.c's bpf_stats_enabled uses the identical pattern).
D7. A-S3 static_assert on addrs union offsets — union members share an
    offset by definition; the KUnit memcmp is the real guard.
D8. B-S3 ENC key interaction — skb_flow_dissect_tunnel_info() runs once,
    before the loop; PROTO_AGAIN re-entry cannot re-run it; cover states it.

## JUDGMENT CALLS (standing decisions kept)

J1. Counter tax master-gate (r1.A-B2): keep unconditional — the counters
    exist to observe while gates are off; rationale now in the message.
J2. Seven knobs / master switch (r1.A-S1): the auto RFC is the answer.
J3. flags=0 clobber/restore refactor (r1.A-S2): KUnit equivalence guards
    divergence; defer unless the list asks.
J4. Port-number sysctls for the descents (r1.B-B2): follow-up; net.rst
    already states the hardcoded port and the non-standard-port gap.
J5. GTP macros to net/gtp.h, __always_inline (B-P1/P2): keep as-is.
