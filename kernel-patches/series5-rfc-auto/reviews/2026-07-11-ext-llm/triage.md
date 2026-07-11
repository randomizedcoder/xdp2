# Triage: external-LLM review of the auto RFC (2026-07-11)

Two personas over the RFC (with the 11-patch fastpath series as context).
Every mechanical claim verified against series5-rfc code before acceptance.

## VERIFIED REAL — mechanical, fix before posting

M1. Per-packet division + num_online_cpus() in flow_dissector_auto_account()
    (r4.2a, r5.1 — both called it a blocker). flow_dissector.c:110. Fix:
    precompute fd_auto_thresh on auto_window_packets writes + CPU hotplug
    callback; hot path reads one variable.
M2. this_cpu_inc_return / this_cpu_write sequence is not migration-safe
    (r5.2). Each op is preemption-safe; the pair isn't — a migration between
    them zeroes the wrong CPU's counter. Benign corruption (window jitter),
    but a reviewer magnet. Fix: get_cpu/put_cpu around the pair (or
    this_cpu_sub of the threshold).
M3. "no extra locking" comment is false (r4.2b, r5.3 — both). proc_set_auto
    resets snapshot state concurrently with a running worker. Fix:
    cancel_work_sync() in proc_set_auto before touching state (also on the
    on->off edge), and fix the comment.
M4. Torn/unclamped counter deltas can drive spurious flips (r4.2c, r5.4).
    u64 per-cpu reads can tear on 32-bit; dtot underflow -> huge frac ->
    text_poke. Fix: READ_ONCE in totals; clamp dtot to [0, ddiss].
M5. fd_auto_managed() is a blacklist (r5.5): if descent shapes ever join the
    enum they'd be auto-managed silently — violating the series' own
    contract. Fix: whitelist with default false.
M6. Global flip-rate cap serializes unrelated shapes (r4.2d): multi-shape
    traffic shift takes up to 6s to adapt. Fix: per-shape last-flip
    timestamps (worst case still bounded: 6 flips/s).
M7. Docs say "after roughly this many dissects", code decides at window/2
    (r5.6). Fix: doc wording ("at least half a window of fresh packets").
M8. GRE pbe 1000 vs IPIP 800 while treated as the same class (r5.8). Fix:
    unify at 1000 for both with a "conservative: rounded up" comment (keeps
    the conservative posture rather than lowering GRE to 800).

## VERIFIED REAL — scope decisions (user)

S1. Per-gate pin so manual writes survive auto (r4.2e/2f: operator writes
    eth_ip=0 to debug, worker flips it back; vlan/qinq coupling makes the
    drift non-obvious).
S2. Break-even table runtime-tunable per shape + derivation in-tree
    (r4.2g, RFC open question 2 answered by both reviewers: "runtime-tunable
    is the minimum").
S3. mpls exclusion configurable rather than hard-coded (r4.2h) — folds into
    S1/S2 naturally (a pinned gate is an unmanaged gate).
S4. Worker-level KUnit tests (r4.3, r5.7): drive the worker with synthetic
    counters; assert flip-rate cap delays and dwell preservation; pinned
    gates untouched.
S5. Document the BPF-attach interaction (r4.4): an attached netns BPF
    dissector zeroes the controller's input (dissects deliberately not
    counted) -> auto sees 0% eligible -> disables all gates. Correct but
    surprising; must be documented either way.
S6. Open question 3 reframed (r4.4): the gates are global static keys, so
    per-netns auto is impossible without redesigning the gating; ask about
    a CONFIG_ knob and hotplug instead.

## STRATEGIC — the make-or-break (user decision)

P1. r4's core position: in-kernel text_poke-driven auto-tuning fails the
    "userspace cannot do it" bar; everything the controller reads and
    writes is already exposed. Recommends a userspace agent (tools/ or
    Documentation sample) or a patchless policy mail asking open question 1
    first; would NAK a v2 kworker without a stronger capability argument.
    Options: (a) post the RFC (mechanically fixed) as the vehicle for that
    question — it is labeled RFC, defaults off, and explicitly offers to
    withdraw to userspace; (b) hold the patch, send the policy question
    with a sample userspace agent; (c) both: RFC + sample agent script in
    the cover.

## DEBUNKED / SOFTENED

D1. r5's verdict "not ready to post as an RFC" rests on M1/M2 being
    blockers — real, but both are small mechanical fixes, not design flaws.
D2. r5.2's framing ("corrupting the window accounting") overstates impact:
    worst case is jittered work scheduling, not unsafety. Still worth
    fixing (M2).
