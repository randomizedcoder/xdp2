# series5-rfc-auto — status

## CURRENT STATE (2026-07-11, post-external-review) — send-ready (after both main series)

External-LLM review (reviews/2026-07-11-ext-llm/, triage.md) + user
decisions applied:
- M1/M2: per-packet division removed (cached fd_auto_thresh, recomputed
  on sysctl writes + per worker run for lazy hotplug tracking);
  preempt_disable around the per-cpu window RMW
- M3: sysctl handlers cancel_work_sync() before touching windowing
  state; false "no extra locking" comment corrected
- M4: READ_ONCE counter reads + dtot clamped to ddiss (torn 32-bit
  reads must not drive a flip)
- M5+pin: fd_auto_managed is a whitelist; NEW net.flow_dissector
  .auto_exclude bitmask (default mpls) pins individual gates while
  auto runs; vlan pin implies qinq unmanaged (coupling honoured)
- M6: flip-rate cap per shape; M7 window/2 doc wording; M8 GRE pbe
  rounding comment
- Cover: sample userspace agent inline + honest framing of open
  question 1 (userspace-can-do-this); Q3 reframed (global by
  construction; CONFIG_ opt-out question); BPF-attach-parks-gates
  interaction documented in cover + net.rst; deferred items
  acknowledged (worker-level KUnit, runtime-tunable pbe table)

Verification: KUnit 54/54; W=1 clean; checkpatch --strict 0/0/0.
Posture per user decision: post the RFC as the vehicle for the policy
question, with the sample agent as the concrete alternative.

## Previous state (pre-external-review)

**[RFC net-next v1 0/1]** adaptive auto-enable — branch `series5-rfc`
(= series5-a + 1). Supersedes `../series4-rfc-auto/` (was based on
series4-final-v3).

**This polish round (pre-external-review):**
- hot-path gate is now a static key (fd_auto_on_key): auto off = one
  not-taken branch, same discipline as the gates themselves (was a
  READ_ONCE load+branch per dissect)
- per-shape policy extracted into pure fd_auto_decide(); dwell now
  saturates instead of wrapping (u8 overflow while rate-capped);
  managed-check ordered before key deref
- NEW KUnit case fd_auto_policy_test (suite 53 -> 54): dwell, both
  margin boundaries, dip reset, deadband, low-break-even clamp,
  saturation
- cherry-pick artifacts from the v3 rebase found and removed (a
  duplicated+mangled comment block missing its */, em-dash churn in
  the stats doc section)
- commit message rewritten (was visibly line-wrap-mangled); smatch
  added to trailer; manual-vs-auto interplay documented in net.rst;
  cover rewritten for the two-series world with explicit open
  questions for the list

**Verification:** KUnit 54/54 at tip; W=1 compile clean; checkpatch
--strict 0/0/0.

**Next:** external-LLM review (payloads staged by the session), triage,
then send AFTER both main series (cover needs SERIES-A-LORE-LINK).
