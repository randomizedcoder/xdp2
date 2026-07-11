# series5-rfc-auto — status

## CURRENT STATE (2026-07-11) — polished, self-reviewed, pending external-LLM review

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
