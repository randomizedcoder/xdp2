# series5-descent — status

## CURRENT STATE (2026-07-11) — code-complete, fully verified, send after series A

**[PATCH net-next v1 00/6]** "opt-in UDP-tunnel inner-flow descent" —
net-next branch `series5-b` (= series5-a + 6). VXLAN, Geneve, GTP-U,
FOU/GUE descents + descent KUnit + descent docs. Behaviour change when a
gate is enabled (skb->hash reflects the inner flow) → separate series per
the external-review split. Cover carries prerequisite-patch-ids for the 11
fastpath patches; fill SERIES-A-LORE-LINK before sending.

**New in this cut (external review + user decisions):**
- IPv6 underlays: VXLAN/Geneve/GTP-U classifiers now family-agnostic
  (FOU/GUE already were) + KUnit v6-outer equivalence/assert-inner cases
- summary static key flow_dissector_udp_inner_any_key: all-gates-off slow
  path pays ONE not-taken branch, not one per tunnel (sysctl handler
  maintains it; tests keep it in step via fd_descent_gate_set())
- descent equivalence now also runs under STOP_AT_FLOW_LABEL
- FOU/GUE KUnit cases KUNIT_SKIP on -EBUSY (real fou owns the ops);
  fou_core pr_warns if registration fails
- GTP_TPDU reused from net/gtp.h (local duplicate dropped); each tunnel
  header include lands in its own patch

**Verification — all green (2026-07-11):**
- KUnit 63/63 at tip (UML; dual-dissector descent checks, inner-v6-label case, GUE plain-only); config matrix: CONFIG_NET_FOU=n (61/61, UML),
  =m (61/61, x86_64), =y (58 pass + 3 skip "fou module owns the flow
  dissector ops", x86_64) × CONFIG_FLOW_DISSECTOR_KUNIT_TEST
- per-commit compile ×6; checkpatch --strict 0 errors 0 warnings 0 checks
  on all 6 patches
