# Round-2 external LLM review: r2-firstread (series A+B post-split)

finish: stop | usage: {"prompt_tokens":77459,"total_tokens":119224,"completion_tokens":41765,"prompt_tokens_details":null,"reasoning_tokens":38849}

## Review

# Review: Series A (byte-identical fast paths) and Series B (UDP-tunnel descents)

## BLOCKERS

### B1. Series A, patches 06/07 vs 09 — unbounded recursion window across three patches

Patches A06 and A07 introduce recursive tunnel descents (`flow_dissect_fast_ipip_inner`, `flow_dissect_fast_gre_inner`) with no depth bound. Patch A09 is what adds the `num_hdrs` counter and the `MAX_FLOW_DISSECT_HDRS` check. The A09 commit message itself states the problem:

> "A crafted frame with a deeply nested tunnel chain (IP-in-IP-in-IP-in-..., or GRE) therefore drives one C stack frame per ~20 bytes of linear header."

and:

> "It is additionally an output divergence: past 15 headers the slow path stops and reports the 15th-level keys, while the fast path would recurse to the innermost, breaking the byte-identical contract."

A bisect landing on A06, A07, or A08 exposes both the stack-exhaustion and the byte-identity violation. The bound should be in A06 (the patch that introduces recursion), not three patches later.

**Fix:** Fold A09's `num_hdrs` threading and `MAX_FLOW_DISSECT_HDRS` check into A06, and add the corresponding check to A07 when GRE recursion is introduced. A09 can then be dropped or repurposed.

---

## SUBSTANTIVE

### S1. Series A, patch 02 — sysctl doc claims VXLAN descent is in this series

`Documentation/admin-guide/sysctl/net.rst`, added by A02:

> "For common shapes (Eth+IPv4/IPv6+TCP/UDP, plus extensions for VLAN, QinQ and **VXLAN inner descent** added by follow-up patches in this series)"

VXLAN inner descent is in series B, not series A. No patch in series A touches VXLAN. A reader of the sysctl doc in a tree with only series A applied would look for a VXLAN knob that does not exist.

**Fix:** Replace "VLAN, QinQ and VXLAN inner descent" with "VLAN, QinQ, PPPoE, MPLS, IP-in-IP and GRE" to match what the series actually adds.

### S2. Series B, patches 01/02/03 — sysctl docs falsely claim IPv6-outer is excluded for Geneve and GTP-U

Patch B02, `Documentation/admin-guide/sysctl/net.rst`:

> "Kept out of the descended set (both paths keep the outer keys): Geneve with options (opt_len > 0), proto_type other than ETH_P_TEB (rare L3-Geneve variants), and **Geneve-over-IPv6 outer (only IPv4 outer is handled)**."

Patch B03, same file:

> "Kept out of the descended set on both paths (outer keys retained): GTPv0 (legacy), GTP' (charging, PT=0), G-PDU type other than 0xFF, GTP-U with extension headers / N-PDU / sequence flags set, and **GTP-U over IPv6 outer**."

Neither `flow_dissect_geneve_inner_ok()` nor `flow_dissect_gtpu_inner_ok()` checks the outer family — both classifiers validate only the tunnel header and inner protocol. The B05 test file confirms this: `build_geneve(buf, true, false, IPPROTO_TCP, 0)` builds an IPv6-outer Geneve packet and `fd_descent_assert_inner(test, buf, len, htons(ETH_P_IPV6), g, false)` asserts the descent happened. Same for GTP-U: `build_gtpu(buf, true, false, IPPROTO_TCP, 0xff)` with an IPv6 outer, asserted to descend.

The B cover letter itself says "for IPv4 and IPv6 underlays alike," contradicting the per-patch docs.

**Fix:** Remove the "Geneve-over-IPv6 outer" and "GTP-U over IPv6 outer" lines from the B02 and B03 sysctl docs.

### S3. Series B, patch 01 and cover letter — RPS/RFS wrongly attributed to STOP_AT_ENCAP callers

B01 commit message:

> "Callers passing FLOW_DISSECTOR_F_STOP_{AT,BEFORE}_ENCAP (RPS/RFS, tunnel drivers) keep the outer tuple even with a gate on."

B cover letter, same sentence.

`skb_get_hash()` (the path RPS/RFS/fq/cake use) passes `FLOW_DISSECTOR_F_STOP_AT_FLOW_LABEL`, not `STOP_AT_ENCAP` or `STOP_BEFORE_ENCAP`. The slow-path descent guard in B01 explicitly checks:

```c
!(flags & (FLOW_DISSECTOR_F_STOP_BEFORE_ENCAP |
           FLOW_DISSECTOR_F_STOP_AT_ENCAP))
```

`STOP_AT_FLOW_LABEL` is not in that mask, so RPS/RFS *does* get the inner flow when a descent gate is on — which is the whole point. The claim that RPS/RFS "keeps the outer tuple even with a gate on" is wrong.

**Fix:** Remove "RPS/RFS" from the parenthetical. Say something like: "Callers passing FLOW_DISSECTOR_F_STOP_{AT,BEFORE}_ENCAP (tunnel drivers) keep the outer tuple even with a gate on. RPS/RFS (skb_get_hash, which passes STOP_AT_FLOW_LABEL) does get the inner flow."

### S4. Series A, patch 08 — "eligible%" overestimates what the fast body would handle

The A08 commit message says:

> "occurrences[]  a shape handled by the SLOW path. Measured while its gate is off, this is the eligible-fraction signal: how much traffic that shape's fast body *would* have handled."

But the slow-path occurrence counters are placed at protocol-recognition points, not at fast-path-eligibility points. Examples:

- **VLAN**: `flow_dissector_count_slow(FLOW_DISSECTOR_SHAPE_VLAN)` fires for *any* 802.1Q-tagged packet, including VLAN+ARP, VLAN+ICMP, VLAN+MPLS. The fast body handles only VLAN+IP+TCP/UDP.
- **PPPoE**: counts all `ETH_P_PPP_SES` frames, including LCP/IPCP control frames. The fast body handles only PPPoE+IP/IPv6+TCP/UDP.
- **MPLS**: counts all MPLS packets, including multi-label stacks. The fast body handles only single-label BoS.
- **eth_ip**: counts any top-level eth+IP+TCP/UDP at the `out:` label, including packets with IP options or fragments, which the fast body rejects.
- **IPIP/GRE**: counts at the `IPPROTO_IPIP`/`IPPROTO_GRE` case, before the `STOP_BEFORE_ENCAP` check, so packets that the fast path would never see (because the dispatcher rejects that flag) are counted as occurrences.

The `/proc/net/flow_dissector_stats` `eligible%` column thus reports an upper bound, not the actual fast-pathable fraction. An operator (or the proposed auto-controller) thresholds against an inflated number.

**Fix:** Either narrow the slow-path counting to match the fast-path eligibility conditions (e.g., for VLAN, count only when the inner ethertype is IP and the IP is IHL=5 non-fragmented TCP/UDP), or change the commit message and docs to say "eligible% is an upper bound — the actual fast-path hit rate is `fast_hits / (occurrences + fast_hits)` after enabling the gate."

### S5. Series A, patch 05 — undefined reference to "v3-namespace series"

A05 commit message:

> "A depth-2+ variant can land later, mirroring the vlan -> qinq staging used for the VLAN gates."

A05 sysctl doc, `Documentation/admin-guide/sysctl/net.rst`:

> "extending to depth-2 or more is a follow-up, mirroring the vlan -> qinq staging **the v3-namespace series** used."

"v3-namespace series" is undefined. A fresh reader has no way to resolve this reference. It appears to be a stale reference to an earlier internal version of the work.

**Fix:** Delete "the v3-namespace series used" and replace with something self-contained, e.g., "mirroring the vlan → qinq staging used earlier in this series."

### S6. Series B, patch 01 — `gre` sysctl section loses its `Default: 0`

B01 inserts the `vxlan_inner` section directly after the `gre` section's last text line (`FLOW_DISSECTOR_KEY_GRE_KEYID``.`) with no blank line, and before the `gre` section's `Default: 0`:

```rst
 ``FLOW_DISSECTOR_KEY_GRE_KEYID``.
+vxlan_inner
+~~~~~~~~~~~
```

The `Default: 0` that follows now reads as belonging to `vxlan_inner`, not `gre`. The `gre` section is left without a `Default: 0` line.

**Fix:** Add a blank line and `Default: 0` for `gre` before the `vxlan_inner` section header.

---

## POLISH

### P1. Series B, patches 01 and 03 — missing blank lines before RST section headers

B01: no blank line between `FLOW_DISSECTOR_KEY_GRE_KEYID``.` and `vxlan_inner`. RST section headers require a preceding blank line; without it, Sphinx may not recognise the header and will merge the text.

B03: no blank line between `Default: 0` (end of `geneve_inner` section) and `gtpu_inner`:

```rst
 Default: 0
+gtpu_inner
+~~~~~~~~~~
```

**Fix:** Add a blank line before each section header.

### P2. Series A, patch 08 — IPIP/GRE occurrence counters fire before the STOP_BEFORE_ENCAP check

```c
case IPPROTO_IPIP:
    flow_dissector_count_slow(FLOW_DISSECTOR_SHAPE_IPIP);
    if (flags & FLOW_DISSECTOR_F_STOP_BEFORE_ENCAP) {
        fdret = FLOW_DISSECT_RET_OUT_GOOD;
        break;
    }
```

Packets with `STOP_BEFORE_ENCAP` are counted as IPIP occurrences even though the fast path would never handle them (the dispatcher rejects that flag). Same for GRE. This inflates those shapes' `eligible%`. Minor, but inconsistent with the stated semantics.

**Fix:** Move the `flow_dissector_count_slow()` call below the `STOP_BEFORE_ENCAP` check.

### P3. Series A, patch 02 — `proc_do_static_key` on `static_key_false.key` works but is fragile

A02's sysctl table entry:

```c
{
    .procname = "eth_ip",
    .data     = &flow_dissector_eth_ip_key.key,
    .maxlen   = sizeof(flow_dissector_eth_ip_key),
    ...
    .proc_handler = proc_do_static_key,
},
```

`proc_do_static_key` expects a `static_key` (the inner `.key` member). This works but bypasses the `static_branch_enable/disable` API, which on some architectures does additional bookkeeping. The coupled vlan/qinq handlers in A03 already wrap `proc_do_static_key` in a custom handler. Consider using `static_branch_enable/disable` consistently, or add a comment explaining why direct `.key` access is safe here.

### P4. Series A, cover letter — "seven knobs" is correct but could enumerate them

The cover letter says "nobody has to hand-tune seven knobs" without listing them. A fresh reader has to scan the patch list to identify all seven. A one-line parenthetical "(eth_ip, vlan, qinq, pppoe, mpls, ipip, gre)" would help.

### P5. Series B, patch 04 — `pr_warn` on ops registration collision may surprise

```c
if (flow_dissector_fou_ops_register(&fou_flow_ops))
    pr_warn("fou: flow dissector ops already registered, fou_inner/gue_inner descent unavailable\n");
```

This `pr_warn` fires on every `fou_init()` if another owner holds the hook. If `fou` is a module that's loaded/unloaded repeatedly, this could spam logs. Consider `pr_warn_once` or rate-limiting.

---

## Overall verdict

**Series A:** The design is sound: a per-shape static-branch-gated fast path with an in-tree KUnit equivalence suite is a credible approach to the cost of the generic graph walk. The byte-identical contract is well-motivated and the test coverage is thorough. The blocker (S1: recursion bound separated from recursion introduction by three patches) must be fixed before merge. The sysctl doc error (S1) and the counter semantics issue (S4) should also be addressed. With those fixes, this is a solid, reviewable series.

**Series B:** The shared-classifier approach (one `*_inner_ok()` per tunnel, called by both paths) is the right design — it makes fast==slow structural rather than maintained by hand. The FOU/GUE ops hook is clean. The substantive issues are all in documentation, not code: the IPv6-outer exclusion claims (S2) and the RPS/RFS misattribution (S3) are wrong and must be fixed. The RST formatting (S6, P1) will cause broken rendered docs. With those fixes, this is a well-structured companion to series A.

## Reasoning trace

Let me carefully review both series systematically. I'll go through each question:
1. Do cover letters introduce the work sensibly and completely?
2. Does each series build up logically patch by patch, and would each bisect cleanly?
3. Do words align with diffs - any wrong/stale/unsupported claims?
4. Anything confusing, undefined, or out of order for a fresh reader, including cross-references?

Let me work through the patches in order.

**Series A (11 patches): byte-identical fast paths**

Cover letter:
- Introduces the work well. Mentions: opt-in static-branch-gated fast paths, common shapes, per-shape sysctls under /proc/sys/net/flow_dissector/, default off, byte-identical contract, KUnit test in patch 10.
- Patches 2-7 are common shapes (eth+IPv4/IPv6 x TCP/UDP, VLAN/QinQ, PPPoE, single MPLS, IP-in-IP, plain GRE).
- Patch 1: small win for existing path - static key for BPF flow dissector program lookup.
- Patch 8: per-shape counters.
- Patch 9: bound recursion.
- Patch 10: KUnit equivalence suite.
- Patch 11: docs.

Let me check patches one by one.

**Patch A01: gate BPF program lookup behind static key**
- Commit message describes adding static key `netns_bpf_flow_dissector_enabled` to skip the BPF flow dissector program lookup when no program is attached.
- Code: adds DEFINE_STATIC_KEY_FALSE in flow_dissector.c, extern in skbuff.h, modifies net_namespace.c to inc/dec the key in the various attach/detach paths.
- Diff looks reasonable. The key is checked in __skb_flow_dissect before the rcu_read_lock block.
- One concern: `static_branch_unlikely` is used to test the key. The static_branch_unlikely should be the right macro since it's the "disabled" (off) case being unlikely.
- Wait: `DEFINE_STATIC_KEY_FALSE` defines a key that is initially false. To check if it's enabled, you use `static_branch_unlikely(&key)` which returns false when the key is disabled. So when no program is attached, the key is false and the unlikely branch is not taken - correct.
- The DEBUG_NET_WARN_ON_ONCE moves inside the gated block as described.
- Looks consistent with commit message.

**Patch A02: opt-in fast-path for eth + IPv{4,6} + {TCP,UDP}**
- Adds `flow_dissect_fast()` dispatcher and `flow_dissect_fast_ipv4()`/`flow_dissect_fast_ipv6()` helpers.
- Adds sysctl subtree /proc/sys/net/flow_dissector/ with `eth_ip` entry.
- The forward declarations and tentative definition of `flow_keys_dissector_symmetric` look correct.
- The dispatcher check rejects dissectors other than `flow_keys_dissector` and `flow_keys_dissector_symmetric`.
- It allows flags `FLOW_DISSECTOR_F_PARSE_1ST_FRAG` and `FLOW_DISSECTOR_F_STOP_AT_FLOW_LABEL`.
- IPv6 defers on any non-zero flow label.
- IPv4 fast path: checks VIHL byte == 0x45, no fragmentation, TCP/UDP protocol.
- The diff hunk in the sysctl table has `proc_do_static_key` as the handler - looks right.

Wait, the commit message says "When the per-shape sysctl is enabled and a packet matches, the helper fills struct flow_keys byte-identically to the slow path and returns."

But there's a subtle issue I should check - the dispatcher `flow_dissect_fast()` is called from `__skb_flow_dissect()` after the BPF hook. Let me check the placement - yes, after the rcu_read_unlock block, before dissector_uses_key for ETH_ADDRS. Good.

Wait, looking at the cover letter, the patch 1 is described as a separate small win - "today every dissect takes rcu_read_lock() and does two dependent rcu_dereference() loads to look for a netns BPF flow dissector program even when none is attached anywhere". And then patches 2-7 are the fast paths.

**Patch A03: VLAN and QinQ fast path**
- Adds `flow_dissect_fast_vlan()` helper, two new static keys (`flow_dissector_vlan_key`, `flow_dissector_qinq_key`).
- Dispatcher gets cases for ETH_P_8021Q and ETH_P_8021AD.
- proc handlers `proc_set_vlan_key` and `proc_set_qinq_key` that couple the two keys.
- Commit message says "writes FLOW_DISSECTOR_KEY_VLAN (vlan_id / vlan_priority / vlan_tpid / vlan_eth_type); inner tag (depth 1): FLOW_DISSECTOR_KEY_CVLAN". The code does this.
- Commit message says "Bumps FLOW_DISSECTOR_KEY_NUM_OF_VLANS when requested by the dissector." The code increments num_of_vlans - wait, let me check the slow path's behavior. Actually I don't see the slow path's num_of_vlans behavior in the diff but the comment says "mirroring the slow-path's MAX -> VLAN -> CVLAN state machine". That's reasonable.

Hmm, one concern: the commit message says "Both hardware-stripped (TCI in skb metadata, inner ethertype in skb->protocol; only ever the outermost tag) and in-band (4-byte vlan_hdr at data + nhoff) tag forms." The code handles hw-stripped via `skb_vlan_tag_present(skb)` only at depth 0. That matches.

The proc handlers - `proc_set_vlan_key` clears qinq when vlan is turned off, `proc_set_qinq_key` enables vlan when qinq is turned on. Reasonable.

**Patch A04: PPPoE fast path**
- Adds `flow_dissect_fast_pppoe()`, new static key, sysctl entry.
- Uses `is_pppoe_ses_hdr_valid()` which was defined earlier (it's already in the file).
- Handles PPP_IP and PPP_IPV6, defers for everything else.
- Writes FLOW_DISSECTOR_KEY_PPPOE when requested.
- Looks correct.

**Patch A05: single MPLS label**
- Adds `flow_dissect_fast_mpls()`, static key, sysctl entry.
- Reads one MPLS label, checks BoS=1, defers multi-label.
- Writes FLOW_DISSECTOR_KEY_MPLS lse[0] when requested.
- Also mirrors the slow path's out_good terminal writes (thoff, n_proto, ip_proto).
- The commit message says "Skipping those writes is observable in struct flow_keys and would break the byte-identical contract; the in-tree KUnit equivalence test added later in this series catches exactly this." OK.

**Patch A06: IP-in-IP family**
- Adds `flow_dissect_fast_ipip_inner()`, static key, sysctl entry.
- Handles IPPROTO_IPIP and IPPROTO_IPV6 from both IPv4 and IPv6 outer.
- Stamps FLOW_DIS_ENCAPSULATION after inner returns (because inner helpers zero key_control->flags).
- The commit message notes "The IPv6 helper's standalone not-TCP/UDP guard becomes unreachable once the new block handles that case in full, so it is removed here." Looking at the diff, the IPv6 helper's `return false` is replaced with the IPIP descent logic. Yes, that's correct.
- The 4in6 residue handling is described: outer IPv6 addrs written before recursion, inner IPv4 leaves tail bytes. The code does `memcpy(&key_addrs->v6addrs.src, ...)` and `memcpy(&key_addrs->v6addrs.dst, ...)` - the full 16-byte addresses. Inner IPv4 then overwrites only the first 4 bytes (v4addrs is a union). Wait, actually I need to think about this. The `key_addrs` is a union, and v4addrs.src is 4 bytes while v6addrs.src is 16 bytes. So writing v4addrs.src overwrites the first 4 bytes of v6addrs.src, leaving bytes 4-15 as the outer IPv6's. The code reproduces this by writing the full v6 addrs first, then letting the inner IPv4 fast path overwrite only the first 4 bytes. That's the "residue" mentioned. Good.

**Patch A07: plain GRE inner**
- Adds `flow_dissect_fast_gre_inner()`, static key, sysctl entry.
- Handles GRE version 0, no flags, protocol ETH_P_IP or ETH_P_IPV6.
- Stamps ENCAP after inner pass, same pattern as IPIP.
- The commit message says "the slow path already descends through plain GRE unconditionally, so this fast path is byte-identical with today's behaviour — a pure CPU saving."
- The IPv6 outer helper gets the same GRE handling as IPIP - the diff shows `bool gre = static_branch_unlikely(&flow_dissector_gre_key) && iph->nexthdr == IPPROTO_GRE;` and then `if (!ipip && !gre) return false;` followed by the outer-IPv6 writes and the descent.
- Wait, there's a subtle issue here. The IPv6 outer writes happen for both IPIP and GRE descents. But the comment says "The IPv6-outer descent mirrors the slow path's outer writes (v6addrs, addr_type) before recursing into the inner header." That's correct for both.

**Patch A08: per-shape counters**
- Adds per-cpu counters, /proc/net/flow_dissector_stats.
- Adds `enum flow_dissector_shape`, per-cpu `struct flow_dissector_stats`.
- The dissects counter is incremented unconditionally per dissect.
- The occurrences counter is incremented in the slow path at each shape's recognition point.
- The fast_hits counter is incremented in the fast path at each shape's success terminal.
- The commit message says "exactly one of occurrences/fast_hits is incremented per shaped packet depending on gate state, so (occurrences + fast_hits) / dissects is a gate-invariant eligible fraction."

Wait, let me think about this. There's a subtle issue with the eth_ip counter placement. The commit message says "for eth_ip that is the out: exit label, taken only on a top-level, non-encapsulated, TCP/UDP terminal, so a packet counted as VLAN/IPIP/GRE is never also counted as eth_ip."

Looking at the code: `eth_ip_top` is set to true when `nhoff == nhoff_init` at the IPv4/IPv6 dissection point. Then at the `out:` label:
```c
if (ret && eth_ip_top &&
    !(key_control->flags & FLOW_DIS_ENCAPSULATION) &&
    (ip_proto == IPPROTO_TCP || ip_proto == IPPROTO_UDP))
    flow_dissector_count_slow(FLOW_DISSECTOR_SHAPE_ETH_IP);
```

So eth_ip is only counted when it's a top-level IP, not encapsulated, and TCP/UDP. That seems right.

But wait - the `nhoff_init` is set right before `proto_again:`. And `eth_ip_top` is set when `nhoff == nhoff_init` at the IP dissection point. So if we re-enter `proto_again` after a descent, nhoff would be different from nhoff_init, and eth_ip_top wouldn't be set again. That's correct - only the first IP header at the initial nhoff counts as eth_ip_top.

Hmm, but there's a question about VLAN. If the packet is VLAN + IPv4 + TCP, the slow path would: dissect VLAN (count VLAN), then re-enter proto_again with the inner ethertype (IPv4). At that point, nhoff != nhoff_init (it's been advanced past the VLAN tag), so eth_ip_top would NOT be set. Good - VLAN packets are counted as VLAN, not eth_ip.

Wait, but what about a plain eth+IP+TCP packet? The slow path would: enter proto_again with IPv4, nhoff == nhoff_init, so eth_ip_top = true. Then at out:, if it's TCP/UDP and not encap, count eth_ip. Good.

What about a plain eth+IP packet with IP-in-IP? The slow path would: dissect outer IPv4 (nhoff == nhoff_init, eth_ip_top = true), then the IPPROTO_IPIP case sets fdret to PROTO_AGAIN. On re-entry, nhoff != nhoff_init, so eth_ip_top stays as it was. Wait - eth_ip_top is set before `nhoff += iph->ihl * 4`. So when the IPIP case triggers, we re-enter proto_again with the inner IPv4. At that point nhoff != nhoff_init, so eth_ip_top is NOT set to true again. But it was already set to true from the outer pass. So at out:, the check `!(key_control->flags & FLOW_DIS_ENCAPSULATION)` should be false (because ENCAP is set by the IPIP descent), so eth_ip is NOT counted. Good.

But wait, IPIP IS counted as its own shape - `flow_dissector_count_slow(FLOW_DISSECTOR_SHAPE_IPIP)` is called at the IPPROTO_IPIP case. Good.

OK so the counting logic seems sound. Let me check one more thing - the IPIP counting in the slow path. The code:
```c
case IPPROTO_IPIP:
    flow_dissector_count_slow(FLOW_DISSECTOR_SHAPE_IPIP);
    if (flags & FLOW_DISSECTOR_F_STOP_BEFORE_ENCAP) {
        fdret = FLOW_DISSECT_RET_OUT_GOOD;
        break;
    }
```
So IPIP is counted even when STOP_BEFORE_ENCAP is set. That seems odd but maybe intentional - the shape was seen, even if we don't descend. The commit message doesn't explicitly address this. Actually, thinking about it more, the "occurrences" counter is meant to measure "how much traffic that shape's fast body would have handled." If STOP_BEFORE_ENCAP is set, the fast path wouldn't handle it (the dispatcher rejects that flag). So counting it as an occurrence might be slightly misleading - it inflates the "eligible fraction" for IPIP even though those packets wouldn't actually use the fast path. But this is a minor observability issue, not a correctness issue.

Similarly for GRE - `flow_dissector_count_slow(FLOW_DISSECTOR_SHAPE_GRE)` is called at the IPPROTO_GRE case, before the STOP_BEFORE_ENCAP check.

Hmm, actually looking more carefully, the eth_ip counting at the out: label checks `ip_proto == IPPROTO_TCP || ip_proto == IPPROTO_UDP`. But what about IPIP/GRE packets? Those have ip_proto == IPPROTO_IPIP or IPPROTO_GRE, so they won't be counted as eth_ip. Good. But they ARE counted as IPIP/GRE shapes earlier. And what if IPIP's inner is TCP? The inner re-enters proto_again, sets ip_proto to the inner's protocol (TCP), but eth_ip_top is still true from the outer. But `key_control->flags & FLOW_DIS_ENCAPSULATION` would be true, so eth_ip is NOT counted. Good.

Now let me look at the fast path counters. For eth_ip:
```c
if (!flow_dissect_fast_ipv4(...))
    return false;
if (!flow_dissect_fast_is_encap(flow_dissector, target_container))
    flow_dissect_count_fast(FLOW_DISSECTOR_SHAPE_ETH_IP);
return true;
```
So eth_ip is only counted when the fast path succeeds AND the result is not an encapsulation. If it's an IPIP descent, `flow_dissect_fast_ipv4` would have descended into the inner via `flow_dissect_fast_ipip_inner`, which stamps ENCAP. So `flow_dissect_fast_is_encap` returns true, and eth_ip is NOT counted - the IPIP shape is counted instead (in `flow_dissect_fast_ipip_inner`). Good.

Wait, but what about the case where the fast path defers? If `flow_dissect_fast_ipv4` returns false, the dispatcher returns false, and the slow path runs. The slow path would then count the shape. So exactly one of fast_hits/occurrences is counted. Good.

Let me check the VLAN counter more carefully. In `flow_dissect_fast_vlan`:
```c
if (ok)
    flow_dissector_count_fast(vlan_depth == 0 ?
                              FLOW_DISSECTOR_SHAPE_VLAN :
                              FLOW_DISSECTOR_SHAPE_QINQ);
return ok;
```
And the comment says "Depth 0 counts vlan, depth >= 1 qinq; a double-tagged hit counts both, as the slow path does." Wait - does a double-tagged hit count both? Let me trace: for a QinQ packet, `flow_dissect_fast_vlan` is called with vlan_depth=0. It processes the outer tag, then recurses with vlan_depth=1. The recursive call processes the inner tag, then dispatches to ipv4/ipv6. If that succeeds, `ok` is true, and it counts `vlan_depth == 0 ? VLAN : QINQ` = QINQ (since vlan_depth is 1 in the recursive call). Then it returns to the outer call, where `ok` is true, and it counts `vlan_depth == 0 ? VLAN : QINQ` = VLAN (since vlan_depth is 0 in the outer call). So yes, a QinQ hit counts both VLAN and QINQ. The comment says this mirrors the slow path. Let me check the slow path:
```c
if (dissector_vlan == FLOW_DISSECTOR_KEY_MAX) {
    dissector_vlan = FLOW_DISSECTOR_KEY_VLAN;
    flow_dissector_count_slow(FLOW_DISSECTOR_SHAPE_VLAN);
} else if (dissector_vlan == FLOW_DISSECTOR_KEY_VLAN) {
    dissector_vlan = FLOW_DISSECTOR_KEY_CVLAN;
    flow_dissector_count_slow(FLOW_DISSECTOR_SHAPE_QINQ);
}
```
Yes, the slow path counts both too. Good.

**Patch A09: bound fast-path tunnel recursion**
- Adds `num_hdrs` parameter to the tunnel-reachable helpers.
- Each tunnel descent increments num_hdrs and checks against MAX_FLOW_DISSECT_HDRS.
- Initial counts: eth_ip starts at 1, VLAN at vlan_depth+2, PPPoE at 2.
- The commit message says "The initial count at each fast-path entry is set at or above the number of headers the slow path has already consumed (outer VLAN tags, PPPoE, the outer IP), so the fast path never descends past the point the slow path would have capped."

Let me verify: 
- For eth_ip: num_hdrs=1 (just the Ethernet). The slow path would have consumed 1 header (the outer IP) before descending. Wait, actually the slow path's num_hdrs is tracked by `skb_flow_dissect_allowed()` which increments on each header. The outer IP would be 1. Then the IPIP descent would be 2. The bound is MAX_FLOW_DISSECT_HDRS=15. So the fast path starting at 1 and incrementing at each descent matches.

- For VLAN: num_hdrs = vlan_depth + 2. If vlan_depth=0 (single VLAN), that's 2 (Ethernet + VLAN tag). Then the outer IP is 3. Then IPIP descent is 4. Hmm, does the slow path count this way? The slow path counts: Ethernet header doesn't count (it's before the loop), VLAN tag counts as 1, outer IP counts as 2. So after the outer IP, the slow path's num_hdrs is 2. The fast path starts at vlan_depth+2 = 2, then the outer IP is not a descent (it's the main path), then the IPIP descent increments to 3. Wait, I need to think about this more carefully.

Actually, looking at the slow path: `skb_flow_dissect_allowed()` is called at the top of the proto_again loop. Each iteration through the loop that processes a header increments num_hdrs. So:
- First iteration: VLAN tag → num_hdrs becomes 1
- Second iteration: outer IPv4 → num_hdrs becomes 2
- Third iteration (IPIP descent): inner IPv4 → num_hdrs becomes 3
- ... and so on until num_hdrs > MAX_FLOW_DISSECT_HDRS (15)

In the fast path:
- flow_dissect_fast_vlan is called with vlan_depth=0. It processes the VLAN tag, then calls flow_dissect_fast_ipv4 with num_hdrs = vlan_depth + 2 = 2.
- flow_dissect_fast_ipv4 processes the outer IPv4. If it's IPIP, it calls flow_dissect_fast_ipip_inner with num_hdrs = 2.
- flow_dissect_fast_ipip_inner does `++num_hdrs` → 3, checks > 15 (no), then calls flow_dissect_fast_ipv4 with num_hdrs = 3.
- And so on.

In the slow path, after the VLAN tag (num_hdrs=1) and outer IP (num_hdrs=2), the IPIP case re-enters proto_again. skb_flow_dissect_allowed increments to 3. So the counts match: both paths allow the same number of descents.

Actually wait, I need to be more careful. The slow path's `skb_flow_dissect_allowed` is called at the start of each proto_again iteration. So:
- proto_again #1: VLAN → num_hdrs=1
- proto_again #2: outer IPv4 → num_hdrs=2
- proto_again #3 (IPIP): inner IPv4 → num_hdrs=3
- ...
- proto_again #16: → num_hdrs=16 > 15 → stop

In the fast path:
- flow_dissect_fast_vlan(depth=0) → calls ipv4 with num_hdrs=2
- ipv4 calls ipip_inner with num_hdrs=2
- ipip_inner does ++num_hdrs=3, calls ipv4 with num_hdrs=3
- ipv4 calls ipip_inner with num_hdrs=3
- ipip_inner does ++num_hdrs=4, calls ipv4 with num_hdrs=4
- ...
- ipip_inner does ++num_hdrs=16, checks > 15 → return false

So the fast path allows 14 IPIP descents (from num_hdrs=3 to num_hdrs=16), while the slow path allows... let me count. Slow path: proto_again #3 has num_hdrs=3 (first inner), proto_again #16 has num_hdrs=16 (14th inner). So both allow 14 inner descents. 

Actually, I realize I need to check whether the slow path's `skb_flow_dissect_allowed` is called before or after processing the header. Looking at the code (not shown in the diff, but referenced): `skb_flow_dissect_allowed()` increments num_hdrs and checks if it exceeds MAX_FLOW_DISSECT_HDRS. If it does, the dissect stops. So the check happens at the top of each iteration, before the header is processed.

Hmm, but I don't have the full slow-path code to verify this precisely. The commit message says "The initial count at each fast-path entry is set at or above the number of headers the slow path has already consumed," which suggests the author has verified this. The KUnit test's deep-nest case exercises this boundary. I'll take the commit message at face value but note that the exact boundary semantics should be verified by the test.

**Patch A10: KUnit tests**
- 1033-line test file with corpus packets, truncation sweep, skb-mode tests, deep-nest test, non-linear skb test, ineligible dissector test, fuzzer, gates-off test.
- The test runs each case with gates off and gates on, comparing flow_keys and flow_hash_from_keys().
- Tests both eligible dissectors (flow_keys_dissector and flow_keys_dissector_symmetric via kunit accessor).
- Tests with and without FLOW_DISSECTOR_F_STOP_AT_FLOW_LABEL.
- The gates-off test checks that fast_hits counter doesn't change when gates are off, and that it does change when gates are on.
- The fuzzer uses a fixed seed (0x1a2b3c4d5e6f7788ULL) for reproducibility.

This looks comprehensive. One thing I notice: the test uses `fd_fast_gates_set(true/false)` which enables/disables ALL fast gates at once. This is fine for testing equivalence but means the test doesn't verify that individual gates work independently. However, the gates-off test does check the counter, and the equivalence test would catch any cross-gate interference.

**Patch A11: Documentation**
- Adds Documentation/networking/flow_dissector.rst with overview, struct flow_keys, dissection path, BPF flow dissector, opt-in fast paths, when to enable, references.
- Indexes the previously orphaned Documentation/bpf/prog_flow_dissector.rst.
- Cross-links the two docs.
- Looks good.

Now let me look at **Series B (6 patches): UDP-tunnel descents**

**Cover letter:**
- Explains the problem: UDP tunnels stop at outer UDP, collapsing inner flows.
- Introduces opt-in descents for VXLAN, Geneve, GTP-U, FOU/GUE.
- Each behind its own gate, default off.
- Enabling changes skb->hash - deliberate operator choice.
- Byte-identical between fast and slow paths (both grow the same descent).
- Summary key `flow_dissector_udp_inner_any_key` for the slow path.
- FOU/GUE need the fou module's port lookup via registered ops.
- KUnit tests in patch 5.
- Config matrix for CONFIG_NET_FOU.
- Links to series A.

The cover letter says the prerequisite patch IDs match series A. Good.

**Patch B01: VXLAN inner descent**
- Introduces shared machinery: `flow_dissect_*_inner_ok()` classifiers, `flow_dissect_fast_udp_tunnels()` dispatcher, `__skb_flow_dissect_udp_encap()` slow-path counterpart.
- `flow_dissect_fast_udp_inner()` shared tail with MAX_FLOW_DISSECT_HDRS bound.
- `MAX_FLOW_DISSECT_HDRS` moved above the fast-path helpers.
- `inner_eth_proto` renamed to `inner_proto` (for GTP-U's bare IP protocol).
- VXLAN validation: I flag set, all other flags zero, dst port 4789.
- The slow path grows matching descent in `__skb_flow_dissect_udp_encap()`, called after the outer UDP ports, rewrites proto/nhoff and re-enters the loop.
- Summary key `flow_dissector_udp_inner_any_key` gates the slow path.
- `proc_set_udp_inner_key` handler maintains the summary key.

Let me check the slow-path integration:
```c
if (ip_proto == IPPROTO_UDP &&
    fdret == FLOW_DISSECT_RET_CONTINUE &&
    !(key_control->flags & FLOW_DIS_IS_FRAGMENT) &&
    !(flags & (FLOW_DISSECTOR_F_STOP_BEFORE_ENCAP |
               FLOW_DISSECTOR_F_STOP_AT_ENCAP)) &&
    static_branch_unlikely(&flow_dissector_udp_inner_any_key) &&
    __skb_flow_dissect_udp_encap(skb, key_control, data, &proto, &nhoff,
                                 hlen,
                                 proto == htons(ETH_P_IP) ? AF_INET :
                                                            AF_INET6))
    fdret = FLOW_DISSECT_RET_PROTO_AGAIN;
```

This is placed after `__skb_flow_dissect_ports()` and before the `switch (fdret)` that processes the result. If the descent succeeds, it sets `fdret = FLOW_DISSECT_RET_PROTO_AGAIN`, which causes the loop to re-enter with the inner proto/nhoff. That looks correct.

The check for `fdret == FLOW_DISSECT_RET_CONTINUE` is important - it means the UDP processing didn't set any other result (like OUT_GOOD). The fragment check ensures fragmented outers don't descend. The STOP flag checks ensure callers who want the outer tuple keep it.

Wait, but what about `FLOW_DISSECTOR_F_STOP_AT_FLOW_LABEL`? The cover letter says "Callers passing FLOW_DISSECTOR_F_STOP_{AT,BEFORE}_ENCAP (RPS/RFS, tunnel drivers) keep the outer tuple even with a gate on." But the fast path dispatcher admits `FLOW_DISSECTOR_F_STOP_AT_FLOW_LABEL`. For a VXLAN packet with a non-zero outer IPv6 flow label, the IPv6 fast path would defer (because it checks for non-zero flow label). So the fast path wouldn't reach the UDP tunnel descent. The slow path would process it normally. That seems consistent.

But wait - what about a VXLAN packet with a ZERO outer IPv6 flow label? The IPv6 fast path would proceed, write the outer IPv6 keys, then hit the UDP case and try the VXLAN descent. The slow path would also process the outer IPv6, reach the UDP case, and try the VXLAN descent. Both paths would descend. That's fine.

One thing I notice: the `family` parameter is passed to `flow_dissect_fast_udp_tunnels()` and `__skb_flow_dissect_udp_encap()`, but looking at `flow_dissect_vxlan_inner_ok()`, it doesn't use the family parameter. The family is only used by the FOU/GUE lookup in patch B04. For VXLAN, Geneve, and GTP-U, the port check is sufficient. The family parameter is passed through but not used by their classifiers. That's fine - it's there for FOU/GUE.

Actually, looking more carefully at `flow_dissect_fast_udp_tunnels()`:
```c
static enum flow_dissect_fast_tunnel
flow_dissect_fast_udp_tunnels(const struct sk_buff *skb,
                              struct flow_dissector *flow_dissector,
                              void *target_container, const void *data,
                              int thoff, int hlen, int num_hdrs, u8 family)
```
The `family` parameter is passed to `flow_dissect_fou_lookup()` in patch B04, but for VXLAN/Geneve/GTP-U it's not used. That's fine.

**Patch B02: Geneve inner descent**
- Adds `flow_dissect_geneve_inner_ok()`, static key, sysctl entry.
- Validates: version 0, opt_len 0, no OAM, proto_type ETH_P_TEB.
- Updates `proc_set_udp_inner_key` to include the Geneve key in the summary.
- Commit message says "Geneve-over-IPv6 outer (only IPv4 outer is handled)" is kept out. But looking at the code, `flow_dissect_geneve_inner_ok()` doesn't check the family - it only checks the Geneve header and the inner Ethernet. The family is passed to `flow_dissect_fast_udp_tunnels()` but not used by the Geneve classifier. So actually, the Geneve descent WOULD work from an IPv6 outer. The fast path's IPv6 helper calls `flow_dissect_fast_udp_tunnels()` with `AF_INET6`, and the Geneve classifier doesn't distinguish. Similarly, the slow path's `__skb_flow_dissect_udp_encap()` is called with `AF_INET6` for IPv6 outers.

Wait, but the commit message says "Geneve-over-IPv6 outer (only IPv4 outer is handled)" is kept out of the descended set. But the code doesn't seem to enforce this restriction! Let me re-read...

Actually, looking at the sysctl doc:
```
Kept out of the descended set (both paths keep the outer keys): Geneve
with options (opt_len > 0), proto_type other than ETH_P_TEB (rare
L3-Geneve variants), and Geneve-over-IPv6 outer (only IPv4 outer is
handled).
```

But the code in `flow_dissect_geneve_inner_ok()` does NOT check the outer family. And `flow_dissect_fast_udp_tunnels()` passes the family but the Geneve classifier doesn't use it. So a Geneve-over-IPv6 packet WOULD be descended. This seems like a discrepancy between the commit message/doc and the actual code.

Wait, let me re-read more carefully. The commit message says:
```
Kept out of the descended set on both paths (so both keep the outer
keys, and fast == slow holds): Geneve with options (opt_len > 0),
OAM control frames (the O bit; RFC 8926 says these are not data),
and proto_type other than ETH_P_TEB.
```

This list does NOT include "Geneve-over-IPv6 outer." But the sysctl doc DOES include it. So there's a discrepancy between the commit message and the sysctl doc. The commit message is correct (no IPv6 restriction in the code), but the sysctl doc is wrong.

Actually, wait. Let me re-read the sysctl doc more carefully:

```
Kept out of the descended set (both paths keep the outer keys): Geneve
with options (opt_len > 0), proto_type other than ETH_P_TEB (rare
L3-Geneve variants), and Geneve-over-IPv6 outer (only IPv4 outer is
handled).
```

This claims Geneve-over-IPv6 is not handled. But the code handles it. So the sysctl doc is wrong. This is a substantive finding.

Hmm, actually let me look at this from the slow path's perspective too. The slow path calls `__skb_flow_dissect_udp_encap()` with:
```c
proto == htons(ETH_P_IP) ? AF_INET : AF_INET6
```
So for an IPv6 outer, it passes AF_INET6. And `__skb_flow_dissect_udp_encap()` calls `flow_dissect_geneve_inner_ok()` which doesn't check the family. So the slow path would also descend. Both paths descend, so fast == slow holds. The sysctl doc's claim that "only IPv4 outer is handled" is wrong.

Wait, but maybe I'm misreading the doc. Let me look at the exact text in the diff for patch B02:

```rst
Kept out of the descended set (both paths keep the outer keys): Geneve
with options (opt_len > 0), proto_type other than ETH_P_TEB (rare
L3-Geneve variants), and Geneve-over-IPv6 outer (only IPv4 outer is
handled).
```

Yes, this says Geneve-over-IPv6 is kept out. But the code doesn't enforce that. This is a documentation error.

Similarly for GTP-U, the sysctl doc says:
```
Kept out of the descended set on both paths (outer keys retained):
GTPv0 (legacy), GTP' (charging, PT=0), G-PDU type other than 0xFF,
GTP-U with extension headers / N-PDU / sequence flags set, and GTP-U
over IPv6 outer.
```

But looking at `flow_dissect_gtpu_inner_ok()`, it doesn't check the family either. So GTP-U over IPv6 would also be descended. The same doc error.

Actually, wait - the cover letter says "for IPv4 and IPv6 underlays alike." And the test patch has `build_gtpu(buf, true, false, IPPROTO_TCP, 0xff)` which is GTP-U over IPv6 outer, and `fd_descent_assert_inner(test, buf, len, htons(ETH_P_IPV6), g, false)` which asserts the descent happened. So the test confirms that GTP-U over IPv6 IS descended. The sysctl doc for GTP-U is wrong about "GTP-U over IPv6 outer" being kept out.

Similarly for Geneve, the test patch has `build_geneve(buf, true, false, IPPROTO_TCP, 0)` (IPv6 outer) and `fd_descent_assert_inner(test, buf, len, htons(ETH_P_IPV6), g, false)`. So Geneve over IPv6 IS descended and the test confirms it. The sysctl doc for Geneve is wrong.

This is a substantive finding: the sysctl docs for `geneve_inner` and `gtpu_inner` both claim IPv6 outers are not handled, but the code and tests show they are.

**Patch B03: GTP-U inner descent**
- Adds `flow_dissect_gtpu_inner_ok()`, static key, sysctl entry.
- Validates: GTPv1, PT=1, no optional fields, type 0xff (G-PDU).
- Naked inner IP (no inner Ethernet), version nibble picks v4/v6.
- Same pattern: both paths grow the same descent.

The code looks correct. The `GTP1_HDR_VERSION` and `GTP1_HDR_PT` macros are defined locally:
```c
#define GTP1_HDR_VERSION    GENMASK(7, 5)
#define GTP1_HDR_PT         BIT(4)
```
And `GTP1_F_MASK` and `GTP_TPDU` are presumably from `<net/gtp.h>`. Let me check - the header is included: `#include <net/gtp.h>`. OK.

Wait, I should check: does `<net/gtp.h>` define `GTP1_F_MASK` and `GTP_TPDU`? I don't have the header file to check, but the code uses them. If they're not defined, it would be a compile error. Since the series claims to compile clean with W=1, sparse, and smatch, I'll assume they're defined.

**Patch B04: FOU/GUE inner descent**
- Adds `flow_dissect_gue_inner_ok()` and `flow_dissect_fou_inner_ok()`.
- FOU/GUE port lookup via registered ops (`flow_dissector_fou_ops`).
- `flow_dissect_fou_lookup()` resolves netns from skb, calls ops->encap_lookup().
- fou_core.c registers the ops, switches fou_list to _rcu list helpers.
- The `fou_add_to_port_list` changes from `list_add` to `list_add_tail_rcu`, and `fou_release` changes from `list_del` to `list_del_rcu`.

Wait, there's a concern here. The commit message says "which switches its fou_list to the _rcu list helpers for the lockless walk." But looking at the diff for `fou_add_to_port_list`:
```c
-	list_add(&fou->list, &fn->fou_list);
+	list_add_tail_rcu(&fou->list, &fn->fou_list);
```
And `fou_release`:
```c
-	list_del(&fou->list);
+	list_del_rcu(&fou->list);
```

But the `fou_add_to_port_list` function still holds `fn->fou_lock` (mutex) while adding. And `fou_release` is called under the mutex too (it's called from `fou_release` which is called from `fou_cfg`...). The RCU walk in `fou_flow_encap_lookup` uses `list_for_each_entry_rcu` without holding the mutex. So the _rcu list operations are needed for the RCU walk to be safe. But this means ALL readers of fou_list must now use the _rcu variants, not just the new flow dissector lookup. Are there other readers?

Looking at the existing code (not in the diff), there are likely other readers of `fn->fou_list` that use `list_for_each_entry` under the mutex. Those don't need to change - the _rcu variants are compatible with non-rcu readers under the mutex. But the new RCU reader (`fou_flow_encap_lookup`) needs the _rcu variants for writers. So the change is correct.

But wait - is `fou->list` already initialized for RCU? The `fou` struct is `kfree_rcu`'d in `fou_release`, which means the struct has an `rcu` member. The commit message mentions "freed entries are kfree_rcu()'d." Looking at the diff, `kfree_rcu(fou, rcu)` was already there before the change. So the struct already had an `rcu` member. Good.

One thing I notice: the `fou_flow_encap_lookup` function walks the list with `list_for_each_entry_rcu` but doesn't check `fou->family` against the `family` parameter... wait, it does:
```c
if (fou->port == port && fou->family == family) {
```
OK, good.

**Patch B05: KUnit tests for descents**
- Extends the test file with descent tests.
- Tests use `fd_descent_gate_set()` to pin a descent gate on and keep the summary key in step.
- `fd_descent_check()` toggles entry gates: off (slow descends) vs on (fast descends), both must produce identical flow_keys.
- `fd_descent_assert_inner()` checks the inner 5-tuple was reached.
- `fd_descent_assert_outer()` checks the outer tuple was kept.
- FOU/GUE tests use a mock ops provider and a dummy netdev.
- Tests skip if the real fou module owns the ops hook.
- Nested VXLAN test exercises the recursion cap.

Wait, there's a potential issue with the FOU/GUE tests. The `fd_fou_gue_descend` function registers the mock ops, but if the real fou module is built-in, registration fails with -EBUSY and the test skips. But the `fd_descent_fou_gue_test` function also registers the mock ops for each iteration. If the real fou module is a module (not built-in), the mock ops would be registered successfully. But what happens if the real fou module is loaded between the check and the test? The test would fail because the ops are already registered. This is a race condition in the test, but it's probably unlikely in practice and the skip mechanism handles the built-in case.

Actually, looking more carefully at `fd_descent_fou_gue_test`, the mock ops are registered and unregistered for each iteration of the loop. Between iterations, another module could register ops. But this is a test, and the window is tiny. I'll note this but not flag it as a blocker.

**Patch B06: Documentation**
- Adds "Tunnel inner-flow descent" section to flow_dissector.rst.
- Explains why descents are off by default, never auto-managed.
- Notes the byte-identical fast==slow property.

OK, now let me organize my findings by severity.

**BLOCKERS:**

Hmm, let me think about what would actually block merging. I don't think there are hard blockers, but let me look for correctness issues.

Actually, I realize I should look more carefully at the claim about the Geneve sysctl doc. The sysctl doc says "Geneve-over-IPv6 outer (only IPv4 outer is handled)" but the code and tests show IPv6 outer IS handled. This is a wrong claim in the documentation that could mislead operators. It's substantive, maybe not a hard blocker, but definitely needs fixing.

Similarly for GTP-U: "GTP-U over IPv6 outer" is listed as kept out, but the code and tests show it IS handled.

Let me also look for bisect issues. Would each patch in series A bisect cleanly?

Patch A01: Adds static key for BPF lookup. Standalone. Bisects clean.
Patch A02: Adds the fast-path dispatcher and eth_ip shape. The dispatcher is called from __skb_flow_dissect(). Bisects clean.
Patch A03: Adds VLAN/QinQ. Builds on A02. Bisects clean.
Patch A04: Adds PPPoE. Builds on A02. Bisects clean.
Patch A05: Adds MPLS. Builds on A02. Bisects clean.
Patch A06: Adds IPIP. Builds on A02. Bisects clean.
Patch A07: Adds GRE. Builds on A06 (uses the same pattern). Bisects clean.
Patch A08: Adds counters. Builds on A02-A07. Bisects clean.
Patch A09: Bounds recursion. Builds on A06-A07. Bisects clean.
Patch A10: Adds KUnit tests. Builds on A01-A09. Bisects clean.
Patch A11: Adds docs. Bisects clean.

For series B:
Patch B01: Adds VXLAN descent + shared machinery. Builds on A. Bisects clean.
Patch B02: Adds Geneve descent. Builds on B01. Bisects clean.
Patch B03: Adds GTP-U descent. Builds on B01-B02. Bisects clean.
Patch B04: Adds FOU/GUE descent. Builds on B01-B03. Bisects clean.
Patch B05: Adds KUnit tests. Builds on B01-B04. Bisects clean.
Patch B06: Adds docs. Bisects clean.

Wait, actually there's a potential bisect issue with patch A08 (counters). Patch A08 adds `this_cpu_inc(flow_dissector_pcpu_stats.dissects)` unconditionally in the fast path's entry. But it also adds slow-path counters at each shape's recognition point. If you bisect to patch A08, the counters are added but the fast-path shapes already exist (from A02-A07). The counters should work correctly. Let me check...

Actually, looking at the A08 diff more carefully, it modifies `flow_dissect_fast_vlan`, `flow_dissect_fast_pppoe`, `flow_dissect_fast_mpls`, `flow_dissect_fast_ipip_inner`, `flow_dissect_fast_gre_inner`, and `flow_dissect_fast` to add the fast_hits counter. It also modifies `__skb_flow_dissect` to add the slow-path occurrences counter and the dissects denominator. These modifications are all consistent. Bisects clean.

Now let me look for more issues.

**Issue: Series A cover letter mentions "seven knobs" but there are actually seven byte-identical shape gates (eth_ip, vlan, qinq, pppoe, mpls, ipip, gre).** The cover letter says "a follow-up RFC will propose an optional auto mode that flips them from the measured traffic mix (via the patch-8 counters), so nobody has to hand-tune seven knobs." Seven knobs: eth_ip, vlan, qinq, pppoe, mpls, ipip, gre. That's 7. Correct.

**Issue: Series A patch 02 commit message says "Admitting STOP_AT_FLOW_LABEL is what makes the fast path reachable from skb_get_hash() at all -- the kernel's main dissection consumer."** Let me verify: `skb_get_hash()` calls `___skb_get_hash()` which calls `__skb_flow_dissect()` with `FLOW_DISSECTOR_F_STOP_AT_FLOW_LABEL`. The fast path dispatcher admits this flag. Correct.

**Issue: The cover letter for series A says "Patches 2-7 are the byte-identical common shapes (eth+IPv4/IPv6 x TCP/UDP, VLAN/QinQ, PPPoE, single MPLS, IP-in-IP, plain GRE)."** That's patches 2-7 = 6 patches. The shapes are: eth_ip (2), VLAN+QinQ (3), PPPoE (4), MPLS (5), IPIP (6), GRE (7). That's 6 patches for 7 shapes (VLAN and QinQ are in one patch). Correct.

**Issue: Series A cover letter says "Patch 9 bounds the fast-path tunnel recursion at MAX_FLOW_DISSECT_HDRS."** But patch 9 is the 9th patch (0-indexed would be 8, but the patches are 1-indexed in the subject lines). Looking at the patch list: patch 9 is "bound fast-path tunnel recursion." Correct.

Now let me look at the cross-references between the two series.

The series A cover letter says: "A companion series (posted separately) builds on this one to add opt-in inner-flow descent for the UDP tunnels (VXLAN, Geneve, GTP-U, FOU/GUE) -- that one changes hashing when enabled, so it is a separate policy discussion; this series is purely a transparent optimisation."

The series B cover letter says it builds on series A and provides a lore link placeholder: "https://lore.kernel.org/netdev/SERIES-A-LORE-LINK/". This is a placeholder that needs to be filled in when series A is actually posted. That's normal for a cover letter.

The series B cover letter also lists prerequisite-patch-id entries that should match series A's patches. That's good.

Now, one thing I notice: series B's cover letter says "The descent keeps that series' byte-identical contract: the slow path grows the same gated descent (__skb_flow_dissect_udp_encap()) as the fast path (flow_dissect_fast_udp_inner()), sharing one header-validation classifier per tunnel (flow_dissect_{vxlan,geneve,gtpu,gue,fou}_inner_ok()), so the fast and slow paths never disagree." But wait - the "byte-identical contract" in series A is between fast and slow paths for the same gate state. In series B, the contract is different: enabling a descent gate changes the output (from outer tuple to inner tuple), but both fast and slow paths produce the same changed output. The cover letter explains this correctly: "the only behaviour change is versus today's non-descending default, and only when an operator turns a gate on."

Let me now look at potential issues I may have missed.

**Issue: Patch A08 counter placement for IPIP/GRE in the slow path.** The slow path counts IPIP at:
```c
case IPPROTO_IPIP:
    flow_dissector_count_slow(FLOW_DISSECTOR_SHAPE_IPIP);
    if (flags & FLOW_DISSECTOR_F_STOP_BEFORE_ENCAP) {
        fdret = FLOW_DISSECT_RET_OUT_GOOD;
        break;
    }
```
This counts IPIP even when STOP_BEFORE_ENCAP is set. But the fast path would not handle this case (the dispatcher admits only PARSE_1ST_FRAG and STOP_AT_FLOW_LABEL). So the "eligible fraction" for IPIP would include packets that the fast path can't actually handle (those with STOP_BEFORE_ENCAP). This is a minor observability inaccuracy but not a correctness issue.

Actually, wait - let me re-read the commit message for A08: "occurrences[] a shape handled by the SLOW path." It doesn't say "a shape eligible for the fast path" - it says "handled by the slow path." So counting IPIP even with STOP_BEFORE_ENCAP is consistent with the definition. The "eligible fraction" interpretation is (occurrences + fast_hits) / dissects, which measures "how much traffic that shape's fast body would have handled" only if the occurrences counter counts the same packets the fast body would handle. If STOP_BEFORE_ENCAP packets are counted as IPIP occurrences but the fast body wouldn't handle them, then the eligible fraction is slightly inflated. But this is a minor point.

Actually, looking more carefully, the IPIP counter is placed BEFORE the STOP_BEFORE_ENCAP check. So it counts all IPIP packets, including those that stop before encap. But those packets wouldn't be eligible for the fast path (the fast path doesn't handle STOP_BEFORE_ENCAP). So the "eligible fraction" for IPIP would be inflated by the STOP_BEFORE_ENCAP packets. Similarly for GRE.

This is a minor observability issue, not a blocker. But it could confuse operators who see a high IPIP eligible fraction but low fast_hits after enabling the gate.

**Issue: Patch B01 commit message says "the recursion helpers' inner_eth_proto parameter is renamed inner_proto (the GTP-U descent later in the series passes a bare IP protocol, not an ethertype)."** The diff shows the rename from `inner_eth_proto` to `inner_proto` in `flow_dissect_fast_ipip_inner` and `flow_dissect_fast_pppoe`. This is a mechanical change that prepares for GTP-U. It bisects cleanly because the semantics don't change - it's just a rename. Good.

**Issue: Patch B01 moves MAX_FLOW_DISSECT_HDRS above the fast-path helpers.** The diff shows:
```c
+/* Maximum number of protocol headers that can be parsed in
+ * __skb_flow_dissect
+ */
+#define MAX_FLOW_DISSECT_HDRS	15
```
moved from after `__skb_flow_dissect_ipv6()` to before the fast-path helpers. And the old definition is removed:
```c
-/* Maximum number of protocol headers that can be parsed in
- * __skb_flow_dissect
- */
-#define MAX_FLOW_DISSECT_HDRS	15
```
This is needed because `flow_dissect_fast_udp_inner()` (added in B01) uses MAX_FLOW_DISSECT_HDRS. Correct.

Wait, but wasn't MAX_FLOW_DISSECT_HDRS already used by the fast path in patch A09? Let me check... In A09, `flow_dissect_fast_ipip_inner` and `flow_dissect_fast_gre_inner` use `MAX_FLOW_DISSECT_HDRS`. But A09 is applied after A08, and MAX_FLOW_DISSECT_HDRS was originally defined after `__skb_flow_dissect_ipv6()`. The fast-path helpers are defined before `__skb_flow_dissect_ipv6()`, so they would be using MAX_FLOW_DISSECT_HDRS before it's defined. That would be a compile error!

Wait, let me look at this more carefully. In the original code (before A09), MAX_FLOW_DISSECT_HDRS is defined at some point in the file. The fast-path helpers were added in A02, which is before A09. In A02, the fast-path helpers don't use MAX_FLOW_DISSECT_HDRS. In A06, `flow_dissect_fast_ipip_inner` is added, but it doesn't use MAX_FLOW_DISSECT_HDRS either (the bound is added in A09). In A09, the `num_hdrs` parameter and the `MAX_FLOW_DISSECT_HDRS` check are added to the helpers.

So in A09, `flow_dissect_fast_ipip_inner` uses `MAX_FLOW_DISSECT_HDRS`. But where is `MAX_FLOW_DISSECT_HDRS` defined at that point? It's defined after `__skb_flow_dissect_ipv6()`, which is after the fast-path helpers. So in A09, the fast-path helpers would be using `MAX_FLOW_DISSECT_HDRS` before it's defined. That would be a compile error!

Let me check the A09 diff more carefully:
```c
+	/* Mirror the slow path's MAX_FLOW_DISSECT_HDRS budget; past the cap
+	 * defer, so both paths stop at the same depth.
+	 */
+	if (++num_hdrs > MAX_FLOW_DISSECT_HDRS)
+		return false;
```

This is in `flow_dissect_fast_ipip_inner`, which is defined before `__skb_flow_dissect_ipv6()` and before the original `MAX_FLOW_DISSECT_HDRS` definition. So this would indeed be a forward reference to an undefined macro.

Wait, actually, in C, `#define` is a preprocessor directive. The preprocessor processes the entire file before compilation, so `#define MAX_FLOW_DISSECT_HDRS 15` is available everywhere in the file regardless of where it appears. So there's no compile error. The `#define` doesn't need to appear before its use in the source file because the preprocessor handles it.

OK, so no compile error. But then why does B01 move the `#define`? The commit message says "MAX_FLOW_DISSECT_HDRS moves above the fast-path helpers so the shared flow_dissect_fast_udp_inner() tail can use it." But as I just reasoned, the preprocessor would make it available regardless of position. So the move is cosmetic/style, not functional. That's fine - it improves readability.

Actually, I realize I was wrong about C preprocessor semantics. A `#define` is processed top-to-bottom by the preprocessor. If a macro is used before its `#define`, the preprocessor would NOT expand it (it would leave the token as-is, which would then be a compile error if it's used in a context that requires the value). So the position DOES matter.

Let me re-check. In A09, the `flow_dissect_fast_ipip_inner` function uses `MAX_FLOW_DISSECT_HDRS`. This function is defined before the `#define MAX_FLOW_DISSECT_HDRS 15` line. So the preprocessor would encounter `MAX_FLOW_DISSECT_HDRS` before it's defined, and would NOT expand it. This would be a compile error.

Wait, but the series claims to compile clean. Let me look at this more carefully.

Actually, let me look at the file structure. In the original kernel source (before this series), `MAX_FLOW_DISSECT_HDRS` is defined at some point. The fast-path helpers are added before that point. So in A09, when the fast-path helpers start using `MAX_FLOW_DISSECT_HDRS`, they're using it before the `#define`. This should be a compile error.

But B01 moves the `#define` above the fast-path helpers. So B01 fixes this issue. But A09 (which is before B01) would have the compile error.

Hmm, but wait - maybe the `#define` is already above the fast-path helpers in the original kernel source? Let me look at the base more carefully.

In the A02 diff, the fast-path helpers are added at:
```
@@ -1043,6 +1070,222 @@ static bool is_pppoe_ses_hdr_valid(const struct pppoe_hdr *hdr)
```
This is after line 1043 in the original file. And in the B01 diff, the `MAX_FLOW_DISSECT_HDRS` is moved from:
```
@@ -1009,11 +1143,6 @@ __skb_flow_dissect_ipv6(const struct sk_buff *skb,
```
to above the fast-path helpers. So in the original file, `MAX_FLOW_DISSECT_HDRS` was defined around line 1009, which is BEFORE the fast-path helpers (added around line 1070). So the fast-path helpers are added AFTER the `#define`, and `MAX_FLOW_DISSECT_HDRS` IS available to them.

Wait, that changes things. Let me re-examine. The B01 diff shows:
```c
@@ -1009,11 +1143,6 @@ __skb_flow_dissect_ipv6(const struct sk_buff *skb,
 	key_ip->ttl = iph->hop_limit;
 }
 
-/* Maximum number of protocol headers that can be parsed in
- * __skb_flow_dissect
- */
-#define MAX_FLOW_DISSECT_HDRS	15
-
 static bool skb_flow_dissect_allowed(int *num_hdrs)
 {
 	++*num_hdrs;
```

And the new definition is placed above the fast-path helpers:
```c
@@ -123,6 +132,131 @@ static bool flow_dissect_fast_gre_inner(const struct sk_buff *skb,
  */
 static struct flow_dissector flow_keys_dissector_symmetric;
 
+/* Maximum number of protocol headers that can be parsed in
+ * __skb_flow_dissect
+ */
+#define MAX_FLOW_DISSECT_HDRS	15
+
```

So in the original file, `MAX_FLOW_DISSECT_HDRS` was defined around line 1009 (after `__skb_flow_dissect_ipv6`). The fast-path helpers are added around line 1070 (after `is_pppoe_ses_hdr_valid`). Wait, that doesn't make sense - line 1070 is after line 1009. So the fast-path helpers are AFTER the `#define`, meaning `MAX_FLOW_DISSECT_HDRS` IS available to them.

Hmm, but the fast-path helpers are added in A02, which adds them at line 1070+. The `#define` is at line ~1009. So 1070 > 1009, meaning the helpers are after the define. So `MAX_FLOW_DISSECT_HDRS` IS available.

But then in B01, the `#define` is moved from line ~1009 to line ~132 (much earlier), and the old definition at line ~1009 is removed. The reason given is "so the shared flow_dissect_fast_udp_inner() tail can use it." But `flow_dissect_fast_udp_inner()` is added at line ~132+ in B01, which is before line 1009. So without the move, `flow_dissect_fast_udp_inner()` would be before the `#define` and couldn't use it. That's why B01 moves it.

So the move is necessary for B01, not for A09. A09's helpers are at line 1070+ (after the original define at 1009), so they CAN use `MAX_FLOW_DISSECT_HDRS` without the move. Good, no compile issue in A09.

OK, so no compile issue there. The B01 move is correctly motivated.

Let me now look for other issues.

**Issue: Series A patch 02 commit message says "The IPv6 fast-path defers on any non-zero flow label: callers passing FLOW_DISSECTOR_F_STOP_AT_FLOW_LABEL -- skb_get_hash(), i.e. RPS/RFS, fq, fq_codel, cake -- make the slow path stop at a non-zero label, and dissectors requesting the label key write it; deferring on the label itself keeps byte-identity for every combination without threading flags into the helpers, and zero-label IPv6 stays on the fast path."**

This is correct. The slow path with STOP_AT_FLOW_LABEL stops at a non-zero label (doesn't dissect further), while without the flag it continues. The fast path can't know which behavior to produce without checking the flag, so it defers on any non-zero label. For zero-label IPv6 (the common case), both paths produce the same output. Correct.

**Issue: Series A patch 06 (IPIP) commit message says "FLOW_DISSECTOR_F_STOP_BEFORE_ENCAP and STOP_AT_ENCAP don't apply because the top-level dispatcher already rejects anything beyond F_PARSE_1ST_FRAG, so the fast-path entry never sees the encap-stop flags - packets that request them go to the slow path unchanged."**

Wait, looking at the dispatcher in A02:
```c
if (flags & ~(unsigned int)(FLOW_DISSECTOR_F_PARSE_1ST_FRAG |
                            FLOW_DISSECTOR_F_STOP_AT_FLOW_LABEL))
    return false;
```

This rejects any flag other than PARSE_1ST_FRAG and STOP_AT_FLOW_LABEL. So STOP_BEFORE_ENCAP and STOP_AT_ENCAP are rejected. The commit message is correct.

**Issue: Series B patch 01 commit message says "Callers passing FLOW_DISSECTOR_F_STOP_{AT,BEFORE}_ENCAP (RPS/RFS, tunnel drivers) keep the outer tuple even with a gate on."** But wait - RPS/RFS uses STOP_AT_FLOW_LABEL, not STOP_AT_ENCAP. The commit message lumps RPS/RFS with tunnel drivers under STOP_AT_ENCAP/STOP_BEFORE_ENCAP. Let me check: `skb_get_hash()` passes `FLOW_DISSECTOR_F_STOP_AT_FLOW_LABEL`, not STOP_AT_ENCAP. So RPS/RFS would NOT be blocked by the STOP_AT_ENCAP check. The commit message's grouping is misleading.

Actually, looking at the slow-path code in B01:
```c
if (ip_proto == IPPROTO_UDP &&
    fdret == FLOW_DISSECT_RET_CONTINUE &&
    !(key_control->flags & FLOW_DIS_IS_FRAGMENT) &&
    !(flags & (FLOW_DISSECTOR_F_STOP_BEFORE_ENCAP |
               FLOW_DISSECTOR_F_STOP_AT_ENCAP)) &&
    static_branch_unlikely(&flow_dissector_udp_inner_any_key) &&
    __skb_flow_dissect_udp_encap(...))
    fdret = FLOW_DISSECT_RET_PROTO_AGAIN;
```

So STOP_AT_FLOW_LABEL does NOT block the descent. RPS/RFS (which passes STOP_AT_FLOW_LABEL) WOULD get the descent. But the commit message says "Callers passing FLOW_DISSECTOR_F_STOP_{AT,BEFORE}_ENCAP (RPS/RFS, tunnel drivers) keep the outer tuple." This implies RPS/RFS passes STOP_AT_ENCAP, which is wrong. RPS/RFS passes STOP_AT_FLOW_LABEL.

Actually, let me re-read: "Callers passing FLOW_DISSECTOR_F_STOP_{AT,BEFORE}_ENCAP (RPS/RFS, tunnel drivers) keep the outer tuple even with a gate on." The parenthetical "(RPS/RFS, tunnel drivers)" is listing the callers that pass those flags. But RPS/RFS passes STOP_AT_FLOW_LABEL, not STOP_AT_ENCAP/STOP_BEFORE_ENCAP. So the parenthetical is wrong - RPS/RFS is not a caller of STOP_AT_ENCAP/STOP_BEFORE_ENCAP.

Wait, maybe there are other callers. Let me think about who passes STOP_AT_ENCAP and STOP_BEFORE_ENCAP. These are typically tunnel drivers that want the outer tuple for their own hashing. RPS/RFS uses STOP_AT_FLOW_LABEL. So the commit message's grouping of RPS/RFS with STOP_AT_ENCAP callers is wrong.

This is a substantive finding: the B01 commit message incorrectly attributes RPS/RFS as callers of STOP_AT_ENCAP/STOP_BEFORE_ENCAP.

Actually, let me re-read the cover letter too. The B cover letter says: "Callers passing FLOW_DISSECTOR_F_STOP_{AT,BEFORE}_ENCAP (RPS/RFS, tunnel drivers) keep the outer tuple even with a gate on." Same issue.

Wait, but maybe I should check: does RPS/RFS actually pass STOP_AT_FLOW_LABEL? Let me think... `skb_get_hash()` → `___skb_get_hash()` → `__skb_flow_dissect()` with `FLOW_DISSECTOR_F_STOP_AT_FLOW_LABEL`. Yes, that's correct. RPS/RFS uses `skb_get_hash()` which passes STOP_AT_FLOW_LABEL.

So the cover letter and B01 commit message both incorrectly group RPS/RFS with STOP_AT_ENCAP callers. RPS/RFS would actually get the descent (because STOP_AT_FLOW_LABEL doesn't block it), which is the desired behavior - RPS/RFS WANTS the inner flow for better hash distribution.

Actually, wait - this makes the descents MORE useful for RPS/RFS, not less. The commit message's claim that "RPS/RFS keep the outer tuple" is wrong - RPS/RFS would get the inner flow. The claim is misleading but the actual behavior is better than described. Still, the claim is wrong and should be fixed.

Hmm, actually let me reconsider. Maybe the author is saying that RPS/RFS and tunnel drivers are BOTH callers who keep the outer tuple, but for different reasons. RPS/RFS passes STOP_AT_FLOW_LABEL (not STOP_AT_ENCAP), and tunnel drivers pass STOP_AT_ENCAP. The sentence structure "Callers passing FLOW_DISSECTOR_F_STOP_{AT,BEFORE}_ENCAP (RPS/RFS, tunnel drivers)" could be read as "callers passing [these flags], [which includes] RPS/RFS [and] tunnel drivers." But that reading is wrong because RPS/RFS doesn't pass those flags.

OK, this is a real error in the commit message. Let me flag it.

**Issue: Series A patch 08 counters - the `eth_ip_top` tracking.** Looking at the A08 diff:
```c
+	int nhoff_init = 0;
+	bool eth_ip_top = false;
```
And:
```c
+	nhoff_init = nhoff;
```
This is set after `key_num_of_vlans->num_of_vlans = 0;` but before `proto_again:`. Then:
```c
+	/* Top-level eth+IPv4: eth_ip shape candidate (confirmed at out:). */
+	if (nhoff == nhoff_init)
+		eth_ip_top = true;
```
This is in the IPv4 case. And similarly for IPv6. So `eth_ip_top` is set when the IP header is at the initial nhoff (no VLAN/PPPoE/MPLS before it). This correctly identifies top-level eth+IP.

But wait - what about a packet that's just eth+IP with no other L2 headers? The initial nhoff would be after the Ethernet header. When we reach the IPv4 case, nhoff should still equal nhoff_init (since no VLAN tag was processed). So eth_ip_top = true. Correct.

What about a VLAN+IP packet? The VLAN tag is processed first, advancing nhoff. When we reach the IPv4 case, nhoff != nhoff_init. So eth_ip_top = false. Correct - this packet is counted as VLAN, not eth_ip.

What about a pure IP packet (no Ethernet, like in raw-data mode with proto=ETH_P_IP)? nhoff would be 0 initially. When we reach IPv4, nhoff == nhoff_init == 0. So eth_ip_top = true. Correct.

OK, the eth_ip_top tracking looks correct.

**Issue: Series A patch 02 sysctl documentation.** The A02 sysctl doc says:
```
For common shapes
(Eth+IPv4/IPv6+TCP/UDP, plus extensions for VLAN, QinQ and VXLAN
inner descent added by follow-up patches in this series), an opt-in
fast-path bypasses the slow-path graph walk and writes
``struct flow_keys`` directly.
```
This mentions "VXLAN inner descent" as a follow-up in this series, but VXLAN descent is in series B, not series A. The parenthetical says "added by follow-up patches in this series" but VXLAN is not in series A. This is a stale/incorrect reference.

Wait, let me re-read: "plus extensions for VLAN, QinQ and VXLAN inner descent added by follow-up patches in this series." The VLAN and QinQ are indeed in this series (patch 03). But VXLAN inner descent is in series B. So listing VXLAN here is wrong - it's not in this series.

This is a substantive finding: the A02 sysctl doc incorrectly claims VXLAN inner descent is in series A.

**Issue: Series A patch 02 sysctl doc says "Each shape is gated by its own static key + sysctl so operators enable only what their deployment uses."** This is accurate for series A. Good.

**Issue: Series B patch 02 (Geneve) sysctl doc claims "Geneve-over-IPv6 outer (only IPv4 outer is handled)" but the code handles both.** As I analyzed above, this is wrong. The code doesn't check the outer family for Geneve. The test in B05 confirms IPv6 outer works.

**Issue: Series B patch 03 (GTP-U) sysctl doc claims "GTP-U over IPv6 outer" is kept out, but the code handles it.** Same issue as Geneve.

**Issue: Series B cover letter says "for IPv4 and IPv6 underlays alike."** This is correct - the code handles both. But it contradicts the per-patch sysctl docs for Geneve and GTP-U. The cover letter is right; the sysctl docs are wrong.

**Issue: Series A patch 08 commit message says "Dissects fully handled by an attached netns BPF flow dissector program are deliberately not counted: the dissects increment sits after the BPF hook's early return."** Looking at the A08 diff:
```c
+	this_cpu_inc(flow_dissector_pcpu_stats.dissects);
+
 	if (flow_dissect_fast(skb, flow_dissector, target_container,
```
The dissects increment is before `flow_dissect_fast()` but after the BPF hook (which is earlier in `__skb_flow_dissect()`). So if the BPF hook returns early, the dissects counter is NOT incremented. Correct.

**Issue: The KUnit test in A10 uses `static_branch_enable`/`static_branch_disable` directly, which is not safe in production but fine for tests.** The test does `fd_fast_gates_set(true/false)` which calls `static_branch_enable`/`static_branch_disable`. These are not atomic and could be racy on SMP. But since this is a KUnit test running in a controlled environment, it's acceptable. Not a finding.

**Issue: Series A patch 10 KUnit test - the `fd_fast_gates_off_test` checks that fast_hits doesn't change when gates are off, then enables gates and checks that fast_hits increases.** But between the two checks, the test calls `__skb_flow_dissect` which increments the `dissects` counter. The `flow_dissector_fast_hits_kunit()` accessor sums all fast_hits across all CPUs. If the test runs on a multi-CPU system and there's concurrent dissection (unlikely in KUnit), the counter could change. But KUnit runs in a single-threaded context, so this shouldn't be an issue. Not a finding.

**Issue: Series B patch 04 (FOU/GUE) - the `flow_dissect_fou_lookup` function uses `guard(rcu)()` which is a cleanup-based RCU lock.** This is a modern kernel idiom. It should be fine. Not a finding.

**Issue: Series B patch 04 - the `fou_flow_encap_lookup` function walks `fn->fou_list` with `list_for_each_entry_rcu` but doesn't hold `fn->fou_lock`.** This is correct because the list operations were changed to _rcu variants. The RCU read lock (held by `guard(rcu)()` in `flow_dissect_fou_lookup`) protects the walk. Not a finding.

**Issue: Series B patch 04 - the `fou_add_to_port_list` function uses `list_add_tail_rcu` under `fn->fou_lock` (mutex).** This is correct - RCU list additions can be done under any lock, including a mutex. The _rcu variant ensures the list manipulation is RCU-safe for concurrent readers. Not a finding.

Wait, I should also check: are there other readers of `fn->fou_list` that use non-rcu list traversal? If so, they would need to be updated too. Looking at the existing fou code (not in the diff), there are likely readers like `fou_lookup` or similar. But those would be under `fn->fou_lock` (mutex), and RCU list traversal with mutex protection is safe. The non-rcu `list_for_each_entry` under mutex is also safe because the mutex prevents concurrent modification. So existing readers don't need to change. Not a finding.

**Issue: Series B patch 01 commit message says "Port discovery is hardcoded to IANA_VXLAN_UDP_PORT (4789); non-standard VXLAN ports (e.g. Cilium's 8472) are not descended."** This is accurate - the code checks `udp_ports[1] != htons(IANA_VXLAN_UDP_PORT)`. Correct.

**Issue: Series B patch 01 - the `flow_dissect_vxlan_inner_ok` function checks `vxh->vx_flags != VXLAN_HF_VNI`.** `VXLAN_HF_VNI` is the I flag bit. The check ensures only the I flag is set and all other bits are zero. This matches the commit message: "I flag set, every other flag bit zero." Correct.

Wait, actually, `VXLAN_HF_VNI` is typically just the I flag bit (0x08 in the flags field). So `vxh->vx_flags != VXLAN_HF_VNI` checks that ONLY the I flag is set. If any other bit is set (GBP, GPE, etc.), the check fails. Correct.

**Issue: Series B patch 02 (Geneve) - the `flow_dissect_geneve_inner_ok` function checks `gnv->ver != 0 || gnv->opt_len != 0 || gnv->oam || gnv->proto_type != htons(ETH_P_TEB)`.** This ensures version 0, no options, no OAM, and TEB inner. Correct per the commit message.

But wait - the commit message says "proto_type ETH_P_TEB" but doesn't mention what happens for other proto_types. The sysctl doc says "proto_type other than ETH_P_TEB (rare L3-Geneve variants)" are kept out. The code rejects anything other than ETH_P_TEB. Correct.

**Issue: Series B patch 03 (GTP-U) - the `flow_dissect_gtpu_inner_ok` function checks `FIELD_GET(GTP1_HDR_VERSION, gtp->flags) != 1` for version 1.** It also checks `!(gtp->flags & GTP1_HDR_PT)` for PT=1, `(gtp->flags & GTP1_F_MASK)` for no optional fields, and `gtp->type != GTP_TPDU` for G-PDU type. Correct per the commit message.

**Issue: Series B patch 04 (FOU/GUE) - the `flow_dissect_gue_inner_ok` function checks `guehdr->version != 0 || guehdr->control || (guehdr->flags & ~GUE_FLAGS_ALL)`.** Wait, what is `GUE_FLAGS_ALL`? It's presumably defined in `<net/gue.h>`. The check rejects non-zero version, control messages, and unknown flags. Correct per the commit message.

But the commit message says "Only GUE version-0 data messages with an IPIP/IPv6 inner are handled." The code checks `guehdr->proto_ctype` for IPPROTO_IPIP or IPPROTO_IPV6. Correct.

**Issue: Series B patch 04 - the `flow_dissect_fou_inner_ok` function takes an `ipproto` parameter from the fou table.** Direct FOU doesn't have an inner protocol on the wire - it comes from the fou table configuration. The function maps the ipproto to ETH_P_IP or ETH_P_IPV6. Correct per the commit message.

**Issue: Series B patch 05 (KUnit) - the `fd_descent_check` function enables a descent gate, then runs the dissection with entry gates off (slow path descends) and on (fast path descends).** But when the entry gates are off, the fast path dispatcher returns false immediately (because `flow_dissect_fast` checks the eth_ip static key first). The slow path then runs, and the slow-path descent in `__skb_flow_dissect_udp_encap` runs because `flow_dissector_udp_inner_any_key` is enabled. When the entry gates are on, the fast path runs and descends via `flow_dissect_fast_udp_tunnels`. Both paths should produce the same result. Correct.

Wait, but there's a subtlety. When the entry gates are off, the fast path returns false, and the slow path runs. The slow path's descent is gated by `flow_dissector_udp_inner_any_key`, which is enabled by `fd_descent_gate_set`. So the slow path descends. When the entry gates are on, the fast path runs and descends. The test checks that both produce the same flow_keys. This is correct.

But there's another subtlety: when the entry gates are off and the slow path descends, the slow path's descent re-enters the loop (goto proto_again). The loop processes the inner header through the slow path's graph walk. When the entry gates are on and the fast path descends, the fast path's `flow_dissect_fast_udp_inner` calls `flow_dissect_fast_ipv4` or `flow_dissect_fast_ipv6` directly. Both should produce the same flow_keys. The test verifies this. Correct.

**Issue: Series B patch 05 - the `fd_descent_stop_flags_test` function tests STOP_AT_ENCAP and STOP_BEFORE_ENCAP.** It enables the VXLAN descent gate and the eth_ip fast-path gate, then dissects with STOP flags. The test asserts that ENCAP is NOT set and the outer tuple is kept. This is correct because the fast-path dispatcher rejects STOP_AT_ENCAP and STOP_BEFORE_ENCAP (only admits PARSE_1ST_FRAG and STOP_AT_FLOW_LABEL), so the fast path returns false and the slow path runs. The slow path's descent is also guarded by the STOP flags. So both paths keep the outer tuple. Correct.

Wait, but the test calls `fd_check_one(test, &flow_keys_dissector, buf, htons(ETH_P_IP), len, stop_flags[i])` which is the equivalence check. With the descent gate on and the eth_ip gate on, and STOP_AT_ENCAP set, the fast path should return false (dispatcher rejects the flag), and the slow path should run without descending (STOP_AT_ENCAP blocks it). Both should produce the outer tuple. The test also directly dissects and checks the outer tuple. Correct.

**Issue: The test in B05 `fd_descent_fou_gue_test` registers and unregisters the mock ops for each iteration.** Between iterations, another module could register ops. But this is a test, and the window is tiny. Not a finding.

**Issue: Series B cover letter says "a CONFIG_NET_FOU {n,m,y} x CONFIG_FLOW_DISSECTOR_KUNIT_TEST config matrix (with fou built in, the real module owns the ops hook and the FOU/GUE cases skip cleanly)."** The test code in B05 handles this with:
```c
ret = flow_dissector_fou_ops_register(&fd_mock_fou_ops);
if (ret == -EBUSY)
    kunit_skip(test, "fou module owns the flow dissector ops");
```
Correct.

**Issue: The `fd_fou_gue_descend` function in B05 calls `kunit_skip` after `KUNIT_ASSERT_EQ(test, 0, ret)`.** Wait, looking at the code:
```c
ret = flow_dissector_fou_ops_register(&fd_mock_fou_ops);
if (ret == -EBUSY)
    kunit_skip(test, "fou module owns the flow dissector ops");
KUNIT_ASSERT_EQ(test, 0, ret);
```
If ret is -EBUSY, `kunit_skip` is called, which should skip the test. But `kunit_skip` might not return (it might longjmp or similar). If it does return, the `KUNIT_ASSERT_EQ` would fail because ret is -EBUSY, not 0. Let me check KUnit semantics...

Actually, `kunit_skip()` typically calls `kunit_skip()` which internally calls `kunit_abort()` (a longjmp), so it doesn't return. So the `KUNIT_ASSERT_EQ` line is never reached. This is fine.

But wait, looking at the `fd_descent_fou_gue_test` function:
```c
ret = flow_dissector_fou_ops_register(&fd_mock_fou_ops);
if (ret == -EBUSY)
    kunit_skip(test, "fou module owns the flow dissector ops");
KUNIT_ASSERT_EQ(test, 0, ret);
```
If ret is 0, `KUNIT_ASSERT_EQ(test, 0, ret)` passes. If ret is -EBUSY, kunit_skip is called and doesn't return. If ret is some other error, KUNIT_ASSERT_EQ fails. Correct.

**Now let me look for any issues with the ordering of patches within each series.**

Series A:
- A01: BPF static key (standalone)
- A02: eth_ip fast path (adds dispatcher, first shape)
- A03: VLAN/QinQ (adds to dispatcher)
- A04: PPPoE (adds to dispatcher)
- A05: MPLS (adds to dispatcher)
- A06: IPIP (adds to v4/v6 helpers)
- A07: GRE (adds to v4/v6 helpers, builds on A06's pattern)
- A08: Counters (adds to all shapes)
- A09: Recursion bound (adds num_hdrs to tunnel helpers from A06/A07)
- A10: KUnit tests (tests everything from A01-A09)
- A11: Documentation

This ordering is logical. Each patch builds on the previous ones. Bisects should be clean.

One thing to check: does A08 (counters) bisect cleanly? It modifies the fast-path helpers from A02-A07 to add counter calls. If you bisect to A08, the helpers already exist (from A02-A07), and A08 adds the counter calls. The counters are per-cpu and the `/proc/net/flow_dissector_stats` file is added. The file would show counters for all shapes. Bisects clean.

Does A09 (recursion bound) bisect cleanly? It modifies the tunnel helpers from A06/A07 to add the `num_hdrs` parameter. If you bisect to A09, the tunnel helpers exist (from A06/A07), and A09 adds the bound. The helpers now check `MAX_FLOW_DISSECT_HDRS`. Bisects clean.

Wait, but A09 also modifies the non-tunnel helpers. Looking at the A09 diff:
- `flow_dissect_fast_ipv4` and `flow_dissect_fast_ipv6` get a new `num_hdrs` parameter.
- `flow_dissect_fast_vlan` passes `vlan_depth + 2` to the IP helpers.
- `flow_dissect_fast_pppoe` passes `2` to the IP helpers.
- `flow_dissect_fast` passes `1` to the IP helpers.

So all callers of the IP helpers are updated. The non-tunnel paths just pass a count and don't check the bound. Only the tunnel helpers (`flow_dissect_fast_ipip_inner`, `flow_dissect_fast_gre_inner`) check the bound. This is correct because only tunnel descents can recurse.

Bisects clean.

Series B:
- B01: VXLAN descent + shared machinery
- B02: Geneve descent
- B03: GTP-U descent
- B04: FOU/GUE descent
- B05: KUnit tests
- B06: Documentation

Each patch adds one tunnel type. B01 introduces the shared machinery. B02-B04 build on it. B05 tests everything. B06 documents. Logical ordering.

**Issue: Series B patch 01 renames `inner_eth_proto` to `inner_proto` in `flow_dissect_fast_ipip_inner` and `flow_dissect_fast_pppoe`.** This is a mechanical rename that doesn't change behavior. But it touches code from series A (patches A04 and A06). If someone bisects to B01, the rename is applied. No issue.

Actually, wait - the rename is in B01, which is the first patch of series B. It modifies code from A04 and A06. But the rename is straightforward and doesn't change semantics. No issue.

**Now let me check for any confusing or undefined terms for a fresh reader.**

**Issue: Series A cover letter uses "allshapes" and "isolated A/B" as instrument names without much context.** The cover letter explains: "Two instruments, each run on 7 of the 8 microarchitectures: 'allshapes' compiles every fast path in (the realistic icache footprint) and measures each shape in isolation... 'isolated A/B' compiles one shape's path against the unmodified dissector (the upper bound for that shape)." This is adequate context. Not a finding.

**Issue: Series A cover letter mentions "the patch-8 counters" in the context of the auto mode.** This is a forward reference to patch 8, which is fine in a cover letter. Not a finding.

**Issue: Series A patch 05 (MPLS) commit message says "mirroring the vlan -> qinq staging the v3-namespace series used."** What is "the v3-namespace series"? This is an undefined reference. The reader has no context for what "v3-namespace" is. Is it a previous version of this series? An unrelated series? This is confusing for a fresh reader.

Similarly, the MPLS sysctl doc says "extending to depth-2 or more is a follow-up, mirroring the vlan -> qinq staging the v3-namespace series used." Same undefined reference.

**Issue: Series A patch 06 (IPIP) commit message says "The ENCAP write must happen *after* the inner returns because the existing fast-path helpers unconditionally set key_control->flags = 0 on entry."** This is clear and well-explained. Not a finding.

**Issue: Series B cover letter says "the fast and slow paths never disagree -- the descent subset is defined once, not mirrored by hand."** This refers to the shared `flow_dissect_*_inner_ok()` classifiers used by both paths. This is clear from the B01 commit message. Not a finding.

**Issue: Series B patch 04 commit message says "the built-in dissector reaches it through a small registered ops hook (the fou module is tristate; registration failure logs a pr_warn)."** This is clear. The `pr_warn` is in `fou_init()`:
```c
if (flow_dissector_fou_ops_register(&fou_flow_ops))
    pr_warn("fou: flow dissector ops already registered, fou_inner/gue_inner descent unavailable\n");
```
Correct.

**Issue: Series A patch 02 commit message says "The sysctl subtree is /proc/sys/net/flow_dissector/ (registered by a new late_initcall in net/core/flow_dissector.c via register_net_sysctl(&init_net, "net/flow_dissector", tbl) — same shape as net/mpls, net/bridge)."** The code uses `late_initcall(flow_dissector_sysctl_init)`. Correct.

**Issue: Series A patch 11 (Documentation) mentions "the break-even model for when a gate is worth enabling."** The doc includes a section "When to enable" with the break-even formula `p_be = C / (S + C)`. This is well-explained. Not a finding.

**Let me now look for any remaining issues I might have missed.**

**Issue: Series A patch 01 - the `DEBUG_NET_WARN_ON_ONCE(!net)` is moved inside the gated block.** The commit message says "DEBUG_NET_WARN_ON_ONCE(!net) moves inside the gated block: it exists to catch a missing netns for the BPF hook, which is only meaningful when a program can actually be attached." This is correct - the warning is only relevant when the BPF hook is enabled.

But wait - what about the case where `net` is NULL and the BPF key is disabled? In that case, the warning is not triggered. Is that a problem? The warning was there to catch missing netns for the BPF hook. If the BPF hook is disabled (no program attached), the netns doesn't matter. So not triggering the warning is correct. Not a finding.

**Issue: Series A patch 01 - the static key is exported.** `EXPORT_SYMBOL(netns_bpf_flow_dissector_enabled)` is in flow_dissector.c, and `extern struct static_key_false netns_bpf_flow_dissector_enabled` is in skbuff.h. The key is defined in flow_dissector.c and used in flow_dissector.c. The export is for potential module users, though none are shown. The export seems reasonable. Not a finding.

Wait, actually, is the extern in `include/linux/skbuff.h` the right place? The key is used in `net/core/flow_dissector.c` which includes `include/linux/skbuff.h`. And `kernel/bpf/net_namespace.c` includes... let me check. The `net_namespace.c` file uses `static_branch_inc/dec(&netns_bpf_flow_dissector_enabled)`, so it needs the extern. It probably includes `include/linux/skbuff.h` already. The extern could also be in a more specific header, but `skbuff.h` is where the BPF flow dissector types are declared, so it's a reasonable choice. Not a finding.

**Issue: Series A patch 08 - the `/proc/net/flow_dissector_stats` file uses `proc_create_single` with `init_net.proc_net`.** This creates the file in the init netns only. The commit message says "the file is visible in the init netns only, so containers do not see it." Correct.

**Issue: Series A patch 10 - the KUnit test file is named `flow_dissector_test.c` and is compiled when `CONFIG_FLOW_DISSECTOR_KUNIT_TEST` is set.** But there's already a `net/core/flow_dissector.c` test infrastructure? Actually, looking at the Makefile:
```makefile
obj-$(CONFIG_FLOW_DISSECTOR_KUNIT_TEST) += flow_dissector_test.o
```
This is a separate file. The Kconfig entry says "tristate" but the test file has `MODULE_DESCRIPTION` and `MODULE_LICENSE` at the end, which is fine for tristate. Not a finding.

Wait, the Kconfig says `default KUNIT_ALL_TESTS` which means it's enabled when KUNIT_ALL_TESTS is set. This is standard. Not a finding.

**Issue: Series B patch 01 - the `__skb_flow_dissect_udp_encap` function takes a `struct flow_dissector_key_control *key_control` parameter.** Looking at the call site:
```c
__skb_flow_dissect_udp_encap(skb, key_control, data, &proto, &nhoff,
                             hlen,
                             proto == htons(ETH_P_IP) ? AF_INET :
                                                        AF_INET6)
```
The `key_control` is already available at the call site (it was obtained earlier in `__skb_flow_dissect`). The function stamps `FLOW_DIS_ENCAPSULATION` on it. This is correct - the slow path needs to set the encap flag when it descends. Not a finding.

**Issue: Series B patch 01 - the slow-path descent is placed after `__skb_flow_dissect_ports()`.** This means the outer UDP ports are already written to `key_ports` before the descent. When the descent re-enters the loop, the inner IP is processed, and the inner ports overwrite the outer ports. The outer addrs are also overwritten by the inner addrs. This matches the fast path's behavior. Correct.

Wait, but what about the outer IP addrs? The slow path writes them before the UDP case. When the descent re-enters the loop with the inner IP, the inner IP's addrs overwrite the outer's. But for IPv6-outer/IPv4-inner, the inner IPv4 only overwrites the first 4 bytes of the addrs union, leaving the outer IPv6's tail bytes. The fast path handles this by writing the outer IPv6 addrs before the descent (as described in A06). Does the slow path also handle this?

Looking at the slow path: when it processes the outer IPv6, it writes the v6addrs. Then the UDP case is reached. Then `__skb_flow_dissect_udp_encap` rewrites proto/nhoff and re-enters the loop. The inner IPv4 is processed, which writes v4addrs (overwriting the first 4 bytes). The tail bytes from the outer IPv6 remain. This matches the fast path's behavior. Correct.

But wait - for the UDP tunnel descents, the outer is IPv4 or IPv6 + UDP. The inner is the tunnel payload (e.g., Eth + IP for VXLAN). The slow path writes the outer IP addrs, then the outer UDP ports, then descends. The inner IP addrs overwrite the outer's. For IPv6-outer/IPv4-inner (e.g., VXLAN over IPv6 with IPv4 inner), the inner IPv4 would overwrite only the first 4 bytes of the v6addrs union, leaving residue. Does the fast path handle this?

Looking at the fast path: `flow_dissect_fast_ipv6` writes the outer v6addrs. Then `flow_dissect_fast_udp_tunnels` is called, which calls `flow_dissect_fast_udp_inner`, which calls `flow_dissect_fast_ipv4` (for IPv4 inner). `flow_dissect_fast_ipv4` writes v4addrs (first 4 bytes). The tail bytes from the outer IPv6 remain. The fast path matches the slow path's behavior. Correct.

But wait - does the fast path write the outer IPv6 addrs before the UDP tunnel descent? Looking at the A02 code for `flow_dissect_fast_ipv6`:
1. Write key_control (addr_type = IPV6_ADDRS, thoff, flags = 0)
2. Write key_basic (n_proto = IPV6, ip_proto = nexthdr)
3. Write v6addrs
4. Write ports
5. Then (in B01) check for UDP tunnel descent

So yes, the outer v6addrs are written before the descent. The inner IPv4 would then overwrite the first 4 bytes. The residue is preserved. Correct.

But there's a subtlety: `flow_dissect_fast_udp_inner` stamps `FLOW_DIS_ENCAPSULATION` after the inner pass. The inner pass (via `flow_dissect_fast_ipv4`) sets `key_control->flags = 0`, which clears any flags. Then `flow_dissect_fast_udp_inner` sets `FLOW_DIS_ENCAPSULATION`. This is the same pattern as IPIP and GRE. Correct.

**Issue: Series B patch 01 - the fast-path UDP tunnel descent is placed after the ports are written.** Looking at the B01 diff for `flow_dissect_fast_ipv4`:
```c
+	/* UDP-tunnel inner descents. */
+	if (iph->protocol == IPPROTO_UDP) {
+		switch (flow_dissect_fast_udp_tunnels(...)) {
+		case FAST_TUNNEL_DISSECTED:
+			return true;
+		case FAST_TUNNEL_DEFER:
+			return false;
+		case FAST_TUNNEL_NONE:
+			break;
+		}
+	}
+
 	return true;
```
This is after the ports are written. If the descent succeeds, the function returns true. The inner IP's addrs/ports have overwritten the outer's. If the descent defers (inner not fast-pathable), the function returns false, and the dispatcher falls through to the slow path. But wait - the outer IP's addrs and ports have already been written. The slow path would then re-dissect from scratch, overwriting everything. So no partial-write leak. Correct.

But the commit message for A10 (KUnit) says "A fast-path miss cannot leak partial writes to callers: flow_dissect_fast() is only invoked from __skb_flow_dissect(), which falls through to the full slow-path walk on the same container whenever the fast path returns false." And the test zeroes the containers before each dissection. So partial writes from a fast-path miss are overwritten by the slow path. Correct.

Wait, but for `FAST_TUNNEL_DEFER`, the fast path returns false. The outer IP's addrs and ports have been written. The slow path re-dissects from scratch, overwriting everything. So the partial writes are overwritten. The test's zeroed containers would catch any case where the slow path doesn't fully overwrite. Correct.

**Issue: Series B patch 02 (Geneve) - the sysctl doc is missing a blank line before "The ``/proc/net/flow_dissector_stats`` observability file" section.** Looking at the diff:
```rst
+Default: 0
 The ``/proc/net/flow_dissector_stats`` observability file
```
The `Default: 0` is the last line of the `geneve_inner` section, and the next line is the start of the observability file section. But there's no blank line between them. In RST, this might cause formatting issues. Let me check...

Actually, looking at the diff context, the `The ``/proc/net/flow_dissector_stats`` observability file` line was already there before this patch (it was added in A08). The new content is inserted before it. The RST formatting might be OK because the `Default: 0` line is followed by a section header (with `~~~~` underline). But looking at the raw text:
```rst
Default: 0
 The ``/proc/net/flow_dissector_stats`` observability file
 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
```
There's no blank line between `Default: 0` and the section header. In RST, section headers need a blank line before them. This could cause a formatting issue. But it might also work if the parser is lenient. This is a polish issue.

Wait, let me look more carefully at the diff. The existing text before the patch has:
```rst
Default: 0

The ``/proc/net/flow_dissector_stats`` observability file
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
```
With a blank line. After the Geneve patch, the new text is inserted:
```rst
Default: 0

geneve_inner
~~~~~~~~~~~~

...

Default: 0
The ``/proc/net/flow_dissector_stats`` observability file
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
```

Wait, the second `Default: 0` (from the geneve_inner section) is immediately followed by `The ``/proc/net/...`` line. Let me look at the diff more carefully:

```rst
+Default: 0
 The ``/proc/net/flow_dissector_stats`` observability file
```

The `+Default: 0` is the last line added by the Geneve patch. The next line (`The ``/proc/net/...``) is context (already exists). There's no blank line between them. This is indeed a formatting issue. The RST parser might not recognize the section header without a preceding blank line.

Actually, looking at it again, the original A08 patch added:
```rst
Default: 0

The ``/proc/net/flow_dissector_stats`` observability file
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
```
With a blank line. The Geneve patch inserts content before the blank line:
```rst
... (previous content)

Default: 0

geneve_inner
~~~~~~~~~~~~

...

Default: 0
The ``/proc/net/flow_dissector_stats`` observability file
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
```

Hmm, the diff shows:
```
+Default: 0
 The ``/proc/net/flow_dissector_stats`` observability file
```

The `+` prefix means `Default: 0` is added. The space prefix means `The ``/proc/net/...`` is context. But there's no `+` line for a blank line between them. So the blank line that was there before (between the old `Default: 0` and the section header) is now between the geneve section's `Default: 0` and the section header. Wait, no - the old `Default: 0` was for the `gre` section (or whatever came before). Let me look at the context more carefully.

Looking at the B02 diff:
```rst
@@ -615,6 +615,31 @@ the same descent), so the choice is only *whether* to descend, not
 
 Default: 0
 
+geneve_inner
+~~~~~~~~~~~~
+
+Descends into the Geneve inner Eth + IPv4/IPv6 + TCP/UDP flow for
...
+
+Default: 0
+
 The ``/proc/net/flow_dissector_stats`` observability file
 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
```

Wait, looking at the diff more carefully, the last added line is `+Default: 0`, and then there's a context line ` The ``/proc/net/...``. But there's also a `+` blank line before the context line? Let me re-read...

Actually, the diff shows:
```
+Default: 0
+
 The ``/proc/net/flow_dissector_stats`` observability file
```

No, wait, let me look at the raw diff again:
```rst
+Default: 0
+
 The ``/proc/net/flow_dissector_stats`` observability file
```

Hmm, I can't tell from the formatting whether there's a blank line. Let me look at the GTP-U patch's diff for comparison:

```rst
+Default: 0
+gtpu_inner
+~~~~~~~~~~
```

For GTP-U, there's no blank line between the previous `Default: 0` and the `gtpu_inner` header. That's also a potential formatting issue.

Wait, looking at the B03 diff:
```rst
@@ -640,6 +640,32 @@ L3-Geneve variants), and Geneve-over-IPv6 outer (only IPv4 outer is
 handled).
 
 Default: 0
+gtpu_inner
+~~~~~~~~~~
```

The `Default: 0` is context (no `+`), and `gtpu_inner` is added (with `+`). There's no blank line between them. In RST, this would cause the `gtpu_inner` header to not be recognized as a section header. This is a formatting bug.

Similarly for B02 (Geneve), looking at the diff:
```rst
@@ -594,6 +594,24 @@ GRE-with-KEY (common in MPLS-over-GRE deployments and some cloud
 overlays) is a follow-up patch — same descent shape with an
 additional 4-byte key field read and a write to
 ``FLOW_DISSECTOR_KEY_GRE_KEYID``.
+vxlan_inner
+~~~~~~~~~~~
```

Wait, that's the VXLAN section in B01, not Geneve. Let me look at B02's diff:

```rst
@@ -615,6 +615,31 @@ the same descent), so the choice is only *whether* to descend, not
 
 Default: 0
 
+geneve_inner
+~~~~~~~~~~~~
```

OK, for Geneve, there IS a blank line before the header. Good.

For GTP-U (B03):
```rst
@@ -640,6 +640,32 @@ L3-Geneve variants), and Geneve-over-IPv6 outer (only IPv4 outer is
 handled).
 
 Default: 0
+gtpu_inner
+~~~~~~~~~~
```

No blank line between `Default: 0` and `gtpu_inner`. This is an RST formatting issue.

And for the end of the GTP-U section:
```rst
+Default: 0
+
 The ``/proc/net/flow_dissector_stats`` observability file
```

There IS a blank line after the GTP-U `Default: 0`. So the issue is only at the beginning of the GTP-U section.

Similarly, let me check the FOU/GUE sections in B04:
```rst
@@ -666,6 +666,50 @@ over IPv6 outer.
 
 Default: 0
 
+gue_inner
+~~~~~~~~~
```

OK, there IS a blank line before `gue_inner`. And:
```rst
+Default: 0
+
+fou_inner
+~~~~~~~~~
```

There IS a blank line between `gue_inner`'s `Default: 0` and `fou_inner`. And:
```rst
+Default: 0
+
 The ``/proc/net/flow_dissector_stats`` observability file
```

There IS a blank line at the end. So B04 is fine.

So the only RST formatting issue is in B03 (GTP-U), where there's no blank line between the Geneve section's `Default: 0` and the `gtpu_inner` header.

Wait, let me also check B01 (VXLAN):
```rst
@@ -594,6 +594,24 @@ GRE-with-KEY (common in MPLS-over-GRE deployments and some cloud
 overlays) is a follow-up patch — same descent shape with an
 additional 4-byte key field read and a write to
 ``FLOW_DISSECTOR_KEY_GRE_KEYID``.
+vxlan_inner
+~~~~~~~~~~~
```

No blank line between `FLOW_DISSECTOR_KEY_GRE_KEYID``.` and `vxlan_inner`. The previous line ends with `.` and the next line is `vxlan_inner` with no blank line. In RST, section headers need a blank line before them. This is a formatting issue.

Wait, but looking at the context, the line before is:
```
``FLOW_DISSECTOR_KEY_GRE_KEYID``.
+vxlan_inner
```

The `.` is the end of the previous paragraph (the GRE section). Without a blank line, RST might not recognize `vxlan_inner` as a section header. This is a formatting issue in B01.

OK so I have RST formatting issues in B01 (VXLAN) and B03 (GTP-U) where section headers are not preceded by blank lines. These are polish issues.

Let me also check the series A sysctl docs. In A02:
```rst
+2. /proc/sys/net/flow_dissector - Flow dissector fast-path per-shape sysctls
+---------------------------------------------------------------------------
+
+The flow dissector is invoked on every packet that needs a flow hash
...
+
+eth_ip
+~~~~~~
+
+Eth + IPv4 (IHL=5, no fragmentation) + TCP/UDP, and Eth + IPv6 (no
...
+
+Default: 0
+
 3. /proc/sys/net/unix - Parameters for Unix domain sockets
```

This looks properly formatted. Good.

In A03 (VLAN/QinQ):
```rst
+Default: 0
+
+vlan
+~~~~
+
+Single 802.1Q or 802.1AD tagged frames over Eth + IPv4/IPv6 +
```

Properly formatted. Good.

In A04 (PPPoE):
```rst
+Default: 0
+
+pppoe
+~~~~~
+
+PPPoE session frames (RFC 2516, EtherType ``ETH_P_PPP_SES`` 0x8864)
```

Properly formatted. Good.

In A05 (MPLS):
```rst
+Default: 0
+
+mpls
+~~~~
+
+Single-label MPLS frames (EtherType ``ETH_P_MPLS_UC`` 0x8847 or
```

Properly formatted. Good.

In A06 (IPIP):
```rst
+Default: 0
+
+ipip
+~~~~
+
+IPv4-in-IPv4 (``IPPROTO_IPIP`` 4), IPv6-in-IPv4 (``IPPROTO_IPV6`` 41
```

Properly formatted. Good.

In A07 (GRE):
```rst
+Default: 0
+
+gre
+~~~
+
+GRE-encapsulated inner IP (``IPPROTO_GRE`` 47). The fast-path
```

Properly formatted. Good.

So the RST formatting issues are only in series B, patches B01 and B03.

Now let me also check: does the A08 sysctl doc addition have proper formatting?
```rst
+Default: 0
+
+The ``/proc/net/flow_dissector_stats`` observability file
+~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
```

Yes, proper blank line before the section header. Good.

**Let me now compile my findings.**

OK, let me also check one more thing: the cover letter for series A mentions "8 microarchitectures" but the performance table lists only 7 for "allshapes" and 7 for "isolated A/B" (with Haswell replacing Zen 1). The cover letter says "Measured across 3 ISAs and 8 microarchitectures in total" and "Two instruments, each run on 7 of the 8 microarchitectures." The testing section lists "x86 Zen1/Zen2/Skylake/Haswell, ARM Cortex-A53/A72/A76, RISC-V X60" which is 8 microarchitectures. This is consistent: 8 total, 7 per instrument (allshapes: Zen1/Zen2/Skylake + A53/A72/A76 + X60 = 7; isolated: Zen2/Skylake/Haswell + A53/A72/A76 + X60 = 7). Correct.

Let me also check: the cover letter says "53 tests" for the KUnit suite. The test file has:
- fd_fast_equiv_test: parametrized over fd_fast_cases (let me count... looking at the array, there are about 45 cases)
- fd_fast_truncation_test: 1
- fd_fast_deep_nest_test: 1
- fd_fast_nonlinear_skb_test: 1
- fd_fast_ineligible_dissector_test: 1
- fd_fast_skb_plain_test: 1
- fd_fast_skb_hwaccel_vlan_test: 1
- fd_fast_skb_hwaccel_vlan_qinq_test: 1
- fd_fast_skb_shapes_test: 1
- fd_fast_fuzz_test: 1
- fd_fast_gates_off_test: 1

That's 10 non-parametrized tests + 45 parametrized cases = 55. The cover letter says 53. Hmm, close but not exact. Let me count the fd_fast_cases more carefully...

Looking at the array:
1. ipv4_tcp
2. ipv4_udp
3. ipv6_tcp
4. ipv6_udp
5. vlan_ipv4_tcp
6. vlan_ipv6_udp
7. qinq_ipv4_tcp
8. pppoe_ipv4_tcp
9. pppoe_ipv6_tcp
10. mpls_ipv4
11. ipip
12. 6in4
13. 4in6
14. 4in6_flowlabel
15. 6in6
16. gre_ipv4
17. gre6_ipv4
18. ipv4_options_tcp
19. ipv4_frag_mf
20. ipv4_frag_mf_1stfrag
21. ipv4_frag_offset
22. ipv4_icmp
23. ipv6_hopopts_tcp
24. ipv6_flowlabel_tcp
25. vlan3_ipv4_tcp
26. pppoe_lcp
27. mpls_multi_label
28. gre_csum_ipv4
29. gre_seq_ipv4
30. gre_key_ipv4
31. gre_version1
32. gre_teb
33. ipv6_hopopts_dest_tcp
34. ipv6_frag_tcp
35. vlan_q_then_ad_ipv4
36. ipv4_options12_tcp
37. pppoe_pfc
38. ipv4_frag_mid
39. ipv4_frag_mid_1stfrag
40. gre_csum_key_ipv4
41. gre_csum_key_seq_ipv4
42. vlan_prio_ipv4_tcp
43. ipv6_routing_tcp

That's 43 parametrized cases + 10 non-parametrized = 53. OK, that matches the cover letter's "53 tests." Good.

Wait, but series B adds more tests. The B05 diff adds:
- fd_fast_gue_descend_test
- fd_fast_fou_descend_test
- fd_descent_vxlan_test
- fd_descent_geneve_test
- fd_descent_gtpu_test
- fd_descent_fou_gue_test
- fd_descent_nest_test
- fd_descent_stop_flags_test

That's 8 more tests. The series B cover letter doesn't claim a specific test count, so no issue.

Now let me also look for one more thing: does the A02 patch's sysctl doc mention "VXLAN inner descent"?

Looking at the A02 diff for the sysctl doc:
```rst
+The flow dissector is invoked on every packet that needs a flow hash
+(RPS, RFS, ECMP, sch_cake, cls_flower, ...). For common shapes
+(Eth+IPv4/IPv6+TCP/UDP, plus extensions for VLAN, QinQ and VXLAN
+inner descent added by follow-up patches in this series), an opt-in
+fast-path bypasses the slow-path graph walk and writes
+``struct flow_keys`` directly. Each shape is gated by its own static
+key + sysctl so operators enable only what their deployment uses.
```

Yes! It says "plus extensions for VLAN, QinQ and VXLAN inner descent added by follow-up patches in this series." But VXLAN inner descent is in series B, not series A. This is wrong. The parenthetical should say "VLAN, QinQ, PPPoE, MPLS, IP-in-IP, and GRE" or just "VLAN, QinQ and other extensions" without mentioning VXLAN.

This is a substantive finding: the A02 sysctl doc incorrectly claims VXLAN inner descent is in series A.

OK let me also look at one more potential issue. The A02 commit message says "This is the parent of the fast-path series. Subsequent patches add per-shape extensions for single VLAN, QinQ, PPPoE, MPLS, IP-in-IP and GRE." This is correct - no mention of VXLAN. So the commit message is fine, but the sysctl doc is wrong.

Now, let me also check: is the "companion series" reference in the A cover letter clear enough for a fresh reader?

The A cover letter says: "A companion series (posted separately) builds on this one to add opt-in inner-flow descent for the UDP tunnels (VXLAN, Geneve, GTP-U, FOU/GUE) -- that one changes hashing when enabled, so it is a separate policy discussion; this series is purely a transparent optimisation."

This is clear. The reader knows there's a companion series that changes behavior. Good.

The B cover letter says: "This series adds opt-in inner descent, each tunnel behind its own default-off gate (net.flow_dissector.{vxlan,geneve,gtpu,gue,fou}_inner): the dissector parses through the tunnel header and dissects the inner flow, for IPv4 and IPv6 underlays alike. Enabling a gate changes skb->hash for that traffic -- a deliberate, per-tunnel-type operator choice, which is why it is a separate series from the byte-identical fast-path series it builds on: [lore link]"

This is clear. Good.

Let me now organize all my findings by severity.

**BLOCKERS:**

I don't see any hard blockers that would cause data corruption or crashes. But let me double-check the recursion bound issue. The A09 patch adds the recursion bound. Before A09 (i.e., at patches A06 and A07), the fast-path tunnel helpers have no recursion bound. This means if you bisect to A06 or A07, a crafted deeply nested IPIP or GRE packet could cause a stack overflow. The cover letter mentions this: "A crafted frame with a deeply nested tunnel chain (IP-in-IP-in-IP-in-..., or GRE) therefore drives one C stack frame per ~20 bytes of linear header."

But A09 fixes this. The question is: is it acceptable to have a 2-patch window (A06-A08) where the recursion is unbounded? In a bisect, someone could land on A06 or A07 and have the vulnerability. But this is the same as any kernel patch series where a fix comes after the feature. The maintainer would merge the whole series, not individual patches.

Actually, looking at this more carefully, the cover letter for A09 says "The fast helpers had no such bound" before this patch. This means A06 and A07 introduce the vulnerability, and A09 fixes it. A reviewer might ask: should the bound be in A06 (the first tunnel descent patch) rather than A09? That would be cleaner. But it's not a blocker - it's a design choice in the patch ordering.

Actually, I think this is worth flagging as a substantive issue. The recursion bound should be in the same patch that introduces the recursion (A06), not three patches later (A09). As it stands, patches A06, A07, and A08 have a stack overflow vulnerability from crafted packets.

Wait, but A08 adds counters, not recursion. So the vulnerability window is A06-A08 (3 patches). A reviewer bisecting to A06, A07, or A08 would have the vulnerability. This is a substantive finding.

Hmm, but actually the KUnit test in A10 tests the bound. And the bound is in A09. So the test only passes after A09. If someone bisects to A06-A08, the test would fail (or rather, the deep-nest test case would fail without the bound). But the test is only added in A10, so at A06-A08 there's no test to fail.

I think this is worth mentioning as a substantive finding: the recursion bound (A09) is separated from the recursion introduction (A06/A07) by two patches (A07 adds GRE recursion, A08 adds counters). For bisectability and safety, the bound should be in A06 or at least before A07.

Actually wait, I realize the cover letter says "Patch 9 bounds the fast-path tunnel recursion at MAX_FLOW_DISSECT_HDRS." This is presented as a feature, not a fix. The cover letter's "Robustness and safety limits" section says "The fast path descends into IP-in-IP and GRE by recursion. The slow path bounds header descents at MAX_FLOW_DISSECT_HDRS; patch 9 gives the fast path the same bound." So the author is aware of the issue and has chosen to put the bound in a separate patch. A reviewer might disagree with this ordering.

Let me flag this as a substantive finding.

**SUBSTANTIVE:**

1. Recursion bound separated from recursion introduction (A06 introduces IPIP recursion, A07 adds GRE recursion, A09 adds the bound). Patches A06-A08 have an unbounded recursion vulnerability.

2. A02 sysctl doc incorrectly mentions "VXLAN inner descent" as being in this series. VXLAN is in series B.

3. B01 commit message and B cover letter incorrectly attribute RPS/RFS as callers of STOP_AT_ENCAP/STOP_BEFORE_ENCAP. RPS/RFS passes STOP_AT_FLOW_LABEL, which does NOT block the descent. RPS/RFS would actually get the inner flow.

4. B02 (Geneve) sysctl doc claims "Geneve-over-IPv6 outer (only IPv4 outer is handled)" but the code handles both outer families. The B05 test confirms IPv6 outer works.

5. B03 (GTP-U) sysctl doc claims "GTP-U over IPv6 outer" is kept out, but the code handles it. The B05 test confirms IPv6 outer works.

6. A05 (MPLS) commit message and sysctl doc reference "the v3-namespace series" which is undefined and confusing for a fresh reader.

**POLISH:**

1. B01 (VXLAN) sysctl doc: no blank line before the `vxlan_inner` section header in RST, which may cause formatting issues.

2. B03 (GTP-U) sysctl doc: no blank line before the `gtpu_inner` section header in RST.

3. A08 counter placement: IPIP and GRE occurrences are counted before the STOP_BEFORE_ENCAP check, inflating the "eligible fraction" for those shapes (minor observability inaccuracy).

Let me also think about whether there are any other issues...

Actually, I want to double-check one more thing about the B01 commit message. It says:

"Callers passing FLOW_DISSECTOR_F_STOP_{AT,BEFORE}_ENCAP (RPS/RFS, tunnel drivers) keep the outer tuple even with a gate on."

Let me re-examine this. The flags mentioned are STOP_AT_ENCAP and STOP_BEFORE_ENCAP. The parenthetical lists RPS/RFS and tunnel drivers. 

- RPS/RFS: uses `skb_get_hash()` which passes `FLOW_DISSECTOR_F_STOP_AT_FLOW_LABEL`. Does NOT pass STOP_AT_ENCAP or STOP_BEFORE_ENCAP.
- Tunnel drivers: some tunnel drivers pass STOP_BEFORE_ENCAP when they want the outer tuple for their own hashing.

So the parenthetical is wrong about RPS/RFS. RPS/RFS does NOT pass STOP_AT_ENCAP/STOP_BEFORE_ENCAP. The commit message should say something like "Callers passing FLOW_DISSECTOR_F_STOP_{AT,BEFORE}_ENCAP (tunnel drivers) keep the outer tuple" and separately note that RPS/RFS (which passes STOP_AT_FLOW_LABEL) DOES get the inner flow.

Actually, looking at the B05 test `fd_descent_stop_flags_test`, it tests STOP_AT_ENCAP and STOP_BEFORE_ENCAP, and asserts the outer tuple is kept. This is correct. But the commit message's attribution of RPS/RFS to these flags is wrong.

Hmm, I realize I should also check: does the B cover letter have the same issue? Let me re-read:

"Callers passing FLOW_DISSECTOR_F_STOP_{AT,BEFORE}_ENCAP (RPS/RFS, tunnel drivers) keep the outer tuple even with a gate on."

Yes, same issue in the cover letter. Both need fixing.

Wait, one more thought: maybe the author meant that RPS/RFS "keeps the outer tuple" in the sense that without the descent gate enabled, RPS/RFS sees the outer tuple. And with the gate enabled, RPS/RFS gets the inner tuple (because STOP_AT_FLOW_LABEL doesn't block the descent). So the claim "RPS/RFS keeps the outer tuple even with a gate on" would be wrong in that case. The claim is doubly wrong: RPS/RFS doesn't pass STOP_AT_ENCAP, and RPS/RFS would get the inner flow with the gate on.

Actually, maybe the author was thinking of a different flag. Let me check: does `skb_get_hash()` pass any encap-stop flag?

`skb_get_hash()` → `___skb_get_hash()`:
```c
__skb_flow_dissect(net, skb, &flow_keys_dissector,
                   &keys, NULL, 0, 0, 0,
                   FLOW_DISSECTOR_F_STOP_AT_FLOW_LABEL);
```

No STOP_AT_ENCAP or STOP_BEFORE_ENCAP. Just STOP_AT_FLOW_LABEL. So RPS/RFS would get the inner flow when a descent gate is enabled. The commit message is wrong.

Let me also check: does `fq_codel` or `cake` pass any encap-stop flags? These are mentioned in the cover letter as hash consumers. `fq_codel` uses `skb_get_hash()` which passes STOP_AT_FLOW_LABEL. `cake` also uses `skb_get_hash()`. So neither passes STOP_AT_ENCAP. The commit message's claim is wrong.

OK, I'm confident this is a substantive finding. The B01 commit message and B cover letter incorrectly group RPS/RFS with STOP_AT_ENCAP callers.

Now let me also check: are there any other claims in the commit messages that are wrong or unsupported?

**B01 commit message says "CPU is ~net-zero (the inner work cancels the outer fast-path saving)."** This is a reasonable claim - the fast path saves time on the outer parse but spends it on the inner parse. The net is approximately zero. This is supported by the reasoning, not by specific measurements. The cover letter says "CPU for the descents is ~net-zero" without providing numbers. This is acceptable for a cover letter but a reviewer might ask for specific measurements.

**B01 commit message says "Port discovery is hardcoded to IANA_VXLAN_UDP_PORT (4789); non-standard VXLAN ports (e.g. Cilium's 8472) are not descended."** This is accurate - the code checks `udp_ports[1] != htons(IANA_VXLAN_UDP_PORT)`. Correct.

**B04 commit message says "the built-in dissector reaches it through a registered struct flow_dissector_fou_ops (registered/unregistered by fou_core.c with a pr_warn if another owner already holds the hook, which switches its fou_list to the _rcu list helpers for the lockless walk)."** This is accurate per the code. Correct.

Let me also check: does the B04 commit message say "registration failure logs a pr_warn"? Looking at the code:
```c
if (flow_dissector_fou_ops_register(&fou_flow_ops))
    pr_warn("fou: flow dissector ops already registered, fou_inner/gue_inner descent unavailable\n");
```
Yes, a pr_warn is logged. But the commit message says "registration failure logs a pr_warn" - is the registration failure fatal? No, the fou init continues:
```c
if (flow_dissector_fou_ops_register(&fou_flow_ops))
    pr_warn("...");
return 0;
```
The init returns 0 (success) even if registration fails. The commit message says this in the "Best-effort" comment. Correct.

OK, I think I've done a thorough review. Let me also check one more thing: the A08 commit message says "exactly one of occurrences/fast_hits is incremented per shaped packet depending on gate state." Let me verify this for the eth_ip shape.

When the gate is OFF:
- Fast path returns false (dispatcher checks the static key, which is off).
- Slow path runs, reaches the out: label, and counts eth_ip as an occurrence.
- fast_hits is NOT incremented.
- So occurrences = 1, fast_hits = 0. Total = 1.

When the gate is ON and the packet matches:
- Fast path runs, succeeds, counts eth_ip as a fast_hit.
- Slow path does NOT run.
- So occurrences = 0, fast_hits = 1. Total = 1.

When the gate is ON and the packet does NOT match (e.g., IPv4 with options):
- Fast path runs, fails (returns false).
- Slow path runs, but the packet has IP options, so the slow path's IPv4 case would process it. Would it be counted as eth_ip? Let me check: `eth_ip_top` is set when `nhoff == nhoff_init` at the IPv4 case. But the IPv4 case would set `nhoff += iph->ihl * 4` (which is > 20 for options). Then the slow path would process the L4 protocol. At the out: label, `ip_proto` would be TCP/UDP, `eth_ip_top` would be true, but `key_control->flags` might not have ENCAP set. So the condition:
```c
if (ret && eth_ip_top &&
    !(key_control->flags & FLOW_DIS_ENCAPSULATION) &&
    (ip_proto == IPPROTO_TCP || ip_proto == IPPROTO_UDP))
    flow_dissector_count_slow(FLOW_DISSECTOR_SHAPE_ETH_IP);
```
Would this count a packet with IP options as eth_ip? Yes! The condition only checks TCP/UDP and not encap. It doesn't check IHL or fragmentation. So a packet with IP options + TCP would be counted as eth_ip in the slow path, even though the fast path would never handle it (the fast path checks `*(const u8 *)iph != FLOW_DIS_IPV4_VIHL_NOOPT`).

This means the "eligible fraction" for eth_ip is inflated by packets with IP options and fragments. The commit message says "occurrences[] a shape handled by the SLOW path." So by the definition, these are "shapes handled by the slow path" - they're top-level eth+IP+TCP/UDP, just with options or fragments. The "eligible fraction" would include these non-fast-pathable packets.

But the commit message also says "(occurrences + fast_hits) / dissects is a gate-invariant eligible fraction" and "how much traffic that shape's fast body would have handled." The fast body would NOT handle packets with IP options or fragments. So the "eligible fraction" is inflated. This is the same issue I noted for IPIP/GRE with STOP_BEFORE_ENCAP.

This is a minor observability inaccuracy. The operator might see a high "eligible%" for eth_ip but a low fast_hits rate after enabling the gate, because some of the "occurrences" are packets with options/fragments that the fast path can't handle. The counter measures "top-level eth+IP+TCP/UDP" not "packets the fast path can actually handle."

This is a polish issue, not a blocker. But it's worth mentioning.

Actually, I realize this could be confusing for operators. The `/proc/net/flow_dissector_stats` file shows "eligible%" which is meant to indicate "how much traffic each shape's fast body would handle." But for eth_ip, the eligible% includes packets with IP options and fragments that the fast body can't handle. The operator might enable the gate based on a high eligible% but not see the expected fast_hits rate.

This is a substantive finding, not just polish. The counter doesn't measure what it claims to measure for eth_ip.

Hmm, but let me re-read the commit message more carefully:

"occurrences[] a shape handled by the SLOW path. Measured while its gate is off, this is the eligible-fraction signal: how much traffic that shape's fast body *would* have handled."

The claim is that occurrences[] measures "how much traffic that shape's fast body would have handled." But for eth_ip, the occurrence is counted for ANY top-level eth+IP+TCP/UDP, including packets with options and fragments. The fast body would NOT handle those. So the claim is wrong for eth_ip.

Wait, actually, maybe I need to think about this differently. The "eligible fraction" is meant to be a signal for the operator (or the auto controller) to decide whether to enable the gate. If the operator sees a high eligible% for eth_ip, they enable the gate. With the gate on, the fast path handles the matching packets (no options, no fragments) and the slow path handles the rest. The fast_hits counter then shows how many packets the fast path actually handled. The operator can compare fast_hits to occurrences to see the hit rate.

But the "eligible%" as defined is (occurrences + fast_hits) / dissects. With the gate off, occurrences = all top-level eth+IP+TCP/UDP packets (including non-fast-pathable ones), and fast_hits = 0. So eligible% = occurrences / dissects. This overestimates the fast-pathable fraction.

With the gate on, occurrences = 0 (fast path handles the matching ones, slow path handles the non-matching ones, but the slow path's eth_ip counter at the out: label would still count non-fast-pathable eth+IP+TCP/UDP packets). Wait, no - with the gate on, the fast path runs first. If it matches, it returns true and the slow path doesn't run. If it doesn't match (options, fragments), the fast path returns false, and the slow path runs. The slow path would then count the packet as an occurrence at the out: label.

So with the gate on:
- fast_hits = fast-pathable eth+IP+TCP/UDP packets (no options, no fragments)
- occurrences = non-fast-pathable eth+IP+TCP/UDP packets (options, fragments)
- eligible% = (occurrences + fast_hits) / dissects = all eth+IP+TCP/UDP / dissects

The eligible% is the same with the gate on or off (gate-invariant), which is the intended property. But it overestimates the fast-pathable fraction.

The operator would need to look at fast_hits / (occurrences + fast_hits) to get the actual hit rate. But the stats file shows eligible% = (occurrences + fast_hits) / dissects, not the hit rate. The hit rate is not shown.

Hmm, but the commit message says "eligible% = (occurrences + fast_hits) / dissects -- the signal a policy layer thresholds against a per-shape break-even." If the policy layer uses eligible% to decide whether to enable the gate, it would overestimate the benefit for eth_ip. But the break-even model in the docs says "enabling the gate is net-positive once the fraction of traffic matching the shape exceeds the break-even p_be = C / (S + C)." The "fraction of traffic matching the shape" should be the fast-pathable fraction, not the eligible% (which includes non-fast-pathable packets).

This is a real discrepancy. The eligible% overestimates the matching fraction for eth_ip (and possibly other shapes). This could lead to suboptimal gate-enable decisions.

OK, I think this is worth flagging as a substantive finding. The counter claims to measure "how much traffic that shape's fast body would have handled" but it actually measures "how much traffic matches the shape's L3/L4 protocol pattern" which is a superset.

Actually, I want to be fair here. Let me re-read the commit message one more time:

"occurrences[] a shape handled by the SLOW path. Measured while its gate is off, this is the eligible-fraction signal: how much traffic that shape's fast body *would* have handled."

Hmm, "how much traffic that shape's fast body would have handled" - this is the claim. For eth_ip, the fast body handles eth+IPv4(IHL=5, no frag)+TCP/UDP and eth+IPv6(no ext, no flow label)+TCP/UDP. The occurrences counter counts ALL eth+IPv4/IPv6+TCP/UDP (including IHL>5, fragments, ext headers, non-zero flow labels). So the claim overestimates.

But wait - for VLAN, the occurrences counter counts VLAN-tagged packets at the VLAN dissection point. The fast body handles VLAN+eth+IPv4(IHL=5, no frag)+TCP/UDP. The occurrences counter counts ALL VLAN-tagged packets (including those with non-IP inner, non-TCP/UDP inner, etc.). Wait, no - looking at the code:

```c
if (dissector_vlan == FLOW_DISSECTOR_KEY_MAX) {
    dissector_vlan = FLOW_DISSECTOR_KEY_VLAN;
    flow_dissector_count_slow(FLOW_DISSECTOR_SHAPE_VLAN);
}
```

This counts ANY packet with at least one VLAN tag, regardless of the inner protocol. So the eligible% for VLAN would include all VLAN-tagged traffic, not just VLAN+IP+TCP/UDP. That's a much bigger overestimate.

Hmm, but the fast body for VLAN (`flow_dissect_fast_vlan`) handles VLAN+IP+TCP/UDP and QinQ+IP+TCP/UDP. It doesn't handle VLAN+non-IP or VLAN+ICMP. So the eligible% for VLAN would be significantly overestimated.

This is a more significant issue than I initially thought. The occurrences counter counts packets at the shape recognition point, not at the fast-path success point. For shapes like eth_ip, VLAN, and QinQ, the recognition point is much broader than the fast-pathable subset.

Let me re-read the commit message once more: "occurrences[] a shape handled by the SLOW path." - OK, it says "shape handled by the slow path." The "shape" for VLAN is "VLAN-tagged packet," not "VLAN+IP+TCP/UDP." So the counter is counting VLAN-tagged packets, which is the "shape" as seen by the slow path. The "eligible fraction" is then "what fraction of traffic is VLAN-tagged," not "what fraction of traffic the VLAN fast body would handle."

But the commit message also says "how much traffic that shape's fast body *would* have handled." This is the wrong claim. The fast body would handle only the subset with IP+TCP/UDP inside, not all VLAN-tagged packets.

Actually, I think I need to be more careful about what "shape" means. The sysctl doc says "vlan: Single 802.1Q or 802.1AD tagged frames over Eth + IPv4/IPv6 + TCP/UDP." So the "shape" is VLAN+IP+TCP/UDP, not just VLAN. But the counter counts all VLAN-tagged packets, not just VLAN+IP+TCP/UDP. So the counter doesn't match the "shape" definition.

Hmm, but maybe I'm wrong. Let me look at the slow-path counting for VLAN more carefully:

```c
case htons(ETH_P_8021Q):
case htons(ETH_P_8021AD):
    if (dissector_vlan == FLOW_DISSECTOR_KEY_MAX) {
        dissector_vlan = FLOW_DISSECTOR_KEY_VLAN;
        flow_dissector_count_slow(FLOW_DISSECTOR_SHAPE_VLAN);
    } else if (dissector_vlan == FLOW_DISSECTOR_KEY_VLAN) {
        dissector_vlan = FLOW_DISSECTOR_KEY_CVLAN;
        flow_dissector_count_slow(FLOW_DISSECTOR_SHAPE_QINQ);
    }
```

This counts any packet with a VLAN tag, regardless of the inner protocol. If the inner is not IP, the slow path would continue processing (e.g., VLAN+ARP would be counted as VLAN). But the fast path would NOT handle VLAN+ARP (it only handles VLAN+IP+TCP/UDP).

So the occurrences counter for VLAN overestimates the fast-pathable fraction. Same for QinQ, PPPoE (counts all PPPoE, not just PPPoE+IP+TCP/UDP), and MPLS (counts all MPLS, not just single-label BoS MPLS).

Wait, let me check PPPoE:
```c
case htons(ETH_P_PPP_SES):
    flow_dissector_count_slow(FLOW_DISSECTOR_SHAPE_PPPOE);
```
This counts ALL PPPoE session frames, not just PPPoE+IP+TCP/UDP. The fast body only handles PPPoE+IP/IPv6+TCP/UDP. So the occurrence counter overestimates.

And MPLS:
```c
case htons(ETH_P_MPLS_UC):
case htons(ETH_P_MPLS_MC):
    flow_dissector_count_slow(FLOW_DISSECTOR_SHAPE_MPLS);
```
This counts ALL MPLS packets, not just single-label BoS MPLS. The fast body only handles single-label BoS MPLS. So the occurrence counter overestimates.

And IPIP:
```c
case IPPROTO_IPIP:
    flow_dissector_count_slow(FLOW_DISSECTOR_SHAPE_IPIP);
```
This counts ALL IPIP packets, including those with options, fragments, etc. The fast body only handles IPIP with IHL=5, no fragments. So the occurrence counter overestimates.

And GRE:
```c
case IPPROTO_GRE:
    flow_dissector_count_slow(FLOW_DISSECTOR_SHAPE_GRE);
```
This counts ALL GRE packets, including those with flags, v1, non-IP inner. The fast body only handles plain GRE (v0, no flags, IP inner). So the occurrence counter overestimates.

So the issue is systemic: the occurrences counter counts ALL packets matching the shape's L2/L3 protocol, not just the subset the fast body can handle. The "eligible%" is consistently overestimated.

The commit message's claim "how much traffic that shape's fast body *would* have handled" is wrong for all shapes except eth_ip (where it's only slightly overestimated by options/fragments) - actually no, it's overestimated for eth_ip too.

Wait, but for eth_ip, the counting at the out: label checks:
```c
if (ret && eth_ip_top &&
    !(key_control->flags & FLOW_DIS_ENCAPSULATION) &&
    (ip_proto == IPPROTO_TCP || ip_proto == IPPROTO_UDP))
    flow_dissector_count_slow(FLOW_DISSECTOR_SHAPE_ETH_IP);
```

This checks for TCP/UDP but doesn't check for IHL=5 or no fragments. So it counts eth+IP+TCP/UDP with options and fragments too. The fast body only handles IHL=5, no fragments. So the occurrence counter overestimates for eth_ip.

OK so this is a systemic issue. The "eligible%" overestimates the fast-pathable fraction for every shape. The commit message's claim is wrong.

But is this really a "blocker"? No, it's an observability inaccuracy. The operator would still see a non-zero eligible% for shapes they care about, and enabling the gate would still help. The fast_hits counter would show the actual hit rate. The operator can compare fast_hits to occurrences to see the match rate. But the "eligible%" as presented is misleading.

I'll flag this as a substantive finding.

Let me also look for any other issues...

One more thing: the A08 commit message says "Because the fast path returns before the slow-path classification, exactly one of occurrences/fast_hits is incremented per shaped packet depending on gate state."

Is this true? Let me think about a VLAN+IP+TCP packet:
- With gate off: Fast path returns false (vlan key off). Slow path runs, counts VLAN at the VLAN dissection point. Slow path continues, reaches out:, and checks eth_ip conditions. But `eth_ip_top` is false (because nhoff != nhoff_init after the VLAN tag). So eth_ip is NOT counted. Only VLAN is counted. Good - exactly one occurrence.

- With gate on and matching: Fast path runs, counts VLAN as fast_hit. Returns true. Slow path doesn't run. So fast_hits[VLAN] = 1, occurrences[VLAN] = 0. Exactly one.

- With gate on and not matching (e.g., VLAN+ARP): Fast path runs, `flow_dissect_fast_vlan` processes the VLAN tag, dispatches to the inner ethertype. ARP is not IP, so the switch falls through to `default: return false`. `flow_dissect_fast_vlan` returns false (ok = false), so fast_hits is NOT incremented. The dispatcher returns false. Slow path runs, counts VLAN at the VLAN dissection point. So occurrences[VLAN] = 1. Exactly one.

OK, so "exactly one of occurrences/fast_hits is incremented per shaped packet" is correct. But the "eligible%" still overestimates because the occurrences counter counts packets that the fast body can't handle (like VLAN+ARP).

Wait, but is VLAN+ARP a "VLAN shape"? The sysctl doc says "vlan: Single 802.1Q or 802.1AD tagged frames over Eth + IPv4/IPv6 + TCP/UDP." So VLAN+ARP is NOT a VLAN shape by this definition. But the counter counts it as a VLAN occurrence. So the counter is counting non-shape packets as shape occurrences.

This confirms the issue: the occurrences counter counts at the protocol recognition point, not at the shape-eligible point. The "eligible%" includes non-eligible packets.

OK, I think I've been thorough enough. Let me finalize my findings.

Actually, let me reconsider the severity of the counter issue. The commit message says:

"Add per-cpu counters, keyed by a small enum flow_dissector_shape covering the byte-identical shapes (eth_ip, vlan, qinq, pppoe, mpls, ipip, gre):

  occurrences[]  a shape handled by the SLOW path. Measured while its gate is off, this is the eligible-fraction signal: how much traffic that shape's fast body *would* have handled."

The claim "how much traffic that shape's fast body would have handled" is wrong. The counter counts packets at the protocol recognition point, which is broader than the fast-pathable subset. For VLAN, it counts ALL VLAN-tagged packets (including VLAN+ARP, VLAN+ICMP, etc.), not just VLAN+IP+TCP/UDP.

This is a substantive claim that doesn't match what the code does. It could mislead operators or an auto-controller into overestimating the benefit of enabling a gate.

However, I should note that the counter is still useful as an upper bound. The actual fast-pathable fraction is fast_hits / dissects (with the gate on), which is always <= eligible%. So the eligible% is an overestimate, not an underestimate. An operator who enables a gate based on a high eligible% would still see a benefit, just potentially less than expected.

I'll flag this as a substantive finding.

Let me also quickly check: does the A08 commit message's claim about the `dissects` counter match the code? "dissects: total dissects — the denominator." The code:
```c
this_cpu_inc(flow_dissector_pcpu_stats.dissects);
```
This is placed before `flow_dissect_fast()` and after the BPF hook. So it counts all dissects that reach the in-kernel dissector (not those handled by BPF). The commit message says "Dissects fully handled by an attached netns BPF flow dissector program are deliberately not counted." Correct.

OK, let me finalize. Let me also check if there's a missing `Default: 0` for the VXLAN sysctl entry in B01. Looking at the B01 sysctl doc:

```rst
+vxlan_inner
+~~~~~~~~~~~
+
+Descends into the VXLAN inner Eth + IPv4/IPv6 + TCP/UDP flow for
+hashing when the outer matches Eth + IPv4/IPv6 + UDP with dst port
+IANA_VXLAN_UDP_PORT (4789). When enabled, the inner 5-tuple replaces
+the outer one in struct flow_keys, and key_control->flags gets
+FLOW_DIS_ENCAPSULATION set.
+
+**Enabling this changes hashing** for VXLAN traffic: the dissector
+stops at the outer UDP header by default, so descending gives k8s
+overlays per-inner-flow fairness in cake / fq / fib_multipath / RPS.
+Because it changes the hash, it is off by default and gated
+independently of the byte-identical fast-path knobs. Once on it is
+byte-identical between the fast and slow paths (the slow path grows
+the same descent), so the choice is only *whether* to descend, not
+*which* path ran. Port discovery is hardcoded to IANA_VXLAN_UDP_PORT
+(4789); non-standard VXLAN ports are not descended.
 
 Default: 0
```

The `Default: 0` is the existing line after the new content (it was the default for the `gre` section). So the VXLAN section reuses the existing `Default: 0` line. This works but is a bit fragile - if someone inserts content between the VXLAN section and the `Default: 0`, it would be confusing. Not a real issue though.

Wait, actually, looking at the diff context:
```rst
 additional 4-byte key field read and a write to
 ``FLOW_DISSECTOR_KEY_GRE_KEYID``.
+vxlan_inner
+~~~~~~~~~~~
+
+...
+(4789); non-standard VXLAN ports are not descended.
 
 Default: 0
```

The `Default: 0` with a space prefix is context (already exists). It was the default for the `gre` section. Now it serves as the default for the `vxlan_inner` section. But the `gre` section no longer has its own `Default: 0` - or does it? Let me look at the full context...

Actually, the `gre` section was added in A07, which includes:
```rst
+gre
+~~~
+
+...
+
+Default: 0
+
 3. /proc/sys/net/unix - Parameters for Unix domain sockets
```

So the `gre` section has its own `Default: 0` followed by a blank line and the unix section. The B01 diff inserts the `vxlan_inner` section between the `gre` section's text and its `Default: 0`. Wait, no - let me look at the B01 diff context more carefully:

```rst
@@ -594,6 +594,24 @@ GRE-with-KEY (common in MPLS-over-GRE deployments and some cloud
 overlays) is a follow-up patch — same descent shape with an
 additional 4-byte key field read and a write to
 ``FLOW_DISSECTOR_KEY_GRE_KEYID``.
+vxlan_inner
+~~~~~~~~~~~
+
+Descends into the VXLAN inner Eth + IPv4/IPv6 + TCP/UDP flow for
+hashing when the outer matches Eth + IPv4/IPv6 + UDP with dst port
+IANA_VXLAN_UDP_PORT (4789). When enabled, the inner 5-tuple replaces
+the outer one in struct flow_keys, and key_control->flags gets
+FLOW_DIS_ENCAPSULATION set.
+
+**Enabling this changes hashing** for VXLAN traffic: the dissector
+stops at the outer UDP header by default, so descending gives k8s
+overlays per-inner-flow fairness in cake / fq / fib_multipath / RPS.
+Because it changes the hash, it is off by default and gated
+independently of the byte-identical fast-path knobs. Once on it is
+byte-identical between the fast and slow paths (the slow path grows
+the same descent), so the choice is only *whether* to descend, not
+*which* path ran. Port discovery is hardcoded to IANA_VXLAN_UDP_PORT
+(4789); non-standard VXLAN ports are not descended.
 
 Default: 0
```

The context line ` Default: 0` (with a space prefix) was originally the `gre` section's default. Now it's being repurposed as the `vxlan_inner` section's default. But what about the `gre` section? Looking at the A07 diff:

```rst
+gre
+~~~
+
+GRE-encapsulated inner IP (``IPPROTO_GRE`` 47). The fast-path
+mirrors the slow path's __skb_flow_dissect_gre() descent for the
+common subset:
+
+- GRE version 0 (the v1 PPTP variant defers to slow path)
+- All GRE flags clear (no GRE_CSUM, GRE_KEY, GRE_SEQ, GRE_ROUTING —
+  i.e. plain 4-byte GRE base header)
+- protocol field is ``ETH_P_IP`` 0x0800 or ``ETH_P_IPV6`` 0x86DD
+  (no Transparent Ethernet Bridging, no PPP-over-GRE, no MPLS-
+  over-GRE)
+
+In that subset, slow path also descends to inner IP and stamps
+``key_control->flags |= FLOW_DIS_ENCAPSULATION``; the fast-path
+produces the same output.
+
+GRE-with-KEY (common in MPLS-over-GRE deployments and some cloud
+overlays) is a follow-up patch — same descent shape with an
+additional 4-byte key field read and a write to
+``FLOW_DISSECTOR_KEY_GRE_KEYID``.
+
+Default: 0
+
 3. /proc/sys/net/unix - Parameters for Unix domain sockets
```

So the `gre` section has its own `Default: 0` followed by a blank line. The B01 diff inserts `vxlan_inner` between the `gre` section's text (ending with `FLOW_DISSECTOR_KEY_GRE_KEYID``.`) and the `gre` section's `Default: 0`. Wait, that means the `gre` section now doesn't have a `Default: 0` - it's been repurposed for `vxlan_inner`!

No wait, let me re-read the B01 diff. The context line before the insertion is:
```
 ``FLOW_DISSECTOR_KEY_GRE_KEYID``.
```
And the context line after the insertion is:
```
 
 Default: 0
```

So the structure before B01 is:
```
...FLOW_DISSECTOR_KEY_GRE_KEYID`.

Default: 0

3. /proc/sys/net/unix...
```

And after B01:
```
...FLOW_DISSECTOR_KEY_GRE_KEYID`.
vxlan_inner
~~~~~~~~~~~

...

(4789); non-standard VXLAN ports are not descended.

Default: 0

3. /proc/sys/net/unix...
```

So the `Default: 0` now applies to `vxlan_inner`, not to `gre`. The `gre` section no longer has a `Default: 0`! This is a documentation bug introduced by B01.

Wait, but maybe the `gre` section's `Default: 0` was on a separate line. Let me look at the A07 diff again:

```rst
+``FLOW_DISSECTOR_KEY_GRE_KEYID``.
+
+Default: 0
+
 3. /proc/sys/net/unix - Parameters for Unix domain sockets
```

So the structure after A07 is:
```
...FLOW_DISSECTOR_KEY_GRE_KEYID`.

Default: 0

3. /proc/sys/net/unix...
```

The `Default: 0` is between the `gre` section text and the unix section. After B01 inserts the `vxlan_inner` section:
```
...FLOW_DISSECTOR_KEY_GRE_KEYID`.
vxlan_inner
~~~~~~~~~~~

...

(4789); non-standard VXLAN ports are not descended.

Default: 0

3. /proc/sys/net/unix...
```

Now the `Default: 0` appears after the `vxlan_inner` section, not after the `gre` section. The `gre` section has lost its `Default: 0`. The RST rendering would show:

```
gre
~~~
...
FLOW_DISSECTOR_KEY_GRE_KEYID`.

vxlan_inner
~~~~~~~~~~~
...

Default: 0
```

So the `Default: 0` would appear to belong to `vxlan_inner`, and `gre` would not have a `Default: 0` shown. This is a documentation bug.

Actually, wait. In RST, `Default: 0` is just a paragraph, not a section header. It would be rendered as regular text. The `gre` section would end at the `vxlan_inner` section header (if recognized) or would merge with the following text. Given the missing blank line before `vxlan_inner`, the RST parser might not recognize it as a section header, and everything would merge into one big paragraph under `gre`. That would be really confusing.

So the B01 sysctl doc has two issues:
1. No blank line before `vxlan_inner` section header (RST formatting)
2. The `gre` section loses its `Default: 0` (it's repurposed for `vxlan_inner`)

Actually, wait. Let me reconsider. The `Default: 0` line after the `vxlan_inner` section text could be interpreted as belonging to either `gre` or `vxlan_inner` depending on the RST structure. Without a clear section break (blank line + header), the parser might merge everything. With a proper section break, `Default: 0` would belong to `vxlan_inner`, and `gre` would lose its default.

Either way, it's a documentation issue. Let me flag it.

Actually, I realize I should also check: does the same issue exist for the other descent sysctl docs? Let me check B02 (Geneve):

The B02 diff inserts `geneve_inner` after `vxlan_inner`'s `Default: 0`:

Wait, no. Let me look at the B02 diff context:

```rst
@@ -615,6 +615,31 @@ the same descent), so the choice is only *whether* to descend, not
 
 Default: 0
 
+geneve_inner
```

The context before the insertion is `Default: 0` followed by a blank line. This `Default: 0` is the one that was originally for `gre` (and now serves as `vxlan_inner`'s default after B01). The B02 diff inserts `geneve_inner` after the blank line. So:

After B02:
```
...vxlan_inner text...

Default: 0

geneve_inner
~~~~~~~~~~~~

...

Default: 0

The ``/proc/net/...`` file
```

So the first `Default: 0` serves `vxlan_inner`, and the second `Default: 0` (added by B02) serves `geneve_inner`. But `gre` still doesn't have its own `Default: 0`.

Hmm, actually, I need to think about this differently. The `Default: 0` that was originally for `gre` is now serving as `vxlan_inner`'s default. `gre` has lost its default. But looking at the A07 diff, the `gre` section ends with:
```
+``FLOW_DISSECTOR_KEY_GRE_KEYID``.
+
+Default: 0
+
```

So after A07, the structure is:
```
gre section text.

Default: 0

(unix section)
```

After B01 inserts `vxlan_inner` between the `gre` text and `Default: 0`:
```
gre section text.
vxlan_inner section text.

Default: 0

(unix section)
```

Now `Default: 0` is after `vxlan_inner`, not after `gre`. `gre` has no `Default: 0`.

After B02 inserts `geneve_inner`:
```
gre section text.
vxlan_inner section text.

Default: 0

geneve_inner section text.

Default: 0

(observability file section)
```

Now `gre` has no `Default: 0`, and the first `Default: 0` is for `vxlan_inner`. The `gre` section's default is lost.

This is a real documentation bug introduced by B01. The fix would be to add a `Default: 0` for `gre` before the `vxlan_inner` section, or to restructure the sections.

OK wait, I need to be even more careful. Let me trace the exact line positions.

After A07 (which adds the `gre` section), the sysctl doc looks like:
```
...previous content...

gre
~~~

GRE-encapsulated inner IP...

...FLOW_DISSECTOR_KEY_GRE_KEYID``.

Default: 0

3. /proc/sys/net/unix...
```

After A08 (which adds the observability file section), it looks like:
```
...previous content...

gre
~~~

GRE-encapsulated inner IP...

...FLOW_DISSECTOR_KEY_GRE_KEYID``.

Default: 0

The ``/proc/net/flow_dissector_stats`` observability file
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

...observability text...

3. /proc/sys/net/unix...
```

After B01 (which adds `vxlan_inner`), the diff inserts the `vxlan_inner` section between `FLOW_DISSECTOR_KEY_GRE_KEYID``.` and the blank line before `Default: 0`:
```
...previous content...

gre
~~~

GRE-encapsulated inner IP...

...FLOW_DISSECTOR_KEY_GRE_KEYID``.
vxlan_inner
~~~~~~~~~~~

...vxlan_inner text...

Default: 0

The ``/proc/net/flow_dissector_stats`` observability file
...
```

Wait, but the B01 diff shows:
```rst
 ``FLOW_DISSECTOR_KEY_GRE_KEYID``.
+vxlan_inner
+~~~~~~~~~~~
+
+...vxlan_inner text...
+(4789); non-standard VXLAN ports are not descended.
 
 Default: 0
```

The `Default: 0` with a space prefix is context (already exists). The blank line before `Default: 0` is also context. So after B01:
```
...FLOW_DISSECTOR_KEY_GRE_KEYID``.
vxlan_inner
~~~~~~~~~~~

...vxlan_inner text...

Default: 0

The ``/proc/net/...`` file
```

So `gre`'s text is immediately followed by `vxlan_inner`'s header (no blank line), then `vxlan_inner`'s text, then `Default: 0`. The `Default: 0` now appears to belong to `vxlan_inner`, not `gre`.

In RST, without a blank line before `vxlan_inner`, the parser might treat it as part of the `gre` section's text. The rendered output would be something like:

```
gre
~~~
GRE-encapsulated inner IP...
...FLOW_DISSECTOR_KEY_GRE_KEYID`.
vxlan_inner ~~~~~~~~~~~ ...vxlan_inner text... Default: 0
```

All merged into one paragraph under `gre`. That's clearly wrong.

So the B01 sysctl doc has two issues:
1. No blank line before `vxlan_inner` (RST formatting - the section header won't be recognized)
2. `gre` loses its `Default: 0` (it's now associated with `vxlan_inner` or merged text)

These are both polish/substantive issues.

OK, I think I've been thorough enough. Let me also quickly check if the B04 (FOU/GUE) sysctl docs have the same `Default: 0` issue.

B04 adds `gue_inner` and `fou_inner`:
```rst
@@ -666,6 +666,50 @@ over IPv6 outer.
 
 Default: 0
 
+gue_inner
+~~~~~~~~~
+
+...gue text...
+
+Default: 0
+
+fou_inner
+~~~~~~~~~
+
+...fou text...
+
+Default: 0
+
 The ``/proc/net/flow_dissector_stats`` observability file
```

Here, `gue_inner` is preceded by a blank line (good), has its own `Default: 0` (good), and `fou_inner` is preceded by a blank line (good) and has its own `Default: 0` (good). So B04 is properly formatted.

But what about the `Default: 0` before `gue_inner`? Looking at the context:
```
 over IPv6 outer.
 
 Default: 0
 
+gue_inner
```

The `Default: 0` is for the `gtpu_inner` section (added in B03). After B04, it still serves as `gtpu_inner`'s default. Good.

But wait - B03 (GTP-U) had the formatting issue where `gtpu_inner` was not preceded by a blank line:
```rst
 Default: 0
+gtpu_inner
+~~~~~~~~~~
```

So `gtpu_inner`'s header might not be recognized, and the `Default: 0` before it (which was for `geneve_inner`) might be merged with `gtpu_inner`'s text. And then the `Default: 0` after `gtpu_inner`'s text (added in B03) would serve as... what? It's ambiguous.

OK, this is getting complicated. Let me just summarize the RST formatting issues:

1. B01: No blank line before `vxlan_inner` header → header not recognized, `gre` loses its `Default: 0`
2. B03: No blank line before `gtpu_inner` header → header not recognized

These are both polish issues that would cause the sysctl documentation to render incorrectly.

OK, let me also check one more thing I missed. In the A08 counters patch, the commit message says:

"Placement mirrors the two paths precisely: the slow counts sit at each protocol's dissection point -- for eth_ip that is the out: exit label, taken only on a top-level, non-encapsulated, TCP/UDP terminal, so a packet counted as VLAN/IPIP/GRE is never also counted as eth_ip"

But as I analyzed, the `eth_ip_top` check at the out: label checks `nhoff == nhoff_init`, which is true for the first IP header at the initial nhoff. But what about a packet like eth+IP+TCP where the IP has IHL=5 and no fragmentation? The slow path would: process IPv4 (eth_ip_top = true), set ip_proto = TCP, reach the out: label, and count eth_ip. Good.

But what about eth+IP+UDP where the IP has IHL=5? Same thing - counted as eth_ip. Good.

What about eth+VLAN+IP+TCP? The slow path would: process VLAN (count VLAN), re-enter proto_again, process IPv4 (nhoff != nhoff_init, eth_ip_top = false), reach out:, NOT count eth_ip. Good - only counted as VLAN.

What about eth+IP+IP (IPIP)? The slow path would: process outer IPv4 (eth_ip_top = true), process IPIP (count IPIP), re-enter proto_again, process inner IPv4 (nhoff != nhoff_init, eth_ip_top stays true from outer), reach out:, check `!(key_control->flags & FLOW_DIS_ENCAPSULATION)` - ENCAP is set, so NOT count eth_ip. Good - only counted as IPIP.

OK, the eth_ip counting looks correct for not double-counting with other shapes. The issue is just that it counts non-fast-pathable eth+IP+TCP/UDP packets (with options/fragments) as eth_ip occurrences.

Let me finalize my findings now.

Actually, one more thing: let me check the claim in the B01 commit message about "two mechanical enablers ride along." It says:

"Two mechanical enablers ride along: MAX_FLOW_DISSECT_HDRS moves above the fast-path helpers so the shared flow_dissect_fast_udp_inner() tail can use it, and the recursion helpers' inner_eth_proto parameter is renamed inner_proto (the GTP-U descent later in the series passes a bare IP protocol, not an ethertype)."

The MAX_FLOW_DISSECT_HDRS move is verified in the diff. The `inner_eth_proto` → `inner_proto` rename is also verified. Both are mechanical changes. Correct.

But wait - the rename touches `flow_dissect_fast_ipip_inner` and `flow_dissect_fast_pppoe`, which are from series A. This is a modification of series A code in series B. Is this OK? Yes - series B builds on top of series A, so modifying series A code is expected. Not a finding.

OK, one final check. The B01 commit message says:

"flow_dissect_fast_ipv4() / flow_dissect_fast_ipv6() descend when the outer is eth + IPv4/IPv6 + UDP (the VXLAN header does not vary with the outer family, so both underlays descend the same way)"

Looking at the code, the descent is added inside `flow_dissect_fast_ipv4` and `flow_dissect_fast_ipv6` after the ports are written:
```c
if (iph->protocol == IPPROTO_UDP) {
    switch (flow_dissect_fast_udp_tunnels(skb, flow_dissector,
                                          target_container, data,
                                          thoff, hlen, num_hdrs,
                                          AF_INET)) {
    ...
    }
}
```

And similarly for IPv6 with `AF_INET6`. The `family` parameter is passed to `flow_dissect_fast_udp_tunnels` but only used by FOU/GUE (in B04). For VXLAN, the classifier doesn't use the family. So both underlays (IPv4 and IPv6) descend the same way for VXLAN. Correct.

OK, I'm confident I've done a thorough review. Let me write up my findings.

Let me also look at the A08 commit message's claim about "exactly one of occurrences/fast_hits is incremented per shaped packet" once more. I want to check if there's a double-counting issue for QinQ packets in the fast path.

For a QinQ+IP+TCP packet with the qinq gate on:
1. `flow_dissect_fast` is called, dispatches to `flow_dissect_fast_vlan` with vlan_depth=0.
2. `flow_dissect_fast_vlan` (depth 0): processes outer tag, recurses with vlan_depth=1.
3. `flow_dissect_fast_vlan` (depth 1): processes inner tag, dispatches to `flow_dissect_fast_ipv4`.
4. `flow_dissect_fast_ipv4` succeeds, returns true.
5. Back in `flow_dissect_fast_vlan` (depth 1): `ok = true`, counts `FLOW_DISSECTOR_SHAPE_QINQ` (vlan_depth == 1). Returns true.
6. Back in `flow_dissect_fast_vlan` (depth 0): `ok = true`, counts `FLOW_DISSECTOR_SHAPE_VLAN` (vlan_depth == 0). Returns true.
7. Back in `flow_dissect_fast`: returns true.

So fast_hits[VLAN] = 1 AND fast_hits[QINQ] = 1. That's TWO fast_hits for one packet. The commit message says "exactly one of occurrences/fast_hits is incremented per shaped packet." But for QinQ, TWO fast_hits are incremented (VLAN and QINQ). This contradicts the claim.

Wait, but the commit message also says "a double-tagged hit counts both, as the slow path does." So the double-counting is intentional and mirrors the slow path. The slow path also counts both VLAN and QINQ for a QinQ packet. So "exactly one" is wrong - it should be "exactly one per shape" or "the same set of shapes is counted on both paths."

Actually, re-reading the commit message: "exactly one of occurrences/fast_hits is incremented per shaped packet depending on gate state." This could be interpreted as "for each shape, exactly one of occurrences or fast_hits is incremented." For VLAN shape: either occurrences or fast_hits is 1 (not both). For QINQ shape: either occurrences or fast_hits is 1 (not both). So for a QinQ packet, VLAN gets one count and QINQ gets one count, but each shape gets exactly one count (either slow or fast, not both). That interpretation is correct.

But the literal reading "exactly one of occurrences/fast_hits is incremented per shaped packet" suggests one total count per packet, which is wrong for QinQ (two counts). The wording is ambiguous.

Actually, I think the intended meaning is: "for each shape, exactly one of occurrences[shape] or fast_hits[shape] is incremented per packet that matches that shape." For a QinQ packet, it matches both VLAN and QINQ shapes, so VLAN gets one count and QINQ gets one count. That's correct.

But the wording "per shaped packet" is ambiguous. It could mean "per packet that matches a shape" (one count total) or "per shape per packet" (one count per matching shape). The latter is correct.

This is a minor wording issue, not a substantive finding. I'll skip it.

OK, let me finalize my findings now. I'll organize them by severity.

Hmm, actually I realize I should double-check one more thing. The A09 patch (recursion bound) modifies the function signatures of `flow_dissect_fast_ipv4`, `flow_dissect_fast_ipv6`, `flow_dissect_fast_ipip_inner`, `flow_dissect_fast_gre_inner`, `flow_dissect_fast_vlan`, `flow_dissect_fast_pppoe`, and `flow_dissect_fast` to add the `num_hdrs` parameter. Does this break any callers?

Looking at the A09 diff:
- `flow_dissect_fast_ipv4` and `flow_dissect_fast_ipv6` get `num_hdrs` parameter.
- `flow_dissect_fast_ipip_inner` gets `num_hdrs`, increments and checks it.
- `flow_dissect_fast_gre_inner` gets `num_hdrs`, increments and checks it.
- `flow_dissect_fast_vlan` passes `vlan_depth + 2` to the IP helpers.
- `flow_dissect_fast_pppoe` passes `2` to the IP helpers.
- `flow_dissect_fast` passes `1` to the IP helpers.

All callers are updated. No missing updates. Bisects clean.

But wait - the forward declarations at the top of the file also need to be updated. Looking at the A09 diff:
```c
-/* Fast-path helper forward declarations. */
+/* @num_hdrs: protocol headers consumed so far (Ethernet = 1, each VLAN
+ * tag, each outer IP header). Tunnel descents increment it and defer
+ * past MAX_FLOW_DISSECT_HDRS, so both paths stop at the same depth.
+ */
 static bool flow_dissect_fast_ipv4(const struct sk_buff *skb,
 				   struct flow_dissector *flow_dissector,
 				   void *target_container,
 				   const void *data,
-				   int nhoff, int hlen);
+				   int nhoff, int hlen, int num_hdrs);
```

Yes, the forward declarations are updated. Good.

OK, I'm done. Let me write up the findings.

One more thing: the B05 test patch has a potential issue. The `fd_descent_check` function enables the descent gate and then runs two dissections: one with entry gates off (slow path descends) and one with entry gates on (fast path descends). But between the two dissections, the `fd_fast_gates_set` function is called, which enables/disables ALL fast gates. This means the eth_ip gate is also toggled. When the entry gates are off, the fast path returns false immediately (because eth_ip is off), and the slow path runs. When the entry gates are on, the fast path runs (eth_ip is on) and descends.

But there's a subtlety: when the entry gates are off, the fast path returns false, and the slow path runs. The slow path's descent is gated by `flow_dissector_udp_inner_any_key`, which is enabled by `fd_descent_gate_set`. So the slow path descends. But the slow path also processes the outer IP through the graph walk, writing the outer keys before descending. The fast path, when it runs, also writes the outer keys before descending. Both paths should produce the same output.

But wait - when the entry gates are off, the slow path processes the outer IP through the full graph walk, which includes writing ETH_ADDRS, CONTROL, BASIC, ADDRS, PORTS, etc. When the entry gates are on, the fast path writes the same keys through the straight-line helpers. Both should produce the same bytes. The test verifies this with `KUNIT_EXPECT_MEMEQ`. Correct.

OK, I'm really done now. Let me write the final findings.

Wait, actually I want to check one more claim. The B cover letter says:

"With every gate off, the added slow-path cost is one not-taken static branch per UDP packet: the per-tunnel gates sit behind a single summary key (flow_dissector_udp_inner_any_key) maintained by their sysctl handler, so the count of tunnel types does not grow the hot path."

Looking at the slow-path code:
```c
if (ip_proto == IPPROTO_UDP &&
    fdret == FLOW_DISSECT_RET_CONTINUE &&
    !(key_control->flags & FLOW_DIS_IS_FRAGMENT) &&
    !(flags & (FLOW_DISSECTOR_F_STOP_BEFORE_ENCAP |
               FLOW_DISSECTOR_F_STOP_AT_ENCAP)) &&
    static_branch_unlikely(&flow_dissector_udp_inner_any_key) &&
    __skb_flow_dissect_udp_encap(...))
```

The `static_branch_unlikely(&flow_dissector_udp_inner_any_key)` is the one not-taken branch. When it's off (no descent gate enabled), the `__skb_flow_dissect_udp_encap()` call is not reached. Correct.

But the conditions before the static branch (`ip_proto == IPPROTO_UDP && fdret == FLOW_DISSECT_RET_CONTINUE && ...`) are evaluated even when the gate is off. These are not static branches - they're regular conditional checks. The cover letter says "one not-taken static branch per UDP packet," but there are also several regular conditional checks. The cover letter's claim is slightly misleading - it's "one not-taken static branch" plus several regular checks that are evaluated for every UDP packet.

But these regular checks are cheap (comparisons), and the `ip_proto == IPPROTO_UDP` check is already part of the existing slow-path code (the switch on ip_proto). The `fdret == FLOW_DISSECT_RET_CONTINUE` and fragment/flag checks are new but cheap. So the cover letter's claim is approximately correct - the dominant cost is the not-taken static branch.

Actually, looking more carefully, the `if (ip_proto == IPPROTO_UDP && ...)` block is placed AFTER `__skb_flow_dissect_ports()` and BEFORE the `switch (fdret)` that processes the result. This is a new block, not part of the existing slow-path code. So for every UDP packet, even with all gates off, the kernel now evaluates:
- `ip_proto == IPPROTO_UDP` (true for UDP)
- `fdret == FLOW_DISSECT_RET_CONTINUE` (usually true for UDP)
- `!(key_control->flags & FLOW_DIS_IS_FRAGMENT)` (true for non-fragments)
- `!(flags & (STOP_BEFORE_ENCAP | STOP_AT_ENCAP))` (true for most callers)
- `static_branch_unlikely(&flow_dissector_udp_inner_any_key)` (false when gates off)

That's 4 regular checks + 1 static branch for every non-fragmented UDP packet. The cover letter says "one not-taken static branch," which understates the cost slightly. But the regular checks are all simple comparisons that compile to a few instructions, so the claim is approximately correct.

Not a finding - just noting for completeness.

OK, now I'm really done. Let me write the final findings.
