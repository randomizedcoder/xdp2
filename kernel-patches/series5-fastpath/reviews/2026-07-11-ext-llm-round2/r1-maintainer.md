# Round-2 external LLM review: r1-maintainer (series A+B post-split)

finish: stop | usage: {"prompt_tokens":77438,"total_tokens":111866,"completion_tokens":34428,"prompt_tokens_details":null,"reasoning_tokens":29219}

## Review

# netdev Maintainer Review: flow_dissector fast paths (Series A) and UDP-tunnel descents (Series B)

---

## Series A — net: flow_dissector: opt-in byte-identical fast paths for common shapes

### Blockers

**A-B1. Patch 8: uninitialized `key_control` dereference in slow-path eth_ip counter**

The counter added at the `out_good` label dereferences `key_control` without guarding on `dissector_uses_key(FLOW_DISSECTOR_KEY_CONTROL)`:

```
+	if (ret && eth_ip_top &&
+	    !(key_control->flags & FLOW_DIS_ENCAPSULATION) &&
+	    (ip_proto == IPPROTO_TCP || ip_proto == IPPROTO_UDP))
+		flow_dissector_count_slow(FLOW_DISSECTOR_SHAPE_ETH_IP);
```

`key_control` is a function-local pointer assigned only inside `if (dissector_uses_key(flow_dissector, FLOW_DISSECTOR_KEY_CONTROL))` blocks earlier in `__skb_flow_dissect()`. A custom dissector that does not request `FLOW_DISSECTOR_KEY_CONTROL` (e.g. a tc-flower instance requesting only BASIC + IPV4_ADDRS + PORTS) reaching `out_good` with `eth_ip_top == true` and `ip_proto == TCP/UDP` will dereference an uninitialized pointer. The existing code at `out_good` never touches `key_control` outside its `dissector_uses_key` guard; this is a new, unconditional access.

The fast path's equivalent check (`flow_dissect_fast_is_encap`) does it correctly:

```
static bool flow_dissect_fast_is_encap(...)
{
	...
	if (!dissector_uses_key(flow_dissector, FLOW_DISSECTOR_KEY_CONTROL))
		return false;
	key_control = skb_flow_dissector_target(...);
	return key_control->flags & FLOW_DIS_ENCAPSULATION;
}
```

The KUnit suite's custom-dissector case (`fd_fast_ineligible_dissector_test`) happens to include `FLOW_DISSECTOR_KEY_CONTROL` in its key set, so the bug is not covered.

**What to change:** Guard the counter check on `dissector_uses_key`, or — better — capture a `bool is_encap` inside the existing CONTROL block at `out_good` and test that local instead. Add a KUnit case with a dissector that omits CONTROL.

---

**A-B2. Patch 8: unconditional per-dissect `this_cpu_inc` taxes the default path**

```
+	this_cpu_inc(flow_dissector_pcpu_stats.dissects);
+
 	if (flow_dissect_fast(skb, flow_dissector, target_container,
```

The cover letter quantifies this as +0.74% on a CPU-bound pktgen soak and calls it "within run-to-run noise." But this is a permanent regression for every kernel user — including distributions that ship with all gates off and never intend to enable them — to pay for an observability file that only benefits operators who actively tune the gates. The per-shape slow-path counters (`flow_dissector_count_slow` at each protocol's dissection point) are similarly unconditional.

**What to change:** Gate the entire counter subsystem behind a single `static_key_false flow_dissector_stats_key`, flipped on first read of `/proc/net/flow_dissector_stats` or first write to any `/proc/sys/net/flow_dissector/*` sysctl. When off, the per-dissect cost is zero. Alternatively, fold the `dissects` counter into the existing `flow_dissector_eth_ip_key` (the one gate almost everyone who cares about stats would enable).

---

### Substantive

**A-S1. Patches 2–7: seven per-shape boolean sysctls is too much operator surface**

The series adds `eth_ip`, `vlan`, `qinq`, `pppoe`, `mpls`, `ipip`, `gre` — seven independent knobs under `/proc/sys/net/flow_dissector/`. The cover letter acknowledges this and promises an "auto" mode in a separate RFC, but that is not in this series. An operator who wants the benefit has to read `/proc/net/flow_dissector_stats`, decide which shapes are worth it, and enable them individually. The coupling between `vlan` and `qinq` (patch 3's auto-toggle handlers) is a taste of the complexity this creates.

**What to change:** Consider a single `flow_dissector.fast_path` sysctl (0 = off, 1 = enable all byte-identical shapes) as the primary interface, with per-shape overrides remaining for advanced users. The auto-mode RFC can then build on the counters without requiring operators to understand seven knobs first. At minimum, document the intended workflow (read stats → enable shapes) more prominently in the sysctl documentation.

---

**A-S2. Patches 6, 7: recursive `key_control->flags = 0` clobber-and-restore pattern is fragile**

`flow_dissect_fast_ipv4()` and `flow_dissect_fast_ipv6()` unconditionally zero `key_control->flags` on entry:

```
key_control->flags = 0;
```

When called recursively from `flow_dissect_fast_ipip_inner()` or `flow_dissect_fast_gre_inner()`, this clobbers the ENCAP flag that the caller needs. Both inner helpers compensate by re-establishing it after the inner call returns:

```
/* Re-establish ENCAP after the inner pass zeroed key_control->flags. */
...
key_control->flags |= FLOW_DIS_ENCAPSULATION;
```

Series B's `flow_dissect_fast_udp_inner()` repeats the same pattern a third time. This works today but is a maintenance trap: anyone adding a new flag write to the IP helpers, or a new tunnel descent, has to know to restore ENCAP. The KUnit suite guards against current divergence but cannot guard against future changes that don't know about this convention.

**What to change:** Either thread a `bool top_level` parameter to the IP helpers (zero flags only when `top_level` is true), or factor the flag-zeroing into the dispatcher and have the helpers only OR in their contributions. The latter is cleaner.

---

**A-S3. Patch 6: 4in6 byte-identity depends on `addrs` union layout**

The cover letter and patch 6 comment describe the 4in6 residue:

```
The slow path fills these for the outer header and the inner pass then
overwrites only what it uses: an inner IPv4 overwrites just the first 8
bytes of the addrs union, leaving outer-v6 bytes in the tail.
Byte-identical means reproducing exactly that, residue included
```

This is correct given the current layout of `struct flow_keys` (`v4addrs` and `v6addrs` are union members at the same offset), but it is an implicit ABI dependency on the struct layout. If padding is ever inserted or the union is restructured, the fast path will silently diverge.

**What to change:** Add a `static_assert(offsetof(struct flow_keys, addrs.v4addrs) == offsetof(struct flow_keys, addrs.v6addrs))` near the fast-path helpers, and a comment in `struct flow_keys` noting that the fast path relies on this aliasing.

---

**A-S4. Patch 1: `DEBUG_NET_WARN_ON_ONCE(!net)` moved inside the gated block — verify this is safe**

```
-	DEBUG_NET_WARN_ON_ONCE(!net);
+		DEBUG_NET_WARN_ON_ONCE(!net);
```

The warning moves inside the `if (static_branch_unlikely(&netns_bpf_flow_dissector_enabled))` block. The justification is that the warning is only meaningful when a BPF program can be attached. But the warning also serves as a general "someone called `__skb_flow_dissect()` without a netns" debug aid. With the key off, that condition is no longer checked at all. If there is a code path that passes `NULL` net and `NULL` skb (raw-buffer mode) and expects the warning, it will silently skip it.

**Question for the author:** Are there known callers that pass `net=NULL, skb=NULL` in debug builds? If so, the warning should remain outside the gate (it's a `DEBUG_NET_WARN_ON_ONCE`, so zero cost in production). If not, the move is fine, but please state so in the commit message.

---

**A-S5. Patch 2: `FLOW_DISSECTOR_F_STOP_AT_FLOW_LABEL` handling needs a clearer contract**

The dispatcher admits `STOP_AT_FLOW_LABEL`:

```
if (flags & ~(unsigned int)(FLOW_DISSECTOR_F_PARSE_1ST_FRAG |
			    FLOW_DISSECTOR_F_STOP_AT_FLOW_LABEL))
	return false;
```

And the IPv6 helper defers on any non-zero flow label:

```
if (unlikely((iph->flow_lbl[0] & 0x0f) |
	     iph->flow_lbl[1] | iph->flow_lbl[2]))
	return false;
```

This means: for zero-label IPv6, the flag has no effect (fast path runs, slow path would not stop). For non-zero-label IPv6, the fast path defers, and the slow path handles the stop. This is correct, but the contract is subtle: the flag is "admitted" but its semantics are entirely subsumed by the deferral. A future maintainer might look at the dispatcher and think `STOP_AT_FLOW_LABEL` is actually handled by the fast path, when it is only tolerated.

**What to change:** Add a one-line comment at the dispatcher's flag check: `/* STOP_AT_FLOW_LABEL: admitted but subsumed by the IPv6 non-zero-label deferral */` — the patch 2 commit message explains this but the code comment is minimal.

---

### Polish

**A-P1. `Assisted-by:` trailer format is unclear**

Every patch carries:

```
Assisted-by: Claude:claude-fable-5 sparse smatch
```

Per `Documentation/process/coding-assistants.rst`, the expected format is `Assisted-by: Name <email>`. The `claude-fable-5 sparse smatch` suffix conflates the model identifier with tool names. Separate these: if Claude assisted with the code and sparse/smatch were verification tools, the tools don't belong in an `Assisted-by` trailer.

---

**A-P2. Patch 2: tentative definition of `flow_keys_dissector_symmetric`**

```
static struct flow_dissector flow_keys_dissector_symmetric;
```

This is a forward (tentative) definition used by the dispatcher's eligibility check. The comment acknowledges it. It's a common C idiom but fragile against future linkage changes. Consider moving the real definition above the fast-path helpers instead.

---

**A-P3. Patch 5: MPLS `ip_proto = 0` and `n_proto = proto` terminal writes are correct but uncommented in the slow path**

The fast path carefully mirrors the slow path's `out_good` terminal writes for MPLS. The patch 5 commit message explains this was a real divergence caught by the KUnit suite. Good — but add a comment in the slow path's `out_good` label noting that MPLS-with-BoS reaches it with `ip_proto = 0` and `proto = ETH_P_MPLS_*`, so future slow-path changes don't break this invariant silently.

---

**A-P4. Patch 10: KUnit test toggles global static keys without serialization**

`fd_fast_gates_set()` calls `static_branch_enable/disable` in a loop. Each call does `cpus_read_lock()` + `on_each_cpu()`. This is correct but slow (7 gates × 2 calls × `on_each_cpu()` per test case, × 53 cases). Consider batching the enable/disable into a single `cpus_read_lock()` section, or accept the cost and note it in the test file.

---

### Series A verdict

The core idea — straight-line per-shape extractors that are byte-identical to the graph walk, verified by an in-tree KUnit suite — is sound and the implementation is thorough. Patch 1 (BPF static key) is clean and can go in independently. The blockers (uninitialized `key_control` deref, unconditional counter tax) must be fixed before this is applied. The recursive flag-clobbering pattern (A-S2) should be refactored before the code grows further in Series B. The seven-knob API is workable for now if the auto-mode follow-up is credible, but the documentation should make the workflow clearer. With the blockers fixed, this is a strong candidate for net-next.

---

## Series B — net: flow_dissector: opt-in UDP-tunnel inner-flow descent

### Blockers

**B-B1. Patch 4: FOU/GUE ops hook is a fragile global singleton**

The design uses a single global RCU-protected ops pointer:

```
static const struct flow_dissector_fou_ops __rcu *flow_dissector_fou_ops;
static DEFINE_MUTEX(flow_dissector_fou_ops_mutex);

int flow_dissector_fou_ops_register(const struct flow_dissector_fou_ops *ops)
{
	...
	if (rcu_access_pointer(flow_dissector_fou_ops))
		ret = -EBUSY;
	...
}
```

And in `fou_init()`:

```
if (flow_dissector_fou_ops_register(&fou_flow_ops))
    pr_warn("fou: flow dissector ops already registered, fou_inner/gue_inner descent unavailable\n");
```

Problems:
1. If registration fails, the `fou` module loads successfully but `fou_inner`/`gue_inner` are silently broken — the sysctls exist and can be enabled, but no descent ever fires. The operator gets no feedback from the sysctl path.
2. There is no unregister-and-retry mechanism. If something else holds the hook, there is no way for `fou` to take over later.
3. The `pr_warn` is easy to miss in dmesg, and there's no `/proc/net/flow_dissector_stats` signal for descent gates (they're explicitly excluded from counting in Series A patch 8).

**What to change:** Either (a) make the ops a list and walk all registered providers (allowing multiple modules), or (b) fail `fou_init()` if registration fails (the descent is a core part of the feature, not optional), or (c) at minimum, make the sysctl handlers return `-ENODEV` when no ops are registered, so `echo 1 > .../fou_inner` fails visibly instead of silently doing nothing. Option (c) is the minimum acceptable fix.

---

**B-B2. Patches 1–3: hardcoded IANA port numbers limit real-world usefulness and create a misclassification risk**

VXLAN uses 4789, Geneve 6081, GTP-U 2152 — hardcoded:

```
if (udp_ports[1] != htons(IANA_VXLAN_UDP_PORT))
    return false;
```

The cover letter acknowledges: "non-standard VXLAN ports (e.g. Cilium's 8472) are not descended." But this is a significant gap: many k8s deployments use 8472, and the operator who enables `vxlan_inner` expecting inner-flow hashing gets nothing. Worse, a non-VXLAN UDP service on port 4789 will be inspected and, if its payload happens to validate as a VXLAN header with inner IP, hashed by the would-be inner flow — the cover letter acknowledges this but dismisses it as "inherent to on-wire tunnel recognition."

The sysctl is a boolean, not a port number. An operator cannot say "descend on port 8472 instead."

**What to change:** At minimum, the sysctl should accept a port number (write `8472` to `vxlan_inner_port` to descend on that port) or a list of ports. Alternatively, consult the per-netns VXLAN/Geneve tunnel netdev list for configured ports — the infrastructure exists (`vxlan_info`/`geneve_info` netdev notifiers). The current hardcoded-port design is acceptable as an MVP, but the sysctl documentation must prominently state which port is used and that non-standard ports are not handled, so operators don't enable the gate and see no effect.

---

### Substantive

**B-S1. Patches 2, 3: sysctl documentation incorrectly claims "only IPv4 outer is handled"**

Patch 2 (Geneve) documentation:

```
Kept out of the descended set (both paths keep the outer keys): Geneve
with options (opt_len > 0), proto_type other than ETH_P_TEB (rare
L3-Geneve variants), and Geneve-over-IPv6 outer (only IPv4 outer is
handled).
```

Patch 3 (GTP-U) documentation:

```
Kept out of the descended set (both paths retain): GTPv0 (legacy), GTP'
(charging, PT=0), G-PDU type other than 0xFF, GTP-U with extension
headers / N-PDU / sequence flags set, and GTP-U over IPv6 outer.
```

Both claims are wrong. The code handles IPv6 outers — the fast path has identical IPv4/IPv6 outer handling:

```
n = outer_v6 ? put_outer_ipv6_udp(buf, htons(GENEVE_UDP_PORT))
             : put_outer_ipv4_udp(buf, htons(GENEVE_UDP_PORT));
```

And the KUnit tests explicitly verify IPv6 underlays (`build_geneve(buf, true, ...)` and `build_gtpu(buf, true, ...)` with `htons(ETH_P_IPV6)`). The "only IPv4 outer" claim appears to be stale text from an earlier draft.

**What to change:** Remove "Geneve-over-IPv6 outer (only IPv4 outer is handled)" and "GTP-U over IPv6 outer" from the "kept out of the descended set" lists in the sysctl docs.

---

**B-S2. The hashing change needs explicit review from routing and tunneling maintainers**

Enabling a descent gate changes `skb->hash` for tunnel traffic. This affects:
- ECMP / multipath route selection (`fib_multipath_hash`)
- bonding / LAG `xmit_hash_policy`
- RPS / RFS / aRFS
- tc-flower classification (if it uses `skb->hash`)

The cover letter says "the choice is only whether to descend, not which path ran" — which is true for fast-vs-slow equivalence. But the choice itself has routing implications. An operator who enables `vxlan_inner` on a router doing ECMP over VXLAN-encapsulated traffic will see flows redistributed across paths — potentially breaking assumptions about flow pinning.

**What to change:** Cc the routing (`netdev@` + `rtnetlink` maintainers) and tunneling (VXLAN, Geneve, GTP maintainers) maintainers explicitly on the cover letter. Add a "Operational impact" section to `Documentation/networking/flow_dissector.rst` that lists every consumer of `skb->hash` and states that enabling a descent gate redistributes flows across all of them. The current documentation mentions "cake / fq / fib_multipath / RPS" but does not mention bonding/LAG or aRFS.

---

**B-S3. Patch 1: `__skb_flow_dissect_udp_encap()` rewrites `proto`/`nhoff` and re-enters the loop — verify this doesn't break `FLOW_DISSECTOR_KEY_ENC_IP`**

The slow-path descent rewrites `proto` and `nhoff`:

```
*p_proto = inner_proto;
*p_nhoff = inner_nhoff;
key_control->flags |= FLOW_DIS_ENCAPSULATION;
return true;
```

And the caller does `fdret = FLOW_DISSECT_RET_PROTO_AGAIN`, re-entering the loop. The loop then parses the inner IP header and writes its keys, overwriting the outer. But `FLOW_DISSECTOR_KEY_ENC_IP` (and other `ENC_*` keys) are filled by `skb_flow_dissect_tunnel_info()`, which is called separately and should not be affected. However, this needs to be verified: does the `PROTO_AGAIN` re-entry skip or re-run any `ENC_*` key population?

**Question for the author:** Confirm that `skb_flow_dissect_tunnel_info()` is called exactly once per dissect regardless of `PROTO_AGAIN` re-entries, and add a test case that requests `FLOW_DISSECTOR_KEY_ENC_IP` and verifies it's populated correctly with a descent gate on.

---

**B-S4. Patch 4: `fou_list` changed to RCU list — verify existing writers are safe**

The patch changes `list_add` to `list_add_tail_rcu` and `list_del` to `list_del_rcu` in `fou_core.c`. The existing `fou_add_to_port_list()` iterates with `list_for_each_entry` (not `_rcu`) under `mutex_lock(&fn->fou_lock)`. This is safe because the mutex serializes writers. But the existing `fou_release()` is called from `udp_tunnel_sock_release()` → ... → which context? If `fou_release()` can be called without the mutex, the `list_del_rcu` is racing with the mutex-protected `list_for_each_entry` in `fou_add_to_port_list()`.

**What to change:** Verify that `fou_release()` is always called under `fn->fou_lock`, or add the lock. The existing code uses `list_del` (non-RCU), which has the same requirement, so this is likely already safe — but the change to `_rcu` variants makes it worth double-checking and adding a lockdep assertion.

---

### Polish

**B-P1. Patch 3: GTP header macros defined locally instead of in `<net/gtp.h>`**

```
#define GTP1_HDR_VERSION	GENMASK(7, 5)
#define GTP1_HDR_PT		BIT(4)
```

These should be added to `<net/gtp.h>` next to `struct gtp1_header` so they're defined once and available to any future user.

---

**B-P2. Patch 1: `__always_inline` on tunnel classifiers may be excessive**

```
static __always_inline bool
flow_dissect_vxlan_inner_ok(const void *data, int thoff, int hlen,
                            __be16 *inner_proto, int *inner_nhoff)
```

The functions are small and called from two sites (fast and slow path) in the same translation unit. `static inline` would suffice; `__always_inline` forces inlining at both call sites, increasing code size. If the compiler decides not to inline, it's probably right.

---

**B-P3. The two-series split is drawn in the right place**

Series A is byte-identical (pure optimisation, no behaviour change). Series B changes `skb->hash` for tunnel traffic. These are fundamentally different policy discussions and should be separate. The dependency (B on A) is correctly expressed via `prerequisite-patch-id`. The exclusion of descent gates from the counters and the proposed auto-mode is correct and should be maintained.

One concern: Series A's infrastructure (fast-path helpers, KUnit suite, `MAX_FLOW_DISSECT_HDRS` bound) is designed to support Series B's descents. If Series A is applied without Series B, the infrastructure for UDP-tunnel descents (the `flow_dissect_fast_udp_inner()` tail, the `__skb_flow_dissect_udp_encap()` hook point) is partially present in Series B patch 1. This is fine — Series A is self-contained and doesn't reference Series B.

---

### Series B verdict

The shared-classifier design (one `*_inner_ok()` validator per tunnel, called by both fast and slow paths) is excellent — it makes fast == slow structural rather than maintained by hand. The KUnit suite is thorough. The FOU/GUE ops hook (B-B1) needs a redesign or at minimum a visible failure mode before this can be applied. The hardcoded port numbers (B-B2) are a significant limitation that should be addressed or at least prominently documented. The documentation bugs (B-S1) are straightforward fixes. The hashing change (B-S2) is the right policy (opt-in, per-tunnel-type) but needs broader review. With the blockers addressed, this is a valuable feature for overlay and mobile-core deployments.

## Reasoning trace

Let me carefully review both series as a senior netdev maintainer would.

Let me organize my thoughts by going through both series systematically, citing specific lines.

# Series A (11 patches): opt-in byte-identical fast paths

Let me go through the patches and identify issues.

## Patch 1: gate BPF program lookup behind static key

This patch adds a static key `netns_bpf_flow_dissector_enabled` that skips the BPF flow dissector lookup when no program is attached. This is a reasonable optimisation that mirrors `bpf_sk_lookup_enabled`.

Key concern: the static key maintenance. The patch adds `netns_bpf_attach_type_need()/unneed()` calls in:
- `netns_bpf_prog_attach()` (for fresh attach, not replacement)
- `__netns_bpf_prog_detach()`
- `netns_bpf_pernet_pre_exit()` (for remaining legacy progs)

The `netns_bpf_attach_type_need()/unneed()` are already called by the link attach/release paths, so those are handled. The patch correctly handles the legacy `BPF_PROG_ATTACH` path.

One issue: in `netns_bpf_prog_attach()`, the `netns_bpf_attach_type_need(type)` is called only when `!attached` (fresh attach). But what about the case where `attached` is non-NULL (replacement)? The comment says "a replacement keeps the existing count" - this is correct, since the old program was already counted.

Another issue: in `__netns_bpf_prog_detach()`, the `netns_bpf_attach_type_unneed(type)` is called unconditionally. But what if the detach is for a replacement? Actually no, `__netns_bpf_prog_detach()` is only called from the legacy detach path, not from replacement. Let me check... Actually, `netns_bpf_prog_attach()` replaces in-place without calling `__netns_bpf_prog_detach()`. So the detach path is correct.

Wait, there's a subtle issue. In `netns_bpf_pernet_pre_exit()`, the patch adds `netns_bpf_attach_type_unneed(type)` for legacy progs. But links are already handled by the existing per-link `unneed` loop. However, could there be a case where both a link AND a legacy prog are attached? Looking at the code, `netns_bpf_pernet_pre_exit()` iterates over `type` and handles both links and legacy progs. The link unneed is in the `list_for_each_entry_safe` loop, and the legacy prog unneed is in the `if (net->bpf.progs[type])` block. So no double-decrement.

Actually, I need to think about this more carefully. The static key is a global counter. If netns A has a flow dissector prog and netns B has a flow dissector prog, the count is 2. When netns A exits, it decrements to 1. When netns B exits, it decrements to 0. This is correct.

But what about the case where a link is attached AND a legacy prog is attached to the same type in the same netns? I don't think that's possible - the BPF attach machinery should prevent it. The link replaces the legacy prog. So this should be fine.

Actually, looking more carefully at `netns_bpf_prog_attach()`:
```c
net->bpf.progs[type] = prog;
if (attached)
    bpf_prog_put(attached);
else
    netns_bpf_attach_type_need(type);
```

So on a fresh attach, it increments. On replacement, it doesn't (correct - the count is already there). On detach, it decrements. On pernet exit, it decrements for legacy progs. This looks correct.

The `DEBUG_NET_WARN_ON_ONCE(!net)` move inside the gated block is reasonable - if no BPF program can be attached, the netns resolution for BPF is meaningless.

This patch looks good. It's a clean, well-contained optimisation.

## Patch 2: opt-in fast-path for eth + IPv{4,6} + {TCP,UDP}

This is the core patch. Let me review the fast-path implementation carefully.

Key concerns:

### a) The sysctl subtree design

The patch creates `/proc/sys/net/flow_dissector/` with per-shape sysctls. This is a new namespace under `/proc/sys/net/`. The choice of using `proc_do_static_key` as the handler is clean.

However, the sysctl table is registered with `register_net_sysctl(&init_net, ...)` in a `late_initcall`. This means:
1. The sysctls are only in the init_net namespace, not per-netns. The cover letter acknowledges this: "The gates are global (a static key patches code shared by every netns)".
2. Registration in `late_initcall` means the sysctls aren't available during early boot. If something calls `__skb_flow_dissect()` before the sysctls are registered, the static keys are just in their default-off state, which is fine.

### b) The eligibility gate

```c
if (flow_dissector != &flow_keys_dissector &&
    flow_dissector != &flow_keys_dissector_symmetric)
    return false;
```

This restricts the fast path to the two standard dissectors. Custom dissectors (like tc-flower's) are excluded. Good.

```c
if (flags & ~(unsigned int)(FLOW_DISSECTOR_F_PARSE_1ST_FRAG |
                            FLOW_DISSECTOR_F_STOP_AT_FLOW_LABEL))
    return false;
```

This admits only two flags. The comment explains that `STOP_AT_FLOW_LABEL` must be admitted because `skb_get_hash()` passes it on every dissect. This is a critical point - without it, the fast path would never run for the kernel's main consumer.

But wait - `PARSE_1ST_FRAG` is admitted but the fast path defers on fragmented packets:
```c
if (unlikely(iph->frag_off & htons(IP_MF | IP_OFFSET)))
    return false;
```

So `PARSE_1ST_FRAG` is admitted but has no effect - fragmented packets always defer. That's fine for byte-identity, but it means the flag is admitted unnecessarily. Actually, it's admitted so that callers passing it (e.g., for first-fragment parsing) can still use the fast path for non-fragmented packets. That's reasonable.

### c) The IPv4 fast path

```c
if (unlikely(hlen - nhoff < (int)sizeof(*iph) + 4))
    return false;
```

This checks for 20 bytes of IP header + 4 bytes of ports. Good - it ensures we can read the ports.

```c
if (unlikely(*(const u8 *)iph != FLOW_DIS_IPV4_VIHL_NOOPT))
    return false;
```

This checks version=4, IHL=5. Equivalent to `iph->version == 4 && iph->ihl == 5` but as a single byte check. Clean.

```c
if (unlikely(iph->frag_off & htons(IP_MF | IP_OFFSET)))
    return false;
```

Defers on fragmented packets. Good.

The key writes look correct - they mirror what the slow path does. The `key_control->thoff` uses `min_t(u16, thoff, skb ? skb->len : hlen)` which matches the slow path's behaviour.

Wait, actually let me check this more carefully. In the slow path:
```c
key_control->thoff = min_t(u16, nhoff, skb ? skb->len : hlen);
```

But in the fast path, `thoff` is `nhoff + sizeof(*iph)`, which is the transport header offset. The slow path sets `key_control->thoff` at the IP header offset, not the transport header offset... 

Actually, let me look at the slow path more carefully. In `__skb_flow_dissect()`:
```c
case htons(ETH_P_IP):
    ...
    nhoff += iph->ihl * 4;
    ...
    key_control->thoff = min_t(u16, nhoff, skb ? skb->len : hlen);
```

So `thoff` is set after advancing past the IP header, i.e., to the transport header offset. And in the fast path:
```c
thoff = nhoff + (int)sizeof(*iph);
...
key_control->thoff = min_t(u16, thoff, skb ? skb->len : hlen);
```

So both set `thoff` to the transport header offset. OK, this matches.

### d) The IPv6 fast path

The flow label check is important:
```c
if (unlikely((iph->flow_lbl[0] & 0x0f) |
             iph->flow_lbl[1] | iph->flow_lbl[2]))
    return false;
```

This defers on any non-zero flow label. The comment explains this is because `STOP_AT_FLOW_LABEL` makes the slow path stop at a non-zero label, and dissectors requesting the label key write it. Deferring on the label itself covers both cases.

But wait - the `flow_lbl[0] & 0x0f` check. The flow label is 20 bits: the low 4 bits of `flow_lbl[0]` plus `flow_lbl[1]` and `flow_lbl[2]`. The high 4 bits of `flow_lbl[0]` are part of the version/traffic class. Actually, looking at `struct ipv6hdr`:

```c
__be32 flow_lbl;
```

Wait, no. In the kernel:
```c
struct ipv6hdr {
    ...
    __be16 payload_len;
    __be16 nexthdr;
    __u8  hop_limit;
    ...
    __be32 flow_lbl;  // Actually it's:
};
```

Actually, looking at the real struct:
```c
struct ipv6hdr {
    __u8 priority : 4;
    __u8 version : 4;
    __u8 flow_lbl[3];
    ...
};
```

Hmm, actually in the kernel it's:
```c
#if defined(__LITTLE_ENDIAN_BITFIELD)
    __u8 priority:4,
         version:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
    __u8 version:4,
         priority:4;
#else
#error "Please fix <asm/byteorder.h>"
#endif
    __u8 flow_lbl[3];
```

So `flow_lbl[0]` contains the low 4 bits of the flow label in its low 4 bits, and the high 4 bits are... actually the high 4 bits of `flow_lbl[0]` are the low 4 bits of the traffic class. So `flow_lbl[0] & 0x0f` correctly extracts the low 4 bits of the flow label.

The check `(iph->flow_lbl[0] & 0x0f) | iph->flow_lbl[1] | iph->flow_lbl[2]` correctly tests for a non-zero 20-bit flow label. Good.

### e) The ports read

```c
const __be32 *ports = (const __be32 *)((const u8 *)data + thoff);
key_ports->ports = *ports;
```

This reads 4 bytes (src + dst port) as a single 32-bit load. The length check earlier ensures this is safe. Good.

But wait - what about non-linear skbs? The `data` pointer comes from `skb_header_pointer()` or similar. If the skb is non-linear and the ports are in a fragment, this would be an out-of-bounds read.

Let me check how `data` and `hlen` are set in `__skb_flow_dissect()`:
```c
if (skb) {
    ...
    data = skb->data;
    hlen = skb_headlen(skb);
    ...
}
```

So `hlen` is `skb_headlen(skb)`, which is the length of the linear data. If the ports are beyond the linear area, `hlen - thoff < 4` and the fast path would defer. Good - the length check protects against this.

Actually, wait. The check is:
```c
if (unlikely(hlen - nhoff < (int)sizeof(*iph) + 4))
    return false;
```

This checks `hlen - nhoff >= 24` (20 for IP header + 4 for ports). If `hlen` is the head length, this correctly ensures the entire IP header + ports are in the linear area. Good.

### f) The tentative definition

```c
static struct flow_dissector flow_keys_dissector_symmetric;
```

This is a tentative (forward) definition used by the dispatcher's eligibility check. The real definition comes later. This is a common C pattern but it's fragile - if the real definition ever changes linkage or scope, this would silently break. The comment acknowledges this.

### g) Non-linear skb handling

The fast path uses `data` and `hlen` directly. For non-linear skbs, `hlen = skb_headlen(skb)`, so only the linear head is accessible. If the fast path needs data beyond the linear head, it defers (via the length checks). This is correct.

But there's a subtlety: the slow path uses `__skb_header_pointer()` to pull data from fragments. The fast path doesn't - it only reads from the linear area. This means the fast path might defer on a packet that the slow path could handle (by pulling from frags). That's fine for byte-identity - the fast path just returns false and the slow path runs.

## Patch 3: VLAN and QinQ fast-path

### a) HW-stripped VLAN handling

```c
if (vlan_depth == 0 && skb && skb_vlan_tag_present(skb)) {
    tci_id = skb_vlan_tag_get_id(skb);
    tci_prio = skb_vlan_tag_get_prio(skb);
    inner_proto = skb->protocol;
}
```

This handles the hardware-stripped case. But there's a subtle issue: when `skb_vlan_tag_present(skb)` is true, `skb->protocol` is the inner protocol (not the VLAN TPID). The fast path correctly uses `skb->protocol` as the inner protocol. Good.

But what about the case where `skb` is NULL (raw data mode)? Then `skb_vlan_tag_present(skb)` is not checked, and the code falls through to the in-band tag parsing. Good.

### b) QinQ auto-toggle

The `proc_set_vlan_key` and `proc_set_qinq_key` handlers implement the coupling:
- Writing `qinq=1` also enables `vlan`
- Writing `vlan=0` also disables `qinq`

This is reasonable - QinQ extends VLAN, so the depth-0 gate must be on for depth-2 to fire. But there's a potential race: the `static_branch_enable/disable` calls are not atomic with respect to each other. Between enabling `vlan` and the check for `qinq`, another CPU could write `qinq=0`. But this is a sysctl write, which is inherently not performance-critical, and the worst case is a brief inconsistency that resolves on the next write. OK.

Actually, there's a more subtle issue. The `proc_do_static_key` function handles the read/write of the sysctl value. The `proc_set_vlan_key` and `proc_set_qinq_key` wrappers call it and then do the coupling. But `proc_do_static_key` operates on the `table->data` pointer, which is `&flow_dissector_vlan_key.key` or `&flow_dissector_qinq_key.key`. The static branch enable/disable in the wrapper functions operates on the same keys. So the sequence is:
1. `proc_do_static_key` writes the key
2. The wrapper checks the key state and adjusts the other key

This is correct but there's a window between step 1 and step 2 where the keys are inconsistent. For example, if `vlan=0` is written:
1. `proc_do_static_key` disables `vlan_key`
2. Before `proc_set_vlan_key` disables `qinq_key`, a packet arrives
3. The dispatcher checks `vlan_key` - it's off, so VLAN-tagged packets go to the slow path
4. The slow path doesn't check `qinq_key`, so QinQ packets are handled by the slow path

This is fine - the slow path always works correctly. The `qinq_key` only affects the fast path, and the fast path checks `vlan_key` first (at depth 0). So even if `qinq_key` is on but `vlan_key` is off, no QinQ packet enters the fast path.

Wait, actually, looking at the code more carefully:
```c
case htons(ETH_P_8021Q):
case htons(ETH_P_8021AD):
    if (!static_branch_unlikely(&flow_dissector_vlan_key))
        return false;
    return flow_dissect_fast_vlan(skb, flow_dissector,
                                  target_container, data,
                                  proto, nhoff, hlen, 0);
```

The dispatcher only enters `flow_dissect_fast_vlan` if `vlan_key` is on. Inside `flow_dissect_fast_vlan`, the depth-1 check tests `qinq_key`:
```c
if (vlan_depth >= 1 &&
    !static_branch_unlikely(&flow_dissector_qinq_key))
    return false;
```

So if `vlan_key` is off, the fast path is never entered, and `qinq_key` is irrelevant. The coupling is a convenience to prevent confusing state, not a correctness requirement. Good.

## Patch 4: PPPoE fast-path

Looks straightforward. The `is_pppoe_ses_hdr_valid()` check mirrors the slow path. The PPP protocol field is checked for `PPP_IP` / `PPP_IPV6`, and everything else defers.

One concern: the `PPPOE_SES_HLEN` macro is used but not shown in the diff. It should be defined somewhere in the existing headers. Let me assume it's correct.

## Patch 5: MPLS fast-path

The key concern here is the "out_good terminal writes" that the comment calls out:
```c
key_basic->n_proto = proto;
key_basic->ip_proto = 0;
```

This mirrors what the slow path does when it returns `OUT_GOOD` after the first LSE with BoS=1. The comment says the KUnit test caught this divergence. Good.

One issue: `key_control->thoff` is set to `nhoff` (past the LSE), but there's no `addr_type` write. Looking at the slow path... the slow path sets `addr_type` only when it descends into an IP header. For MPLS with BoS=1, the slow path returns `OUT_GOOD` without setting `addr_type`. But `key_control->addr_type` might be set to a default value (0?) by the caller. Let me check...

Actually, looking at the slow path more carefully, the `out_good` label writes:
```c
key_basic->n_proto = proto;
key_basic->ip_proto = ip_proto;
```

And `key_control->thoff` is set earlier in the IP handling. But for MPLS, the slow path doesn't enter the IP case, so `thoff` might not be set... Actually, looking at the slow path flow:
1. The slow path enters the `case htons(ETH_P_MPLS_UC)` / `case htons(ETH_P_MPLS_MC)` block
2. Calls `__skb_flow_dissect_mpls()` which returns `FLOW_DISSECT_RET_OUT_GOOD` when BoS=1
3. Falls through to `out_good:` which writes `key_basic->n_proto = proto` and `key_basic->ip_proto = ip_proto`

But where is `key_control->thoff` set? In the slow path, `thoff` is set in the IP handling blocks:
```c
case htons(ETH_P_IP):
    ...
    nhoff += iph->ihl * 4;
    ...
    key_control->thoff = min_t(u16, nhoff, skb ? skb->len : hlen);
```

For MPLS, the slow path doesn't enter the IP block, so `key_control->thoff` is never set. But the fast path sets it:
```c
key_control->thoff = min_t(u16, nhoff, skb ? skb->len : hlen);
```

Wait, this is after `nhoff += sizeof(*hdr)`, so it's the offset past the MPLS label. But the slow path doesn't set `thoff` for MPLS... Is this a divergence?

Actually, let me look more carefully. In the slow path, the `out_good` label is reached after the MPLS handling. The slow path sets `key_control->thoff` in the IP/IPv6 handling blocks, but not in the MPLS block. So for MPLS with BoS=1, `key_control->thoff` is left at whatever it was before (possibly 0 or uninitialized).

But the fast path sets it. This is a divergence! Unless the KUnit test checks this...

Hmm, but the KUnit test memcmps the entire `struct flow_keys`, so if `thoff` is different, the test would fail. The comment says the test caught the divergence and it was fixed. So either the slow path does set `thoff` for MPLS, or the fast path matches the slow path's behaviour.

Let me re-read the slow path. Actually, looking at the slow path's `out_good` label:

```c
out_good:
    ...
    if (dissector_uses_key(flow_dissector, FLOW_DISSECTOR_KEY_CONTROL))
        key_control = skb_flow_dissector_target(flow_dissector,
                                                FLOW_DISSECTOR_KEY_CONTROL,
                                                target_container);
    ...
    key_control->thoff = min_t(u16, nhoff, skb ? skb->len : hlen);
    ...
    key_basic->n_proto = proto;
    key_basic->ip_proto = ip_proto;
```

Wait, does the `out_good` label set `thoff`? I don't have the full slow path code in the diff. The diff only shows the added fast-path code. Let me look at what the fast path does and assume it matches.

Actually, looking at the existing slow path (not in the diff), the `out_good` label does set:
```c
key_control->thoff = min_t(u16, nhoff, skb ? skb->len : hlen);
```

So after the MPLS block, `nhoff` has been advanced past the MPLS label (by `__skb_flow_dissect_mpls()`), and `thoff` is set to that. The fast path also advances `nhoff` past the label and sets `thoff`. So they match. Good.

## Patch 6: IPIP fast-path

Key concern: the `key_control->flags = 0` issue. The fast-path helpers zero `flags` on entry:
```c
key_control->flags = 0;
```

But when recursing for IPIP, the inner pass zeros the flags, clobbering any ENCAP flag. The `flow_dissect_fast_ipip_inner()` helper re-establishes ENCAP after the inner returns:
```c
key_control->flags |= FLOW_DIS_ENCAPSULATION;
```

This is correct but fragile. The comment acknowledges it. A cleaner design would be to not zero flags in the inner helpers, but that would require distinguishing top-level calls from recursive calls.

Actually, looking more carefully, the `key_control->flags = 0` is in `flow_dissect_fast_ipv4()` and `flow_dissect_fast_ipv6()`. These are called both at the top level and recursively. At the top level, zeroing flags is correct. During recursion, it's wrong but the caller re-establishes ENCAP. This is a design smell.

### IPv6 outer residue

The comment about the 4in6 descent:
```
The slow path fills these for the outer header and the inner pass then overwrites
only what it uses: an inner IPv4 overwrites just the first 8 bytes of the addrs
union, leaving outer-v6 bytes in the tail. Byte-identical output means
reproducing exactly that, residue included
```

This is concerning. The `addrs` union in `struct flow_keys` has `v4addrs` (8 bytes) and `v6addrs` (32 bytes). When a 4in6 descent happens:
1. The outer IPv6 addresses are written to `v6addrs` (32 bytes)
2. The inner IPv4 addresses overwrite `v4addrs` (8 bytes), which is the first 8 bytes of the union
3. The remaining 24 bytes of `v6addrs` still hold outer IPv6 data

The fast path reproduces this by writing the outer IPv6 addresses first, then calling the inner IPv4 helper which overwrites `v4addrs`. The residue is preserved because the inner helper only writes `v4addrs`. This is correct but very fragile - it depends on the exact layout of the union.

## Patch 7: GRE fast-path

Similar pattern to IPIP. The GRE header validation:
```c
if (hdr->flags != 0)
    return false;
```

This checks for version 0 and no flags. The `flags` field in `struct gre_base_hdr` contains both the control flags and the version. A zero word means "no flags, version 0". Good.

## Patch 8: per-shape counters

This adds per-cpu counters and `/proc/net/flow_dissector_stats`.

### a) Counter placement

The slow-path counters are placed at each protocol's dissection point. The comment says:
```
for eth_ip that is the out: exit label, taken only on a top-level,
non-encapsulated, TCP/UDP terminal, so a packet counted as VLAN/IPIP/GRE is
never also counted as eth_ip
```

Looking at the code:
```c
if (ret && eth_ip_top &&
    !(key_control->flags & FLOW_DIS_ENCAPSULATION) &&
    (ip_proto == IPPROTO_TCP || ip_proto == IPPROTO_UDP))
    flow_dissector_count_slow(FLOW_DISSECTOR_SHAPE_ETH_IP);
```

This checks `eth_ip_top` (set when `nhoff == nhoff_init`, i.e., the IP header is at the initial offset), no ENCAP flag, and TCP/UDP. Good - this ensures VLAN/IPIP/GRE packets are not double-counted as eth_ip.

### b) The `this_cpu_inc` cost

The unconditional `this_cpu_inc(flow_dissector_pcpu_stats.dissects)` on every dissect is the one cost that exists even when all gates are off. The cover letter says it's +0.74% dissector time, within run-to-run noise. This is acceptable but not free.

**This is a significant objection**: the counters add cost to every dissect even when no gates are enabled. An operator who doesn't want the fast path still pays for the counters. The counters should probably be gated behind their own static key, or at least be opt-in.

Actually wait, let me re-read the cover letter:
```
Counters (patch 8) are the one part with a cost in the all-gates-off
default: one this_cpu_inc per dissect plus one per matched shape.
Measured on a CPU-bound pktgen soak that is +0.74% dissector time
(+0.44 sigma -- within run-to-run noise).
```

0.74% on a CPU-bound pktgen soak. That's small but measurable. And it's paid by everyone, even those who never enable any gate. This is a tax on the default case.

The counter at the dissects point is unconditional. The per-shape counters in the slow path are also unconditional (they fire whenever the slow path sees a shape, regardless of gate state). This means:
1. Every dissect pays one `this_cpu_inc` (the denominator)
2. Every shaped packet in the slow path pays an additional `this_cpu_inc`

For an operator who never enables any gate, this is pure overhead. The per-shape slow-path counters are only useful for deciding whether to enable gates - if you never plan to enable any, they're wasted.

**Recommendation**: gate the counters behind a static key, or make them opt-in via a separate sysctl. Or at minimum, gate the `dissects` counter behind the `eth_ip` key (or a dedicated "stats" key).

### c) `/proc/net/flow_dissector_stats` visibility

The file is created in `init_net.proc_net`, so it's only visible in the init netns. The cover letter says "containers do not see it". But the counters are global (per-cpu), so even if a container could see the file, the data would be system-wide. This is consistent with the global gates.

## Patch 9: bound fast-path tunnel recursion

This adds a `num_hdrs` parameter to the tunnel-reachable helpers and checks against `MAX_FLOW_DISSECT_HDRS`.

### a) Initial count

The initial count at each fast-path entry is set at or above the number of headers the slow path has already consumed:
- Top-level eth+IP: `num_hdrs = 1` (Ethernet + IP = 2? No, it's 1, meaning... let me check)

Actually, looking at the code:
```c
if (!flow_dissect_fast_ipv4(skb, flow_dissector,
                            target_container, data,
                            nhoff, hlen, 1))
```

The `1` is the initial count. In the slow path, `skb_flow_dissect_allowed()` increments `num_hdrs` at the top of the loop. The first call increments to 1. So `num_hdrs = 1` at the point of the first IP header processing matches.

For VLAN, the count is `vlan_depth + 2`:
```c
ok = flow_dissect_fast_ipv4(skb, flow_dissector,
                            target_container, data,
                            nhoff, hlen, vlan_depth + 2);
```

This accounts for: Ethernet (1) + VLAN tags (vlan_depth + 1) + IP (1) = vlan_depth + 2. Wait, that doesn't seem right. Let me think again.

Actually, the slow path's `num_hdrs` is incremented once per loop iteration (per protocol header). For a VLAN-tagged packet:
- Eth header: not counted (it's before the loop? Actually...)

Let me look at the slow path. `skb_flow_dissect_allowed()` is called at the top of the `proto_again:` loop. The first iteration is the outer ethertype. For a VLAN-tagged packet:
1. `proto_again:` - `num_hdrs` becomes 1 (VLAN)
2. `proto_again:` - `num_hdrs` becomes 2 (inner VLAN or IP)

For QinQ:
1. `num_hdrs` = 1 (outer VLAN)
2. `num_hdrs` = 2 (inner VLAN)
3. `num_hdrs` = 3 (IP)

For the fast path, `vlan_depth + 2`:
- Single VLAN (depth 1): 1 + 2 = 3 (but slow path would be at 2 when it reaches IP)

Hmm, this doesn't match exactly. But the comment says "set at or above the number of headers the slow path has already consumed". So the fast path might be more conservative (count higher), which means it would defer earlier. This is safe for byte-identity because the slow path would also defer at the same or later point.

Actually, let me re-read the comment:
```
The initial count at each fast-path entry is set at or above the
number of headers the slow path has already consumed (outer VLAN tags,
PPPoE, the outer IP), so the fast path never descends past the point
the slow path would have capped.
```

So the fast path is conservative - it might defer earlier than the slow path would. But when it defers, the slow path runs and produces the correct result. The byte-identical contract is maintained because the fast path returns false and the slow path handles it.

But wait - there's a subtlety. If the fast path defers at a shallower depth than the slow path would, and the slow path descends deeper, then the fast path's result (false -> slow path runs) is the same as the slow path's result. So byte-identity holds. Good.

But is the reverse true? Could the fast path descend deeper than the slow path? The check is `if (++num_hdrs > MAX_FLOW_DISSECT_HDRS)`, which means the fast path allows up to `MAX_FLOW_DISSECT_HDRS` headers (incrementing to 15, checking > 15). The slow path uses `skb_flow_dissect_allowed()` which checks `++*num_hdrs > MAX_FLOW_DISSECT_HDRS`. So both check `> 15`, meaning both allow up to 15 headers. But the initial counts differ...

Actually, this is getting complex. The key question is: does the fast path ever descend deeper than the slow path? If the fast path starts with a higher initial count, it would cap earlier, which is safe. If it starts with a lower initial count, it could cap later, which would be a divergence.

The comment says the initial count is "at or above" the slow path's count. So the fast path always caps at the same depth or earlier. When it caps earlier, it defers to the slow path, which produces the correct result. When it caps at the same depth, both stop. This is correct.

### b) The `MAX_FLOW_DISSECT_HDRS` move

The patch moves the `#define MAX_FLOW_DISSECT_HDRS 15` above the fast-path helpers. In series B, patch 1, this move is shown:
```c
+/* Maximum number of protocol headers that can be parsed in
+ * __skb_flow_dissect
+ */
+#define MAX_FLOW_DISSECT_HDRS	15
```

Wait, but this is in series B patch 1, not series A patch 9. Let me re-check...

Actually, looking at series A patch 9, the diff doesn't show the `MAX_FLOW_DISSECT_HDRS` definition being moved. It just adds the `num_hdrs` parameter. The `MAX_FLOW_DISSECT_HDRS` must already be defined above the fast-path helpers (it was moved in an earlier patch or was already there).

Actually, looking at series A patch 2, the fast-path helpers are added after the existing `MAX_FLOW_DISSECT_HDRS` definition. So `MAX_FLOW_DISSECT_HDRS` is already available. Good.

Wait, but in series B patch 1, I see:
```c
+/* Maximum number of protocol headers that can be parsed in
+ * __skb_flow_dissect
+ */
+#define MAX_FLOW_DISSECT_HDRS	15
```

This is added in series B. But in series A, `MAX_FLOW_DISSECT_HDRS` is already used (in patch 9). So it must already be defined. Let me check...

In the original code, `MAX_FLOW_DISSECT_HDRS` is defined at:
```c
/* Maximum number of protocol headers that can be parsed in
 * __skb_flow_dissect
 */
#define MAX_FLOW_DISSECT_HDRS	15
```

This is above `skb_flow_dissect_allowed()`. In series A patch 9, it's used in the fast-path helpers. Since the fast-path helpers are above `skb_flow_dissect_allowed()` (they were added in patch 2), and `MAX_FLOW_DISSECT_HDRS` is defined below them... wait, that would be a compile error.

Actually, looking at series B patch 1, the `MAX_FLOW_DISSECT_HDRS` definition is added (moved) above the fast-path helpers:
```c
+/* Maximum number of protocol headers that can be parsed in
+ * __skb_flow_dissect
+ */
+#define MAX_FLOW_DISSECT_HDRS	15
```

And the old definition is removed:
```c
-/* Maximum number of protocol headers that can be parsed in
- * __skb_flow_dissect
- */
-#define MAX_FLOW_DISSECT_HDRS	15
```

But this is in series B, not series A. So in series A patch 9, how is `MAX_FLOW_DISSECT_HDRS` available to the fast-path helpers?

Let me re-read series A patch 9. The diff shows:
```c
 if (++num_hdrs > MAX_FLOW_DISSECT_HDRS)
     return false;
```

If `MAX_FLOW_DISSECT_HDRS` is defined below the fast-path helpers in the file, this would be a compile error. Unless the definition was already moved in an earlier patch in series A...

Looking at series A patch 2, the fast-path helpers are added at line ~1070:
```c
+static bool flow_dissect_fast_ipv4(const struct sk_buff *skb,
```

And `MAX_FLOW_DISSECT_HDRS` is at... let me check the original code. In the original `flow_dissector.c`, `MAX_FLOW_DISSECT_HDRS` is defined at:
```c
/* Maximum number of protocol headers that can be parsed in
 * __skb_flow_dissect
 */
#define MAX_FLOW_DISSECT_HDRS	15
```

This is before `skb_flow_dissect_allowed()`, which is at around line 1000 in the original. The fast-path helpers are added at around line 1070 in patch 2. So `MAX_FLOW_DISSECT_HDRS` is already defined above the fast-path helpers. Good.

But then in series B patch 1, the definition is moved (added above the helpers and removed from the old location). This suggests that in series A, the definition is between the fast-path helpers and `skb_flow_dissect_allowed()`. But that would mean it's below the fast-path helpers... 

Actually, I think I'm overcomplicating this. The original `MAX_FLOW_DISSECT_HDRS` is at a position that's above where the fast-path helpers are inserted. In series B, it's moved even higher to be above `flow_dissect_fast_udp_inner()`. This is a minor cleanup.

OK, let me move on.

## Patch 10: KUnit tests

This is a comprehensive test suite. Key observations:

### a) Test design

The test dissects each packet twice (gates off, gates on) and memcmps the results. This is the right approach for verifying byte-identity.

### b) Truncation sweep

The test cuts every packet at every byte boundary. This is excellent for finding off-by-one errors and missing length checks.

### c) Fuzzer

The seeded fuzzer mutates corpus packets and re-checks equivalence. This is a good guard against divergences the hand-written corpus doesn't cover.

### d) Gates-off negative

The test asserts the fast path never runs when gates are off (observed via counters). This is a good positive control.

### e) Test-only accessors

```c
struct flow_dissector *flow_keys_dissector_symmetric_kunit(void);
u64 flow_dissector_fast_hits_kunit(void);
```

These are compiled only under `CONFIG_FLOW_DISSECTOR_KUNIT_TEST`. This is acceptable for testing.

### f) The `fd_check_one` function

```c
fd_fast_gates_set(false);
memset(&keys_slow, 0, sizeof(keys_slow));
ret_slow = __skb_flow_dissect(&init_net, NULL, fd, &keys_slow,
                              data, proto, 0, hlen, flags);

fd_fast_gates_set(true);
memset(&keys_fast, 0, sizeof(keys_fast));
ret_fast = __skb_flow_dissect(&init_net, NULL, fd, &keys_fast,
                              data, proto, 0, hlen, flags);
fd_fast_gates_set(false);
```

The gates are toggled between the two dissects. This is safe because `static_branch_enable/disable` is synchronous. But there's a concern: on a multi-CPU system, another CPU might be dissecting packets and see the gate state change. In a KUnit test, this shouldn't matter because the test runs in a single thread and there's no real network traffic. But it's worth noting.

Actually, `static_branch_enable/disable` is not instant - it uses IPI to update other CPUs. But for a KUnit test, this is fine because the test waits for the operation to complete.

Hmm, actually, `static_branch_enable` does `cpus_read_lock()` + `on_each_cpu()` which is synchronous. So by the time it returns, all CPUs see the new state. Good.

## Patch 11: Documentation

Adds `Documentation/networking/flow_dissector.rst` and indexes it. Also indexes the previously orphaned `Documentation/bpf/prog_flow_dissector.rst`.

The documentation is well-written and explains the fast paths, the byte-identical contract, and the break-even model. Good.

---

Now let me review Series B.

# Series B (6 patches): opt-in UDP-tunnel inner-flow descent

## Patch 1: VXLAN inner descent

This is the most complex and controversial patch in the series.

### a) The descent changes hashing

This is the key policy issue. The cover letter acknowledges it:
```
Enabling a gate changes skb->hash for that traffic -- a deliberate, per-tunnel-type operator choice
```

This is why the series is split. The descent gates are separate from the byte-identical fast-path gates.

### b) The shared classifier design

The patch introduces `flow_dissect_vxlan_inner_ok()` which is called by both the fast path and the slow path:
```c
static __always_inline bool
flow_dissect_vxlan_inner_ok(const void *data, int thoff, int hlen,
                            __be16 *inner_proto, int *inner_nhoff)
```

This is a good design - it makes fast == slow structural rather than maintained by hand. The `__always_inline` ensures no function call overhead.

### c) The slow-path descent

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

This is inserted after `__skb_flow_dissect_ports()` and before the `switch (fdret)` that processes the result. On a match, it rewrites `proto` and `nhoff` to the inner header and sets `fdret = FLOW_DISSECT_RET_PROTO_AGAIN`, which re-enters the loop.

**Concern**: This changes the slow path's behaviour even when no fast-path gates are enabled. The `flow_dissector_udp_inner_any_key` summary key protects against this - when no descent gates are on, the slow path pays one not-taken branch. But when a descent gate is on, the slow path descends, which is the intended behaviour change.

### d) Port recognition

The patch hardcodes `IANA_VXLAN_UDP_PORT` (4789). The cover letter acknowledges: "non-standard VXLAN ports (e.g. Cilium's 8472) are not descended."

This is a significant limitation. Many VXLAN deployments use non-standard ports. The patch says "Consulting the tunnel netdev for per-netns port config is left as a follow-up." But this means the feature is incomplete for many real-world deployments.

**Question for the author**: How does an operator know which port their VXLAN uses? If they're using 8472 (common in k8s), this feature doesn't help them. Should the sysctl accept a port number instead of a boolean?

### e) The `family` parameter

The `flow_dissect_fast_udp_tunnels()` function takes a `u8 family` parameter, but it's not used for VXLAN (the VXLAN header doesn't vary with the outer family). It's used for FOU/GUE in patch 4. This is forward-looking but adds a parameter that's unused in this patch.

### f) `MAX_FLOW_DISSECT_HDRS` move

The patch moves `MAX_FLOW_DISSECT_HDRS` above the fast-path helpers. This is necessary because `flow_dissect_fast_udp_inner()` uses it. The move is clean.

### g) The `inner_eth_proto` -> `inner_proto` rename

This is a mechanical rename to accommodate GTP-U, which passes a bare IP protocol. The rename is reasonable but touches multiple functions.

## Patch 2: Geneve inner descent

Similar to VXLAN. The Geneve validation:
```c
if (gnv->ver != 0 || gnv->opt_len != 0 || gnv->oam ||
    gnv->proto_type != htons(ETH_P_TEB))
    return false;
```

This is correct - only version 0, no options, no OAM, transparent-Ethernet inner. Good.

But the documentation says:
```
Kept out of the descended set (both paths keep the outer keys): Geneve
with options (opt_len > 0), proto_type other than ETH_P_TEB (rare
L3-Geneve variants), and Geneve-over-IPv6 outer (only IPv4 outer is
handled).
```

Wait, "Geneve-over-IPv6 outer (only IPv4 outer is handled)"? But the code handles both IPv4 and IPv6 outers:
```c
n = outer_v6 ? put_outer_ipv6_udp(buf, htons(GENEVE_UDP_PORT))
             : put_outer_ipv4_udp(buf, htons(GENEVE_UDP_PORT));
```

And the test case `build_geneve(buf, true, false, IPPROTO_TCP, 0)` tests IPv6 underlay. So the documentation is wrong - both outer families are handled.

**This is a documentation bug.** The sysctl doc says "Geneve-over-IPv6 outer (only IPv4 outer is handled)" but the code and tests handle both. This should be fixed.

## Patch 3: GTP-U inner descent

The GTP-U validation:
```c
if (FIELD_GET(GTP1_HDR_VERSION, gtp->flags) != 1 ||
    !(gtp->flags & GTP1_HDR_PT) || (gtp->flags & GTP1_F_MASK) ||
    gtp->type != GTP_TPDU)
    return false;
```

This checks: version 1, PT=1, no optional fields (E/S/PN flags), type 0xFF (G-PDU). Good.

The inner protocol detection:
```c
ver = *((const u8 *)data + nhoff) >> 4;
if (ver != 4 && ver != 6)
    return false;
```

GTP-U carries naked inner IP (no Ethernet), so the version nibble picks v4/v6. Good.

**Concern**: The `GTP1_HDR_VERSION` and `GTP1_HDR_PT` macros are defined locally:
```c
#define GTP1_HDR_VERSION	GENMASK(7, 5)
#define GTP1_HDR_PT		BIT(4)
```

These should probably come from `<net/gtp.h>` instead of being redefined. Let me check if they exist there...

Actually, `GTP1_HDR_VERSION` and `GTP1_HDR_PT` might not exist in the kernel headers. The GTP header structs in `<net/gtp.h>` might use different naming. Defining them locally is acceptable but should be noted.

Actually, looking at the existing kernel code, `include/uapi/linux/gtp.h` defines:
```c
#define GTP_V1	1
```
And `include/net/gtp.h` has `struct gtp1_header` with `flags` field. The version is in bits 7-5 of `flags`. The macros `GTP1_HDR_VERSION` and `GTP1_HDR_PT` are new. They should probably be added to the GTP header file instead of being local.

## Patch 4: FOU/GUE inner descent

### a) The ops hook

The patch adds a `struct flow_dissector_fou_ops` with a single `encap_lookup` function pointer. The fou module registers/unregisters it. This is a reasonable design for avoiding a direct module dependency.

But there's a concern: the hook is global (single ops pointer), not per-netns. If multiple modules try to register, only one succeeds. The `pr_warn` on failure is concerning:
```c
if (flow_dissector_fou_ops_register(&fou_flow_ops))
    pr_warn("fou: flow dissector ops already registered, fou_inner/gue_inner descent unavailable\n");
```

This means if something else has already registered, the fou module's FOU/GUE descent is silently unavailable. This is a fragile design.

### b) The RCU list walk

The patch changes `fou_list` from `list_add` to `list_add_tail_rcu` and from `list_del` to `list_del_rcu`. This is necessary for the lockless walk in `fou_flow_encap_lookup()`.

But there's a concern: the existing `fou_add_to_port_list()` function already holds `fou_lock` (a mutex), and the walk in `fou_flow_encap_lookup()` uses `list_for_each_entry_rcu`. The `_rcu` list operations require that readers use RCU and writers use the `_rcu` variants. The patch changes both readers and writers to RCU, which is correct.

But wait - the existing code in `fou_add_to_port_list()` iterates the list with `list_for_each_entry` (not `_rcu`):
```c
list_for_each_entry(fou, &fn->fou_list, list) {
```

This is under `mutex_lock(&fn->fou_lock)`, so it's safe. But after the patch, the list is manipulated with `_rcu` variants. The existing `list_for_each_entry` under the mutex is still safe because the mutex prevents concurrent modifications. And the new `list_for_each_entry_rcu` in `fou_flow_encap_lookup()` is safe because it's under RCU.

But there's a subtlety: the existing code uses `list_del` (not `list_del_rcu`), which means the entry is immediately unlinked. After the patch, `list_del_rcu` is used, which means the entry is unlinked but the memory might still be accessed by RCU readers. The `kfree_rcu(fou, rcu)` in `fou_release()` ensures the memory is freed only after all RCU readers are done. Good.

But does `struct fou` have an `rcu` member? The diff shows:
```c
static void fou_release(struct fou *fou)
{
    list_del_rcu(&fou->list);
    udp_tunnel_sock_release(fou->sk);
    kfree_rcu(fou, rcu);
}
```

So `struct fou` must have an `rcu` member. Let me check... The existing code doesn't show `struct fou`, but `kfree_rcu(fou, rcu)` requires it. The patch doesn't add the `rcu` member, so it must already exist. OK.

### c) The `guard(rcu)` in `flow_dissect_fou_lookup`

```c
static u16 flow_dissect_fou_lookup(const struct sk_buff *skb, u8 family,
                                   __be16 port, u8 *protocol)
{
    const struct flow_dissector_fou_ops *ops;
    const struct net *net = NULL;

    guard(rcu)();
    ...
}
```

This uses the `guard(rcu)` pattern for automatic RCU unlock. This is the modern C++-style cleanup pattern. It's correct but might not be available in all kernel versions. Let me check... `guard(rcu)` was introduced in recent kernels (6.10+). Since this targets net-next, it should be fine.

### d) Non-skb mode

```c
if (!net || !ops)
    return FOU_ENCAP_UNSPEC;
```

When `skb` is NULL (raw data mode), `net` is NULL, so the lookup returns `FOU_ENCAP_UNSPEC`. This means FOU/GUE descent only works in skb mode. The cover letter acknowledges: "a raw-buffer dissect (skb == NULL) does not descend."

This is correct because the FOU table is per-netns, and without an skb, there's no way to determine the netns.

## Patch 5: KUnit tests for descents

The test design is different from the byte-identical tests: since the descent changes the output, the equivalence is checked by having both the fast and slow paths descend (one with entry gates on, one with entry gates off).

### a) The `fd_descent_check` function

```c
fd_descent_gate_set(descent_gate, true);

fd_fast_gates_set(false);
ret_slow = __skb_flow_dissect(...);

fd_fast_gates_set(true);
ret_fast = __skb_flow_dissect(...);
fd_fast_gates_set(false);

KUNIT_EXPECT_EQ(test, ret_slow, ret_fast);
KUNIT_EXPECT_MEMEQ(test, &keys_slow, &keys_fast, sizeof(keys_slow));
```

With the descent gate on and fast gates off, the slow path descends (via `__skb_flow_dissect_udp_encap()`). With both on, the fast path descends. Both should produce the same result. Good.

### b) The mock FOU ops

The test registers a mock `flow_dissector_fou_ops` for FOU/GUE testing. If the real fou module already owns the hook, the test skips:
```c
ret = flow_dissector_fou_ops_register(&fd_mock_fou_ops);
if (ret == -EBUSY)
    kunit_skip(test, "fou module owns the flow dissector ops");
```

This is a reasonable approach.

### c) The `fd_descent_assert_inner` and `fd_descent_assert_outer` functions

These assert specific field values to guard against both paths being wrong in the same way (which equivalence can't catch). Good.

## Patch 6: Documentation

Adds the "Tunnel inner-flow descent" section to the overview. Well-written.

---

Now let me think about the overall review and structure my findings.

## Overall assessment

### Series A

**Strengths:**
1. Clean, well-structured optimisation
2. Comprehensive KUnit test suite
3. Good documentation
4. The byte-identical contract is well-motivated and mechanically enforced
5. The static key gating is well-designed

**Blockers:**
1. The unconditional `this_cpu_inc` counter cost in patch 8 - taxes all users even when no gates are enabled
2. The sysctl API design - 7 separate boolean knobs is a lot; needs justification or a simpler API

**Substantive:**
1. The `key_control->flags = 0` clobbering in recursive calls is fragile
2. The 4in6 residue handling depends on union layout
3. The `flow_keys_dissector_symmetric` tentative definition is fragile

**Polish:**
1. The `Assisted-by` trailer format should be verified
2. The `__always_inline` on the tunnel classifiers might be excessive

### Series B

**Strengths:**
1. The shared classifier design (one validator per tunnel, called by both paths) is excellent
2. The summary key design keeps the slow-path cost to one branch
3. Good test coverage

**Blockers:**
1. The hashing change is significant and needs broader community buy-in
2. The FOU/GUE ops hook is a global singleton with no fallback

**Substantive:**
1. Hardcoded port numbers limit usefulness
2. The Geneve documentation says "only IPv4 outer is handled" but the code handles both
3. The GTP header macros should be in a header

Let me now write up the review in the requested format.

Actually, let me think more carefully about what the most serious issues are.

### Most serious issues:

1. **Series A patch 8: Unconditional counter cost.** The `this_cpu_inc(flow_dissector_pcpu_stats.dissects)` runs on every dissect, even when all gates are off. This is a tax on the default case. The cover letter says +0.74%, which is "within run-to-run noise", but it's still a regression for users who never enable any gate. This should be gated behind a static key.

2. **Series B: Hashing change.** Enabling a descent gate changes `skb->hash` for tunnel traffic. This affects ECMP, bonding, RPS, etc. An operator might enable it expecting better fairness but inadvertently breaking ECMP or routing. The cover letter acknowledges this, but the risk is real. The gates are per-tunnel-type, which is good, but there's no way to preview the impact before enabling.

3. **Series A: Sysctl API design.** Seven separate boolean knobs is a lot of surface area. The cover letter mentions an "auto" mode as a follow-up, but that's not in this series. An operator has to manually enable each shape, and the counters help them decide, but the UX is complex. A simpler API might be a single "enable all" knob with per-shape overrides.

4. **Series B patch 4: FOU/GUE ops hook.** The global singleton ops with `pr_warn` on failure is fragile. If the fou module fails to register (because something else registered), the feature is silently unavailable. This needs a better design - perhaps per-netns ops or a list of ops.

5. **Series A patch 6: `key_control->flags = 0` clobbering.** The recursive call pattern where the inner helper zeros `flags` and the caller re-establishes ENCAP is fragile. A future change to the flag handling could easily break this.

6. **Series A patch 6: 4in6 residue.** The byte-identity depends on the exact layout of the `addrs` union. If the union layout ever changes (e.g., padding is added), the fast path would diverge.

Let me also think about whether the two-series split is drawn in the right place.

### Two-series split

The split is correct: Series A is byte-identical (no behaviour change), Series B changes hashing. They should be discussed separately. However, the split creates a dependency: Series B builds on Series A's infrastructure (fast-path helpers, KUnit suite, counters). This means Series A must be accepted first, and Series B can't be applied independently.

The cover letter for Series B says "applies on top of A". The prerequisite-patch-id list confirms this. This is the right approach - the policy discussion for Series B can happen independently, but the code depends on Series A.

One concern: Series A's patch 8 (counters) explicitly excludes the descent shapes from counting:
```c
/* Byte-identical shapes only; the behaviour-changing descents are
 * never counted or auto-managed.
 */
```

This is the right call - the descent gates should never be auto-managed because they change hashing. But it means the counters can't help an operator decide whether to enable a descent gate. The operator has to know their traffic mix independently.

OK let me also look at some more specific issues:

### Series A Patch 1: static key for BPF program lookup

Actually, I want to look at this more carefully. The patch adds `netns_bpf_attach_type_need(type)` / `unneed(type)` for the FLOW_DISSECTOR type in the legacy attach/detach paths. But `netns_bpf_attach_type_need()` and `unneed()` are functions that switch on the type. The patch adds `NETNS_BPF_FLOW_DISSECTOR` to both functions.

But wait - `netns_bpf_attach_type_need()` and `unneed()` are also called from the link attach/release paths. Looking at the existing code (before the patch), these functions already handle `NETNS_BPF_SK_LOOKUP` but not `NETNS_BPF_FLOW_DISSECTOR`. The patch adds `NETNS_BPF_FLOW_DISSECTOR` to both functions.

So after the patch:
- Link attach: calls `netns_bpf_attach_type_need(NETNS_BPF_FLOW_DISSECTOR)` -> `static_branch_inc(&netns_bpf_flow_dissector_enabled)`
- Legacy attach: calls `netns_bpf_attach_type_need(NETNS_BPF_FLOW_DISSECTOR)` (added in `netns_bpf_prog_attach()`)
- Link release: calls `netns_bpf_attach_type_unneed(NETNS_BPF_FLOW_DISSECTOR)` -> `static_branch_dec(&netns_bpf_flow_dissector_enabled)`
- Legacy detach: calls `netns_bpf_attach_type_unneed(NETNS_BPF_FLOW_DISSECTOR)` (added in `__netns_bpf_prog_detach()`)
- Pernet exit: calls `unneed` for both links and legacy progs

This looks correct. The count tracks the number of attached programs (whether via link or legacy attach).

But there's a subtle issue: in `netns_bpf_prog_attach()`, the `need()` is called only on fresh attach (not replacement). But what if a link-attached program is replaced by a legacy-attached program? The link release would `unneed()`, and the legacy attach would `need()` (since `attached` is NULL in `netns_bpf_prog_attach()` - wait, no, the link-attached program is in `net->bpf.progs[type]`... actually, I'm not sure about the interaction between link and legacy attach.

Let me think about this more carefully. The link attach path sets `net->bpf.progs[type]` and calls `need()`. The legacy attach path also sets `net->bpf.progs[type]` and calls `need()` (on fresh attach). If a link is attached and then a legacy attach replaces it:
1. Link attach: `progs[type] = prog_link`, `need()` -> count = 1
2. Legacy attach: `progs[type] = prog_legacy`, `attached = prog_link`, `bpf_prog_put(prog_link)`, no `need()` (replacement) -> count = 1

Wait, but the link is still attached! The link's `prog` pointer is still set. Actually no - `netns_bpf_prog_attach()` replaces `net->bpf.progs[type]` but doesn't release the link. The link and the legacy prog are in different slots... actually, I think `net->bpf.progs[type]` is the legacy prog slot, and links are in `net->bpf.links[type]`. Let me not go down this rabbit hole - the BPF netns attach machinery is complex and I'm not going to fully verify it here. The patch mirrors the existing `bpf_sk_lookup_enabled` pattern, which gives me confidence it's correct.

Actually, I realize I should focus on the most impactful review points rather than trying to verify every detail. Let me structure the review now.

Let me also think about some specific code issues:

### Series A, Patch 2: `proc_do_static_key` usage

The sysctl handler is `proc_do_static_key`, which operates on `&flow_dissector_eth_ip_key.key`. This is the `static_key` inside the `static_key_false` wrapper. The `proc_do_static_key` function handles the read/write of the key's enabled state. This is a clean approach.

But there's a concern: `proc_do_static_key` is not a standard kernel API. Let me check if it exists... Actually, it's used in `net/mpls/sysctl.c` and possibly other places. It's a kernel function that handles static key toggling via sysctl. OK, it's a known pattern.

### Series A, Patch 8: Counter for eth_ip in the slow path

The eth_ip slow-path counter is placed at the `out_good` label:
```c
if (ret && eth_ip_top &&
    !(key_control->flags & FLOW_DIS_ENCAPSULATION) &&
    (ip_proto == IPPROTO_TCP || ip_proto == IPPROTO_UDP))
    flow_dissector_count_slow(FLOW_DISSECTOR_SHAPE_ETH_IP);
```

But `eth_ip_top` is set when `nhoff == nhoff_init`:
```c
if (nhoff == nhoff_init)
    eth_ip_top = true;
```

And `nhoff_init` is saved before `proto_again:`:
```c
nhoff_init = nhoff;
```

So `eth_ip_top` is true only when the IP header is at the initial offset (no VLAN/PPPoE/etc. before it). This correctly excludes VLAN/PPPoE-tagged packets from the eth_ip count. Good.

But there's a subtle issue: `nhoff` might change during the loop (e.g., after VLAN processing), and the check `nhoff == nhoff_init` is done inside the IP case:
```c
case htons(ETH_P_IP):
    ...
    if (nhoff == nhoff_init)
        eth_ip_top = true;
    nhoff += iph->ihl * 4;
```

Wait, this checks `nhoff` before advancing it. So `eth_ip_top` is true if the IP header starts at the initial offset. But what if there's a VLAN tag? Then `nhoff` would have been advanced past the VLAN tag, and `nhoff != nhoff_init`, so `eth_ip_top` would be false. Good.

But what about the case where the packet is Eth + IP (no VLAN)? Then `nhoff` starts at the Ethernet header size (14 bytes), and `nhoff_init` is also 14. The IP case checks `nhoff == nhoff_init` (14 == 14), so `eth_ip_top` is true. Good.

Actually, wait. Looking at the code more carefully:
```c
nhoff_init = nhoff;

proto_again:
    ...
    case htons(ETH_P_IP):
        ...
        if (nhoff == nhoff_init)
            eth_ip_top = true;
```

But `nhoff` might be modified between `nhoff_init = nhoff` and the `proto_again:` label. Let me check... Actually, `nhoff_init` is set after the fast-path check:
```c
this_cpu_inc(flow_dissector_pcpu_stats.dissects);

if (flow_dissect_fast(skb, flow_dissector, target_container,
                      data, proto, nhoff, hlen, flags))
    return true;

...
nhoff_init = nhoff;

proto_again:
```

So `nhoff_init` is set just before the slow-path loop starts. At this point, `nhoff` is the offset to the first network header (after Ethernet). If the first ethertype is IP, `nhoff == nhoff_init` in the IP case, and `eth_ip_top` is true. If there's a VLAN tag, the VLAN case advances `nhoff`, so when the IP case is reached, `nhoff != nhoff_init`, and `eth_ip_top` is false. Correct.

### Series B, Patch 1: The `__skb_flow_dissect_udp_encap` placement

The slow-path descent is placed after `__skb_flow_dissect_ports()`:
```c
__skb_flow_dissect_ports(skb, flow_dissector, target_container,
                         data, nhoff, ip_proto, hlen);

/* Opt-in UDP-tunnel descent, mirroring the fast path so fast == slow. */
if (ip_proto == IPPROTO_UDP &&
    fdret == FLOW_DISSECT_RET_CONTINUE &&
    ...
    __skb_flow_dissect_udp_encap(skb, key_control, data, &proto, &nhoff,
                                 hlen, ...))
    fdret = FLOW_DISSECT_RET_PROTO_AGAIN;
```

This means the outer UDP ports are already written to `key_ports` before the descent. When the descent re-enters the loop, the inner IP/TCP/UDP processing will overwrite `key_ports` with the inner ports. So the final `key_ports` has the inner ports, which is correct.

But there's a concern: the outer UDP ports are written first, then overwritten. This is the same as the IPIP/GRE case in the slow path (where the outer IP addrs are written, then overwritten by the inner). So it's consistent.

But wait - what about `FLOW_DISSECTOR_KEY_ENC_IP`? If the dissector requests the enc IP key, the slow path might write it. But the descent doesn't write any enc keys. Looking at the slow path... `FLOW_DISSECTOR_KEY_ENC_IP` is filled by `skb_flow_dissect_tunnel_info()`, not by the main dissection loop. So the descent doesn't affect it. Good.

### Series B: The `FLOW_DISSECTOR_F_STOP_AT_ENCAP` / `STOP_BEFORE_ENCAP` handling

The slow-path descent checks:
```c
!(flags & (FLOW_DISSECTOR_F_STOP_BEFORE_ENCAP |
           FLOW_DISSECTOR_F_STOP_AT_ENCAP))
```

And the fast-path dispatcher already rejects these flags:
```c
if (flags & ~(unsigned int)(FLOW_DISSECTOR_F_PARSE_1ST_FRAG |
                            FLOW_DISSECTOR_F_STOP_AT_FLOW_LABEL))
    return false;
```

So the fast path never sees `STOP_AT_ENCAP` / `STOP_BEFORE_ENCAP` - it defers to the slow path. And the slow path checks these flags before descending. Good - callers that want to stop at the outer tuple are not affected.

But there's a subtlety: the fast path rejects `STOP_AT_ENCAP` / `STOP_BEFORE_ENCAP` at the dispatcher level, which means the entire fast path is disabled for these flags, not just the descent. This is correct but conservative - a caller passing `STOP_AT_ENCAP` won't get the eth_ip fast path even for a non-tunneled packet. But `STOP_AT_ENCAP` is typically only passed by tunnel drivers, and they're dissecting tunnel packets, so this is probably fine.

Actually wait, let me re-read the fast-path dispatcher:
```c
if (flags & ~(unsigned int)(FLOW_DISSECTOR_F_PARSE_1ST_FRAG |
                            FLOW_DISSECTOR_F_STOP_AT_FLOW_LABEL))
    return false;
```

This rejects ANY flag other than `PARSE_1ST_FRAG` and `STOP_AT_FLOW_LABEL`. So `STOP_AT_ENCAP`, `STOP_BEFORE_ENCAP`, and any other flag causes the fast path to defer entirely. This is the right call for byte-identity - the fast path only handles the simplest case.

### Series B: The test for STOP flags

```c
static void fd_descent_stop_flags_test(struct kunit *test)
{
    ...
    fd_descent_gate_set(&flow_dissector_vxlan_inner_key, true);
    for (i = 0; i < ARRAY_SIZE(stop_flags); i++) {
        fd_check_one(test, &flow_keys_dissector, buf,
                     htons(ETH_P_IP), len, stop_flags[i]);
        ...
    }
    fd_descent_gate_set(&flow_dissector_vxlan_inner_key, false);
}
```

This test calls `fd_check_one` with the STOP flags. `fd_check_one` dissects with gates off and gates on, and checks equivalence. With the STOP flags, the fast path defers (dispatcher rejects the flags), and the slow path doesn't descend (the STOP flag check prevents it). So both paths produce the outer tuple. Good.

But the test also asserts the outer tuple directly:
```c
KUNIT_EXPECT_FALSE(test, keys.control.flags & FLOW_DIS_ENCAPSULATION);
KUNIT_EXPECT_EQ(test, keys.basic.ip_proto, IPPROTO_UDP);
```

This is the right approach - verify the actual values, not just equivalence.

OK, I think I have a thorough understanding now. Let me write the review.

Actually, one more thing I want to check: the `proc_do_static_key` function. Is it safe to call from a sysctl handler? Does it handle the `write` flag correctly?

Looking at the kernel source, `proc_do_static_key` is defined in `kernel/sysctl.c`:
```c
int proc_do_static_key(const struct ctl_table *table, int write,
                       void *buffer, size_t *lenp, loff_t *ppos)
```

It handles both read (returns the current state) and write (toggles the static key). For write, it reads a boolean value from the buffer and enables/disables the key accordingly. This is a standard pattern used elsewhere in the kernel.

But there's a concern: `proc_do_static_key` calls `static_branch_enable`/`static_branch_disable`, which do `cpus_read_lock()` + `on_each_cpu()`. This is expensive and shouldn't be done in a fast path. But since it's only called on sysctl write, it's fine.

### Series A Patch 3: The `proc_set_vlan_key` / `proc_set_qinq_key` handlers

These handlers call `proc_do_static_key` first, then check the state and adjust the other key. The concern is that `proc_do_static_key` might fail (return non-zero), and the handler still checks the key state. Let me look:

```c
static int proc_set_vlan_key(const struct ctl_table *table, int write,
                             void *buffer, size_t *lenp, loff_t *ppos)
{
    int ret;

    ret = proc_do_static_key(table, write, buffer, lenp, ppos);
    if (ret == 0 && write &&
        !static_branch_unlikely(&flow_dissector_vlan_key) &&
        static_branch_unlikely(&flow_dissector_qinq_key))
        static_branch_disable(&flow_dissector_qinq_key);
    return ret;
}
```

If `proc_do_static_key` fails, `ret != 0`, and the handler skips the coupling check. Good.

But there's a subtlety: `static_branch_unlikely` in a sysctl handler is unusual. The `unlikely` annotation is for the branch predictor, but in a sysctl handler, the branch prediction doesn't matter. It's not wrong, just unnecessary. The `static_branch_unlikely` macro returns the current key state regardless of the annotation.

Actually, `static_branch_unlikely` is the function that tests the key state, not just an annotation. It returns `true` if the key is enabled. The `unlikely` part affects the code generation when the key is disabled (the branch is predicted not-taken). In a sysctl handler, this doesn't matter, but it's not wrong.

OK, let me also think about the `static_key_enabled` function used in `flow_dissector_shape_gate`:
```c
static bool flow_dissector_shape_gate(enum flow_dissector_shape shape)
{
    switch (shape) {
    case FLOW_DISSECTOR_SHAPE_ETH_IP:
        return static_key_enabled(&flow_dissector_eth_ip_key);
    ...
    }
}
```

`static_key_enabled` returns the current key state. This is used for the `/proc/net/flow_dissector_stats` output. Good.

Let me also check if there are any issues with the test's `fd_fast_gates_set` function:
```c
static void fd_fast_gates_set(bool on)
{
    int i;

    for (i = 0; i < ARRAY_SIZE(fd_fast_gates); i++) {
        if (on)
            static_branch_enable(fd_fast_gates[i]);
        else
            static_branch_disable(fd_fast_gates[i]);
    }
}
```

This enables/disables all gates at once. Each `static_branch_enable`/`disable` does `cpus_read_lock()` + `on_each_cpu()`, which is expensive. Calling it in a loop is O(n * cpus). For 7 gates, this is 7 * `on_each_cpu()` calls. This is slow but acceptable for a test.

One more thing: the test's `fd_check_one` function calls `fd_fast_gates_set(false)` and then `fd_fast_gates_set(true)` for each test case. This means each test case does 14 `static_branch_enable/disable` calls. For 53 test cases, that's 742 calls. This is slow but acceptable for KUnit.

OK, I think I've done enough analysis. Let me write the review now.

Let me also consider: are there any safety issues with the fast path reading packet data directly?

The fast path reads data via `const u8 *data` with bounds checking via `hlen`. The key checks are:
- `hlen - nhoff < sizeof(*iph) + 4` (IPv4)
- `hlen - nhoff < sizeof(*iph) + 4` (IPv6)
- `hlen - nhoff < sizeof(*vlan)` (VLAN)
- `hlen - nhoff < sizeof(*hdr)` (PPPoE, MPLS, GRE)

These checks ensure the fast path only reads within the linear head. If data is beyond the linear head, the fast path defers. Good.

But there's a subtle issue: `hlen` is `skb_headlen(skb)` in skb mode. The fast path reads up to `hlen` bytes from `data`. But `data` is `skb->data`, which is the start of the linear head. So the fast path reads `[data, data + hlen)`, which is the linear head. This is safe.

What about the non-linear skb test case? The test creates a non-linear skb with 8 bytes in the linear head and the rest in a frag. The fast path checks `hlen - nhoff < sizeof(*iph) + 4 = 24`, and `hlen = 8`, so it defers. The slow path pulls from the frag and dissects correctly. Good.

OK, now let me think about what the most important review points are, in order of severity.

## Blockers:

1. **Series A, Patch 8: Unconditional per-dissect counter cost.** The `this_cpu_inc(flow_dissector_pcpu_stats.dissects)` runs on every dissect even when all gates are off. This is a regression for the default case. The +0.74% is small but real and paid by everyone. The counters should be gated behind their own static key or made opt-in.

2. **Series B: Hashing change needs broader discussion.** Changing `skb->hash` for tunnel traffic affects ECMP, bonding, RPS, etc. The opt-in gate model is sound, but the change is significant enough that it needs buy-in from routing and tunneling maintainers, not just the flow dissector maintainer.

3. **Series A: Seven per-shape sysctls is too much surface area.** The API design needs simplification. A single "enable" knob with auto-detection (the proposed follow-up) would be better. In the meantime, the seven knobs create maintenance and documentation burden.

Actually, wait. Let me reconsider point 3. The seven knobs are all default-off and the counters help the operator decide. The "auto" mode is a follow-up. Is seven knobs really a blocker? It's more of a substantive concern. The operator can ignore all of them and the behaviour is unchanged. The knobs are only for operators who want to optimise. I'll downgrade this to substantive.

And for point 1, let me reconsider. The +0.74% is "within run-to-run noise" according to the cover letter. Is it really a blocker? The counter is needed for the operator to decide which gates to enable. Without it, the feature is much less useful. But the cost is paid by everyone, even those who never use the feature.

Actually, I think the counter cost is a substantive issue, not a blocker. The +0.74% is small, and the counters are essential for the feature's usability. But the author should consider gating them behind a static key.

Let me re-evaluate what's truly a blocker vs. substantive:

**Blockers** (must fix before applying):
- The recursion safety issue in series A patch 9: the `num_hdrs` initial counts need to be verified more carefully. Actually, the KUnit test covers this, and the comment explains the conservative approach. I'll downgrade to substantive.
- The FOU/GUE ops hook design in series B patch 4: the global singleton with `pr_warn` on failure is fragile. This is a design issue that needs to be resolved before merging.

Actually, I think the most serious issues are:

1. **Series A patch 8: Unconditional counter cost** - substantive, not a blocker, but should be addressed
2. **Series B: Hashing change** - needs broader discussion, but the opt-in gate model is sound
3. **Series B patch 4: FOU/GUE ops hook** - the global singleton design is fragile
4. **Series A: Sysctl API complexity** - seven knobs is a lot
5. **Series A patch 6: Recursive flag clobbering** - fragile pattern
6. **Series B: Hardcoded port numbers** - limits usefulness

Let me also think about whether there are any correctness issues I've missed.

### Correctness check: IPv4 fragment handling

The fast path defers on fragmented IPv4:
```c
if (unlikely(iph->frag_off & htons(IP_MF | IP_OFFSET)))
    return false;
```

This checks both MF (More Fragments) and the offset. If either is set, it defers. But what about the case where `FLOW_DISSECTOR_F_PARSE_1ST_FRAG` is set and the packet is a first fragment (MF=1, offset=0)? The slow path would parse the first fragment. The fast path defers, and the slow path handles it. This is correct for byte-identity.

### Correctness check: VLAN hw-accel

The fast path handles hw-accel VLAN:
```c
if (vlan_depth == 0 && skb && skb_vlan_tag_present(skb)) {
    tci_id = skb_vlan_tag_get_id(skb);
    tci_prio = skb_vlan_tag_get_prio(skb);
    inner_proto = skb->protocol;
}
```

But there's a subtle issue: when `skb_vlan_tag_present(skb)` is true, the VLAN tag is in skb metadata, not in the packet data. The `data` pointer starts at the Ethernet header, and `nhoff` is past the Ethernet header. So the packet data at `nhoff` is the inner protocol, not the VLAN tag. The fast path correctly reads the tag from skb metadata and the inner protocol from `skb->protocol`.

But what about the case where the skb has a hw-accel VLAN tag AND the packet data also contains a VLAN tag? This shouldn't happen - if the tag is hw-accel, it's been stripped from the data. So this is fine.

### Correctness check: `skb->protocol` in hw-accel VLAN

When `skb_vlan_tag_present(skb)` is true, `skb->protocol` is the VLAN TPID (e.g., `ETH_P_8021Q`), not the inner protocol. Wait, actually... let me check.

When a VLAN tag is hw-accelerated, `skb->protocol` is set to the VLAN TPID (e.g., `ETH_P_8021Q`), and `skb->vlan_proto` holds the TPID. The inner protocol is in the packet data after the VLAN tag... but the tag has been stripped, so the inner protocol is at the current `nhoff`.

Actually, I think the code is wrong here. Let me re-read:
```c
if (vlan_depth == 0 && skb && skb_vlan_tag_present(skb)) {
    tci_id = skb_vlan_tag_get_id(skb);
    tci_prio = skb_vlan_tag_get_prio(skb);
    inner_proto = skb->protocol;
}
```

When `skb_vlan_tag_present(skb)` is true, `skb->protocol` is the VLAN TPID (e.g., `ETH_P_8021Q`), not the inner protocol. The inner protocol should be read from the packet data at `nhoff` (which is past the Ethernet header, at the inner protocol position).

Wait, actually, I need to check how the slow path handles this. In the slow path:
```c
if (skb_vlan_tag_present(skb)) {
    ...
    key_vlan->vlan_id = skb_vlan_tag_get_id(skb);
    ...
    key_vlan->vlan_eth_type = skb->protocol;  // Wait, is this right?
    ...
}
```

Hmm, actually, when a VLAN tag is hw-stripped, the network stack sets `skb->protocol` to the inner protocol (not the VLAN TPID). The VLAN TPID is in `skb->vlan_proto`. So `skb->protocol` is the inner protocol (e.g., `ETH_P_IP`).

Let me verify this by looking at `__skb_flow_dissect()`:
```c
if (skb_vlan_tag_present(skb)) {
    ...
    key_vlan->vlan_tpid = skb->vlan_proto;
    key_vlan->vlan_eth_type = skb->protocol;
    ...
}
```

Wait, I don't see this in the diff. Let me look at the slow path's VLAN handling more carefully.

Actually, looking at the slow path:
```c
if (dissector_vlan == FLOW_DISSECTOR_KEY_MAX) {
    dissector_vlan = FLOW_DISSECTOR_KEY_VLAN;
    ...
}
```

The slow path's VLAN handling is complex. Let me not try to verify this in detail - the KUnit test covers it, and the test's `fd_fast_skb_hwaccel_vlan_test` specifically tests the hw-accel VLAN case. If the inner protocol were wrong, the test would fail.

Actually, I realize I should trust the KUnit test here. The test creates an skb with a hw-accel VLAN tag and checks equivalence between the fast and slow paths. If the fast path reads the wrong protocol, the test would catch it.

But let me still note this as a question to ask the author, because it's a subtle area.

### Correctness check: `key_control->thoff` in MPLS

In the MPLS fast path:
```c
key_control->thoff = min_t(u16, nhoff, skb ? skb->len : hlen);
```

But `thoff` is supposed to be the transport header offset. For MPLS with BoS=1, there's no transport header - the slow path returns `OUT_GOOD` without descending. So what does `thoff` mean in this context?

Looking at the slow path, at the `out_good` label:
```c
key_control->thoff = min_t(u16, nhoff, skb ? skb->len : hlen);
```

So `thoff` is set to the current `nhoff` (past the last parsed header), regardless of whether there's a transport header. For MPLS, this is past the MPLS label. The fast path matches this. Good.

### Correctness check: `key_basic->n_proto` in MPLS

In the MPLS fast path:
```c
key_basic->n_proto = proto;
```

Where `proto` is the MPLS ethertype (`ETH_P_MPLS_UC` or `ETH_P_MPLS_MC`). This matches the slow path, which sets `n_proto = proto` at the `out_good` label. Good.

### Correctness check: `key_basic->ip_proto` in MPLS

In the MPLS fast path:
```c
key_basic->ip_proto = 0;
```

The slow path sets `ip_proto = 0` (initialized at the top of the function) and never changes it for MPLS. At `out_good`, `key_basic->ip_proto = ip_proto = 0`. Good.

OK, I'm now confident in my understanding. Let me write the review.

Actually, one more thing: let me check the Geneve documentation issue more carefully.

In series B patch 2, the documentation says:
```
Kept out of the descended set (both paths keep the outer keys): Geneve
with options (opt_len > 0), proto_type other than ETH_P_TEB (rare
L3-Geneve variants), and Geneve-over-IPv6 outer (only IPv4 outer is
handled).
```

But the code handles both IPv4 and IPv6 outers:
```c
n = outer_v6 ? put_outer_ipv6_udp(buf, htons(GENEVE_UDP_PORT))
             : put_outer_ipv4_udp(buf, htons(GENEVE_UDP_PORT));
```

And the test:
```c
len = build_geneve(buf, true, false, IPPROTO_TCP, 0);
fd_descent_run(test, buf, len, htons(ETH_P_IPV6), g);
fd_descent_assert_inner(test, buf, len, htons(ETH_P_IPV6), g, false);
```

So the documentation is wrong - Geneve-over-IPv6 IS handled. This should be fixed.

Wait, let me re-read the documentation more carefully. It says "Geneve-over-IPv6 outer (only IPv4 outer is handled)". This is in the "Kept out of the descended set" list, meaning these are cases that are NOT descended. But the code clearly handles IPv6 outers. So the documentation is incorrect - IPv6 outers ARE handled, not kept out.

This is a clear documentation bug.

Let me also check the GTP-U documentation:
```
Kept out of the descended set (both paths retain): GTPv0 (legacy), GTP'
(charging, PT=0), G-PDU type other than 0xFF, GTP-U with extension
headers / N-PDU / sequence flags set, and GTP-U over IPv6 outer.
```

Again, "GTP-U over IPv6 outer" is listed as not handled, but the code handles it:
```c
n = outer_v6 ? put_outer_ipv6_udp(buf, htons(GTP1U_PORT))
             : put_outer_ipv4_udp(buf, htons(GTP1U_PORT));
```

And the test:
```c
len = build_gtpu(buf, true, false, IPPROTO_TCP, 0xff);
fd_descent_run(test, buf, len, htons(ETH_P_IPV6), g);
fd_descent_assert_inner(test, buf, len, htons(ETH_P_IPV6), g, false);
```

So the GTP-U documentation is also wrong - GTP-U over IPv6 IS handled.

These are clear documentation bugs that should be fixed before merging.

Now, let me also think about whether there are any issues with the `__always_inline` on the tunnel classifiers:

```c
static __always_inline bool
flow_dissect_vxlan_inner_ok(const void *data, int thoff, int hlen,
                            __be16 *inner_proto, int *inner_nhoff)
```

The `__always_inline` is used to ensure no function call overhead. But these functions are called from both the fast and slow paths, which are in the same translation unit. The compiler would likely inline them anyway. The `__always_inline` is a strong hint that might increase code size if the function is called from multiple places. But since the functions are small, this is probably fine.

OK, I think I'm ready to write the review now. Let me organize it by severity.

Let me also note: the cover letter mentions "Assisted-by: Claude:claude-fable-5 sparse smatch" in every patch. The format should be checked against `Documentation/process/coding-assistants.rst`. The format seems to be `Assisted-by: Name:details`, but I'm not sure if "Claude:claude-fable-5 sparse smatch" is the correct format. The "sparse smatch" part seems odd - it looks like it's saying Claude assisted with sparse and smatch, but it's actually a model identifier. This should be clarified.

Actually, looking more carefully at the trailer:
```
Assisted-by: Claude:claude-fable-5 sparse smatch
```

This looks like it's trying to say "Claude (model claude-fable-5) assisted with sparse and smatch". But the format is confusing. The `coding-assistants.rst` format might require a specific structure. Let me not dwell on this - it's a polish issue.

Let me now write the final review.

One more thing: I should check if the two-series split is drawn in the right place.

The split is:
- Series A: byte-identical fast paths (no behaviour change)
- Series B: behaviour-changing tunnel descents (changes hashing)

This is the right split. Series A is a pure optimisation - the output is unchanged, only the CPU cost is reduced. Series B changes the output (the hash reflects the inner flow instead of the outer). These are fundamentally different policy discussions and should be separate.

However, there's a dependency: Series B builds on Series A's infrastructure. Specifically:
- Series B uses the fast-path helpers (`flow_dissect_fast_ipv4/ipv6`) from Series A
- Series B extends the KUnit suite from Series A
- Series B uses the `MAX_FLOW_DISSECT_HDRS` bound from Series A patch 9

This dependency is acknowledged in the cover letter and the prerequisite-patch-id list. The split is correct.

One concern: Series A's patch 8 (counters) explicitly excludes the descent shapes:
```c
/* Byte-identical shapes only; the behaviour-changing descents are
 * never counted or auto-managed.
 */
```

This means the counters can't help an operator decide whether to enable a descent gate. The operator has to know their traffic mix independently. This is a deliberate design choice - the descents change hashing and should never be auto-managed. But it limits the observability for Series B.

OK, I'm now ready to write the review. Let me structure it as:
1. Blockers (must fix before applying)
2. Substantive (should fix or justify)
3. Polish (nice to fix)

For each finding, I'll cite the series, patch number, and quote the relevant lines.

Let me draft the review:

---

## Series A Review

### Blockers

**A-1. Patch 8: Unconditional per-dissect counter tax on the default path**

The `this_cpu_inc(flow_dissector_pcpu_stats.dissects)` in `__skb_flow_dissect()` runs on every dissect, even when all gates are off:

```c
this_cpu_inc(flow_dissector_pcpu_stats.dissects);

if (flow_dissect_fast(skb, flow_dissector, target_container,
                      data, proto, nhoff, hlen, flags))
    return true;
```

The cover letter acknowledges +0.74% on a CPU-bound pktgen soak. That is a real regression for every user of the flow dissector, including those who never enable a gate. The counters are essential for the feature's usability, but they should not tax the default case.

**Fix**: Gate the `dissects` counter (and the per-shape slow-path counters) behind a static key, enabled on first write to any `/proc/sys/net/flow_dissector/*` sysctl, or provide a separate `stats` sysctl that enables counting.

Actually, I realize the +0.74% is within noise and might not be a blocker. Let me think about this more carefully.

The +0.74% is on a CPU-bound pktgen soak. In real workloads, the dissector is a smaller fraction of CPU time, so the impact would be even smaller. And the counters are essential for the feature.

But the principle is important: the default case should not regress. Even +0.74% is a regression. And the counters are only useful if you plan to enable gates.

I'll keep this as a blocker but acknowledge it's borderline.

**A-2. Patch 6: Recursive `key_control->flags = 0` clobbering is a latent bug**

The IPIP and GRE inner helpers rely on the inner IP helper zeroing `key_control->flags` and then re-establishing `FLOW_DIS_ENCAPSULATION` after the inner returns:

```c
/* Re-establish ENCAP after the inner pass zeroed key_control->flags. */
if (dissector_uses_key(flow_dissector,
                       FLOW_DISSECTOR_KEY_CONTROL)) {
    key_control = skb_flow_dissector_target(flow_dissector,
                                            FLOW_DISSECTOR_KEY_CONTROL,
                                            target_container);
    key_control->flags |= FLOW_DIS_ENCAPSULATION;
}
```

This is fragile because:
1. The inner helper's `key_control->flags = 0` is correct for top-level calls but wrong for recursive calls
2. A future change to the flag handling (e.g., adding a new flag) could silently break this
3. The pattern is duplicated in `flow_dissect_fast_ipip_inner()` and `flow_dissect_fast_gre_inner()`, and again in series B's `flow_dissect_fast_udp_inner()`

**Fix**: Thread a `bool is_inner` parameter to the IP helpers, or split the flag-zeroing out of the helpers and into the dispatcher.

Hmm, actually, this is more of a substantive concern than a blocker. The code is correct as written - the KUnit test verifies it. The concern is about future maintainability. Let me downgrade to substantive.

Let me reconsider what's truly a blocker. I think the only true blockers are:
1. Things that are incorrect (bugs)
2. Things that are unsafe (security issues)
3. Things that are fundamentally the wrong design

Let me re-evaluate:

1. **Counter cost** - not incorrect, not unsafe, just a small regression. Substantive.
2. **Flag clobbering** - correct but fragile. Substantive.
3. **Seven sysctls** - design choice, not wrong. Substantive.
4. **FOU/GUE ops hook** - fragile design. Substantive.
5. **Hardcoded ports** - limitation, not wrong. Substantive.
6. **Geneve/GTP-U doc bugs** - documentation is wrong. Polish, but should be fixed.

Actually, let me look for actual bugs:

### Bug check: `eth_ip_top` with IPv6

The `eth_ip_top` flag is set in both the IPv4 and IPv6 cases:
```c
case htons(ETH_P_IP):
    ...
    if (nhoff == nhoff_init)
        eth_ip_top = true;
    ...

case htons(ETH_P_IPV6):
    ...
    if (nhoff == nhoff_init)
        eth_ip_top = true;
    ...
```

And the counter check:
```c
if (ret && eth_ip_top &&
    !(key_control->flags & FLOW_DIS_ENCAPSULATION) &&
    (ip_proto == IPPROTO_TCP || ip_proto == IPPROTO_UDP))
    flow_dissector_count_slow(FLOW_DISSECTOR_SHAPE_ETH_IP);
```

This counts both IPv4 and IPv6 as `eth_ip`. That's correct - the `eth_ip` shape covers both.

### Bug check: VLAN counter placement

The slow-path VLAN counter is placed when the VLAN tag is first seen:
```c
if (dissector_vlan == FLOW_DISSECTOR_KEY_MAX) {
    dissector_vlan = FLOW_DISSECTOR_KEY_VLAN;
    flow_dissector_count_slow(FLOW_DISSECTOR_SHAPE_VLAN);
} else if (dissector_vlan == FLOW_DISSECTOR_KEY_VLAN) {
    dissector_vlan = FLOW_DISSECTOR_KEY_CVLAN;
    flow_dissector_count_slow(FLOW_DISSECTOR_SHAPE_QINQ);
}
```

This counts the first VLAN tag as `vlan` and the second as `qinq`. But the `dissector_vlan` state machine starts at `FLOW_DISSECTOR_KEY_MAX`, transitions to `VLAN` on the first tag, then to `CVLAN` on the second. So the first tag is counted as `vlan` and the second as `qinq`. Good.

But what about the fast-path VLAN counter? In `flow_dissect_fast_vlan`:
```c
if (ok)
    flow_dissector_count_fast(vlan_depth == 0 ?
                              FLOW_DISSECTOR_SHAPE_VLAN :
                              FLOW_DISSECTOR_SHAPE_QINQ);
```

This counts depth 0 as `vlan` and depth >= 1 as `qinq`. But the slow path counts the first tag (depth 0) as `vlan` and the second (depth 1) as `qinq`. So they match. Good.

But wait - there's a comment:
```c
/* Count only on full success -- a miss defers and the slow path
 * counts the occurrence. Depth 0 counts vlan, depth >= 1 qinq; a
 * double-tagged hit counts both, as the slow path does.
 */
```

"a double-tagged hit counts both" - does it? The fast path counts only once: `vlan_depth == 0 ? VLAN : QINQ`. For a double-tagged packet, `vlan_depth` starts at 0 and the function recurses with `vlan_depth + 1 = 1`. The outer call counts `VLAN` (depth 0), the inner call counts `QINQ` (depth 1). So yes, both are counted. Good.

But the slow path also counts both: the first tag triggers `VLAN` and the second triggers `QINQ`. So both paths count both shapes for a double-tagged packet. Good.

Actually wait, let me re-read the fast path. `flow_dissect_fast_vlan` is called with `vlan_depth = 0` initially. It processes the first tag, then recurses with `vlan_depth = 1`:
```c
case htons(ETH_P_8021Q):
case htons(ETH_P_8021AD):
    ok = flow_dissect_fast_vlan(skb, flow_dissector,
                                target_container, data,
                                inner_proto, nhoff, hlen,
                                vlan_depth + 1);
    break;
```

After the recursive call returns, the counting happens:
```c
if (ok)
    flow_dissector_count_fast(vlan_depth == 0 ?
                              FLOW_DISSECTOR_SHAPE_VLAN :
                              FLOW_DISSECTOR_SHAPE_QINQ);
return ok;
```

So for a double-tagged packet:
1. Outer call (depth 0): processes first tag, recurses with depth 1
2. Inner call (depth 1): processes second tag, calls IP helper, returns true
3. Inner call counts QINQ (depth 1)
4. Outer call counts VLAN (depth 0)

Yes, both are counted. And the slow path also counts both. Good.

### Bug check: `nhoff_init` and `eth_ip_top` interaction with VLAN

When a VLAN-tagged packet enters the slow path, `nhoff_init` is saved before the VLAN processing. After VLAN processing, `nhoff` is advanced past the VLAN tag. When the IP case is reached, `nhoff != nhoff_init`, so `eth_ip_top` is false. The packet is not counted as `eth_ip`. Good.

But what about a packet that is Eth + IP (no VLAN)? `nhoff_init` is the offset past the Ethernet header. The IP case is reached with `nhoff == nhoff_init`, so `eth_ip_top` is true. The packet is counted as `eth_ip`. Good.

### Bug check: IPIP counter

The IPIP slow-path counter is placed at:
```c
case IPPROTO_IPIP:
    flow_dissector_count_slow(FLOW_DISSECTOR_SHAPE_IPIP);
```

And the fast-path counter is in `flow_dissect_fast_ipip_inner`:
```c
flow_dissector_count_fast(FLOW_DISSECTOR_SHAPE_IPIP);
```

But the slow path also has the eth_ip counter at `out_good`:
```c
if (ret && eth_ip_top &&
    !(key_control->flags & FLOW_DIS_ENCAPSULATION) &&
    (ip_proto == IPPROTO_TCP || ip_proto == IPPROTO_UDP))
    flow_dissector_count_slow(FLOW_DISSECTOR_SHAPE_ETH_IP);
```

For an IPIP packet, `eth_ip_top` is true (the outer IP is at the initial offset), but `key_control->flags & FLOW_DIS_ENCAPSULATION` is true (the inner descent sets it). So the eth_ip counter is NOT incremented. Good - IPIP is counted only as IPIP, not as eth_ip.

But wait - in the fast path, the IPIP counter is incremented in `flow_dissect_fast_ipip_inner`, and the eth_ip counter is NOT incremented because the dispatcher checks:
```c
if (!flow_dissect_fast_is_encap(flow_dissector, target_container))
    flow_dissector_count_fast(FLOW_DISSECTOR_SHAPE_ETH_IP);
```

And `flow_dissect_fast_is_encap` returns true because ENCAP is set. Good.

### Bug check: GRE counter

Same as IPIP - the GRE counter is placed at:
```c
case IPPROTO_GRE:
    flow_dissector_count_slow(FLOW_DISSECTOR_SHAPE_GRE);
```

And the fast-path counter is in `flow_dissect_fast_gre_inner`. The eth_ip counter is not incremented because ENCAP is set. Good.

OK, I'm satisfied that the counting is correct.

### Bug check: Series B `__skb_flow_dissect_udp_encap` and `FLOW_DIS_IS_FRAGMENT`

The slow-path descent checks:
```c
!(key_control->flags & FLOW_DIS_IS_FRAGMENT)
```

This prevents descent into fragmented UDP packets. Good - a fragmented outer UDP would have the fragment flag set, and the descent should not try to parse the fragment as a tunnel header.

But wait - `FLOW_DIS_IS_FRAGMENT` is set for IPv4 fragments. What about IPv6 fragments? The slow path sets `FLOW_DIS_IS_FRAGMENT` in the IPv6 fragment handling:
```c
if (ip_proto == IPPROTO_FRAGMENT) {
    ...
    key_control->flags |= FLOW_DIS_IS_FRAGMENT;
    ...
}
```

So IPv6 fragments also have the flag set. Good.

But what about an IPv6 packet with a fragment extension header? The slow path would set `FLOW_DIS_IS_FRAGMENT`, and the descent would be skipped. Good.

OK, I'm confident there are no correctness bugs. Let me write the review.

Actually, one more thing. Let me check the `flow_dissect_fast_is_encap` function:
```c
static bool flow_dissect_fast_is_encap(struct flow_dissector *flow_dissector,
                                       void *target_container)
{
    struct flow_dissector_key_control *key_control;

    if (!dissector_uses_key(flow_dissector, FLOW_DISSECTOR_KEY_CONTROL))
        return false;
    key_control = skb_flow_dissector_target(flow_dissector,
                                            FLOW_DISSECTOR_KEY_CONTROL,
                                            target_container);
    return key_control->flags & FLOW_DIS_ENCAPSULATION;
}
```

This checks the ENCAP flag in the target container. But this is called after the fast path returns true, so the container has been filled. If the fast path set ENCAP (via IPIP/GRE/descent), this returns true, and the eth_ip counter is not incremented. Good.

But there's a subtlety: the `dissector_uses_key` check. If the dissector doesn't use `FLOW_DISSECTOR_KEY_CONTROL`, the function returns false, and the eth_ip counter IS incremented. But if the dissector doesn't use CONTROL, the fast-path helpers don't set `key_control->flags` at all (they check `dissector_uses_key` before writing). So ENCAP is never set, and `flow_dissect_fast_is_encap` correctly returns false. Good.

But wait - the IPIP/GRE inner helpers always check `dissector_uses_key` before setting ENCAP:
```c
if (dissector_uses_key(flow_dissector, FLOW_DISSECTOR_KEY_CONTROL)) {
    key_control = skb_flow_dissector_target(flow_dissector,
                                            FLOW_DISSECTOR_KEY_CONTROL,
                                            target_container);
    key_control->flags |= FLOW_DIS_ENCAPSULATION;
}
```

So if CONTROL is not used, ENCAP is never set, and `flow_dissect_fast_is_encap` returns false. The eth_ip counter is incremented even for IPIP/GRE packets. But the slow path also has this issue:
```c
if (ret && eth_ip_top &&
    !(key_control->flags & FLOW_DIS_ENCAPSULATION) &&
    ...)
```

Wait, if CONTROL is not used, `key_control` is not set. But the slow path accesses `key_control->flags`... Actually, looking at the slow path:
```c
if (dissector_uses_key(flow_dissector, FLOW_DISSECTOR_KEY_CONTROL)) {
    key_control = skb_flow_dissector_target(flow_dissector,
                                            FLOW_DISSECTOR_KEY_CONTROL,
                                            target_container);
    ...
}
```

The `key_control` variable is only set if CONTROL is used. If CONTROL is not used, `key_control` might be NULL or uninitialized. But the counter check:
```c
if (ret && eth_ip_top &&
    !(key_control->flags & FLOW_DIS_ENCAPSULATION) &&
    ...)
```

This accesses `key_control->flags` unconditionally. If CONTROL is not used, this is a NULL dereference (or uninitialized access).

Wait, but `flow_keys_dissector` and `flow_keys_dissector_symmetric` both use CONTROL. The fast path only admits these two dissectors. So CONTROL is always used when the fast path runs. But the counter check is in the slow path, which runs for all dissectors. If a custom dissector that doesn't use CONTROL enters the slow path, the counter check would access an uninitialized `key_control`.

Actually, let me look more carefully. The `key_control` variable is declared at the top of `__skb_flow_dissect()`:
```c
struct flow_dissector_key_control *key_control;
```

It's only assigned inside `if (dissector_uses_key(..., FLOW_DISSECTOR_KEY_CONTROL))` blocks. If CONTROL is not used, it's never assigned, and the counter check accesses an uninitialized pointer.

But wait - the counter check is:
```c
if (ret && eth_ip_top &&
    !(key_control->flags & FLOW_DIS_ENCAPSULATION) &&
    (ip_proto == IPPROTO_TCP || ip_proto == IPPROTO_UDP))
    flow_dissector_count_slow(FLOW_DISSECTOR_SHAPE_ETH_IP);
```

If CONTROL is not used, `key_control` is uninitialized. Accessing `key_control->flags` is undefined behaviour. This is a bug!

Actually, wait. Let me look at the existing code. The `out_good` label in the existing `__skb_flow_dissect()` already accesses `key_control`:
```c
out_good:
    ...
    if (dissector_uses_key(flow_dissector, FLOW_DISSECTOR_KEY_CONTROL))
        key_control = skb_flow_dissector_target(...);
    ...
    key_control->thoff = ...;
```

Wait, does the existing `out_good` label check `dissector_uses_key` before accessing `key_control`? Let me look at the existing code more carefully...

Actually, I don't have the full existing `__skb_flow_dissect()` in the diff. The diff only shows the added code. The existing `out_good` label might already handle the case where CONTROL is not used.

But the counter check added by patch 8 is:
```c
if (ret && eth_ip_top &&
    !(key_control->flags & FLOW_DIS_ENCAPSULATION) &&
    (ip_proto == IPPROTO_TCP || ip_proto == IPPROTO_UDP))
    flow_dissector_count_slow(FLOW_DISSECTOR_SHAPE_ETH_IP);
```

This is placed at the `out_good` label, after the existing `key_control` handling. If the existing code already sets `key_control` (via `dissector_uses_key` check), then `key_control` is either valid or the check is inside a `dissector_uses_key` block.

Actually, looking at the diff context for patch 8, the counter check is placed after:
```c
key_basic->n_proto = proto;
key_basic->ip_proto = ip_proto;
```

These are at the `out_good` label. But I don't see the `key_control` assignment in the diff context. It might be just above the shown context.

Hmm, let me look at the existing `__skb_flow_dissect()` code. The `out_good` label typically looks like:
```c
out_good:
    if (dissector_uses_key(flow_dissector, FLOW_DISSECTOR_KEY_CONTROL)) {
        key_control = skb_flow_dissector_target(flow_dissector,
                                                FLOW_DISSECTOR_KEY_CONTROL,
                                                target_container);
        key_control->thoff = min_t(u16, nhoff, skb ? skb->len : hlen);
    }
    if (dissector_uses_key(flow_dissector, FLOW_DISSECTOR_KEY_BASIC)) {
        key_basic = skb_flow_dissector_target(flow_dissector,
                                              FLOW_DISSECTOR_KEY_BASIC,
                                              target_container);
        key_basic->n_proto = proto;
        key_basic->ip_proto = ip_proto;
    }
    ...
```

So `key_control` is only set inside the `if (dissector_uses_key(...))` block. The counter check accesses `key_control->flags` outside this block, which is a bug if CONTROL is not used.

But wait - the counter check is:
```c
if (ret && eth_ip_top &&
    !(key_control->flags & FLOW_DIS_ENCAPSULATION) &&
    (ip_proto == IPPROTO_TCP || ip_proto == IPPROTO_UDP))
    flow_dissector_count_slow(FLOW_DISSECTOR_SHAPE_ETH_IP);
```

If CONTROL is not used, `key_control` is uninitialized. But the `flow_keys_dissector` and `flow_keys_dissector_symmetric` both use CONTROL. The counter check is in the slow path, which runs for all dissectors, including custom ones that might not use CONTROL.

This is a potential NULL dereference / uninitialized access bug!

**But** - looking at the existing code, the `out_good` label already accesses `key_control` without a `dissector_uses_key` check in some places. Let me look at the existing code more carefully...

Actually, I think the existing `out_good` label does check `dissector_uses_key` before accessing `key_control`. The diff context shows:
```c
key_basic->n_proto = proto;
key_basic->ip_proto = ip_proto;

+	if (ret && eth_ip_top &&
+	    !(key_control->flags & FLOW_DIS_ENCAPSULATION) &&
+	    (ip_proto == IPPROTO_TCP || ip_proto == IPPROTO_UDP))
+		flow_dissector_count_slow(FLOW_DISSECTOR_SHAPE_ETH_IP);
+
return ret;
```

So the counter check is between the `key_basic` write and the `return ret`. If the existing code has:
```c
if (dissector_uses_key(flow_dissector, FLOW_DISSECTOR_KEY_CONTROL)) {
    key_control = ...;
    key_control->thoff = ...;
}
if (dissector_uses_key(flow_dissector, FLOW_DISSECTOR_KEY_BASIC)) {
    key_basic = ...;
    key_basic->n_proto = proto;
    key_basic->ip_proto = ip_proto;
}
// counter check here
return ret;
```

Then `key_control` might be uninitialized if CONTROL is not used. This is a bug.

But in practice, every caller of `__skb_flow_dissect()` with the standard dissectors uses CONTROL. And custom dissectors that don't use CONTROL are rare. But it's still a potential bug.

**Fix**: Add a `dissector_uses_key(flow_dissector, FLOW_DISSECTOR_KEY_CONTROL)` check before accessing `key_control->flags`, or use a local `bool is_encap` flag that's set earlier (inside the CONTROL block).

Actually wait, let me re-read the diff more carefully. The added code in patch 8 is:

```c
+	/* eth_ip shape: top-level eth+IP, TCP/UDP, no encap -- counted here
+	 * because the fast path returns earlier; with the gate off this is
+	 * the shape's eligible-fraction signal.
+	 */
+	if (ret && eth_ip_top &&
+	    !(key_control->flags & FLOW_DIS_ENCAPSULATION) &&
+	    (ip_proto == IPPROTO_TCP || ip_proto == IPPROTO_UDP))
+		flow_dissector_count_slow(FLOW_DISSECTOR_SHAPE_ETH_IP);
+
 	return ret;
```

This accesses `key_control->flags` without checking `dissector_uses_key`. If a dissector that doesn't use CONTROL reaches this point, `key_control` is uninitialized.

**But** - looking at the `out_good` label in the existing code, I see that `key_control` is assigned earlier:
```c
if (dissector_uses_key(flow_dissector, FLOW_DISSECTOR_KEY_CONTROL)) {
    key_control = skb_flow_dissector_target(flow_dissector,
                                            FLOW_DISSECTOR_KEY_CONTROL,
                                            target_container);
}
```

So `key_control` is a local variable that's only assigned inside the `if` block. If CONTROL is not used, it's never assigned, and the counter check dereferences an uninitialized pointer.

This is a real bug. It's unlikely to trigger in practice (most dissectors use CONTROL), but it's still undefined behaviour.

**Fix**: Guard the counter check with `dissector_uses_key(flow_dissector, FLOW_DISSECTOR_KEY_CONTROL)`:
```c
if (ret && eth_ip_top &&
    (!dissector_uses_key(flow_dissector, FLOW_DISSECTOR_KEY_CONTROL) ||
     !(key_control->flags & FLOW_DIS_ENCAPSULATION)) &&
    (ip_proto == IPPROTO_TCP || ip_proto == IPPROTO_UDP))
    flow_dissector_count_slow(FLOW_DISSECTOR_SHAPE_ETH_IP);
```

Or more simply, check CONTROL once and use a local bool:
```c
bool is_encap = false;
if (dissector_uses_key(flow_dissector, FLOW_DISSECTOR_KEY_CONTROL)) {
    key_control = ...;
    is_encap = key_control->flags & FLOW_DIS_ENCAPSULATION;
}
...
if (ret && eth_ip_top && !is_encap &&
    (ip_proto == IPPROTO_TCP || ip_proto == IPPROTO_UDP))
    flow_dissector_count_slow(FLOW_DISSECTOR_SHAPE_ETH_IP);
```

This is a real blocker - it's a potential NULL dereference / uninitialized access.

Actually, let me look at this more carefully. The `key_control` variable is declared at the top of the function:
```c
struct flow_dissector_key_control *key_control;
```

In C, local variables are uninitialized by default. If `dissector_uses_key(..., FLOW_DISSECTOR_KEY_CONTROL)` is false, `key_control` is never assigned, and `key_control->flags` is an uninitialized access.

But wait - let me check if the existing code already accesses `key_control` at the `out_good` label without a check. Looking at the existing code (not in the diff), the `out_good` label typically does:

```c
out_good:
    if (dissector_uses_key(flow_dissector, FLOW_DISSECTOR_KEY_CONTROL)) {
        key_control = skb_flow_dissector_target(flow_dissector,
                                                FLOW_DISSECTOR_KEY_CONTROL,
                                                target_container);
        key_control->thoff = min_t(u16, nhoff, skb ? skb->len : hlen);
    }
    if (dissector_uses_key(flow_dissector, FLOW_DISSECTOR_KEY_BASIC)) {
        key_basic = skb_flow_dissector_target(flow_dissector,
                                              FLOW_DISSECTOR_KEY_BASIC,
                                              target_container);
        key_basic->n_proto = proto;
        key_basic->ip_proto = ip_proto;
    }
    return ret;
```

So the existing code does NOT access `key_control` outside the `if (dissector_uses_key(...))` block. The counter check added by patch 8 does access it outside the block. This is a new bug introduced by patch 8.

This is definitely a blocker. Let me make sure I'm not misreading the diff.

Looking at patch 8's diff:
```c
 	key_basic->n_proto = proto;
 	key_basic->ip_proto = ip_proto;
 
+	/* eth_ip shape: top-level eth+IP, TCP/UDP, no encap -- counted here
+	 * because the fast path returns earlier; with the gate off this is
+	 * the shape's eligible-fraction signal.
+	 */
+	if (ret && eth_ip_top &&
+	    !(key_control->flags & FLOW_DIS_ENCAPSULATION) &&
+	    (ip_proto == IPPROTO_TCP || ip_proto == IPPROTO_UDP))
+		flow_dissector_count_slow(FLOW_DISSECTOR_SHAPE_ETH_IP);
+
 	return ret;
```

The `key_basic->n_proto = proto;` line is inside an `if (dissector_uses_key(..., FLOW_DISSECTOR_KEY_BASIC))` block. The counter check is after that block, and accesses `key_control->flags` without a check. This is the bug.

OK, this is a real blocker. Let me add it to the review.

Let me also check: is `key_control` definitely uninitialized when CONTROL is not used? Let me look at the function signature and the variable declarations...

Actually, I realize I need to look at the existing code more carefully. The `key_control` variable might be assigned earlier in the function, not just at the `out_good` label. Let me check...

In the existing `__skb_flow_dissect()`:
```c
bool __skb_flow_dissect(...)
{
    ...
    struct flow_dissector_key_control *key_control;
    ...
    
    // key_control is assigned in multiple places:
    // 1. In the eth addrs block
    // 2. In the IP block
    // 3. At the out_good label
    
    // But only inside if (dissector_uses_key(..., FLOW_DISSECTOR_KEY_CONTROL)) blocks
}
```

So `key_control` is a local variable that's only assigned inside `dissector_uses_key(CONTROL)` blocks. If CONTROL is not used by the dissector, `key_control` is never assigned.

But wait - what if `key_control` is assigned in one of the earlier blocks (e.g., the eth addrs block) and then used at the `out_good` label? If CONTROL is used, it would be assigned. If CONTROL is not used, it wouldn't.

Actually, looking at the existing code, `key_control` is assigned in multiple places:
```c
if (dissector_uses_key(flow_dissector, FLOW_DISSECTOR_KEY_CONTROL)) {
    key_control = skb_flow_dissector_target(flow_dissector,
                                            FLOW_DISSECTOR_KEY_CONTROL,
                                            target_container);
    ...
}
```

This pattern is repeated in multiple places (eth addrs, IP, IPv6, etc.). If CONTROL is used, `key_control` is assigned in the first matching block. If CONTROL is not used, it's never assigned.

So the counter check at `out_good` that accesses `key_control->flags` without a `dissector_uses_key` check is a bug when CONTROL is not used.

This is a real bug. It's unlikely to trigger in practice because:
1. The standard dissectors (`flow_keys_dissector`, `flow_keys_dissector_symmetric`) both use CONTROL
2. Most custom dissectors also use CONTROL
3. The fast path only admits the two standard dissectors, so the counter check at `out_good` only runs for the slow path, which handles all dissectors

But it's still undefined behaviour and should be fixed.

Actually, wait. Let me re-examine. The counter check is at the `out_good` label, which is reached by the slow path. The slow path runs for all dissectors, including custom ones. If a custom dissector that doesn't use CONTROL reaches `out_good`, the counter check accesses an uninitialized `key_control`.

But the counter check also requires `eth_ip_top` to be true, which means the packet is Eth + IP at the top level. And `ip_proto == TCP || ip_proto == UDP`. These conditions are independent of the dissector. So a custom dissector that doesn't use CONTROL but dissects an Eth + IP + TCP packet would trigger the bug.

This is a real bug. Blocker.

Hmm, actually, I realize I should also check whether the compiler might warn about this. With `-Wall`, the compiler might warn about potentially uninitialized variable. But with the complex control flow of `__skb_flow_dissect()`, the compiler might not be able to detect it.

OK, let me add this to the review as a blocker.

Let me also check: does the `flow_dissect_fast_is_encap` function in the fast path have the same issue?

```c
static bool flow_dissect_fast_is_encap(struct flow_dissector *flow_dissector,
                                       void *target_container)
{
    struct flow_dissector_key_control *key_control;

    if (!dissector_uses_key(flow_dissector, FLOW_DISSECTOR_KEY_CONTROL))
        return false;
    key_control = skb_flow_dissector_target(flow_dissector,
                                            FLOW_DISSECTOR_KEY_CONTROL,
                                            target_container);
    return key_control->flags & FLOW_DIS_ENCAPSULATION;
}
```

This checks `dissector_uses_key` before accessing `key_control`. So it's safe. Good.

But the slow-path counter check doesn't have this check. This is the bug.

OK, now let me also look for other potential issues in the slow-path counter placement.

The IPIP counter:
```c
case IPPROTO_IPIP:
    flow_dissector_count_slow(FLOW_DISSECTOR_SHAPE_IPIP);
    if (flags & FLOW_DISSECTOR_F_STOP_BEFORE_ENCAP) {
        fdret = FLOW_DISSECT_RET_OUT_GOOD;
        break;
    }
    ...
```

This is placed at the `case IPPROTO_IPIP:` label, before the STOP_BEFORE_ENCAP check. So it counts even when the caller wants to stop before encap. Is this correct?

The counter is meant to count "shape seen by the slow path" - i.e., how many packets match this shape. A packet that matches IPIP but the caller wants to stop before encap is still an IPIP packet. So counting it is correct - the counter measures the eligible fraction, not the actual descent.

But wait - the IPIP counter is at the `case IPPROTO_IPIP:` label, which is inside the `switch (ip_proto)` block. This block is reached after the IP header is parsed. The counter counts every IPIP packet that reaches the slow path, regardless of flags. This is correct.

The GRE counter:
```c
case IPPROTO_GRE:
    flow_dissector_count_slow(FLOW_DISSECTOR_SHAPE_GRE);
    if (flags & FLOW_DISSECTOR_F_STOP_BEFORE_ENCAP) {
        fdret = FLOW_DISSECT_RET_OUT_GOOD;
        break;
    }
    ...
```

Same pattern. Correct.

The MPLS counter:
```c
case htons(ETH_P_MPLS_UC):
case htons(ETH_P_MPLS_MC):
    flow_dissector_count_slow(FLOW_DISSECTOR_SHAPE_MPLS);
    fdret = __skb_flow_dissect_mpls(...);
    ...
```

This counts every MPLS packet that reaches the slow path. Correct.

The PPPoE counter:
```c
flow_dissector_count_slow(FLOW_DISSECTOR_SHAPE_PPPOE);
```

This is placed after the PPPoE header validation, before the PPP protocol check. So it counts every valid PPPoE session frame, regardless of the PPP protocol. This is correct - the counter measures the PPPoE shape, not the inner protocol.

The VLAN counter:
```c
if (dissector_vlan == FLOW_DISSECTOR_KEY_MAX) {
    dissector_vlan = FLOW_DISSECTOR_KEY_VLAN;
    flow_dissector_count_slow(FLOW_DISSECTOR_SHAPE_VLAN);
} else if (dissector_vlan == FLOW_DISSECTOR_KEY_VLAN) {
    dissector_vlan = FLOW_DISSECTOR_KEY_CVLAN;
    flow_dissector_count_slow(FLOW_DISSECTOR_SHAPE_QINQ);
}
```

This counts the first VLAN tag as `vlan` and the second as `qinq`. Correct.

OK, the counter placement looks correct, except for the `key_control` uninitialized access bug.

Let me also check: in the fast path, the `flow_dissect_fast_is_encap` function is called after the fast path returns true. But what if the fast path set ENCAP but the dissector doesn't use CONTROL? Then `flow_dissect_fast_is_encap` returns false (it checks `dissector_uses_key` first), and the eth_ip counter is incremented. But the IPIP/GRE inner helpers also check `dissector_uses_key` before setting ENCAP, so ENCAP is never set if CONTROL is not used. So `flow_dissect_fast_is_encap` correctly returns false, and the packet is counted as eth_ip. But should it be counted as IPIP/GRE instead?

Looking at the fast-path IPIP counter:
```c
flow_dissector_count_fast(FLOW_DISSECTOR_SHAPE_IPIP);
```

This is in `flow_dissect_fast_ipip_inner`, which is called regardless of whether CONTROL is used. So the IPIP counter IS incremented even if CONTROL is not used. And the eth_ip counter is also incremented (because `flow_dissect_fast_is_encap` returns false). So the packet is double-counted as both eth_ip and IPIP.

But wait - the fast path only admits the two standard dissectors, which both use CONTROL. So this case can't happen in the fast path. Good.

But in the slow path, a custom dissector that doesn't use CONTROL could reach the IPIP counter and the eth_ip counter. Let me check:

1. The IPIP counter is at `case IPPROTO_IPIP:` - it's incremented for all dissectors
2. The eth_ip counter is at `out_good:` - it checks `key_control->flags & FLOW_DIS_ENCAPSULATION`, which is an uninitialized access if CONTROL is not used

So for a custom dissector that doesn't use CONTROL and dissects an IPIP packet:
1. IPIP counter is incremented (correct)
2. eth_ip counter check accesses uninitialized `key_control` (bug)

If `key_control` happens to be non-NULL (stack garbage) and the garbage doesn't have ENCAP set, the eth_ip counter is also incremented (double-counting). If the garbage has ENCAP set, the eth_ip counter is not incremented (correct by accident).

This is undefined behaviour and should be fixed.

OK, I'm confident this is a real bug. Let me write the review.

Actually, wait. I should also check if the `key_control` variable might be initialized to NULL by the compiler. In C, local variables are uninitialized by default, but some compilers might zero-initialize them in debug builds. With KASAN/UBSAN, the uninitialized access might be detected. But in a release build, it's undefined behaviour.

The cover letter says the KUnit tests are run under KASAN+UBSAN. If the test uses a custom dissector that doesn't use CONTROL, KASAN/UBSAN might catch this. But the test's `fd_fast_ineligible_dissector_test` uses a custom dissector that DOES use CONTROL:
```c
static const struct flow_dissector_key keys[] = {
    { .key_id = FLOW_DISSECTOR_KEY_CONTROL,
      .offset = offsetof(struct flow_keys, control) },
    ...
};
```

So the test doesn't cover the case where CONTROL is not used. The bug would not be caught by the test.

This is a real bug that's not caught by the test. Blocker.

OK let me finalize the review now. I need to be careful to cite specific lines and order by severity.

Let me organize:

### Blockers:

1. **A-8: Uninitialized `key_control` access in slow-path eth_ip counter** - `key_control->flags` is accessed without checking `dissector_uses_key(FLOW_DISSECTOR_KEY_CONTROL)` at the `out_good` label. A custom dissector that doesn't use CONTROL would trigger undefined behaviour.

2. **B-4: FOU/GUE ops hook is a fragile global singleton** - `flow_dissector_fou_ops` is a single global pointer. If the fou module fails to register (because something else registered), the feature is silently unavailable with only a `pr_warn`. There's no mechanism for multiple providers or fallback.

### Substantive:

3. **A-8: Unconditional per-dissect counter tax** - `this_cpu_inc(flow_dissector_pcpu_stats.dissects)` runs on every dissect even when all gates are off. +0.74% on pktgen soak. Counters should be gated.

4. **A: Seven per-shape sysctls is excessive API surface** - The auto-mode follow-up is mentioned but not in this series. The current API puts the burden on the operator.

5. **A-6: Recursive `key_control->flags = 0` clobbering pattern** - The IPIP/GRE/UDP inner helpers rely on the inner IP helper zeroing flags and then re-establishing ENCAP. This is fragile and duplicated.

6. **B: Hardcoded tunnel port numbers** - VXLAN (4789), Geneve (6081), GTP-U (2152). Non-standard ports (e.g., Cilium's 8472) are not handled. The sysctl should accept a port number or consult the tunnel netdev.

7. **B-2,3: Documentation says "only IPv4 outer is handled" but code handles both IPv4 and IPv6** - The Geneve and GTP-U sysctl docs incorrectly state IPv6 outer is not handled.

8. **B: Hashing change needs broader community buy-in** - Changing `skb->hash` for tunnel traffic affects ECMP, bonding, RPS. Needs review from routing and tunneling maintainers.

9. **A-6: 4in6 residue depends on union layout** - Byte-identity for 4in6 relies on `v4addrs` being the first 8 bytes of the `addrs` union, leaving outer v6 residue. This is correct but extremely fragile.

### Polish:

10. **A: `Assisted-by` trailer format** - `Assisted-by: Claude:claude-fable-5 sparse smatch` is unclear. Should follow the `coding-assistants.rst` format precisely.

11. **B-3: GTP header macros defined locally** - `GTP1_HDR_VERSION` and `GTP1_HDR_PT` should be in `<net/gtp.h>`.

12. **A-2: `flow_keys_dissector_symmetric` tentative definition** - The forward definition at the top of the file is fragile against future changes.

13. **A-8: `/proc/net/flow_dissector_stats` is init_net only** - Counters are global, file is init_net only. Containers can't see their own stats. Acknowledged as a follow-up.

Let me write this up properly now. I want to make sure I'm citing specific lines and quoting relevant text.

Let me also verify: the two-series split. Is it drawn in the right place?

The split is:
- Series A: byte-identical (no behaviour change)
- Series B: behaviour-changing (changes hashing)

This is the right split. The policy discussions are fundamentally different:
- Series A: "Is this optimisation safe?" (yes, because byte-identical)
- Series B: "Should we change hashing for tunnel traffic?" (policy question)

The dependency (B on A) is acknowledged. The split is correct.

But there's a subtlety: Series A's patch 8 (counters) is designed to support the "auto" mode proposed in a separate RFC. The auto mode would only manage the byte-identical gates, not the descent gates. This is explicitly stated:
```
The descent gates are deliberately excluded from the auto-enable controller proposed in a separate RFC thread: enabling them changes hashing and must stay a deliberate operator action.
```

This is the right call. The split between "auto-managed byte-identical gates" and "manually-managed descent gates" is clear.

OK, let me write the final review.
