# External LLM review: r1-maintainer

Prompt: full v1 series (16 files) + persona instructions; self-hosted 128k model; max_tokens 55000.

finish_reason: stop | usage: {"prompt_tokens":72636,"total_tokens":101028,"completion_tokens":28392,"prompt_tokens_details":null,"reasoning_tokens":23843}

## Review (content)

# Maintainer Review: [PATCH net-next v1 00/15] net: flow_dissector: opt-in byte-identical fast paths + tunnel inner descent

## Blockers

### 1. Patch 8 — Unconditional per-packet counter overhead in the default (all-gates-off) configuration

The cover letter states:

> "when a gate is off the added cost is one not-taken branch per dissect"

This is false once patch 8 is applied. The dissects counter is unconditional:

```c
+	this_cpu_inc(flow_dissector_pcpu_stats.dissects);
```

This runs on **every** `__skb_flow_dissect()` call, regardless of gate state. Additionally, the slow-path occurrence counters add branches and `this_cpu_inc` calls at multiple protocol recognition points:

```c
+		/* First (outer) tag: the vlan fast-path shape. */
+		flow_dissector_count_slow(FLOW_DISSECTOR_SHAPE_VLAN);
```

```c
+		flow_dissector_count_slow(FLOW_DISSECTOR_SHAPE_PPPOE);
```

```c
+	case IPPROTO_GRE:
+		flow_dissector_count_slow(FLOW_DISSECTOR_SHAPE_GRE);
```

And the eth_ip slow-path counter adds several branches at the `out:` label:

```c
+	if (ret && eth_ip_top &&
+	    !(key_control->flags & FLOW_DIS_ENCAPSULATION) &&
+	    (ip_proto == IPPROTO_TCP || ip_proto == IPPROTO_UDP))
+		flow_dissector_count_slow(FLOW_DISSECTOR_SHAPE_ETH_IP);
```

plus the `nhoff == nhoff_init` comparison and `eth_ip_top` assignment on every IPv4/IPv6 packet.

**What to change:** Gate all counters behind a single `static_key_false` (e.g. `flow_dissector_stats_enabled`) that is enabled only when `/proc/net/flow_dissector_stats` has been opened (or when any gate is on). The default path must be truly zero-overhead. Without this fix, the series is a performance regression in the default config, and I will not take it.

---

### 2. Patches 10–13 — Slow path is modified to add new tunnel descents, undermining the "single source of semantic truth" claim

The cover letter states:

> "The slow path remains the single source of semantic truth and the fast path is verified against it, not vice versa."

But patches 10–13 add **new behaviour** to the slow path that did not exist before — tunnel inner-flow descent via `__skb_flow_dissect_udp_encap()`:

```c
+	if (ip_proto == IPPROTO_UDP &&
+	    fdret == FLOW_DISSECT_RET_CONTINUE &&
+	    ...
+	    __skb_flow_dissect_udp_encap(skb, key_control, data, &proto, &nhoff,
+					 hlen, ...))
+		fdret = FLOW_DISSECT_RET_PROTO_AGAIN;
```

This is not verifying the fast path against the slow path — it is **changing the slow path to match the fast path**. The `goto proto_again` re-enters the graph walk for the inner packet, which is new behaviour that affects every caller of `__skb_flow_dissect()`, not just the fast-path-eligible ones.

This is a significant semantic change to the dissector: it makes the slow path descend into UDP tunnels when a gate is on, which changes `skb->hash` for tunnel traffic. While the gates are opt-in, the mechanism blurs the line between "optimization" and "behaviour change" in a way that the cover letter does not fully acknowledge.

**What to change:** Split this series into two independent submissions:
1. Patches 1–9 + 14–15: the byte-identical fast-path optimization (no behaviour change).
2. Patches 10–13: the tunnel inner-descent feature (behaviour change, needs its own justification and discussion).

The fast-path optimization can stand on its own merits. The descent feature is a separate policy question that deserves its own thread.

---

### 3. Patches 10–13 — Growing OR of `static_branch_unlikely` checks on the slow-path hot path

By patch 13, the slow path has:

```c
+	    (static_branch_unlikely(&flow_dissector_vxlan_inner_key) ||
+	     static_branch_unlikely(&flow_dissector_geneve_inner_key) ||
+	     static_branch_unlikely(&flow_dissector_gtpu_inner_key) ||
+	     static_branch_unlikely(&flow_dissector_gue_inner_key) ||
+	     static_branch_unlikely(&flow_dissector_fou_inner_key)) &&
```

This is five static-branch tests on every UDP packet in the slow path. Even with all gates off, each `static_branch_unlikely` on a `static_key_false` compiles to a `jmp` that is not taken, but five of them in sequence is non-trivial on the hot path, and the compiler cannot merge them.

**What to change:** Add a single summary key `flow_dissector_udp_inner_any`, enabled when any of the five individual descent keys is enabled. The slow path checks only the summary key. The individual keys are checked inside `__skb_flow_dissect_udp_encap()`. The `proc_do_static_key` handlers for the individual gates should inc/dec the summary key.

---

### 4. Patch 15 — Documentation references non-existent `auto` mode

```rst
+An optional ``auto`` mode (``net.flow_dissector.auto``) turns that decision into
+one knob: the kernel samples the per-shape counters over a packet-count window
+(``net.flow_dissector.auto_window_packets``) and flips the byte-identical gates
+itself, with hysteresis and a flip-rate cap, so the operator does not have to
+tune each shape by hand.
```

Neither `net.flow_dissector.auto` nor `net.flow_dissector.auto_window_packets` exist in any patch in this series. The cover letter mentions "A separate RFC thread proposes an adaptive auto-enable controller." Documenting non-existent sysctls is misleading — users will look for them and not find them.

**What to change:** Remove the `auto` mode paragraph entirely. If/when the auto-controller lands, it can update this document.

---

## Substantial issues

### 5. Partial writes on fast-path miss are not adequately tested

The fast path can write keys before returning false. For example, in `flow_dissect_fast_vlan()` (patch 3):

```c
+	if (dissector_uses_key(flow_dissector, vlan_key)) {
+		key_vlan = skb_flow_dissector_target(...);
+		key_vlan->vlan_id = tci_id;
+		...
+	}
+	...
+	switch (inner_proto) {
+	case htons(ETH_P_IP):
+		ok = flow_dissect_fast_ipv4(...);
+		break;
+	...
+	}
+	return ok;
```

If the inner IPv4 helper returns false (e.g. IP options), the VLAN key has already been written. Similarly, in the IPIP descent (patch 6), the outer IPv4 keys are written before `flow_dissect_fast_ipip_inner()` is called; if the inner fails, the outer writes remain.

The test's zeroed-container check does **not** catch this. The test calls `__skb_flow_dissect()` with gates on; when the fast path returns false, the slow path runs on the same container and overwrites the partial writes. The final `memcmp` compares the slow-path-overwritten output against the gates-off output, which trivially matches. The test comment even claims:

> "Zeroed containers also prove a fast-path miss never leaves partial writes behind."

This claim is false as implemented.

**What to change:** Add a test that calls `flow_dissect_fast()` directly (not through `__skb_flow_dissect()`), checks the return value is false, and then verifies the container is still all zeroes. Or: structure the helpers so that all `return false` paths come before any writes, and add a static assertion or code comment documenting this invariant.

---

### 6. Patch 6 — 4in6 residue reproduction is fragile

```c
+		/* Mirror the slow path's outer-IPv6 writes before the
+		 * descent. The slow path fills v6addrs for the outer
+		 * header and the inner pass then overwrites only what
+		 * it uses — an inner IPv4 leaves the tail of the addrs
+		 * union holding outer-v6 bytes. Byte-identical means
+		 * reproducing exactly that, residue included.
+		 */
```

This reproduces an unintentional artefact of the slow path's `union` handling: when an inner IPv4 overwrites `key_addrs->v4addrs` (8 bytes), the remaining 16 bytes of the 24-byte `v6addrs` union retain the outer IPv6 values. The fast path must reproduce this residue to be byte-identical.

This makes the fast path dependent on a slow-path implementation detail. If anyone later "fixes" the slow path to zero the union before writing (a reasonable cleanup), the fast path would diverge and the KUnit test would fail — but the fix would be correct and the fast path would be wrong.

**What to change:** Document this as a known fragility in a code comment near the slow path's address union handling, so future maintainers know not to "fix" it without updating the fast path. Better: consider whether the slow path should be cleaned up to not leave residue, and the fast path updated to match — but that would be a separate patch with its own test coverage.

---

### 7. Sysctl API design — too many knobs, surprising auto-toggle

The series adds 12 sysctls under `/proc/sys/net/flow_dissector/`:

- 7 byte-identical shape gates: `eth_ip`, `vlan`, `qinq`, `pppoe`, `mpls`, `ipip`, `gre`
- 5 descent gates: `vxlan_inner`, `geneve_inner`, `gtpu_inner`, `gue_inner`, `fou_inner`

The vlan/qinq auto-toggle (patch 3) is surprising:

```c
+static int proc_set_qinq_key(const struct ctl_table *table, int write,
+			     void *buffer, size_t *lenp, loff_t *ppos)
+{
+	...
+	if (ret == 0 && write &&
+	    static_branch_unlikely(&flow_dissector_qinq_key) &&
+	    !static_branch_unlikely(&flow_dissector_vlan_key))
+		static_branch_enable(&flow_dissector_vlan_key);
+	return ret;
+}
```

Setting `qinq=1` silently enables `vlan`. Setting `vlan=0` silently disables `qinq`. An operator reading back the sysctls after setting `qinq=1` will see `vlan=1` too, with no explanation.

The gates are also global (init_net sysctl, global static key) but affect all network namespaces. The cover letter acknowledges this ("per-netns dissector policy already has a mechanism — the netns BPF flow dissector"), but the sysctl is invisible to non-init namespaces.

**What to change:**
- Reject `qinq=1` when `vlan=0` with `-EINVAL` instead of silently auto-toggling. Let the operator enable `vlan` first.
- Consider whether 12 knobs is the right API. A single `enabled_shapes` bitmask (one sysctl, one static key) might be simpler for the byte-identical shapes. The descent gates can stay per-tunnel-type since they're independent policy decisions.
- Add a clear note in the sysctl documentation that these are global and affect all namespaces.

---

### 8. Patch 13 — FOU/GUE ops hook: cross-module interface, per-packet RCU lock, silent failure

The FOU/GUE descent introduces a new registered-ops interface:

```c
+struct flow_dissector_fou_ops {
+	u16 (*encap_lookup)(const struct net *net, u8 family, __be16 port,
+			    u8 *protocol);
+};
```

This is called per UDP packet when either gate is on:

```c
+	type = flow_dissect_fou_lookup(skb, family, udp_ports[1],
+				       &ipproto);
```

Which does:

```c
+	guard(rcu)();
+	...
+	ops = rcu_dereference(flow_dissector_fou_ops);
+	if (!net || !ops)
+		return FOU_ENCAP_UNSPEC;
+	return ops->encap_lookup(net, family, port, protocol);
```

An RCU lock + per-netns list walk on every UDP packet is a significant cost on the fast path. The registration failure is silently ignored:

```c
+	/* Best-effort: the flow-dissector FOU/GUE descent is an
+	 * optional consumer; failure to register (another owner) must
+	 * not fail fou init.
+	 */
+	flow_dissector_fou_ops_register(&fou_flow_ops);
+	return 0;
```

If registration fails, the `fou_inner`/`gue_inner` gates can be enabled but will never match — there is no indication to the operator.

**What to change:** Drop FOU/GUE from this series. VXLAN, Geneve, and GTP-U all have well-known ports and are self-describing — they don't need a cross-module hook. FOU/GUE descent is a niche feature that introduces disproportionate complexity (new ops interface, RCU list walk, tristate module dependency). It can be a follow-up series with its own discussion.

---

### 9. Patch 14 — KUnit FOU mock conflicts with real fou module

```c
+	KUNIT_ASSERT_EQ(test, 0,
+			flow_dissector_fou_ops_register(&fd_mock_fou_ops));
```

If `CONFIG_NET_FOU=y` (or `=m` and loaded), the real fou module has already registered its ops, and this returns `-EBUSY`. The test will fail.

**What to change:** Either (a) guard the FOU/GUE tests with `#if !IS_MODULE(CONFIG_NET_FOU)` and `#if !IS_ENABLED(CONFIG_NET_FOU)`, or (b) drop the FOU/GUE tests (and the FOU/GUE descent) per finding 8. At minimum, check the return value and `KUNIT_SKIP` if registration fails.

---

### 10. Patch 12 — GTP-U macro definitions duplicated locally

```c
+#define GTP1_HDR_VERSION	GENMASK(7, 5)
+#define GTP1_HDR_PT		BIT(4)
+#define GTP1_MSG_GPDU		0xff
```

`include/net/gtp.h` already defines `GTP1_VERSION` (or equivalent), `GTP1_FLAGS_*`, and `GTP_TPDU`. Redefining them locally risks divergence if the canonical definitions change.

**What to change:** Use the existing definitions from `<net/gtp.h>`. If some are missing, add them to the header in a separate patch.

---

## Polish

### 11. Patch 4 — Commit message says `static_branch_likely`, code uses `static_branch_unlikely`

The commit message says:

> `static_branch_likely(&flow_dissector_pppoe_key)` guard

But the code uses:

```c
+		if (!static_branch_unlikely(&flow_dissector_pppoe_key))
+			return false;
```

`static_branch_likely` and `static_branch_unlikely` have opposite default branch predictions. The code is correct (the gate is unlikely when off); the commit message is wrong.

---

### 12. Patches 3–5 — Vestigial "v3-namespace" references

Patch 3:

> "same per-shape pattern as the other v3-namespace patches"

Patch 4:

> "matching the v3-namespace layout"

Patch 5:

> "mirroring the vlan → qinq staging the v3-namespace series used"

These are references to an internal version that doesn't exist on the list. Clean them up.

---

### 13. `Assisted-by` trailer format

Every patch carries:

```
Assisted-by: Claude:claude-fable-5 sparse smatch
```

Per `Documentation/process/coding-assistants.rst`, the expected format for AI tool assistance is `Co-developed-by:` with the tool's email, or a note in the cover letter. "claude-fable-5" is not a model identifier that Anthropic publishes, and "sparse smatch" appears to be incorrectly appended to the trailer. Fix the trailer format or remove it and rely on the cover letter disclosure.

---

### 14. Patch 10 — `MAX_FLOW_DISSECT_HDRS` definition moved

```c
-/* Maximum number of protocol headers that can be parsed in
- * __skb_flow_dissect
- */
-#define MAX_FLOW_DISSECT_HDRS	15
```

moves above the fast-path helpers so `flow_dissect_fast_udp_inner()` can use it. This is a mechanical move that adds noise to the diff. Consider keeping the definition where it is and adding a forward declaration, or note the move in the commit message.

---

### 15. `__always_inline` on tunnel classifiers

```c
+static __always_inline bool
+flow_dissect_vxlan_inner_ok(...)
```

`__always_inline` forces inlining regardless of optimization level. For functions called from both fast and slow paths, this duplicates the code at both call sites. `inline` (or just `static`) would let the compiler decide. If there's a measured reason for `__always_inline`, note it in a comment.

---

## Questions I would ask on the list

1. **Counters:** Have you measured the overhead of the unconditional `this_cpu_inc(dissects)` on a high-ppc NIC (e.g. 100G+ with XDP redirect to stack)? What is the cycle count delta for the default (all gates off) configuration, before and after this series, on your fastest test platform?

2. **Slow-path descent:** You say the slow-path descent is "the same classifiers." But the slow path re-enters the full graph walk via `goto proto_again`, while the fast path calls `flow_dissect_fast_ipv4()` directly. These are not the same code path. How do you ensure they produce the same result for inner packets with extension headers, options, or fragments?

3. **Real-world impact:** The isolated A/B numbers (47–55%) are impressive but measure only the dissector function in isolation. Have you measured end-to-end impact on a real workload (e.g. RPS distribution on a busy server, or `sch_fq` throughput)? What is the pps delta for a real kernel build with all gates on?

4. **BPF flow dissector precedence:** If a BPF flow dissector is attached and returns `BPF_FLOW_DISSECTOR_CONTINUE`, the fast path runs. But the BPF program may have partially filled `flow_keys`. Does the fast path's unconditional `key_control->flags = 0` clobber the BPF program's writes? (Looking at the code, the BPF path uses a separate `struct bpf_flow_keys`, so this should be fine — but please confirm and add a test.)

5. **`proc_do_static_key` and racing dissects:** When an operator flips a gate, concurrent dissects may see the old or new key state. For byte-identical shapes this is benign. For descent gates, a transient mismatch between the fast and slow path's view of the key could cause one path to descend and the other not to. Is this possible? (I believe both paths check the same key, so the answer is no — but the transition window deserves explicit analysis.)

---

## Overall verdict

**Not ready for net-next.** The core idea — straight-line fast paths for common shapes, verified by an in-tree equivalence test — is sound and the test suite is commendable. But this submission conflates two different things: a transparent optimization (patches 1–9) and a behaviour-changing feature (patches 10–13). The unconditional counter overhead in patch 8 is a regression in the default configuration and must be gated. The slow-path modifications for tunnel descent are a significant semantic change that deserves its own thread. The sysctl API needs simplification. The FOU/GUE cross-module hook should be deferred.

**Recommended path forward:**
1. Split into two series: (a) byte-identical fast paths + KUnit tests, (b) tunnel descents.
2. Gate all counters behind a static key; make the default path truly zero-overhead.
3. Add a single summary static key for the UDP-tunnel descents in the slow path.
4. Drop FOU/GUE from the first submission.
5. Fix the partial-write test gap and the `auto` mode documentation.
6. Re-measure with all gates off to confirm no regression in the default config.

I would take a cleaned-up version of (a) — the byte-identical shapes, with gated counters and the KUnit suite — for net-next after one more revision. The descents (b) need their own discussion, particularly around the sysctl API and the slow-path modification.

## Reasoning trace (reasoning_content)

The user wants me to act as a senior Linux kernel networking (netdev) maintainer reviewing a 15-patch series for net-next. I need to:

1. Identify top objections, NAK risks, questions for the author
2. Consider maintainability, API/sysctl design, safety of opt-in gates, credibility of cover letter claims
3. Ground every finding in actual text (patch number + quotes)
4. Order by severity: blockers first, then substantive improvements, then polish
5. Say concretely what I would change
6. End with a short overall verdict

Let me go through the series carefully.

**Patch 1: Gate BPF program lookup behind a static key**

This patch adds a static key to skip the BPF flow dissector program lookup when no program is attached. This is a reasonable optimization on its own. Let me look for issues.

The key is `netns_bpf_flow_dissector_enabled` in `include/linux/skbuff.h`. The inc/dec logic in `kernel/bpf/net_namespace.c` needs to handle all attach/detach paths. The commit message mentions:
- link attach/release paths (already call need/unneed)
- legacy BPF_PROG_ATTACH: inc on fresh attach, dec in __netns_bpf_prog_detach(), dec for remaining legacy prog in netns_bpf_pernet_pre_exit()

One concern: the `netns_bpf_attach_type_need()` call in `netns_bpf_prog_attach()` is called for ALL attach types, not just flow dissector. The switch in `netns_bpf_attach_type_need()` handles `NETNS_BPF_FLOW_DISSECTOR` and `NETNS_BPF_SK_LOOKUP`, but what about other types? Looking at the code:

```c
static void netns_bpf_attach_type_need(enum netns_bpf_attach_type type)
{
	switch (type) {
	case NETNS_BPF_FLOW_DISSECTOR:
		static_branch_inc(&netns_bpf_flow_dissector_enabled);
		break;
#ifdef CONFIG_INET
	case NETNS_BPF_SK_LOOKUP:
		static_branch_inc(&bpf_sk_lookup_enabled);
		break;
#endif
	default:
		break;
	}
}
```

OK, so there's a default case that does nothing. That's fine.

But wait - the `netns_bpf_prog_attach()` function is called for all netns_bpf attach types. The new call to `netns_bpf_attach_type_need(type)` is unconditional for fresh attaches. Before this patch, only the link path called need/unneed. Now the legacy attach path also calls it. This seems correct - but I need to verify there's no double-counting. The link path calls `netns_bpf_attach_type_need()` via `bpf_link_inc()` or similar. Actually, looking at the code more carefully:

In `netns_bpf_prog_attach()`:
```c
	net->bpf.progs[type] = prog;
	if (attached)
		bpf_prog_put(attached);
	else
		/* Mark attach point as used on a fresh attach; a
		 * replacement keeps the existing count.
		 */
		netns_bpf_attach_type_need(type);
```

So on a fresh attach (not replacement), it calls need(). On replacement, it doesn't. That makes sense - the old prog is being replaced, so the count stays the same.

In `__netns_bpf_prog_detach()`:
```c
	attached = net->bpf.progs[type];
	if (!attached || attached != old)
		return -ENOENT;
	/* Mark attach point as unused */
	netns_bpf_attach_type_unneed(type);
	net->bpf.run_array_detach(net, type);
	net->bpf.progs[type] = NULL;
	bpf_prog_put(attached);
```

And in `netns_bpf_pernet_pre_exit()`:
```c
		if (net->bpf.progs[type]) {
			netns_bpf_attach_type_unneed(type);
			bpf_prog_put(net->bpf.progs[type]);
		}
```

Wait, there's a potential double-dec here. The pre_exit function already has a loop for links:
```c
		list_for_each_entry(net_link, &net->bpf.links[type], node) {
			net_link->net = NULL; /* auto-detach link */
			netns_bpf_attach_type_unneed(type);
		}
```

And then:
```c
		if (net->bpf.progs[type]) {
			netns_bpf_attach_type_unneed(type);
			bpf_prog_put(net->bpf.progs[type]);
		}
```

If a netns has both a link and a legacy prog attached... actually, can it? Let me think. The link and legacy attach paths are separate. I think a netns can have both a link and a legacy prog for the same type. Actually, looking at the existing code, `net->bpf.progs[type]` and `net->bpf.links[type]` are separate. A legacy prog attach sets `net->bpf.progs[type]`, while a link attach adds to `net->bpf.links[type]`. So yes, both can coexist.

If both exist, the pre_exit path would call unneed twice (once for the link, once for the prog), but need would have been called twice (once for the link attach, once for the legacy prog attach). So the counting is balanced. OK.

But actually, there's a subtlety. The pre_exit loop for links calls `netns_bpf_attach_type_unneed(type)` for each link. And then for legacy progs, it calls it again. So if there are 2 links and 1 legacy prog, need was called 3 times (2 for links, 1 for prog), and unneed is called 3 times (2 for links, 1 for prog). That's balanced.

Actually wait - I need to re-read. The existing code already had the link unneed in pre_exit. The new code adds the prog unneed. So this is adding a new unneed call that wasn't there before. If a netns has a legacy prog but no link, the need was called at attach time (new code), and unneed is called at pre_exit (new code). Balanced.

But what if a netns has a legacy prog AND a link? The need was called at legacy prog attach time and at link attach time. The unneed is called for the link in pre_exit (existing) and for the legacy prog in pre_exit (new). Still balanced.

Actually, I realize there might be a more subtle issue. Looking at the existing `netns_bpf_pernet_pre_exit()` more carefully:

```c
	list_for_each_entry(net_link, &net->bpf.links[type], node) {
		net_link->net = NULL; /* auto-detach link */
		netns_bpf_attach_type_unneed(type);
	}
	if (net->bpf.progs[type]) {
		netns_bpf_attach_type_unneed(type);
		bpf_prog_put(net->bpf.progs[type]);
	}
```

The link detach path: each link called `netns_bpf_attach_type_need()` when attached. In pre_exit, each link calls `netns_bpf_attach_type_unneed()`. Balanced.

The legacy prog path: the prog called `netns_bpf_attach_type_need()` when attached (new code). In pre_exit, it calls `netns_bpf_attach_type_unneed()` (new code). Balanced.

But what about the `__netns_bpf_prog_detach()` path? If a legacy prog is detached before pre_exit, `netns_bpf_attach_type_unneed()` is called in `__netns_bpf_prog_detach()`. Then in pre_exit, `net->bpf.progs[type]` is NULL, so the unneed is not called again. Balanced.

OK, so the counting seems correct. This patch looks reasonable on its own. It's a clean optimization that follows an existing pattern.

One concern: `DEBUG_NET_WARN_ON_ONCE(!net)` moves inside the gated block. The commit message says "it exists to catch a missing netns for the BPF hook, which is only meaningful when a program can actually be attached." This is reasonable - if no program can be attached, the netns doesn't matter. But it does mean that if someone is debugging a different issue where net is NULL, they won't get the warning. This seems acceptable.

**Patch 2: opt-in fast-path for eth + IPv{4,6} + {TCP,UDP}**

This is the core patch. Let me look for issues.

The sysctl design:
```c
static struct ctl_table flow_dissector_sysctl_table[] = {
	{
		.procname	= "eth_ip",
		.data		= &flow_dissector_eth_ip_key.key,
		.maxlen		= sizeof(flow_dissector_eth_ip_key),
		.mode		= 0644,
		.proc_handler	= proc_do_static_key,
	},
};
```

Using `proc_do_static_key` directly on `&flow_dissector_eth_ip_key.key` - this is reaching into the internal `.key` field of `struct static_key_false`. This is fragile. Let me check if `proc_do_static_key` normally takes a `struct static_key` or a boolean. Looking at the kernel, `proc_do_static_key` expects `data` to point to a `struct static_key` (or `static_key_true`/`static_key_false`). Actually, `struct static_key_false` contains a `struct static_key key` member, so `&flow_dissector_eth_ip_key.key` is a `struct static_key *`. This should work, but reaching into the internals of `static_key_false` is not great. Let me check if there's a better pattern.

Actually, looking at how `bpf_sk_lookup_enabled` is used, it's a `DEFINE_STATIC_KEY_FALSE`, and its sysctl uses... actually, I don't think bpf_sk_lookup_enabled has a sysctl. Let me think about this differently.

The use of `proc_do_static_key` is a known pattern. Looking at `net/ipv4/sysctl_net_ipv4.c`, there are examples. Actually, I recall that `proc_do_static_key` was added specifically for this kind of use. The `.data` field pointing to `&key.key` is how it's done. Let me check... In `include/linux/jump_label.h`, `struct static_key_false` is defined as `struct static_key_false { struct static_key key; };`, so `.key` is a member, not internal. This is fine.

The dispatcher:
```c
static bool flow_dissect_fast(const struct sk_buff *skb,
			      struct flow_dissector *flow_dissector,
			      void *target_container,
			      const void *data,
			      __be16 proto, int nhoff, int hlen,
			      unsigned int flags)
{
	if (flow_dissector != &flow_keys_dissector &&
	    flow_dissector != &flow_keys_dissector_symmetric)
		return false;

	if (flags & ~(unsigned int)(FLOW_DISSECTOR_F_PARSE_1ST_FRAG |
				    FLOW_DISSECTOR_F_STOP_AT_FLOW_LABEL))
		return false;
	...
```

The eligibility check restricts to the two standard dissectors. The flag check admits `PARSE_1ST_FRAG` and `STOP_AT_FLOW_LABEL`. The commit message explains why `STOP_AT_FLOW_LABEL` must be admitted (skb_get_hash passes it).

But wait - `FLOW_DISSECTOR_F_PARSE_1ST_FRAG` is admitted but the fast path defers on fragmented packets:
```c
	if (unlikely(iph->frag_off & htons(IP_MF | IP_OFFSET)))
		return false;
```

So `PARSE_1ST_FRAG` is admitted but fragments always defer. That seems correct - the flag being set means "parse first fragment", and the fast path would handle it only if the packet is a first fragment (MF set, offset 0). But the fast path defers on any fragmentation flags. Hmm, actually:

```c
	if (unlikely(iph->frag_off & htons(IP_MF | IP_OFFSET)))
		return false;
```

This defers if MF is set OR offset is non-zero. But `PARSE_1ST_FRAG` means the caller wants to parse first fragments (MF=1, offset=0). The fast path defers on MF=1, so it would defer on first fragments too. That means the flag is admitted (so the dispatcher doesn't reject the call), but the fast path always defers for any fragment. This is correct for byte-identity - the slow path with PARSE_1ST_FRAG does parse first fragments, and the fast path defers those to the slow path.

Actually, wait. Let me think about this more carefully. If `PARSE_1ST_FRAG` is set and the packet is NOT a fragment (no MF, no offset), the slow path parses it normally. The fast path would also handle it (no fragmentation flags set). So the flag being set doesn't change behavior for non-fragmented packets. The fast path handles non-fragmented packets and defers fragmented ones. This is correct.

But what about the case where `PARSE_1ST_FRAG` is NOT set and the packet is a first fragment? The slow path would stop early (not parse L4). The fast path defers (because MF is set). The slow path runs and stops early. Byte-identical. OK.

What about `STOP_AT_FLOW_LABEL`? The fast path defers on non-zero flow labels:
```c
	if (unlikely((iph->flow_lbl[0] & 0x0f) |
		     iph->flow_lbl[1] | iph->flow_lbl[2]))
		return false;
```

So for zero-label IPv6, the fast path runs regardless of whether `STOP_AT_FLOW_LABEL` is set. For non-zero label, it defers. The slow path with `STOP_AT_FLOW_LABEL` stops at a non-zero label (doesn't continue to L4). The slow path without it continues. Either way, the fast path defers on non-zero labels, so the slow path handles those. For zero labels, both fast and slow produce the same result regardless of the flag. This is correct.

Now, the key concern: the fast path writes to `target_container` directly using `skb_flow_dissector_target()`. If the fast path returns false (miss), does it leave any partial writes? The commit message says the KUnit test checks this with zeroed containers. Looking at the code:

In `flow_dissect_fast_ipv4()`:
```c
	if (unlikely(hlen - nhoff < (int)sizeof(*iph) + 4))
		return false;

	iph = (const struct iphdr *)((const u8 *)data + nhoff);

	if (unlikely(*(const u8 *)iph != FLOW_DIS_IPV4_VIHL_NOOPT))
		return false;

	if (unlikely(iph->frag_off & htons(IP_MF | IP_OFFSET)))
		return false;

	if (unlikely(iph->protocol != IPPROTO_TCP &&
		     iph->protocol != IPPROTO_UDP))
		return false;

	thoff = nhoff + (int)sizeof(*iph);

	// ... writes start here
```

All the `return false` paths come before any writes. Good. But in the tunnel descent patches, the inner helpers may write before returning false. Let me check that later.

The `key_control->thoff` calculation:
```c
		key_control->thoff = min_t(u16, thoff,
					   skb ? skb->len : hlen);
```

This uses `min_t(u16, ...)`. The slow path does `min_t(u16, thoff, hlen)` for the raw case, or `skb->len` for the skb case. Wait, let me check. Actually, looking at the slow path in `__skb_flow_dissect()`:

```c
	key_control->thoff = min_t(u16, thoff, skb ? skb->len : hlen);
```

Hmm, I'm not sure if the slow path uses `skb->len` or `hlen`. Let me look at the actual slow path code... I don't have the full slow path in the diff, but the fast path's `min_t(u16, thoff, skb ? skb->len : hlen)` looks right. Actually, I think the slow path might use `skb->len` when skb is available, and `hlen` otherwise. Let me check more carefully.

Actually, in the slow path, `key_control->thoff` is set at the `out:` label:
```c
	if (dissector_uses_key(flow_dissector, FLOW_DISSECTOR_KEY_CONTROL)) {
		key_control = skb_flow_dissector_target(flow_dissector,
							FLOW_DISSECTOR_KEY_CONTROL,
							target_container);
		key_control->thoff = min_t(u16, thoff, skb ? skb->len : hlen);
		...
	}
```

Wait, I need to look at the actual existing code. Let me check the slow path's `out:` label. From the patch context:

```c
	key_basic->n_proto = proto;
	key_basic->ip_proto = ip_proto;

	/* eth_ip shape: top-level eth+IP, TCP/UDP, no encap -- counted here
	 * because the fast path returns earlier; with the gate off this is
	 * the shape's eligible-fraction signal.
	 */
	if (ret && eth_ip_top &&
	    !(key_control->flags & FLOW_DIS_ENCAPSULATION) &&
	    (ip_proto == IPPROTO_TCP || ip_proto == IPPROTO_UDP))
		flow_dissector_count_slow(FLOW_DISSECTOR_SHAPE_ETH_IP);

	return ret;
```

The `key_control->thoff` is set earlier in the slow path, not at the `out:` label. Let me look at where it's set for IPv4:

In the slow path, for IPv4:
```c
		nhoff += iph->ihl * 4;
		...
		key_control->thoff = min_t(u16, nhoff, skb ? skb->len : hlen);
```

Wait, that's `nhoff` after adding `ihl * 4`, which is the transport header offset. The fast path does:
```c
	thoff = nhoff + (int)sizeof(*iph);
	...
	key_control->thoff = min_t(u16, thoff, skb ? skb->len : hlen);
```

Since `sizeof(struct iphdr) == 20` and `ihl == 5` (checked), `ihl * 4 == 20 == sizeof(struct iphdr)`. So `thoff` is the same. Good.

Now, the big question: **the sysctl namespace**. The sysctl table is registered with `register_net_sysctl(&init_net, "net/flow_dissector", ...)`. This registers it only in init_net. But the gates are global static keys. This means:
1. The sysctls are only visible in init_net
2. But the gates affect all netns

This is a design issue. In a containerized environment, the host operator can enable gates that affect all containers. The cover letter acknowledges this: "The gates are global (a static key patches code shared by every netns); per-netns dissector policy already has a mechanism -- the netns BPF flow dissector -- and it keeps full precedence here."

This is defensible but should be clearly documented. Actually, the sysctls being in init_net only is correct for global gates - you don't want each netns to control global state. But it means non-init netns can't even see the state. The `/proc/net/flow_dissector_stats` file is also init_net only, which the patch acknowledges.

**Major concern: the sysctl subtree design.** Creating a new `/proc/sys/net/flow_dissector/` subtree with 12+ individual sysctls is a significant API addition. Each gate is a separate static key + sysctl. This is a lot of knobs. The cover letter proposes an "auto" mode in a separate RFC, which suggests the author recognizes this is too many knobs for operators.

Actually, looking at the sysctl design more carefully: the `proc_do_static_key` handler is used. This means writing 0 or 1 to the sysctl enables/disables the static key. This is a boolean sysctl. The documentation says "All defaults are 0 (off). Flipping any of these on takes effect immediately; no kernel rebuild needed."

But there's a subtlety with `proc_do_static_key`: it's not atomic with respect to concurrent dissects. A packet being dissected when the key is flipped might be in the middle of the fast path. This is fine because the fast path is byte-identical - whether the fast or slow path runs, the result is the same. For the byte-identical shapes, this is safe.

For the descent gates, this is also safe because both paths grow the same descent. But there's a window where the key is enabled but a concurrent dissect hasn't seen it yet - that dissect would use the slow path (non-descending for descents... wait, no, the slow path also has the gated descent). Actually, both paths check the same static key for descents. So if the key is enabled, both paths descend; if disabled, neither does. The transition window is fine because the static key is just a branch hint.

Actually wait, I need to re-read this. The slow path checks `static_branch_unlikely(&flow_dissector_vxlan_inner_key)` before calling `__skb_flow_dissect_udp_encap()`. The fast path checks the same key in `flow_dissect_fast_udp_tunnels()`. So both paths agree on whether to descend. Good.

But there's a subtle issue: the fast path's eligibility check (dispatcher) also checks keys. If `eth_ip` is off but `vxlan_inner` is on, the dispatcher returns false (eth_ip gate off), so the fast path doesn't run. The slow path then runs and checks the vxlan_inner key for descent. This is correct - the slow path handles the descent even when the fast path is off. Good.

But what about the reverse: `eth_ip` is on, `vxlan_inner` is off, and a VXLAN packet arrives. The fast path's `flow_dissect_fast_ipv4()` handles the outer IPv4+UDP, writes the outer keys, then checks `flow_dissect_fast_udp_tunnels()`. Since `vxlan_inner` is off, `flow_dissect_fast_udp_tunnels()` returns `FAST_TUNNEL_NONE`, and the fast path returns true with the outer keys. The slow path would also not descend (vxlan_inner off). Byte-identical. Good.

**Patch 3: VLAN and QinQ**

The auto-toggle logic for vlan/qinq:
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

This disables qinq when vlan is turned off. And:
```c
static int proc_set_qinq_key(const struct ctl_table *table, int write,
			     void *buffer, size_t *lenp, loff_t *ppos)
{
	int ret;

	ret = proc_do_static_key(table, write, buffer, lenp, ppos);
	if (ret == 0 && write &&
	    static_branch_unlikely(&flow_dissector_qinq_key) &&
	    !static_branch_unlikely(&flow_dissector_vlan_key))
		static_branch_enable(&flow_dissector_vlan_key);
	return ret;
}
```

This enables vlan when qinq is turned on. This coupling is a bit surprising for sysctls. If an operator sets qinq=1, vlan silently becomes 1 too. If they then set vlan=0, qinq silently becomes 0. This is non-obvious behavior. I'd prefer either:
1. Reject qinq=1 when vlan=0 with an error
2. Or don't auto-toggle, and just have the code check both keys

Actually, looking at the code, the qinq gate is checked inside `flow_dissect_fast_vlan()` only at depth >= 1:
```c
	if (vlan_depth >= 1 &&
	    !static_branch_unlikely(&flow_dissector_qinq_key))
		return false;
```

And the vlan gate is checked in the dispatcher at depth 0. So if qinq is on but vlan is off, a QinQ packet would hit the dispatcher, fail the vlan gate, and go to the slow path. The auto-toggle prevents this. But it's surprising behavior. A simpler design would be: if qinq is on, the dispatcher's vlan case also checks qinq, or the qinq check is done in the dispatcher regardless of the vlan gate.

Actually, the simplest fix: just check both keys in the dispatcher. If either is on, enter `flow_dissect_fast_vlan()`. Then inside, check qinq at depth >= 1. No auto-toggle needed. But this changes the cost model slightly - when vlan is off but qinq is on, every VLAN-tagged packet would enter the helper and then check qinq at depth 0 (which would pass), then at depth 1 check qinq again. Actually this doesn't work because the dispatcher gates entry.

Hmm, actually the auto-toggle is a reasonable design choice, but it should be more clearly documented and perhaps return a notice to the user. The silent auto-toggle is the kind of behavior that surprises operators.

**Patch 4: PPPoE**

Looks straightforward. The PPPoE fast path validates the header, extracts the PPP protocol, and tail-calls into the IP fast path. One issue: the commit message mentions "static_branch_likely" but the code uses `static_branch_unlikely`:
```
  - dispatcher case `htons(ETH_P_PPP_SES)` with
    `static_branch_likely(&flow_dissector_pppoe_key)` guard
```
But the code:
```c
	case htons(ETH_P_PPP_SES):
		if (!static_branch_unlikely(&flow_dissector_pppoe_key))
			return false;
```
This is a documentation inconsistency, not a code bug. But it's confusing.

**Patch 5: MPLS**

The MPLS fast path handles only single-label (BoS=1) stacks. It mirrors the slow path's `out_good` terminal writes. The commit message explains this was caught by the KUnit test. Good.

One concern: the MPLS fast path writes `key_basic->n_proto = proto` (the MPLS ethertype) and `key_basic->ip_proto = 0`. Let me verify this matches the slow path. In the slow path, after `__skb_flow_dissect_mpls()` returns `OUT_GOOD`, the code falls through to the `out:` label which sets:
```c
	key_basic->n_proto = proto;
	key_basic->ip_proto = ip_proto;
```
Where `proto` is the MPLS ethertype and `ip_proto` is 0 (never set for MPLS). So yes, this matches.

**Patch 6: IP-in-IP**

This adds tunnel descent for IPIP. The key issue is the ENCAP flag handling:
```c
static bool flow_dissect_fast_ipip_inner(...)
{
	...
	if (!ok)
		return false;

	if (dissector_uses_key(flow_dissector,
			       FLOW_DISSECTOR_KEY_CONTROL)) {
		key_control = skb_flow_dissector_target(flow_dissector,
							FLOW_DISSECTOR_KEY_CONTROL,
							target_container);
		key_control->flags |= FLOW_DIS_ENCAPSULATION;
	}
	return true;
}
```

The ENCAP flag is OR'd in after the inner returns. The commit message explains why: the inner helpers zero `key_control->flags` on entry. Let me verify:

In `flow_dissect_fast_ipv4()`:
```c
	if (dissector_uses_key(flow_dissector,
			       FLOW_DISSECTOR_KEY_CONTROL)) {
		key_control = skb_flow_dissector_target(flow_dissector,
							FLOW_DISSECTOR_KEY_CONTROL,
							target_container);
		key_control->addr_type = FLOW_DISSECTOR_KEY_IPV4_ADDRS;
		key_control->thoff = min_t(u16, thoff,
					   skb ? skb->len : hlen);
		key_control->flags = 0;
	}
```

Yes, `key_control->flags = 0` is set unconditionally. So when the inner IP helper runs (during recursion), it zeros the flags. The ipip_inner helper then sets ENCAP after. This is correct but fragile - any future change to the inner helper that doesn't zero flags would break this.

A cleaner design would be to not zero flags in the inner helpers, or to pass a flag indicating recursion. But this is a maintainability concern, not a correctness bug.

The 4in6 residue issue is interesting:
```c
		/* Mirror the slow path's outer-IPv6 writes before the
		 * descent. The slow path fills v6addrs for the outer
		 * header and the inner pass then overwrites only what
		 * it uses — an inner IPv4 leaves the tail of the addrs
		 * union holding outer-v6 bytes. Byte-identical means
		 * reproducing exactly that, residue included.
		 */
```

This is reproducing a quirk of the slow path where an inner IPv4 overwrites only the first 8 bytes of the addrs union, leaving the tail with outer IPv6 bytes. This is the kind of thing that makes the fast path fragile - it's reproducing unintentional behavior of the slow path. If someone later "fixes" the slow path to zero the addrs union, the fast path would diverge. The KUnit test would catch this, but it's still a maintainability concern.

Actually, this is a deeper issue: the "byte-identical" contract means the fast path must reproduce all behaviors of the slow path, including unintentional ones. This makes the fast path a copy of the slow path's implementation details, not just its semantics. This is the fundamental tension in the approach.

**Patch 7: GRE**

Similar to IPIP. The GRE fast path checks `hdr->flags != 0` to ensure plain GRE (version 0, no flags). This is correct.

**Patch 8: Counters**

The per-shape counters add `this_cpu_inc` on the hot path. The commit message says "Cost is one this_cpu_inc on the already-hot classification path, summed only on read — within the pktgen cyc/pkt noise floor, and an off gate stays a NOP."

But wait - the `this_cpu_inc(flow_dissector_pcpu_stats.dissects)` is unconditional:
```c
	this_cpu_inc(flow_dissector_pcpu_stats.dissects);
```

This runs on every dissect, even when all gates are off. The commit message says "an off gate stays a NOP" but the dissects counter is always incremented. This is a regression for the default (all gates off) case. The `this_cpu_inc` is cheap but not free - it's a memory write to a per-cpu variable on every packet.

Also, the slow-path occurrence counters run even when gates are off:
```c
		/* First (outer) tag: the vlan fast-path shape. */
		flow_dissector_count_slow(FLOW_DISSECTOR_SHAPE_VLAN);
```

These `flow_dissector_count_slow()` calls are in the slow path and run regardless of gate state. They add `this_cpu_inc` calls at various points in the slow path. This is a performance regression for the default case.

The cover letter says "when a gate is off the added cost is one not-taken branch per dissect." But patch 8 adds unconditional per-cpu increments to the slow path. This contradicts the cover letter's claim.

This is a significant issue. The counters should be gated behind a static key too, or at least the dissects counter should be. The per-shape occurrence counters in the slow path are particularly concerning because they add branches and increments to the hot path.

Actually, looking more carefully at the slow path counters, they're added at specific protocol recognition points:
- VLAN: at the `dissector_vlan == FLOW_DISSECTOR_KEY_MAX` check
- PPPoE: after header validation
- MPLS: at the `case htons(ETH_P_MPLS_UC)` 
- GRE: at `case IPPROTO_GRE`
- IPIP: at `case IPPROTO_IPIP`
- eth_ip: at the `out:` label with `eth_ip_top` check

These are all points where the slow path is already doing work, so the branch is already taken. The `this_cpu_inc` is the added cost. For the eth_ip case, there's a conditional check at the out: label:
```c
	if (ret && eth_ip_top &&
	    !(key_control->flags & FLOW_DIS_ENCAPSULATION) &&
	    (ip_proto == IPPROTO_TCP || ip_proto == IPPROTO_UDP))
		flow_dissector_count_slow(FLOW_DISSECTOR_SHAPE_ETH_IP);
```

This adds several branches to the slow path's exit. For the common case (eth_ip), these branches are mostly taken. This is a measurable regression.

**The counters should be gated behind a static key that's enabled only when /proc/net/flow_dissector_stats has been read recently, or when any gate is enabled.** Or better: make the counters opt-in too.

Actually, the most concerning part is the unconditional `this_cpu_inc(flow_dissector_pcpu_stats.dissects)` at the top of the dissect path. That's a per-packet write to a per-cpu cacheline, regardless of whether any gate is on. For a network stack that prides itself on nanosecond-level optimizations, this is a regression.

**Patch 9: Bound fast-path tunnel recursion**

This is a safety fix. The recursion bound is necessary. The `num_hdrs` counter is threaded through the helpers. The initial count is set at entry:
- eth_ip: `num_hdrs = 1` (one IP header)
- vlan: `num_hdrs = vlan_depth + 2` (eth + vlan tags + IP)
- pppoe: `num_hdrs = 2` (pppoe + IP)

Wait, the initial count for the top-level dispatch is 1:
```c
		if (!flow_dissect_fast_ipv4(skb, flow_dissector,
					    target_container, data,
					    nhoff, hlen, 1))
```

And for vlan:
```c
		ok = flow_dissect_fast_ipv4(skb, flow_dissector,
					    target_container, data,
					    nhoff, hlen, vlan_depth + 2);
```

Where `vlan_depth` is 0 for single VLAN and 1 for QinQ. So `vlan_depth + 2` = 2 for single VLAN, 3 for QinQ. This counts: eth (1) + vlan tags (vlan_depth + 1) + IP (1) = vlan_depth + 3. But the code says `vlan_depth + 2`. Hmm, does the count include the Ethernet header? Let me check the slow path's `num_hdrs` counting.

In the slow path, `num_hdrs` is incremented by `skb_flow_dissect_allowed()`:
```c
static bool skb_flow_dissect_allowed(int *num_hdrs)
{
	++*num_hdrs;
	return *num_hdrs <= MAX_FLOW_DISSECT_HDRS;
}
```

And it's called at the top of the loop, before each protocol dispatch. So it counts iterations of the main loop. For eth + IPv4 + TCP, that's 1 iteration (the IPv4 case). For eth + VLAN + IPv4 + TCP, that's 2 iterations (VLAN, then IPv4). Wait, actually the Ethernet header is handled before the loop, and the loop starts at the ethertype. So:
- eth + IPv4: 1 loop iteration (IPv4)
- eth + VLAN + IPv4: 2 iterations (VLAN, IPv4)
- eth + QinQ + IPv4: 3 iterations (outer VLAN, inner VLAN, IPv4)
- eth + PPPoE + IPv4: 2 iterations (PPPoE, IPv4)

But the fast path uses:
- eth + IPv4: `num_hdrs = 1`
- eth + VLAN + IPv4: `num_hdrs = 0 + 2 = 2`
- eth + QinQ + IPv4: `num_hdrs = 1 + 2 = 3`
- eth + PPPoE + IPv4: `num_hdrs = 2`

These match! Good. And for tunnel descents, the ipip_inner helper does `++num_hdrs` before recursing. So:
- eth + IPv4 + IPIP + IPv4: 1 (outer IP) + 1 (IPIP inner) = 2, matches slow path's 2 iterations (outer IPv4, inner IPv4).

Wait, but the slow path would also count the GRE header as a separate iteration. For eth + IPv4 + GRE + IPv4:
- Slow path: 1 (IPv4) + 1 (GRE dispatch via IPPROTO_GRE, which does PROTO_AGAIN) + 1 (inner IPv4) = 3
- Fast path: 1 (outer IP) + 1 (gre_inner increments) = 2

Hmm, that doesn't match. Let me re-read. In `flow_dissect_fast_gre_inner()`:
```c
	if (++num_hdrs > MAX_FLOW_DISSECT_HDRS)
		return false;
```

So gre_inner increments num_hdrs by 1. For eth + IPv4 + GRE + IPv4:
- Fast path: enters IPv4 with num_hdrs=1, then gre_inner increments to 2, then inner IPv4 runs with num_hdrs=2.
- Slow path: skb_flow_dissect_allowed() is called at the start of each loop iteration. For IPv4 (1), then PROTO_AGAIN for GRE (2), then inner IPv4 (3). Wait, does the GRE case in the slow path call skb_flow_dissect_allowed() separately? Let me think...

Actually, in the slow path, the GRE case is handled in the `switch (ip_proto)` block, not in the main `switch (proto)` loop. It doesn't re-enter the loop for GRE itself - it sets `*p_proto = hdr->protocol` and returns `PROTO_AGAIN`, which causes the loop to re-enter with the inner protocol. So the loop iterations are:
1. IPv4 (skb_flow_dissect_allowed: num_hdrs=1)
2. Inner IPv4 via PROTO_AGAIN (skb_flow_dissect_allowed: num_hdrs=2)

The GRE header is consumed within the IPv4 iteration, not as a separate iteration. So the slow path uses 2 iterations for eth + IPv4 + GRE + IPv4. The fast path uses num_hdrs=1 (outer IP) + 1 (gre_inner) = 2. They match!

OK, but I'm not 100% sure about the IPIP case. For eth + IPv4 + IPIP + IPv4:
- Slow path: 1 (outer IPv4) + 1 (inner IPv4 via PROTO_AGAIN from IPPROTO_IPIP case) = 2
- Fast path: 1 (outer IP) + 1 (ipip_inner increments) = 2

They match. Good.

Now, the bound check: `if (++num_hdrs > MAX_FLOW_DISSECT_HDRS)`. MAX_FLOW_DISSECT_HDRS is 15. The slow path checks `*num_hdrs <= MAX_FLOW_DISSECT_HDRS` (i.e., allows up to 15). The fast path checks `++num_hdrs > MAX_FLOW_DISSECT_HDRS` (i.e., allows up to 15). So both allow the same number of headers. Good.

But there's a subtle issue: the initial num_hdrs value. The fast path starts with 1 for a top-level IPv4 dissect. The slow path starts with 0 and increments to 1 at the first loop iteration. So the fast path's initial count is 1, meaning it has already "consumed" one header (the IP header). When it descends into a tunnel, it increments to 2. The slow path would be at 1 (first IP) and then 2 (inner IP). They match.

But for VLAN, the fast path starts with `vlan_depth + 2`. For a single VLAN + IPv4, that's 2. The slow path would be at 1 (VLAN iteration) + 1 (IPv4 iteration) = 2. They match.

For PPPoE + IPv4, the fast path starts with 2. The slow path would be at 1 (PPPoE iteration) + 1 (IPv4 iteration) = 2. They match.

OK, the counting seems correct. But I'm worried about edge cases with nested tunnels through VLAN/PPPoE. For example, eth + VLAN + IPv4 + IPIP + IPv4:
- Fast path: enters IPv4 with num_hdrs=2, ipip_inner increments to 3, inner IPv4 runs with 3.
- Slow path: 1 (VLAN) + 1 (outer IPv4) + 1 (inner IPv4) = 3. They match.

And eth + VLAN + IPv4 + IPIP + IPv4 + IPIP + IPv4:
- Fast path: 2 (VLAN+IP) + 1 (first IPIP) + 1 (second IPIP) = 4
- Slow path: 1 (VLAN) + 1 (outer IP) + 1 (first inner IP) + 1 (second inner IP) = 4. They match.

Good. The bound seems correct.

**Patch 10: VXLAN inner descent**

This is where things get interesting. The descent changes behavior - it makes the dissector parse through the VXLAN header and hash on the inner flow. This is a significant behavior change, even if opt-in.

Key concerns:

1. **Port-based matching only.** The descent matches on `IANA_VXLAN_UDP_PORT (4789)`. The commit message acknowledges this: "Port discovery is hardcoded to IANA_VXLAN_UDP_PORT (4789); non-standard VXLAN ports (e.g. Cilium's 8472) are not descended." This is a significant limitation. Many deployments use non-standard ports.

2. **The slow path grows the same descent.** This is a big deal. The slow path (`__skb_flow_dissect()`) now has a `__skb_flow_dissect_udp_encap()` call that can rewrite proto/nhoff and re-enter the loop. This modifies the slow path's behavior when the gate is on. The claim is that both paths do the same thing, but now the slow path has been modified to support descents it didn't do before.

This is the crux of the issue: **the slow path is no longer the "single source of semantic truth" it was before.** The cover letter claims "The slow path remains the single source of semantic truth and the fast path is verified against it, not vice versa." But patches 10-13 modify the slow path to add new behavior (tunnel descents). The slow path is being changed to match the fast path, not the other way round. This undermines the "slow path as truth" claim.

3. **The slow path descent uses `goto proto_again`:**
```c
	if (ip_proto == IPPROTO_UDP &&
	    fdret == FLOW_DISSECT_RET_CONTINUE &&
	    !(key_control->flags & FLOW_DIS_IS_FRAGMENT) &&
	    !(flags & (FLOW_DISSECTOR_F_STOP_BEFORE_ENCAP |
		       FLOW_DISSECTOR_F_STOP_AT_ENCAP)) &&
	    static_branch_unlikely(&flow_dissector_vxlan_inner_key) &&
	    __skb_flow_dissect_udp_encap(skb, key_control, data, &proto, &nhoff,
					 hlen,
					 proto == htons(ETH_P_IP) ? AF_INET :
								    AF_INET6))
		fdret = FLOW_DISSECT_RET_PROTO_AGAIN;
```

This re-enters the loop, which means the inner packet is fully dissected by the slow path's graph walk. This is correct but adds complexity to the slow path.

4. **The check `proto == htons(ETH_P_IP) ? AF_INET : AF_INET6`** is after `__skb_flow_dissect_udp_encap()` might have changed `proto`. Wait, no - this is in the argument to the function call, so `proto` is evaluated before the call. But `proto` might have been changed by the loop from the original ethertype to ETH_P_IP or ETH_P_IPV6 after the IP header was processed. Actually, looking at the slow path, at the point where this check runs, `proto` is the current protocol being processed, which should be ETH_P_IP or ETH_P_IPV6 (since we're in the IP proto switch). Hmm, actually, at this point in the code, `proto` has been set to the IP protocol's ethertype. Let me look at the context more carefully.

Actually, I think `proto` at this point is the ethertype that was processed (ETH_P_IP or ETH_P_IPV6). The IP header processing sets `ip_proto` to the L4 protocol (IPPROTO_UDP). Then the ports are dissected. Then the UDP encap check runs. At this point, `proto` should still be ETH_P_IP or ETH_P_IPV6. So the `AF_INET`/`AF_INET6` determination is correct.

But wait - after `__skb_flow_dissect_udp_encap()` rewrites `proto` and `nhoff`, the code does `fdret = FLOW_DISSECT_RET_PROTO_AGAIN`, which causes the loop to re-enter with the new `proto` and `nhoff`. This is the standard way the slow path handles encapsulation. OK.

5. **The `__skb_flow_dissect_udp_encap()` function checks the static key internally:**
```c
	if (static_branch_unlikely(&flow_dissector_vxlan_inner_key) &&
	    flow_dissect_vxlan_inner_ok(...))
```

But the caller also checks the key:
```c
	    static_branch_unlikely(&flow_dissector_vxlan_inner_key) &&
	    __skb_flow_dissect_udp_encap(...)
```

Wait, in patch 10, the caller only checks `vxlan_inner_key`. In patch 11, it's:
```c
	    (static_branch_unlikely(&flow_dissector_vxlan_inner_key) ||
	     static_branch_unlikely(&flow_dissector_geneve_inner_key)) &&
```

And in patch 13:
```c
	    (static_branch_unlikely(&flow_dissector_vxlan_inner_key) ||
	     static_branch_unlikely(&flow_dissector_geneve_inner_key) ||
	     static_branch_unlikely(&flow_dissector_gtpu_inner_key) ||
	     static_branch_unlikely(&flow_dissector_gue_inner_key) ||
	     static_branch_unlikely(&flow_dissector_fou_inner_key)) &&
```

This is a growing OR of static branches on the slow path's hot path. Even with static keys, this is 5 branches. And `__skb_flow_dissect_udp_encap()` checks them again internally. So there's redundancy. When all are off, the OR short-circuits, but it's still 5 static_branch_unlikely checks. When any is on, all 5 are evaluated (since the OR can't short-circuit until one is true). Actually, `||` does short-circuit - if the first is true, the rest aren't evaluated. But if the first is false and the second is true, the first is still evaluated.

This is getting messy. A single static key that's enabled when ANY descent gate is on would be cleaner. Like a "summary" key.

Actually, I think a better approach would be to have a single `flow_dissector_udp_inner_any` static key that's enabled when any of the individual descent gates is on. Then the slow path only checks one key. The individual gates are still checked inside `__skb_flow_dissect_udp_encap()`.

**Patch 11: Geneve descent**

Similar to VXLAN. The `flow_dissect_geneve_inner_ok()` validator checks version 0, no options, no OAM, proto_type ETH_P_TEB. This looks correct.

One issue: the Geneve fast path only handles IPv4 outer (`if (family != AF_INET) return false`). The commit message says "Geneve-over-IPv6 outer" is kept out. But the fast path's `flow_dissect_fast_udp_tunnels()` is called for both AF_INET and AF_INET6 (from both the IPv4 and IPv6 fast paths). So a Geneve-over-IPv6 packet would enter the UDP tunnel dispatcher, check the geneve gate, call `flow_dissect_geneve_inner_ok()` which returns false for AF_INET6. This is correct but means the gate check is done even for IPv6 outer Geneve, which is a minor inefficiency.

**Patch 12: GTP-U descent**

The GTP-U validator defines its own macros:
```c
#define GTP1_HDR_VERSION	GENMASK(7, 5)
#define GTP1_HDR_PT		BIT(4)
#define GTP1_MSG_GPDU		0xff
```

These should probably come from `include/net/gtp.h` rather than being redefined. If the kernel's GTP header definitions change, these could diverge.

Also, the validator checks `gtp->flags & GTP1_F_MASK` - where is `GTP1_F_MASK` defined? It should be in `include/net/gtp.h`. Let me check... it's used but not defined in the patch. It must be from the included `<net/gtp.h>`. OK.

**Patch 13: FOU/GUE descent**

This is the most complex patch. It introduces a registered ops hook for the FOU module:

```c
struct flow_dissector_fou_ops {
	u16 (*encap_lookup)(const struct net *net, u8 family, __be16 port,
			    u8 *protocol);
};

int flow_dissector_fou_ops_register(const struct flow_dissector_fou_ops *ops);
void flow_dissector_fou_ops_unregister(const struct flow_dissector_fou_ops *ops);
```

Concerns:

1. **Only one ops provider can register.** The register function returns -EBUSY if already registered:
```c
	if (rcu_access_pointer(flow_dissector_fou_ops))
		ret = -EBUSY;
```
This is fine since only the fou module should register, but it's a limitation.

2. **The FOU lookup does a list walk:**
```c
	list_for_each_entry_rcu(fou, &fn->fou_list, list) {
		if (fou->port == port && fou->family == family) {
			*protocol = fou->protocol;
			type = fou->type;
			break;
		}
	}
```

The commit message acknowledges this: "The port lookup is an RCU list walk of the per-netns fou table -- O(configured fou/gue tunnels), typically a handful." This is acceptable for small numbers but doesn't scale.

3. **The fou module changes `list_add` to `list_add_tail_rcu` and `list_del` to `list_del_rcu`:**
```c
-	list_add(&fou->list, &fn->fou_list);
+	list_add_tail_rcu(&fou->list, &fn->fou_list);
```
This changes the fou_list to be RCU-protected. But the existing code uses `mutex_lock(&fn->fou_lock)` for writes. The RCU list walk in `fou_flow_encap_lookup()` is under `guard(rcu)()` (from `flow_dissect_fou_lookup()`). So readers use RCU, writers use mutex. This is correct.

But wait - the existing `fou_release()` function is called under `fn->fou_lock`:
```c
static void fou_release(struct fou *fou)
{
	list_del_rcu(&fou->list);
	udp_tunnel_sock_release(fou->sk);
	kfree_rcu(fou, rcu);
}
```

The `kfree_rcu(fou, rcu)` means the memory is freed after an RCU grace period. The RCU readers in `fou_flow_encap_lookup()` are safe. Good.

But I need to check: does the existing code have a `struct rcu_head rcu` member in `struct fou`? The `kfree_rcu(fou, rcu)` suggests it does. Let me check... I can't see the struct definition in the diff, but the existing code already uses `kfree_rcu(fou, rcu)` in the original `fou_release()`. Wait, the original code:
```c
 static void fou_release(struct fou *fou)
 {
-	list_del(&fou->list);
+	list_del_rcu(&fou->list);
 	udp_tunnel_sock_release(fou->sk);
 	kfree_rcu(fou, rcu);
 }
```

So `kfree_rcu(fou, rcu)` was already there. But `list_del` was used (not `list_del_rcu`). This means the existing code frees the list node via RCU but doesn't use RCU list operations. That's actually a bug in the existing code if there are concurrent readers - but there aren't, because the existing code doesn't have RCU readers of the fou_list. The patch adds RCU readers, so it correctly changes to `list_del_rcu` and `list_add_tail_rcu`.

Wait, but `list_add` is changed to `list_add_tail_rcu`. The existing code uses `list_add` under mutex. The new code uses `list_add_tail_rcu` under mutex. The `_rcu` variant includes the `smp_wmb()` (or equivalent) needed for RCU readers. This is correct.

But there's a subtlety: `list_add_tail_rcu` adds to the tail, while `list_add` adds to the head. This changes the order of the list. The `fou_flow_encap_lookup()` breaks on the first match, so the order matters if there are duplicate port/family entries. But duplicates shouldn't exist (the `fou_add_to_port_list()` function checks for conflicts). So the order change is benign.

4. **The `flow_dissect_fou_lookup()` function resolves the netns from the skb:**
```c
static u16 flow_dissect_fou_lookup(const struct sk_buff *skb, u8 family,
				   __be16 port, u8 *protocol)
{
	const struct flow_dissector_fou_ops *ops;
	const struct net *net = NULL;

	guard(rcu)();
	if (skb) {
		if (skb->dev)
			net = dev_net_rcu(skb->dev);
		else if (skb->sk)
			net = sock_net(skb->sk);
	}
	ops = rcu_dereference(flow_dissector_fou_ops);
	if (!net || !ops)
		return FOU_ENCAP_UNSPEC;
	return ops->encap_lookup(net, family, port, protocol);
}
```

This takes an RCU lock for every FOU/GUE lookup. But the lookup is only done when a gate is on, so it's acceptable. The `guard(rcu)()` is a clean way to handle the lock.

But there's a concern: `dev_net_rcu(skb->dev)` and `sock_net(skb->sk)` are called under RCU. Is this safe? `dev_net_rcu()` is the RCU-safe version of `dev_net()`. `sock_net()` is also safe under RCU. Good.

5. **The `fou_init()` function ignores the return value of `flow_dissector_fou_ops_register()`:**
```c
	/* Best-effort: the flow-dissector FOU/GUE descent is an
	 * optional consumer; failure to register (another owner) must
	 * not fail fou init.
	 */
	flow_dissector_fou_ops_register(&fou_flow_ops);
	return 0;
```

This silently ignores registration failure. The commit message explains why, but it means the FOU/GUE descent won't work if registration fails, and there's no way for the operator to know. At minimum, this should log a warning.

**Patch 14: KUnit tests**

The test suite is comprehensive - 1674 lines. It tests byte-identical equivalence, truncation, deep nesting, non-linear skb, ineligible dissectors, fuzzing, and descent tests. This is good.

Concerns:

1. **The test uses `static_branch_enable/disable` directly**, which modifies global state. In a KUnit test, this could affect other tests running concurrently. The suite init/exit functions clear all gates, which helps.

2. **The test registers a mock FOU ops provider:**
```c
KUNIT_ASSERT_EQ(test, 0,
		flow_dissector_fou_ops_register(&fd_mock_fou_ops));
```

If the real fou module is loaded, this will fail with -EBUSY. The test should handle this gracefully. Actually, since KUnit tests run in a controlled environment, the fou module might not be loaded. But if it is, the test would fail.

3. **The fuzz test runs 4000 iterations**, which is relatively few. For a kernel dissector, I'd want more. But it's a start.

4. **The test accesses `flow_keys_dissector_symmetric_kunit()`** via an exported accessor. This is a test-only export, which is acceptable but adds to the kernel's exported symbol namespace.

5. **The `flow_dissector_fast_hits_kunit()` function** sums per-cpu counters. This is a test-only accessor that reads internal state. It's under `CONFIG_FLOW_DISSECTOR_KUNIT_TEST`, so it's fine.

**Patch 15: Documentation**

This adds a general flow_dissector overview document. It mentions an "auto" mode that doesn't exist in this series:
```
An optional ``auto`` mode (``net.flow_dissector.auto``) turns that decision into
one knob: the kernel samples the per-shape counters over a packet-count window
(``net.flow_dissector.auto_window_packets``) and flips the byte-identical gates
itself, with hysteresis and a flip-rate cap, so the operator does not have to
tune each shape by hand.
```

This documents functionality that doesn't exist in the kernel. The cover letter says "A separate RFC thread proposes an adaptive auto-enable controller." Documenting non-existent functionality is misleading. This should be removed or clearly marked as proposed/future.

**Overall concerns:**

1. **The size and complexity of the series.** 15 patches, ~3800 lines added. This is a large, complex change to a core networking path. The fast path duplicates the slow path's logic for each shape, and the two must be kept in sync. The KUnit test helps, but the maintenance burden is real.

2. **The sysctl explosion.** 12+ new sysctls under `/proc/sys/net/flow_dissector/`. This is a lot of knobs for operators. The cover letter mentions an "auto" mode as a separate RFC, which suggests the author recognizes this.

3. **The counters add unconditional overhead.** The `this_cpu_inc(flow_dissector_pcpu_stats.dissects)` runs on every dissect, even when all gates are off. The slow-path occurrence counters also add branches and increments.

4. **The slow path is modified to add tunnel descents.** The cover letter claims the slow path is the "single source of semantic truth," but patches 10-13 modify the slow path to add new behavior. This is a fundamental change to the dissector's behavior, not just a fast path.

5. **The FOU/GUE ops hook** introduces a new cross-module interface. This is a maintenance burden and a potential ABI concern.

6. **The performance claims are extraordinary** (47-55% reduction). While the isolated A/B numbers are plausible for a straight-line vs. graph-walk comparison, the "allshapes" numbers (which include the icache footprint of all fast paths) are more modest. The real-world impact depends on the workload.

7. **The "byte-identical" contract is fragile.** The 4in6 residue case shows that the fast path must reproduce unintentional slow-path behavior. Any future slow-path change that affects the same packets must be mirrored in the fast path.

8. **The descent gates change hashing behavior.** This is a significant semantic change, even if opt-in. Enabling a descent gate changes `skb->hash` for tunnel traffic, which affects RPS, RFS, ECMP, bonding, and tc-flower. The operator must understand these implications.

Let me now organize these into a structured review.

Actually, let me re-check one more thing. The cover letter says:

"The series is byte-identical by contract: for any packet, the fast path either writes exactly the flow_keys bytes the slow path would have written, or it returns false and the slow path runs."

But for the descent gates, this is only true when the gate is on. When the gate is off, the fast path doesn't descend (returns the outer keys), and the slow path also doesn't descend (the descent is gated). When the gate is on, both descend. So the "byte-identical" contract holds between fast and slow paths, but the behavior vs. today's kernel changes when a descent gate is enabled. The cover letter acknowledges this: "The only behaviour change is versus today's non-descending default, and it happens only when an operator turns a gate on."

OK, so the contract is: fast == slow, always. And: with gates off, behavior == today's behavior. With descent gates on, behavior != today's behavior (but fast == slow). This is clearly stated.

Let me also check the partial-write concern more carefully. When the fast path returns false, does it leave any writes in the target_container?

For `flow_dissect_fast_ipv4()`:
- All `return false` paths come before any `skb_flow_dissector_target()` calls. ✓

For `flow_dissect_fast_ipv6()`:
- Same. ✓

For `flow_dissect_fast_vlan()`:
- The `return false` at `vlan_depth >= 2` comes before writes. ✓
- The `return false` at `hlen - nhoff < sizeof(*vlan)` comes before writes. ✓
- But after writing the VLAN key, it tail-calls into ipv4/ipv6/vlan. If the inner call returns false, the VLAN key has already been written! This is a partial write!

Wait, let me look more carefully:
```c
	if (dissector_uses_key(flow_dissector, vlan_key)) {
		key_vlan = skb_flow_dissector_target(...);
		key_vlan->vlan_id = tci_id;
		...
	}
	if (dissector_uses_key(flow_dissector,
			       FLOW_DISSECTOR_KEY_NUM_OF_VLANS)) {
		key_nvs = skb_flow_dissector_target(...);
		key_nvs->num_of_vlans++;
	}

	switch (inner_proto) {
	case htons(ETH_P_IP):
		ok = flow_dissect_fast_ipv4(...);
		break;
	...
	}
	return ok;
```

If the VLAN key is written and then the inner IPv4 call returns false, the VLAN key has been partially written. The test uses zeroed containers and checks that the full `flow_keys` matches, which would catch this... but only if the slow path also writes the VLAN key in the same case. Does the slow path write the VLAN key before failing on the inner IP?

In the slow path, the VLAN case writes the VLAN key and then continues the loop with the inner protocol. If the inner IP has options (IHL != 5), the slow path handles it (it doesn't fail - it parses it normally). So the slow path would write the VLAN key and then the IP keys. The fast path writes the VLAN key but then returns false (because IHL != 5). The slow path would produce different output (VLAN key + IP keys with options), while the fast path would have written only the VLAN key and returned false.

But wait - when the fast path returns false, the dispatcher falls through to the slow path. The slow path runs from scratch. It writes the VLAN key and the IP keys. The fast path's partial VLAN key write is in a different container (the test uses separate containers for fast and slow). So the partial write doesn't affect the slow path's result.

But the concern is: what if the fast path is called with the real target_container (not a test), writes partial data, returns false, and then the slow path runs on the same container? Does the slow path overwrite the partial data?

Looking at the call site:
```c
	if (flow_dissect_fast(skb, flow_dissector, target_container,
			      data, proto, nhoff, hlen, flags))
		return true;
```

If `flow_dissect_fast()` returns false, the slow path runs on the same `target_container`. The slow path would overwrite any partial writes. But there's a subtle issue: if the slow path doesn't write a key that the fast path partially wrote, the partial write would remain. For example, if the fast path writes `FLOW_DISSECTOR_KEY_CVLAN` (for a QinQ packet) and then the inner IP fails, the slow path might not write `FLOW_DISSECTOR_KEY_CVLAN` in the same way.

Actually, the slow path would process the same packet and write the same keys. The VLAN processing in the slow path would write the VLAN and CVLAN keys, then the IP processing would write the IP keys. So the slow path would overwrite the fast path's partial writes. But only if the slow path writes the same keys.

Hmm, but what about `FLOW_DISSECTOR_KEY_NUM_OF_VLANS`? The fast path does `key_nvs->num_of_vlans++`. If the fast path increments this and then returns false, the slow path would start with `num_of_vlans = 0` (it initializes it) and then increment it. So the slow path would set it to the correct value, overwriting the fast path's partial increment. OK.

But wait - the slow path initializes `num_of_vlans`:
```c
	if (dissector_uses_key(flow_dissector,
			       FLOW_DISSECTOR_KEY_NUM_OF_VLANS)) {
		key_num_of_vlans = skb_flow_dissector_target(flow_dissector,
							     FLOW_DISSECTOR_KEY_NUM_OF_VLANS,
							     target_container);
		key_num_of_vlans->num_of_vlans = 0;
	}
```

So it zeroes it first. Good, that overwrites the fast path's partial write.

What about `key_control->flags`? The fast path sets `key_control->flags = 0`. If the fast path returns false after this, the slow path would eventually set `key_control->flags` at the `out:` label. But would it? Let me check... the slow path's `out:` label sets:
```c
	key_control->flags = flags;
```
Wait, I need to look at the actual slow path code. In the slow path, `key_control->flags` is set from the `flags` variable which accumulates fragment flags etc. The fast path sets `key_control->flags = 0`. If the fast path returns false, the slow path would eventually set `key_control->flags` to the correct value. So the partial write is overwritten.

But there's a more subtle issue: what if the fast path writes a key that the slow path doesn't request? The eligibility check ensures only `flow_keys_dissector` and `flow_keys_dissector_symmetric` enter the fast path. These are standard dissectors with known key sets. The slow path would write the same keys. So this shouldn't be an issue.

Actually, the most concerning partial-write case is in the tunnel descents. For IPIP:
```c
static bool flow_dissect_fast_ipip_inner(...)
{
	...
	if (++num_hdrs > MAX_FLOW_DISSECT_HDRS)
		return false;

	if (inner_eth_proto == htons(ETH_P_IP))
		ok = flow_dissect_fast_ipv4(...);
	...
	if (!ok)
		return false;

	// Write ENCAP flag
	...
	return true;
}
```

If `flow_dissect_fast_ipv4()` returns true (inner IP was handled) but then the outer caller checks the return value... actually, the ipip_inner helper calls the inner IPv4 helper, which writes the inner keys. If the inner helper returns true, ipip_inner writes the ENCAP flag and returns true. If the inner helper returns false, ipip_inner returns false. In the false case, the inner helper may have written partial keys (though as we discussed, the inner helper's `return false` paths come before writes).

Actually, for the ipip_inner case, the outer IPv4 helper has already written the outer keys (addrs, basic, control) before calling ipip_inner. The ipip_inner then calls the inner IPv4 helper, which overwrites the addrs and basic. If the inner helper returns false (e.g., inner IP has options), the outer keys have been overwritten by the inner helper's partial writes... wait, no. The inner helper's `return false` paths come before any writes. So if the inner helper returns false, no inner keys have been written. The outer keys are still in the container.

But the outer IPv4 helper has already written the outer keys. When the fast path returns false (because the inner couldn't be handled), the slow path runs from scratch and overwrites everything. So the partial outer keys are overwritten.

Actually, I realize the issue is more nuanced. Let me trace through a specific case: eth + IPv4 (proto=IPIP) + inner IPv4 with options.

1. `flow_dissect_fast()` is called, dispatches to `flow_dissect_fast_ipv4()`.
2. `flow_dissect_fast_ipv4()` checks the outer IPv4: IHL=5, not fragmented, protocol=IPIP. All checks pass.
3. `flow_dissect_fast_ipv4()` writes outer keys: `key_control->addr_type = FLOW_DISSECTOR_KEY_IPV4_ADDRS`, `key_control->thoff = thoff`, `key_control->flags = 0`, `key_basic->n_proto = ETH_P_IP`, `key_basic->ip_proto = IPPROTO_IPIP`, `key_addrs->v4addrs = outer addrs`.
4. Then it checks `iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP` → true (it's IPIP).
5. `static_branch_unlikely(&flow_dissector_ipip_key)` → true (gate on).
6. `iph->protocol == IPPROTO_IPIP` → true, calls `flow_dissect_fast_ipip_inner()`.
7. `flow_dissect_fast_ipip_inner()` increments `num_hdrs`, calls `flow_dissect_fast_ipv4()` for the inner.
8. Inner `flow_dissect_fast_ipv4()` checks IHL: `*(const u8 *)iph != FLOW_DIS_IPV4_VIHL_NOOPT` → true (IHL=6). Returns false.
9. `flow_dissect_fast_ipip_inner()` gets `ok = false`, returns false.
10. `flow_dissect_fast_ipv4()` returns false (from the IPIP branch).
11. `flow_dissect_fast()` returns false.
12. Slow path runs.

At step 3, the outer keys were written. The slow path will overwrite them. But there's a window where the container has partial data. The test checks this by using zeroed containers and verifying that the fast path's miss doesn't leave partial writes that differ from the slow path's output. But the test compares the full `flow_keys` struct, so if the slow path overwrites the partial writes, the test passes.

Wait, but the test uses separate containers for fast and slow:
```c
	memset(&keys_slow, 0, sizeof(keys_slow));
	ret_slow = __skb_flow_dissect(&init_net, NULL, fd, &keys_slow, ...);

	fd_fast_gates_set(true);
	memset(&keys_fast, 0, sizeof(keys_fast));
	ret_fast = __skb_flow_dissect(&init_net, NULL, fd, &keys_fast, ...);
```

So `keys_fast` is zeroed before the fast path runs. If the fast path returns false, `keys_fast` may have partial writes. Then the slow path runs on the same `keys_fast` (since `flow_dissect_fast()` returning false causes `__skb_flow_dissect()` to continue to the slow path). Wait, no - the test calls `__skb_flow_dissect()` separately for fast and slow. Let me re-read:

```c
	fd_fast_gates_set(false);
	memset(&keys_slow, 0, sizeof(keys_slow));
	ret_slow = __skb_flow_dissect(&init_net, NULL, fd, &keys_slow,
				      data, proto, 0, hlen, flags);

	fd_fast_gates_set(true);
	memset(&keys_fast, 0, sizeof(keys_fast));
	ret_fast = __skb_flow_dissect(&init_net, NULL, fd, &keys_fast,
				      data, proto, 0, hlen, flags);
```

So `ret_slow` is the result with gates off (slow path only). `ret_fast` is the result with gates on (fast path tries first, falls back to slow path on miss). Both use zeroed containers. The test compares `keys_slow` and `keys_fast`. If the fast path partially writes and then the slow path completes the dissection, `keys_fast` would have the slow path's output (which overwrites the partial writes). So the test would pass.

But what if the fast path partially writes a field that the slow path doesn't touch? For the standard dissectors, the slow path writes all the same fields. So this shouldn't happen. But it's a fragile assumption.

The test comment says: "Zeroed containers also prove a fast-path miss never leaves partial writes behind." But that's not quite right - the zeroed containers prove that the final output matches, not that the fast path didn't leave partial writes. The slow path runs after the fast path (in the same `__skb_flow_dissect()` call) and overwrites the partial writes.

Actually, hmm. The test calls `__skb_flow_dissect()` with gates on. Inside that call, `flow_dissect_fast()` runs first. If it returns false, the slow path runs on the same container. The slow path's output is what ends up in `keys_fast`. So `keys_fast` is the slow path's output (same as `keys_slow`), not the fast path's partial output. The test is checking that the final output is the same, which it should be since both are the slow path's output.

But the test's claim of "proving no partial writes" is misleading. To actually test for partial writes, you'd need to check the container after the fast path returns false but before the slow path runs. The test doesn't do this.

This is a gap in the test coverage. The fast path could leave partial writes that happen to be overwritten by the slow path, and the test wouldn't catch it. If a future change to the slow path stops overwriting a particular field, the partial write would become visible.

OK, I think I've done enough analysis. Let me write the review.

Let me organize by severity:

**Blockers:**

1. Patch 8: Unconditional `this_cpu_inc` on every dissect (performance regression in default config)
2. Patches 10-13: Slow path modified to add tunnel descents - undermines "slow path as truth" claim and adds complexity to the hot path
3. Patch 13: FOU/GUE ops hook - new cross-module interface, silently ignores registration failure
4. Patch 15: Documents non-existent `auto` mode

**Substantial:**

5. Sysctl explosion - 12+ knobs, no per-netns, auto-toggle behavior is surprising
6. Partial writes on fast-path miss - not adequately tested
7. 4in6 residue reproduction - fragile byte-identity
8. Growing OR of static branches in slow path (patches 10-13)
9. GTP-U macro redefinition
10. KUnit test: mock FOU ops conflicts with real fou module

**Polish:**

11. Documentation inconsistency (patch 4: `static_branch_likely` vs `static_branch_unlikely`)
12. `__always_inline` on tunnel classifiers
13. FOU list order change (head vs tail)
14. Cover letter mentions "v3-namespace" in several patches (vestigial version references)

Let me write this up properly now.

Actually, I want to reconsider what's truly a blocker vs. substantial. The unconditional `this_cpu_inc` is a performance regression in the default configuration (all gates off). That's a hard NAK from a netdev perspective - you don't add overhead to the default path. The slow path modification for tunnel descents is a design concern but not necessarily a blocker if it's well-justified. The FOU/GUE ops hook is a design concern that needs discussion.

Let me also reconsider the cover letter's claims:

1. "when a gate is off the added cost is one not-taken branch per dissect" - This is false because of the unconditional `this_cpu_inc` in patch 8 and the slow-path occurrence counters.

2. "The slow path remains the single source of semantic truth" - This is undermined by patches 10-13 which modify the slow path to add new behavior.

3. "byte-identical by contract" - True for the fast vs. slow comparison, but the contract is fragile (4in6 residue, partial writes).

4. Performance claims - Plausible for isolated A/B but the "allshapes" numbers are more relevant and less dramatic.

OK, let me write the review now. I'll be thorough but focused.

One more thing I want to check: the `MAX_FLOW_DISSECT_HDRS` definition is moved in patch 10:

```c
-/* Maximum number of protocol headers that can be parsed in
- * __skb_flow_dissect
- */
-#define MAX_FLOW_DISSECT_HDRS	15
```

moves to above the fast-path helpers. This is fine mechanically but it's a code organization change that makes the diff harder to read.

Also, I want to check the `flow_dissect_fast_udp_tunnels()` function's family parameter. In the IPv4 fast path:
```c
		if (iph->protocol == IPPROTO_UDP) {
		switch (flow_dissect_fast_udp_tunnels(skb, flow_dissector,
						      target_container, data,
						      thoff, hlen, num_hdrs,
						      AF_INET)) {
```

And in the IPv6 fast path:
```c
	if (iph->nexthdr == IPPROTO_UDP) {
		switch (flow_dissect_fast_udp_tunnels(skb, flow_dissector,
						      target_container, data,
						      thoff, hlen, num_hdrs,
						      AF_INET6)) {
		}
	}
```

But the VXLAN classifier checks `if (family != AF_INET) return false;`. So VXLAN-over-IPv6 doesn't descend in the fast path. But the slow path's `__skb_flow_dissect_udp_encap()` also calls `flow_dissect_vxlan_inner_ok()` with the family parameter. So both paths agree: VXLAN-over-IPv6 doesn't descend. This is consistent.

But wait - in the IPv6 fast path, after the UDP tunnel check, the code does:
```c
	if (iph->nexthdr == IPPROTO_UDP) {
		switch (flow_dissect_fast_udp_tunnels(..., AF_INET6)) {
		case FAST_TUNNEL_DISSECTED:
			return true;
		case FAST_TUNNEL_DEFER:
			return false;
		case FAST_TUNNEL_NONE:
			break;
		}
	}

	return true;
```

So for IPv6 + UDP + no tunnel descent, the fast path returns true (the outer keys are written). This is correct - the fast path handled the outer IPv6 + UDP, and no descent is needed (or the gate is off).

But for IPv6 + UDP + VXLAN (gate on), `flow_dissect_fast_udp_tunnels()` is called with AF_INET6. `flow_dissect_vxlan_inner_ok()` returns false (family != AF_INET). So `flow_dissect_fast_udp_tunnels()` returns `FAST_TUNNEL_NONE`. The fast path returns true with the outer keys. The slow path would also not descend (same check). Byte-identical. Good.

Now, one more thing: the IPv6 fast path's UDP handling. In patch 2, the IPv6 fast path checks:
```c
	if (unlikely(iph->nexthdr != IPPROTO_TCP &&
		     iph->nexthdr != IPPROTO_UDP))
		return false;
```

But in patch 6, this is changed to handle IPIP/GRE descents. And in patch 10, the UDP tunnel descent is added. Let me trace the evolution:

After patch 2: IPv6 fast path handles TCP/UDP only. Non-TCP/UDP defers.
After patch 6: IPv6 fast path handles TCP/UDP and IPIP/GRE (when gates on). The check becomes:
```c
	if (unlikely(iph->nexthdr != IPPROTO_TCP &&
		     iph->nexthdr != IPPROTO_UDP)) {
		// IPIP / GRE handling
		...
		return false;
	}
```
After patch 10: The IPv6 fast path also handles UDP tunnel descents. But the check for UDP is already in the TCP/UDP path. The UDP tunnel descent is added after the ports are written:
```c
	if (iph->nexthdr == IPPROTO_UDP) {
		switch (flow_dissect_fast_udp_tunnels(...)) {
		...
		}
	}
	return true;
```

Wait, but in patch 10, there's a change to the IPv6 fast path:
```c
-	if (unlikely(iph->nexthdr != IPPROTO_TCP &&
-		     iph->nexthdr != IPPROTO_UDP))
-		return false;
-
 	thoff = nhoff + (int)sizeof(*iph);
```

The TCP/UDP check is removed! This means the IPv6 fast path no longer defers on non-TCP/UDP at this point. Instead, it continues to write the keys and then checks for UDP tunnels. But for non-TCP/UDP, non-tunnel protocols, the fast path would write the keys and return true, even though the slow path might handle them differently.

Wait, let me re-read the patch 10 diff more carefully:

```c
-	if (unlikely(iph->nexthdr != IPPROTO_TCP &&
-		     iph->nexthdr != IPPROTO_UDP))
-		return false;
-
 	thoff = nhoff + (int)sizeof(*iph);
```

This removes the TCP/UDP check. But the check was there to ensure only TCP/UDP are handled by the fast path. Without it, the fast path would write `key_basic->ip_proto = iph->nexthdr` for any nexthdr, including ICMP, SCTP, etc. The slow path would also write the same ip_proto. But the slow path might write additional keys (e.g., ICMP keys) that the fast path doesn't.

Wait, but the fast path only writes basic, addrs, ports, and control keys. For ICMP, the slow path would also write `FLOW_DISSECTOR_KEY_ICMP`. The fast path doesn't. So the outputs would differ.

But the fast path does write `key_ports`:
```c
	if (dissector_uses_key(flow_dissector,
			       FLOW_DISSECTOR_KEY_PORTS)) {
		const __be32 *ports = (const __be32 *)
			((const u8 *)data + thoff);
		key_ports = skb_flow_dissector_target(...);
		key_ports->ports = *ports;
	}
```

For ICMP, this would read 4 bytes at the transport header offset and write them as "ports". The slow path would do the same (it writes ports for any protocol, not just TCP/UDP). But the slow path would also write ICMP keys. So the fast path's output would be missing the ICMP keys.

Wait, but the eligibility check restricts to `flow_keys_dissector` and `flow_keys_dissector_symmetric`. Do these dissectors request `FLOW_DISSECTOR_KEY_ICMP`? Let me check... `flow_keys_dissector` is initialized in `init_default_flow_dissectors()`:
```c
	skb_flow_dissector_init(&flow_keys_dissector,
			-flow_keys, ARRAY_SIZE(flow_keys));
```

Where `flow_keys` is a static array that includes `FLOW_DISSECTOR_KEY_ICMP`. So yes, `flow_keys_dissector` requests the ICMP key. The fast path doesn't write it for ICMP packets. This is a divergence!

But wait - the removed check was `iph->nexthdr != IPPROTO_TCP && iph->nexthdr != IPPROTO_UDP`. Without this check, the IPv6 fast path would handle ICMP packets. But the fast path doesn't write the ICMP key. The slow path does. This is a byte-identity violation.

Let me look more carefully at the patch 10 diff. The removed check is in the IPv6 fast path:

```c
 	if (unlikely(iph->nexthdr != IPPROTO_TCP &&
-		     iph->nexthdr != IPPROTO_UDP))
-		return false;
-
 	thoff = nhoff + (int)sizeof(*iph);
```

Wait, but this check was already modified in patch 6 to handle IPIP/GRE. After patch 6, the check looks like:

```c
	if (unlikely(iph->nexthdr != IPPROTO_TCP &&
		     iph->nexthdr != IPPROTO_UDP)) {
		bool ipip = ...;
		bool gre = ...;
		if (!ipip && !gre)
			return false;
		// IPIP / GRE handling
		...
	}

	thoff = nhoff + (int)sizeof(*iph);
```

Then patch 10 removes the entire `if` block:
```c
-	if (unlikely(iph->nexthdr != IPPROTO_TCP &&
-		     iph->nexthdr != IPPROTO_UDP)) {
-		...
-	}
-
-	if (unlikely(iph->nexthdr != IPPROTO_TCP &&
-		     iph->nexthdr != IPPROTO_UDP))
-		return false;
-
 	thoff = nhoff + (int)sizeof(*iph);
```

Hmm, actually I need to be more careful. Let me re-read the patch 10 diff for the IPv6 fast path:

```c
@@ -1325,10 +1475,6 @@ static bool flow_dissect_fast_ipv6(const struct sk_buff *skb,
 				nhoff + (int)sizeof(*iph), hlen, num_hdrs);
 	}
 
-	if (unlikely(iph->nexthdr != IPPROTO_TCP &&
-		     iph->nexthdr != IPPROTO_UDP))
-		return false;
-
 	thoff = nhoff + (int)sizeof(*iph);
```

OK so the removed check is the second TCP/UDP check - the one after the IPIP/GRE block. In patch 6, the IPIP/GRE block was added, which handles non-TCP/UDP protocols. After the IPIP/GRE block, if the protocol is not IPIP or GRE, the code falls through to the `return false`. But if it IS IPIP or GRE, the IPIP/GRE block handles it and returns.

Wait, let me trace the patch 6 code more carefully:

```c
	if (unlikely(iph->nexthdr != IPPROTO_TCP &&
		     iph->nexthdr != IPPROTO_UDP)) {
		bool ipip = static_branch_unlikely(&flow_dissector_ipip_key) &&
			    (iph->nexthdr == IPPROTO_IPIP ||
			     iph->nexthdr == IPPROTO_IPV6);
		bool gre = static_branch_unlikely(&flow_dissector_gre_key) &&
			   iph->nexthdr == IPPROTO_GRE;

		if (!ipip && !gre)
			return false;

		// outer IPv6 writes + IPIP/GRE descent
		...
		return flow_dissect_fast_ipip_inner(...) or flow_dissect_fast_gre_inner(...);
	}

	if (unlikely(iph->nexthdr != IPPROTO_TCP &&
		     iph->nexthdr != IPPROTO_UDP))
		return false;
```

Wait, the second check is redundant after the first check! If the first `if` block handles non-TCP/UDP and returns, the code that follows is only reached for TCP/UDP. The second check is dead code after patch 6. So removing it in patch 10 is correct - it's removing dead code.

But wait, what if the first `if` block is entered but neither ipip nor gre is true? Then `return false` is executed. So the code after the first `if` is only reached when `nexthdr` is TCP or UDP. The second check is indeed redundant. Removing it is correct.

OK, so the removal is fine. The IPv6 fast path still only handles TCP/UDP (for the main path) plus IPIP/GRE (for the descent path). No ICMP packets leak through.

But then in patch 10, after the ports are written, the UDP tunnel check is added:
```c
	if (iph->nexthdr == IPPROTO_UDP) {
		switch (flow_dissect_fast_udp_tunnels(..., AF_INET6)) {
		case FAST_TUNNEL_DISSECTED:
			return true;
		case FAST_TUNNEL_DEFER:
			return false;
		case FAST_TUNNEL_NONE:
			break;
		}
	}

	return true;
```

This is fine - for UDP packets that don't match a tunnel, `FAST_TUNNEL_NONE` is returned and the fast path returns true with the outer keys. For UDP packets that match a tunnel but the inner can't be handled, `FAST_TUNNEL_DEFER` returns false. For successful descents, `FAST_TUNNEL_DISSECTED` returns true.

Wait, there's a subtle issue. For `FAST_TUNNEL_DEFER`, the fast path returns false. But the outer keys have already been written (addrs, basic, ports, control). When the slow path runs, it will overwrite these. But the partial writes exist. As discussed earlier, this is a potential issue if the slow path doesn't overwrite all fields. But for the standard dissectors, the slow path writes all the same fields. So it should be OK.

Actually, for `FAST_TUNNEL_DEFER`, the tunnel was recognized (e.g., VXLAN with valid header) but the inner IP couldn't be handled (e.g., inner IP has options). The fast path has written the outer keys. The slow path, with the descent gate on, would also recognize the tunnel and descend. The slow path's inner dissection would handle the options (since it's the full graph walk). So the slow path's output would have inner keys, not outer keys. The fast path's partial outer writes would be overwritten by the slow path's inner writes. This is correct.

But wait - `FAST_TUNNEL_DEFER` means "the fast path's tunnel classifier accepted the packet, but the inner fast path couldn't handle it." The fast path returns false. The slow path runs. The slow path also descends (gate on). The slow path handles the inner packet with the full graph walk. The output is the inner keys. The fast path's partial outer writes are overwritten. OK, this is correct.

But what about `FAST_TUNNEL_NONE`? This means no tunnel was recognized. The fast path returns true with the outer keys. The slow path would also not descend (same classifier). The outputs match. OK.

So the logic is correct. The partial-write concern is theoretical but not a practical bug for the standard dissectors.

Now let me also check the IPv4 fast path. In patch 10, the UDP tunnel check is added after the ports are written:

```c
+	if (iph->protocol == IPPROTO_UDP) {
+		switch (flow_dissect_fast_udp_tunnels(skb, flow_dissector,
+						      target_container, data,
+						      thoff, hlen, num_hdrs,
+						      AF_INET)) {
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

This is the same pattern. For UDP packets, after writing the outer keys, the tunnel descent is attempted. If no tunnel matches, `FAST_TUNNEL_NONE` and return true. If a tunnel matches but inner fails, `FAST_TUNNEL_DEFER` and return false. If successful, `FAST_TUNNEL_DISSECTED` and return true.

But there's an issue: for `FAST_TUNNEL_DEFER`, the fast path returns false after writing the outer keys. The slow path runs. But the slow path, with the descent gate on, would also try to descend. If the slow path successfully descends (because it can handle the inner packet that the fast path couldn't), the output would have inner keys. The fast path's outer key writes are overwritten. OK, this is correct.

But what if the descent gate is off? Then `FAST_TUNNEL_NONE` is returned (the tunnel classifier's gate check fails). The fast path returns true with the outer keys. The slow path also doesn't descend (gate off). Outputs match. Good.

OK, I think the logic is sound. Let me also check one more thing: the IPv4 fast path's protocol check. After patch 2, the IPv4 fast path checks:
```c
	if (unlikely(iph->protocol != IPPROTO_TCP &&
		     iph->protocol != IPPROTO_UDP))
		return false;
```

After patch 6, this becomes:
```c
	if (unlikely(iph->protocol != IPPROTO_TCP &&
		     iph->protocol != IPPROTO_UDP)) {
		// IPIP / GRE handling
		...
		return false;
	}
```

So for non-TCP/UDP, non-IPIP, non-GRE protocols (like ICMP), the fast path returns false. Good.

After patch 10, the UDP tunnel check is inside the TCP/UDP path (after the protocol check passes). So only TCP/UDP packets reach the tunnel check. Good.

OK, I'm now satisfied that the logic is correct. Let me finalize my review.

Actually, one more thing: the `flow_dissect_fast_udp_tunnels()` function is called with `thoff` (the transport header offset), not `nhoff` (the network header offset). The function then accesses the UDP header at `thoff`:
```c
	if (hlen - thoff < (int)sizeof(struct udphdr))
		return FAST_TUNNEL_NONE;
```

And the UDP ports:
```c
	const __be16 *udp_ports = (const __be16 *)((const u8 *)data + thoff);
```

Wait, `udp_ports[0]` is the source port and `udp_ports[1]` is the destination port. The classifiers check `udp_ports[1]` (destination port) against the well-known ports. This is correct.

But the length check is `hlen - thoff < sizeof(struct udphdr)`. This only checks that there's enough room for the UDP header. The individual tunnel classifiers then check for the tunnel header + inner Ethernet. For example, VXLAN:
```c
	if (hlen - thoff < (int)(sizeof(struct udphdr) +
				 sizeof(struct vxlanhdr) + ETH_HLEN))
		return false;
```

This checks for UDP + VXLAN + Ethernet. But it doesn't check for the inner IP header. The inner IP header length is checked by `flow_dissect_fast_ipv4()`/`_ipv6()` when they're called from `flow_dissect_fast_udp_inner()`. Good.

OK, I think I've been thorough enough. Let me write the review.

Actually, I realize I should also look at the FOU/GUE lookup more carefully. In `flow_dissect_fast_udp_tunnels()`:
```c
	if (static_branch_unlikely(&flow_dissector_gue_inner_key) ||
	    static_branch_unlikely(&flow_dissector_fou_inner_key)) {
		const __be16 *udp_ports =
			(const __be16 *)((const u8 *)data + thoff);
		u8 ipproto = 0;
		u16 type;

		type = flow_dissect_fou_lookup(skb, family, udp_ports[1],
					       &ipproto);
		if (type == FOU_ENCAP_GUE &&
		    static_branch_unlikely(&flow_dissector_gue_inner_key) &&
		    flow_dissect_gue_inner_ok(data, thoff, hlen,
					      &inner_proto, &inner_nhoff))
			goto descend;
		if (type == FOU_ENCAP_DIRECT &&
		    static_branch_unlikely(&flow_dissector_fou_inner_key) &&
		    flow_dissect_fou_inner_ok(ipproto, thoff,
					      &inner_proto, &inner_nhoff))
			goto descend;
	}
```

The `flow_dissect_fou_lookup()` is called for every UDP packet when either GUE or FOU gate is on. This does an RCU lock + list walk per packet. The commit message acknowledges this: "The port lookup is an RCU list walk of the per-netns fou table -- O(configured fou/gue tunnels), typically a handful -- and runs per outer-UDP packet only while a gate is on."

But this is on the fast path! The whole point of the fast path is to be fast. An RCU lock + list walk per UDP packet is not fast. If the FOU/GUE gates are on, every UDP packet (not just FOU/GUE packets) goes through this lookup. That's a significant cost.

Actually, the `guard(rcu)()` in `flow_dissect_fou_lookup()` takes the RCU read lock. But `__skb_flow_dissect()` might already be in an RCU read section (depending on the caller). Taking the RCU lock again is cheap (it's recursive for non-preemptible kernels), but it's still overhead.

Also, `flow_dissect_fou_lookup()` resolves the netns from the skb:
```c
	if (skb) {
		if (skb->dev)
			net = dev_net_rcu(skb->dev);
		else if (skb->sk)
			net = sock_net(skb->sk);
	}
```

For raw-buffer dissection (skb == NULL), the lookup returns `FOU_ENCAP_UNSPEC`. This means FOU/GUE descent doesn't work for raw-buffer dissection. The commit message says "a raw-buffer dissect (skb == NULL) does not descend." This is a limitation but acceptable since FOU/GUE are inherently stateful.

OK, I think the FOU/GUE descent is the weakest part of the series. It introduces a cross-module hook, adds per-packet RCU lock + list walk overhead, and only works in skb mode. The benefit (inner-flow hashing for FOU/GUE) is niche compared to VXLAN/Geneve/GTP-U.

Let me now write the final review. I'll focus on the most important issues.

Hmm, let me also think about whether there are any correctness bugs I've missed.

One thing I want to check: in the slow path, the UDP encap descent is gated on `fdret == FLOW_DISSECT_RET_CONTINUE`:
```c
	if (ip_proto == IPPROTO_UDP &&
	    fdret == FLOW_DISSECT_RET_CONTINUE &&
	    ...
```

`FLOW_DISSECT_RET_CONTINUE` means the IP proto processing didn't return OUT_GOOD or OUT_BAD. For UDP, the slow path's `switch (ip_proto)` has:
```c
	case IPPROTO_UDP:
		__skb_flow_dissect_ports(skb, flow_dissector, target_container,
					 data, nhoff, ip_proto, hlen);
		break;
```

The `break` means `fdret` stays at `FLOW_DISSECT_RET_CONTINUE` (set at the top of the loop). So the UDP encap check is reached. Good.

But what about fragmented packets? The check `!(key_control->flags & FLOW_DIS_IS_FRAGMENT)` ensures fragmented outers don't descend. Good.

What about `FLOW_DISSECTOR_F_STOP_AT_ENCAP` and `FLOW_DISSECTOR_F_STOP_BEFORE_ENCAP`? The check `!(flags & (FLOW_DISSECTOR_F_STOP_BEFORE_ENCAP | FLOW_DISSECTOR_F_STOP_AT_ENCAP))` ensures callers who want to stop at/before encap don't descend. Good.

But the dispatcher (fast path) already rejects these flags:
```c
	if (flags & ~(unsigned int)(FLOW_DISSECTOR_F_PARSE_1ST_FRAG |
				    FLOW_DISSECTOR_F_STOP_AT_FLOW_LABEL))
		return false;
```

So `STOP_AT_ENCAP` and `STOP_BEFORE_ENCAP` cause the fast path to defer. The slow path then runs, and the descent check in the slow path also rejects these flags. Both paths agree: no descent for stop-at-encap callers. Good.

But there's a subtle issue: the fast path rejects `STOP_AT_ENCAP` and `STOP_BEFORE_ENCAP` unconditionally, even when no descent gate is on. This means the fast path doesn't run for callers like tunnel drivers who pass these flags. Is this a performance regression? Before this series, those callers would use the slow path. After this series, they still use the slow path (fast path defers). No regression. Good.

One more thing: the `FLOW_DISSECTOR_F_STOP_AT_FLOW_LABEL` flag. The dispatcher admits it:
```c
	if (flags & ~(unsigned int)(FLOW_DISSECTOR_F_PARSE_1ST_FRAG |
				    FLOW_DISSECTOR_F_STOP_AT_FLOW_LABEL))
		return false;
```

But the IPv6 fast path defers on non-zero flow labels:
```c
	if (unlikely((iph->flow_lbl[0] & 0x0f) |
		     iph->flow_lbl[1] | iph->flow_lbl[2]))
		return false;
```

So for zero-label IPv6, the fast path runs regardless of whether `STOP_AT_FLOW_LABEL` is set. For non-zero label, it defers. The slow path with `STOP_AT_FLOW_LABEL` stops at a non-zero label (doesn't continue to L4). The slow path without it continues. Either way, the fast path defers on non-zero labels, so the slow path handles those. For zero labels, both fast and slow produce the same result regardless of the flag. This is correct.

But wait - does the slow path's behavior differ for zero-label IPv6 with and without `STOP_AT_FLOW_LABEL`? The flag says "stop at flow label" - if the label is zero, there's nothing to stop at. The slow path would continue normally. So both paths produce the same result for zero-label IPv6 regardless of the flag. The fast path's admission of the flag is correct.

OK, I'm confident in my analysis now. Let me write the review.

Let me also note: the cover letter mentions "Assisted-by: Claude:claude-fable-5" trailers. This is notable. The use of LLM assistance is disclosed, which is good. The cover letter says "Every patch carries an Assisted-by: trailer in the Documentation/process/coding-assistants.rst format." However, the trailer format "Assisted-by: Claude:claude-fable-5" doesn't match the standard format. Looking at `Documentation/process/coding-assistants.rst`, the expected format might be different. Also, "claude-fable-5" is not a real Claude model name - it might be a placeholder or internal name. This is a minor issue but worth noting.

Actually, looking at the patches, the trailer is:
```
Assisted-by: Claude:claude-fable-5 sparse smatch
```

This looks like it's trying to credit Claude for sparse/smatch cleanup, but the format is wrong. It should probably be:
```
Co-developed-by: Claude <noreply@anthropic.com>
```
or similar, per the coding-assistants.rst guidelines. And "sparse smatch" seems to be incorrectly included in the trailer. This is a polish issue.

OK, now I'll write the review. Let me structure it clearly.

Let me reconsider severity one more time:

**Blockers (would NAK or require fundamental rework):**

1. **Patch 8: Unconditional per-packet counter overhead.** `this_cpu_inc(flow_dissector_pcpu_stats.dissects)` on every dissect, plus slow-path occurrence counters, adds measurable overhead to the default configuration (all gates off). This directly contradicts the cover letter's claim of "one not-taken branch per dissect" when gates are off. The counters must be gated behind a static key.

2. **Patches 10-13: Slow path modified for tunnel descents.** The cover letter claims the slow path is the "single source of semantic truth," but these patches add new behavior to the slow path. This is a fundamental design change to `__skb_flow_dissect()` that affects all callers, not just the fast path. The slow path now has `goto proto_again` for tunnel descents, which adds complexity and potential for bugs. This needs to be clearly justified and may warrant a separate discussion from the fast-path optimization.

3. **Growing OR of static_branch checks in the slow path.** By patch 13, the slow path checks 5 static branches in an OR:
```c
(static_branch_unlikely(&flow_dissector_vxlan_inner_key) ||
 static_branch_unlikely(&flow_dissector_geneve_inner_key) ||
 static_branch_unlikely(&flow_dissector_gtpu_inner_key) ||
 static_branch_unlikely(&flow_dissector_gue_inner_key) ||
 static_branch_unlikely(&flow_dissector_fou_inner_key))
```
This should be a single summary key.

4. **Patch 15: Documents non-existent `auto` mode.** The documentation describes `net.flow_dissector.auto` and `net.flow_dissector.auto_window_packets`, which don't exist in any patch. This is misleading.

**Substantial (must fix but not necessarily NAK):**

5. **Partial writes on fast-path miss.** The fast path can write keys before returning false (e.g., VLAN keys before inner IP miss, outer IP keys before tunnel descent miss). The KUnit test doesn't actually verify "no partial writes" - it compares final output after the slow path has overwritten partial writes. A dedicated test that checks the container state after a fast-path miss would be needed.

6. **4in6 residue reproduction.** The IPIP patch reproduces the slow path's unintentional behavior where inner IPv4 overwrites only the first 8 bytes of the IPv6 addrs union, leaving residue. This makes the fast path dependent on a slow-path implementation detail.

7. **Sysctl API design.** 12+ new sysctls is a lot. The auto-toggle behavior for vlan/qinq is surprising. The sysctls are init_net only but control global state. Consider a simpler API (e.g., a single bitmask, or a per-netns approach via the existing BPF flow dissector mechanism).

8. **FOU/GUE ops hook.** New cross-module interface for a niche feature. The per-packet RCU lock + list walk on the fast path is expensive. The registration failure is silently ignored. Consider deferring FOU/GUE to a follow-up series.

9. **KUnit test: FOU mock conflicts with real fou module.** If the fou module is loaded, `flow_dissector_fou_ops_register(&fd_mock_fou_ops)` returns -EBUSY and the test fails.

10. **GTP-U macro definitions.** `GTP1_HDR_VERSION`, `GTP1_HDR_PT`, `GTP1_MSG_GPDU` are defined locally rather than using existing definitions from `include/net/gtp.h`.

**Polish:**

11. Patch 4 commit message says `static_branch_likely` but code uses `static_branch_unlikely`.
12. Vestigial "v3-namespace" references in patch commit messages (patches 3-5).
13. `Assisted-by: Claude:claude-fable-5 sparse smatch` trailer format is incorrect.
14. `MAX_FLOW_DISSECT_HDRS` definition moved for code organization, making the diff noisier.
15. The `__always_inline` on tunnel classifiers may be excessive - `inline` would suffice.

OK, I think that's comprehensive. Let me write it up now.

Wait, I also want to flag one more thing about the counter placement. The `eth_ip_top` flag in the slow path:

```c
+	int nhoff_init = 0;
+	bool eth_ip_top = false;
```

And:
```c
+	nhoff_init = nhoff;
```

And:
```c
+		/* Top-level eth+IPv4: eth_ip shape candidate (confirmed at out:). */
+		if (nhoff == nhoff_init)
+			eth_ip_top = true;
```

This checks if the current nhoff equals the initial nhoff. For a top-level IPv4 packet, the first protocol processed is IPv4, and nhoff has been advanced past the Ethernet header but not past any other headers. So `nhoff == nhoff_init` is true. For a VLAN-tagged packet, the first protocol is VLAN, which advances nhoff. When IPv4 is processed, nhoff has been advanced past the VLAN tag, so `nhoff != nhoff_init`. This correctly identifies top-level eth+IPv4.

But what about the case where the packet has no Ethernet header (raw IP)? In that case, `nhoff` starts at 0, and the IPv4 processing starts with `nhoff == 0 == nhoff_init`. So `eth_ip_top` is true. But is this correct? For raw IP, there's no Ethernet header, so it's not "eth+IP". But the counter is for the "eth_ip" shape, which the fast path handles for both eth+IP and raw IP (the fast path doesn't check for an Ethernet header). So this is consistent.

Actually, wait. The fast path's `flow_dissect_fast()` is called with `proto` set to the ethertype (ETH_P_IP or ETH_P_IPV6). It doesn't check for an Ethernet header. So the fast path handles both eth+IP and raw IP. The slow path's `eth_ip_top` flag also doesn't check for an Ethernet header - it just checks if the IP header is the first protocol. So both paths are consistent.

But the counter name "eth_ip" is misleading for raw IP. Minor issue.

One more concern: the `eth_ip_top` check adds a branch to the slow path's hot path (every IPv4/IPv6 packet):
```c
+		if (nhoff == nhoff_init)
+			eth_ip_top = true;
```

This is a comparison and a conditional set. It's cheap but it's still overhead on the default path (gates off).

OK, I'll include this in the counter overhead discussion.

Let me finalize the review now.
