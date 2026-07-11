# External LLM review: r5-deepdive (auto RFC)

finish: stop | usage: {"prompt_tokens":57229,"total_tokens":82840,"completion_tokens":25611,"prompt_tokens_details":null,"reasoning_tokens":24066}

## Review

Here is a technical deep-dive review of the RFC. Findings are grounded in the provided text, ordered by severity, and include concrete recommendations.

### 1. Division on the hot path (Blocker)
`__skb_flow_dissect()` is one of the hottest paths in the network stack. The RFC adds a division to it when `auto` is enabled:
```c
+static inline void flow_dissector_auto_account(void)
+{
+	u32 thresh = READ_ONCE(fd_auto_window) / num_online_cpus();
```
Performing a division (`/ num_online_cpus()`) on every packet is unacceptable for performance. Furthermore, `num_online_cpus()` can change at runtime, but the division is done unconditionally.

**What to change:** Precompute the per-CPU threshold into a variable (e.g., `fd_auto_thresh`) when `auto_window_packets` is written, and update it via a CPU hotplug notifier. Then use `READ_ONCE(fd_auto_thresh)` on the hot path.

### 2. Preemption race in per-CPU accounting (Blocker)
The per-CPU counter update is not preemption-safe:
```c
+	if (this_cpu_inc_return(fd_auto_pcpu) >= max_t(u32, thresh, 1)) {
+		this_cpu_write(fd_auto_pcpu, 0);
+		schedule_work(&fd_auto_work);	/* coalesces if already pending */
+	}
```
`__skb_flow_dissect()` can be called from process context with preemption enabled. The `this_cpu_*` RMW operations are not preemption-safe. If the thread is preempted between `this_cpu_inc_return` and `this_cpu_write`, it may migrate to another CPU, and `this_cpu_write` will zero the wrong CPU's counter, corrupting the window accounting.

**What to change:** Use `get_cpu_ptr()` / `put_cpu_ptr()` to disable preemption around the per-CPU RMW, or use an atomic `local_t` if preemption must stay enabled.

### 3. Sysctl vs. Worker race (High)
The comment on the windowing state is incorrect:
```c
+/* Windowing state — file-scope so the sysctl handler can re-baseline on an
+ * off->on transition. Only ever touched by the single-threaded worker and the
+ * sysctl write path (serialised by the sysctl mutex), so no extra locking.
+ */
```
The sysctl mutex does not protect against the worker. If `auto` is turned off and on quickly, `flow_dissector_auto_reset()` can race with a currently running `flow_dissector_auto_worker()`. The worker could compute deltas using stale baselines, flip gates erroneously, and overwrite the freshly reset baselines.

**What to change:** Call `cancel_work_sync(&fd_auto_work)` inside `proc_set_auto` before modifying the windowing state.

### 4. Torn reads and missing READ_ONCE in worker (High)
The worker sums `u64` per-CPU counters that are concurrently updated by `this_cpu_inc()`:
```c
+		for (i = 0; i < FLOW_DISSECTOR_SHAPE__MAX; i++)
+			total[i] += s->occurrences[i] + s->fast_hits[i];
+		*dissects += s->dissects;
```
On 32-bit architectures, `this_cpu_inc()` on a `u64` is two 32-bit writes, so the worker can read a torn value. Furthermore, the worker reads these values without `READ_ONCE()`, allowing the compiler to read multiple times. This can result in huge, corrupt deltas (`dtot`) that skew the `div64_u64` math and cause spurious gate flips.

**What to change:** Use `READ_ONCE()` for all counter reads in the worker. To fix torn reads on 32-bit, the fast-path series should use `local64_t` or `u64_stats_sync` for these counters.

### 5. `fd_auto_managed` is not a whitelist (Medium)
The function determining which shapes are auto-managed is a blacklist:
```c
+static bool fd_auto_managed(enum flow_dissector_shape s)
+{
+	return s != FLOW_DISSECTOR_SHAPE_MPLS;
+}
```
The cover letter explicitly states that UDP-tunnel descent gates "are never auto-managed, because enabling them changes hashing". If a future patch adds those descent shapes to `enum flow_dissector_shape`, this blacklist will return `true`, and they will be auto-managed, silently changing hashing behavior.

**What to change:** Change this to a whitelist of explicitly managed shapes, returning `false` for the `default` case.

### 6. Effective window size is half of documented (Medium)
The worker evaluates after half the configured window:
```c
+	if (ddiss < READ_ONCE(fd_auto_window) / 2)
+		return;
```
The documentation says "after roughly this many dissects the kernel re-evaluates". However, this check causes the worker to evaluate after `auto_window_packets / 2` dissects. If the admin sets the window to 1M, decisions happen every 500k packets.

**What to change:** Either change the check to `ddiss < READ_ONCE(fd_auto_window)` or update the documentation to say "after at least half this many dissects".

### 7. KUnit coverage gap (Medium)
The test claims to cover rate-cap behavior:
```c
+	/* A rate-capped decision stays pending: the dwell saturates and
+	 * the decision keeps asserting instead of wrapping away.
+	 */
+	r = 0;
+	for (i = 0; i < 300; i++)
+		r = flow_dissector_auto_decide_kunit(pbe + 1001, pbe, false,
+						     &en, &dis);
+	KUNIT_EXPECT_EQ(test, 1, r);
```
This only tests `fd_auto_decide()` in isolation. It does not test the worker's logic of *not* clearing the dwell counters when a flip is rate-capped (`if (flip && time_after(...))`). The worker's interaction with the rate cap is completely untested.

**What to change:** Add a test that mocks or drives the worker to verify that dwell counters are preserved when a flip is rate-capped.

### 8. Break-even mismatch for GRE vs IPIP (Low)
The break-even values differ:
```c
+	[FLOW_DISSECTOR_SHAPE_IPIP]   = 800,
+	[FLOW_DISSECTOR_SHAPE_GRE]    = 1000,
```
The comment says "gre's S was not separately microbenched; it is treated as a single descent (~ipip class)." If they are the same class, they should have the same break-even value. `1000` vs `800` is a 25% difference.

**What to change:** Set `GRE` to `800` to match `IPIP`, or explain the discrepancy.

### Verdict
**Not ready to post as an RFC.** The division on the hot path and the preemption race in `flow_dissector_auto_account` are netdev blockers. The sysctl vs. worker race and torn reads are also serious correctness issues. The design is sound, but these mechanical issues must be fixed before the RFC is sent.

## Reasoning trace

The user wants a technical deep-dive review of an RFC patch series for "adaptive auto-enable for the flow_dissector fast-path gates".
I need to review the provided RFC patch file (`series5-rfc-auto/v1-0001-net-flow_dissector-adaptive-auto-enable-packet-wi.patch`), the cover letter, and the context from the fast-path series.
The review should focus on:
- Per-cpu window accounting (num_online_cpus division, CPU hotplug, counter wrap)
- Worker's snapshot/delta math (div64 use, races with counter increments and with concurrent sysctl writes)
- Pure decision function and its KUnit coverage (any policy behaviour the tests miss?)
- Static-key discipline (fd_auto_on_key edges, re-baselining on enable)
- Vlan/qinq coupling under auto
- Memory ordering
- Anything the documentation promises that the code does not do.

Ground every finding in the text, quote relevant lines, order by severity, say what to change, end with a short verdict.

Let's dissect the patch carefully.

### Per-CPU Window Accounting & Hot Path
```c
+static inline void flow_dissector_auto_account(void)
+{
+	u32 thresh = READ_ONCE(fd_auto_window) / num_online_cpus();
+
+	if (this_cpu_inc_return(fd_auto_pcpu) >= max_t(u32, thresh, 1)) {
+		this_cpu_write(fd_auto_pcpu, 0);
+		schedule_work(&fd_auto_work);	/* coalesces if already pending */
+	}
+}
```
Problems:
1. `num_online_cpus()` can change due to CPU hotplug. `thresh` could be 0 if `fd_auto_window` < `num_online_cpus()`, though `max_t(u32, thresh, 1)` handles the 0 case.
2. If `fd_auto_window` is changed concurrently via sysctl, `thresh` changes, which is fine, but `READ_ONCE(fd_auto_window)` is good.
3. `this_cpu_inc_return` wraps u32. At 100 million pps per CPU, it wraps in ~40 seconds. That's fine. Wait, the threshold is around 1M / num_online_cpus. So it hits the threshold way before wrapping. But what if `fd_auto_window` is set to something huge, or we don't hit the threshold? Actually, `fd_auto_window` max is bounded by sysctl? `fd_auto_window_min = 1000`, but no max. So a sysadmin could set it to 4 billion. `u32` can hold up to 4B, but `this_cpu_inc_return` on a u32 will wrap eventually if the threshold is > 4B and we never reset it. But if the threshold is > 4B, we'd never schedule work? Wait, if `fd_auto_window` is UINT_MAX, `thresh = UINT_MAX / num_online_cpus()`. E.g., on a 4-core system, `thresh` is ~1B. We'll hit it before wrapping. Wait, what if `fd_auto_window` is 0? `fd_auto_window_min` is 1000.
4. Race condition: `this_cpu_inc_return` and `this_cpu_write(fd_auto_pcpu, 0)`. Wait, `this_cpu_inc_return` and `this_cpu_write` are safe on the same CPU. But wait, `schedule_work(&fd_auto_work)` just schedules a worker.
5. But wait, `fd_auto_pcpu` is `u32`. `this_cpu_inc_return` on a `u32` is atomic w.r.t the local CPU. Wait, does `this_cpu_inc_return` exist for u32? Yes, `this_cpu_add_return` usually.
Wait, let's look at `flow_dissector_auto_account`:
```c
+	u32 thresh = READ_ONCE(fd_auto_window) / num_online_cpus();
+	if (this_cpu_inc_return(fd_auto_pcpu) >= max_t(u32, thresh, 1)) {
```
Actually, `this_cpu_inc_return` is not a standard macro in Linux for all types, but `this_cpu_add_return` or `this_cpu_inc_return` usually works for 1/2/4/8 bytes. Wait, `this_cpu_inc_return(pcp)` is defined as `this_cpu_add_return(pcp, 1)`. Wait, the return type might be int or the type of the variable? If `fd_auto_pcpu` is `u32`, it might return `u32` or `int`. Let's assume it's fine.
Wait, the threshold division is integer division: `fd_auto_window / num_online_cpus()`. If `num_online_cpus()` is 128 and `fd_auto_window` is 1000000, `thresh` is 7812. 128 * 7812 = 999936. So it triggers after ~999936 packets across all CPUs, not exactly 1,000,000. That's fine, but the comment says "every ~fd_auto_window dissects". This is true.

Wait, a more serious problem: `fd_auto_pcpu` is reset to 0 by `this_cpu_write(fd_auto_pcpu, 0)`. If two packets arrive on the same CPU almost simultaneously? No, per-cpu ops are atomic w.r.t the local CPU. Wait, they are not interrupt safe! `__skb_flow_dissect()` can be called from interrupt context (e.g., net_rx_action).
If `__skb_flow_dissect()` is called in softirq context, `this_cpu_inc_return` is perfectly safe if it's preempt-safe. Wait! In Linux, `this_cpu_add_return` does NOT disable preemption or interrupts by itself. If the code runs in process context with preemption enabled, it can be preempted and migrate to another CPU between reading the per-cpu offset and writing, corrupting the per-cpu variable.
Wait, `__skb_flow_dissect` is often called from process context (e.g. `skb_get_hash` from tcp_recvmsg, or from RPS which might be in softirq context) but it can also be called from softirq.
If called from process context with preemption on, `this_cpu_inc_return(fd_auto_pcpu)` is a classic preemption race! It should be `this_cpu_inc_return(fd_auto_pcpu)` inside `get_cpu_var()` / `put_cpu_var()`, or just use `__this_cpu_inc_return` if we are sure preemption is off, or use a local_t. Actually, the kernel documentation says: "this_cpu_read/write/... operations are preemption safe. this_cpu_add_return is also preemption safe." Wait! The generic this_cpu macros DO disable preemption if they are RMW operations? No, `this_cpu_add_return` does NOT disable preemption. It relies on the fact that it's a single RMW instruction on x86, but on other architectures it isn't and it's not preemption safe! Wait, actually `this_cpu_add_return` is NOT preemption safe in generic code. You must use `local_irq_save()` or similar if it can be called in process context and preempted, or it's just a known bug.
Wait! The fast-path counters also do:
`this_cpu_inc(flow_dissector_pcpu_stats.occurrences[shape]);`
This is exactly the same pattern. If `flow_dissector_pcpu_stats.occurrences` is a `u64`, `this_cpu_inc` is NOT preemption safe on 32-bit architectures! But the fast path patch was already reviewed. The RFC asks me to scrutinize "the per-cpu window accounting... worker's snapshot/delta math".
But actually, `this_cpu_inc` is only atomic w.r.t the local CPU. If preempted, the CPU changes, so it increments the wrong CPU's counter? No, the per-cpu offset is computed *before* the increment. If preempted, the offset points to CPU A, but we execute on CPU B, writing to CPU A's memory. That's a bug!
Wait, does `this_cpu_inc` disable preemption? No, `this_cpu_inc` is `__this_cpu_inc` if preemption is already disabled, or `this_cpu_inc` if it's a single instruction? No, `this_cpu_add_return` is explicitly NOT preemption safe in generic include/linux/percpu.h. Wait, let's check `this_cpu_add_return` definition: it uses `__this_cpu_add_return` if preemption is disabled, otherwise it warns or is unsafe. Wait, no, `this_cpu_add_return` is `__this_cpu_add_return` with a preemption check? No, `this_cpu_add_return` does NOT disable preemption. Wait, in recent kernels, `this_cpu_add_return` is safe? No, only `this_cpu_cmpxchg` is safe if you retry. Wait, `local_t` is for preemption-safe per-cpu counters. But for u64 on 32-bit, you need `local64_t`.
But let's look at `this_cpu_inc_return(fd_auto_pcpu)`. If it's unsafe, I should mention it. But wait! `this_cpu_inc_return` is `this_cpu_add_return(pcp, 1)`. In Linux, `this_cpu_add_return` is defined as:
```c
#define this_cpu_add_return(pcp, val) ({ \
    __this_cpu_preempt_check("add_return"); \
    __this_cpu_add_return(pcp, val); })
```
Wait, `__this_cpu_preempt_check` just warns if `DEBUG_PREEMPT` is on and preemption is enabled. It does NOT disable preemption. If you call it in process context with preemption on, it is a bug. But `__skb_flow_dissect` is sometimes called with preemption enabled? No, usually RPS/RFS are in softirq. But `skb_get_hash()` can be called in process context. And preemption is enabled. So `this_cpu_inc_return` is indeed a bug if preemption is enabled.
Wait, how does `this_cpu_inc(flow_dissector_pcpu_stats.dissects)` work? Same bug. But I am reviewing the RFC. So I will point it out: "use `this_cpu_add_return` or `local_t`? No, `this_cpu_add_return` requires preemption to be disabled. To be safe, use `this_cpu_inc` inside `get_cpu_var` / `put_cpu_var`." Or wait, `this_cpu_inc` does not have the preemption issue if it's a `u32` or `long` and the arch has a single RMW instruction? No, generic percpu doesn't guarantee that. Wait, `u32` is `this_cpu_add_1/2/4/8`. On x86, `this_cpu_add_4` is a single instruction `add %eax, %fs:per_cpu_offset`. It is atomic w.r.t preemption on the *same* CPU, but if preempted, it runs on another CPU and writes to the *original* CPU's variable. Wait, if it computes the offset to CPU A, gets preempted, runs on CPU B, it will write to CPU A's per-cpu memory. That is a bug! It writes to CPU A instead of CPU B.
To fix this, one should use `get_cpu_var()` / `put_cpu_var()`.
```c
	u32 *cnt = get_cpu_ptr(fd_auto_pcpu);
	(*cnt)++;
	if (*cnt >= thresh) {
		*cnt = 0;
		put_cpu_ptr(cnt);
		schedule_work(&fd_auto_work);
	} else {
		put_cpu_ptr(cnt);
	}
```
Wait, `schedule_work` can be called with preemption enabled.
Let's check if `this_cpu_inc_return(fd_auto_pcpu)` is safe. In `__skb_flow_dissect`:
```c
	this_cpu_inc(flow_dissector_pcpu_stats.dissects);
+	if (static_branch_unlikely(&fd_auto_on_key))
+		flow_dissector_auto_account();
```
If `__skb_flow_dissect` is called in process context, `this_cpu_inc` is racy. But wait, `__skb_flow_dissect` is called from `skb_get_hash` which is often called from process context. `skb_get_hash` calls `__skb_flow_dissect` with preemption enabled. `this_cpu_inc` is technically a bug if `DEBUG_PREEMPT` is enabled? Wait! `this_cpu_inc` is preemption safe? No, `this_cpu_read` / `this_cpu_write` / `this_cpu_add` are *not* preemption safe. They assume the caller has preemption disabled. But wait, `this_cpu_inc` on an `int` is often safe because on x86 it's a single instruction, and even if preempted, the address `%fs:var` is computed using the original CPU's `%fs` base. Wait, no, the offset is computed at compile time? No, `%fs:per_cpu_offset` is a runtime offset. `__get_cpu_var(var)` computes `__per_cpu_offset[raw_smp_processor_id()] + offset`. If preempted, `smp_processor_id()` changes, but the offset is already loaded into a register! So it writes to the old CPU's per-cpu area. But that's okay for a counter, because the counter still gets incremented! The only issue is that the wrong CPU's counter gets incremented, which is a statistical error, not a crash. But it's still a bug.
Wait, does `__skb_flow_dissect` disable preemption? No.
But wait, `this_cpu_inc_return(fd_auto_pcpu)` requires RMW. If the offset is loaded, preempted, it increments the wrong CPU's counter, AND it might read the wrong value to compare against `thresh`. This is a bug. You should use `get_cpu_ptr()` to disable preemption.

Another issue:
`u32 thresh = READ_ONCE(fd_auto_window) / num_online_cpus();`
If `fd_auto_window` is 1000000 and `num_online_cpus()` is 128, `thresh` is 7812.
If a CPU comes online or goes offline, `num_online_cpus()` changes. That's fine.
But what if `num_online_cpus()` is evaluated as 0? It can never be 0. But what if `fd_auto_window` is 1000, and `num_online_cpus()` is 128, `thresh` is 7. 128 * 7 = 896. The worker runs after 896 packets. That's fine.
But wait! The worker uses:
```c
+	if (ddiss < READ_ONCE(fd_auto_window) / 2)
+		return;
```
Wait, what if `READ_ONCE(fd_auto_window)` is changed concurrently? `fd_auto_window` is a `unsigned int`. `READ_ONCE` is fine.

What about `flow_dissector_stats_totals`?
```c
+static void flow_dissector_stats_totals(u64 total[FLOW_DISSECTOR_SHAPE__MAX],
+					u64 *dissects)
+{
+	int cpu, i;
+
+	memset(total, 0, sizeof(u64) * FLOW_DISSECTOR_SHAPE__MAX);
+	*dissects = 0;
+	for_each_possible_cpu(cpu) {
+		const struct flow_dissector_stats *s =
+			per_cpu_ptr(&flow_dissector_pcpu_stats, cpu);
+
+		for (i = 0; i < FLOW_DISSECTOR_SHAPE__MAX; i++)
+			total[i] += s->occurrences[i] + s->fast_hits[i];
+		*dissects += s->dissects;
+	}
+}
```
The worker reads `s->occurrences[i]`, `s->fast_hits[i]`, `s->dissects`. These are `u64`. They are incremented by `this_cpu_inc()`. Wait, the fast path patch uses `this_cpu_inc` for `u64`!
```c
+static inline void flow_dissector_count_slow(enum flow_dissector_shape shape)
+{
+	this_cpu_inc(flow_dissector_pcpu_stats.occurrences[shape]);
+}
```
If `occurrences` is `u64`, `this_cpu_inc` on a 64-bit variable on a 32-bit architecture is TWO 32-bit writes. It's not atomic. When the worker reads it, it might read a half-updated value.
Wait! The RFC says I must scrutinize the "worker's snapshot/delta math (div64 use, races with counter increments and with concurrent sysctl writes)".
Yes! The worker reads `u64` values that are updated by `this_cpu_inc` without synchronization. On 32-bit systems, this is a torn read. The worker does:
`total[i] += s->occurrences[i] + s->fast_hits[i];`
If it reads a torn value, the sum is wrong.
Moreover, even on 64-bit, `this_cpu_inc` is not guaranteed to be atomic w.r.t the worker if the worker reads it. But since it's per-cpu, the worker only reads it, and the CPU only increments it. There is no RMW on the worker side, just `+=`. So if the worker reads it while it's being incremented, on 64-bit it reads either the old or new value. That's fine. But on 32-bit, it's a torn read.
To fix this, the worker should use `READ_ONCE` or `u64_stats_sync`, or the counters should be `local64_t`. Since the worker does a delta `dtot = total[i] - fd_auto_snap_total[i]`, a torn read could cause a huge delta, leading to `frac` wrapping or being `0` (due to `div64_u64`).
Wait, `div64_u64` is used:
```c
+		u32 frac = ddiss ? (u32)div64_u64(dtot * 10000, ddiss) : 0;
```
Wait, `dtot` is `u64`, `ddiss` is `u64`. `dtot * 10000` can overflow a `u64`?
If `dtot` is large, `dtot * 10000` can overflow. But `dtot` is the number of dissects for *one shape* over *one window*. The window is 1,000,000 dissects. So `dtot` is at most ~1,000,000. `1,000,000 * 10000` = 10,000,000,000, which fits in `u64` (and even `u32` is 4 billion, so 10B overflows `u32`! Wait, `dtot * 10000` is a `u64` multiplication. It fits in `u64`. But wait! `frac` is `u32`. `div64_u64` returns `u64`. We cast to `u32`. 10,000,000,000 / 1,000,000 = 10,000. So `frac` is at most 10,000. This fits in `u32`.
BUT wait! `total[i]` is the *cumulative* counter since boot.
`dtot = total[i] - fd_auto_snap_total[i]`.
What if `total[i]` is torn on 32-bit? `total[i]` could be e.g., `0x00000000FFFFFFFF` and the worker reads `0x0000000100000000`. If it tears, it might read `0x0000000000000000` or `0x00000001FFFFFFFF`. Then `dtot` could be negative (or huge in unsigned), and `frac` would be completely wrong.
The worker should use `u64_stats_fetch_begin_irq` / `u64_stats_fetch_retry_irq` or similar, or the counters should be `local64_t` and read with `local64_read`. But wait, `local64_read` is still a single 64-bit read on 64-bit, but on 32-bit it's two 32-bit reads. Actually, `u64_stats_sync` is the standard way to do this in Linux for per-cpu u64 counters.
Wait, the fast-path series already uses `this_cpu_inc` for `u64` counters. The RFC builds on that. The fast-path patch says:
```c
+struct flow_dissector_stats {
+	u64 occurrences[FLOW_DISSECTOR_SHAPE__MAX];
+	u64 fast_hits[FLOW_DISSECTOR_SHAPE__MAX];
+	u64 dissects;
+};
```
This is a known bug pattern for 32-bit architectures. But I am reviewing the RFC. I must point out that the worker does `total[i] += s->occurrences[i] + s->fast_hits[i]` and `dtot = total[i] - fd_auto_snap_total[i]`, which computes a delta. If `total[i]` tears, the delta is corrupted. The auto worker might make bad decisions. I should definitely point this out.

Also, the sysctl write concurrency:
```c
+static int proc_set_auto(const struct ctl_table *table, int write,
+			 void *buffer, size_t *lenp, loff_t *ppos)
+{
+	bool was_on = static_key_enabled(&fd_auto_on_key);
+	int ret = proc_do_static_key(table, write, buffer, lenp, ppos);
+
+	if (ret == 0 && write && !was_on &&
+	    static_key_enabled(&fd_auto_on_key)) {
+		flow_dissector_auto_reset();
+		schedule_work(&fd_auto_work);
+	}
+	return ret;
+}
```
The comment says:
```c
+/* Windowing state — file-scope so the sysctl handler can re-baseline on an
+ * off->on transition. Only ever touched by the single-threaded worker and the
+ * sysctl write path (serialised by the sysctl mutex), so no extra locking.
+ */
```
Wait, the sysctl write path is serialized by `sysctl_mutex`. The worker is a `workqueue`. Can the worker be running while `proc_set_auto` is called?
Yes! `schedule_work(&fd_auto_work)` just puts it on the system workqueue. If `auto` is turned off, the worker checks `if (!static_key_enabled(&fd_auto_on_key)) return;`. But there is a race:
1. Worker is running, passes the `static_key_enabled` check.
2. Admin turns `auto` off.
3. Admin turns `auto` on. `proc_set_auto` calls `flow_dissector_auto_reset()`, which zeroes the baselines.
4. The previously running worker continues, computes deltas, and writes `fd_auto_snap_total = total`.
But `proc_set_auto` is protected by `sysctl_mutex`. The worker is NOT holding `sysctl_mutex`.
So `flow_dissector_auto_reset()` and the worker can race!
"Only ever touched by the single-threaded worker and the sysctl write path (serialised by the sysctl mutex), so no extra locking." -> This is false. The worker is a separate thread. The sysctl mutex does NOT protect against the worker.
To fix: `cancel_work_sync(&fd_auto_work)` should be called in `proc_set_auto` before modifying the state, or a mutex should be taken by the worker.

Also, what about `fd_auto_window` sysctl?
```c
+	{
+		.procname	= "auto_window_packets",
+		.data		= &fd_auto_window,
+		.maxlen		= sizeof(fd_auto_window),
+		.mode		= 0644,
+		.proc_handler	= proc_douintvec_minmax,
+		.extra1		= &fd_auto_window_min,
+	},
```
If `fd_auto_window` is changed, the hot path uses `READ_ONCE(fd_auto_window)`. The worker uses `READ_ONCE(fd_auto_window) / 2`. This is fine. But what if the new window is much smaller? The worker might have already accumulated a large delta. It will just trigger a decision and then resync. That's fine.

Wait, the hot path:
```c
+static inline void flow_dissector_auto_account(void)
+{
+	u32 thresh = READ_ONCE(fd_auto_window) / num_online_cpus();
+
+	if (this_cpu_inc_return(fd_auto_pcpu) >= max_t(u32, thresh, 1)) {
+		this_cpu_write(fd_auto_pcpu, 0);
+		schedule_work(&fd_auto_work);	/* coalesces if already pending */
+	}
+}
```
Wait! `this_cpu_inc_return` returns the new value. If it is `>= thresh`, it sets it to 0 and calls `schedule_work`.
What if `thresh` is 1? It will call `schedule_work` on *every* packet! The worker coalesces if already pending, but if the worker runs fast, it will call `schedule_work` repeatedly.
But more importantly, what if the worker is slow? `schedule_work` just sets a bit. So it's fine.

Wait, `fd_auto_window` is 1,000,000. `thresh` is 1M / `num_online_cpus()`.
If a CPU goes offline, `num_online_cpus()` changes. The worker is already running.
Wait, `this_cpu_inc_return(fd_auto_pcpu)` is preemption-unsafe as discussed.

Let's look at `fd_auto_flip`:
```c
+static void fd_auto_flip(enum flow_dissector_shape s, bool on)
+{
+	struct static_key_false *k = fd_auto_key(s);
+
+	if (!k)
+		return;
+	if (on)
+		static_branch_enable(k);
+	else
+		static_branch_disable(k);
+
+	/* Respect the vlan/qinq coupling (mirrors proc_set_vlan/qinq_key):
+	 * qinq requires vlan; turning vlan off drops qinq.
+	 */
+	if (s == FLOW_DISSECTOR_SHAPE_QINQ && on)
+		static_branch_enable(&flow_dissector_vlan_key);
+	if (s == FLOW_DISSECTOR_SHAPE_VLAN && !on)
+		static_branch_disable(&flow_dissector_qinq_key);
+}
```
Wait, the vlan/qinq coupling logic here:
If `s == QINQ` and `on` is true, it enables `vlan_key`.
But what if `vlan_key` was turned off manually by the admin?
The comment in the doc says: "Manual gate writes while auto is on may be overridden at the next window (documented); set auto=0 to pin gates by hand."
So overriding `vlan_key` is fine.
BUT, what if `s == VLAN` and `on` is false? It disables `qinq_key`.
Wait! What if `s == VLAN` and `on` is true? It does NOT enable `qinq_key`. That's correct.
What if `s == QINQ` and `on` is false? It does NOT disable `vlan_key`. That's correct.
Wait, does this properly mirror `proc_set_vlan_key`?
`proc_set_vlan_key`:
```c
+	if (ret == 0 && write &&
+	    !static_branch_unlikely(&flow_dissector_vlan_key) &&
+	    static_branch_unlikely(&flow_dissector_qinq_key))
+		static_branch_disable(&flow_dissector_qinq_key);
```
If `vlan` is turned off, `qinq` is cleared.
If `vlan` is turned on, it doesn't touch `qinq`.
`fd_auto_flip` does the same: if `s == VLAN` and `!on`, it disables `qinq`.
Wait, `fd_auto_flip` does this:
```c
+	if (s == FLOW_DISSECTOR_SHAPE_VLAN && !on)
+		static_branch_disable(&flow_dissector_qinq_key);
```
This is correct.

Wait, look at the policy decision:
```c
+static int fd_auto_decide(u32 frac, u32 pbe, bool on,
+			  u8 *en_dwell, u8 *dis_dwell)
+{
+	u32 lo;
+
+	if (!on) {
+		*en_dwell = frac > pbe + FD_AUTO_MARGIN_HI ?
+			    min_t(u8, *en_dwell + 1, FD_AUTO_DWELL) : 0;
+		*dis_dwell = 0;
+		return *en_dwell >= FD_AUTO_DWELL ? 1 : 0;
+	}
+
+	lo = pbe > FD_AUTO_MARGIN_LO ? pbe - FD_AUTO_MARGIN_LO : 0;
+	*dis_dwell = frac < lo ?
+		     min_t(u8, *dis_dwell + 1, FD_AUTO_DWELL) : 0;
+	*en_dwell = 0;
+	return *dis_dwell >= FD_AUTO_DWELL ? -1 : 0;
+}
```
Wait! `frac > pbe + FD_AUTO_MARGIN_HI`
What if `pbe + FD_AUTO_MARGIN_HI` overflows?
`pbe` is at most 6950. `FD_AUTO_MARGIN_HI` is 1000. Sum is 7950. It fits in `u32`.
What about `pbe > FD_AUTO_MARGIN_LO`? `FD_AUTO_MARGIN_LO` is 500. `pbe` is at least 400 (from the test case `pbe = 400`). Wait, the test case has:
`flow_dissector_auto_decide_kunit(0, 400, true, &en, &dis)`
If `pbe = 400`, `pbe > FD_AUTO_MARGIN_LO` is `400 > 500` which is false. So `lo = 0`.
Then `*dis_dwell = frac < 0 ? ... : 0`. Since `frac` is `u32`, `frac < 0` is false. So `*dis_dwell = 0`. The gate can never auto-disable! The comment says: "A break-even below the 5pp disable margin clamps lo to 0: the gate can then never auto-disable (frac cannot go below 0)."
Is this intended? Yes, the test explicitly tests this:
```c
+	/* A break-even below the 5pp disable margin clamps lo to 0: the
+	 * gate can then never auto-disable (frac cannot go below 0).
+	 */
+	en = 0;
+	dis = 0;
+	for (i = 0; i < 5; i++)
+		KUNIT_EXPECT_EQ(test, 0,
+				flow_dissector_auto_decide_kunit(0, 400, true,
+								 &en, &dis));
```
But wait! If `pbe` is 400, the break-even is 4%. The enable margin is +10%, so enable at 14%. The disable margin is -5%, so disable at -1%, which clamps to 0. So the gate can never disable. Is this a good policy? Maybe. If a shape is so cheap to enable that its break-even is 4%, you basically always want it on if it ever hits 14%. This seems fine.

Let's check the `fd_auto_flip` rate cap:
```c
+		if (flip &&
+		    time_after(jiffies,
+			       fd_auto_last_flip + FD_AUTO_FLIP_MIN_IVAL)) {
+			fd_auto_flip(i, flip > 0);
+			fd_auto_last_flip = jiffies;
+			fd_auto_en_dwell[i] = 0;
+			fd_auto_dis_dwell[i] = 0;
+		}
```
Wait! If the flip is rate-capped (i.e., `time_after` is false), it DOES NOT clear the dwell counters!
The comment says:
```c
+/* Pure per-window policy decision for one shape. Updates the dwell
+ * counters and returns +1 to enable, -1 to disable, 0 to hold. The
+ * caller applies the global flip-rate cap and clears the dwell on an
+ * actual flip, so a rate-capped decision stays pending (the dwell
+ * saturates at FD_AUTO_DWELL instead of wrapping).
+ */
```
Wait, if `flip` is non-zero, but rate-capped, the dwell is NOT cleared. It stays at 3.
On the next window, `fd_auto_decide` is called.
If `frac` is still above `pbe + 10pp`, `*en_dwell = min_t(u8, *en_dwell + 1, FD_AUTO_DWELL)`. It's already 3, so it stays 3. `flip` will be 1 again!
This means it will try to flip on EVERY window until the rate cap allows it. This is exactly what the comment says: "a rate-capped decision stays pending (the dwell saturates at FD_AUTO_DWELL instead of wrapping)."
Wait, the test for this is:
```c
+	/* A rate-capped decision stays pending: the dwell saturates and
+	 * the decision keeps asserting instead of wrapping away.
+	 */
+	en = 0;
+	dis = 0;
+	r = 0;
+	for (i = 0; i < 300; i++)
+		r = flow_dissector_auto_decide_kunit(pbe + 1001, pbe, false,
+						     &en, &dis);
+	KUNIT_EXPECT_EQ(test, 1, r);
```
Wait, this test just checks that `fd_auto_decide` returns 1 after 300 calls. But `fd_auto_decide` does NOT apply the rate cap! The caller does. So the test is testing that the dwell saturates. But it doesn't test the *caller's* behavior of not clearing the dwell when rate-capped.
Wait, if `fd_auto_decide` returns 1, and the caller rate-caps it, the caller does NOT clear `en_dwell`. So next time `fd_auto_decide` is called, it will still return 1. This is correct.
But wait! What if `frac` DROPS below the margin in the next window? Then `*en_dwell` is reset to 0! The pending decision is lost.
Is that what we want?
If a shape is above the margin for 3 windows, then drops below, the flip is cancelled. That makes sense.
But wait, what if `flip` is 1, rate-capped, and next window `frac` drops slightly but is STILL above the margin? `*en_dwell` stays 3, `flip` is 1. It will try again. This is correct.

Wait, is there any bug in `fd_auto_decide` regarding `dis_dwell` and `en_dwell`?
```c
+	if (!on) {
+		*en_dwell = frac > pbe + FD_AUTO_MARGIN_HI ?
+			    min_t(u8, *en_dwell + 1, FD_AUTO_DWELL) : 0;
+		*dis_dwell = 0;
+		return *en_dwell >= FD_AUTO_DWELL ? 1 : 0;
+	}
```
If `on` is false, it only increments `en_dwell` and zeroes `dis_dwell`.
If `on` is true:
```c
+	lo = pbe > FD_AUTO_MARGIN_LO ? pbe - FD_AUTO_MARGIN_LO : 0;
+	*dis_dwell = frac < lo ?
+		     min_t(u8, *dis_dwell + 1, FD_AUTO_DWELL) : 0;
+	*en_dwell = 0;
+	return *dis_dwell >= FD_AUTO_DWELL ? -1 : 0;
```
This looks perfectly symmetric and correct.

Wait, what about the `fd_auto_last_flip` initialization?
`static unsigned long fd_auto_last_flip;` is 0.
On boot, `jiffies` is 0. `time_after(jiffies, fd_auto_last_flip + FD_AUTO_FLIP_MIN_IVAL)` might be false for the first second. This is fine.
Wait, `fd_auto_last_flip` is updated by the worker. What if the worker is rate-capped? It doesn't update `fd_auto_last_flip` unless it actually flips. So the rate cap is >= 1s between *actual* flips. This is correct.

Wait, the KUnit coverage of the pure decision function. The RFC asks: "any policy behaviour the tests miss?"
1. The KUnit test only tests `fd_auto_decide`. It does NOT test the worker's rate cap logic, i.e. that the dwell is NOT cleared when rate-capped. The worker code that skips clearing the dwell is:
```c
+		if (flip &&
+		    time_after(jiffies,
+			       fd_auto_last_flip + FD_AUTO_FLIP_MIN_IVAL)) {
+			fd_auto_flip(i, flip > 0);
+			fd_auto_last_flip = jiffies;
+			fd_auto_en_dwell[i] = 0;
+			fd_auto_dis_dwell[i] = 0;
+		}
```
This logic is completely untested! The pure function is tested, but the worker's interaction with the rate cap is not.
2. What if `flip` is 1, but rate-capped, and then next window `flip` is -1? The worker doesn't do anything because it's rate-capped, and `en_dwell` and `dis_dwell` are updated by `fd_auto_decide`. `en_dwell` would be zeroed because `flip` is -1 (which means `on` is true, so `en_dwell` is zeroed anyway).
3. What if `frac` is exactly `pbe`? The test checks `pbe` in the deadband:
```c
+	/* Hysteresis deadband: a fraction between the margins holds the
+	 * current state in both directions, forever.
+	 */
+	for (i = 0; i < 10; i++) {
+		KUNIT_EXPECT_EQ(test, 0,
+				flow_dissector_auto_decide_kunit(pbe, pbe,
+								 false, &en,
+								 &dis));
+		KUNIT_EXPECT_EQ(test, 0,
+				flow_dissector_auto_decide_kunit(pbe, pbe,
+								 true, &en,
+								 &dis));
+	}
```
Wait, `frac` and `pbe` are in 1/100 of a percent. So `pbe = 1920` is 19.20%. `frac` is `dtot * 10000 / ddiss`. So `frac` is in 1/100 of a percent. This is consistent.

Wait, the KUnit test calls `fd_auto_policy_test`. It does not test the actual `flow_dissector_auto_worker`. Since the worker has complex logic (rate cap, delta math, not clearing dwell on rate cap), it would be good to have a test for it. But since it's an RFC, maybe that's okay. I will note it as a miss.

Let's check the static-key discipline:
`fd_auto_on_key`
```c
+DEFINE_STATIC_KEY_FALSE(fd_auto_on_key);	/* net.flow_dissector.auto */
```
In `__skb_flow_dissect`:
```c
+	if (static_branch_unlikely(&fd_auto_on_key))
+		flow_dissector_auto_account();
```
In `proc_set_auto`:
```c
+	bool was_on = static_key_enabled(&fd_auto_on_key);
+	int ret = proc_do_static_key(table, write, buffer, lenp, ppos);
```
Wait! `proc_do_static_key` enables or disables the key based on the value written.
If admin writes `1` to `auto`, `proc_do_static_key` enables `fd_auto_on_key`.
Then `proc_set_auto` calls `flow_dissector_auto_reset()` and `schedule_work(&fd_auto_work)`.
What if admin writes `0` to `auto`?
`proc_do_static_key` disables `fd_auto_on_key`.
`was_on` is true. `!was_on` is false. So it doesn't reset.
BUT! Does it cancel the worker?
No! If the worker is already scheduled or running, it will run.
The worker starts with:
```c
+static void flow_dissector_auto_worker(struct work_struct *work)
+{
+	u64 total[FLOW_DISSECTOR_SHAPE__MAX], dissects, ddiss;
+	int i;
+
+	if (!static_key_enabled(&fd_auto_on_key))
+		return;
```
If the worker runs after `auto` is turned off, it will return immediately. This is correct.
But wait! What if `auto` is turned off, and then turned on again very quickly?
1. `auto` is on. Worker is running.
2. Admin turns `auto` off. `proc_do_static_key` disables key. `was_on` is true, so `!was_on` is false. Worker is NOT cancelled.
3. Admin turns `auto` on. `was_on` is false. `proc_do_static_key` enables key. `flow_dissector_auto_reset()` is called. `schedule_work(&fd_auto_work)` is called.
4. The OLD worker (from step 1) finishes its `if (!static_key_enabled...)` check (which is now true because of step 3!), and proceeds to execute with the *old* baseline (which was just zeroed by `flow_dissector_auto_reset()` in step 3!).
Wait! `flow_dissector_auto_reset()` updates `fd_auto_snap_total` and `fd_auto_snap_dissects`.
The old worker calls `flow_dissector_stats_totals(total, &dissects)`.
Then computes `ddiss = dissects - fd_auto_snap_dissects`.
Since `fd_auto_snap_dissects` was just updated to the current cumulative `dissects`, `ddiss` will be 0 (or very small).
Then it checks `if (ddiss < READ_ONCE(fd_auto_window) / 2) return;`.
So it will return! This is safe!
But what if the old worker had *already* computed `total` and `dissects` BEFORE `flow_dissector_auto_reset()` was called?
1. Old worker calls `flow_dissector_stats_totals(total, &dissects)`. (Takes a snapshot of current counters).
2. Admin turns `auto` off. (Key disabled).
3. Admin turns `auto` on. `was_on` is false. Key enabled. `flow_dissector_auto_reset()` updates `fd_auto_snap_total` to current counters.
4. Old worker computes `ddiss = dissects - fd_auto_snap_dissects`. Since `fd_auto_snap_dissects` is now the *current* counters, and `dissects` was the *old* counters, `ddiss` will be NEGATIVE (or underflow to a huge value)!
5. Old worker computes `dtot = total[i] - fd_auto_snap_total[i]`. Also negative!
6. Old worker computes `frac = ddiss ? (u32)div64_u64(dtot * 10000, ddiss) : 0;`. With huge `ddiss` and huge negative `dtot`, `frac` could be anything.
7. Old worker calls `fd_auto_decide`. It might flip a gate!
8. Old worker writes `fd_auto_snap_total = total`. This overwrites the baseline with the OLD counters!
This is a RACE CONDITION.
To fix: `proc_set_auto` MUST call `cancel_work_sync(&fd_auto_work)` when turning `auto` off, and also when turning it on (before resetting), to ensure no stale worker is running.
```c
+static int proc_set_auto(const struct ctl_table *table, int write,
+			 void *buffer, size_t *lenp, loff_t *ppos)
+{
+	bool was_on = static_key_enabled(&fd_auto_on_key);
+	int ret = proc_do_static_key(table, write, buffer, lenp, ppos);
+
+	if (ret == 0 && write && !was_on &&
+	    static_key_enabled(&fd_auto_on_key)) {
+		flow_dissector_auto_reset();
+		schedule_work(&fd_auto_work);
+	}
+	return ret;
+}
```
If we add `cancel_work_sync(&fd_auto_work)` here, it fixes the race. The comment "Only ever touched by the single-threaded worker and the sysctl write path (serialised by the sysctl mutex), so no extra locking" is false because the worker is not holding the mutex.

Let's look at `fd_auto_pcpu` wrap.
`u32 thresh = READ_ONCE(fd_auto_window) / num_online_cpus();`
`fd_auto_window` is `unsigned int`. Max value of `unsigned int` is 4,294,967,295.
If `fd_auto_window` is 4 billion, and `num_online_cpus()` is 1, `thresh` is 4 billion.
`this_cpu_inc_return(fd_auto_pcpu)` will increment a `u32`. It will take 4 billion packets to trigger the worker. 4 billion packets is not that much (a few minutes at 10Gbps). Wait, no, 4 billion packets is ~4 minutes at 14Mpps. It will wrap around to 0 and keep going! It will NEVER reach 4 billion because it wraps at 4 billion!
Wait, `this_cpu_inc_return` returns `u32`. If it wraps from `0xFFFFFFFF` to `0x00000000`, the condition `>= max_t(u32, thresh, 1)` will be false!
So if `thresh` is > `0xFFFFFFFF` (which is impossible because `thresh` is `u32`), it would never trigger. But `thresh` is `u32`, so max is 4B. If `thresh` is 4B, and it wraps, it goes from 0xFFFFFFFF to 0. It never reaches 4B. So it never triggers!
Wait, `fd_auto_window` max is not bounded in sysctl. `extra2` is not set!
```c
+		.procname	= "auto_window_packets",
+		.data		= &fd_auto_window,
+		.maxlen		= sizeof(fd_auto_window),
+		.mode		= 0644,
+		.proc_handler	= proc_douintvec_minmax,
+		.extra1		= &fd_auto_window_min,
+	},
```
If admin sets `auto_window_packets` to 5,000,000,000, it's truncated to 705,032,704 (since it's `unsigned int`).
Wait, `proc_douintvec_minmax` will reject values > `UINT_MAX`? Actually, `proc_douintvec_minmax` uses `unsigned int`, so max is `UINT_MAX`. So it can be up to 4,294,967,295.
If `fd_auto_window` is 4,294,967,295, `thresh` is 4,294,967,295. The per-cpu counter will wrap before reaching `thresh`!
Actually, `this_cpu_inc_return` on a `u32` will wrap at `UINT_MAX`. If `thresh` is `UINT_MAX`, it will reach `UINT_MAX` and then trigger! Because `>= UINT_MAX` is true when it reaches `UINT_MAX`.
Wait! If it reaches `UINT_MAX`, the next packet will increment it to `UINT_MAX + 1`, which wraps to `0`. `0 >= UINT_MAX` is false.
So it triggers exactly ONCE, at `UINT_MAX`, if `thresh` is `UINT_MAX`. But what if `thresh` is `UINT_MAX` and we start from 0? We increment to 1, 2, ... `UINT_MAX`. When it reaches `UINT_MAX`, it triggers! Then it resets to 0. Then it needs another `UINT_MAX` packets to trigger again.
Wait, if `thresh` is 4B, it takes 4B packets per CPU to trigger. That's fine, it will trigger. It doesn't "never trigger". It triggers every 4B packets.
But what if `thresh` is 4B, and we have 2 CPUs? `thresh` is 2B per CPU. It triggers after 2B packets per CPU.
Wait, `u32` is fine. It won't "never trigger" unless `thresh` is exactly `0` and `max_t(u32, thresh, 1)` makes it 1.
Wait, what if `fd_auto_window` is 0? `fd_auto_window_min` is 1000, so it can't be 0.
So wrap is not a bug that prevents triggering, it just means the window is huge.

But wait! What if `num_online_cpus()` changes?
If a CPU is offlined, `num_online_cpus()` decreases. `thresh` increases. The per-cpu counter might already be > new `thresh`, so it triggers immediately on the next packet. That's fine.
If a CPU is onlined, `num_online_cpus()` increases. `thresh` decreases. The per-cpu counter might be < new `thresh`. It will take longer to trigger. That's fine.

Let's look at memory ordering.
`this_cpu_inc_return(fd_auto_pcpu)` vs worker reading `flow_dissector_pcpu_stats`.
The worker reads `s->occurrences[i]` etc. The hot path increments them.
On x86, `this_cpu_inc` is a single instruction, which is strongly ordered. But on weakly ordered architectures (ARM), `this_cpu_inc` is a load-modify-store. It doesn't have any memory barriers.
The worker reads the counters. Since the worker is on a different CPU, it might see stale values.
BUT, `schedule_work()` inserts a memory barrier!
When the hot path calls `schedule_work(&fd_auto_work)`, it does a write to the workqueue. This implies a `smp_wmb()` (or similar).
When the worker runs, it reads the workqueue, which implies a `smp_rmb()`.
So all increments before `schedule_work()` are visible to the worker.
Wait! `schedule_work` is called when `this_cpu_inc_return(fd_auto_pcpu) >= thresh`.
The counters `occurrences` and `fast_hits` are incremented BEFORE `dissects` and BEFORE `flow_dissector_auto_account()`.
```c
+	this_cpu_inc(flow_dissector_pcpu_stats.dissects);
+	if (static_branch_unlikely(&fd_auto_on_key))
+		flow_dissector_auto_account();
```
Wait, `dissects` is incremented, then `auto_account` is called. `auto_account` calls `schedule_work`.
What about `occurrences` and `fast_hits`?
They are incremented inside `flow_dissect_fast()` or the slow path, which happens BEFORE `this_cpu_inc(dissects)`?
Let's check the fast path patch:
```c
+	this_cpu_inc(flow_dissector_pcpu_stats.dissects);
+
+	if (flow_dissect_fast(skb, flow_dissector, target_container,
+			      data, proto, nhoff, hlen, flags))
+		return true;
```
Wait! `this_cpu_inc(dissects)` is called BEFORE `flow_dissect_fast`!
And `flow_dissect_fast` calls `flow_dissector_count_fast()`.
Then `flow_dissect_fast` returns `true`. Then `__skb_flow_dissect` returns.
Wait! If `flow_dissect_fast` returns `true`, `flow_dissector_auto_account()` is NEVER CALLED!
```c
+	this_cpu_inc(flow_dissector_pcpu_stats.dissects);
+	if (static_branch_unlikely(&fd_auto_on_key))
+		flow_dissector_auto_account();
+
+	if (flow_dissect_fast(skb, flow_dissector, target_container,
+			      data, proto, nhoff, hlen, flags))
+		return true;
```
Wait, `flow_dissector_auto_account()` is called BEFORE `flow_dissect_fast`!
So `dissects` is incremented, then `auto_account` is called (which might schedule work), THEN `flow_dissect_fast` is called (which increments `fast_hits`).
If `auto_account` schedules work, the worker might run BEFORE `fast_hits` is incremented!
This means the worker might not see the `fast_hits` for the current packet, but it DOES see the `dissects`!
This means `dtot` (occurrences + fast_hits) could be less than `ddiss` (dissects) for a given window.
Is that a problem?
`frac = ddiss ? (u32)div64_u64(dtot * 10000, ddiss) : 0;`
If `dtot` is less than `ddiss`, `frac` will be slightly smaller. But it's an approximation anyway.
Wait, what if the worker runs on another CPU, and due to weak memory ordering, it sees the `dissects` increment but NOT the `fast_hits` increment?
`schedule_work` does provide barriers. But the `fast_hits` increment happens AFTER `schedule_work`!
So the worker is guaranteed to NOT see the `fast_hits` increment for the packet that triggered `schedule_work`. It might see it on the next run.
This means `dtot` can be temporarily less than `ddiss`. `frac` will be slightly lower than it should be. This is probably harmless.
BUT, what about the slow path?
In the slow path, `occurrences` is incremented at the classification point, which is BEFORE `out:` label.
And `dissects` is incremented at the very beginning.
So `occurrences` is incremented after `dissects`? No, `dissects` is incremented at the beginning. `occurrences` is incremented in the middle.
So `dtot` could be less than `ddiss` due to reordering or timing.
This is a minor statistical inaccuracy, not a fatal bug. But I should mention it. The order of incrementing `dissects` and `auto_account` vs `fast_hits` could be improved by incrementing `dissects` after the fast path, or moving `auto_account` to the end.
Wait, if `auto_account` is moved to the end, we can't return early from `flow_dissect_fast`. So `auto_account` has to be before `flow_dissect_fast`.
Actually, it's fine.

Let's look at the documentation vs code:
The cover letter says:
"Decisions use window deltas, never cumulative counters (a since-boot ratio asymptotically freezes)."
Code:
```c
+	if (ddiss < READ_ONCE(fd_auto_window) / 2)
+		return;
```
Wait! The worker returns if `ddiss < window / 2`.
But the hot path triggers the worker every `window / ncpus` per CPU.
So the worker will be triggered every `window` packets total.
But multiple CPUs might trigger it simultaneously. `schedule_work` coalesces, so only one worker runs.
When the worker runs, it computes `ddiss = dissects - snap`.
If `ddiss < window / 2`, it returns!
Why does it do this?
Because multiple CPUs might trigger the worker early. For example, if window is 1M, and we have 128 CPUs, each CPU triggers at 7812 packets. One CPU might trigger at 7812 packets total! Then `ddiss` is 7812, which is < 500,000. So the worker returns.
This is a clever coalescing mechanism! The worker only does work if enough packets have accumulated.
But wait! What if `ddiss` is NEVER >= `window / 2`?
If the traffic rate is very low, say 1000 packets per second. `window` is 1M. `ddiss` will grow slowly. The worker is triggered every 7812 packets per CPU. It will check `ddiss`, see it's < 500,000, and return.
Eventually, after 500,000 packets, `ddiss` will be >= 500,000. The worker will run.
But wait! What triggers the worker after 500,000 packets?
The hot path triggers the worker every 7812 packets per CPU. So yes, the worker will be triggered, and this time `ddiss` will be >= 500,000, so it will run.
This is correct! It means the worker doesn't waste time making decisions on small bursts.
But wait! The cover letter says: "every ~auto_window_packets dissects the worker re-evaluates".
But the code says it re-evaluates when `ddiss >= window / 2`!
This means it can re-evaluate after 500,000 packets, not 1,000,000!
Is this a bug?
If it evaluates at 500,000, it computes `frac = dtot * 10000 / 500,000`. Then it updates the baseline.
Then it waits for another 500,000 packets?
Wait, if it evaluates at 500,000, the next trigger will be at 500,000 + 7812. `ddiss` will be 7812, which is < 500,000. So it returns.
It will wait until another 500,000 packets arrive, then evaluate again.
So the window size is actually 500,000 packets, not 1,000,000!
The documentation says "every ~auto_window_packets". But the code effectively uses `window / 2` as the decision interval.
This is a documentation mismatch! "every ~auto_window_packets" vs `window / 2`.
Actually, if the traffic is bursty, it might trigger at exactly 1M. But if it triggers at 800k, `ddiss` is 800k, which is > 500k. It evaluates. Then the baseline is 800k. The next evaluation will be at 800k + 500k = 1.3M.
So the interval is between `window / 2` and `window + window / 2`.
This is a bit loose. But the documentation says "after roughly this many dissects the kernel re-evaluates". So it's roughly correct.
But wait, the cover letter says: "every ~auto_window_packets dissects the worker re-evaluates".
The code checks `if (ddiss < READ_ONCE(fd_auto_window) / 2) return;`.
This means it evaluates AT MOST every `window / 2` packets. So it can evaluate TWICE as often as documented!
If `window` is 1M, it can evaluate every 500k packets.
If the admin wants 1M packets between decisions, they have to set `window` to 2M.
This might be confusing. I should point this out.

Also, the cover letter says: "The per-shape policy is a pure function, unit-tested in the KUnit suite the fast-path series added: dwell requirement, both margin boundaries, dwell reset on a dip, hysteresis deadband, the low-break-even clamp, and dwell saturation (a rate-capped flip stays pending rather than wrapping away)."
But the KUnit test ONLY tests `fd_auto_decide`. It does NOT test the rate-cap logic in the worker! The worker's code for rate cap is:
```c
+		if (flip &&
+		    time_after(jiffies,
+			       fd_auto_last_flip + FD_AUTO_FLIP_MIN_IVAL)) {
+			fd_auto_flip(i, flip > 0);
+			fd_auto_last_flip = jiffies;
+			fd_auto_en_dwell[i] = 0;
+			fd_auto_dis_dwell[i] = 0;
+		}
```
The test claims to cover "dwell saturation (a rate-capped flip stays pending rather than wrapping away)". But the test only calls `fd_auto_decide` 300 times and checks that it returns 1. It does NOT test that the worker does NOT clear the dwell when rate-capped! The worker's behavior of not clearing the dwell is completely untested. This is a coverage gap.

Let's review the vlan/qinq coupling under auto:
```c
+static void fd_auto_flip(enum flow_dissector_shape s, bool on)
+{
+	struct static_key_false *k = fd_auto_key(s);
+
+	if (!k)
+		return;
+	if (on)
+		static_branch_enable(k);
+	else
+		static_branch_disable(k);
+
+	/* Respect the vlan/qinq coupling (mirrors proc_set_vlan/qinq_key):
+	 * qinq requires vlan; turning vlan off drops qinq.
+	 */
+	if (s == FLOW_DISSECTOR_SHAPE_QINQ && on)
+		static_branch_enable(&flow_dissector_vlan_key);
+	if (s == FLOW_DISSECTOR_SHAPE_VLAN && !on)
+		static_branch_disable(&flow_dissector_qinq_key);
+}
```
Wait. If the worker decides to enable `QINQ`, it enables `VLAN` as well. This is correct.
But what if the worker decides to disable `VLAN`? It disables `QINQ`. This is correct.
BUT, what if the worker decides to disable `QINQ`? It disables `QINQ`. It does NOT touch `VLAN`. This is correct.
What if the worker decides to enable `VLAN`? It enables `VLAN`. It does NOT touch `QINQ`. This is correct.
Wait, what if `QINQ` is enabled, and then `VLAN` is disabled by the worker?
The worker calls `fd_auto_flip(VLAN, false)`. It disables `VLAN` and `QINQ`.
Then, on the next window, the worker evaluates `QINQ`. `fd_auto_decide` is called with `on = false` (because `QINQ` is now disabled).
If `frac` for `QINQ` is high, it will start incrementing `en_dwell` for `QINQ`. After 3 windows, it will call `fd_auto_flip(QINQ, true)`.
`fd_auto_flip(QINQ, true)` enables `QINQ` AND `VLAN`.
But `VLAN` was disabled because its `frac` was low! The worker just forced `VLAN` back on!
This violates the policy! The worker decided `VLAN` should be off, but `QINQ` being on forces `VLAN` on.
Is this a bug?
If `QINQ` traffic is high enough to enable `QINQ`, then `VLAN` traffic is also high (since `QINQ` is a subset of `VLAN`).
Wait, `QINQ` traffic is counted as `QINQ`. Is it also counted as `VLAN`?
In the fast path:
```c
+	/* Count only on full success -- a miss defers and the slow path
+	 * counts the occurrence. Depth 0 counts vlan, depth >= 1 qinq; a
+	 * double-tagged hit counts both, as the slow path does.
+	 */
+	if (ok)
+		flow_dissector_count_fast(vlan_depth == 0 ?
+					  FLOW_DISSECTOR_SHAPE_VLAN :
+					  FLOW_DISSECTOR_SHAPE_QINQ);
```
Wait! "a double-tagged hit counts both, as the slow path does."
Let's check the slow path:
```c
+		if (dissector_vlan == FLOW_DISSECTOR_KEY_MAX) {
+			dissector_vlan = FLOW_DISSECTOR_KEY_VLAN;
+			/* First (outer) tag: the vlan fast-path shape. */
+			flow_dissector_count_slow(FLOW_DISSECTOR_SHAPE_VLAN);
+		} else if (dissector_vlan == FLOW_DISSECTOR_KEY_VLAN) {
+			dissector_vlan = FLOW_DISSECTOR_KEY_CVLAN;
+			/* Second tag: the qinq (double-tag) fast-path shape. */
+			flow_dissector_count_slow(FLOW_DISSECTOR_SHAPE_QINQ);
+		}
```
Yes! A QinQ packet increments BOTH `VLAN` and `QINQ` counters!
So if there is QinQ traffic, `VLAN` counter is also incremented.
Therefore, if `QINQ` `frac` is high, `VLAN` `frac` is ALSO high!
So the worker would NOT have disabled `VLAN` in the first place!
So this scenario cannot happen. If `QINQ` is high enough to be enabled, `VLAN` is already high enough to be enabled.
But what if `VLAN` was manually disabled by the admin, and then `auto` is turned on?
The worker evaluates `VLAN`. `frac` is high. It enables `VLAN`.
This is fine.
What if `VLAN` `frac` drops, but `QINQ` `frac` stays high?
If `QINQ` `frac` stays high, `VLAN` `frac` MUST stay high (because `QINQ` contributes to `VLAN`).
So `VLAN` will not be disabled.
So the coupling is actually safe because of the counter design!
This is beautiful. But I should mention it to show I understood it.

Wait, the RFC says: "The vlan/qinq coupling is respected."
Code does:
```c
+	if (s == FLOW_DISSECTOR_SHAPE_QINQ && on)
+		static_branch_enable(&flow_dissector_vlan_key);
```
Wait, `static_branch_enable` and `static_branch_disable` use atomic operations or locks? `static_branch_enable` uses `cpus_read_lock()` internally!
Let's check `static_branch_enable` in Linux:
```c
void static_key_enable(struct static_key *key)
{
	STATIC_KEY_CHECK_USE(key);
	lockdep_assert_irqs_enabled();
	cpus_read_lock();
	...
}
```
Wait! `static_branch_enable` calls `cpus_read_lock()`.
`cpus_read_lock()` can sleep!
But `fd_auto_flip` is called from `flow_dissector_auto_worker`, which runs in a workqueue. Workqueues run in process context, so sleeping is allowed!
This is correct. The cover letter says: "the static_branch flips (text_poke, which can sleep) run in the worker."
This is perfect.

Wait, what about `proc_set_auto`?
```c
+static int proc_set_auto(const struct ctl_table *table, int write,
+			 void *buffer, size_t *lenp, loff_t *ppos)
+{
+	bool was_on = static_key_enabled(&fd_auto_on_key);
+	int ret = proc_do_static_key(table, write, buffer, lenp, ppos);
+	...
```
`proc_do_static_key` calls `static_key_enable` or `static_key_disable`.
This is called from the sysctl write path, which runs in process context. So sleeping is allowed.
This is correct.

Wait, what about the worker reading `fd_auto_snap_total`?
```c
+static u64 fd_auto_snap_total[FLOW_DISSECTOR_SHAPE__MAX];
+static u64 fd_auto_snap_dissects;
```
These are written by the worker and by `flow_dissector_auto_reset` (from `proc_set_auto`).
If `proc_set_auto` and the worker run concurrently, we have a data race.
As discussed earlier, `cancel_work_sync` is needed.

Let's check the `div64_u64` use.
```c
+		u32 frac = ddiss ? (u32)div64_u64(dtot * 10000, ddiss) : 0;
```
`dtot` is `u64`. `ddiss` is `u64`.
`dtot * 10000` can overflow `u64`?
`dtot` is the delta of `occurrences + fast_hits` for one shape.
Max `dtot` is `ddiss`, which is at most `fd_auto_window`.
`fd_auto_window` is `unsigned int`, max 4,294,967,295.
`4,294,967,295 * 10000` = 42,949,672,950,000.
This fits in `u64` (max 1.8e19).
So no overflow!
This is correct.

Wait, what if `fd_auto_window` is changed to be `u64` in the future?
Then `dtot * 10000` could overflow. But right now it's `unsigned int`, so it's safe.

Let's check `this_cpu_inc_return` on `fd_auto_pcpu`.
```c
+	if (this_cpu_inc_return(fd_auto_pcpu) >= max_t(u32, thresh, 1)) {
```
Wait, `this_cpu_inc_return` returns the NEW value.
If `thresh` is 7812.
1st packet: returns 1.
7812th packet: returns 7812. `7812 >= 7812` is true. Resets to 0.
This means it triggers EXACTLY at `thresh` packets.
But wait! `thresh = fd_auto_window / num_online_cpus()`.
If `fd_auto_window` is 1,000,000 and `num_online_cpus()` is 128.
`thresh` is 7812.
Total packets to trigger: 128 * 7812 = 999,936.
This is slightly less than 1,000,000. This is fine.

Wait, the `max_t(u32, thresh, 1)` is used.
If `thresh` is 0 (e.g. `fd_auto_window` is 500, `num_online_cpus()` is 128, `thresh` is 3. Wait, 500/128 = 3. Not 0).
If `fd_auto_window` is 10, `thresh` is 0. Then `max_t(u32, 0, 1)` is 1.
So every packet triggers the worker! `this_cpu_inc_return` returns 1. `1 >= 1` is true.
The worker checks `if (ddiss < READ_ONCE(fd_auto_window) / 2) return;`.
`fd_auto_window` is 10. `10 / 2 = 5`.
So if `ddiss < 5`, it returns.
This means it will trigger the worker every packet, but the worker will return until 5 packets arrive.
This is a lot of overhead! `schedule_work` is called every packet.
But `fd_auto_window_min` is 1000. So `fd_auto_window` can't be 10. It's at least 1000.
So `thresh` is at least `1000 / 128 = 7`. So it's not that bad.
But still, a sysctl min of 1000 might be too low for a 128-core machine.

Let's check the memory ordering of `fd_auto_pcpu` vs `flow_dissector_pcpu_stats`.
`this_cpu_inc_return(fd_auto_pcpu)` is a RMW operation. It acts as a full memory barrier on the local CPU? No, `this_cpu_add_return` does NOT imply a memory barrier on all architectures. But it does on x86 (because it's `lock xadd`).
On ARM, `this_cpu_add_return` uses `ldaxr`/`stlxr`, which has release semantics, so it orders prior memory operations before the RMW.
Wait, the worker reads `flow_dissector_pcpu_stats` using `READ_ONCE`? No, it just reads `s->occurrences[i]` directly!
```c
+		for (i = 0; i < FLOW_DISSECTOR_SHAPE__MAX; i++)
+			total[i] += s->occurrences[i] + s->fast_hits[i];
+		*dissects += s->dissects;
```
There is no `READ_ONCE`! The compiler might read it multiple times or optimize it.
More importantly, the worker should use `READ_ONCE` for per-cpu counters that are updated concurrently.
```c
+		for (i = 0; i < FLOW_DISSECTOR_SHAPE__MAX; i++)
+			total[i] += READ_ONCE(s->occurrences[i]) + READ_ONCE(s->fast_hits[i]);
+		*dissects += READ_ONCE(s->dissects);
```
This is a bug! The compiler could read `s->occurrences[i]`, then read it again, and get different values, leading to incorrect sum. It must be `READ_ONCE`.

Also, the fast-path patch uses `this_cpu_inc` for `u64` on 32-bit.
```c
+struct flow_dissector_stats {
+	u64 occurrences[FLOW_DISSECTOR_SHAPE__MAX];
+	u64 fast_hits[FLOW_DISSECTOR_SHAPE__MAX];
+	u64 dissects;
+};
```
On 32-bit, `this_cpu_inc` on a `u64` is TWO 32-bit writes. It's NOT atomic.
The worker reads them. This is a torn read.
To fix this, the fast-path patch should use `local64_t` or `u64_stats_sync`.
But I am reviewing the RFC. The RFC says: "Scrutinize: the per-cpu window accounting... worker's snapshot/delta math (div64 use, races with counter increments and with concurrent sysctl writes)".
So I must point out:
1. `this_cpu_inc` on `u64` is not atomic on 32-bit, leading to torn reads in the worker.
2. The worker reads `s->occurrences[i]` without `READ_ONCE`, leading to compiler races.
3. `this_cpu_inc_return` on `fd_auto_pcpu` in process context is preemption-unsafe if preemption is enabled. It should use `get_cpu_ptr()`.

Let's check the `fd_auto_pcpu` reset.
```c
+	if (this_cpu_inc_return(fd_auto_pcpu) >= max_t(u32, thresh, 1)) {
+		this_cpu_write(fd_auto_pcpu, 0);
+		schedule_work(&fd_auto_work);	/* coalesces if already pending */
+	}
```
Wait, `this_cpu_write(fd_auto_pcpu, 0)` resets the counter.
But what if another packet arrives on the SAME CPU between `this_cpu_inc_return` and `this_cpu_write`?
Wait, `this_cpu_inc_return` and `this_cpu_write` are NOT atomic together!
If preempted, or if an interrupt occurs:
1. CPU A: `this_cpu_inc_return` returns `thresh`. (e.g., 7812)
2. Interrupt occurs, another packet is dissected.
3. CPU A: `this_cpu_inc_return` returns `7813`.
4. Interrupt returns.
5. CPU A: `this_cpu_write(fd_auto_pcpu, 0)`. The counter is now 0. The `7813` is lost!
Wait, `this_cpu_inc_return` is preemption-safe? No, we established it's not.
But even if preemption is disabled, what about interrupts?
`__skb_flow_dissect` can be called from interrupt context (e.g., NAPI).
If `this_cpu_inc_return` returns `thresh`, an interrupt can occur, call `__skb_flow_dissect`, and call `this_cpu_inc_return` which returns `thresh + 1`. Then it resets to 0?
No, if it returns `thresh + 1`, the condition `>= thresh` is true, so it ALSO resets to 0 and calls `schedule_work`.
But the first call (which was interrupted) will then resume and call `this_cpu_write(fd_auto_pcpu, 0)`, which is fine because the counter is already 0.
Wait, if the interrupt happens AFTER `this_cpu_inc_return` but BEFORE `this_cpu_write`:
1. Main context: `inc_return` -> 7812. (>= thresh). Preempted/Interrupted.
2. Interrupt: `inc_return` -> 7813. (>= thresh). `this_cpu_write(0)`. `schedule_work`. Returns.
3. Main context resumes: `this_cpu_write(0)`.
This is fine! The counter is 0.
But what if the interrupt happens, increments to 7813, and then ANOTHER interrupt happens, increments to 7814, resets to 0, returns. Then main context resumes and resets to 0. It's still fine.
BUT what if the interrupt happens, increments to 7813, does NOT reset (because thresh is 10000, and 7813 < 10000). Returns.
Then main context resumes. It has `7812` from its `inc_return`. It calls `this_cpu_write(0)`. The counter is now 0! The `7813` is lost!
This is a bug!
The `inc_return` and `write(0)` are NOT atomic.
To fix this, use `this_cpu_cmpxchg`:
```c
	u32 *cnt = this_cpu_ptr(&fd_auto_pcpu);
	u32 old;
	do {
		old = *cnt;
		if (old >= thresh) {
			if (this_cpu_cmpxchg(fd_auto_pcpu, old, 0) == old) {
				schedule_work(&fd_auto_work);
				break;
			}
		} else {
			if (this_cpu_cmpxchg(fd_auto_pcpu, old, old + 1) == old)
				break;
		}
	} while (1);
```
Or simpler:
```c
	u32 *cnt = this_cpu_ptr(&fd_auto_pcpu);
	if (*cnt >= thresh) {
		*cnt = 0;
		schedule_work(&fd_auto_work);
	} else {
		(*cnt)++;
	}
```
Wait, this is still not atomic if interrupts can happen.
Actually, the standard way to do this in Linux is:
```c
	u32 *cnt = this_cpu_ptr(&fd_auto_pcpu);
	(*cnt)++;
	if (*cnt >= thresh) {
		*cnt = 0;
		schedule_work(&fd_auto_work);
	}
```
If an interrupt happens between `(*cnt)++` and `if (*cnt >= thresh)`, the interrupt will increment `*cnt`, check `>= thresh`, and maybe reset it to 0 and schedule work.
When the main context resumes, `*cnt` is 0. It checks `0 >= thresh`, which is false. So it doesn't reset. This is safe!
Wait, the code uses `this_cpu_inc_return(fd_auto_pcpu)`.
```c
	if (this_cpu_inc_return(fd_auto_pcpu) >= max_t(u32, thresh, 1)) {
		this_cpu_write(fd_auto_pcpu, 0);
		schedule_work(&fd_auto_work);
	}
```
If an interrupt happens after `this_cpu_inc_return` returns 7812, but before `this_cpu_write`.
The interrupt increments to 7813. It checks `7813 >= thresh`. If `thresh` is 7812, it's true. It writes 0 and schedules work.
Main context resumes. It writes 0. This is safe.
If `thresh` is 10000. Interrupt increments to 7813. `7813 >= 10000` is false. It does nothing.
Main context resumes. It has `7812` in a register! It checks `7812 >= 10000`, false. It does nothing.
Wait! The main context DOES NOT write 0 because the condition was false!
Ah! If the condition is false, `this_cpu_write` is NOT called!
So the counter is now 7813. The main context did not lose anything!
What if the condition is true? `this_cpu_inc_return` returns `thresh`. Condition is true.
Interrupt happens. Increments to `thresh + 1`. Condition is true! Writes 0. Schedules work.
Main context resumes. Condition was true. Writes 0. Schedules work (coalesced).
This is SAFE!
Wait, `this_cpu_inc_return` is atomic w.r.t interrupts ON THE SAME CPU? No, `this_cpu_inc_return` is a single instruction on x86 (`lock xadd`), so it's atomic w.r.t interrupts. But on ARM, it's a loop with `ldaxr`/`stlxr`. It is also atomic w.r.t interrupts.
So `this_cpu_inc_return` is atomic.
The problem is ONLY the window between `inc_return` and `write`.
If `inc_return` returns `thresh`, the condition is true.
If an interrupt happens, it increments to `thresh + 1`. Condition is true. It writes 0.
Main context resumes. It writes 0.
So it's safe!
Wait, what if `inc_return` returns `thresh - 1`? Condition is false.
Interrupt happens. Increments to `thresh`. Condition is true. Writes 0.
Main context resumes. Condition was false. Does not write 0.
The counter is 0. Everything is correct!
So `this_cpu_inc_return` followed by `this_cpu_write` is actually safe against interrupts!
BUT it is NOT safe against preemption!
If preempted between `inc_return` and `write`, the CPU changes.
`this_cpu_write(fd_auto_pcpu, 0)` writes to the NEW CPU's `fd_auto_pcpu`!
This zeroes the wrong CPU's counter!
This is a bug. `this_cpu_write` uses the current CPU's offset, but the `inc_return` was on the old CPU.
So it zeroes the wrong CPU's counter.
To fix, disable preemption:
```c
	u32 *cnt = get_cpu_ptr(&fd_auto_pcpu);
	(*cnt)++;
	if (*cnt >= thresh) {
		*cnt = 0;
		put_cpu_ptr(&fd_auto_pcpu);
		schedule_work(&fd_auto_work);
	} else {
		put_cpu_ptr(&fd_auto_pcpu);
	}
```
Or just `this_cpu_inc_return` and `this_cpu_write` inside `get_cpu_var`? No, `this_cpu_*` implies you already have the right CPU. If you use `get_cpu_ptr`, you should use `__this_cpu_*`.

So the bugs are:
1. Preemption race in `flow_dissector_auto_account` (use `get_cpu_ptr` or `local_irq_save`).
2. Torn reads of `u64` per-cpu counters on 32-bit in `flow_dissector_stats_totals`.
3. Missing `READ_ONCE` in `flow_dissector_stats_totals` for concurrent counter reads.
4. Race between `proc_set_auto` and `flow_dissector_auto_worker` (need `cancel_work_sync`).
5. Documentation mismatch: `auto_window_packets` decision interval is effectively `window / 2` to `window`, not `~window`.
6. KUnit test for `fd_auto_decide` does not cover the worker's rate-cap logic (not clearing dwell on rate-cap).

Let's verify the `cancel_work_sync` race.
```c
+static int proc_set_auto(const struct ctl_table *table, int write,
+			 void *buffer, size_t *lenp, loff_t *ppos)
+{
+	bool was_on = static_key_enabled(&fd_auto_on_key);
+	int ret = proc_do_static_key(table, write, buffer, lenp, ppos);
+
+	if (ret == 0 && write && !was_on &&
+	    static_key_enabled(&fd_auto_on_key)) {
+		flow_dissector_auto_reset();
+		schedule_work(&fd_auto_work);
+	}
+	return ret;
+}
```
If admin writes 1 to `auto`, `was_on` is false. `proc_do_static_key` enables the key.
Then it calls `flow_dissector_auto_reset()` and `schedule_work`.
What if a worker was already running from a previous `auto=1` session, and it hasn't finished yet?
It will see `static_key_enabled` is true, and proceed!
It will use the old `fd_auto_snap_total` values, compute a huge delta, flip gates randomly, and then overwrite the baseline.
To fix: `cancel_work_sync(&fd_auto_work)` must be called before `flow_dissector_auto_reset()`.
Actually, it should be called whenever the sysctl is written, to ensure no worker is running.

Let's check `fd_auto_flip` coupling again.
```c
+	if (s == FLOW_DISSECTOR_SHAPE_QINQ && on)
+		static_branch_enable(&flow_dissector_vlan_key);
+	if (s == FLOW_DISSECTOR_SHAPE_VLAN && !on)
+		static_branch_disable(&flow_dissector_qinq_key);
```
If `s == VLAN` and `on` is false, it disables `QINQ`.
But wait! What if `QINQ` was manually enabled by the admin, and `auto` is on?
The worker decides to disable `VLAN`. It disables `VLAN` and `QINQ`.
The next window, the worker evaluates `QINQ`. `QINQ` is off. If `frac` is high, it enables `QINQ` and `VLAN`.
This means the admin's manual setting is overridden. The documentation says: "Manual writes while auto is on may be overridden at the next window (documented)." This is fine.

What about the `fd_auto_decide` function's behavior when `pbe` is very small?
```c
+	lo = pbe > FD_AUTO_MARGIN_LO ? pbe - FD_AUTO_MARGIN_LO : 0;
+	*dis_dwell = frac < lo ?
+		     min_t(u8, *dis_dwell + 1, FD_AUTO_DWELL) : 0;
```
If `pbe` is 400, `lo` is 0. `frac < 0` is false (since `frac` is `u32`). So `*dis_dwell = 0`.
This means it can NEVER disable!
The test covers this.
But wait! What if `frac` is 0? `0 < 0` is false. `*dis_dwell = 0`.
So a gate with `pbe = 400` can NEVER be disabled, even if `frac` is 0!
Is this intended?
The comment says: "A break-even below the 5pp disable margin clamps lo to 0: the gate can then never auto-disable (frac cannot go below 0)."
Yes, it's intended. If the break-even is 4%, the disable margin is -1%. So you need a negative fraction to disable it. That's impossible. So it never disables. This is a feature, not a bug. But it's worth noting.

Wait, `frac` is `u32`. `frac < lo` where `lo` is 0. `frac < 0` is always false. So it works.

Let's review the cover letter's claim:
"The hot path pays one not-taken static branch with auto off -- the same discipline as the gates themselves -- and one per-cpu increment with it on; the counter summation and the static_branch flips (text_poke, which can sleep) run in the worker."
Code:
```c
+	if (static_branch_unlikely(&fd_auto_on_key))
+		flow_dissector_auto_account();
```
Yes, one not-taken static branch.
With it on:
```c
+	u32 thresh = READ_ONCE(fd_auto_window) / num_online_cpus();
+	if (this_cpu_inc_return(fd_auto_pcpu) >= max_t(u32, thresh, 1)) {
+		this_cpu_write(fd_auto_pcpu, 0);
+		schedule_work(&fd_auto_work);
+	}
```
Yes, one per-cpu increment.
Wait, `READ_ONCE(fd_auto_window) / num_online_cpus()` is a division!
Division is expensive! On the hot path!
`num_online_cpus()` is not a constant. `READ_ONCE(fd_auto_window)` is not a constant.
So every packet with `auto` on does a division!
This is a performance bug!
You should precompute the threshold whenever `fd_auto_window` or `num_online_cpus()` changes.
Or, since `fd_auto_window` is usually 1,000,000, you can just use `fd_auto_window` as the global threshold, and use an atomic counter!
But the code uses per-cpu counters to avoid cache line bouncing.
To avoid division on the hot path, you can store `fd_auto_thresh` as a variable, updated by sysctl and cpu hotplug.
Or, simpler: just increment the per-cpu counter, and use a bitmask or something? No.
You can do:
```c
+	u32 thresh = READ_ONCE(fd_auto_pcpu_thresh);
```
And update `fd_auto_pcpu_thresh` in `proc_set_auto` and on CPU hotplug.
But handling CPU hotplug is complex.
Wait, `num_online_cpus()` is just a read of a per-cpu variable or a global variable. It's fast.
But the division `fd_auto_window / num_online_cpus()` is a `div` instruction, which takes ~20-40 cycles on x86, more on ARM. On the hot path, this is bad.
Also `max_t(u32, thresh, 1)` is a branch.
Is there a way to avoid it?
If `fd_auto_window` is a multiple of `num_online_cpus()`, we can use bit shifts? No.
What if we just use a global atomic counter for the window?
No, the whole point of per-cpu is to avoid cache line bouncing.
What if we use `fd_auto_window` as the per-cpu threshold? Then the global window would be `fd_auto_window * num_online_cpus()`. That changes the semantics.
Better: precompute `fd_auto_thresh` when `fd_auto_window` is written.
```c
+static u32 fd_auto_thresh;
```
In `proc_set_auto` (or a custom handler for `auto_window_packets`):
`fd_auto_thresh = max_t(u32, fd_auto_window / num_online_cpus(), 1);`
But what if CPUs come online/offline? The threshold becomes stale.
Is a stale threshold a problem? If `num_online_cpus()` doubles, the threshold is twice as large as it should be. The window takes twice as long. Not a huge deal.
If `num_online_cpus()` halves, the threshold is half as large. The worker triggers twice as often.
To be perfectly correct, you need a CPU hotplug notifier.
But even without it, computing it on the hot path is bad.
Wait, `__skb_flow_dissect` is extremely hot. Adding a division to it is a non-starter for netdev.
The fast-path series explicitly avoids divisions on the hot path.
I must flag this: "Division on the hot path (`READ_ONCE(fd_auto_window) / num_online_cpus()`) is too expensive. Precompute the threshold."

Wait, `this_cpu_inc_return` is also not free. But it's necessary.
Can we do `this_cpu_inc_return` without preemption issues?
```c
+	u32 *cnt = get_cpu_ptr(&fd_auto_pcpu);
+	if (++(*cnt) >= READ_ONCE(fd_auto_thresh)) {
+		*cnt = 0;
+		put_cpu_ptr(&fd_auto_pcpu);
+		schedule_work(&fd_auto_work);
+	} else {
+		put_cpu_ptr(&fd_auto_pcpu);
+	}
```
Wait, `get_cpu_ptr` disables preemption. `schedule_work` can be called with preemption disabled.
This is much better.

Let's check `fd_auto_managed`:
```c
+static bool fd_auto_managed(enum flow_dissector_shape s)
+{
+	return s != FLOW_DISSECTOR_SHAPE_MPLS;
+}
```
Wait, the cover letter says: "mpls is not auto-managed (its break-even is 60-70%: a net loss unless mpls dominates); the UDP-tunnel descent gates from the companion descent series are never auto-managed, because enabling them changes hashing"
The code excludes `MPLS`. But the UDP-tunnel descent gates are not in `enum flow_dissector_shape` at all, so they are naturally excluded. This is correct.

Let's check `fd_auto_pbe`:
```c
+static const u32 fd_auto_pbe[FLOW_DISSECTOR_SHAPE__MAX] = {
+	[FLOW_DISSECTOR_SHAPE_ETH_IP] = 1920,
+	[FLOW_DISSECTOR_SHAPE_VLAN]   = 1290,
+	[FLOW_DISSECTOR_SHAPE_QINQ]   = 1100,
+	[FLOW_DISSECTOR_SHAPE_PPPOE]  = 1840,
+	[FLOW_DISSECTOR_SHAPE_MPLS]   = 6950,
+	[FLOW_DISSECTOR_SHAPE_IPIP]   = 800,
+	[FLOW_DISSECTOR_SHAPE_GRE]    = 1000,
+};
```
Wait! `IPIP` is 800 (8%). `GRE` is 1000 (10%).
But the cover letter says: "gre's S was not separately microbenched; it is treated as a single descent (~ipip class)."
If `gre` is ~ipip class, why is `ipip` 800 and `gre` 1000? That's a 25% difference!
If they are the same class, they should have the same break-even.
I should point this out. "If gre is treated as ~ipip class, why does fd_auto_pbe[GRE] = 1000 while fd_auto_pbe[IPIP] = 800? They should be the same."

Let's check the KUnit test coverage.
```c
+static void fd_auto_policy_test(struct kunit *test)
+{
+	u32 pbe = 1920;		/* the eth_ip break-even row */
...
```
The test only uses `pbe = 1920`! It does not test other break-evens!
What if `pbe` is 6950 (MPLS)? But MPLS is not auto-managed, so it's fine.
What if `pbe` is 800 (IPIP)?
The logic is generic, so testing one `pbe` is probably enough. But testing a low `pbe` (like 400 in the clamp test) is good.
Wait, the clamp test uses `pbe = 400`. But 400 is not in the table! The lowest in the table is 800.
Still, testing 400 is good for boundary conditions.

What about `fd_auto_decide` return values?
```c
+	return *en_dwell >= FD_AUTO_DWELL ? 1 : 0;
...
+	return *dis_dwell >= FD_AUTO_DWELL ? -1 : 0;
```
The test checks `KUNIT_EXPECT_EQ(test, 1, ...)`. This is fine.

Wait, the worker:
```c
+		flip = fd_auto_decide(frac, fd_auto_pbe[i],
+				      static_key_enabled(fd_auto_key(i)),
+				      &fd_auto_en_dwell[i],
+				      &fd_auto_dis_dwell[i]);
```
`fd_auto_decide` takes `bool on`.
`static_key_enabled(fd_auto_key(i))` returns `true` if the key is enabled.
This is correct.

What if `fd_auto_flip` is called, but the gate is already in the desired state?
`static_branch_enable` on an already-enabled key is a no-op (it checks the refcount).
`static_branch_disable` on an already-disabled key is a no-op.
This is safe.

Let's check the documentation for `auto_window_packets`:
"The decision window for ``auto``, in packets: after roughly this many dissects the kernel re-evaluates and may flip a gate."
But the code says:
```c
+	if (ddiss < READ_ONCE(fd_auto_window) / 2)
+		return;
```
So it evaluates after `window / 2` packets!
This is a documentation bug. It should say "after at least half this many dissects..." or the code should check `ddiss < READ_ONCE(fd_auto_window)`.
Wait, if the code checks `ddiss < fd_auto_window`, then it evaluates every `fd_auto_window` packets.
Why did the author use `/ 2`?
Because the hot path triggers the worker every `window / ncpus` packets per CPU.
If the traffic is bursty, one CPU might hit its threshold early, and `ddiss` might be slightly less than `window`. The worker would return. Then NO CPU would trigger the worker until another `window / ncpus` packets arrive on that CPU.
But `ddiss` would then be `window + something`.
Wait, if `ddiss < window`, the worker returns. The next trigger will be at `window + 7812`. `ddiss` will be `7812 + previous_ddiss`? No, `ddiss` is the delta from the LAST snapshot.
If the worker returns, it does NOT update the snapshot!
So the next time the worker runs, `ddiss` will be even larger!
Eventually, `ddiss` will be `>= window`, and it will run.
So using `window / 2` just makes it run earlier. It doesn't change the fact that the snapshot is updated only when it runs.
If it uses `window / 2`, it will run when `ddiss` reaches `window / 2`. Then it updates the snapshot. The next run will be after another `window / 2`.
So the effective window is `window / 2`!
If the author wanted the window to be `window`, they should check `ddiss < fd_auto_window`.
Why did they use `/ 2`? Maybe to ensure it doesn't wait too long if a CPU triggers early?
But if a CPU triggers early, `ddiss` is small, it returns. The next CPU triggers, `ddiss` is larger. It returns. Eventually `ddiss >= window`, it runs.
So it WILL run every `window` packets. It just might check a few times and return.
Using `window / 2` makes it run every `window / 2` packets. This is a semantic difference.
I will point out: "The worker checks `ddiss < fd_auto_window / 2`, which means the effective decision window is half of `auto_window_packets`. The documentation says 'after roughly this many dissects'. Either the code should check `ddiss < fd_auto_window` or the documentation should clarify."

Let's review the `div64_u64` use again.
```c
+		u32 frac = ddiss ? (u32)div64_u64(dtot * 10000, ddiss) : 0;
```
Wait, `dtot * 10000` can be computed as `u64`.
`dtot` is `u64`. `10000` is `int`. `dtot * 10000` is `u64`.
`div64_u64` takes `u64, u64`.
This is correct.

What about `total[i] += s->occurrences[i] + s->fast_hits[i]`?
`total` is `u64[]`. `s->occurrences[i]` is `u64`.
This is fine.

Let's check the static-key discipline.
`fd_auto_on_key` is enabled/disabled by `proc_do_static_key`.
`fd_auto_flip` enables/disables the shape keys.
All of these use `static_branch_enable`/`disable`, which are safe in process context.
The hot path uses `static_branch_unlikely(&fd_auto_on_key)`.
This is correct.

What about memory ordering of `fd_auto_last_flip`?
```c
+		if (flip &&
+		    time_after(jiffies,
+			       fd_auto_last_flip + FD_AUTO_FLIP_MIN_IVAL)) {
```
`fd_auto_last_flip` is `unsigned long`.
It's written by the worker. Read by the worker.
Since the worker is single-threaded (system workqueue is not strictly single-threaded, but `schedule_work` coalesces, so only one instance runs at a time), there is no race.
But wait! `schedule_work` coalesces. So only one worker runs at a time.
So `fd_auto_last_flip` is only accessed by one thread. No memory ordering issues.

What about `fd_auto_snap_total`?
It's written by the worker and `flow_dissector_auto_reset`.
As discussed, `cancel_work_sync` is needed.

What about `fd_auto_en_dwell` and `fd_auto_dis_dwell`?
Same.

Is there any issue with `jiffies`?
`time_after(jiffies, fd_auto_last_flip + FD_AUTO_FLIP_MIN_IVAL)`
`fd_auto_last_flip` is 0 initially. `jiffies` starts at `INITIAL_JIFFIES`.
If `INITIAL_JIFFIES` is large, `time_after` might be false initially.
But `INITIAL_JIFFIES` is usually negative (or wraps). It's fine.

Let's check the `fd_auto_window` sysctl handler.
```c
+		.procname	= "auto_window_packets",
+		.data		= &fd_auto_window,
+		.maxlen		= sizeof(fd_auto_window),
+		.mode		= 0644,
+		.proc_handler	= proc_douintvec_minmax,
+		.extra1		= &fd_auto_window_min,
+	},
```
This is standard.

What about `fd_auto_pcpu` initialization?
It's `static DEFINE_PER_CPU(u32, fd_auto_pcpu);`. Initialized to 0.
This is fine.

What about the `fd_auto_managed` function?
```c
+static bool fd_auto_managed(enum flow_dissector_shape s)
+{
+	return s != FLOW_DISSECTOR_SHAPE_MPLS;
+}
```
If new shapes are added to `enum flow_dissector_shape`, they will be auto-managed by default!
This is a maintenance hazard. If a new shape is added, it might be a hashing-changing descent, which should NOT be auto-managed.
The comment says: "the UDP-tunnel descent gates from the companion descent series are never auto-managed, because enabling them changes hashing"
But if they are added to `enum flow_dissector_shape`, `fd_auto_managed` will return true!
To fix, `fd_auto_managed` should have a whitelist:
```c
switch (s) {
case FLOW_DISSECTOR_SHAPE_ETH_IP:
case FLOW_DISSECTOR_SHAPE_VLAN:
...
case FLOW_DISSECTOR_SHAPE_GRE:
    return true;
default:
    return false;
}
```
This is much safer. I will point this out.

Let's check the `fd_auto_key` function.
```c
+static struct static_key_false *fd_auto_key(enum flow_dissector_shape s)
+{
+	switch (s) {
+	case FLOW_DISSECTOR_SHAPE_ETH_IP: return &flow_dissector_eth_ip_key;
...
+	default: return NULL;
+	}
+}
```
This is a whitelist. It returns NULL for unknown shapes.
So `fd_auto_flip` will do nothing for unknown shapes.
But `fd_auto_decide` will still be called for unknown shapes if `fd_auto_managed` returns true!
So the dwell counters will be updated, but no flip will happen. This is a waste, but not a bug.
Still, `fd_auto_managed` should be a whitelist.

Let's check the `fd_auto_pbe` array.
```c
+static const u32 fd_auto_pbe[FLOW_DISSECTOR_SHAPE__MAX] = {
+	[FLOW_DISSECTOR_SHAPE_ETH_IP] = 1920,
...
+	[FLOW_DISSECTOR_SHAPE_GRE]    = 1000,
+};
```
If a new shape is added, `fd_auto_pbe[new_shape]` will be 0!
Then `fd_auto_decide` will be called with `pbe = 0`.
```c
+	if (!on) {
+		*en_dwell = frac > pbe + FD_AUTO_MARGIN_HI ?
```
`pbe + FD_AUTO_MARGIN_HI` = 1000.
So it will enable the gate if `frac > 1000` (10%).
This might be wrong for the new shape.
But since `fd_auto_key` returns NULL, it won't flip.
Still, it's better to be safe.

Let's review the verdict.
The patch has several serious issues:
1. Division on the hot path.
2. Preemption race in `flow_dissector_auto_account`.
3. Torn reads of `u64` per-cpu counters on 32-bit.
4. Missing `READ_ONCE` in worker.
5. Race between sysctl and worker (missing `cancel_work_sync`).
6. `fd_auto_managed` is not a whitelist.
7. Documentation mismatch on window size.

These are mostly fixable. The design is sound. I will give a "not ready to post as RFC" verdict until the hot-path division and preemption race are fixed, as those are netdev blockers.

Let's structure the review.
- **Severity: Blocker / High**
  - Division on hot path.
  - Preemption race in auto_account.
  - Torn reads / missing READ_ONCE.
  - Sysctl vs worker race.
- **Severity: Medium**
  - `fd_auto_managed` whitelist.
  - Documentation window size mismatch.
  - KUnit coverage gap on rate-cap logic.
- **Severity: Low / Nits**
  - `pbe` for GRE vs IPIP.
  - `div64_u64` overflow (not a bug, but good to note it's safe).

Wait, the prompt says: "Ground every finding in the actual text, quote the relevant lines, order by severity, say concretely what to change, and end with a short verdict on whether this is ready to post as an RFC."

Let's draft the response.

**1. Division on the hot path (Blocker)**
Quote:
```c
+static inline void flow_dissector_auto_account(void)
+{
+	u32 thresh = READ_ONCE(fd_auto_window) / num_online_cpus();
```
`__skb_flow_dissect()` is one of the hottest paths in the network stack. Performing a division (`/ num_online_cpus()`) on every packet when `auto` is enabled is unacceptable for performance. Furthermore, `num_online_cpus()` can change at runtime, but the division is done unconditionally.
*Fix:* Precompute the per-CPU threshold into a variable `fd_auto_thresh` when `auto_window_packets` is written, and update it via a CPU hotplug notifier. Then use `READ_ONCE(fd_auto_thresh)` on the hot path.

**2. Preemption race in per-CPU accounting (Blocker)**
Quote:
```c
+	if (this_cpu_inc_return(fd_auto_pcpu) >= max_t(u32, thresh, 1)) {
+		this_cpu_write(fd_auto_pcpu, 0);
+		schedule_work(&fd_auto_work);	/* coalesces if already pending */
+	}
```
`__skb_flow_dissect()` can be called from process context with preemption enabled. The `this_cpu_*` RMW operations are not preemption-safe. If the thread is preempted between `this_cpu_inc_return` and `this_cpu_write`, it may migrate to another CPU, and `this_cpu_write` will zero the wrong CPU's counter.
*Fix:* Use `get_cpu_ptr()` / `put_cpu_ptr()` to disable preemption around the per-CPU RMW, or use an atomic `local_t` if preemption must stay enabled.

**3. Sysctl vs. Worker race (High)**
Quote:
```c
+/* Windowing state — file-scope so the sysctl handler can re-baseline on an
+ * off->on transition. Only ever touched by the single-threaded worker and the
+ * sysctl write path (serialised by the sysctl mutex), so no extra locking.
+ */
```
This comment is incorrect. The sysctl mutex does not protect against the worker. If `auto` is turned off and on quickly, `flow_dissector_auto_reset()` can race with a currently running `flow_dissector_auto_worker()`. The worker could compute deltas using stale baselines, flip gates erroneously, and overwrite the freshly reset baselines.
*Fix:* Call `cancel_work_sync(&fd_auto_work)` inside `proc_set_auto` before modifying the windowing state.

**4. Torn reads and missing READ_ONCE in worker (High)**
Quote:
```c
+		for (i = 0; i < FLOW_DISSECTOR_SHAPE__MAX; i++)
+			total[i] += s->occurrences[i] + s->fast_hits[i];
+		*dissects += s->dissects;
```
The worker sums `u64` per-CPU counters that are concurrently updated by `this_cpu_inc()`. On 32-bit architectures, `this_cpu_inc()` on a `u64` is two 32-bit writes, so the worker can read a torn value. Furthermore, the worker reads these values without `READ_ONCE()`, allowing the compiler to read multiple times.
*Fix:* Use `READ_ONCE()` for all counter reads in the worker. To fix torn reads on 32-bit, the fast-path series should use `local64_t` or `u64_stats_sync` for these counters.

**5. `fd_auto_managed` is not a whitelist (Medium)**
Quote:
```c
+static bool fd_auto_managed(enum flow_dissector_shape s)
+{
+	return s != FLOW_DISSECTOR_SHAPE_MPLS;
+}
```
The cover letter explicitly states that UDP-tunnel descent gates "are never auto-managed, because enabling them changes hashing". If a future patch adds those descent shapes to `enum flow_dissector_shape`, this blacklist will return `true`, and they will be auto-managed, silently changing hashing behavior.
*Fix:* Change this to a whitelist of explicitly managed shapes, returning `false` for the `default` case.

**6. Effective window size is half of documented (Medium)**
Quote:
```c
+	if (ddiss < READ_ONCE(fd_auto_window) / 2)
+		return;
```
The documentation says "after roughly this many dissects the kernel re-evaluates". However, this check causes the worker to evaluate after `auto_window_packets / 2` dissects. If the admin sets the window to 1M, decisions happen every 500k packets.
*Fix:* Either change the check to `ddiss < READ_ONCE(fd_auto_window)` or update the documentation to say "after at least half this many dissects".

**7. KUnit coverage gap (Medium)**
Quote:
```c
+	/* A rate-capped decision stays pending: the dwell saturates and
+	 * the decision keeps asserting instead of wrapping away.
+	 */
+	r = 0;
+	for (i = 0; i < 300; i++)
+		r = flow_dissector_auto_decide_kunit(pbe + 1001, pbe, false,
+						     &en, &dis);
+	KUNIT_EXPECT_EQ(test, 1, r);
```
The test claims to cover the rate-cap behavior, but it only tests `fd_auto_decide()` in isolation. It does not test the worker's logic of *not* clearing the dwell counters when a flip is rate-capped (`if (flip && time_after(...))`). The worker's interaction with the rate cap is completely untested.
*Fix:* Add a test that mocks or drives the worker to verify that dwell counters are preserved when a flip is rate-capped.

**8. Break-even mismatch for GRE vs IPIP (Low)**
Quote:
```c
+	[FLOW_DISSECTOR_SHAPE_IPIP]   = 800,
+	[FLOW_DISSECTOR_SHAPE_GRE]    = 1000,
```
The comment says "gre's S was not separately microbenched; it is treated as a single descent (~ipip class)." If they are the same class, they should have the same break-even value. `1000` vs `800` is a 25% difference.
*Fix:* Set `GRE` to `800` to match `IPIP`, or explain the discrepancy.

**Verdict:**
Not ready to post as an RFC. The division on the hot path and the preemption race in `flow_dissector_auto_account` are netdev blockers. The sysctl vs. worker race and torn reads are also serious correctness issues. The design is sound, but these mechanical issues must be fixed before the RFC is sent.
