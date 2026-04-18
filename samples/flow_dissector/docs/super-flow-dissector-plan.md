# Super Flow Dissector — porting xdp2-rs techniques to kernel C, eBPF, and AF_XDP

> **Status:** planning document. No code changes in this round.
> **Companion docs:** [`xdp2-rs/docs/cpp-backport-plan.md`](../../../xdp2-rs/docs/cpp-backport-plan.md) (C++ port), [`kernel-patches.md`](kernel-patches.md) (existing 5 small BPF selftest patches), [`comprehensive-enhancement-plan.md`](comprehensive-enhancement-plan.md) (existing protocol-parity enhancement plan).

## Abstract

We have an advanced Rust flow parser in [`xdp2-rs/`](../../../xdp2-rs/) whose design docs describe performance techniques that reach line-rate on commodity hardware (2 ns/pkt in template mode, 36 ns/pkt compiled, 150 ns/pkt graph). This document defines a bridge: how to take those techniques into (a) the in-kernel C flow dissector, (b) the upstream BPF flow dissector, (c) a **new production-quality eBPF dissector** packaged for Kubernetes/Cilium-style distribution, and (d) a **new production-quality AF_XDP userspace dissector** packaged as a Rust crate plus standalone binary.

Four parallel upstream/distribution tracks, one shared comparison harness (`samples/flow_dissector/`), one novel optimization (dynamic fast-path tuning from listening-socket state).

---

## 1. Motivation & measured headroom

Current head-to-head numbers from [`benchmarks.md:31–35, 70–82, 95–111`](benchmarks.md):

| Impl | ns/pkt | Mpps | Source |
|---|---|---|---|
| Kernel flow dissector (userspace port) | 137 | 7 | flowdis optimized |
| Upstream BPF flow dissector (selftest) | 213 | 4 | kern_bpf/bpf_flow.c |
| xdp2 parser optimized (`-O`) | 150 | 6 | xdp2-compiler |
| xdp2 parse-only (memset isolated) | **135** | 7 | xdp2-compiler |
| xdp2-rs template (Rust, fixed-offset) | **2** | 364 | [`hardware-classified-extraction.md`](../../../xdp2-rs/docs/hardware-classified-extraction.md) |
| xdp2-rs SIMD batch (Rust, AVX2) | 44 | — | [`performance-optimization.md:59`](../../../xdp2-rs/docs/performance-optimization.md), [`fast-path-dispatch.md:84–86`](../../../xdp2-rs/docs/fast-path-dispatch.md) |

Three claims this document will back up:

1. **Kernel C flow_dissector has ~10 ns/pkt recoverable** via metadata cleanup and template fast-paths ([`benchmarks.md:75–82`](benchmarks.md) — most of the xdp2-vs-flowdis delta is a 200-byte memset, not parsing).
2. **Upstream BPF flow dissector has ~80 ns/pkt recoverable** (213 → ~130) via unified port loads, tail-call fast path, and fixed-offset templates.
3. **A new standalone eBPF dissector built from scratch can target ≤50 ns/pkt** on fast-path hits by fully committing to fixed-offset templates + tail-called long-tail handler, while the slow-path fallback preserves full protocol coverage.

The traffic justification is in [`fast-path-dispatch.md:108–156, 190–200, 236–247`](../../../xdp2-rs/docs/fast-path-dispatch.md): top-10 chains cover 99.5% of packets on mixed real traffic; workload profiles (https-web, nfs-server, k8s) all collapse to ≤6 chains with top-5 covering ≥97.8%.

---

## 2. Technique inventory: portability matrix

Five techniques. SIMD is the sharpest portability divide — primary win for AF_XDP userspace, contentious in kernel C (FPU context rules), flatly impossible in eBPF.

| Technique | Rust source | Kernel C | eBPF | AF_XDP userspace |
|---|---|---|---|---|
| **Template extraction** | [`hardware-classified-extraction.md:1–82`](../../../xdp2-rs/docs/hardware-classified-extraction.md), `xdp2-bench/src/template.rs` | Yes — `static const` offset tables + `__always_inline` per-chain | **Excellent** — zero branches, verifier-trivial | Best case — combine with SIMD |
| **Fast-path top-N dispatch** | [`fast-path-dispatch.md:108–156`](../../../xdp2-rs/docs/fast-path-dispatch.md) | Yes — `switch` / jump table on chain id | **Excellent** — BPF `tail_call` array | Yes — with SIMD prefilter |
| **Unified port / header loads** | [`kernel-patches.md:9–58`](kernel-patches.md) (BPF selftest form); kernel's own `skb_flow_get_ports()` already uses this | Generalize to SCTP/DCCP, L4 len, IPv6 next-hdr — single 32/64-bit aligned loads | Major win — cuts verifier-visible load count | Yes — pair with prefetch |
| **Prefetch + ILP tuning** | [`performance-next-steps.md:106–116`](../../../xdp2-rs/docs/performance-next-steps.md) | Yes — `prefetch()` from `<linux/prefetch.h>`; hoist independent loads | **No** — BPF has no prefetch; verifier forbids speculative memory access | Yes — `_mm_prefetch` |
| **SIMD (parsing + batching)** | [`fast-path-dispatch.md:84–86`](../../../xdp2-rs/docs/fast-path-dispatch.md), [`performance-optimization.md:59`](../../../xdp2-rs/docs/performance-optimization.md), `xdp2-bench/src/simd_batch.rs` — 44 ns/pkt AVX2 batch | **Constrained** — hot path must avoid `kernel_fpu_begin/end` (heavy save/restore, ~100 ns); acceptable only with GRO/NAPI batching ≥ 8 skbs | **No** — BPF has no SIMD ISA; kernel softirq can't use FPU without `kernel_fpu_begin()` | **Primary win** — AVX2/AVX-512 gather on UMEM-contiguous frames ([`af-xdp-integration-plan.md:203–239`](../../../xdp2-rs/docs/af-xdp-integration-plan.md)); 4–8 packets per vector |

Techniques **not portable to kernel or eBPF** (kept for reference, not ported):
- **LTO + monomorphization** — [`performance-optimization.md:26–53, 327–348`](../../../xdp2-rs/docs/performance-optimization.md). Requires whole-program optimization; kernel doesn't build that way, eBPF programs are tiny TUs.
- **PGO** — [`performance-optimization.md:232–323`](../../../xdp2-rs/docs/performance-optimization.md). Kernel has its own PGO story (`CONFIG_FG_KASLR`, etc.); not a flow-dissector-specific lever.

### SIMD — the non-obvious portability story

In AF_XDP userspace, SIMD is the single biggest remaining win: `simd_batch.rs` achieves 44 ns/pkt by classifying 4–8 packets against signature templates in one `vpshufb`/`vpcmpeqd` pass, reading directly from UMEM at predictable 4096-byte strides. In eBPF there is no path — the BPF ISA has no vector register class and the verifier rejects inline assembly. In kernel C it is a judgment call: `kernel_fpu_begin()`/`kernel_fpu_end()` work (NET_RX already uses them for crypto and checksum), but the save/restore cost (~100 ns on x86_64) only pays off if we amortize over ≥8 packets per call. That implies batching at GRO/NAPI granularity, not per-skb. See Implementation 1 patch 7 below.

---

## 3. Implementation 1 — Kernel C `flow_dissector.c` patch series

**Target:** upstream `net/core/flow_dissector.c` (not vendored here; [`src/lib/flowdis/flow_dissector.c`](../../../src/lib/flowdis/flow_dissector.c) is a direct userspace port we use for comparison).
**Mailing list:** `netdev@vger.kernel.org`, CC maintainers per `scripts/get_maintainer.pl`.

### Patch order (each self-contained and benchable)

1. **Preparatory — `flow_keys_basic_lite`.** Export a lightweight struct for callers that only need the 4-tuple, reducing the 88-byte `flow_keys` memset cost. Motivation: [`benchmarks.md:75–82`](benchmarks.md) shows metadata size is the dominant remaining overhead.
2. **Unified L4 port load.** Consolidate the per-protocol `__skb_flow_get_ports` variants into a single 32-bit aligned load covering TCP/UDP/SCTP/DCCP. Mirrors the pattern already proposed for BPF selftest in [`kernel-patches.md:9–58`](kernel-patches.md). Uncontroversial — lead with this.
3. **Fast-path top-N chains.** Add `static __always_inline` functions for the top-5 chains (ETH/IPv4/TCP, ETH/IPv4/UDP, ETH/IPv6/TCP, ETH/VLAN/IPv4/TCP, ETH/IPv4/TCP+TS-opt) gated at entry by a 16-byte signature match (`ethertype | ihl | protocol | frag_off` loaded as a `u64`). On miss, fall through to the existing general path. Evidence for utility: [`fast-path-dispatch.md:190–200, 236–247`](../../../xdp2-rs/docs/fast-path-dispatch.md).
4. **Template extraction macro.** Introduce `DEFINE_FLOW_TEMPLATE(name, offsets…)` that emits a per-chain inlined extractor. Apply to each of the top-5 chains from patch 3. Offset tables come from [`hardware-classified-extraction.md:98–150`](../../../xdp2-rs/docs/hardware-classified-extraction.md).
5. **Prefetch loop friendliness.** At `__skb_flow_dissect` entry, `prefetch(skb->data + 64)` so IPv4/TCP headers are warm by the time control reaches them. Use existing [`<linux/prefetch.h>`](https://elixir.bootlin.com/linux/latest/source/include/linux/prefetch.h).
6. **(Optional) Metadata memset elision.** Selectively zero only fields callers read, using `FLOW_DISSECTOR_KEY_*` bit tests.
7. **(Speculative, contentious) GRO-batched SIMD classify.** Optional `CONFIG_FLOW_DISSECTOR_SIMD` path: at NAPI poll time with a batch of ≥8 skbs, enter `kernel_fpu_begin()`, run one `vpshufb`/`vpcmpeqd` over the batch's L2/L3 headers to compute chain IDs, exit `kernel_fpu_end()`, dispatch each skb to its per-chain template. Amortizes ~100 ns FPU save/restore over 8 packets (~12 ns/pkt overhead) while winning ~30 ns/pkt on classification. Rust precedent: `xdp2-bench/src/simd_batch.rs`. **Lands last or as an out-of-tree demo** — NAPI avoiding FPU is long-standing netdev policy; we need concrete numbers before a real argument.

### Risks and anticipated pushback

- Per-chain inline templates grow `.text`. Mitigation: gate under `CONFIG_FLOW_DISSECTOR_FAST_PATH`, default-n on embedded, default-y on x86_64/arm64 server defconfigs.
- Maintainers will want real-traffic evidence. PR body cites this doc and [`benchmarks.md`](benchmarks.md) and reproduces with `nix build .#tests.flow-dissector-benchmark`.
- The SIMD patch (7) will attract the most scrutiny. Ship the first six first; treat (7) as an RFC.

---

## 4. Implementation 2 — BPF selftest `bpf_flow.c` extensions

**Target:** [`tools/testing/selftests/bpf/progs/bpf_flow.c`](https://elixir.bootlin.com/linux/latest/source/tools/testing/selftests/bpf/progs/bpf_flow.c). Vendored here at [`samples/flow_dissector/kern_bpf/bpf_flow.c`](../kern_bpf/bpf_flow.c) from Linux v6.12.

Extends the existing 5-patch plan in [`kernel-patches.md`](kernel-patches.md) with three more techniques that plan didn't cover.

### New patches stacked on the existing 5

6. **Tail-call fast-path array.** Introduce `BPF_MAP_TYPE_PROG_ARRAY` with ≤16 slots, one per top-N chain. Entry program does the 16-byte signature match (unified load of eth/ip headers) and `bpf_tail_call` into the specialized dissector. Falls through to the existing general program on miss. Pattern already demonstrated in [`samples/xdp/flow_tracker_tmpl/`](../../xdp/flow_tracker_tmpl/).
7. **Fixed-offset templates.** For each fast-path slot, generate a flat dissector with no switch or loop — just `bpf_core_read` at compile-time offsets. Verifier-trivial. Offset tables from [`hardware-classified-extraction.md:98–150`](../../../xdp2-rs/docs/hardware-classified-extraction.md).
8. **Unified port load in BPF.** Already in the 5-patch plan ([`kernel-patches.md:9–58`](kernel-patches.md)); this doc affirms sequencing — land first, uncontroversial.

### eBPF-specific constraints to keep in mind

- **No prefetch intrinsic** — row 4 of section 2's matrix is hard "No" for eBPF.
- **No SIMD.** The 44 ns/pkt batch classify win is unreachable. The only hypothetical path is offloading classification to a kernel-C helper (Impl 1 patch 7) and having eBPF consume the pre-computed chain ID via a per-CPU map — architecturally ugly, probably not worth pursuing.
- **`NUM_FAST_NODES = 64` limit** from [`comprehensive-enhancement-plan.md:459–464`](comprehensive-enhancement-plan.md): the tail-call array must stay small.
- **Nix cc-wrapper quirk:** `NIX_HARDENING_ENABLE=` workaround documented in the [`samples/xdp/`](../../xdp/) READMEs.

---

## 5. Implementation 3 — Production eBPF dissector (`xdp2-flow-ebpf`)

**First-class, distribution-bound deliverable, not a benchmark ceiling.** Lives in `samples/flow_dissector/fast_bpf/` *and* is packaged independently for direct deployment.

Community appetite is real: Cilium, Katran, Falco, Cloudflare's bpf-traffic-manager, Isovalent tooling, Tracee. eBPF deploys on today's kernels without waiting for a CONFIG_ gate to land in mainline and propagate to distros.

### Core design (fast path)

- **Entry program** (~60 lines): one `BPF_PROG_TYPE_FLOW_DISSECTOR` function.
  - 16-byte signature load: `u64 sig = *(u64*)(data+12); u64 sig2 = *(u64*)(data+20);`
  - Masked against a small set of constants, computes chain id.
  - `bpf_tail_call` into a `BPF_MAP_TYPE_PROG_ARRAY`. Default slots: ETH/IPv4/TCP, ETH/IPv4/UDP, ETH/IPv6/TCP, ETH/IPv6/UDP, ETH/VLAN/IPv4/TCP, ETH/VLAN/IPv4/UDP, ETH/IPv4/ICMP; eighth slot reserved for dynamic entries (see §5a).
- **Specialized programs** (10–20 lines each): no loops, no switch, only fixed-offset reads. Write directly into a caller-provided `bpf_flow_keys`.
- **Slow-path fallback:** the full `bpf_flow.c`-equivalent parser generated by `xdp2-compiler` from the existing [`parser_xdp.c`](../parser_xdp.c) wrapper. **No loss of coverage vs. upstream** — every packet the fast path doesn't match still gets a correct dissection.
- **Expected per-packet cost:** ~30–50 ns on fast-path hit (~½ of upstream's 213 ns). Slow path matches or beats upstream via §4 patches.

### What "production quality" means (deliverables)

1. **Userspace control plane** (`xdp2-flow-loader`, small Rust or C binary): loads programs, populates the PROG_ARRAY, attaches to the flow-dissector hook, exposes a Unix socket / gRPC for runtime updates.
2. **Coverage parity tests.** Every packet from [`gen_test_pcap.py`](../gen_test_pcap.py)'s 512-chain combinatorial PCAP must produce identical `bpf_flow_keys` between fast-path and slow-path. Enforced in CI via a new `nix build .#tests.xdp2-flow-ebpf`.
3. **Stability guarantees.** CO-RE (`BPF_CORE_READ`) for kernel-version portability. `libbpf-1.x` minimum. Output ABI matches upstream `bpf_flow_keys` exactly so consumers swap cleanly.
4. **Packaging.** `nix build .#xdp2-flow-ebpf` producing the `.o` + loader + man pages + systemd unit. Container image `ghcr.io/.../xdp2-flow-ebpf:latest` as a Kubernetes DaemonSet.
5. **Documentation.** `README.md` with quickstart, Cilium/Katran integration notes, reproducible benchmarks via `benchmark_bpf.c`, security model writeup (required privileges, failure modes).
6. **License clarity.** GPLv2 on the BPF `.o` (kernel requirement); dual MIT/Apache-2.0 on the userspace loader to match Rust ecosystem norms. **Confirm with user before first release.**

### Distribution path (eBPF ecosystem, not kernel tree)

- Independent project under this repo; releases on GitHub + Nix flake output; loader crate on crates.io.
- Integration PRs to: Cilium (`pkg/datapath/` flow-dissect offload), Katran (flow-classify hook), Falco/Tracee (flow-keys provider), Cloudflare internal tooling.
- Kubernetes angle: Helm chart (`helm install xdp2-flow-ebpf`) for opt-in per-node DaemonSet deployment.
- Semver from day 1 — Cilium et al. won't adopt an unstable dependency.

### Integration with the benchmark harness

A new `parser_xdp_fast.c` wrapper compiled alongside the existing [`parser_xdp.c`](../parser_xdp.c). Selected via a new `-M fast-bpf` flag in [`benchmark_bpf.c`](../benchmark_bpf.c) (existing `BPF_PROG_TEST_RUN` path requires no new infrastructure). Also runs standalone under `xdp2-flow-loader` for real-traffic validation.

---

## 5a. The novel contribution — dynamic fast-path tuning from listening-socket state

xdp2-rs picks its top-N chains from PCAP-derived histograms ([`fast-path-dispatch.md:108–156`](../../../xdp2-rs/docs/fast-path-dispatch.md)). That is great for static profiling. On a real server we have a much better oracle: **the set of listening sockets tells us exactly which flows matter.**

A host running nginx+sshd has listen entries for `:443/tcp`, `:80/tcp`, `:22/tcp`. Every non-listening-port inbound packet is overwhelmingly outbound-response or background noise, not a classification target for downstream RPS/RFS.

### Design

- **Startup enumeration.** Loader reads current listen state via `sock_diag` netlink (`AF_INET`/`AF_INET6` with `NETLINK_SOCK_DIAG`), requesting `TCP_LISTEN` and unconnected `UDP`. Returns `(proto, local_port, local_addr_family)` tuples.
- **Template instantiation.** For each tuple, the loader installs a template program into the PROG_ARRAY. nginx on `:443` → a slot with "ETH/IPv4/TCP, dst_port==443, fast extractor" and a mirror slot for IPv6.
- **Real-time updates.** Three subscription mechanisms, preference order:
  1. **`BPF_CGROUP_INET4_BIND` / `BPF_CGROUP_INET6_BIND`** — a tiny cgroup-attached BPF program observes `bind()` calls, writes `(port, proto)` to a ringbuf; loader reads and updates PROG_ARRAY. Works cleanly for processes in the cgroup.
  2. **`inet_diag` netlink multicast.** Kernel announces socket state transitions; loader subscribes. Works system-wide without cgroup attachment.
  3. **Fallback: `/proc/net/{tcp,tcp6,udp,udp6}` polling** every N seconds for deployments where (1) and (2) aren't available.
- **Hysteresis.** Don't unload a template the moment a listen socket disappears — processes restart. LRU-retire after a minute of no traffic.

### Why this is powerful

- On a typical web server, ~99% of inbound classification traffic targets listening ports. Pre-warming templates for exactly those ports drives fast-path hit rate toward 100% with only 4–8 slots.
- No static configuration, no traffic profiling required. The kernel already knows what matters.
- **It's a pattern, not a one-off.** The same mechanism auto-generates templates for DNAT'd services (via `conntrack`), service-mesh sidecars (via `xt_MARK`), k8s NodePort ranges (via iptables rules).

### Prior art and positioning

- Cilium uses identity-based lookup maps for policy, not classification acceleration.
- Katran uses static backend pools with no dynamic reprogramming from socket state.
- We believe this is a novel flow-dissection optimization. Worth writing up as a short paper or Linux Plumbers / netdev.conf talk alongside the implementation.

### Risks and mitigations

- **Listen-state race with packet arrival** — loader must be defensive; template must be live before we depend on it.
- **Adversarial listen** — local unprivileged user binding high ports to displace legitimate templates. Mitigate by filtering to ports <1024, or privileged processes, or cgroup-scoped enumeration.
- **Listen doesn't capture all flows** — outgoing `connect()` for UDP, for example. Acceptable; slow-path fallback catches anything the fast path misses.

---

## 6. Implementation 4 — Production AF_XDP dissector (`xdp2-flow-afxdp`)

**Also first-class, distribution-bound.** AF_XDP is the modern answer to DPDK for userspace performance without pulling devices off the kernel. Interest is broad: Suricata, VPP, Cilium, Cloudflare, Meta. Most AF_XDP consumers today bolt on hand-written parsers; a general-purpose high-coverage flow dissector as an AF_XDP library fills a real gap.

**SIMD is the centerpiece** — the *only* implementation where SIMD is first-class, because FPU restrictions and BPF ISA rule it out everywhere else.

Baseline architecture is in [`af-xdp-integration-plan.md:1–476`](../../../xdp2-rs/docs/af-xdp-integration-plan.md); this section specifies the production deliverable.

### Deliverables

1. **Rust crate `xdp2-af-xdp`.** Published on crates.io with a stable API:
   ```rust
   let mut d = XskDissector::new("eth0")?;
   while let Some(flow) = d.next() { /* handle flow */ }
   ```
2. **CLI binary `xdp2-flow-afxdp`.** Attaches to an interface, runs the dissector, emits flow records over Unix socket / gRPC / file / stdout. IPFIX-compatible schema if feasible.
3. **Kernel-side XDP classifier** (pre-AF_XDP redirect). Small BPF program filters to interesting traffic before pushing to XSKMAP. Reuses the §5a listening-socket control plane so the SIMD loop doesn't waste gathers on uninteresting packets.
4. **Dynamic reconfiguration.** Shares §5a's control plane. One loader daemon drives both the eBPF dissector and the AF_XDP classifier's templates.
5. **Packaging.** `nix build .#xdp2-flow-afxdp`, container image, systemd unit, man pages. GPLv2 for the XDP `.o`, dual MIT/Apache-2.0 for the Rust crate/binary.
6. **Performance guarantees.** Documented per-platform ceilings: Zen 2 + AVX2, Intel + AVX-512, ARM64 + NEON (Graviton, Ampere). Reproducible via `benchmark_matrix_afxdp.sh`.

### SIMD specifics

- Reference implementation: `xdp2-bench/src/simd_batch.rs`.
- UMEM frame-stride layout from [`af-xdp-integration-plan.md:203–239`](../../../xdp2-rs/docs/af-xdp-integration-plan.md) makes `vpgatherdd`-style gathers efficient.
- Pair SIMD batch classification with per-chain template extraction: SIMD picks the chain, template extracts with zero branches. Amortized per-packet cost: 2 ns/pkt template + 44 ns/pkt batch classify — still bottlenecked by template on hot chains.
- AVX-512 (where available) does 16-wide packet-header compares; per-packet classification cost approaches zero.
- NEON-equivalent path on ARM64 servers — AVX isn't portable; don't pretend it is.

### Phased delivery

- **Pre-X710** (today, Apr 2026): `pktgen` on a veth pair, validate hot-path correctness against flowdis, publish first crates.io release (0.x).
- **Post-X710** (~May 2026, per project note): real NIC test, measure ceiling with SIMD batch + prefetch, publish 1.0 with documented performance envelope.

### Benchmark hook

A new `benchmark_afxdp.rs` entry (inside `xdp2-rs/crates/xdp2-flow-afxdp/`, not `samples/flow_dissector/`), invoked from a new `benchmark_matrix_afxdp.sh` alongside the existing [`benchmark_matrix.sh`](../benchmark_matrix.sh). The comparison matrix grows from 4×1 to 5×1.

---

## 7. Harness integration

How each implementation slots into [`samples/flow_dissector/`](..):

| Implementation | Where it lives | Benchmark entry |
|---|---|---|
| Kernel C patch series (§3) | Patched kernel's `flow_dissector.c` + vendored `src/lib/flowdis/flow_dissector_nextgen.c` for userspace comparison | New `-I nextgen` flag in [`benchmark.c`](../benchmark.c) |
| BPF selftest extensions (§4) | `samples/flow_dissector/kern_bpf/bpf_flow_v2.c` (patched copy) | Existing [`benchmark_bpf.c`](../benchmark_bpf.c) loads arbitrary `.o` via CLI arg |
| Production eBPF `xdp2-flow-ebpf` (§5) | `samples/flow_dissector/fast_bpf/{entry,eth_ipv4_tcp,eth_ipv6_tcp,…}.bpf.c` + loader + Nix output | New `-M fast-bpf` in `benchmark_bpf.c`; also runs standalone via `xdp2-flow-loader` |
| Production AF_XDP `xdp2-flow-afxdp` (§6) | `xdp2-rs/crates/xdp2-af-xdp/` (library) + `xdp2-rs/crates/xdp2-flow-afxdp/` (binary) | New `benchmark_matrix_afxdp.sh`, pktgen on veth |
| Shared control plane (§5a) | `xdp2-rs/crates/xdp2-fastpath-control/` (listen enumeration + PROG_ARRAY update API) | Used by both eBPF and AF_XDP; unit-tested in isolation |

### Existing scaffolding to reuse (do not reinvent)

- [`gen_test_pcap.py`](../gen_test_pcap.py) — 512 combinatorial chains, deterministic.
- [`nix/tests/flow-dissector-benchmark.nix`](../../../nix/tests/flow-dissector-benchmark.nix) — correctness matrix.
- [`benchmark_matrix.sh`](../benchmark_matrix.sh) — current 4-way wrapper; extend to 5-way (add patched-kernel column), then 6-way (add AF_XDP column).
- [`benchmark.c`](../benchmark.c) and [`benchmark_bpf.c`](../benchmark_bpf.c) — both already designed for plug-in implementations.

---

## 8. Distribution and upstreaming strategy

Four parallel tracks. No single sequencing — the targets are different ecosystems.

### Track A — `samples/flow_dissector/` comparison harness

All four implementations measurable head-to-head against both kernel flowdis and upstream `bpf_flow.c` on the same PCAPs. **Gate for everything else: no external claims until we have numbers from our own harness.**

### Track B — BPF selftest patches to the kernel

Easy review cycle, small surface, no `CONFIG_` gates, CI via `tools/testing/selftests/bpf/`. Land the 5 existing patches from [`kernel-patches.md`](kernel-patches.md) plus the 3 new ones from §4. Target maintainers per `scripts/get_maintainer.pl`. Lowest risk, lands soonest.

### Track C — Kernel C patch series to `net/core/flow_dissector.c`

Much larger surface, needs `CONFIG_FLOW_DISSECTOR_FAST_PATH`, more review. Lead with unified port load (uncontroversial, mirrors existing `skb_flow_get_ports`), then fast-path top-N, then templates. Hold the GRO-batched SIMD patch (§3 patch 7) for last or treat as demo-only — netdev is reflexively against FPU in softirq and we need strong numbers before a real argument.

### Track D — Production eBPF dissector (`xdp2-flow-ebpf`)

**First-class product, not a benchmark reference.** Distribution is the eBPF ecosystem:

- Independent project on GitHub + Nix flake; loader crate on crates.io.
- Target integrators: Cilium (`pkg/datapath/` flow-dissect offload), Katran (flow-classify hook), Falco and Tracee (flow-keys provider), Cloudflare tooling. Each gets a PR adding us as an optional dependency with measured motivation.
- Kubernetes angle: Helm chart DaemonSet for opt-in per-node deployment.
- Semver from day 1 — Cilium et al. won't adopt an unstable dep.
- §5a listening-socket tuning is the marquee feature of the first release; anchor the announcement blog post / LPC talk on it.

### Track E — Production AF_XDP dissector (`xdp2-flow-afxdp`)

Also first-class:

- `xdp2-af-xdp` Rust crate on crates.io (library); `xdp2-flow-afxdp` standalone CLI.
- Target integrators: Suricata (IDS), VPP (FD.io), Cilium (AF_XDP datapath mode), research groups.
- Demo milestone: Linux Plumbers or netdev.conf post-May 2026 with X710 line-rate numbers.
- Coordinate release cadence with Track D through the shared §5a control plane.

### Cross-track coordination

- The §5a listening-socket control plane is shared by Tracks D and E. Ship it as `xdp2-fastpath-control` so both consume it cleanly.
- Track C improvements (GRO-batch SIMD, if they land) would bypass D/E in the long run — but `CONFIG_FLOW_DISSECTOR_FAST_PATH` takes years to reach production distros. D and E deploy today.
- Track A benchmarks compare all five: upstream kernel flowdis, upstream kernel BPF, Track C patched kernel, Track D eBPF, Track E AF_XDP. That becomes the definitive comparison.

---

## 9. Out of scope for this document

- New `.c` / `.bpf.c` files. (Planned, not yet written.)
- New Makefile / Nix targets.
- Actual benchmark runs. (The numbers cited here are already measured in [`benchmarks.md`](benchmarks.md).)
- Rust code changes in [`xdp2-rs/`](../../../xdp2-rs/).
- Superseding [`xdp2-rs/docs/cpp-backport-plan.md`](../../../xdp2-rs/docs/cpp-backport-plan.md) — that remains the C++ port plan; this document targets kernel C and eBPF.

---

## References

### In-repo

- [`xdp2-rs/docs/cpp-backport-plan.md`](../../../xdp2-rs/docs/cpp-backport-plan.md) — prior backport plan (C++ target)
- [`xdp2-rs/docs/performance-optimization.md`](../../../xdp2-rs/docs/performance-optimization.md) — LTO, PGO, SIMD numbers
- [`xdp2-rs/docs/performance-maximization-plan.md`](../../../xdp2-rs/docs/performance-maximization-plan.md), [`performance-next-steps.md`](../../../xdp2-rs/docs/performance-next-steps.md), [`deep-performance-analysis.md`](../../../xdp2-rs/docs/deep-performance-analysis.md) — technique details
- [`xdp2-rs/docs/fast-path-dispatch.md`](../../../xdp2-rs/docs/fast-path-dispatch.md) — Zipfian chain distribution, SIMD prefilter
- [`xdp2-rs/docs/hardware-classified-extraction.md`](../../../xdp2-rs/docs/hardware-classified-extraction.md) — template offset tables
- [`xdp2-rs/docs/af-xdp-integration-plan.md`](../../../xdp2-rs/docs/af-xdp-integration-plan.md) — AF_XDP plan, UMEM layout
- [`xdp2-rs/docs/adversarial-testing-strategy.md`](../../../xdp2-rs/docs/adversarial-testing-strategy.md) — correctness validation
- [`benchmarks.md`](benchmarks.md) — current measured numbers
- [`kernel-patches.md`](kernel-patches.md) — existing 5-patch plan
- [`comprehensive-enhancement-plan.md`](comprehensive-enhancement-plan.md) — existing enhancement plan
- [`correctness.md`](correctness.md) — cross-impl equivalence methodology
- [`benchmark.c`](../benchmark.c), [`benchmark_bpf.c`](../benchmark_bpf.c), [`benchmark_matrix.sh`](../benchmark_matrix.sh) — harness entry points
- [`parser.c`](../parser.c), [`parser_xdp.c`](../parser_xdp.c) — parser wiring patterns
- [`kern_bpf/bpf_flow.c`](../kern_bpf/bpf_flow.c) — upstream BPF reference
- [`src/lib/flowdis/flow_dissector.c`](../../../src/lib/flowdis/flow_dissector.c) — vendored kernel flow dissector
- [`samples/xdp/flow_tracker_tmpl/`](../../xdp/flow_tracker_tmpl/), [`samples/xdp/af_xdp_parser/`](../../xdp/af_xdp_parser/) — XDP/AF_XDP sample patterns
- [`nix/tests/flow-dissector-benchmark.nix`](../../../nix/tests/flow-dissector-benchmark.nix) — Nix test harness

### External (to be linked from the doc, not read from this repo)

- `sock_diag(7)` — netlink socket enumeration interface
- `BPF_CGROUP_INET4_BIND` / `BPF_CGROUP_INET6_BIND` — cgroup-attached bind observers
- Cilium datapath docs — for positioning, not copying
- Katran flow-classify architecture — for positioning
- Suricata AF_XDP capture — integration target
- VPP / FD.io — integration target
