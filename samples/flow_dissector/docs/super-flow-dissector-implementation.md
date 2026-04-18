# Super Flow Dissector — implementation log

> **Companion to:** [`super-flow-dissector-plan.md`](super-flow-dissector-plan.md).
> This doc is a **living log**: current status per track, completed milestones, and a change log for any variations from the plan.
> The plan doc is the *design*; this doc is the *record*.

---

## Status dashboard

| Track | Scope | Status | Next milestone |
|---|---|---|---|
| **A. Harness integration** | Extend `samples/flow_dissector/` to compare all five implementations | 🟡 not started | Add slot skeletons to `benchmark.c`, `benchmark_bpf.c`, `benchmark_matrix.sh` |
| **B. BPF selftest patches** | 3 new patches on top of existing 5 from `kernel-patches.md` | 🟡 not started | Patch 8 (unified port load) — lowest risk, lands first |
| **C. Kernel C patch series** | `net/core/flow_dissector.c` — 7 patches | 🟡 not started | Patch 2 (unified L4 port load) prototype |
| **D. Production eBPF (`xdp2-flow-ebpf`)** | Fast-path + tail-call array + slow-path fallback + loader + Nix packaging | 🔵 in progress (D1–D3 ✅) | D4: coverage parity test vs slow-path |
| **E. Production AF_XDP (`xdp2-flow-afxdp`)** | Rust crate + CLI + XDP classifier + shared control plane | 🟡 not started | Crate skeleton under `xdp2-rs/crates/xdp2-af-xdp/` |
| **§5a. Shared control plane (`xdp2-fastpath-control`)** | Listen-socket enumeration + PROG_ARRAY update API | 🟡 not started | `sock_diag` netlink enumerator (read-only spike) |

Legend: 🟡 not started · 🔵 in progress · ✅ complete · ⚠️ blocked · 🔴 superseded

---

## Milestones

### Track A — harness integration

- [ ] **A1.** Add `-I <impl>` selector to `benchmark.c` (userspace comparison) with `flowdis`, `xdp2-optimized`, `xdp2-nextgen` values.
- [ ] **A2.** Add `-M <mode>` selector to `benchmark_bpf.c` with `upstream-bpf`, `fast-bpf`, `xdp2-bpf` values.
- [ ] **A3.** Extend `benchmark_matrix.sh` from 4-way to 5-way (add patched-kernel column) and eventually to 6-way (add AF_XDP column).
- [ ] **A4.** Add Nix test `nix build .#tests.super-flow-dissector` that runs the full matrix on the combinatorial PCAP and asserts zero mismatches between fast-path and slow-path.

### Track B — BPF selftest patches (target: `tools/testing/selftests/bpf/progs/bpf_flow.c`)

- [ ] **B1.** Land existing 5 patches from [`kernel-patches.md`](kernel-patches.md) (unified port load → SCTP/DCCP → IPv6 routing → GRE byte order → memcpy removal).
- [ ] **B2.** Patch 6: tail-call fast-path `BPF_MAP_TYPE_PROG_ARRAY` (≤16 slots).
- [ ] **B3.** Patch 7: fixed-offset template programs for each fast-path slot.
- [ ] **B4.** Patch 8: confirmation that unified port load (B1 patch 1) is sequenced first upstream.

### Track C — kernel C patch series (target: `net/core/flow_dissector.c`)

- [ ] **C1.** Patch 1 prep: `flow_keys_basic_lite` struct export.
- [ ] **C2.** Patch 2: unified L4 port load (TCP/UDP/SCTP/DCCP).
- [ ] **C3.** Patch 3: fast-path top-5 chain functions gated by 16-byte signature match.
- [ ] **C4.** Patch 4: `DEFINE_FLOW_TEMPLATE` macro and top-5 chain templates.
- [ ] **C5.** Patch 5: `prefetch(skb->data + 64)` at dissect entry.
- [ ] **C6.** Patch 6 (optional): `FLOW_DISSECTOR_KEY_*`-guided selective memset.
- [ ] **C7.** Patch 7 (RFC, contentious): `CONFIG_FLOW_DISSECTOR_SIMD` GRO-batched SIMD classify. Out-of-tree demo first.

### Track D — production eBPF `xdp2-flow-ebpf`

- [x] **D1.** `samples/flow_dissector/fast_bpf/` directory scaffolding + Makefile target. ✅ 2026-04-18
- [x] **D2.** Entry program: 16-byte signature match + `bpf_tail_call` skeleton. ✅ 2026-04-18 (IPv4/TCP gate only; IPv6/VLAN gates are D5)
- [x] **D3.** First specialized program: ETH/IPv4/TCP fast extractor (no loops, no switch). ✅ 2026-04-18
- [ ] **D4.** Coverage-parity test: fast-path hit must produce identical `bpf_flow_keys` as slow-path fallback on matching packets.
- [ ] **D5.** Fill out remaining 7 fast-path slots (IPv4/UDP, IPv6/TCP, IPv6/UDP, VLAN/IPv4/TCP, VLAN/IPv4/UDP, IPv4/ICMP, dynamic).
- [ ] **D6.** Slow-path fallback via `xdp2-compiler` from existing `parser_xdp.c`.
- [ ] **D7.** Userspace loader `xdp2-flow-loader` (Rust).
- [ ] **D8.** `nix build .#xdp2-flow-ebpf` output (kernel `.o` + loader + man pages + systemd unit).
- [ ] **D9.** CO-RE via `BPF_CORE_READ` for kernel-version portability.
- [ ] **D10.** Container image + Helm chart.
- [ ] **D11.** License headers: GPLv2 on `.o`, dual MIT/Apache-2.0 on Rust loader (confirm with user).
- [ ] **D12.** Integration PRs: Cilium → Katran → Falco/Tracee.

### Track E — production AF_XDP `xdp2-flow-afxdp`

- [ ] **E1.** Rust crate skeleton `xdp2-rs/crates/xdp2-af-xdp/` with `XskDissector` API.
- [ ] **E2.** Binary crate skeleton `xdp2-rs/crates/xdp2-flow-afxdp/` (CLI).
- [ ] **E3.** Kernel-side XDP classifier program (pre-XSKMAP redirect).
- [ ] **E4.** SIMD batch classifier (AVX2 first, AVX-512 feature-gated, NEON for ARM64).
- [ ] **E5.** Veth + pktgen pre-X710 validation harness.
- [ ] **E6.** X710 measurements (post-hardware-arrival, ~May 2026).
- [ ] **E7.** crates.io 0.x release.
- [ ] **E8.** `nix build .#xdp2-flow-afxdp` output.
- [ ] **E9.** Integration PRs: Suricata → VPP → Cilium AF_XDP mode.

### §5a — shared control plane `xdp2-fastpath-control`

- [ ] **S1.** Crate skeleton `xdp2-rs/crates/xdp2-fastpath-control/`.
- [ ] **S2.** `sock_diag` netlink enumerator (read-only spike): list current `TCP_LISTEN` and unconnected `UDP` sockets.
- [ ] **S3.** `BPF_CGROUP_INET4_BIND`/`INET6_BIND` ringbuf producer program + consumer.
- [ ] **S4.** `inet_diag` multicast subscriber (system-wide, no cgroup).
- [ ] **S5.** `/proc/net/{tcp,tcp6,udp,udp6}` polling fallback.
- [ ] **S6.** PROG_ARRAY update API consumed by Tracks D and E.
- [ ] **S7.** LRU hysteresis for template retirement.
- [ ] **S8.** Adversarial-bind mitigations (port ≥1024 filter, cgroup scoping).

---

## Progress log (chronological)

### 2026-04-18
- Plan approved and committed as `1a76bcc`: [`super-flow-dissector-plan.md`](super-flow-dissector-plan.md).
- Implementation log (this file) created.
- All tracks at 🟡 not started.
- **D1–D3 landed**: [`fast_bpf/fast_flow.bpf.c`](../fast_bpf/fast_flow.bpf.c) with `_dissect` entry (IPv4/TCP signature-match gate) and `flow_dissector_eth_ipv4_tcp` specialized extractor. Makefile target `fast_bpf/fast_flow.bpf.o` builds cleanly via `nix develop --command make -C samples/flow_dissector fast_bpf/fast_flow.bpf.o`. `llvm-objdump` confirms both programs present.

---

## Change log — variations from the plan

Record any deviation from [`super-flow-dissector-plan.md`](super-flow-dissector-plan.md) here, with the reason. If we discover the plan's approach doesn't work, we update *both* this log and the plan doc — don't let them drift.

| Date | Track | Variation | Reason |
|---|---|---|---|
| 2026-04-18 | D / A | Plan §7 anticipated a new `-M fast-bpf` flag in `benchmark_bpf.c`; the existing `-b <bpf_obj>` flag already accepts arbitrary `.o` paths, so no CLI change is needed for the D1–D3 skeleton. Defer CLI work until Track A (§A2) lands the 3-way `-M` selector holistically. | Avoids churn in `benchmark_bpf.c` for a flag that would be immediately superseded. |

---

## Open questions

Track unresolved decisions so they don't get lost between sessions.

- **License for `xdp2-flow-loader`**: plan proposes dual MIT/Apache-2.0 to match Rust ecosystem. Needs user confirmation before first release. (D11)
- **Starting track**: which milestone do we execute first? See plan §8 — Track A is the gate, but Track D or §5a spike may give faster feedback.
