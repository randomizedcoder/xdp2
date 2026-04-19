# Super Flow Dissector — implementation log

> **Companion to:** [`super-flow-dissector-plan.md`](super-flow-dissector-plan.md).
> This doc is a **living log**: current status per track, completed milestones, and a change log for any variations from the plan.
> The plan doc is the *design*; this doc is the *record*.

---

## Status dashboard

| Track | Scope | Status | Next milestone |
|---|---|---|---|
| **A. Harness integration** | Extend `samples/flow_dissector/` to compare all five implementations | 🔵 in progress (A4 ✅) | Add slot skeletons to `benchmark.c`, `benchmark_bpf.c`, `benchmark_matrix.sh` |
| **B. BPF selftest patches** | 3 new patches on top of existing 5 from `kernel-patches.md` | 🟡 not started | Patch 8 (unified port load) — lowest risk, lands first |
| **C. Kernel C patch series** | `net/core/flow_dissector.c` — 7 patches | 🟡 not started | Patch 2 (unified L4 port load) prototype |
| **D. Production eBPF (`xdp2-flow-ebpf`)** | Fast-path + tail-call array + slow-path fallback + loader + Nix packaging | 🔵 in progress (D1–D4 ✅, D5 ✅ minus §5a, D6a ✅) | D6: full slow-path tail call; D7: Rust loader |
| **E. Production AF_XDP (`xdp2-flow-afxdp`)** | Rust crate + CLI + XDP classifier + shared control plane | 🟡 not started | Crate skeleton under `xdp2-rs/crates/xdp2-af-xdp/` |
| **§5a. Shared control plane (`xdp2-fastpath-control`)** | Listen-socket enumeration + PROG_ARRAY update API | 🟡 not started | `sock_diag` netlink enumerator (read-only spike) |

Legend: 🟡 not started · 🔵 in progress · ✅ complete · ⚠️ blocked · 🔴 superseded

---

## Milestones

### Track A — harness integration

- [ ] **A1.** Add `-I <impl>` selector to `benchmark.c` (userspace comparison) with `flowdis`, `xdp2-optimized`, `xdp2-nextgen` values.
- [ ] **A2.** Add `-M <mode>` selector to `benchmark_bpf.c` with `upstream-bpf`, `fast-bpf`, `xdp2-bpf` values.
- [ ] **A3.** Extend `benchmark_matrix.sh` from 4-way to 5-way (add patched-kernel column) and eventually to 6-way (add AF_XDP column).
- [x] **A4.** `nix build .#tests.super-flow-dissector` / `nix build .#super-flow-dissector-test` — [`nix/tests/super-flow-dissector.nix`](../../../nix/tests/super-flow-dissector.nix). Builds `fast_flow.bpf.o` + `bpf_flow.kern.o` + `parity_test`, verifies all 5 BPF program symbols are present, generates the combinatorial PCAP via `gen_test_pcap.py`, and — when run as root — invokes `parity_test` on it asserting zero mismatches and ≥1 fast-path hit. Non-root runs stop after the build checks. ✅ 2026-04-18

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
- [x] **D4.** Coverage-parity test binary: [`fast_bpf/parity_test.c`](../fast_bpf/parity_test.c). Runs fast + oracle via `BPF_PROG_TEST_RUN`, asserts `bpf_flow_keys` parity on fast-path hits. Oracle is upstream `bpf_flow.kern.o` until D6 lands the slow-path fallback. Nix-test wiring is Track A (A4). ✅ 2026-04-18
- [ ] **D5.** Fill out remaining 7 fast-path slots:
  - [x] IPv4/UDP ✅ 2026-04-18
  - [x] IPv6/TCP ✅ 2026-04-18 (entry gate rejects packets with IPv6 extension headers — ext-hdr walk stays in the slow path)
  - [x] IPv6/UDP ✅ 2026-04-18
  - [x] VLAN/IPv4/TCP ✅ 2026-04-18 (entry gate rejects QinQ; extractor rewrites `nhoff`/`n_proto` to match oracle's post-unwrap state)
  - [x] VLAN/IPv4/UDP ✅ 2026-04-18
  - [x] IPv4/ICMP ✅ 2026-04-18 (no L4 ports; sport/dport stay at zero default matching upstream)
  - [ ] dynamic (§5a)
- [ ] **D6.** Slow-path fallback via `xdp2-compiler` from existing `parser_xdp.c`.
  - [x] **D6a** (intermediate): slow-path fall-through returns `BPF_FLOW_DISSECTOR_CONTINUE` instead of `BPF_DROP`, so non-fast-path packets are handed back to the kernel's software dissector. Full D6 (tail call into an xdp2-compiler-generated slow path) still pending. ✅ 2026-04-18
- [x] **D7.** Userspace loader `xdp2-flow-loader` (Rust). ✅ 2026-04-18 (all four subtasks complete)
  - [x] **D7a** — crate skeleton [`xdp2-rs/crates/xdp2-flow-loader/`](../../../xdp2-rs/crates/xdp2-flow-loader/) with API surface (`LoaderConfig`, `Loader`, `LoaderError`) and CLI binary. All operations return `LoaderError::NotImplemented` pending D7b. Registered in workspace; `cargo test -p xdp2-flow-loader` passes (2/2). ✅ 2026-04-18
  - [x] **D7b** — `Loader::load` now opens the BPF object, sets every program to `BPF_PROG_TYPE_FLOW_DISSECTOR`, loads, finds `_dissect`, and populates `jmp_table` with non-entry programs in declaration order — mirroring `parity_test.c:42-100`. Uses hand-written FFI ([`src/libbpf_sys.rs`](../../../xdp2-rs/crates/xdp2-flow-loader/src/libbpf_sys.rs)) linking against system libbpf; no crates.io libbpf-sys/libbpf-rs dep (keeps the crate buildable offline). `Drop` calls `bpf_object__close`. `cargo test`: 3/3 pass. ✅ 2026-04-18
  - [x] **D7c** — `Loader::attach` opens the target netns (defaults to `/proc/self/ns/net`) and calls `bpf_prog_attach(entry_fd, netns_fd, BPF_FLOW_DISSECTOR)`. `Drop` calls `bpf_prog_detach2` and closes the stored `netns_fd` before `bpf_object__close`, so the attachment is cleaned up on process exit. Requires `CAP_NET_ADMIN` in the target netns. `cargo test -p xdp2-flow-loader`: 3/3 pass. ✅ 2026-04-18
  - [x] **D7d** — slow-path `.o` handling. When `LoaderConfig.slow_path_object` is `Some(path)`, `Loader::load` opens the object, coerces every program to `BPF_PROG_TYPE_FLOW_DISSECTOR`, loads, finds `_dissect`, and writes its fd into `jmp_table[CHAIN_DYNAMIC=7]`. Hard error if the fast-path object has no `jmp_table` (caller asked for a slow-path install but there's no tail-call table). New pub const `xdp2_flow_loader::CHAIN_DYNAMIC` keeps the Rust and C sides in sync. `Drop` closes `slow_obj` before `obj` so the PROG_ARRAY entry's fd reference releases first. `cargo test`: 5/5 pass. Unblocks full D6 once the xdp2-compiler slow path is wired in. ✅ 2026-04-18
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
- **D1–D3 landed** (`c14935d`): [`fast_bpf/fast_flow.bpf.c`](../fast_bpf/fast_flow.bpf.c) with `_dissect` entry (IPv4/TCP signature-match gate) and `flow_dissector_eth_ipv4_tcp` specialized extractor. Makefile target `fast_bpf/fast_flow.bpf.o` builds cleanly via `nix develop --command make -C samples/flow_dissector fast_bpf/fast_flow.bpf.o`. `llvm-objdump` confirms both programs present.
- **D4 landed** (`b8b316c`): [`fast_bpf/parity_test.c`](../fast_bpf/parity_test.c) — standalone harness loading fast + oracle `.o`, running both via `BPF_PROG_TEST_RUN` on every PCAP packet, diffing `bpf_flow_keys` on fast-path hits. Exits non-zero on any mismatch so CI can gate on it. Oracle is the vendored upstream `bpf_flow.kern.o` until D6; swap in the xdp2-compiler slow-path object once that lands.
- **D5 partial landed** (`ed78526`): IPv4/UDP, IPv6/TCP, IPv6/UDP extractors added to [`fast_bpf/fast_flow.bpf.c`](../fast_bpf/fast_flow.bpf.c); entry program now gates pure IPv6 (no extension headers) and dispatches to the four non-VLAN slots. `llvm-objdump` confirms all 5 programs present (`_dissect` + 4 specialised). Parity test extended to diff `ipv6_src`/`ipv6_dst`/`flow_label`. VLAN, ICMP, and §5a dynamic slots still TODO.
- **A4 landed**: [`nix/tests/super-flow-dissector.nix`](../../../nix/tests/super-flow-dissector.nix) wired into `nix/tests/default.nix` and `flake.nix` (exposed as both `tests.super-flow-dissector` and `super-flow-dissector-test`). Runs 9 build checks non-root (all pass) and adds a runtime parity assertion when root+BPF are available. Output on this host: `Passed: 9  Failed: 0` (runtime check skipped — non-root).
- **D7b landed**: `Loader::load` now actually loads the BPF object. Uses hand-written FFI in [`xdp2-rs/crates/xdp2-flow-loader/src/libbpf_sys.rs`](../../../xdp2-rs/crates/xdp2-flow-loader/src/libbpf_sys.rs) linking against system libbpf via `#[link(name = "bpf")]` — no crates.io dep (libbpf-sys/libbpf-rs are not in the offline cargo index; hand-rolling the ~10 entry points we need keeps the crate buildable offline). Implementation path: `bpf_object__open` → iterate `bpf_object__next_program` calling `bpf_program__set_type(BPF_PROG_TYPE_FLOW_DISSECTOR)` → `bpf_object__load` → `bpf_object__find_program_by_name("_dissect")` → iterate again populating `jmp_table` via `bpf_map_update_elem`. `Drop` calls `bpf_object__close`. New error variants: `Open`, `Load`, `MissingEntryProgram`, `JmpTableFd`, `JmpTableUpdate`, `BadPath`. CLI now prints `loaded: entry_fd=N, jmp_table_slots=N`. `cargo test`: 3/3 pass. Smoke-test against real `fast_flow.bpf.o` requires root (not run in this session).
- **D7a landed**: Rust loader crate skeleton under [`xdp2-rs/crates/xdp2-flow-loader/`](../../../xdp2-rs/crates/xdp2-flow-loader/). Exposes `LoaderConfig`, `Loader`, `LoaderError` plus a CLI binary `xdp2-flow-loader` accepting `--bpf`, `--slow-path`, `--netns`. All operations return `LoaderError::NotImplemented` (exit code 2) — D7b will plug in libbpf. Registered in `xdp2-rs/Cargo.toml`. `nix develop --command cargo test -p xdp2-flow-loader`: 2/2 pass. Dependency choice (libbpf-rs vs libbpf-sys FFI) deferred to D7b so the skeleton introduces no new network-fetched deps.
- **D5 IPv4/ICMP landed**: `flow_dissector_eth_ipv4_icmp` added to [`fast_bpf/fast_flow.bpf.c`](../fast_bpf/fast_flow.bpf.c); entry program dispatches `IPPROTO_ICMP` to `CHAIN_ETH_IPV4_ICMP`. ICMP has no L4 port pair, so sport/dport stay at the zero default — which matches upstream exactly, since `bpf_flow.kern.o` validates `sizeof(icmphdr)` bytes then returns `BPF_OK` without touching sport/dport. Nix test now verifies 8 program symbols; Output: `Passed: 12  Failed: 0`. D5 is now complete modulo the §5a dynamic slot (far-future).
- **D5 VLAN + D6a landed**: `flow_dissector_eth_vlan_ipv4_tcp` and `flow_dissector_eth_vlan_ipv4_udp` added to [`fast_bpf/fast_flow.bpf.c`](../fast_bpf/fast_flow.bpf.c); entry program gains an `ETH_P_8021Q` arm that rejects QinQ (encapsulated ethertype must be IPv4) and dispatches single-tagged VLAN/IPv4 TCP/UDP. Both extractors rewrite `keys->nhoff` and `keys->n_proto` to match the oracle's post-unwrap state (upstream `bpf_flow.kern.o` removes the tag in-place before calling the IPv4 handler). `struct vlan_hdr` is declared inline — `<linux/if_vlan.h>` isn't available to BPF builds. Slow-path fall-through now returns `BPF_FLOW_DISSECTOR_CONTINUE` instead of `BPF_DROP` (D6a): non-fast-path packets go to the kernel's software dissector instead of being silently dropped — required for production correctness ahead of full D6. Nix test expanded to check 7 program symbols (up from 5). Output: `Passed: 11  Failed: 0`.
- **D7d landed**: `Loader::load` now accepts a slow-path `.o` via `LoaderConfig.slow_path_object`. On `Some(path)` it opens, coerces programs to FLOW_DISSECTOR, loads, finds `_dissect`, and writes the fd into `jmp_table[CHAIN_DYNAMIC=7]`. Absent fast-path `jmp_table` is a hard error now (previously silent no-op) — if the caller requested a slow-path install, a missing tail-call table is a misconfiguration. New pub const `xdp2_flow_loader::CHAIN_DYNAMIC` (with a doc comment pinning it to the C header) and a test asserting `CHAIN_DYNAMIC == 7` so a drift between Rust and C fails fast. `Drop` closes `slow_obj` before `obj`. New error variants `SlowPathOpen { path, source }`, `SlowPathLoad { source }`, `SlowPathMissingEntry`; `Display` wording includes "slow path" so logs distinguish which object errored. `slow_path_installed()` accessor added. `cargo test`: 5/5 pass. Completes D7 — the loader now matches the D6 end-state; the D6 checkbox itself still depends on the xdp2-compiler producing a slow-path `.o` to feed into `--slow-path`.
- **D7c landed**: `Loader::attach` opens the target netns path with `O_RDONLY|O_CLOEXEC` (defaulting to `/proc/self/ns/net`) and calls `bpf_prog_attach(entry_fd, netns_fd, BPF_FLOW_DISSECTOR_ATTACH=17, 0)` via the hand-rolled FFI. The owned netns fd is stashed on the `Loader` so `Drop` can `bpf_prog_detach2` + `close()` it before `bpf_object__close`, ensuring the attachment doesn't outlive the process. New error variants: `OpenNetns`, `Attach`, `AlreadyAttached` (display formats include the netns path and `BPF_FLOW_DISSECTOR` hook name). CLI dropped the D7a `NotImplemented` arm; on successful attach it logs `attached; detaching on exit`. Attach test uses `LoaderError::Display` (an attach exercise against a real `.o` requires `CAP_NET_ADMIN`). `cargo test`: 3/3 pass.

---

## Change log — variations from the plan

Record any deviation from [`super-flow-dissector-plan.md`](super-flow-dissector-plan.md) here, with the reason. If we discover the plan's approach doesn't work, we update *both* this log and the plan doc — don't let them drift.

| Date | Track | Variation | Reason |
|---|---|---|---|
| 2026-04-18 | D / A | Plan §7 anticipated a new `-M fast-bpf` flag in `benchmark_bpf.c`; the existing `-b <bpf_obj>` flag already accepts arbitrary `.o` paths, so no CLI change is needed for the D1–D3 skeleton. Defer CLI work until Track A (§A2) lands the 3-way `-M` selector holistically. | Avoids churn in `benchmark_bpf.c` for a flag that would be immediately superseded. |
| 2026-04-18 | D | D4 oracle is upstream `bpf_flow.kern.o` instead of the plan's "slow-path fallback" — the latter (D6) isn't built yet. Parity test header documents the swap once D6 lands. | Keeps D4 actionable before D6; both oracles are behaviourally equivalent for ETH/IPv4/TCP traffic the fast-path accepts today. |
| 2026-04-18 | D | Added D6a as an intermediate step before D6. D6a changes only the slow-path return value (`BPF_DROP` → `BPF_FLOW_DISSECTOR_CONTINUE`); full D6 still needs a loader-driven tail call into the xdp2-compiler-generated slow path. | D6a is a one-line production-correctness fix that unblocks real-world load-tests before D6's larger loader work lands. Until D6a, a packet that missed the fast path was dropped rather than dissected. |
| 2026-04-18 | D | `struct vlan_hdr` declared inline in `fast_flow.bpf.c` rather than imported from `<linux/if_vlan.h>`. | `<linux/if_vlan.h>` is kernel-internal and doesn't export the struct to BPF-target builds (clang errored on forward declaration). The wire-format struct is 4 bytes and stable — inlining is simpler than vendoring the header. |

---

## Open questions

Track unresolved decisions so they don't get lost between sessions.

- **License for `xdp2-flow-loader`**: plan proposes dual MIT/Apache-2.0 to match Rust ecosystem. Needs user confirmation before first release. (D11)
- **Starting track**: which milestone do we execute first? See plan §8 — Track A is the gate, but Track D or §5a spike may give faster feedback.
