# Super Flow Dissector — implementation log

> **Companion to:** [`super-flow-dissector-plan.md`](super-flow-dissector-plan.md).
> This doc is a **living log**: current status per track, completed milestones, and a change log for any variations from the plan.
> The plan doc is the *design*; this doc is the *record*.

---

## Status dashboard

| Track | Scope | Status | Next milestone |
|---|---|---|---|
| **A. Harness integration** | Extend `samples/flow_dissector/` to compare all five implementations | 🔵 in progress (A3 ✅, A4 ✅) | A1, A2 still pending — add slot skeletons to `benchmark.c`, `benchmark_bpf.c` |
| **B. BPF selftest patches** | 3 new patches on top of existing 5 from `kernel-patches.md` | 🟡 not started | Patch 8 (unified port load) — lowest risk, lands first |
| **C. Kernel C patch series** | `net/core/flow_dissector.c` — 7 patches | 🟡 not started | Patch 2 (unified L4 port load) prototype |
| **D. Production eBPF (`xdp2-flow-ebpf`)** | Fast-path + tail-call array + slow-path fallback + loader + Nix packaging | 🔵 in progress (D1–D5 ✅ minus §5a, D6a ✅, D7 ✅, D8 ✅, D9 ✅ re-scoped, D10 ✅) | D6 (full slow-path) awaits xdp2-compiler `.o`; D11 (license) needs user input; D12 (integration PRs) next |
| **E. Production AF_XDP (`xdp2-flow-afxdp`)** | Rust crate + CLI + XDP classifier + shared control plane | 🟡 not started | Crate skeleton under `xdp2-rs/crates/xdp2-af-xdp/` |
| **§5a. Shared control plane (`xdp2-fastpath-control`)** | Listen-socket enumeration + PROG_ARRAY update API | 🔵 in progress (S1 ✅, S2 ✅, S6 ✅) | S3 `BPF_CGROUP_INETx_BIND` ringbuf (real-time updates) or S5 `/proc/net/*` polling fallback |

Legend: 🟡 not started · 🔵 in progress · ✅ complete · ⚠️ blocked · 🔴 superseded

---

## Milestones

### Track A — harness integration

- [ ] **A1.** Add `-I <impl>` selector to `benchmark.c` (userspace comparison) with `flowdis`, `xdp2-optimized`, `xdp2-nextgen` values.
- [ ] **A2.** Add `-M <mode>` selector to `benchmark_bpf.c` with `upstream-bpf`, `fast-bpf`, `xdp2-bpf` values.
- [x] **A3.** Extended `benchmark_matrix.sh` from 4-way to 6-way: added `-f <fast_bpf_obj>` flag (default `fast_bpf/fast_flow.bpf.o`), a third BPF benchmark run block that invokes `benchmark_bpf -b <fast_bpf_obj>` (no C changes needed — it already takes arbitrary `.o` via `-b`), and a new matrix row `xdp2-flow-ebpf fast`. Banner text bumped from "4-Way" to "6-Way". AF_XDP row still pending (Track E). ✅ 2026-04-18
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
- [x] **D8.** `nix build .#xdp2-flow-ebpf` output ([`nix/xdp2-flow-ebpf.nix`](../../../nix/xdp2-flow-ebpf.nix)) — `symlinkJoin` of the Rust loader binary, the compiled `fast_flow.bpf.o`, a `man 1 xdp2-flow-loader` scaffold, and a systemd unit. Layout: `bin/xdp2-flow-loader`, `lib/xdp2-flow-ebpf/fast_flow.bpf.o`, `share/man/man1/xdp2-flow-loader.1`, `share/xdp2-flow-ebpf/xdp2-flow-loader.service`. Built and smoke-tested: `nix build .#xdp2-flow-ebpf` → `./result/bin/xdp2-flow-loader --bpf ./result/lib/xdp2-flow-ebpf/fast_flow.bpf.o` reaches `bpf_object__load` and fails with `EPERM` as expected under non-root (the expected behavior without `CAP_BPF`). ✅ 2026-04-18
- [x] **D9.** Portability floor documented — the actual portability work reduces to pinning a minimum kernel (Linux ≥ 5.1 for `BPF_FLOW_DISSECTOR_CONTINUE`) and libbpf version (≥ 0.7 for `bpf_tail_call_static`). CO-RE via `BPF_CORE_READ` turned out to be a no-op for this code: every memory access is either BPF uapi (`__sk_buff`, `bpf_flow_keys`) or wire-format (RFC-stable header structs), neither of which vary across kernels. Upstream `tools/testing/selftests/bpf/progs/bpf_flow.c` reaches the same conclusion (zero `BPF_CORE_READ` hits). Added a portability block comment to [`fast_bpf/fast_flow.bpf.c`](../fast_bpf/fast_flow.bpf.c) and mirrored the kernel/libbpf floor into the Rust loader's doc comment in [`src/lib.rs`](../../../xdp2-rs/crates/xdp2-flow-loader/src/lib.rs). ✅ 2026-04-18
- [x] **D10.** Container image + Helm chart. ✅ 2026-04-18 — [`nix/xdp2-flow-ebpf-image.nix`](../../../nix/xdp2-flow-ebpf-image.nix) + [`deploy/helm/xdp2-flow-ebpf/`](../../../deploy/helm/xdp2-flow-ebpf/).
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

- [x] **S1.** Crate skeleton [`xdp2-rs/crates/xdp2-fastpath-control/`](../../../xdp2-rs/crates/xdp2-fastpath-control/). Registered in workspace; depends only on `libc` (stays offline-buildable, matches `xdp2-flow-loader` pattern). ✅ 2026-04-19
- [x] **S2.** `sock_diag` netlink enumerator: read-only `enumerate(family, proto)` + `enumerate_all()` returning `Vec<ListenSocket { family, proto, port }>`. Hand-rolled `nlmsghdr`/`inet_diag_req_v2`/`inet_diag_msg` structs (`#[repr(C)]`, layout-checked by test), `SOCK_DIAG_BY_FAMILY` dump request, state-mask `1 << TCP_LISTEN` for TCP / `1 << TCP_CLOSE` for unconnected UDP. `cargo test -p xdp2-fastpath-control`: 6/6 pass. Live smoke test (`XDP2_FASTPATH_CONTROL_LIVE=1`) against the dev host kernel returned 19 IPv4/TCP listeners. ✅ 2026-04-19
- [ ] **S3.** `BPF_CGROUP_INET4_BIND`/`INET6_BIND` ringbuf producer program + consumer.
- [ ] **S4.** `inet_diag` multicast subscriber (system-wide, no cgroup).
- [ ] **S5.** `/proc/net/{tcp,tcp6,udp,udp6}` polling fallback.
- [x] **S6.** PROG_ARRAY update API consumed by Tracks D and E. [`crates/xdp2-fastpath-control/src/controller.rs`](../../../xdp2-rs/crates/xdp2-fastpath-control/src/controller.rs) + [`bpf.rs`](../../../xdp2-rs/crates/xdp2-fastpath-control/src/bpf.rs) — `TemplateController::{install,remove,lookup,reconcile}` over a non-owning `jmp_table_fd`, raw `bpf(2)` syscall wrappers (no libbpf link — keeps the control-plane crate dep-light), `FIRST_DYNAMIC_SLOT = CHAIN_DYNAMIC+1 = 8` guardrail so a §5a control-plane bug can't clobber static slots 0–6 or the slow-path at slot 7. Loader gains `jmp_table_fd()` accessor so consumers can build a controller from the loader they already own. 11/11 crate tests pass. ✅ 2026-04-19
- [ ] **S7.** LRU hysteresis for template retirement.
- [ ] **S8.** Adversarial-bind mitigations (port ≥1024 filter, cgroup scoping).

---

## Progress log (chronological)

### 2026-04-19
- **§5a S6 landed**: [`crates/xdp2-fastpath-control/src/controller.rs`](../../../xdp2-rs/crates/xdp2-fastpath-control/src/controller.rs) adds `TemplateController` — a non-owning wrapper around a PROG_ARRAY `jmp_table` fd that Tracks D and E will both use to drive per-port template install/remove. `install(slot, prog_fd)` / `remove(slot)` / `lookup(slot)` / `reconcile(desired, max_slot)`. `FIRST_DYNAMIC_SLOT = CHAIN_DYNAMIC + 1 = 8` guardrail enforced at install/remove time so a control-plane bug can't inadvertently clobber the static specialised extractors (slots 0–6) or the slow-path (slot 7). [`crates/xdp2-fastpath-control/src/bpf.rs`](../../../xdp2-rs/crates/xdp2-fastpath-control/src/bpf.rs) adds raw `bpf(2)` syscall wrappers (`map_update_elem` / `map_delete_elem` / `map_lookup_elem_u32`) so the crate stays libbpf-free — consumers don't pay elfutils/zlib linker cost just to drive the jmp_table. `xdp2-flow-loader::Loader` stores the `jmp_table_fd` during `load()` and exposes it via `pub fn jmp_table_fd()` so §5a consumers can build a `TemplateController` from the same `Loader` they already own. 11/11 fastpath-control tests pass + 5/5 loader tests still pass. `nix build .#xdp2-rs .#xdp2-flow-ebpf` both succeed (no cargoHash change needed — the new files are pure additions; cargo vendor hash is stable).
- **§5a S1+S2 landed**: new crate [`xdp2-rs/crates/xdp2-fastpath-control/`](../../../xdp2-rs/crates/xdp2-fastpath-control/) — the shared control plane that Tracks D and E will both consume. Deliberately dep-free beyond `libc` so it stays offline-buildable and portable across consumers. S2 implements the read-only `sock_diag` netlink enumerator: `enumerate(Family, Proto) -> Vec<ListenSocket>` opens `AF_NETLINK`+`NETLINK_SOCK_DIAG`, ships a single `SOCK_DIAG_BY_FAMILY` dump request with `idiag_states = 1<<TCP_LISTEN` (TCP) or `1<<TCP_CLOSE` (unconnected UDP), drains the reply stream, and normalises the BE port to host order. Hand-rolled `#[repr(C)]` uapi structs (`nlmsghdr`, `inet_diag_req_v2`, `inet_diag_msg`) with size-regression tests (48/56/16) so a future refactor can't silently misparse wire data. Live smoke: `XDP2_FASTPATH_CONTROL_LIVE=1 cargo test ... enumerate_smoke` found 19 IPv4/TCP listeners on the dev host. Also fixed a latent issue in [`nix/xdp2-rs.nix`](../../../nix/xdp2-rs.nix): the commonArgs `buildInputs` was empty, but since D7a added `xdp2-flow-loader` (which `#[link(name = "bpf")]`s the hand-rolled libbpf FFI) to the workspace, workspace-wide cargo builds in the Nix sandbox needed `libbpf` + `elfutils` + `zlib` to link. `nix build .#xdp2-rs` and `.#xdp2-flow-ebpf` both succeed. cargoHash bumped in both nix files.

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
- **D9 landed** (re-scoped): turned out to be a documentation task, not a code task. Audit of [`fast_bpf/fast_flow.bpf.c`](../fast_bpf/fast_flow.bpf.c) showed zero kernel-internal struct reads — everything is either BPF uapi (`__sk_buff`/`bpf_flow_keys`, both stable ABI) or RFC-stable wire-format headers. Upstream `tools/testing/selftests/bpf/progs/bpf_flow.c` has zero `BPF_CORE_READ` hits for the same reason. Added a "Portability" block comment to the `.bpf.c` file stating: Linux ≥ 5.1 (for `BPF_FLOW_DISSECTOR_CONTINUE` added in commit `ad50d30ba39c`) and libbpf ≥ 0.7 (for `bpf_tail_call_static`). Mirrored the kernel/libbpf floor into the Rust loader crate's top-level doc comment so operators reading rustdoc get the same portability contract. Change log updated with the re-scope rationale so a future reader understands why D9 didn't produce code changes.
- **D8 landed**: [`nix/xdp2-flow-ebpf.nix`](../../../nix/xdp2-flow-ebpf.nix) wraps the fast-path deliverable as a single Nix flake output `xdp2-flow-ebpf`. Internally: `rustPlatform.buildRustPackage` with `cargoBuildFlags = ["-p" "xdp2-flow-loader" "--bin" "xdp2-flow-loader"]` (so only the loader binary is compiled — the rest of the workspace is covered by `xdp2-rs-test`), plus a `runCommand` that invokes `clang -target bpf` to compile `fast_flow.bpf.o` (with `NIX_HARDENING_ENABLE=` to silence `-fzero-call-used-regs` and `-fstack-protector-strong`, both unsupported for BPF), plus a `writeText` man page and systemd unit. `symlinkJoin` produces `$out/{bin,lib,share}` in the layout documented at the top of the nix file. cargoHash for the xdp2-rs workspace bumped in both `nix/xdp2-rs.nix` and `nix/xdp2-flow-ebpf.nix` to match the updated `Cargo.lock` after adding `xdp2-flow-loader` → `libc = "0.2"`. Smoke test: `nix build .#xdp2-flow-ebpf` succeeds; `./result/bin/xdp2-flow-loader --bpf ./result/lib/xdp2-flow-ebpf/fast_flow.bpf.o` reaches `bpf_object__load` and fails with EPERM as expected under non-root.
- **D7d landed**: `Loader::load` now accepts a slow-path `.o` via `LoaderConfig.slow_path_object`. On `Some(path)` it opens, coerces programs to FLOW_DISSECTOR, loads, finds `_dissect`, and writes the fd into `jmp_table[CHAIN_DYNAMIC=7]`. Absent fast-path `jmp_table` is a hard error now (previously silent no-op) — if the caller requested a slow-path install, a missing tail-call table is a misconfiguration. New pub const `xdp2_flow_loader::CHAIN_DYNAMIC` (with a doc comment pinning it to the C header) and a test asserting `CHAIN_DYNAMIC == 7` so a drift between Rust and C fails fast. `Drop` closes `slow_obj` before `obj`. New error variants `SlowPathOpen { path, source }`, `SlowPathLoad { source }`, `SlowPathMissingEntry`; `Display` wording includes "slow path" so logs distinguish which object errored. `slow_path_installed()` accessor added. `cargo test`: 5/5 pass. Completes D7 — the loader now matches the D6 end-state; the D6 checkbox itself still depends on the xdp2-compiler producing a slow-path `.o` to feed into `--slow-path`.
- **D7c landed**: `Loader::attach` opens the target netns path with `O_RDONLY|O_CLOEXEC` (defaulting to `/proc/self/ns/net`) and calls `bpf_prog_attach(entry_fd, netns_fd, BPF_FLOW_DISSECTOR_ATTACH=17, 0)` via the hand-rolled FFI. The owned netns fd is stashed on the `Loader` so `Drop` can `bpf_prog_detach2` + `close()` it before `bpf_object__close`, ensuring the attachment doesn't outlive the process. New error variants: `OpenNetns`, `Attach`, `AlreadyAttached` (display formats include the netns path and `BPF_FLOW_DISSECTOR` hook name). CLI dropped the D7a `NotImplemented` arm; on successful attach it logs `attached; detaching on exit`. Attach test uses `LoaderError::Display` (an attach exercise against a real `.o` requires `CAP_NET_ADMIN`). `cargo test`: 3/3 pass.
- **A3 landed**: [`benchmark_matrix.sh`](../benchmark_matrix.sh) extended from 4-way to 6-way. New `-f <fast_bpf_obj>` flag (default `fast_bpf/fast_flow.bpf.o`) and a third BPF benchmark run block invoking `benchmark_bpf -b <fast_bpf_obj> -l "xdp2-flow-ebpf fast"` — `benchmark_bpf.c` already takes arbitrary `.o` via `-b`, so no C changes needed (A2 can stay deferred). Matrix adds a fourth row `xdp2-flow-ebpf fast` in the BPF column; row label width bumped from 20 to 24 chars to fit. Banner text "4-Way" → "6-Way" to match the top-of-file "Ways:" comment (3 userspace + 3 BPF). AF_XDP row still pending (Track E). `bash -n` clean.
- **D10 landed**: container image + Helm chart. [`nix/xdp2-flow-ebpf-image.nix`](../../../nix/xdp2-flow-ebpf-image.nix) wraps the D8 `xdp2-flow-ebpf` derivation as a `pkgs.dockerTools.buildLayeredImage` (33 MB tar.gz, reproducible `created = "1970-01-01T00:00:00Z"`). Entrypoint `/bin/xdp2-flow-loader`, default `CMD` passes `--bpf /lib/xdp2-flow-ebpf/fast_flow.bpf.o`. Also includes coreutils + bashInteractive (~2 MB) so `kubectl exec` debugging works without a rebuild. Exposed as flake output `xdp2-flow-ebpf-image`; `nix build .#xdp2-flow-ebpf-image` succeeds. [`deploy/helm/xdp2-flow-ebpf/`](../../../deploy/helm/xdp2-flow-ebpf/) adds a minimal Helm chart: `DaemonSet` with `hostNetwork: true` (required — the flow-dissector hook is netns-scoped), drops `ALL` caps and re-adds only `NET_ADMIN` + `BPF` + `SYS_RESOURCE`, `allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true`, `priorityClassName: system-node-critical` (don't evict best-effort infra). Chart tested with `helm template` — renders cleanly.

---

## Change log — variations from the plan

Record any deviation from [`super-flow-dissector-plan.md`](super-flow-dissector-plan.md) here, with the reason. If we discover the plan's approach doesn't work, we update *both* this log and the plan doc — don't let them drift.

| Date | Track | Variation | Reason |
|---|---|---|---|
| 2026-04-18 | D / A | Plan §7 anticipated a new `-M fast-bpf` flag in `benchmark_bpf.c`; the existing `-b <bpf_obj>` flag already accepts arbitrary `.o` paths, so no CLI change is needed for the D1–D3 skeleton. Defer CLI work until Track A (§A2) lands the 3-way `-M` selector holistically. | Avoids churn in `benchmark_bpf.c` for a flag that would be immediately superseded. |
| 2026-04-18 | D | D4 oracle is upstream `bpf_flow.kern.o` instead of the plan's "slow-path fallback" — the latter (D6) isn't built yet. Parity test header documents the swap once D6 lands. | Keeps D4 actionable before D6; both oracles are behaviourally equivalent for ETH/IPv4/TCP traffic the fast-path accepts today. |
| 2026-04-18 | D | Added D6a as an intermediate step before D6. D6a changes only the slow-path return value (`BPF_DROP` → `BPF_FLOW_DISSECTOR_CONTINUE`); full D6 still needs a loader-driven tail call into the xdp2-compiler-generated slow path. | D6a is a one-line production-correctness fix that unblocks real-world load-tests before D6's larger loader work lands. Until D6a, a packet that missed the fast path was dropped rather than dissected. |
| 2026-04-18 | D | `struct vlan_hdr` declared inline in `fast_flow.bpf.c` rather than imported from `<linux/if_vlan.h>`. | `<linux/if_vlan.h>` is kernel-internal and doesn't export the struct to BPF-target builds (clang errored on forward declaration). The wire-format struct is 4 bytes and stable — inlining is simpler than vendoring the header. |
| 2026-04-18 | D | Plan reserved slot 7 (`CHAIN_DYNAMIC`) for §5a listening-socket-driven templates; D7d uses slot 7 for the slow-path dissector install instead. §5a now targets slots ≥8 (requires bumping `NUM_FAST_CHAINS` when §5a lands). | Both features are "installed by the loader at runtime", but they serve different purposes. Putting the slow-path at a fixed low slot keeps the entry program's "miss → tail-call slot 7" contract stable as §5a adds and retires per-port templates; otherwise §5a churn would have to coordinate with the slow-path install. |
| 2026-04-18 | D | D9 re-scoped from "add `BPF_CORE_READ`" to "document portability floor." | CO-RE exists to read kernel-internal structs that change across versions. This code only touches BPF uapi (`__sk_buff`, `bpf_flow_keys`) and RFC-stable wire-format headers — neither class needs CO-RE. Upstream `bpf_flow.c` confirms the pattern (zero `BPF_CORE_READ` hits). The real portability surface is the kernel feature floor (≥5.1 for `BPF_FLOW_DISSECTOR_CONTINUE`) and libbpf floor (≥0.7 for `bpf_tail_call_static`); both are now documented in code comments. Re-introduce CO-RE if/when we ever need to read kernel-internal struct fields (e.g., for a future `__sk_buff` extension or a `vmlinux.h`-sourced internal). |

---

## Open questions

Track unresolved decisions so they don't get lost between sessions.

- **License for `xdp2-flow-loader`**: plan proposes dual MIT/Apache-2.0 to match Rust ecosystem. Needs user confirmation before first release. (D11)
- **Starting track**: which milestone do we execute first? See plan §8 — Track A is the gate, but Track D or §5a spike may give faster feedback.
