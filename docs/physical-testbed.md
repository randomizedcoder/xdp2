# XDP2 Physical Testbed (hp2 ↔ hp5)

This document describes the dedicated bare-metal testbed used to validate and
benchmark the XDP2 networking stack against real Intel X710 NICs over a
back-to-back fibre link, and how to drive automated test runs against it.

It is written so that someone new to the project can:

1. Understand *what* the testbed is and *why* it exists.
2. Reproduce an equivalent setup in their own environment.
3. Run the full automated test matrix against either or both hosts.

> Status as of 2026-04-20: the two hosts (`hp2` and `hp5`) are racked,
> reachable via root SSH, and physically cabled. The XDP2 repository ships
> the NixOS module and runner described below; applying the module to the
> host configurations under `~/nixos/hp/{hp2,hp5}/` is a one-line import
> change tracked separately from this doc.

---

## Table of contents

1. [Why bare-metal](#1-why-bare-metal)
2. [Hardware summary](#2-hardware-summary)
3. [Network topology](#3-network-topology)
4. [Software baseline](#4-software-baseline)
5. [Access (SSH)](#5-access-ssh)
6. [The xdp2-shipped NixOS module](#6-the-xdp2-shipped-nixos-module)
7. [Tuning applied by the module](#7-tuning-applied-by-the-module)
8. [Manual one-time fixes](#8-manual-one-time-fixes)
9. [Test catalog and per-test recipes](#9-test-catalog-and-per-test-recipes)
10. [Automation wrapper (`nix run .#run-on-host`)](#10-automation-wrapper-nix-run-run-on-host)
11. [Result collection](#11-result-collection)
12. [Replicating in your own environment](#12-replicating-in-your-own-environment)
13. [Future work](#13-future-work)

[Appendix A — Known issues and gotchas](#appendix-a--known-issues-and-gotchas)
[Appendix B — One-line cheatsheet](#appendix-b--one-line-cheatsheet)

---

## 1. Why bare-metal

XDP2 has two stated workload personas (see project memory and
[`samples/flow_dissector/SUMMARY.md`](../samples/flow_dissector/SUMMARY.md)):

- **HFT** — extreme parsing latency, single-core, no allocations.
- **DPI** — extreme aggregate throughput, multi-core, sustained line rate.

Both claims need ground-truth measurements. CI runners and VMs cannot deliver
that ground truth because they:

- introduce hypervisor-side variance that swamps the nanosecond-scale signal;
- do not expose AF_XDP zero-copy descriptors, hardware ntuple steering, or
  `XDP_REDIRECT` between physical NICs;
- cannot pin IRQs to dedicated cores or guarantee `nohz_full` quiescence.

The testbed is the only environment in which the BPF programs in
[`samples/flow_dissector/fast_bpf/`](../samples/flow_dissector/fast_bpf/) and
the AF_XDP loader in
[`xdp2-rs/crates/xdp2-flow-loader/`](../xdp2-rs/crates/xdp2-flow-loader/) can
be exercised against real packets at line rate.

For tests that do **not** need the NIC (`xdp2-rs` cargo tests, `proto-audit`,
the `BPF_PROG_TEST_RUN` paths in the flow-dissector matrix), the testbed
still gives a deterministic, ungoverned, no-other-workload baseline that
makes results comparable across runs.

---

## 2. Hardware summary

Both hosts are physically identical except for installed RAM. They share a
chassis model (HP small-form-factor desktop with one PCIe x8 slot) and run
the same NixOS profile (see §6).

| Field | hp2 | hp5 |
| --- | --- | --- |
| CPU | AMD Ryzen 5 PRO 2400G | AMD Ryzen 5 PRO 2400G |
| Cores / threads | 4 / 8 | 4 / 8 |
| NUMA nodes | 1 (CPUs 0–7) | 1 (CPUs 0–7) |
| RAM | 30 GB | 61 GB |
| NIC | Intel X710 10 GbE SFP+ (`01:00.0`, `01:00.1`) | identical |
| NIC driver | `i40e` | `i40e` |
| Link speed | 10 Gb/s, 10000baseSR/Full | 10 Gb/s, 10000baseSR/Full |
| Onboard NIC | Realtek 1 GbE (`eno1`, mgmt) | Realtek 1 GbE (`eno1`, mgmt) |

**Live verification (run from your laptop, requires SSH access — see §5):**

```bash
ssh root@hp2 lscpu | grep 'Model name'
ssh root@hp5 free -g
ssh root@hp2 lspci | grep -i ethernet
```

### Why X710 specifically

The Intel X710 (i40e family — *not* the older XL710 despite the prior
project memory entry; the two are closely related but the testbed hardware
is X710) was chosen because it is the cheapest 10 GbE part with full XDP
native-mode support, AF_XDP zero-copy, hardware flow director (ntuple
steering), and a stable upstream kernel driver. It is the same NIC family
exercised by the upstream kernel BPF flow-dissector selftests.

### Asymmetric RAM — convention

Both hosts have DDR4 with all four DIMM slots populated (dual-channel,
fully stuffed). The difference is **capacity and clock**, not channel
count:

| Host | DIMMs | Configured speed |
|---|---|---|
| hp2 | 4× 8 GiB  (32 GiB installed) | 2133 MT/s |
| hp5 | 4× 16 GiB (64 GiB installed) | 1866 MT/s |

For packet-processing benchmarks at the working-set sizes we exercise
(PCAPs in MiBs, metadata structs in hundreds of bytes), **RAM capacity
is irrelevant** — nothing spills to swap, page cache fits easily on
either host. Memory *bandwidth* is the axis that could matter, and
hp2's faster clock gives it the edge there.

As a workload-routing convention: use `hp5` when you want large
generated PCAP corpora or in-memory result aggregation to fit
comfortably, use `hp2` when you want the fastest memory clock. Both
hosts can run any test; this is not a capability constraint.

*Earlier docs labeled hp5 the "throughput target" on the basis of RAM
size. That framing turned out to be baseless — a 2026-04-20 matrix
run showed hp5 ~20 % faster across all 5 usable ways, but hp5 is also
the host with the slower RAM clock, so the delta is run-to-run noise
at the 11-packet × 10-iteration micro-benchmark scale, not a host-class
difference. See [`samples/flow_dissector/docs/benchmarks.md`](../samples/flow_dissector/docs/benchmarks.md)
§ "Physical-Testbed 6-Way Matrix (2026-04-20)".*

---

## 3. Network topology

```
                ┌──────────────────────────────────────────┐
                │   1 GbE management LAN (Realtek eno1)    │
                │     (SSH, package fetch, monitoring)     │
                └─────────────┬─────────────┬──────────────┘
                              │             │
                          eno1│             │eno1
                       ┌──────┴───┐     ┌───┴──────┐
                       │   hp2    │     │   hp5    │
                       │ Ryzen 5  │     │ Ryzen 5  │
                       │  30 GB   │     │  61 GB   │
                       └───┬──┬───┘     └───┬──┬───┘
              enp1s0f0np0  │  │ enp1s0f1np1 │  │  enp1s0f1np1
                           │  │             │  │
                           │  └──fibre──────┘  │
                           │   (10 GbE SR)     │
                           └──────fibre────────┘
                              (10 GbE SR)
                            enp1s0f0np0 ↔ enp1s0f0np0
```

**Key facts about the data-plane links:**

- Two parallel back-to-back 10 GbE links between `hp2` and `hp5`.
- `f0 ↔ f0` and `f1 ↔ f1` is the **assumed** cable mapping; verify with
  `ethtool -p enp1s0f0np0 5` (LED blink test) before trusting it.
- The two links allow splitting control-plane traffic from data-plane,
  testing `XDP_REDIRECT` between physical interfaces, or LACP bonding
  for ≥ 10 Gb/s aggregate measurements.
- MTU is **1500 by default** for parser correctness comparability with
  upstream kernel selftests. Jumbo (9000) is opt-in via
  `xdp2.testbed.jumbo = true;` for pure-throughput perf runs.
- Static addressing recommended: `10.10.0.{2,5}/29` on `f0`,
  `10.10.1.{2,5}/29` on `f1`. **`/29`, not `/30`** — `.2` and `.5` fall in
  different `/30` subnets (`.0/30` = `.0–.3`, `.4/30` = `.4–.7`), so under
  a `/30` mask the reply path falls through to the default route and
  leaves via the management NIC (see Appendix A §10 for the diagnosis).
  `/29` covers `.0–.7` so both `.2` and `.5` are directly reachable.

### Interface naming

The actual interface names on both hosts are
**`enp1s0f0np0`** and **`enp1s0f1np1`** (verify with `ip -br link`).
Older host configs reference `enp3s0f0` / `enp3s0f1`, which were the names
when the NIC was in a different PCIe slot. **Any tuning that hardcodes
those legacy names is silent dead code today.** The new NixOS module
(see §6) takes interface names as parameters so this can't drift again.

---

## 4. Software baseline

| Field | hp2 | hp5 |
| --- | --- | --- |
| NixOS channel | `nixos-25.11` (stable) | `nixos-unstable` |
| `system.stateVersion` | `24.05` | `24.11` |
| Kernel | 6.18.21 (NixOS-built) | 6.18.21 (NixOS-built) |
| libbpf | 1.x (provided by nixpkgs) | 1.x |
| Nix | flakes + `nix-command` enabled | same |

**Recommendation**: pick one channel and converge both hosts on it.
Diverging stable/unstable means the matrix can compare two slightly
different libbpf or kernel point releases, which makes ns-scale results
non-comparable. Stable is the safe default; unstable only if you need a
specific upstream fix not yet backported.

---

## 5. Access (SSH)

Root SSH via ed25519 key is already configured on both hosts. The relevant
NixOS settings (in `~/nixos/hp/{hp2,hp5}/sshd-INSECURE.nix`) are:

```nix
services.openssh = {
  enable = true;
  settings.PermitRootLogin = "prohibit-password";
};
users.users.root.openssh.authorizedKeys.keys = [
  "ssh-ed25519 AAAA… das@t"
];
```

The `INSECURE` filename is historical and refers to the policy of permitting
root login over SSH — not to any CVE. The hosts are reachable only on the
internal management LAN, never the public internet.

### Recommended `~/.ssh/config` entry

```
Host hp2
  HostName hp2.lan
  User root
  IdentityFile ~/.ssh/id_ed25519

Host hp5
  HostName hp5.lan
  User root
  IdentityFile ~/.ssh/id_ed25519
```

After this, `ssh root@hp2`, `rsync -avz ./ hp2:./xdp2/`, and the automation
wrapper in §10 all just work.

### Why root, not a sudo user

`BPF_PROG_TEST_RUN`, attaching XDP programs, ethtool ring/queue rewrites,
IRQ affinity changes, and `nix copy --to ssh-ng://…` all require
combinations of `CAP_BPF`, `CAP_NET_ADMIN`, and `CAP_SYS_ADMIN`. A dedicated
benchmark host has no other user accounts to worry about, so direct root
keeps the wrapper simple (no `sudo -n` plumbing, no NOPASSWD policy).

---

## 6. The xdp2-shipped NixOS module

The repository ships a NixOS module at
[`nix/modules/physical-testbed.nix`](../nix/modules/physical-testbed.nix)
that applies the tuning described in §7. The module is exposed as
`nixosModules.physical-testbed` from the flake.

### How a host imports it

In `~/nixos/hp/hp5/flake.nix`, add `xdp2` as an input:

```nix
{
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
  inputs.xdp2.url = "github:randomizedcoder/xdp2";

  outputs = { self, nixpkgs, xdp2, ... }: {
    nixosConfigurations.hp5 = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        xdp2.nixosModules.physical-testbed
        ./configuration.nix
      ];
    };
  };
}
```

Then in `~/nixos/hp/hp5/configuration.nix`:

```nix
{
  xdp2.testbed = {
    enable = true;

    # Real interface names — see §3 for why this matters.
    peerInterfaces = [ "enp1s0f0np0" "enp1s0f1np1" ];

    addresses = {
      enp1s0f0np0 = { local = "10.10.0.5/29"; peer = "10.10.0.2"; };
      enp1s0f1np1 = { local = "10.10.1.5/29"; peer = "10.10.1.2"; };
    };

    # Pin CPUs 2..7 for benchmarks; leave 0,1 for housekeeping (kernel
    # threads, ssh, nix-daemon).
    isolatedCpus = [ 2 3 4 5 6 7 ];

    hugepages2M = 512;   # 1 GiB total
    jumbo = false;       # set true for pure-throughput sweeps
    gro = false;         # GRO/LRO/TSO/GSO off for parser reproducibility
  };
}
```

`hp2` is identical except its `addresses.*.local` fields end in `.2/29`.

### Opt-in options for the live ntuple + template bench

Two options wire the hardware-classification path documented in
[`docs/ntuple-template-bench.md`](ntuple-template-bench.md):

```nix
xdp2.testbed = {
  # …standard tuning above…

  # Program Intel i40e Flow Director rules at boot so the NIC steers
  # matching 5-tuples to dedicated RX queues. Each list-index is the
  # ethtool location slot (idempotent on re-apply). Up to 8K rules on
  # X710. Verify with: ssh root@hp5 'ethtool -n enp1s0f0np0'.
  flowDirectorRules = [
    { interface = "enp1s0f0np0"; flowType = "tcp4"; destPort = 22;  queue = 1; }
    { interface = "enp1s0f0np0"; flowType = "tcp4"; destPort = 443; queue = 2; }
  ];

  # Re-enable nginx (:443, snake-oil cert, 1-byte index) + add
  # wrk2/h2load to systemPackages. Nginx is force-pinned to CPUs 0,1
  # via systemd CPUAffinity so it never competes with parser threads
  # on isolated cores. Overrides disableNonEssentialServices for
  # nginx specifically; grafana/prometheus/lldpd remain off.
  realServicesBench = true;
};
```

Both options default to "disabled" (`[]` and `false`), so existing
hp2/hp5 configs that don't opt in keep behaving exactly as before.
The ntuple+template bench in category I (§9) won't work until both
are set.

### What this module deliberately does *not* do

- It does **not** disable services like `docker` or `kubernetes`. Those are
  workload-specific cleanups that a replicator may or may not want; see §8
  for the `hp2`-specific cleanup that is needed today.
- It does **not** install your SSH keys or set up users. Those live in
  per-host config.
- It does **not** auto-detect interface names — by design, since silent
  auto-detection is exactly what produced the historical `enp3s0f0` drift
  problem. You name your NICs explicitly.

---

## 7. Tuning applied by the module

Each tuning below is documented as **What / Why / Trade-off** so you can
selectively override it in your `xdp2.testbed.*` settings if your workload
needs different behaviour.

### Kernel command-line

| Param | Why | Trade-off |
| --- | --- | --- |
| `mitigations=off` | Spectre/Meltdown mitigations add ~10-20% latency to syscall-heavy paths and ~5% to BPF JIT. | **Insecure** — only on a single-purpose host with no untrusted code. |
| `intel_pstate=disable` (no-op on AMD) | Future-proofing for if the testbed gains an Intel host. | None on AMD. |
| `processor.max_cstate=1` | Disables deep C-states; CPUs stay in C0/C1 so wakeup latency is < 1 µs. | Idle power draw +30-50 W per host. |
| `nohz_full=2-7` | Stops the scheduler tick on isolated CPUs when they run a single task. Removes ~1 µs/ms periodic jitter. | Isolated CPUs cannot be used by general kernel work. |
| `rcu_nocbs=2-7` | Offloads RCU callbacks off isolated CPUs. | Slight overhead on housekeeping CPUs. |
| `isolcpus=2-7` | Removes isolated CPUs from the general scheduler. Benchmark threads must explicitly bind via `taskset`. | Forgetting to bind = no work runs there. |
| `default_hugepagesz=2M hugepages=512` | 1 GiB of 2 MiB hugepages reserved at boot for AF_XDP UMEM and DPDK-style ring allocations. | RAM permanently reserved. |
| `transparent_hugepage=never` | THP defragmentation introduces unpredictable stalls. | Slightly higher TLB pressure. |
| `audit=0` | Disables kernel audit subsystem (saves ~100 ns per syscall). | Lose audit logs (irrelevant on a benchmark host). |

### sysctls

```nix
boot.kernel.sysctl = {
  "kernel.perf_event_paranoid" = 0;          # for nix run .#perf-*
  "kernel.sched_rt_runtime_us" = -1;         # let RT threads run uncapped
  "net.core.bpf_jit_enable" = 1;
  "net.core.bpf_jit_harden" = 0;             # benchmark host only
  "net.core.busy_poll" = 50;                 # 50 µs busy-poll
  "net.core.busy_read" = 50;
  "net.core.netdev_max_backlog" = 50000;
};
```

### Services

- `services.irqbalance.enable = false;` — the module pins IRQs explicitly.
- `powerManagement.cpuFreqGovernor = "performance";` — pin governor.
- `systemd.services.xdp2-nic-tune-${ifname}` — per-NIC `ethtool` setup
  (rings 4096 rx/tx, combined queues = `length isolatedCpus`, GRO/LRO/TSO
  off unless `gro = true`, flow-control off, flow-director enabled).
- `systemd.services.xdp2-nic-affinity-${ifname}` — parses
  `/proc/interrupts`, maps each `${ifname}-TxRx-N` IRQ to
  `isolatedCpus[N % length isolatedCpus]`, and writes both
  `/proc/irq/N/smp_affinity` and the device's `affinity_hint`.

### Networking

- Static IPv4 on each peer interface (replaces today's accidental
  link-local fallback).
- MTU 9000 if `xdp2.testbed.jumbo = true;`, else 1500.

### Tools

`environment.systemPackages` adds `ethtool`, `bpftools` (note: nixpkgs
attribute is `bpftools`, plural — the binary it installs is `bpftool`),
and
`linuxPackages.perf` matched to the running kernel. **This fixes a real
bug**: the existing `systemd.services.ethtool-enp3s0f{0,1}.nix` units on
both hosts try to call `ethtool` but the binary is not in PATH, so they
fail silently in addition to targeting wrong interface names.

---

## 8. Manual one-time fixes (not in the module)

These are workload-specific cleanups the operator should apply on top of
importing the module.

### hp2 only — remove incidental container workloads

`hp2` currently runs a docker daemon, a `br-gdp` bridge, and a
`vethb664dbd` interface from a previous workload. For a dedicated
benchmark host these introduce CPU steal, kernel softirq noise, and
unpredictable network state. Remove with:

```nix
# in ~/nixos/hp/hp2/configuration.nix
services.docker.enable = false;
virtualisation.containers.enable = false;
networking.bridges = lib.mkForce {};
```

Then `nixos-rebuild switch` and `ip link delete br-gdp` (or just reboot).

### Verify cable mapping

The diagram in §3 assumes `f0↔f0, f1↔f1`. If the rack tech crossed the
links, your tests will pass anyway but with surprising latency asymmetry.
Verify once after install:

```bash
ssh root@hp5 'ethtool -p enp1s0f0np0 10' &
# walk to the rack, watch which port LED on hp2 blinks
```

If wires are crossed, just swap the addresses in
`xdp2.testbed.addresses` so the IPs match the physical wiring.

### Converge nixpkgs channels

See §4. Set both hosts to the same `inputs.nixpkgs.url` and rebuild.

---

## 9. Test catalog and per-test recipes

The xdp2 repo exposes ~40 Nix flake outputs that are candidates for
remote execution. They group as follows. Privilege column means the
*minimum* needed; root works for everything.

| # | Category | Nix targets | Privilege | Needs peer link? | Best host | Output | Wall |
| --- | --- | --- | --- | --- | --- | --- | --- |
| A | xdp2-rs cargo tests | `xdp2-rs-test`, `xdp2-rs-test-graph-enum`, `xdp2-rs-clippy`, `xdp2-rs-fmt-check`, `xdp2-rs-doc`, `xdp2-rs-golden`, `xdp2-rs-adversarial`, `xdp2-rs-stress` | none | no | either | stdout, `result/` log files | ~5 min |
| B | flow-dissector matrix ways 1–3 | `flow-dissector-matrix` (userspace ways) | none | no | either | stdout table | ~2 min |
| C | flow-dissector matrix ways 4–6 | `flow-dissector-matrix` (BPF ways via `BPF_PROG_TEST_RUN`) | root + `CAP_BPF` | no | either | stdout table | ~10 min |
| D | proto-audit | `proto-audit-report`, `proto-audit-c-check`, `proto-audit-validate-all` | none | no | either | `result/*.{txt,json}` | ~15 min |
| E | perf sweeps | `perf-sweep-tcp`, `perf-sweep-mixed`, `perf-sweep-combo`, `perf-flamegraph`, `perf-annotate`, `perf-graph-enum-compare`, `chain-histogram-all`, `chain-histogram-workloads`, `sweep-workloads-all`, `perf-analysis-all` | `perf_event_paranoid≤2` | no | either (hp5 for larger result corpora) | `result/perf-results/…` | 30–60 min |
| F | XDP samples (load) | `xdp-samples` plus loader-side smoke tests | root + `CAP_NET_ADMIN` | **yes** | hp5 receives | future work | 5 min ea. |
| G | AF_XDP throughput | `xdp2-flow-ebpf` loader against real traffic | root | **yes** | hp5 receives | future work | varies |
| H | Hardware ntuple offload | `flow-dissector-ntuple-template-bench` | root + `CAP_NET_ADMIN` | **yes** | hp5 receives | `perf-results/${host}/ntuple-template-bench-*/` | ~2 min |
| I | Unified xdp2-rs vs C matrix | `flow-dissector-matrix-unified` | none (usp) / root (BPF ways 4–6) | no | either | stdout 10-row table | ~2 min |

### Manual recipes

```bash
# Category A — full Rust suite, no NIC needed
ssh root@hp5 'cd ~/xdp2 && nix build .#xdp2-rs-test --print-build-logs'

# Category C — root for BPF_PROG_TEST_RUN
ssh root@hp5 'cd ~/xdp2 && nix run .#flow-dissector-matrix'

# Category D — proto-audit full report
ssh root@hp5 'cd ~/xdp2 && nix build .#proto-audit-report'

# Category E — overnight perf sweep on hp5
ssh root@hp5 'cd ~/xdp2 && nix run .#perf-analysis-all'

# Pull results back
rsync -avz hp5:~/xdp2/result/ ./perf-results/hp5/perf-analysis-all/
```

The automation wrapper in §10 reduces all of the above to a single
`nix run .#run-on-host -- HOSTS… -- TARGETS…` command and handles result
collection automatically.

### Categories F–H (real-NIC tests)

Category H (hardware ntuple offload) landed as the
`flow-dissector-ntuple-template-bench` Nix target — see
[`docs/ntuple-template-bench.md`](ntuple-template-bench.md) for the
design rationale and
[`samples/flow_dissector/docs/benchmarks.md`](../samples/flow_dissector/docs/benchmarks.md)
for the "Live Ntuple + Template" section where results are recorded.
Prerequisite: target host sets `xdp2.testbed.flowDirectorRules` and
`xdp2.testbed.realServicesBench = true` (see §6 above).

#### Category H live progress (2026-04-24, hp2 → hp5)

The orchestrator graduated past "smoke test" this session. The
end-to-end path is now: kernel pktgen on hp2 (peer) → 10 GbE fibre →
X710 i40e Flow Director (UDP/443 → queue 1) on hp5 (target) →
**native XDP** program (`xdpdrv`, not `xdpgeneric`) → **AF_XDP
zero-copy** socket → `xdp2-bench --mode af-xdp-template` dispatching
through `EthIpv4Udp` with no software classification.

Wiring confirmations baked into the orchestrator (verified live):

- `XDP_MODE=xdpdrv (native — i40e ndo_bpf path)` printed at attach
  time; falls back to `xdpgeneric` only if native attach fails.
- `ip link show enp1s0f0np0` reports `xdp` (native), not `xdpgeneric`.
- `AF_XDP: busy-poll enabled (50us timeout)` printed at bind time
  via the `--busy-poll` CLI flag.
- `--zero-copy` and `--need-wakeup` are passed to `xdp2-bench` by
  default; flip with `ZEROCOPY=0` / `NEED_WAKEUP=0` env vars to A/B.

Measured throughput, sweep across packet size and pktgen thread count:

| Run | Pkt size | pktgen threads | Sent (Mpkts/30s) | Received (Mpkts) | Mpps RX | ns/pkt | Bottleneck |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Baseline (`xdpgeneric` + copy mode) | 1400 B | 2 | 28.4 | 19.7 | 0.66 | 1524 | 10 GbE line rate |
| `xdpdrv` + ZC + busy-poll | 1400 B | 2 | 28.0 | 19.5 | 0.65 | 1541 | 10 GbE line rate |
| `xdpdrv` + ZC + busy-poll | 64 B | 4 | 44.4 | 41.2 | 1.37 | 727 | pktgen TX cap (~1.48 Mpps) |
| `xdpdrv` + ZC + busy-poll | 64 B | 6 | 44.5 | 41.0 | 1.37 | 732 | pktgen TX cap, unchanged |

Read this table carefully: the 1500-ns figure in the first two rows is
**not a parser cost** — it is `1 / Mpps × 10⁹` while we are at 10 GbE
line rate for 1418-byte frames (≈ 880 kpps theoretical max). The
parser is finishing every packet inside that interval; we just
cannot drive packets across the wire faster. Going to 64-byte
frames lifts the bandwidth ceiling but immediately exposes the next
ceiling: hp2's kernel pktgen tops out at ~1.48 Mpps total regardless
of thread count, even with `clone_skb 100000` already configured.
Per-thread output of ~250 kpps is well below what kernel pktgen
should produce on a Xeon-class host, so this is its own bug to
chase, not a parser limit. We have not measured the parser-only
ceiling yet; doing so requires either fixing the pktgen TX cap on
hp2 or driving load with DPDK / a userspace generator. See §13.

Receiver behaviour at 1.37 Mpps RX showed ~7.8% drops (sent 44.5M,
received 41.0M). That is **not** the line-rate ceiling — it is the
receiver dropping packets that pktgen managed to actually emit. The
RX-side drop is unwelcome and will be diagnosed in a follow-up: top
suspects are RX ring depth, NAPI budget, or `XDP_USE_NEED_WAKEUP`
handling under bursty arrival. We've documented it rather than
hiding it because the diagnosis is the testbed's value-add.

A run produces these artifacts under
`perf-results/${host}/ntuple-template-bench-${ts}/`:

- `ntuple-rules.txt` — `ethtool -n` snapshot proving the FD rule was
  in place when the bench started.
- `xdp2-bench-af-xdp-template.txt` — the per-queue Mpps / ns/pkt
  table, including the "AF_XDP: busy-poll enabled" / "registered in
  XSKMAP" wiring lines so future-you can confirm the fast path.
- `pktgen-start.log` / `pktgen-final-status.log` — TX-side counters
  per thread, the input to "is the receiver dropping or is pktgen
  not even sending?" diagnosis.

#### Per-experiment matrix (Deliverables 1, 2, 3)

The two ceilings exposed in the table above (pktgen TX cap, RX-side
drop) and the absence of a userspace generator alternative each have
their own row of `xdp2-exp-*` Nix targets. Each target is a
shellchecked `writeShellApplication` produced by the
`mkBenchExperiment` factory at
[`nix/lib/mkBenchExperiment.nix`](../nix/lib/mkBenchExperiment.nix).
A run lands in
`perf-results/${target}/exp-${shortname}-${ts}/` with `run.log`,
`summary.json`, and `SUMMARY.md`. `summary.json` carries the
hypothesis + expectation strings as provenance — the doc is the
**lab notebook**, summary.json is the regression-friendly machine
copy.

Operator workflow:

```bash
# Re-run any single experiment
nix run .#xdp2-exp-pktgen-baseline -- hp5 hp2

# List every experiment exposed by the flake
nix flake show 2>&1 | grep -E '^ +├── xdp2-exp-'
```

| Tier | Target | Tunable difference vs baseline | Expected |
| --- | --- | --- | --- |
| D1 (pktgen TX cap) | `xdp2-exp-pktgen-baseline` | none — regression check | Reproduces the 1.37 Mpps/64B baseline within noise |
| D1 | `xdp2-exp-pktgen-burst-32` | `PKTGEN_BURST=32` | TX ≥ 3 Mpps if softirq-per-packet dominates |
| D1 | `xdp2-exp-pktgen-queue-map` | + `PKTGEN_QUEUE_MAP_MODE=per-thread` | TX ≥ 6 Mpps if TX-ring contention dominates |
| D1 | `xdp2-exp-pktgen-cpu-pin` | + `PKTGEN_CPU_PIN_MODE=isolcpus-aligned` | Marginal (≤5%) gain or jitter cut |
| D1 | `xdp2-exp-pktgen-cloneskb-zero` | `PKTGEN_CLONE_SKB=0` | Regression vs baseline iff skb reuse is load-bearing |
| D2 (DPDK alt) | `xdp2-exp-dpdk-baseline` | swap to DPDK pktgen on peer (vfio-pci) | TX ≥ 5 Mpps if i40e PMD supports it |
| D2 | `xdp2-exp-dpdk-multi-lcore` | + `PKTGEN_DPDK_LCORES=0@0,1@1,2@2,3@3,4@4` | TX approaches 40 GbE line rate at 64B |
| D3 (RX drop) | `xdp2-exp-afxdp-rings-baseline` | none — regression check | Reproduces the ~7.8% drop% baseline |
| D3 | `xdp2-exp-afxdp-rings-large` | `RX_RING=4096 FILL_RING=4096 FRAME_COUNT=16384` | Drop → 0% if fill-ring depth is the limit |
| D3 | `xdp2-exp-afxdp-busypoll-100` | `BUSY_POLL_US=100` | Modest drop reduction if NAPI gap is the limit |
| D3 | `xdp2-exp-afxdp-netdev-budget` | host-side `net.core.netdev_budget=600` | Modest drop reduction if softirq budget is the limit |

Result columns (Mpps / ns/pkt / drop%) are filled in from
`summary.json` after each run. Today the **Expected** column is
load-bearing — every experiment ships with a hypothesis and a
kill-criterion so a "did not lift the ceiling" outcome is itself a
publishable result, not a build failure.

D1 kill-criterion: if all five D1 experiments leave TX ≤ 2 Mpps,
hp2's kernel-pktgen-on-i40e is at a genuine kernel ceiling and the
investigation pivots to D2. D2 kill-criterion: if DPDK pktgen also
fails to exceed tuned kernel pktgen, write up the result — that is
itself useful (PCIe / IOMMU / firmware ceiling). D3 kill-criterion:
if all four leave drop ≥ 3%, the bottleneck is below
instrumentation today (PCIe BW, IOMMU TLB, X710 firmware buffer
caps).

Pre-flight for D2: hp2 (peer) must be running NixOS with
`xdp2.testbed.dpdkBenchHost = true` — the
[`physical-testbed`](../nix/modules/physical-testbed.nix) module
loads `vfio-pci`, sets `iommu=pt intel_iommu=on` on the kernel
cmdline, and reserves 1024×2 MiB hugepages. The orchestrator's
trap-driven cleanup restores the i40e driver after each run, but
the kernel-cmdline / module bits must be in place before the first
DPDK experiment can run.

Pre-flight for D3 `netdev-budget`: hp5 (target) must already have
been rebuilt against the C4 module change (new `mkDefault` sysctl
`net.core.netdev_budget = 600`); without that the experiment sees
the kernel default of 300 and reports a baseline-equivalent number.

Categories F (XDP samples) and G (AF_XDP throughput) remain future
work; the pieces are in place:

- The X710 NIC supports XDP native mode and AF_XDP zero-copy with the
  i40e driver in 6.18.21 — verified live above.
- `xdp2-flow-loader` from the `xdp2-flow-ebpf` bundle attaches the BPF
  program to a named ifname (`-i enp1s0f0np0`) and reads RX queues.
- `iperf3` / `pktgen` / a custom traffic generator on the peer host
  drives load across the fibre.

### Category I (unified xdp2-rs vs C matrix)

`flow-dissector-matrix-unified` runs the 6-way C matrix AND the four
xdp2-rs modes (graph / mono / compiled / template) against the same
filtered pcap and emits one 10-row comparison table. Default pcap is
the cached `workload-pcap-https-web` derivation (20k packets). See
the "Unified xdp2-rs vs C-Matrix" section of
[`samples/flow_dissector/docs/benchmarks.md`](../samples/flow_dissector/docs/benchmarks.md)
for the measurement model; no host-side configuration is required.

---

## 10. Automation wrapper (`nix run .#run-on-host`)

The repo exposes a `writeShellApplication` named `xdp2-run-on-host`
(source: [`nix/physical-testbed-runner.nix`](../nix/physical-testbed-runner.nix))
that wraps the rsync + ssh + `nix run` + result-pull cycle.

### CLI shape

```
nix run .#run-on-host -- HOST [HOST...] -- TARGET [TARGET...]
```

The `--` separator distinguishes hosts from targets. Examples:

```bash
# Smoke test on hp5
nix run .#run-on-host -- hp5 -- xdp2-rs-test

# PR gate: cargo + matrix + audit on hp5
nix run .#run-on-host -- hp5 -- xdp2-rs-test flow-dissector-matrix proto-audit-report

# Same suite on both hosts in parallel
nix run .#run-on-host -- hp2 hp5 -- xdp2-rs-test flow-dissector-matrix

# Overnight perf on hp5
nix run .#run-on-host -- hp5 -- perf-analysis-all
```

### Behaviour per (host, target) pair

1. `rsync -avz --delete --exclude=result --exclude=perf-results/ --exclude=.git/ --exclude=target/ ./ ${host}:~/xdp2/`
2. Detect whether the target is a runnable app (`nix run`) or a buildable
   package (`nix build`); BPF targets that need root do not need `sudo`
   because we ssh in as root.
3. Capture wall time and exit code.
4. `rsync -az ${host}:~/xdp2/result/ ./perf-results/${host}/${target}-${ISO8601}/`
5. Append one row to a stdout summary table.

### Failure semantics

A non-zero exit on any (host, target) pair sets the wrapper's overall exit
to 1 but does not abort siblings. This matches the CI use-case where you
want to see *all* failing tests in one report instead of stopping at the
first one.

### Parallelism

Hosts run in parallel (one ssh session per host). Targets within a host
run sequentially because they may contend for `/sys/fs/bpf`, the kernel
BPF JIT cache, and shared `result/` symlinks.

### Example summary output

```
HOST    TARGET                    WALL     EXIT  RESULT
hp5     xdp2-rs-test              4m12s    0     perf-results/hp5/xdp2-rs-test-2026-04-20T19:42:11+00:00/
hp5     flow-dissector-matrix     8m45s    0     perf-results/hp5/flow-dissector-matrix-2026-04-20T19:46:23+00:00/
hp5     proto-audit-report        12m03s   0     perf-results/hp5/proto-audit-report-2026-04-20T19:55:08+00:00/
hp2     xdp2-rs-test              4m31s    0     perf-results/hp2/xdp2-rs-test-2026-04-20T19:42:11+00:00/
```

---

## 11. Result collection

Results are collected back to the developer machine under
`perf-results/${host}/${target}-${ISO8601-timestamp}/`. The directory
mirrors the structure of the `result/` symlink that the corresponding
Nix build produced on the host:

```
perf-results/
├── hp2/
│   ├── xdp2-rs-test-2026-04-20T19:42:11+00:00/
│   │   ├── test.log
│   │   └── summary.txt
│   └── flow-dissector-matrix-2026-04-20T19:43:55+00:00/
│       └── matrix-output.txt
└── hp5/
    ├── perf-sweep-tcp-2026-04-20T20:11:08+00:00/
    │   └── perf-results/tcp_ipv4/...
    └── proto-audit-report-2026-04-20T20:18:30+00:00/
        ├── audit.json
        ├── matrix.json
        └── findings.json
```

The wrapper also writes `perf-results/INDEX.json` with one entry per
(host, target, timestamp) for downstream tooling. A future
`.#testbed-index` target (see §13) will render this as a Markdown
dashboard listing the most recent run per pair.

`perf-results/` is gitignored (it already is) — these are local
artifacts, not committed history.

---

## 12. Replicating in your own environment

### Minimum hardware

- Two x86_64 (or aarch64) hosts, ≥ 4 cores each.
- One `i40e`, `ice`, `mlx5`, or `igc` NIC per host (XDP native mode +
  AF_XDP zero-copy support is the requirement; see
  <https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md>
  for capability matrix).
- One direct cable between them (fibre or DAC for 10 GbE+, twisted pair
  for 1 GbE — slower link is fine for everything except categories E/G/H).

### Software baseline

- NixOS ≥ 24.11 (any channel; converge both hosts on the same one).
- Kernel ≥ 6.6 (for AF_XDP zero-copy stability).
- `nix.settings.experimental-features = [ "nix-command" "flakes" ];`
- Root SSH via key.

### Five-step recipe

1. Add this repo as a flake input on both hosts:
   ```nix
   inputs.xdp2.url = "github:randomizedcoder/xdp2";
   ```
2. Import the module:
   ```nix
   imports = [ inputs.xdp2.nixosModules.physical-testbed ];
   ```
3. Set `xdp2.testbed = { … };` per §6 — your interface names, your
   addresses, your isolated CPU set.
4. `nixos-rebuild switch --flake .#${hostname}` on each host.
5. From your developer workstation, clone xdp2 and:
   ```bash
   nix run .#run-on-host -- ${host1} ${host2} -- xdp2-rs-test
   ```

### Non-NixOS environments

The module is NixOS-specific, but every option maps to a documented
sysctl / kernel command-line / ethtool flag / systemd unit. Annex A in
the module source lists the equivalent commands for Ubuntu 24.04
(`/etc/default/grub`, `tuned-adm profile network-latency`, ethtool
shell scripts, `set_irq_affinity` from the Mellanox tooling). The
automation wrapper (§10) is plain bash and works against any Linux host
with rsync + ssh + nix.

---

## 13. Future work

The testbed is the precondition; the items below are tracked separately
and lean on the testbed once they land.

- **GitHub Actions self-hosted runner** registered against the developer
  workstation, running `.#run-on-host` against both hosts on every push
  to `main`. PR gate.
- **AF_XDP throughput suite** (category G in §9). Wraps
  `xdp2-flow-loader` + `pktgen` (or a Rust traffic generator) into a
  Nix target that returns `{ pps, bps, drops }` JSON.
- **Diagnose hp2 kernel pktgen TX cap** (~1.48 Mpps total regardless
  of thread count, despite `clone_skb 100000`). **Status: wired.**
  Five Nix experiment targets `xdp2-exp-pktgen-{baseline,burst-32,
  queue-map,cpu-pin,cloneskb-zero}` each twist one tunable
  (`PKTGEN_BURST`, `PKTGEN_QUEUE_MAP_MODE`, `PKTGEN_CPU_PIN_MODE`,
  `PKTGEN_CLONE_SKB`) and emit a comparable `summary.json`. See §9
  Category H per-experiment matrix for hypotheses + kill-criterion;
  required before category H can claim a parser ceiling number
  rather than a generator ceiling number.
- **DPDK / userspace traffic generator alternative.** **Status:
  wired.** Two Nix experiment targets `xdp2-exp-dpdk-{baseline,
  multi-lcore}` swap the peer-side generator for DPDK pktgen via
  vfio-pci. The target side stays on i40e + Flow Director + AF_XDP
  unchanged — only the peer's NIC is rebound. Pre-flight: hp2 must
  have `xdp2.testbed.dpdkBenchHost = true`. See §9 Category H
  per-experiment matrix.
- **Investigate the RX-side ~7.8% drop at 1.37 Mpps** observed in
  the category H table. **Status: wired.** Four Nix experiment
  targets `xdp2-exp-afxdp-{rings-baseline,rings-large,busypoll-100,
  netdev-budget}` each isolate one candidate (fill-ring depth,
  busy-poll budget, NAPI budget). The CLI overrides
  `--rx-ring-size` / `--fill-ring-size` / `--frame-count` are
  available on `xdp2-bench` for ad-hoc tuning outside the
  experiment harness too.
- **Hardware ntuple offload tests** (category H). Verifies that
  `ethtool -N enp1s0f0np0 flow-type tcp4 …` rules survive, fire on the
  expected packets, and route to the correct RX queue.
- **`xdp2-rs cargo test` coverage for the loader** (currently the
  loader is built but not exercised end-to-end against real packets).
- **`.#testbed-index`** target that renders `perf-results/INDEX.json` as
  a Markdown dashboard.
- **Per-run delta renderer**: diff the latest `perf-results/${host}/${target}-*`
  against the previous one, flagging regressions ≥ 5%.
- **Converge `~/nixos/hp/{hp2,hp5}/` channels** (see §4) so the testbed
  is reproducible bit-for-bit between hosts.

---

## Appendix A — Known issues and gotchas

1. **Interface-name drift** (`enp3s0f0` vs `enp1s0f0np0`). The legacy
   `~/nixos/hp/{hp2,hp5}/systemd.services.ethtool-enp3s0f{0,1}.nix`
   units target nonexistent interfaces and are silent dead code today.
   The new module sidesteps this by taking interface names as
   parameters. Delete or update those legacy `.nix` files when you
   apply the module.

2. **`ethtool` not in `$PATH`**. The legacy units assume `ethtool` is
   available; on a stock NixOS install it is not. The new module adds
   `ethtool`, `bpftools`, and `perf` to `environment.systemPackages`.

3. **hp2 runs incidental docker workload**. Visible as a `br-gdp`
   bridge and `vethb664dbd` interface in `ip -br link`. See §8.

4. **Channels diverged**. `hp2` is on stable (`nixos-25.11`), `hp5` is
   on unstable. The matrix can compare across slightly different
   libbpf 1.x point releases — converge before drawing ns-scale
   conclusions.

5. **Cable mapping unverified**. §3 assumes `f0↔f0, f1↔f1`. Verify
   with `ethtool -p` blink test before relying on it.

6. **`nix copy` could replace rsync** but rsync is simpler, well-known,
   and survives store-mismatch issues (e.g. one host on stable, the
   other on unstable). Rsync chosen for that reason.

7. **`mitigations=off` is insecure**. The module enables it because
   benchmark hosts run no untrusted code. Do not set this on a
   multi-tenant or internet-facing host.

8. **Asymmetric RAM** (hp2 4×8 GiB @ 2133 MT/s / hp5 4×16 GiB @ 1866 MT/s).
   Both dual-channel fully populated. hp5 has more headroom for large
   in-memory PCAP corpora; hp2 has the faster memory clock. For the
   workload sizes the matrix currently exercises (MiBs, not GiBs),
   neither difference is load-bearing — see § 2 "Asymmetric RAM".

9. **Kernel pktgen on hp2 caps at ~1.48 Mpps regardless of thread
   count** (measured 2026-04-24, see §9 Category H live progress).
   With 64-byte UDP packets, `clone_skb 100000`, and `delay 0`,
   total TX is ~1.48 Mpps whether you set `THREADS=2`, `4`, or `6`.
   Per-thread output of ~250 kpps is well below what kernel pktgen
   should produce on this CPU class — likely NIC TX-ring contention
   or kpktgend per-thread CPU pinning. Until this is fixed, category
   H numbers reflect a *generator* ceiling, not a parser ceiling.
   Diagnosis is now wired as the D1 / D2 experiment scripts (see §9
   Category H per-experiment matrix); §13 Future work flags those
   `xdp2-exp-*` targets by name.

10. **`xdpgeneric` vs `xdpdrv` attach mode is silent.** The
    `ip link set dev <iface> xdp pinned ...` form picks whichever
    mode the kernel can attach without telling you which it picked.
    The category H orchestrator now explicitly tries
    `xdpdrv` first, falls back to `xdpgeneric` only if native attach
    fails, and prints `XDP_MODE=xdpdrv` (or `xdpgeneric (FALLBACK)`)
    so the test log shows what actually happened. **Important
    consequence:** AF_XDP `XDP_ZEROCOPY` only works under native
    attach — if you set the flag while the program is in
    `xdpgeneric` mode the kernel silently falls back to copy mode
    and you measure copy-mode performance under what you think is
    a zerocopy bind. Always verify post-attach via `ip link show
    <iface>` (look for the `xdp/id` flag, *not* `xdpgeneric/id`).
    Related: the RX-side ~7.8% drop seen at 1.37 Mpps with native
    XDP + ZC + busy-poll is being chased through the D3 experiment
    matrix in §9 Category H — fill-ring depth, busy-poll budget,
    and `net.core.netdev_budget` are each isolated by one
    `xdp2-exp-afxdp-*` target.

9. **Lab L3 unicast was broken 2026-04-22 — resolved same day (root cause:
   `/30` mask too tight for `.2`/`.5` address pair; fixed by switching to
   `/29`).** Kept here because the diagnostic trail is a useful reference
   for any future "L2 works, L3 doesn't" class of failure on the testbed:

   - `ping 10.10.0.5` from hp2 → 100% loss. Same for `10.10.1.5`, and
     the reverse direction. TCP/443 and TCP/22 time out similarly.
   - L1 healthy: `ethtool enp1s0f{0,1}np*` reports `Speed: 10000Mb/s`,
     `Link detected: yes` on all four ports.
   - L2 healthy: `arping -I enp1s0f0np0 10.10.0.5` from hp2 returns
     ~0.6 ms reply. LLDP frames cross both cables in both directions.
   - L3 blocked specifically for IPv4 unicast: hp2's
     `ethtool -S enp1s0f0np0` shows `tx_unicast: 2` and
     `tx_multicast: 130` after the test run — the kernel increments
     the ping "transmitted" counter but `tcpdump -i enp1s0f0np0 icmp`
     captures zero ICMP on either the sender's own NIC or the
     receiver's NIC. ARP and LLDP multicast frames from the same NIC
     are captured fine on both sides.
   - Not the firewall: `nft list ruleset` empty on both, iptables
     also empty, `networking.firewall.enable = false` in firewall.nix.
   - Not the ntuple rules: toggling `ethtool -K enp1s0f0np0 ntuple off`
     on both hosts does not restore connectivity.
   - Not stale BPF: `bpftool net show` reports no xdp / tc /
     flow_dissector / netfilter hooks on either host.
   - Not a link glitch: `ip link set enp1s0f0np0 down && up` on both
     sides does not restore connectivity either.

   **LLDP recipe for cable-topology verification** (proves which
   physical port connects to which peer port — useful whenever this
   class of issue reappears):

   ```bash
   # lldpd binary ships with the testbed hosts but its systemd unit is
   # stripped by disableNonEssentialServices. Create the privsep
   # user+group and start the daemon restricted to the lab interfaces;
   # stop it afterwards so the perf-noise profile is preserved.

   for H in hp2 hp5; do
     ssh root@$H 'getent group _lldpd >/dev/null || groupadd -r _lldpd
       id _lldpd           >/dev/null 2>&1 || useradd -r -g _lldpd \
                                                -s /usr/sbin/nologin _lldpd
       lldpd -I enp1s0f0np0,enp1s0f1np1'
   done

   sleep 10   # one LLDP TX interval

   for H in hp2 hp5; do
     echo "=== $H ==="
     ssh root@$H 'lldpcli show neighbors summary'
   done

   # When done, stop the daemon on both hosts:
   for H in hp2 hp5; do ssh root@$H 'pkill -TERM lldpd'; done
   ```

   On a correctly cabled back-to-back testbed you should see:
   ```
   Interface: enp1s0f0np0 ... SysName: <peer host>, PortDescr: enp1s0f0np0
   Interface: enp1s0f1np1 ... SysName: <peer host>, PortDescr: enp1s0f1np1
   ```
   On 2026-04-22 this check confirmed the cables are correct end-to-end
   (hp2:f0 ↔ hp5:f0, hp2:f1 ↔ hp5:f1). The i40e firmware ALSO emits its
   own LLDP frames (OUI 00:80:C2, 802.1 port-extender sub-TLVs); these
   can be silenced with
   `ethtool --set-priv-flags <ifc> disable-fw-lldp on` but are
   harmless for topology verification.

   **Implication for live-traffic benches.** Until the L3 unicast
   drop is diagnosed and fixed, every test that needs real packets on
   the lab link — `flow-dissector-ntuple-template-bench`,
   `flow-dissector-matrix` live runs against iperf/wrk2, and anything
   that depends on reachability between 10.10.0.2 ↔ 10.10.0.5 — will
   report zero packets. The xdp2-rs-side work (AF_XDP binding, FD
   rules applied, bench orchestrator wiring, per-queue template
   extraction) has been verified to work end-to-end; it just needs
   packets to count. PCAP-replay-style tests that don't need L3 work
   fine.

   **Root cause (resolved 2026-04-22).** It was **not** the cables, the
   NICs, the kernel, the firewall, ntuple, or any BPF hook. It was
   plain IP subnet arithmetic: `/30` is too tight for the addresses
   we picked.

   - `/30` allocates 4 addresses. Network `10.10.0.0/30` covers
     `.0, .1, .2, .3` (with `.0` = network, `.3` = broadcast,
     usable = `.1, .2`). Network `10.10.0.4/30` covers `.4, .5, .6, .7`
     (usable = `.5, .6`).
   - `hp2 = 10.10.0.2/30` lands in `10.10.0.0/30`. `hp5 = 10.10.0.5/30`
     lands in `10.10.0.4/30`. They are **not in the same subnet** — a
     routing-table impossibility the kernel exposes via
     `ip route get 10.10.0.2` on hp5: the lookup falls through to the
     default route and returns `via 172.16.40.1 dev eno1`.
   - L2 worked because ARP is a broadcast protocol that ignores IP
     subnets. Cable-forced ping (`ping -I enp1s0f0np0 10.10.0.5`)
     also worked on the *request* path because `-I` bypasses route
     lookup. hp5's reply path did an unconstrained route lookup and
     sent the ICMP echo reply out `eno1` toward the management
     gateway, which silently black-holed it.
   - Identical bug on the `f1` cable (`10.10.1.2/30` vs
     `10.10.1.5/30`). The bug was symmetric: hp2→hp5 lost replies
     exactly the same way hp5→hp2 did.

   **Fix:** change the mask from `/30` to `/29` on both hosts, both
   interfaces. `/29` covers `.0–.7`, so `.2` and `.5` share a subnet
   and the reply path stays on the lab NIC. The example config in
   §5 and the `addresses.local` option default in the NixOS module
   now specify `/29`. Live verification after the change:
   `ping -c 3 10.10.0.5` from hp2 returned 3/3, 0.12 ms RTT.

   **Why this wasn't caught earlier.** Prior matrix runs against
   pre-captured PCAPs don't exercise the lab-link path — the parser
   reads packets from disk. Only the live-traffic benches
   (`flow-dissector-ntuple-template-bench` and any future iperf/wrk2
   drivers) hit this. Lesson: include a bidirectional-ping smoke test
   as a pre-flight in the live-traffic harness. Small follow-up to
   `samples/flow_dissector/run_ntuple_template_bench.sh`.

---

## Appendix B — One-line cheatsheet

```bash
# Smoke
nix run .#run-on-host -- hp5 -- xdp2-rs-test

# PR gate (~25 min)
nix run .#run-on-host -- hp5 -- \
    xdp2-rs-test flow-dissector-matrix proto-audit-report

# Both hosts, parallel
nix run .#run-on-host -- hp2 hp5 -- xdp2-rs-test flow-dissector-matrix

# Overnight perf
nix run .#run-on-host -- hp5 -- perf-analysis-all

# Manual probe
ssh root@hp5 'ip -br link; ethtool enp1s0f0np0 | grep Speed'

# Rebuild after changing host config
ssh root@hp5 'cd /etc/nixos && nixos-rebuild switch --flake .#hp5'
```
