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
5. [Access (SSH)](#5-access-ssh) — includes [Updating a host's NixOS configuration](#updating-a-hosts-nixos-configuration)
6. [The xdp2-shipped NixOS module](#6-the-xdp2-shipped-nixos-module)
7. [Tuning applied by the module](#7-tuning-applied-by-the-module)
8. [Manual one-time fixes](#8-manual-one-time-fixes)
9. [Test catalog and per-test recipes](#9-test-catalog-and-per-test-recipes)
10. [Automation wrapper (`nix run .#run-on-host`)](#10-automation-wrapper-nix-run-run-on-host)
11. [Result collection](#11-result-collection)
12. [Replicating in your own environment](#12-replicating-in-your-own-environment)
13. [Future work](#13-future-work)
14. [Second testbed pair (hp1 ↔ hp3, mlx5_core 25 GbE)](#14-second-testbed-pair-hp1--hp3-mlx5_core-25-gbe)
15. [IPv6 testbed addresses (ULA)](#15-ipv6-testbed-addresses-ula)
16. [Standalone Intel data point (chromebox1, Haswell-ULT)](#16-standalone-intel-data-point-chromebox1-haswell-ult)
17. [High-end Intel data point (t, Comet Lake-H)](#17-high-end-intel-data-point-t-comet-lake-h)
18. [ARM testbed pair (pi5-1 ↔ pi5-2, BCM2712 Cortex-A76, 1 GbE switched)](#18-arm-testbed-pair-pi5-1--pi5-2-bcm2712-cortex-a76-1-gbe-switched)
19. [Standalone ARM Cortex-A72 data point (pi4-1, BCM2711)](#19-standalone-arm-cortex-a72-data-point-pi4-1-bcm2711)
20. [Standalone ARM Cortex-A53 data point (pi3-1, BCM2837)](#20-standalone-arm-cortex-a53-data-point-pi3-1-bcm2837)
21. [x86 testbed pair (l ↔ l2, ConnectX-4 Lx 25 GbE back-to-back)](#21-x86-testbed-pair-l--l2-connectx-4-lx-25-gbe-back-to-back)
22. [RISC-V testbed pair (pi5-1 → bpi-f3, SpacemiT K1, 1 GbE switched)](#22-risc-v-testbed-pair-pi5-1--bpi-f3-spacemit-k1-1-gbe-switched)

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
| Storage | Kioxia KBG40ZNV256G 256 GB NVMe | Samsung MZHPV512HDGL 512 GB M.2 SSD |

**Live verification (run from your laptop, requires SSH access — see §5):**

```bash
ssh root@hp2 lscpu | grep 'Model name'
ssh root@hp5 free -g
ssh root@hp2 lspci | grep -i ethernet
```

### Storage — hp5 upgrade (2026-04-26)

hp5's storage was upgraded to a **Samsung MZHPV512HDGL 512 GB M.2 SSD**
(partitioned as 1 GB EFI `/boot`, 408 GB ext4 `/`, 68 GB swap). With
372 GB available on `/` (as of the fresh rebuild), hp5 can comfortably
host full Nix store builds (fat LTO of xdp2-rs, proto-audit, etc.)
without running out of space. This removes the earlier constraint of
pre-building on the dev box and rsyncing binaries — `nix build` and
`nix develop` can run directly on hp5.

hp2 has a **Kioxia KBG40ZNV256G 256 GB NVMe** (512 MB EFI `/boot`,
205 GB ext4 `/`, 33 GB swap). With 128 GB available (63 GB used by
existing Nix store), hp2 is tighter — fat LTO builds of xdp2-rs may
require periodic `nix-collect-garbage` to stay under budget. For
build-heavy workflows, prefer hp5.

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
                       │ 256G NVMe│     │ 512G SSD │
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
| NixOS version | 26.05.20260422 | 26.05.20260422 |
| Kernel | 7.0.1 (NixOS-built) | 7.0.1 (NixOS-built) |
| libbpf | 1.x (provided by nixpkgs) | 1.x |
| Nix | flakes + `nix-command` enabled | same |

**Status (2026-04-26):** Both hosts now run the same NixOS version
(26.05.20260418) and kernel (7.0.0). The earlier channel divergence
(hp2 stable, hp5 unstable) has been resolved — both are on
`nixos-unstable` after the storage upgrade and rebuild cycle. This
makes ns-scale benchmark results directly comparable across hosts.

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

### Updating a host's NixOS configuration

The NixOS configurations for both testbed hosts live on the developer
workstation ("l") at:

```
~/nixos/hp/hp2/   — hp2's NixOS flake (configuration.nix, flake.nix, etc.)
~/nixos/hp/hp5/   — hp5's NixOS flake
```

Each directory has a `Makefile` that drives the workflow. The full
update cycle for a host (e.g. hp5) is:

```bash
# 1. Edit the config on the dev box
cd ~/nixos/hp/hp5
vim configuration.nix               # make your changes

# 2. Sync the config to the target host
make sync                            # rsync to hp5:~/nixos/hp/hp5/

# 3. SSH into the target
ssh hp5
cd ~/nixos/hp/hp5

# 4. (Optional) Update flake inputs — pulls latest nixpkgs + xdp2
make update                          # runs: sudo nix flake update

# 5. Rebuild and apply
make                                 # runs: sudo nixos-rebuild switch --flake .
```

**Important:** If the rebuild reports a `switchInhibitors` failure (e.g.
a `dbus-implementation` change), use `nixos-rebuild boot` instead and
then reboot:

```bash
sudo nixos-rebuild boot --flake .
sudo reboot
```

The `switch` path tries to live-migrate running services into the new
configuration; changes to core system services (dbus, systemd, etc.)
cannot be migrated safely and require a reboot.

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
`perf` (top-level nixpkgs attr since 26.05; previously
`config.boot.kernelPackages.perf`). **This fixes a real
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

##### Live results (2026-04-25, hp2 → hp5)

| Target | ts | Sent | RX | Drop% | ns/pkt | Mpps | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `xdp2-exp-pktgen-baseline` | 20260425T131605 | 44.42 M | 41.15 M | 7.38% | 729 | 1.37 | Regression check passed: matches the 1.37 Mpps / 727 ns/pkt / 7.84% drop documented in the live-progress table within run-to-run noise. The `mkBenchExperiment` wrapper introduces no measurement perturbation. `summary.json` at `perf-results/hp5/exp-pktgen-baseline-20260425T131605/`. |
| `xdp2-exp-pktgen-baseline` | 20260425T133523 | 44.48 M | 41.15 M | 7.48% | 729 | 1.37 | Re-run, identical config. Mpps + ns/pkt match prior run to two-decimal precision; drop% varied 0.10 pp. Confirms the baseline is reproducible — future experiment deltas are signal, not jitter. `summary.json` at `perf-results/hp5/exp-pktgen-baseline-20260425T133523/`. |
| `xdp2-exp-pktgen-burst-32` | 20260425T135212 | 133.79 M | 124.17 M | 7.19% | 241 | **4.14** | **Hypothesis (1) confirmed.** `PKTGEN_BURST=32` alone lifted RX 1.37 → 4.14 Mpps (3.02×) with a single env var; ns/pkt 729 → 241. The "1.48 Mpps pktgen TX cap" we documented in §9 Category H live progress was an artifact of pktgen's default `burst=1`, not a kernel-pktgen-on-i40e ceiling. Drop% stayed flat at ~7%, meaning the RX-side drop is proportional to TX rate (steady-state fill-ring/refill latency), not an absolute capacity wall — D3's `xdp2-exp-afxdp-rings-large` is the right next probe. `summary.json` at `perf-results/hp5/exp-pktgen-burst-32-20260425T135212/`. |
| `xdp2-exp-pktgen-queue-map` | 20260425T140125 | 431.81 M | 220.20 M | 49.00% | 136 | **7.34** | **Hypothesis (2) confirmed; bottleneck has crossed the wire.** Adding per-thread `queue_map_min/max` (each kpktgend owns its own X710 TX ring) on top of `BURST=32` pushed pktgen TX to 431.8 M/30s = **14.39 Mpps — essentially 10 GbE line rate at 64-byte frames** (theoretical max 14.88 Mpps for 64B+24B preamble/IFG/FCS overhead). RX rose 4.14 → 7.34 Mpps (1.77×), ns/pkt 241 → 136. **D1 has answered its question:** kernel pktgen on hp2 is *not* the parser-measurement bottleneck once `burst` and `queue_map` are set. The new 49% drop is purely receiver-side (line rate arriving, half drained) and the right next probe is D3 `xdp2-exp-afxdp-rings-large` — fill-ring depth at line rate, exactly hypothesis (1) of D3. ns/pkt=136 is still inverted-rate, not parser cost; the parser is keeping up at this budget. `summary.json` at `perf-results/hp5/exp-pktgen-queue-map-20260425T140125/`. |
| `xdp2-exp-pktgen-cpu-pin` | 20260425T161354 | 266.35 M | 149.69 M | 43.80% | 200 | 4.99 | **Hypothesis (3) refuted on this config.** Plan expected "marginal (≤5%) gain or jitter cut"; actual was a **−32% regression** vs queue-map (7.34 → 4.99 Mpps). Plausible cause: hp2's CPUs 2-7 are `isolcpus + nohz_full + rcu_nocbs`, and `nohz_full` disables the periodic tick on a CPU running only one task — kernel pktgen's softirq-driven TX path benefits from the tick, so pinning kpktgend onto the fully-isolated cores hurt rather than helped. The default kpktgend_0..5 placement on housekeeping CPUs 0-1 + isolated 2-5 happened to be the better mix. Real lab-notebook negative result: `cpu-pin` is not free when `isolcpus + nohz_full` overlap with where pktgen wants to live. **Also surfaced a driver bug:** switching `PKTGEN_CPU_PIN_MODE` between runs leaves stale device entries owned by the previous mode's thread set; the script's `rem_device_all` loop only walks the current mode's threads. Workaround: `modprobe -r pktgen && modprobe pktgen` on the peer between mode switches; permanent fix would be to walk *all* `/proc/net/pktgen/kpktgend_*` on cleanup. `summary.json` at `perf-results/hp5/exp-pktgen-cpu-pin-20260425T161354/`. |
| `xdp2-exp-pktgen-cloneskb-zero` | 20260425T162513 | 40.92 M | 37.98 M | 7.20% | 789 | 1.27 | **Hypothesis (4) weakly confirmed.** With `CLONE_SKB=0` and otherwise-default tunables (no burst, no queue_map), RX dropped 1.37 → 1.27 Mpps (−7%) and ns/pkt rose 729 → 789. So skb reuse *does* help — but only marginally. With default `burst=1` the softirq-dispatch cost dominates, swamping any skb-alloc savings; clone_skb is load-bearing in a small way. Drop% essentially flat (7.20% vs 7.48%) confirms the receiver-side characteristic is steady-state at this rate regardless of skb reuse. `summary.json` at `perf-results/hp5/exp-pktgen-cloneskb-zero-20260425T162513/`. |

**D1 finding (all five experiments complete):** kernel pktgen on hp2
reaches **10 GbE line rate (~14.4 Mpps TX)** at 64-byte frames with
`PKTGEN_BURST=32` + per-thread `queue_map_min/max` — burst-fix
delivers most of the lift (3.02×), per-thread queues delivers the
rest (1.77× on top). `cpu-pin` regressed because of an
`isolcpus + nohz_full` interaction; `clone_skb` is a marginal
nice-to-have. **Conclusion: kernel pktgen is no longer the
parser-measurement bottleneck on hp2 once the right two env vars are
set.** D2 (DPDK pktgen alternative) is therefore retained as a
documented option, not the production path — the conditional plan
outcome where "if `burst`+`queue_map` lifts kernel pktgen above the
parser's ceiling, we don't need DPDK". The remaining bottleneck is
receiver-side: AF_XDP currently drains 7.34 Mpps of the 14.4 Mpps
arriving (49% drop), which is exactly the question D3 was written to
answer.

Subsequent experiments will append rows to this table as they
land. Each row's `summary.json` carries the hypothesis +
expectation strings as provenance so later readers can attribute a
number to the exact tunable difference that produced it.

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

## 14. Second testbed pair (hp1 ↔ hp3, mlx5_core 25 GbE)

A second physical testbed pair was racked alongside hp2/hp5: **hp1**
and **hp3**, each fitted with a **Mellanox ConnectX-4 Lx 25 GbE** NIC,
connected back-to-back over two DAC cables (`f0 ↔ f0`, `f1 ↔ f1` —
same topology as hp2/hp5, see §3). Hostnames, role assignment, and
NixOS layout mirror the first pair so the same automation runs
against both.

| | hp2 / hp5 (pair #1) | hp1 / hp3 (pair #2) |
| --- | --- | --- |
| CPU | AMD Ryzen 5 PRO 2400G (Zen 1, 4c/8t) | AMD Ryzen 5 PRO 2400G (Zen 1, 4c/8t) |
| RAM | hp2 30 GiB / hp5 62 GiB | hp1 30 GiB / hp3 62 GiB |
| NIC | Intel X710 10 GbE SFP+ fibre | Mellanox MT27710 ConnectX-4 Lx 25 GbE DAC |
| Driver | `i40e` | `mlx5_core` |
| Flow steering | ethtool ntuple (Flow Director) | tc-flower (see `nix/modules/nic-tuning.nix` § mlx5_core) |
| Data-plane subnets | `10.10.0.0/29` + `10.10.1.0/29` | `10.10.2.0/29` + `10.10.3.0/29` |
| Generator / DUT | hp2 (gen) ↔ hp5 (dut) | hp1 (gen) ↔ hp3 (dut) |
| Testbed config | [`testbeds/hp2-hp5-x710.toml`](../testbeds/hp2-hp5-x710.toml) | [`testbeds/hp1-hp3-mlx5.toml`](../testbeds/hp1-hp3-mlx5.toml) |
| Host config | `~/nixos/hp/hp{2,5}/` | `~/nixos/hp/hp{1,3}/` |

By symmetry, hp3 is the "big-RAM dut" on pair #2 (analogous to hp5 on
pair #1) and hp1 is the generator (analogous to hp2). Workload-routing
heuristics from §2 apply identically: if you want extra headroom for
generated PCAP corpora or in-memory result aggregation, drive the run
on hp3.

Both pairs are driven through the same orchestrator:

```bash
# Pair #1 (i40e):
nix run .#run-on-host -- --testbed testbeds/hp2-hp5-x710.toml -- flow-dissector-matrix-unified

# Pair #2 (mlx5_core):
nix run .#run-on-host -- --testbed testbeds/hp1-hp3-mlx5.toml -- flow-dissector-matrix-unified
```

The `xdp2.nicTuning.driver` option (forwarded automatically by
`xdp2.testbed`) selects the per-driver ethtool/IRQ-affinity branch.
On pair #2's hosts the config sets `driver = "mlx5_core"`; everything
else (CPU isolation, hugepages, kernel cmdline, sshd policy, sysctls)
is identical to pair #1.

### Verified live state (2026-05-24)

Both hosts running NixOS 26.05.20260523 / kernel 7.0.9. Kernel cmdline
on each carries `isolcpus=2-7 nohz_full=2-7 rcu_nocbs=2-7 mitigations=off
processor.max_cstate=1 hugepages=1024 default_hugepagesz=2M
transparent_hugepage=never audit=0`. All four
`xdp2-nic-{tune,affinity}-enp1s0f{0,1}np{0,1}.service` units exit
`active (exited)` against the mlx5_core branch.

Data-plane state at bring-up:

| Interface | hp1 | hp3 | Link | RTT (steady) |
| --- | --- | --- | --- | --- |
| `enp1s0f0np0` (`f0 ↔ f0`) | `10.10.2.1/29` | `10.10.2.3/29` | 25 Gb/s full | ~60 µs |
| `enp1s0f1np1` (`f1 ↔ f1`) | `10.10.3.1/29` | `10.10.3.3/29` | 25 Gb/s full | ~60 µs |

Both directions on both links pass `ping -c 3` with 0% loss. The first
ICMP per (src, dst) pair is ~0.3-0.4 ms (ARP resolution); subsequent
pings settle around 50-100 µs — the expected latency profile for a
direct DAC link on mlx5 hardware.

### Bringing up a fresh hp1/hp3 install

A freshly-installed NixOS host has no `flake.lock` and
`experimental-features` is empty in `/etc/nix/nix.conf`. The hp3
Makefile (and copy at `~/nixos/hp/hp1/Makefile` for symmetry) ships
three bootstrap targets that work around this:

- `make bootstrap_update` — runs `nix flake update` with the
  `--extra-experimental-features 'nix-command flakes'` flag inline so
  the lockfile resolves without needing flakes enabled system-wide.
- `make bootstrap` — runs `nixos-rebuild boot --option
  experimental-features 'nix-command flakes' --flake .#<host>` and
  reminds the operator to `sudo reboot`. Uses `boot` (not `switch`)
  because the kernel cmdline changes (`isolcpus`, `mitigations=off`,
  `hugepages`, `nohz_full`, `rcu_nocbs`) only take effect on the next
  boot. Pins the configuration name explicitly because on a fresh
  install the hostname is still `nixos`, not `hp1`/`hp3`, so the
  hostname-lookup form `--flake .` won't find the right entry.
- `make bootstrap_switch` — `switch` variant of the above, for the
  case where you've already booted into the new kernel once.

Once the first bootstrap rebuild lands and the NixOS-managed
`/etc/nix/nix.conf` carries `experimental-features = [ "nix-command"
"flakes" ]`, plain `make` / `make update` work for all subsequent
rebuilds.

### Outstanding follow-up

- Flow Director rules in `xdp2.testbed.flowDirectorRules` are empty
  on hp1/hp3 today. When the ntuple+template bench (category H in §9)
  is brought up on the mlx5 pair, add the same UDP/443 → queue 1 rule
  pattern used on hp2/hp5; the mlx5_core branch translates it to a
  tc-flower filter automatically.

---

## 15. IPv6 testbed addresses (ULA)

Both testbed pairs carry IPv6 alongside IPv4 on the back-to-back
interfaces. We use IPv6 ULA (RFC 4193, `fd00::/8` private prefix)
addressed deterministically so the layout is mnemonic and survives
reboot.

### Layout convention

`fd10:10:N::M/64` where:

- `N` matches the v4 third octet (`0` and `1` for the hp2-hp5 pair;
  `2` and `3` for the hp1-hp3 pair)
- `M` matches the v4 host octet (`.2`/`.5` on pair 1; `.1`/`.3` on
  pair 2)

This makes the v6 address derivable from the v4 address at a glance.

| pair | iface | host A | host B |
| --- | --- | --- | --- |
| hp2 ↔ hp5 (i40e 10 GbE) | `enp1s0f0np0` | hp2 `fd10:10:0::2/64` | hp5 `fd10:10:0::5/64` |
| hp2 ↔ hp5 | `enp1s0f1np1` | hp2 `fd10:10:1::2/64` | hp5 `fd10:10:1::5/64` |
| hp1 ↔ hp3 (mlx5 25 GbE) | `enp1s0f0np0` | hp1 `fd10:10:2::1/64` | hp3 `fd10:10:2::3/64` |
| hp1 ↔ hp3 | `enp1s0f1np1` | hp1 `fd10:10:3::1/64` | hp3 `fd10:10:3::3/64` |
| l ↔ l2 (mlx5 25 GbE) | `enp35s0f0np0` | l `fd10:10:4::2/64` | l2 `fd10:10:4::5/64` |
| l ↔ l2 | `enp35s0f1np1` | l `fd10:10:5::2/64` | l2 `fd10:10:5::5/64` |

The `/64` prefix is per-link (one link per cable). Each per-link
subnet is independent so adding a third pair later (or a third
interface on an existing pair) is a matter of picking the next
`N`.

### Where these are set

The IPv6 addresses are part of the NixOS `xdp2.testbed.addresses`
schema (see [`nix/modules/physical-testbed.nix`](../nix/modules/physical-testbed.nix)
for the option definition). Each host's
`~/nixos/hp/<hp>/configuration.nix` carries:

```nix
xdp2.testbed = {
  addresses = {
    enp1s0f0np0 = {
      local  = "10.10.0.5/29";     peer  = "10.10.0.2";
      local6 = "fd10:10:0::5/64";  peer6 = "fd10:10:0::2";
    };
    # ...
  };
};
```

The `local6` and `peer6` fields are optional (`nullable`); set both
to add IPv6 assignment, leave at default (`null`) to skip. The
module's `networking.interfaces` builder picks up `local6` and
emits an `ipv6.addresses = [ ... ]` entry alongside the v4 one.

### Verifying IPv6 is up

After `nixos-rebuild switch` on each host, confirm the addresses
are configured:

```bash
ssh root@hp5 'ip -6 addr show dev enp1s0f0np0 | grep fd10'
# inet6 fd10:10:0::5/64 scope global noprefixroute ...

ssh root@hp2 'ping -6 -c 3 fd10:10:0::5'
# 64 bytes from fd10:10:0::5: icmp_seq=1 ttl=64 time=...
```

### Why ULA (`fd00::/8`) and not link-local

Link-local addresses (`fe80::/10`) work fine for direct neighbour
discovery but require specifying the source interface in every
client invocation (`-6 -c fe80::xxx%enp1s0f0np0`). ULA addresses
route through the kernel's normal IPv6 forwarding logic, so test
clients like `iperf3 -6 -c fd10:10:0::5` work without per-call
interface annotation.

ULA also makes test-script generation simpler: the same `-c <v4>`
vs `-c <v6>` mode switch works with bare addresses, no escape
needed.

### Why per-link `/64`

IPv6 best practice is `/64` per L2 segment so SLAAC and ND work
correctly. Even though we don't use SLAAC here (addresses are
static), keeping the prefix size canonical avoids surprises if we
later add VLANs or run things like radvd for autoconfiguration.

The `/64` also gives plenty of room to add hosts to a pair if it
ever becomes a 3+ host segment (e.g. an out-of-band test
generator).

---

## 16. Standalone Intel data point (chromebox1, Haswell-ULT)

A third host was added to the fleet on 2026-06-02: **chromebox1**, a
Google "Panther" Chromebox running NixOS. It is **not** part of any
peer pair — it has no 10/25 GbE NIC and no DAC link — but it joins
the fleet as the **Intel-uarch data point** for cross-microarchitecture
comparison against the four AMD Zen 1 Ryzen hosts. Same NixOS module
treatment, same automation wrapper, just with the two NIC-bound
options (`peerInterfaces`, `flowDirectorRules`) and CPU isolation
disabled because the hardware can't support them.

### Hardware

| Field | chromebox1 |
| --- | --- |
| Chassis | Google "Panther" Chromebox |
| CPU | Intel Celeron 2955U **(Haswell-ULT, Family 6 Model 69)** |
| Cores / threads | 2 / 2 (1 thread per core, no SMT) |
| Base clock | 1.4 GHz (no turbo) |
| RAM | 16 GiB DDR3 |
| Storage | 1.9 TB SATA SSD (`/dev/sda`, LVM via disko) |
| NIC (mgmt) | Realtek RTL8111/8168 1 GbE (`enp1s0`, PCI `01:00.0`) |
| NIC (wifi) | Qualcomm Atheros AR9462 (`wlp2s0`, unused) |
| Mgmt IPv4 | 172.16.40.178 (DHCP) |

Live verification (run from your dev box, requires the root SSH key
landed by `sshd-INSECURE.nix`):

```bash
ssh root@chromebox1 'lscpu | grep "Model name"; free -g; lspci | grep -i ethernet'
```

### What chromebox1 can / cannot run

Driven from §9's category table:

| Category | Description | chromebox1 | Why |
| --- | --- | --- | --- |
| A | xdp2-rs cargo tests | ✅ | No NIC needed. |
| B | flow-dissector matrix userspace ways | ✅ | Pcap replay, no NIC. |
| C | flow-dissector matrix BPF_PROG_TEST_RUN ways | ✅ | Root only, no NIC. |
| D | proto-audit | ✅ | Stdlib only. |
| E | perf sweeps over cached PCAPs | ✅ | `perf_event_paranoid≤2` set by module. |
| F | XDP samples loaded against real traffic | ❌ | No peer 10 GbE+ link. |
| G | AF_XDP throughput | ❌ | No peer link, no zero-copy-capable NIC. |
| H | Hardware ntuple offload | ❌ | Realtek 1 GbE has no Flow Director / tc-flower offload worth measuring. |
| I | Unified xdp2-rs vs C matrix | ✅ | Pcap replay, no NIC. |

So chromebox1 covers six of nine categories — the same set as a
pcap-only run on hp2/hp5/hp1/hp3, with results comparable to the AMD
hosts on the same workloads.

### NixOS module deltas vs the hp pattern

The same `xdp2.nixosModules.physical-testbed` is imported. Two options
are forced empty on chromebox1 because of the 2-core / no-peer-link
hardware constraints:

```nix
# ~/nixos/chromebox/chromebox1/configuration.nix
xdp2.testbed = {
  enable = true;
  peerInterfaces = [ ];   # no data-plane NICs
  addresses = { };
  isolatedCpus = [ ];     # 2-core CPU — no room to dedicate any
  hugepages2M = 256;      # 512 MiB (vs 1024 = 2 GiB on the hp boxes)
  disableNonEssentialServices = true;
  lowJitter = false;
  managementInterface = "enp1s0";  # not "eno1" — see Realtek above
  flowDirectorRules = [ ];
  realServicesBench = false;
};
```

With both lists empty, the module compiles away:

- No `xdp2-nic-tune-*` / `xdp2-nic-affinity-*` systemd services
  generated (the `peerInterfaces = []` guard in `nic-tuning.nix`).
- No `isolcpus=` / `nohz_full=` / `rcu_nocbs=` kernel cmdline entries
  (the `isolatedCpus != []` guard in `physical-testbed.nix:333`).

The kernel cmdline still gets the noise-suppression bits, verified
post-boot:

```
processor.max_cstate=1 transparent_hugepage=never audit=0
default_hugepagesz=2M hugepagesz=2M hugepages=256 mitigations=off
```

`HugePages_Total: 256` (= 512 MiB) reserved at boot.

### Bringing up a fresh chromebox1

The `~/nixos/chromebox/chromebox1/Makefile` ships the same
`bootstrap` / `bootstrap_switch` / `bootstrap_update` targets as
the hp1/hp3 Makefiles — see §14 "Bringing up a fresh hp1/hp3
install" for the procedure; only the directory changes.

Post-boot smoke check:

```bash
ssh root@chromebox1 'hostname; uname -r; \
  tr " " "\n" < /proc/cmdline | grep -E "mitigations|hugepages|max_cstate"; \
  ip -br link'
```

### Why no testbed config TOML for chromebox1

`testbeds/hp1-hp3-mlx5.toml` and `testbeds/hp2-hp5-x710.toml` describe
**pairs** (one DUT + one generator). chromebox1 is a single host
running the no-NIC subset of category A/B/C/D/E/I, which has no
generator role and no `[nic]` block worth parameterising.

For ad-hoc runs use the positional host form of `nix run .#run-on-host`:

```bash
# Smoke
nix run .#run-on-host -- chromebox1 -- xdp2-rs-test

# Full pcap-bound matrix
nix run .#run-on-host -- chromebox1 -- flow-dissector-matrix proto-audit-report

# Cross-uarch comparison (Zen 1 vs Haswell on same workloads)
nix run .#run-on-host -- hp5 chromebox1 -- flow-dissector-matrix-unified
```

If we ever want a TOML form (e.g. to feed the testbed-config adapter
in `nix/modules/testbed-config-adapter.nix`), the loader's allowed
`cpu_uarch` set in `nix/testbed-config.nix` needs `"haswell"` added —
currently the validator only enumerates `skylake icelake icx
sapphirerapids` on the Intel side.

### Expected performance vs the hp boxes

Haswell-ULT @ 1.4 GHz with no turbo is roughly **3-4× slower** in
single-thread parser throughput than Zen 1 @ ~3.4 GHz. Treat
chromebox1's ns/pkt numbers as an Intel reference point, not a
direct apples-to-apples comparison — the value is in the
**uarch-specific deltas** (e.g. how each parser mode's performance
varies between Haswell and Zen 1), not the absolute numbers.

---

## 17. High-end Intel data point (t, Comet Lake-H)

A fourth host joined the fleet on 2026-06-04: **t**, a laptop with an
Intel Core i9-10885H. Like chromebox1, t is **not** part of any peer
pair — it has only WiFi, no wired ethernet — but it complements
chromebox1 by being a much higher-end Intel CPU, giving the fleet two
Intel data points at the opposite ends of the perf curve:

| | chromebox1 (entry-level Intel) | t (high-end Intel) |
| --- | --- | --- |
| CPU | Celeron 2955U (Haswell-ULT) | Core i9-10885H (Comet Lake-H) |
| Cores / threads | 2 / 2 (no SMT) | 8 / 16 (SMT) |
| Base clock | 1.4 GHz (no turbo) | 2.4 GHz |
| Max boost | 1.4 GHz | 5.3 GHz |
| L1d/L1i/L2/L3 per core | 32K / 32K / 256K / 2M | 32K / 32K / 256K / 16M |
| Generation | 2013 | 2020 |

Comet Lake-H is microarchitecturally a Skylake derivative (same core
IP, refined process node + higher binning); use `cpu_uarch = "skylake"`
in any future testbed TOML and add a comment noting it's actually
Comet Lake-H.

### Hardware

| Field | t |
| --- | --- |
| Chassis | laptop (no model recorded in this doc — see `~/nixos/laptops/t/` for the full hardware-configuration.nix) |
| CPU | Intel Core i9-10885H **(Comet Lake-H, Family 6 Model 165)** |
| Cores / threads | 8 / 16 (2 threads per core, SMT enabled) |
| Base / boost clock | 2.4 GHz / 5.3 GHz |
| RAM | ~31 GiB |
| Storage | 1 TB Toshiba KXG6AZNV1T02 NVMe SSD |
| GPU | Intel UHD Graphics (iGPU) + NVIDIA Quadro T2000 Mobile (dGPU — uninitialised on the bench profile; nouveau is blacklisted, nvidia driver is not loaded) |
| NIC (mgmt / only NIC) | Intel Comet Lake PCH CNVi WiFi (`wlp0s20f3`, PCI `00:14.3`) |
| Wired ethernet | **none** |
| Thunderbolt 3 | Intel JHL7540 Titan Ridge 4C 2018 (could host a future 10/25 GbE USB-C/TB adapter) |
| Mgmt IPv4 | 172.16.50.141 (DHCP over WiFi) |

Live verification:

```bash
ssh root@t 'lscpu | grep "Model name"; free -g; ip -br link'
```

### What t can / cannot run

Identical to chromebox1's category-coverage table (§16) since the
constraint is purely "no peer 10/25 GbE link": A/B/C/D/E/I ✅,
F/G/H ❌.

The added value vs chromebox1: t can run cargo test, the matrix
runners, and proto-audit **dramatically faster** thanks to 16
threads and 5.3 GHz boost. Benchmark workloads that exercise
parallelism (`flow-dissector-matrix` over a large pcap, perf sweeps,
the unified matrix's parallel cells) will lift the bottleneck off the
parser and onto memory bandwidth or BPF JIT throughput on t,
exposing different ratios than the 4c/8t hp boxes show.

t also fills the **second-vendor / Skylake-derivative** gap in the
fleet's uarch coverage. Concretely, the series 3 v1 RFC's Phase 3
microbench was extended to t on 2026-06-04 with this result:

| uarch | host | baseline ns/pkt | patched ns/pkt | speedup |
| --- | --- | ---: | ---: | ---: |
| Zen 2 | workstation (3945WX) | 12.44 | 6.56 | -47.3% |
| Skylake-deriv | **t (i9-10885H)** | **10.61** | **5.62** | **-47.0%** |
| Zen 1 | hp5 (2400G) | 20.50 | 20.53 | 0% (masked by timer floor) |

Comet Lake-H confirms the Zen 2 saving on an Intel CPU — the
same ~5 ns absolute reduction, indistinguishable percentage. The
Zen 1 "0%" result is now clearly identified as a clock_gettime
resolution-floor artefact rather than a uarch-specific no-op:
the ~5 ns saving Comet Lake-H exposes lies below Zen 1's
measurement band at p50. Details:
`perf-results/2026-06-04-series3-phase3-t/results.md`.

### NixOS module deltas vs the hp pattern

```nix
# ~/nixos/laptops/t/configuration.nix
xdp2.testbed = {
  enable = true;
  peerInterfaces = [ ];                # WiFi-only, no peer DAC link
  addresses = { };
  # 8c/16t Comet Lake-H. SMT layout (verified live via `lscpu
  # --extended`): CPU N and N+8 are siblings on phys core N.
  # Keep CPUs 0,1 for housekeeping (one thread each of phys cores 0,1);
  # isolate the other 14 logical CPUs (7 phys cores) for benchmarks.
  isolatedCpus = [ 2 3 4 5 6 7 8 9 10 11 12 13 14 15 ];
  hugepages2M = 1024;                  # 2 GiB — aligned with hp1/hp3/hp5
  disableNonEssentialServices = true;
  lowJitter = false;
  managementInterface = "wlp0s20f3";   # Intel CNVi WiFi, the only network path
  flowDirectorRules = [ ];
  realServicesBench = false;
};
```

Three deltas worth knowing:

1. **`isolatedCpus` is populated**, unlike chromebox1 where it's
   empty. The 8c/16t Comet Lake-H has plenty of cores to dedicate
   isolated ones to benchmarks while keeping housekeeping responsive
   on CPUs 0,1.
2. **`managementInterface = "wlp0s20f3"`** instead of `enp1s0`. Only
   matters under `lowJitter = true` (IRQ pinning); the bench profile
   keeps `lowJitter = false`.
3. **`boot.blacklistedKernelModules = [ "nouveau" ]`** in
   configuration.nix. The NVIDIA Quadro T2000 dGPU is physically
   present; nouveau would grab it. Blacklisting keeps the GPU
   uninitialised, which is what we want on a headless bench host
   (no display, no compositor).

The historic config had a full Hyprland (Wayland compositor) + NVIDIA
proprietary driver + OBS + libvirtd + docker + binfmt aarch64/riscv64
+ printing + pipewire desktop. All of that is dropped at the imports
level (kept on disk for git history). Reverting to a usable laptop
means restoring the relevant `.nix` files in `imports` — see the file
list documented in configuration.nix's header.

### Verified live state (2026-06-04 first bootstrap)

```
hostname: t
kernel:   7.0.10
cmdline:  processor.max_cstate=1 transparent_hugepage=never audit=0
          default_hugepagesz=2M hugepagesz=2M hugepages=1024
          mitigations=off
          isolcpus=2,3,4,5,6,7,8,9,10,11,12,13,14,15
          nohz_full=2,3,4,5,6,7,8,9,10,11,12,13,14,15
          rcu_nocbs=2,3,4,5,6,7,8,9,10,11,12,13,14,15
isolated: 2-15
hugepages: HugePages_Total: 1024 (2 GiB reserved)
network:  wlp0s20f3 UP 172.16.50.141/24
xdp2:     no nic-tune-* / nic-affinity-* services (peerInterfaces=[])
```

### Bootstrap procedure

Same shape as chromebox1 / hp3, with the additional one-time
caveat that the WiFi-only network means `make sync` must complete
*after* the laptop is awake and on the lab WiFi. The
`~/nixos/laptops/t/Makefile` carries the `bootstrap` / `bootstrap_switch`
/ `bootstrap_update` targets — see §14 "Bringing up a fresh
hp1/hp3 install" for the procedure; only the directory changes.

NetworkManager remains enabled across the bench-profile rebuild
because WiFi credentials live in
`/etc/NetworkManager/system-connections/` (stateful), so they
survive the rebuild without re-entry. **Critical:** do NOT disable
NetworkManager on this host — it's the only network path.

### Why no testbed config TOML for t

Same reason as chromebox1 (§16): single host, no generator role,
no `[nic]` block worth parameterising for a WiFi-only host. For
ad-hoc runs use the positional host form of `nix run .#run-on-host`:

```bash
# Smoke
nix run .#run-on-host -- t -- xdp2-rs-test

# Cross-Intel (Haswell vs Comet Lake) on the same pcap-bound matrix
nix run .#run-on-host -- chromebox1 t -- flow-dissector-matrix proto-audit-report

# Full cross-uarch (Zen 1 + Haswell + Comet Lake)
nix run .#run-on-host -- hp5 chromebox1 t -- flow-dissector-matrix-unified
```

### Expected performance vs the rest of the fleet

Comet Lake-H @ 5.3 GHz boost should be roughly **1.5–2× faster** in
single-thread parser throughput than Zen 1 @ ~3.4 GHz (Ryzen 5 PRO
2400G), and roughly **10–15× faster** than chromebox1's Haswell
Celeron. With 16 threads vs hp's 8, parallel-friendly workloads
(matrix sweeps, perf-analysis-all) should also scale up
proportionally. Treat t's numbers as the modern-Intel reference
point; treat chromebox1's as the entry-Intel reference point. The
**uarch-specific deltas** between the three CPUs are the publishable
signal, not the absolute numbers.

---

## 18. ARM testbed pair (pi5-1 ↔ pi5-2, BCM2712 Cortex-A76, 1 GbE switched)

A fifth and sixth host joined the fleet on 2026-06-08: two
Raspberry Pi 5 boards running NixOS via the
[nixos-raspberrypi](https://github.com/nvmd/nixos-raspberrypi)
flake. They form a third pair in the testbed, with two important
differences from the hp pairs:

1. **ARM uarch (Broadcom BCM2712, 4× Cortex-A76 @ 2.4 GHz).** Third
   CPU vendor in the fleet alongside AMD (Zen 1, hp1-5) and Intel
   (Haswell, chromebox1; Comet Lake-H, t). Each Pi 5 is a 4-core
   no-SMT package — a much smaller compute envelope than the 4c/8t
   Zen 1 boxes, but a modern ARMv8 uarch with out-of-order execution
   and a 16K page size by default (set by the rpi-5.page-size-16k
   nixos-raspberrypi module).
2. **1 GbE switched, not back-to-back DAC.** Both Pi 5s connect to
   the same lab switch on `end0` at 1 GbE. There is no peer
   /29 carved for them — they reach each other via their
   regular lab IPs (172.16.40.122 ↔ 172.16.40.174). Test results
   that depend on switch-side scheduling (e.g. cake/fq pacing
   under load) carry that caveat versus the back-to-back hp
   pairs.

### Hardware

| Field | pi5-1 | pi5-2 |
| --- | --- | --- |
| Chassis | Raspberry Pi 5 SBC | Raspberry Pi 5 SBC |
| SoC | Broadcom BCM2712 | Broadcom BCM2712 |
| CPU | 4× ARM Cortex-A76 @ 2.4 GHz | 4× ARM Cortex-A76 @ 2.4 GHz |
| Cores / threads | 4 / 4 (no SMT) | 4 / 4 (no SMT) |
| Page size | 16 KiB (rpi-5.page-size-16k module) | 16 KiB |
| RAM | 8 GiB LPDDR4X | 8 GiB LPDDR4X |
| Boot storage | SD card (NIXOS_SD label) | SD card (NIXOS_SD label) |
| Build storage | **Kingston SNV2S1000G NVMe (1 TB)** | **Kingston SNV3S1000G NVMe (1 TB)** |
| NIC (end0) | onboard 1 GbE (BCM54213PE PHY) | onboard 1 GbE (BCM54213PE PHY) |
| MAC | `2c:cf:67:37:a1:b2` | `2c:cf:67:31:df:b7` |
| Mgmt IPv4 | 172.16.40.122 | 172.16.40.174 |

**NVMe state (2026-06-08):** both Pi 5s have the Kingston NVMe SSDs
physically attached via the Pi 5's PCIe 2.0 x1 lane (FPC), and the
drives appear as `/dev/nvme0n1`. They are **not currently mounted**
and `/nix/store` lives on the SD card. The NVMe drives are
planned to back `/nix` to make kernel builds tractable; until then,
on-host kernel builds (e.g. the series 3 patched kernel) are very
slow (multi-hour) on SD.

Live verification:

```bash
ssh root@pi5-1 'uname -r; lsblk -d | grep -E "mmc|nvme"; df -h /nix'
# Expected:
#   6.12.87
#   mmcblk0   119G   ...
#   nvme0n1   931.5G KINGSTON SNV2S1000G
#   /dev/mmcblk0p2  117G   3.5G  108G   4% /
```

### What pi5-1 / pi5-2 can / cannot run

Identical to hp1↔hp3 / hp2↔hp5 in terms of category coverage —
they have a peer link, so all categories work. The link
is 1 GbE rather than 10/25 GbE, so some absolute numbers in
the F/G/H categories (XDP / AF_XDP throughput, hardware ntuple
offload) will be link-limited rather than CPU-limited. But each
category exercises the code path correctly:

- A–E, I (single-host parsers and matrices): ✅
- F (XDP samples on real traffic): ✅ (1 GbE link)
- G (AF_XDP throughput): ✅ (1 GbE link)
- H (hardware ntuple offload): **N/A** — BCM54213PE PHY does not
  expose Flow Director / ethtool-ntuple steering. The category is
  skipped for this pair the same way chromebox1 and t skip it.

The added value vs the hp pairs: a **third CPU vendor** in the
A/B/C/D/E/I + F/G sweeps, with very different cache hierarchy
(64 KiB L1d per core, 512 KiB L2 per core, 2 MiB shared L3
vs the Zen 1 4×96 KiB / 4×512 KiB / 4 MiB hp pattern) and a
16 KiB page size. The `static_branch` / `jump_label` runtime
patching machinery the series 3 RFC depends on is arch-specific
code in `arch/arm64/kernel/jump_label.c` — exercising it on real
hardware is meaningful evidence the patches generalise beyond
x86.

### NixOS module deltas vs the hp pattern

The two Pi 5s use `nixos-raspberrypi`'s `raspberry-pi-5.base` +
`raspberry-pi-5.page-size-16k` modules rather than the
upstream `pkgs.linuxPackages_latest` used by hp* and t. The
kernel is the rpi-shipped `linux_rpi5` (currently 6.12.87) with
rpi-specific patches and the `bcm2712_defconfig`.

```nix
# ~/nixos/arm/pi5-1/configuration.nix (and pi5-2)
imports = with nixos-raspberrypi.nixosModules; [
  raspberry-pi-5.base
  raspberry-pi-5.page-size-16k
  ./il8n.nix
  ./sshd-INSECURE.nix
];

fileSystems."/" = {
  device = "/dev/disk/by-label/NIXOS_SD";
  fsType = "ext4";
  options = [ "noatime" ];
};
fileSystems."/boot/firmware" = {
  device = "/dev/disk/by-label/FIRMWARE";
  fsType = "vfat";
  options = [ "noatime" "noauto"
              "x-systemd.automount" "x-systemd.idle-timeout=1min" ];
};

boot.loader.raspberry-pi.bootloader = "kernel";
networking.hostName = "pi5-1";   # or "pi5-2"
networking.networkmanager.enable = false;
```

There is **no `xdp2.testbed` block** on either Pi 5 today —
neither the IRQ-affinity tuning nor the cmdline isolation
parameters from §6/§7 are applied. The lab kernel cmdline already
carries the rpi-baseline tuning (`pci=pcie_bus_safe`,
`coherent_pool=1M`, `numa=fake=8`, `system_heap.max_order=0`) via
the rpi module. Adding an `xdp2.testbed` block on the Pi 5s is a
follow-up if more aggressive tuning is needed for benchmark
runs.

### Why no testbed config TOML for this pair

Same reason as chromebox1 (§16) and t (§17): no `[nic]` block
worth parameterising yet, and the pair runs on the shared lab
switch rather than a back-to-back link. For ad-hoc runs use the
positional host form of `nix run .#run-on-host`:

```bash
# Smoke (parser on the Pi 5)
nix run .#run-on-host -- pi5-1 -- xdp2-rs-test

# Cross-uarch matrix (Zen 1 + Skylake-deriv + Cortex-A76)
nix run .#run-on-host -- hp5 t pi5-1 -- flow-dissector-matrix-unified
```

### Measured performance — series 3 A/B (2026-06-09)

| test | sysctl=0 | sysctl=1 | delta |
|---|---:|---:|---:|
| TCP -P 16 cake 1Gbit | 936.20 Mbit/s | 936.16 Mbit/s | ~0% (link sat) |
| TCP -P 16 fq_codel | 936.15 Mbit/s | 936.21 Mbit/s | ~0% |
| TCP -P 16 fq | 936.25 Mbit/s | 936.18 Mbit/s | ~0% |
| TCP -P 16 noqueue | 936.16 Mbit/s | 936.18 Mbit/s | ~0% |
| UDP -b 0 -l 64 -P 8 cake (N=3) | 162.8 Mbit/s mean | 153.8 Mbit/s mean | **-5.5%** |

TCP at wire rate saturates ~936 Mbit/s in both modes with 0
retransmits — **no regression at sysctl=0**, byte-exact contract
holds. UDP small-packet (PPS-limited) shows a small but consistent
ARM-specific regression at sysctl=1 — every sysctl=1 sample below
every sysctl=0 sample. Default-off case unaffected; the regression
is in the opt-in path only.

Working hypotheses for the ARM UDP regression (none verified, all
held for series 3 v2 follow-up): branch predictor on the dispatcher
chain handling fast-path less well than slow path on Cortex-A76;
16 KiB page boundary effect from the larger page size; or
fast-path .text layout crossing an i-cache line the slow path
didn't. Details:
`perf-results/2026-06-09-series3-arm-ab/results.md`.

For uarch comparison purposes: Cortex-A76 @ 2.4 GHz has roughly
**0.5–0.7×** the single-thread parser throughput of Zen 1 @ 3.4
GHz (hp1-5) — narrower dispatch width, lower clock. With 4 cores
vs hp's 8 logical threads, parallel-friendly workloads scale
4-wide.

---

## 19. Standalone ARM Cortex-A72 data point (pi4-1, BCM2711)

A seventh host joined the fleet on 2026-06-08: **pi4-1**, a
Raspberry Pi 4 running NixOS via the same nixos-raspberrypi
flake. Like chromebox1 and t, pi4-1 is **not** part of any peer
pair — it provides an older ARM uarch data point for the
single-host categories.

### Hardware

| Field | pi4-1 |
| --- | --- |
| Chassis | Raspberry Pi 4 SBC |
| SoC | Broadcom BCM2711 |
| CPU | 4× ARM Cortex-A72 @ 1.8 GHz |
| Cores / threads | 4 / 4 (no SMT) |
| RAM | 8 GiB LPDDR4 |
| Storage | SD card only (NIXOS_SD label) — no NVMe HAT |
| NIC (end0) | onboard 1 GbE |
| MAC | `e4:5f:01:42:a1:0f` |
| Mgmt IPv4 | 172.16.40.199 |

Live verification:

```bash
ssh root@pi4-1 'uname -r; lscpu | grep -E "Model name|max MHz"; free -g'
# Expected:
#   6.12.87
#   Model name: Cortex-A72   CPU max MHz: 1800.0000
#   8 GiB
```

### What pi4-1 can / cannot run

Identical to chromebox1 (§16) and t (§17) since the constraint is
"no peer link": **A/B/C/D/E/I ✅, F/G/H ❌**.

The added value vs the Pi 5 pair: **older Cortex-A72 uarch** (3
generations behind the A76 — in-order vs out-of-order, narrower
dispatch, smaller caches, 4 KiB pages by default). For the series
3 microbench this gives the same kind of "entry-level" reference
point that chromebox1 provides on the Intel side. The
uarch-specific deltas across A72 / A76 / Zen 1 / Zen 2 / Haswell /
Skylake-deriv are the publishable signal.

### NixOS module deltas

Uses `raspberry-pi-4.base` (no page-size module — Pi 4 uses 4 KiB
pages) and **u-boot** rather than the kernelboot loader the Pi 5s
use:

```nix
# ~/nixos/arm/pi4-1/configuration.nix
imports = with nixos-raspberrypi.nixosModules; [
  raspberry-pi-4.base
  ./il8n.nix
  ./sshd-INSECURE.nix
];
networking.hostName = "pi4-1";
```

Same caveat as the Pi 5s: **no `xdp2.testbed` block** today;
benchmark-mode tuning is a follow-up.

### Why no testbed config TOML

Same as chromebox1 / t / the Pi 5 pair: single peerless host.
Use the positional form:

```bash
nix run .#run-on-host -- pi4-1 -- xdp2-rs-test
nix run .#run-on-host -- chromebox1 pi4-1 -- flow-dissector-matrix
```

### Expected performance vs the rest of the fleet

Cortex-A72 @ 1.8 GHz is roughly **0.3–0.5×** the single-thread
parser throughput of Cortex-A76 @ 2.4 GHz (pi5-1/pi5-2) — older
uarch, lower clock. On the parser microbench it should sit
between chromebox1 (Haswell Celeron @ 1.4 GHz, even slower)
and the Pi 5 pair. As with chromebox1, the absolute numbers are
not the publishable signal — the **uarch comparison** is.

---

## 20. Standalone ARM Cortex-A53 data point (pi3-1, BCM2837)

An eighth host joined the fleet on 2026-06-09: **pi3-1**, a
Raspberry Pi 3B (BCM2837, Cortex-A53). Like chromebox1, t, and
pi4-1, it is not part of any peer pair — single-host categories
only. The added value here is a fundamentally different ARM
uarch family from the Pi 5 / Pi 4:

| uarch | host | dispatch | year | typical use |
| --- | --- | --- | --- | --- |
| Cortex-A53 | pi3-1 | **in-order** | 2012 | low-cost networking gear, embedded |
| Cortex-A72 | pi4-1 | OoO 3-wide | 2015 | mid-range routers, SBCs |
| Cortex-A76 | pi5-1, pi5-2 | OoO 4-wide | 2018 | flagship phones, modern routers |

The Cortex-A53 in-order dispatch is significant for the series 3
flow_dissector fast-path RFC: the fast-path adds a short branch
chain (static_branch + dissector identity + flag + ethertype
switch + per-shape parse) ahead of the slow-path graph walk. In-
order cores cannot speculate around mispredicted branches the way
A72/A76 can, so any dispatcher-chain misprediction cost shows up
more visibly on A53. Validating the patches on Cortex-A53 covers
the "extensively used in embedded networking" class of devices
that reviewers will (correctly) ask about.

### Hardware

| Field | pi3-1 |
| --- | --- |
| Chassis | Raspberry Pi 3 SBC |
| SoC | Broadcom BCM2837 |
| CPU | 4× ARM Cortex-A53 @ 1.2 GHz |
| Cores / threads | 4 / 4 (no SMT) |
| RAM | 1 GiB LPDDR2 |
| Storage | 256 GB SD card (NIXOS_SD label) — no NVMe |
| NIC | SMSC LAN9514 (USB 2.0 → 10/100 Mbit Ethernet, internally bridged) |
| Interface | `enu1u1` |
| MAC | `b8:27:eb:70:39:cb` (canonical RPi OUI) |
| WiFi | onboard BCM43438 (disabled in lab profile) |
| Mgmt IPv4 | 172.16.40.224 |
| Mgmt IPv6 (EUI-64) | `2603:8000:9c01:3b01:ba27:ebff:fe70:39cb/64` |

The interface name `enu1u1` (not `end0` / `eth0`) reflects the
Pi 3's network topology: the Ethernet PHY is bridged through an
internal USB 2.0 hub. systemd-udev names USB-attached NICs as
`enu<bus><port>`. This caps real throughput at ~95 Mbit/s — far
below what the Pi 4 / Pi 5 onboard MAC reaches. For series 3 macro
testing this matters less than the per-packet CPU envelope, which
is the relevant quantity for the dissector saving.

Live verification:

```bash
ssh root@pi3-1 'cat /proc/cpuinfo | grep "CPU part" | head -1; vcgencmd measure_temp; ip -br addr show enu1u1'
# Expected:
#   CPU part : 0xd03   (Cortex-A53)
#   temp=45.1'C
#   enu1u1  UP  172.16.40.224/24  2603:8000:9c01:3b01:...  fe80::...
```

### What pi3-1 can / cannot run

Identical to chromebox1 / t / pi4-1 — A/B/C/D/E/I ✅, F/G/H ❌.
The 100 Mbit USB-bridged NIC makes the F/G/H link-rate categories
meaningless even if pi3-1 had a peer (which it doesn't); the
single-host parser categories are the contributing role.

The added value vs pi4-1: in-order Cortex-A53 ARM uarch (see
table above), and 1 GB of RAM forcing a tighter compile/test
footprint — useful as a stress signal for any test that assumes
generous memory.

### NixOS module deltas

Uses `raspberry-pi-3.base` (no page-size module — Pi 3 uses 4 KiB
pages) and u-boot, mirroring the Pi 4 setup:

```nix
# ~/nixos/arm/pi3-1/configuration.nix
imports = with nixos-raspberrypi.nixosModules; [
  raspberry-pi-3.base
  ./il8n.nix
  ./sshd-INSECURE.nix
];
networking.hostName = "pi3-1";
```

No `xdp2.testbed` block today; no `test-kernel/` either. Series
3 patches on Cortex-A53 are a follow-on (the patches build on
linux_rpi3 in principle but the on-Pi build is slow on SD card;
cross-compile from the workstation is the practical path).

### Why no testbed config TOML

Same as the other single-host data points — single peerless host,
no `[nic]` block worth parameterising. Use the positional form:

```bash
nix run .#run-on-host -- pi3-1 -- xdp2-rs-test
# Or in a cross-uarch sweep with the other ARM data points:
nix run .#run-on-host -- pi3-1 pi4-1 pi5-2 -- flow-dissector-matrix
```

### Expected performance vs the rest of the fleet

Cortex-A53 @ 1.2 GHz is the slowest ARM data point in the fleet —
the dispatch width is 2-wide and the core is in-order, plus the
clock is below pi4-1's 1.8 GHz. On the libflowdis microbench it
should sit between chromebox1 (Haswell Celeron @ 1.4 GHz, similar
era and similar single-thread envelope) and the Pi 4 (Cortex-A72
@ 1.8 GHz). The publishable signal from pi3-1 is the in-order
ARM uarch row in the cross-uarch microbench table, not absolute
throughput.

---

## 21. x86 testbed pair (l ↔ l2, ConnectX-4 Lx 25 GbE back-to-back)

A fourth /29 subnet block (`10.10.4/5`) hosts the high-performance x86
pair: **l** (the developer's main desktop, acting as generator) and
**l2** (a dedicated DUT), each with a **Mellanox ConnectX-4 Lx 25 GbE**
NIC, cabled back-to-back over two DAC links (`f0 ↔ f0` = link A,
`f1 ↔ f1` = link B — same topology as hp1/hp3). Both run NixOS; configs
live under `~/nixos/desktop/{l,l2}/`.

The motivation is headroom. The Zen 1 hp1/hp3 pair is CPU-bound well
below the 25 GbE line rate (~16.4 Gbit/s on the iperf3 macro), so the
flow_dissector fast-path's macro signal is muted. l/l2 are AMD
Threadripper PRO 3945WX (Zen 2, 12c/24t) — far more raw throughput — and
the x86 long-soak analogue of the Pi fleet's `nix run .#series3-soak`.

> **Measured (2026-06-30, first live run — see
> [`perf-results/2026-06-30-phase-h-l-l2-summary/`](../perf-results/2026-06-30-phase-h-l-l2-summary/)).**
> The pair still caps **~16 Gbps**, *not* because of the Zen 2 silicon
> (the iperf3 sender uses <1 core; l2 idles) but because **l2 is tuned
> for AF_XDP, not kernel-stack throughput**: `isolcpus`+`nohz_full`+
> `rcu_nocbs` on cores 4-23 leave only 4 schedulable cores for the RX
> stack, NIC offloads are off (GRO/TSO/GSO), and NIC queues/IRQs are
> pinned to the isolated cores. Relaxing these at runtime made throughput
> *worse* (nohz_full cores reject softirq/RPS). So the fast-path's
> **macro signal is measured as receiver CPU/cycles saved, not as higher
> throughput** — headline **eth_ip pktgen −112 cyc/pkt (−4.9%)**, and
> encap-TCP softirq savings up to −15.5% (vxlan). Reaching 25 GbE
> kernel-stack would require re-tuning l2 (offloads on, isolation off,
> queues spread) + reboot — a separate effort tracked in the findings.

| | hp1 / hp3 (pair #2) | l / l2 (pair #4) |
| --- | --- | --- |
| CPU | AMD Ryzen 5 PRO 2400G (Zen 1, 4c/8t) | AMD Threadripper PRO 3945WX (Zen 2, 12c/24t) |
| NIC | Mellanox ConnectX-4 Lx 25 GbE DAC | Mellanox ConnectX-4 Lx 25 GbE DAC |
| Driver | `mlx5_core` | `mlx5_core` |
| Iface names | `enp1s0f{0,1}np{0,1}` | `enp35s0f{0,1}np{0,1}` (PCI 23:00.x) |
| Data-plane subnets | `10.10.2.0/29` + `10.10.3.0/29` | `10.10.4.0/29` + `10.10.5.0/29` |
| Generator / DUT | hp1 (gen) ↔ hp3 (dut) | l (gen, `.2`) ↔ l2 (dut, `.5`) |
| Dedicated? | both dedicated | l2 dedicated; l is a daily-driver desktop |
| Testbed config | [`testbeds/hp1-hp3-mlx5.toml`](../testbeds/hp1-hp3-mlx5.toml) | [`testbeds/l-l2-mlx5.toml`](../testbeds/l-l2-mlx5.toml) |
| Host config | `~/nixos/hp/hp{1,3}/` | `~/nixos/desktop/{l,l2}/` |

### Generator-lite profile on `l`

Unlike every other testbed host, `l` is the user's interactive
workstation (NVIDIA GPU, GNOME, llama.cpp) and must stay usable. It
imports `xdp2.nixosModules.physical-testbed` with a deliberately light
profile:

- `xdp2.testbed.dedicatedHost = false` — skips the always-on
  `processor.max_cstate=1` / `transparent_hugepage=never` / `audit=0`
  kernel params that raise idle power/heat on a desktop (see §7 and the
  option doc in `nix/modules/physical-testbed.nix`).
- `disableMitigations = false` — CPU mitigations stay **on** (daily
  driver).
- `disableNonEssentialServices = false` and `lowJitter = false` — GNOME,
  printing, VPN, turbo all preserved.
- `isolatedCpus = [ 2 3 4 5 ]` — only ~4 logical cores are isolated for
  traffic generation; the remaining ~20 threads stay for the desktop.
  The soak harness `taskset`-pins the generator load onto these cores.

`l2` keeps the full dedicated profile (`dedicatedHost = true`,
`lowJitter = true`, `isolatedCpus = 4-23`) and the series-3 patched
kernel. Both hosts set `xdp2.nicTuning.driver = "mlx5_core"`.

### Kernel patch on both ends

The series-3 A/B flips `net.core.flow_dissector_fastpath` on **both**
hosts, so both must boot a kernel carrying the gated patch:

- `l2` builds it via `~/nixos/desktop/l2/test-kernel/` (the same 3
  pinned patches hp1/hp2/hp3/hp5 use, on `linuxPackages_latest`).
- `l` applies the same 3 canonical patches as a `boot.kernelPatches`
  overlay on its existing NVIDIA-compatible `pkgs.linuxPackages` (no
  net-next needed; `flow_dissector.c` is stable across 6.x/7.x). The
  earlier squashed single-file backport was replaced because it omitted
  the sysctl-gate hunk (`net/core/sysctl_net_core.c`), which would make
  the runtime A/B impossible.

### Long soak

```bash
# Smoke (~18 min): 12 cells × 60 s
DUR=60 COOLDOWN=10 L2_V4=10.10.4.5 L2_V6=fd10:10:4::5 \
  nix run .#series3-soak-l-l2

# Full demonstration (~12 h): 12 cells × 3600 s
L2_V4=10.10.4.5 L2_V6=fd10:10:4::5 nix run .#series3-soak-l-l2
```

The 12-cell matrix (iperf3 TCP/UDP v4+v6, iperf2 TCP, tcpreplay VXLAN ×
sysctl 0/1) is weighted toward CPU-bound workloads — small-packet UDP
and tunnelled tcpreplay — because a 25 GbE TCP elephant is GRO/PCIe-
bound and runs the dissector only once per super-packet, hiding the
per-packet win. Output layout matches the Pi soak
(`cells/*/summary.json`, `aggregate.csv`) so the same analysis tooling
applies. See `nix/series3-soak-x86.nix`.

### Outstanding follow-up

- **NIC swap resolved (2026-06-30).** The Mellanox links were `DOWN` (no
  carrier) at config time because l2's original **generic-OEM** card
  (PSID `MT_…`) refused to read the DAC's I²C EEPROM (`err -5`). Swapping
  in an **HP-OEM** ConnectX-4 Lx (PSID `HP_2420110034`, fw `14.27.4000`,
  whose firmware skips that verification) brought both back-to-back DACs
  up at `25000Mb/s`. `ethtool -i` now shows the `HP_…` PSID on both ends.
  See `perf-results/2026-06-15-l-l2-dac-eeprom-issue.md` (closed).
- `flowDirectorRules` on l2 are ethtool-ntuple-shaped; under
  `mlx5_core` they translate to tc-flower (or drop them — they are not
  needed for the cake-based soak).
- For tcpreplay cells, copy a `vxlan-k8s-pure.pcap` onto `l` and rewrite
  its dst MAC to l2's `enp35s0f0np0` MAC (see `series3-soak-x86.nix`
  header).

---

## 22. RISC-V testbed pair (pi5-1 → bpi-f3, SpacemiT K1, 1 GbE switched)

A seventh host joined the fleet on 2026-06-23: **bpi-f3**, a Banana Pi
BPI-F3 (SpacemiT K1, octa-core RISC-V), brought in as the fleet's
**third CPU architecture** alongside x86_64 (AMD Zen 1/2, Intel
Haswell/Comet Lake) and ARM (Cortex-A53/A72/A76). With it the series-3
flow_dissector fast-path is demonstrated across x86 + ARM + RISC-V.

It is a single board, so it is driven as a DUT/receiver paired with an
existing lab host as generator. The two share the lab switch on `end0`
at 1 GbE (172.16.40.122 → 172.16.40.205), exactly like the pi5 pair —
there is no back-to-back /29. The **generator is ARM (pi5-1)** and the
**measured DUT is the RISC-V box (bpi-f3)**; the fast-path being
measured runs on the DUT, which is what the cross-arch claim needs.

| | pi5-1 (generator) | bpi-f3 (DUT, measured) |
| --- | --- | --- |
| Chassis | Raspberry Pi 5 SBC | Banana Pi BPI-F3 SBC |
| SoC | Broadcom BCM2712 | SpacemiT K1 |
| CPU | 4× ARM Cortex-A76 @ 2.4 GHz | 8× SpacemiT X60 RISC-V (RVA22 + RVV 1.0) |
| Cores / threads | 4 / 4 (no SMT) | 8 / 8 (no SMT) |
| ISA / page size | ARMv8-A / 16 KiB | rv64gcv (Sv39) / 4 KiB |
| RAM | 8 GiB LPDDR4X | 8 GiB LPDDR4X |
| Boot storage | SD card (NIXOS_SD) | SD card (extlinux / U-Boot + OpenSBI) |
| Root / build storage | NVMe (not yet root) | **NVMe (root `/`, `/nix/store`)** |
| NIC (end0) | onboard 1 GbE (BCM54213PE PHY) | onboard 1 GbE (`k1_emac` + RTL8211F PHY) |
| MAC | `2c:cf:67:37:a1:b2` | `fe:fe:fe:e2:46:d4` |
| Mgmt IPv4 | 172.16.40.122 | 172.16.40.205 |
| Kernel | `linux_rpi5` (6.12.87 for pktgen) | `linuxPackages_latest` 7.0.12 + series-3 |

Live verification:

```bash
ssh root@bpi-f3 'uname -a; mount | grep " / "; ls /proc/sys/net/flow_dissector/'
# Expected:
#   Linux bpi-f3 7.0.12 ... riscv64 GNU/Linux
#   /dev/nvme0n1p1 on / type ext4 (rw,...)
#   eth_ip geneve_inner gre gtpu_inner ipip mpls pppoe qinq vlan vxlan_inner
```

### What this pair can / cannot run

- A–E, I (single-host parsers and matrices on the RISC-V DUT): ✅
- F (live-traffic iperf3 receiver-side A/B): ✅ (1 GbE link) — the
  **primary** measurement; runs with pi5-1 on its current kernel.
- G (kernel-pktgen + ksoftirqd `perf stat` cycles/pkt): ✅ (1 GbE) —
  **secondary**, gated on the generator: pi5-1 must run **6.12.87**,
  because its 6.18 `bcmgenet` driver wedges the NIC under pktgen TX.
- H (hardware ntuple offload): **N/A** — the `k1_emac` does not expose
  Flow Director / ethtool-ntuple steering (same as the pi5/chromebox/t).

The added value: the series-3 `static_branch` / `jump_label` runtime
patching is arch-specific code in `arch/riscv/kernel/jump_label.c` —
exercising it on real RISC-V hardware is direct evidence the patches
generalise beyond x86 and ARM. The patches themselves touch only
arch-independent code (`net/core/flow_dissector.c`,
`include/net/flow_dissector.h`, `net/core/sysctl_net_core.c`, docs).

### NixOS module deltas vs the hp pattern

bpi-f3 is a per-host flake at `~/nixos/riscv/bpi-f3/`, **cross-compiled
from x86_64 → riscv64** at `rv64gcv` (the K1's X60 cores implement RVV
1.0). `rv64gcv` diverges from the riscv64 community caches, so the whole
closure — kernel included — builds locally; build on a fast x86 host
(`l`), not on-device. Custom bootloader inputs (`uboot-spacemit`,
`opensbi-spacemit`) are built from source; the kernel is mainline
`pkgs.linuxPackages_latest` (7.0.12) with the K1 drivers forced on.

The same **10 v3/v4 flow_dissector patches** the x86/ARM hosts carry are
appended to the inline `kernelPatches` list in
`~/nixos/riscv/bpi-f3/nix/modules/kernel.nix` (no separate
`test-kernel/` override needed — the flake already keeps a `kernelPatches`
list for the K1 Kconfig + reboot fix). `nix/modules/sshd-INSECURE.nix`
grants key-only root SSH (same `das` key as hp*/pi5) so the orchestrator
can drive it; `perf` + `iperf3` are added to `base.nix`.

The device runs the **NVMe-root mutable system** (`nixosConfigurations.
bpi-f3-nvme`, `/` on `/dev/nvme0n1p1`). Deploys cross-build on `l` and
push the closure to the device's fast NVMe store via
`nixos-rebuild switch --target-host root@bpi-f3` — **no SD image is
reflashed** (only extlinux on the SD `/boot/firmware` is regenerated).

### Running the A/B

```bash
# Smoke (iperf3, no generator-kernel dependency):
PAIRS=pi5-bpif3 SCENARIOS=eth_ip DUR=30 REPLICATES=1 CONSUMER_ALL=1 \
  OUT=/tmp/bpif3-smoke nix run .#series3-extensions-soak

# Phase F (iperf3 receiver-side A/B) — PRIMARY:
PAIRS=pi5-bpif3 OUT=perf-results/<date>-riscv-bpif3-iperf3 \
  nix run .#series3-comprehensive-iperf3-soak

# Phase G (pktgen cycles/pkt) — after pi5-1 is on 6.12.87:
PAIRS=pi5-bpif3 OUT=perf-results/<date>-riscv-bpif3-pktgen \
  nix run .#series3-comprehensive-pktgen-soak
```

### Measured performance — userland libflowdis microbench (2026-06-25)

**Headline: the fast-path roughly halves dissector cost on RISC-V —
−48.88 ns/pkt, −49.8%** (patched 49.27 ± 0.32 vs baseline 98.16 ± 0.21
ns/pkt, 10×10 M-iter runs, `taskset`-pinned). This is the single
highest-signal A/B in the series — it isolates the dissector from the
NIC/qdisc/scheduler, which is why it shows a clean result where the
1 GbE-limited Phase F/G runs below could not. It lands squarely in the
ARM range (A53 −48.5%, A72 −55.0%, A76 −52.3%) and completes the
cross-architecture story: ~50% reduction on x86, ARM, **and RISC-V**.

The two `libflowdis.so` variants (patched = current
`src/lib/flowdis/flow_dissector.c`; baseline = the same file at
`5960a9c6^`, before the port) were cross-compiled on `l` with
`pkgsCross.riscv64.stdenv.cc` — the full `nix run .#xdp2-debug-riscv64`
path fails on an unrelated `sox` cross-build and the K1 has no riscv64
binary cache — then copied to bpi-f3 and run. Full writeup + raw runs:
`perf-results/2026-06-25-series3-riscv-microbench/`.

### Measured performance — series 3 A/B (2026-06-25, Phase F)

First Phase F run: `PAIRS=pi5-bpif3`, all 8 scenarios (eth_ip, vlan, qinq,
vxlan, mpls, ipip, gre, geneve) × tcp/udp × sysctl 0/1, N=3, DUR=60,
CONSUMER_ALL=1. **96/96 cells `status=ok` — every scenario, including all
five encap paths, set up and dissected correctly on riscv64.** This is the
headline result: it is direct evidence the patches are functionally correct
on a third architecture — the per-shape `net.flow_dissector.*` sysctls
toggle, and the `static_branch`/`jump_label` gates resolve via
`arch/riscv/kernel/jump_label.c`.

Throughput is link-saturated at ~1 GbE on every scenario (TCP ~0.90–0.94
Gbps, UDP ~0.91–0.95 Gbps; MPLS-over-`lo` TCP is the outlier at ~0.64
Gbps), so — as on the pi5 and hp pairs — the A/B signal can only live in
receiver CPU, not throughput. At 1 GbE the K1 is **not CPU-bound** (receiver
softirq only ~15–39%), so the flow_dissector fast-path's per-packet saving
sits below the run-to-run noise floor: the sysctl=0→1 receiver-softirq
deltas are small (≈ ±0.3–4 pp) and **inconsistent in sign** across
scenarios (e.g. vlan-udp −4.4 pp but geneve-udp +3.9 pp, ipip-tcp −2.9 pp
but eth_ip-udp +1.7 pp). `series3-summary-report` tags essentially all rows
`(noise)`; the few that pass the 2×stddev gate point in opposite
directions — i.e. sampling noise, not a real effect or regression. Full
matrix: `perf-results/2026-06-25-riscv-bpif3-iperf3/`, summary:
`perf-results/2026-06-25-riscv-bpif3-summary.md`.

This mirrors the fleet-wide finding (only the hp2-hp5 vlan-UDP cell is
cleanly above noise anywhere). The RISC-V data point stands as a
**correctness** demonstration, which is what the cross-architecture claim
requires.

### Measured performance — Phase G (2026-06-25, kernel-pktgen cycles/pkt)

Phase G ran after rolling the **generator pi5-1 back to 6.12.87** — its
6.18 `bcmgenet` driver reproducibly wedges the NIC within ~30 s of pktgen
TX; 6.12.87 sends the flood without wedging. `PAIRS=pi5-bpif3`, 8
scenarios × sysctl 0/1, N=3: **48/48 cells `status=ok`**, and the K1 PMU
counts cleanly under perf (cycles, instructions, branches, branch-misses,
L1-dcache loads/misses all populated on the riscv64 ksoftirqd).

But there is **no usable cyc/pkt A/B on this pair**, for structural
reasons rather than a patch problem:
- The 1 GbE link can't make the 8-core K1 CPU-bound on dissection, so
  the per-packet dissector cost never dominates.
- ksoftirqd attribution is unreliable: several cells `perf stat` to 0
  cyc/pkt because the K1 processed RX in NAPI-poll context on the RX CPU
  rather than ksoftirqd (the PIDs perf was attached to).
- pktgen's inner-encap delivery doesn't traverse this path for the
  tunnels — geneve/vxlan cells received only ~8 packets.
- pps_recv differs widely between the two sysctl states (e.g. vlan 1.56M
  vs 0.55M), so cyc/pkt isn't comparable cell-to-cell.

Consequently `series3-summary-report` tags every Phase G row `(noise)`
(pooled stddev ±1000–3600 cyc/pkt vs deltas that bounce −54%…+64% with no
consistent sign). Matrix retained for the record at
`perf-results/2026-06-25-riscv-bpif3-pktgen/`. A clean RISC-V cyc/pkt
number would need a faster link (so the CPU is the bottleneck) or a
userspace dissector microbench — noted as future work; it does not change
the correctness conclusion above.

### Outstanding follow-ups / caveats

- **Reboot may hang** at "Restarting system" (vendor OpenSBI lacks the
  SBI System-Reset extension; the P1-PMIC reboot patch is applied but a
  power-cycle is the reliable fallback).
- **rv64gcv has no binary cache** — every kernel rebuild compiles
  locally; build-gate `nix build .#nixosConfigurations.bpi-f3-nvme.\
config.system.build.toplevel` on `l` before deploying.
- **Phase G depends on pi5-1 @ 6.12.87** (its 6.18 `bcmgenet` wedges
  under pktgen TX). Phase F (iperf3) is unblocked at any pi5-1 kernel.
- Single RISC-V box: the generator is ARM, not RISC-V. Fine — the
  measured fast-path is on the RISC-V DUT.

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
