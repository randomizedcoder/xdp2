# Deploying the series3 extension patches on a NixOS testbed

This is Phase 3 of the cross-testbed harness. The Phase 1 / Phase 2 work (network-scenario scripts + matrix orchestrator) measures the deltas; this doc explains how to get the extension-patched kernel onto a testbed so those deltas are non-zero.

## What you're doing

Adding three patches to whatever kernel your testbed already runs:

| patch | shape | byte-identical |
|---|---|---|
| `0001-…single-VLAN` | Eth + ETH_P_8021Q/8021AD + IPv4/IPv6 + TCP/UDP | yes |
| `0002-…QinQ` | + a second stacked tag | yes |
| `0003-…VXLAN inner` | UDP dst 4789 → inner Eth + IPv4 | **no — behaviour change** |

The first two are pure performance wins under the parent series3's existing sysctl gate (`net.core.flow_dissector_fastpath`). The third descends into VXLAN payloads for hashing — useful for k8s overlay fairness but it changes the dissector's contract, so it's gated separately and defaults off.

## Prerequisite

The host must already have the **parent** series3 fast-path patches applied — i.e. `sysctl -n net.core.flow_dissector_fastpath` must return a value, not "unknown key". For most of the existing testbeds (l, l2, hp1, hp3, hp2, hp5, pi5-1, pi5-2) this is already true via the host's `boot.kernelPatches` referencing the series3 v1 patches.

If a host doesn't have the parent series3 yet, add the v1 patches from `kernel-patches/series3-flowdis-fastpath/v1-netdev/000{1,2,3}-*.patch` to its kernel-build first, *or* upgrade to a net-next 7.1.0-rc4+ kernel which has the parent series in upstream as commit `8013aee91ccb`.

## Step 1 — import the module in your host config

In your NixOS host configuration (e.g. `~/nixos/arm/pi5-1/configuration.nix`):

```nix
{ inputs, ... }: {
  imports = [
    inputs.xdp2.nixosModules.flowdisFastpathExtensions
    # ... your existing imports
  ];

  xdp2.flowdisFastpathExtensions = {
    enable = true;
    # Set true only if you want to A/B the VXLAN-inner behaviour change.
    # Default off because it breaks the byte-identical contract with
    # the parent series3 — see the patch 0003 commit message.
    enableVxlanInner = false;
  };
}
```

If your flake doesn't already pull in xdp2 as an input, add it:

```nix
# flake.nix
inputs.xdp2.url = "github:randomizedcoder/xdp2/flow-keys-compat-reorder";
```

(Replace `flow-keys-compat-reorder` with whichever branch the extension-patches landed on by the time you read this. As of the commit that introduced this doc: `flow-keys-compat-reorder`.)

## Step 2 — stage and reboot

```sh
cd ~/nixos/arm/pi5-1     # or wherever your host config lives
sudo nixos-rebuild boot  # builds the patched kernel, stages for next boot
sudo reboot
```

`nixos-rebuild boot` rather than `switch` because the only thing changing is the kernel, and the new kernel only takes effect on reboot. If you've changed userspace too, `switch` is also fine — the kernel still won't take effect until reboot.

## Step 3 — verify the patches are in

After reboot, on the host:

```sh
uname -r                                       # should match new kernel version
sysctl -n net.core.flow_dissector_fastpath     # 0 (default; gate is still off)
sysctl -w net.core.flow_dissector_fastpath=1   # enable
```

The orchestrator (`series3-extensions-soak`) drives the sysctl toggles itself per cell, but it's worth a quick manual check that the sysctl is settable and the kernel didn't panic.

## Step 4 — run the matrix

From the xdp2 repo (any host that can SSH to your testbeds):

```sh
# Quick smoke (DUR=10, just the pi5 pair, all three byte-identical scenarios)
PAIRS=pi5-pair SCENARIOS=vlan,qinq,vxlan DUR=10 \
  nix run .#series3-extensions-soak

# Full matrix across all pairs (~64 cells, DUR=60 → ~1 hour wall)
PAIRS=l-l2,hp1-hp3,hp2-hp5,pi5-pair SCENARIOS=vlan,qinq,vxlan DUR=60 \
  nix run .#series3-extensions-soak
```

Compare `mbps` between rows of the same `pair,scenario,proto` where `sysctl=0` vs `sysctl=1`. On a wire-saturating workload the delta won't show up as throughput — it shows up as CPU headroom (lower remote_cpu in iperf3's JSON, or in a follow-up cell with cake / mpstat in the loop). On a CPU-bound workload it shows up directly. The headline shape from the cover-letter is +0.8 % to +2.4 % macro, ~5 ns/skb microbench.

## Rolling back

The module is opt-in — comment out or remove the import, `nixos-rebuild boot`, and reboot. The host returns to its previous kernel.

If you want to keep the kernel but disable the extensions at runtime, set the parent sysctl to 0:

```sh
sysctl -w net.core.flow_dissector_fastpath=0
```

That turns the static-branch off and the dispatcher falls through to the slow path, with or without the extension patches present. Same shape of rollback that the parent series3 supports.

## Notes & gotchas

- **Cross-arch**: the patches are portable C; they apply equally to x86_64 (l↔l2, hp1↔hp3, hp2↔hp5) and aarch64 (pi5-1↔pi5-2).
- **Kernel version**: the patches were generated against `8013aee91ccb` (net-next 7.1.0-rc4 with the parent v2-inline applied). They should apply cleanly to any kernel that has the parent series3 in roughly that shape. If you're on a stable kernel where the parent was backported, the line numbers will shift but `git am`'s 3-way merge should still succeed.
- **Patch 3 / VXLAN inner**: hardcodes UDP dst 4789 (the IANA-assigned VXLAN port). Cilium and some other CNIs use 8472 — those won't be matched. A production-ready version would consult a sysctl or per-netns config; this draft is for the discussion, not for general deployment.
- **`netconf-pppoe`**: requires `pppd` + `pppoe-server` on the host. If your testbed NixOS module doesn't install them, add `environment.systemPackages = with pkgs; [ ppp rp-pppoe ];` separately. Not required for the byte-identical patches 0001 and 0002.
