# hp5 configuration.nix — patched-kernel test edit

**Purpose**: switch hp5 to boot a custom net-next kernel with our 4
patches (combined-test-rfc branch) for runtime validation of the
flow_hash_from_keys_small series + bpf_flow PPPoE patch.

**Reversibility**: edit is a single-line replacement plus a small
let-binding addition. To revert, undo the diff + nixos-rebuild boot
+ reboot. The previous generation stays in the GRUB menu in any case.

## Files to copy to hp5

1. `/home/das/nixos/hp/hp5/test-kernel/default.nix` — copy from
   `kernel-patches/test-kernel/default.nix` in this repo
2. `/home/das/nixos/hp/hp5/test-kernel/hp5-kernel.config` — copy from
   `kernel-patches/test-kernel/hp5-kernel.config` in this repo

The `default.nix` references `/home/das/Downloads/net-next` as the
source path. That tree must also exist on hp5 with the
`combined-test-rfc` branch checked out (head `011dab72ddf8`). Easiest
path: rsync the net-next tree to hp5 if not present, OR build locally
and push the closure via `nix-copy-closure`.

## Configuration.nix diff

```diff
@@ around line 70-73 @@
   # https://nixos.wiki/wiki/Linux_kernel
-  # Pinned to linuxPackages_latest so hp2 + hp5 run the same newest
-  # kernel (xdp2 docs/physical-testbed.md §3, 2026-04-20).
-  boot.kernelPackages = pkgs.linuxPackages_latest;
+  # TEMPORARY: switched to a custom net-next kernel built from the
+  # combined-test-rfc branch for runtime validation of the
+  # flow_hash_from_keys_small + bpf_flow PPPoE patch series.
+  # Restore to `pkgs.linuxPackages_latest` after testing.
+  boot.kernelPackages = pkgs.linuxPackagesFor
+    (pkgs.callPackage ./test-kernel {});
```

## Deploy workflow

```bash
# 1. On workstation: copy test-kernel files into nixos config dir
mkdir -p /home/das/nixos/hp/hp5/test-kernel
cp /home/das/Downloads/xdp2/kernel-patches/test-kernel/default.nix \
   /home/das/nixos/hp/hp5/test-kernel/
cp /home/das/Downloads/xdp2/kernel-patches/test-kernel/hp5-kernel.config \
   /home/das/nixos/hp/hp5/test-kernel/

# 2. Apply the configuration.nix diff above.

# 3. Sync the entire nixos config tree to hp5 (uses existing Makefile)
cd /home/das/nixos/hp/hp5
make sync   # rsyncs to hp5:/home/das/nixos/hp/hp5/

# 4. Copy the built kernel closure to hp5's nix store (much faster
#    than letting hp5 build from scratch — saves ~5 hours)
nix-copy-closure --to ssh://root@hp5 /nix/store/<kernel-store-path>
# (store path from local `nix-build` output)

# 5. Optionally also copy the net-next source to hp5 (only needed if
#    hp5 has to re-eval the derivation; if the closure copy worked,
#    the build will be cached and src access isn't needed)
rsync -a --exclude=.git /home/das/Downloads/net-next/ \
   root@hp5:/home/das/Downloads/net-next/

# 6. On hp5: nixos-rebuild boot (creates a new generation as
#    next-boot WITHOUT switching the running system)
ssh root@hp5 'cd /home/das/nixos/hp/hp5 && sudo nixos-rebuild boot --flake .'

# 7. USER decision: reboot hp5 when ready.
#    DO NOT run reboot from this script — needs to be your call given
#    the safety implications.
#    ssh root@hp5 reboot

# 8. After hp5 comes back up, verify the new kernel is running:
ssh root@hp5 'uname -r'   # expect 7.1.0-rc4-flowdis-pppoe

# 9. Run validation tests (see kernel-patches/test-kernel/post-boot-tests.md)
```

## Rollback procedure

If the kernel boots and tests pass, you can either keep the test
kernel running or roll back to the canonical config:

```bash
# Edit configuration.nix to restore linuxPackages_latest, then:
cd /home/das/nixos/hp/hp5
make sync
ssh root@hp5 'cd /home/das/nixos/hp/hp5 && sudo nixos-rebuild boot --flake .'
ssh root@hp5 reboot   # (your call, as above)
```

If the kernel **doesn't boot** at all, you need to manually select
the previous NixOS generation from the GRUB menu at boot time. That
requires either console access or IPMI/iKVM. For an SSH-only headless
host, this is the risk we're explicitly taking. Mitigations:

- The `nixos-rebuild boot` (not `switch`) means the system runs the
  CURRENT generation until reboot. The patched kernel is only active
  AFTER you trigger the reboot.
- The previous NixOS generation (with `pkgs.linuxPackages_latest`)
  stays in the GRUB menu as a "Previous generation" entry. Select
  that if the new one fails to boot.
- All NixOS generations are listed in
  `/run/current-system/specialisation/` and `/boot/loader/entries/`
  (or via `nix-env --list-generations -p /nix/var/nix/profiles/system`).
  You can also `nixos-rebuild --rollback` from a recovery shell if
  you can get one.

## What the test-kernel derivation does NOT change

- Hardware modules (i40e for X710 NIC, NVMe, etc.) — all built into
  the new kernel from hp5's existing `.config`
- xdp2 testbed config — `xdp2.testbed.enable = true` is unchanged
- isolcpus / nohz_full kernel cmdline — unchanged
- Network configuration, firewall, services — all unchanged

The ONLY change is which kernel binary is booted.
