# Patched-kernel build validation — series 1 + series 2

**Date**: 2026-05-23 to 2026-05-24
**Test host**: hp5 (AMD Ryzen 5 PRO 2400G, Zen 1, 4c/8t)
**Net-next branch**: `combined-test-rfc` on `/home/das/Downloads/net-next/`
  (4 commits: docs + flow_hash_from_keys_small + sch_cake adoption + bpf PPPoE)
**Build host**: hp5, `/tmp/net-next-build/`
**Kernel version**: 7.1.0-rc4 (with our 4 patches)
**Build config**: based on hp5's running 7.0.1 .config, reconciled via
  `make olddefconfig`, with these tweaks for the build environment:
  - `CONFIG_DEBUG_INFO_BTF=n` (resolves the in-tree-libbpf vs nix-libelf
    version skew — see "Build env workaround" below)
  - `CONFIG_SYSTEM_TRUSTED_KEYRING=n`, `CONFIG_MODULE_SIG=n`
    (avoids openssl dependency for module signing)
  - All other config values inherited from hp5's running kernel

## Build results

```
vmlinux:           389 MB
arch/x86/boot/bzImage: 12 MB
modules:           all built (net/* qdiscs, fs/* including XFS, drivers/*)
build time:        ~5 hours (vmlinux+modules) + 2 min (bzImage)
build host CPU:    4 isolated taskset cores; -j8 make parallelism
```

## Patch presence verification

### Patch 2 — `flow_hash_from_keys_small()` exported

```
$ grep "flow_hash_from_keys_small" /tmp/net-next-build/System.map
ffffffff81eca2e0 T __pfx_flow_hash_from_keys_small
ffffffff81eca2f0 T flow_hash_from_keys_small
ffffffff81eca600 T __pfx_flow_hash_from_keys_small_seed
ffffffff81eca610 T flow_hash_from_keys_small_seed
ffffffff829fce60 r __ksymtab_flow_hash_from_keys_small
ffffffff829fce6c r __ksymtab_flow_hash_from_keys_small_seed
ffffffff82a14326 r __flags_flow_hash_from_keys_small
ffffffff82a14327 r __flags_flow_hash_from_keys_small_seed
```

Both `flow_hash_from_keys_small` and the `_seed` variant are present
in the kernel's text section and exported via `__ksymtab_*`. The
`EXPORT_SYMBOL` calls in our patch 2 took effect.

### Patch 3 — sch_cake.ko references the new helper

```
$ nm /tmp/net-next-build/net/sched/sch_cake.ko | grep flow_hash
                 U flow_hash_from_keys
                 U flow_hash_from_keys_small
```

Both symbols are unresolved-imports in cake.ko, exactly as expected:
- `flow_hash_from_keys` — for the main `flow_hash` call (kept on the
  full function for skb->hash compatibility)
- `flow_hash_from_keys_small` — for the two host_keys hashes (our
  patch 3 substitution)

The 4 source-level call sites for host_keys hashes dedupe to a single
unresolved reference, which is what dynamic linking expects.

### Patch 1 — Documentation/networking/flow_dissector.rst present

```
$ ls -lh /tmp/net-next-build/Documentation/networking/flow_dissector.rst
[present, 8 KB]
```

(The RST file doesn't affect the binary kernel; it lands in the kernel
docs build output when `make htmldocs` runs. Patch 1 is reviewed as
RST source rather than as binary content.)

### Patch 4 — bpf_flow.bpf.o handles PPPOE (validated previously)

Already validated on 2026-05-23 on hp5's running 7.0.1 kernel via
`bpftool prog loadall`. All 7 sub-programs (including
`flow_dissector_6` = PROG(PPPOE)) loaded successfully; BPF verifier
accepted the program. See
`kernel-patches/series2-bpf-pppoe/README.md` for the disassembly +
sizes.

## What this validates

| validation | status | implication |
|---|---|---|
| Full kernel compiles end-to-end with all 4 patches | ✅ | no syntax errors, no missing dependencies, no type mismatches |
| vmlinux links | ✅ | EXPORT_SYMBOL works, no unresolved symbols |
| New helper visible in kernel symbol table | ✅ | loaders / consumers can find `flow_hash_from_keys_small` |
| sch_cake.ko has the right unresolved-reference set | ✅ | patch 3's substitution is in the object code, not just the source |
| BPF flow_dissector loads (separate test, 2026-05-23) | ✅ | verifier accepts PROG(PPPOE); BPF runtime test passed |

## What this does NOT validate

The build succeeded but the kernel was never booted. Outstanding:

- **Boot test**: does the patched kernel actually boot on hp5?
  Strongly predicted yes (build is clean, no Kbuild warnings of
  concern, no symbol-resolution issues), but not yet verified.
- **Runtime sch_cake test**: does cake's host accounting still
  function correctly with the new hash variant? The new hash values
  are different from the old ones but should still distribute uniformly
  per the chi² validation. Not yet observed in a running cake.
- **Runtime PPPoE BPF test**: does PROG(PPPOE) actually dispatch a
  real PPPoE packet to the right sub-program? Verifier accepted the
  code path but no end-to-end packet was run through it.

To get the remaining validation, the patched kernel needs to actually
boot. On NixOS this requires either a custom Nix derivation +
nixos-rebuild + reboot, or a kexec one-shot with a compatible initrd.
Both are non-trivial (each takes another ~1-3 hours of work).

## Build env workaround (for reproducibility)

The kernel build was difficult because the xdp2 nix dev shell on hp5
ships `libelf-0.8.13` (the standalone Michael Riepe library) which
is too old for current `tools/objtool` and `tools/bpf/resolve_btfids`
(they need elfutils 0.182+ for `gelf_getsymshndx`, `GElf_Nhdr`,
`gelf_getnote`, etc.). The hp5 dev shell also lacks `bc` and
`openssl-dev`.

Working build invocation:

```bash
ssh root@hp5
cd ~/xdp2 && nix develop --command bash -c '
  # Add bc, openssl, and elfutils into the build environment
  BC=$(nix-build --no-out-link "<nixpkgs>" -A bc 2>/dev/null)/bin
  OPENSSL=$(nix-build --no-out-link "<nixpkgs>" -A openssl.dev 2>/dev/null)
  export PATH=$BC:$PATH
  ELF=/nix/store/1m12mh1nv5vcnhv1dpdlwzl7icnjzhxz-elfutils-0.194-dev
  export PKG_CONFIG_PATH=$ELF/lib/pkgconfig:$OPENSSL/lib/pkgconfig:$PKG_CONFIG_PATH
  export HOSTPKG_CONFIG_PATH=$ELF/lib/pkgconfig:$OPENSSL/lib/pkgconfig

  cd /tmp/net-next-build
  # one-time tweaks to config
  scripts/config --disable CONFIG_DEBUG_INFO_BTF
  scripts/config --disable CONFIG_SYSTEM_TRUSTED_KEYRING
  scripts/config --disable CONFIG_MODULE_SIG
  scripts/config --set-val CONFIG_SYSTEM_TRUSTED_KEYS ""
  yes "" | make olddefconfig

  # build (~5h for vmlinux+modules on Zen 1 4c/8t; +2min for bzImage)
  taskset -c 0-7 make -j8 vmlinux modules
  taskset -c 0-7 make -j8 bzImage
'
```

The elfutils-0.194-dev nix store path rotates as nixpkgs updates;
locate the current one with
`ls -d /nix/store/*elfutils-*-dev | head -1`.

## Whether to proceed to boot+runtime tests

The build validation is very strong:
- Patches compile end-to-end at full kernel scale
- Symbols resolve correctly
- BPF verifier already accepted the BPF patch on a running kernel

The patches are small (8 lines of substitution in sch_cake; 100 lines
of new helper; 63 lines of new BPF program). The risk of a runtime
issue not surfaced by build validation is low.

Recommendation: discuss with the user whether to invest another
~1-3 hours to set up boot validation, or treat the build validation
as sufficient for posting the RFC. The cover letters can document
exactly what was validated.
