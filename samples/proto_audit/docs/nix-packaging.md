# Nix Packaging

proto-audit uses Nix flakes for reproducible builds, external source pinning,
and cached report generation. All external sources are Nix-pinned so builds
are fully deterministic. See the comments at the top of
`nix/proto-audit-sources.nix` for the complete guide on adding new sources.

## nix/proto-audit.nix

Rust package build using `rustPlatform.buildRustPackage`. When `Cargo.lock`
changes, update `cargoHash`:

1. Set `cargoHash = pkgs.lib.fakeHash;`
2. Run `nix build .#proto-audit`
3. Copy the correct hash from the error message
4. Paste it back into `cargoHash`

## nix/proto-audit-sources.nix

External source pinning, patching, and provisioning:

| Output | Source | Patching |
|---|---|---|
| `kernelSrc` | Linux 6.12 `include/` + `drivers/net/` + `net/` trees | None |
| `dpdkSrc` | DPDK `lib/net/*.h` protocol headers | None |
| `ndpiSrc` | nDPI `src/include/` headers (ndpi_typedefs.h) | None |
| `pppdSrc` | pppd `pppd/*.h` + `include/` headers | None |
| `scapyPython` | Python 3.14 + scapy | None |
| `tshark` | wireshark-cli binary | None |
| `etherparseSrc` | GitHub-pinned etherparse crate | 332 per-protocol overlay patches |
| `libpcapSrc` | GitHub-pinned libpcap source | 332 per-protocol overlay patches |

### Source Patching with `applyPatches`

etherparse and libpcap sources are extended with per-protocol overlay struct
patches using Nix's `pkgs.applyPatches`. A helper function `patchesIn`
dynamically reads all `.patch` files from a directory, so adding a new
protocol requires only dropping a `.patch` file — no Nix changes needed:

```nix
# Helper: collect all .patch files from a directory
patchesIn = dir:
  map (f: dir + "/${f}")
    (builtins.filter (f: pkgs.lib.hasSuffix ".patch" f)
      (builtins.attrNames (builtins.readDir dir)));

# etherparse with 31 overlay struct patches
etherparseSrc = pkgs.applyPatches {
  src = pkgs.fetchFromGitHub {
    owner = "JulianSchmid";
    repo = "etherparse";
    rev = "f87e17057...";
    hash = "sha256-...";
  };
  patches = patchesIn ../samples/proto_audit/patches/etherparse;
};

# libpcap with 18 overlay struct patches
libpcapSrc = pkgs.applyPatches {
  src = pkgs.fetchFromGitHub {
    owner = "the-tcpdump-group";
    repo = "libpcap";
    rev = "ccc5817bd...";
    hash = "sha256-...";
  };
  patches = patchesIn ../samples/proto_audit/patches/libpcap;
};
```

Each patch creates a single new file (e.g., `src/proto_audit/gre.rs` or
`pcap/proto_audit/gre.h`), making patches order-independent and
conflict-free. See [Source Patching](patching.md) for the full list of
overlay protocols and fine-grained field analysis.

## Flake Outputs

| Output | Description |
|---|---|
| `proto-audit` | `writeShellApplication` wrapper setting all `PROTO_AUDIT_*` env vars |
| `proto-audit-bin` | Raw Rust binary (no env defaults) |
| `proto-audit-report` | Cached derivation producing `matrix.txt`, `findings.txt`, `audit.json` |

The `proto-audit` wrapper sets environment variables so the tool finds all
external sources without CLI flags. See the
[environment variable table](field-matching.md#environment-variables) in
field-matching.md for the full list.
