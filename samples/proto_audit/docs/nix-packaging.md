# Nix Packaging

proto-audit uses Nix flakes for reproducible builds, external source pinning,
and cached report generation. All external sources (kernel headers, Scapy,
tshark, etherparse, libpcap) are Nix-pinned so builds are fully deterministic.

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
| `kernelSrc` | Linux 6.12 `include/` tree | None |
| `scapyPython` | Python 3.14 + scapy | None |
| `tshark` | wireshark-cli binary | None |
| `etherparseSrc` | GitHub-pinned etherparse crate | 31 per-protocol overlay patches |
| `libpcapSrc` | GitHub-pinned libpcap source | 18 per-protocol overlay patches |

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

| Output | Kind | Description |
|---|---|---|
| `proto-audit` | `nix run` / `nix build` | `writeShellApplication` wrapper setting all `PROTO_AUDIT_*` env vars. Interactive entry point for every subcommand. |
| `proto-audit-bin` | `nix build` | Raw Rust binary (no env defaults). Useful when you want to override paths yourself. |
| `proto-audit-report` | `nix build` (cached) | Runs `audit`, `matrix`, `findings`, `list`, and XDP2 `scan` in text + JSON form. Outputs land in `result/{audit,matrix,findings,protocols,xdp2-scan}.{txt,json}`. |
| `proto-audit-c-check` | `nix build` (cached) | Generates every curated-tier protocol as a C header (`generate-all --target c --tier curated`) and compile-tests each with `clang -fsyntax-only -target bpf`. Outputs: `result/headers/*.h`, `result/logs/{generate.log,compile.log,failures.txt,summary.txt}`. Catches generator regressions across the whole curated set. |
| `proto-audit-validate-all` | `nix build` (cached) | Runs `validate --proto all --tier curated --json` — IR→PCAP→tshark→IR round-trip for every curated protocol. Outputs: `result/validate_all.json` plus an `audit_baseline.json` for regression tracking. Use as the baseline for CI regressions. |

### Typical invocations

    # Ad-hoc query (interactive; scapy/tshark already wired)
    nix run .#proto-audit -- list
    nix run .#proto-audit -- compare --proto IPv4
    nix run .#proto-audit -- validate --proto TCP

    # Pre-built cached reports — reproducible across machines
    nix build .#proto-audit-report        && cat  result/matrix.txt
    nix build .#proto-audit-c-check       && cat  result/logs/summary.txt
    nix build .#proto-audit-validate-all  && head result/validate_all.json

### CI usage

`proto-audit-c-check` and `proto-audit-validate-all` are the two
regression gates: each produces a deterministic output that can be
diffed against a previous run to detect generator or extractor drift.
The summary files (`logs/summary.txt`, `validate_all.json`) are small
enough to commit as baselines.

The `proto-audit` wrapper sets environment variables so the tool finds all
external sources without CLI flags. See the
[environment variable table](field-matching.md#environment-variables) in
field-matching.md for the full list.
