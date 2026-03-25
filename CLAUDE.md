# XDP2 Development Notes

## Nix

This project uses Nix flakes for all builds, tests, and development environments. Always use `nix develop`, `nix build`, or `nix run` — never install dependencies manually.

Key targets:
- `nix develop` — development shell with all tools
- `nix build .#xdp2` — production build
- `nix build .#proto-audit` — protocol audit tool (wrapped with all sources)
- `nix build .#proto-audit-report` — full cached audit report
- `nix run .#proto-audit -- <subcommand>` — run proto-audit interactively
- `nix develop --command cargo test` — run Rust tests (from samples/proto_audit/)

## proto-audit

The proto-audit tool lives in `samples/proto_audit/`. It compares protocol definitions across XDP2, Linux kernel, Scapy, and tshark.

- Rust source: `samples/proto_audit/src/`
- Nix packaging: `nix/proto-audit.nix` (build), `nix/proto-audit-sources.nix` (external sources)
- The `proto-audit` flake output is a `writeShellApplication` wrapper that sets `PROTO_AUDIT_*` env vars
- The `proto-audit-bin` output is the raw Rust binary without env var defaults
- When updating Cargo dependencies, you must update `cargoHash` in `nix/proto-audit.nix` (set to `pkgs.lib.fakeHash`, build, copy the hash from the error)
