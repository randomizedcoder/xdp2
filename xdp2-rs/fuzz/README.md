# XDP2-RS Fuzz Targets

Coverage-guided fuzz targets for the xdp2-rs packet parsers using
[cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) (libfuzzer).

## Prerequisites

cargo-fuzz requires the **nightly** Rust toolchain:

```bash
# Install cargo-fuzz
cargo install cargo-fuzz

# Or in a Nix shell with nightly Rust
nix develop  # ensure nightly is available
```

## Targets

| Target | Description |
|--------|-------------|
| `fuzz_graph_engine` | Graph engine `parse()` with raw bytes |
| `fuzz_mono_parser` | Monomorphized parser with raw bytes |
| `fuzz_compiled_parser` | Compiled (inline) parser with raw bytes |
| `fuzz_consistency` | Cross-mode oracle — asserts all 3 modes agree |
| `fuzz_all_modes` | All modes + templates, no consistency check (finds panics) |

## Running

```bash
# From the workspace root (xdp2-rs/)
cd fuzz

# Run a single target
cargo +nightly fuzz run fuzz_graph_engine

# Run with parallel workers
cargo +nightly fuzz run fuzz_all_modes -- -jobs=4 -workers=4

# Time-limited run (5 minutes)
cargo +nightly fuzz run fuzz_consistency -- -max_total_time=300

# Run all targets in parallel
for target in fuzz_graph_engine fuzz_mono_parser fuzz_compiled_parser \
              fuzz_consistency fuzz_all_modes; do
    cargo +nightly fuzz run $target -- -max_total_time=300 &
done
wait
```

## Seed Corpus

Seed packets are in `corpus/seed_packets/`. To regenerate:

```bash
# From xdp2-rs/
cargo test -p xdp2-fuzz -- seed_corpus  # verify seeds are valid
```

## Investigating Crashes

```bash
# Reproduce a crash
cargo +nightly fuzz run fuzz_graph_engine fuzz/artifacts/fuzz_graph_engine/crash-<hash>

# Minimize a crash input
cargo +nightly fuzz tmin fuzz_graph_engine fuzz/artifacts/fuzz_graph_engine/crash-<hash>
```
