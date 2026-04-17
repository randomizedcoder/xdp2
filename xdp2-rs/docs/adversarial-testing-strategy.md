# Adversarial Testing & Fuzzing Strategy

This document describes the multi-layered strategy for proving that all xdp2-rs
parsers safely handle malicious, corrupt, and malformed packet input. The goal
is zero panics, zero out-of-bounds accesses, and consistent behavior across all
four parser modes for any possible input byte sequence.

## Threat Model

The parser takes raw `&[u8]` from the network (or AF_XDP shared memory) and
must produce `Ok(FlowMeta)` or `Err(ParseError)` -- never panic, never access
out-of-bounds memory, never produce undefined behavior. Specific threats:

- **Truncated packets**: Header claims N bytes but only M < N remain
- **Inflated length fields**: IPv4 IHL=15 (60 bytes), AH hdrlen=255 (1028 bytes),
  IPv6 EH hdrlen=255 (2048 bytes), Geneve optlen=63 (260 bytes)
- **Zero-length fields**: IHL=0, TCP data_offset=0, TLV length=0
- **Invalid dispatch values**: Unknown ethertypes, invalid IP protocol numbers
- **Deep nesting**: GRE-in-GRE-in-GRE, VXLAN-in-VXLAN, 255 VLAN tags
- **Tunnel loops**: VXLAN wrapping Ethernet wrapping IP wrapping UDP wrapping VXLAN
- **All-zero / all-0xFF packets**: Adversarial field values across every header
- **Invalid flag combinations**: GRE with all flag bits set, reserved bits set
- **Cross-mode divergence**: One parser mode accepts what another rejects

## Safety Architecture

All 4 parser modes have engine-level bounds checking that catches
protocol-level `header_len()` overflows:

| Mode | Bounds check location | Mechanism |
|------|----------------------|-----------|
| Graph engine | `engine.rs:104` | `if hdr_len > remaining { Err(Length) }` |
| Mono parser | `graph_mono.rs:70` | `if hlen > hdr.len() { Err(Length) }` |
| Compiled parser | Inline per-protocol | `if rest.len() < N { Err(Length) }` |
| Template extractors | Per-template | `if pkt.len() < REQUIRED { Err(Length) }` |

Individual protocol `header_len()` methods compute sizes from untrusted packet
fields (e.g., `(ihl & 0x0F) * 4`) but do NOT validate against `maxlen` -- the
engine catches overflow values afterward. This strategy verifies that this
two-level design holds for every protocol and every parser mode.

### Known Risk: Tunnel Depth Reset

The compiled parser (`graph_compiled.rs:339,352`) resets depth to 0 when
entering VXLAN/Geneve tunnels, while GRE propagates depth. The graph engine
uses `max_encaps` to bound tunnel nesting. A crafted deeply-nested VXLAN packet
could cause the compiled parser to recurse deeper than other modes allow.

---

## Approach 1: cargo-fuzz (libfuzzer) -- Coverage-Guided Byte Fuzzing

[cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) uses LLVM's libfuzzer
for coverage-guided mutation. It is the standard Rust fuzzing tool, excels at
finding panics and bounds violations in `&[u8] -> Result` functions, and runs
in parallel natively.

### Fuzz Targets

| Target | What it tests | Entry point |
|--------|--------------|-------------|
| `fuzz_graph_engine` | Core parse loop | `engine::parse(parser, data)` |
| `fuzz_mono_parser` | Monomorphized parser | `graph_mono::parse_packet_mono(data, meta)` |
| `fuzz_compiled_parser` | Inline byte-read parser | `graph_compiled::parse_packet(data, meta)` |
| `fuzz_template_all` | All 63 template extractors | `template::extract_by_id(id, data, meta)` |
| `fuzz_consistency` | Cross-mode oracle | All 3 parsers, compare results |
| `fuzz_protocol_ops` | Individual header_len/next_proto | 25 variable-length Ops |
| `fuzz_tlv_parsing` | TLV sub-parser loop | `tlvs::parse_tlvs()` |
| `fuzz_flag_fields` | GRE flag-field parsing | `flag_fields::parse_flag_fields()` |
| `fuzz_pcap_mutate` | Mutated real-world packets | Seed corpus + mutations |

### Assertion Contract

```rust
// For per-mode targets: the ONLY assertion is no panic.
// Ok or Err are both acceptable; panics are bugs.
let _ = parse_function(data);
```

For `fuzz_consistency`: additionally assert that all 3 parser modes agree on
success/failure status and produce identical `FlowMeta` on success.

### Directory Structure

```
fuzz/
  Cargo.toml                    # Separate workspace (cargo-fuzz requirement)
  fuzz_targets/
    fuzz_graph_engine.rs        # Raw bytes -> graph engine
    fuzz_mono_parser.rs         # Raw bytes -> mono parser
    fuzz_compiled_parser.rs     # Raw bytes -> compiled parser
    fuzz_template_all.rs        # Template index + raw bytes -> all 63 extractors
    fuzz_consistency.rs         # Raw bytes -> all 3 parsers, compare
    fuzz_protocol_ops.rs        # Protocol index + raw bytes -> header_len/next_proto
    fuzz_tlv_parsing.rs         # Raw bytes -> TLV parser
    fuzz_flag_fields.rs         # Raw bytes -> flag-field parser
    fuzz_pcap_mutate.rs         # Seed index + mutation bytes -> parser
  corpus/
    seed_packets/               # ~60 minimal valid packets (one per protocol path)
```

### Running

```bash
# Single target, 4 parallel workers
cargo fuzz run fuzz_graph_engine -- -jobs=4 -workers=4

# All targets in parallel (see scripts/fuzz-all.sh)
scripts/fuzz-all.sh --duration 3600  # 1 hour per target
```

---

## Approach 2: proptest -- Structured Property-Based Testing

[proptest](https://github.com/proptest-rs/proptest) generates structurally
valid protocol headers with edge-case field values. It integrates as standard
`#[test]` functions, runs in CI, and produces reproducible regression files.

### Properties

1. **No-panic**: Any `Vec<u8>` of length 0..2000 -> all 4 parsers return
   `Ok` or `Err`, never panic
2. **Cross-mode consistency**: For any input, graph/mono/compiled agree on
   success/failure and produce identical `FlowMeta` when all succeed
3. **Idempotency**: Parsing the same input twice produces identical results
4. **Depth limiting**: Packets with >8 tunnel nesting layers produce an error
5. **Truncation safety**: For any valid packet that parses successfully,
   truncating at any byte offset 0..len either succeeds or returns
   `ParseError::Length` -- never panics

### Structured Generators

Protocol header builders with controlled field ranges including adversarial
edge cases:

| Protocol | Field | Valid range | Adversarial values |
|----------|-------|------------|-------------------|
| IPv4 | IHL | 5-15 | 0, 1, 2, 3, 4 |
| TCP | data_offset | 5-15 | 0, 1, 2, 3, 4 |
| IPv6 EH | hdrlen | 0-30 typical | 200, 254, 255 |
| AH | hdrlen | 1-10 typical | 0, 200, 254, 255 |
| Geneve | optlen | 0-10 typical | 50, 62, 63 |
| GRE | flags | Valid combos | All 16 C/K/S/R combinations |
| SCTP | chunk_length | 4-1400 typical | 0, 1, 2, 3, 65534, 65535 |

### Files

```
crates/xdp2-bench/tests/
  consistency_proptest.rs       # Cross-mode consistency property
  adversarial_headers.rs        # Adversarial protocol field values
  nesting_depth.rs              # Tunnel recursion limit testing
```

### Running

```bash
# Default (256 cases per property)
cargo test -p xdp2-bench --test consistency_proptest

# Extended (10K cases for CI nightly)
PROPTEST_CASES=10000 cargo test -p xdp2-bench
```

---

## Approach 3: PCAP Mutation -- Real-World Packet Corruption

Start from real protocol stacks that exercise real paths through the parser,
then systematically corrupt them. This catches issues that pure random bytes
would take billions of iterations to find, because the mutations operate on
packets that are already structurally close to valid.

### Mutation Strategies

| Strategy | Description | Target |
|----------|-------------|--------|
| Byte flip | Flip 1-4 random bytes in valid packets | General robustness |
| Truncation sweep | Cut packet at every offset 0..len | Length validation |
| Length field corruption | Overwrite IHL, data_offset, hdrlen with adversarial values | Variable-length headers |
| Dispatch randomization | Replace ethertype/protocol with random u16/u8 | Protocol table dispatch |
| Layer insertion | Duplicate or remove protocol headers | Nesting logic |
| Extension | Append random bytes beyond packet end | Trailing garbage handling |

### Seed Corpus

- ~60 minimal valid packets generated programmatically (one per protocol path
  through the 28-ethertype dispatch + IP transport + tunnel dispatch)
- 34 existing PCAPs in `data/pcaps/` covering GRE, VXLAN, IPv6, VLAN, L2TP,
  SRv6, QinQ, and more

### Integration with cargo-fuzz

The seed corpus feeds `fuzz/corpus/seed_packets/`. libfuzzer's coverage
guidance discovers interesting mutations from these seeds automatically. The
`fuzz_pcap_mutate` target uses the first byte of fuzz input to select a seed,
then XORs remaining bytes as mutations.

---

## Approach 4: Targeted Adversarial Unit Tests

Hand-crafted packets for specific known-dangerous patterns. Fast, deterministic,
and they document the exact threat model as executable specifications.

### Priority Attack Vectors

| # | Attack | Protocol | Risk |
|---|--------|----------|------|
| 1 | IHL=0 (header claims 0 bytes) | IPv4 | `ihl_bytes()` returns 0 |
| 2 | IHL=1-4 (below minimum 5) | IPv4 | Returns 4-16, below MIN_LEN=20 |
| 3 | data_offset=0 | TCP | Returns 0, below MIN_LEN=20 |
| 4 | hdrlen=255 | IPv6 EH | Claims 2048 bytes |
| 5 | hdrlen=255 | AH | Claims 1028 bytes |
| 6 | optlen=63 | Geneve | Claims 260 bytes |
| 7 | All flag bits set | GRE v0 | Invalid flags -> ParseError::BadFlag |
| 8 | chunk_length=0 | SCTP | TLV parser must catch zero-length |
| 9 | chunk_length=65535 | SCTP | Claims 64KB |
| 10 | VXLAN->Eth->IP->UDP->VXLAN loop | Compiled | Depth resets to 0 per tunnel |
| 11 | 255 VLAN tags chained | VLAN | Exceeds max_nodes/max_encaps |
| 12 | 255 IPv6 extension headers | IPv6 EH | Exceeds MAX_EH_DEPTH |
| 13 | Empty packet (0 bytes) | All modes | Must return Length, not panic |
| 14 | 1-byte packet | All modes | Must return Length, not panic |
| 15 | All-0xFF packet (1500 bytes) | All modes | Adversarial field values |
| 16 | All-0x00 packet (1500 bytes) | All modes | Zero-valued dispatch fields |

Each test constructs the exact byte sequence, runs it through all 4 parser
modes, and asserts: (a) no panic, (b) appropriate error code, (c) modes agree.

---

## Shared Infrastructure: `crates/xdp2-fuzz/`

```
crates/xdp2-fuzz/
  Cargo.toml                    # Depends on xdp2-core, xdp2-protocols, arbitrary, proptest
  src/
    lib.rs                      # Re-exports
    packet_builder.rs           # Composable Eth -> IP -> Transport header builders
    arbitrary_packets.rs        # Arbitrary trait impls for structured fuzzing
    pcap_mutator.rs             # PCAP read + mutation engine
    oracle.rs                   # Cross-mode consistency comparison
    seed_corpus.rs              # Generate minimal valid packets per protocol path
```

### Cross-Mode Oracle

The oracle is the most valuable piece of infrastructure. It runs a single input
through all parser modes and checks for divergence:

```rust
pub struct OracleResult {
    pub graph_result: Result<FlowMeta, ParseError>,
    pub mono_result: Result<FlowMeta, ParseError>,
    pub compiled_result: Result<FlowMeta, ParseError>,
    pub consistent: bool,
}

pub fn run_oracle(pkt: &[u8]) -> OracleResult {
    // Run all 3 parsers, compare success/failure and FlowMeta fields
}
```

### Prerequisites

1. `FlowMeta` and nested types need `PartialEq` derive for comparison
2. `xdp2-bench` needs a `[lib]` section so the fuzz crate can import parsers

---

## Parallelization

| Tool | Parallelism | Command |
|------|------------|---------|
| cargo-fuzz | libfuzzer `-jobs=N -workers=N` per target | `cargo fuzz run TARGET -- -jobs=4 -workers=4` |
| All fuzz targets | 9 independent processes | `scripts/fuzz-all.sh` |
| proptest | `cargo test -j N` standard parallelism | `PROPTEST_CASES=10000 cargo test -p xdp2-bench` |
| Truncation sweep | rayon `par_iter` over byte offsets | `(0..pkt.len()).into_par_iter()` |

With 9 fuzz targets running at 4 workers each on a 32-core Threadripper, all
targets run concurrently with full CPU utilization.

---

## Implementation Phases

### Phase 1: Foundation

- Add `PartialEq` derives to `FlowMeta` and all nested types
- Add `[lib]` to xdp2-bench, create `lib.rs` re-exporting parser modules
- Create `crates/xdp2-fuzz/` with oracle and seed corpus generation
- `cargo fuzz init` and implement core fuzz targets (graph, mono, compiled, consistency)
- Generate seed corpus (~60 minimal valid packets)

### Phase 2: Structured Fuzzing + Proptest

- Implement packet builders with `Arbitrary` derives
- Implement per-protocol-ops, TLV, and flag-field fuzz targets
- Write proptest suites (consistency, adversarial headers, nesting depth)

### Phase 3: PCAP Mutation + Templates

- Implement PCAP mutator and `fuzz_pcap_mutate` target
- Implement `fuzz_template_all` for 63 template extractors
- Write 16 targeted adversarial unit tests

### Phase 4: Coverage Analysis + CI

- Run `cargo fuzz coverage` to measure line coverage (goal: >95%)
- Create `scripts/fuzz-all.sh` for parallel fuzzing
- Add CI scheduled fuzzing (5 min per target on merge)
- Identify and fill any coverage gaps with additional seeds

---

## Success Criteria

1. **Zero panics** across all fuzz targets after 24h per target
2. **Zero cross-mode divergence** detected by the consistency oracle
3. **>95% line coverage** of `engine.rs`, all protocol Ops, and all parser modes
4. **All 16 adversarial unit tests pass** across all 4 parser modes
5. **Proptest suites pass** with 10,000+ cases per property
6. **CI integration** running fuzzing on every merge
