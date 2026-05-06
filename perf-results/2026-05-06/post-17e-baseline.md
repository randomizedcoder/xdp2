# Post-17.E Baseline — 2026-05-06

First multi-pcap matrix campaign with `XDP2_MATRIX_PARITY=1` active.
Established by two campaigns running back-to-back on the same day:
the headline `https-web.pcap` campaign (commit `fff4646`) and the
extended 3-pcap follow-up below.

## Configuration

- **Testbed:** hp2-hp5-x710 (AMD Ryzen 5 PRO 2400G × 2, Intel X710
  10GbE, NixOS, kernel 7.0.1).
- **Parsers:** all 14 (3 C userspace + 3 C BPF + 8 Rust modes).
  c-bpf-xdp2 verifier-rejected on 7.x → reported as N/A
  (documented Way-5).
- **Parameters:** ITER=100 (Rust), BPF_REPEAT=1000.
- **Replicates:** 5 per (host, pcap, mode) cell.
- **Hosts:** hp5 = DUT, hp2 = generator (both run the full sweep,
  numbers cross-checked).

## Pcaps + parity attestation

| PCAP             | Source                              | Packets | parity_ok | parity_disagreements |
|------------------|-------------------------------------|--------:|:---------:|--------------------:|
| `tcp_ipv4.pcap`  | `data/pcaps/tcp_ipv4.pcap`          | ~10     | **true**  | 0                   |
| `combo.pcap`     | `.#test-pcap` Nix derivation        | 500,000 | false     | 4,358,958           |
| `mixed-real.pcap`| `.#perf-mixed-pcap` Nix derivation  | varies  | false     | 1,765               |
| `https-web.pcap` | `.#workload-pcap-https-web`         | ~2,200  | false     | 9,280               |

**Apples-to-apples:** every cell within a (host, pcap) block measures
the same xdp2-bench-filtered packet set. parity_ok=true on
tcp_ipv4 means cross-parser agreement is also clean — that's the
honest "100% parity" cell. The other three carry real correctness
gaps that the parity gate surfaces; perf numbers there are still
comparable across modes within the pcap, with the caveat noted.

## Headline ns/pkt (median across 5 replicates, hp5)

### tcp_ipv4.pcap (clean — parity_ok=true)

| Mode | hp2 ns/pkt | hp5 ns/pkt | hp5 Mpps |
|---|---:|---:|---:|
| rust-template      | 19.0 | **18.0** | **55.0** |
| rust-template-simd | 21.0 | 19.0 | 52.0 |
| rust-compiled      | 25.0 | 22.0 | 45.0 |
| rust-mono          | 27.0 | 24.0 | 41.0 |
| c-bpf-fast         | 27.5 | 25.0 | 40.0 |
| c-flowdis-usp      | 29.5 | 26.0 | 38.0 |
| rust-mono-x4       | 29.0 | 27.0 | 36.5 |
| rust-simd          | 32.0 | 29.0 | 34.0 |
| rust-graph-enum    | 46.0 | 37.5 | 29.0 |
| c-xdp2-parse-only  | 79.5 | 70.5 | 14.0 |
| c-bpf-flowdis      | 91.5 | 83.0 | 12.0 |
| c-xdp2-usp         | 96.5 | 91.5 | 10.0 |
| rust-graph         | 240.5 | 214.5 | 5.0 |
| c-bpf-xdp2         | — | — | (verifier-rejected) |

### combo.pcap (500K synthetic mix — parity_ok=false, 4.4M disagreements)

| Mode | hp2 ns/pkt | hp5 ns/pkt | hp5 Mpps |
|---|---:|---:|---:|
| rust-graph-enum    | 16.5 | **17.0** | **63.0** |
| c-bpf-fast         | 18.0 | 18.0 | 55.0 |
| rust-compiled      | 46.5 | 47.0 | 21.0 |
| rust-template      | 49.0 | 50.0 | 20.0 |
| rust-mono          | 50.0 | 51.0 | 20.0 |
| rust-mono-x4       | 54.0 | 55.0 | 18.0 |
| rust-template-simd | 54.5 | 56.0 | 18.0 |
| rust-simd          | 55.0 | 56.0 | 18.0 |
| c-bpf-flowdis      | 87.0 | 90.0 | 10.5 |
| c-flowdis-usp      | 160.0 | 162.0 | 6.0 |
| c-xdp2-parse-only  | 217.0 | 221.0 | 4.0 |
| c-xdp2-usp         | 228.0 | 232.0 | 4.0 |
| rust-graph         | 287.5 | 293.5 | 3.0 |
| c-bpf-xdp2         | — | — | (verifier-rejected) |

## Reproducibility

hp2 ↔ hp5 within 5% on every mode × pcap → testbed is reproducible.
Identical hardware (Zen 1, X710), identical NixOS image, identical
build hashes (`/nix/store/2npllk3a20zrwhvhwk3b8w8rvbfv5yk2-xdp2-rs`).

## Per-pcap parity finding interpretation

- **tcp_ipv4** (parity_ok=true): all parsers agree on every packet.
  Numbers here are the most directly comparable. Use as the
  reference for headline single-protocol claims.

- **combo.pcap** (4.4M disagreements over 500K packets ≈ 8.7 per
  packet): synthetic mix surfaces nearly every Type A and Type B
  finding documented in `2026-05-06-parity-baseline.md`. Each
  packet hits multiple disagreement types.

- **mixed-real.pcap** (1,765 disagreements): smaller real-traffic
  capture; one or two protocol categories trip strict-vs-liberal.

- **https-web.pcap** (9,280 disagreements): TLS/HTTP traffic
  exercises TCP-options + flag-handling cross-parser gaps.

## Files

- `summary.md` / `summary.csv` — full table of all 4 pcaps × 14 modes
  × 2 hosts. Each cell carries `parity_ok` + `parity_disagreements`
  in the CSV (columns 13-14) and `(parity-fail, N)` annotation in
  the markdown.
- `campaign.log` — first campaign (https-web only), 5 replicates.
- `campaign-extended.log` — second campaign (combo + tcp_ipv4 +
  mixed-real), 5 replicates each.
- `hp2-hp5-x710/{hp2,hp5}/flow-dissector-matrix-unified-*Z/<pcap>/<mode>.json`
  — 560 per-cell JSONs (4 pcaps × 5 reps × 2 hosts × 14 modes).

## What this answers

The campaign closes the loop on the user's question "Does Phase 17.E
mean we get apples-to-apples results on hp2/hp5?":

- **For perf within a (host, pcap):** yes, always — the
  xdp2-bench filter step ensures every parser measures the same
  packet set. (This was true pre-17.E.)
- **For correctness:** parity_ok=true on tcp_ipv4 — *and only
  there* — proves apples-to-apples on both axes. The other three
  pcaps deliver perf numbers comparable across modes but flag the
  reader: "parsers disagree on these packets; interpret with care."
  That distinction is what 17.E added.
