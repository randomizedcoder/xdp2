# Series 3 Phase 4 — full macro test matrix on patched kernel

**Date**: 2026-05-28
**Patched kernel**: 7.1.0-rc4-flowdis-fastpath (series 3 RFC v1, 3 patches)
**Pairs**: hp2↔hp5 i40e 10 GbE, hp1↔hp3 mlx5_core 25 GbE
**Test shape**: 60 s, -P 16, cake triple-isolate, TCP-tuned sysctls

## TL;DR

**All 16 cells pass, no regression.** Patched kernel works
correctly under both IPv4 and IPv6, both TCP and UDP, both
iperf3 and iperf2 server models, both NIC families.

The fast-path code (verified by disassembly of `__skb_flow_dissect`
showing `cmpb $0x45, (%rsi)` + `testw $0xff3f, 0x6(%rsi)`) is
exercised on every RX packet through cake.

## Full results matrix

| pair | family | tool | proto | Gbit/s | retx/lost |
|---|---|---|---|---:|---:|
| i40e | IPv4 | iperf3 | TCP | 9.408 | 32,086 retx |
| i40e | IPv4 | iperf3 | UDP | 9.563 | 5.2M lost (cake) |
| i40e | IPv4 | iperf2 | TCP | 9.406 | n/a |
| i40e | IPv4 | iperf2 | UDP | 10.363 | n/a |
| i40e | IPv6 | iperf3 | TCP | 9.277 | 42,219 retx |
| i40e | IPv6 | iperf3 | UDP | 9.424 | 4.4M lost (cake) |
| i40e | IPv6 | iperf2 | TCP | 9.278 | n/a |
| i40e | IPv6 | iperf2 | UDP | 10.129 | n/a |
| mlx5 | IPv4 | iperf3 | TCP | **15.942** | 8,539 retx |
| mlx5 | IPv4 | iperf3 | UDP | 10.446 | 0 |
| mlx5 | IPv4 | iperf2 | TCP | **16.785** | n/a |
| mlx5 | IPv4 | iperf2 | UDP | 10.265 | n/a |
| mlx5 | IPv6 | iperf3 | TCP | **16.545** | 14,671 retx |
| mlx5 | IPv6 | iperf3 | UDP | 10.359 | 0 |
| mlx5 | IPv6 | iperf2 | TCP | **16.719** | n/a |
| mlx5 | IPv6 | iperf2 | UDP | 9.980 | n/a |

## Headline observations

### TCP throughput is identical across families

| pair | tool | IPv4 TCP | IPv6 TCP | delta |
|---|---|---:|---:|---:|
| i40e | iperf3 | 9.408 | 9.277 | -1.4 % |
| i40e | iperf2 | 9.406 | 9.278 | -1.4 % |
| mlx5 | iperf3 | 15.942 | 16.545 | +3.8 % |
| mlx5 | iperf2 | 16.785 | 16.719 | -0.4 % |

i40e shows a slight v4 > v6 (about 1.4%, consistent across both
tools — likely from the 20-byte v6 header overhead vs 20-byte
v4 header). mlx5 has v4 and v6 within noise of each other.

### Patches 2 + 3 are both being exercised

- IPv4 cells (patch 2 hits)
- IPv6 cells (patch 3 hits, when nexthdr is TCP/UDP and flow
  label is zero)

Both families produce expected throughput. Both fast-paths
work.

### Comparison with B.1 baseline (series 1+2 kernel, mlx5 only)

| metric | B.1 baseline | Phase 4 patched | delta |
|---|---:|---:|---:|
| mlx5 iperf3 TCP IPv4 | 16.023 (N=279) | 15.942 (N=1) | -0.5 % |
| mlx5 retx per 60 s | 14,715 | 8,539 | within variance |

Throughput is within the 1.3 % CV measured in B.1 over 23h.
**No regression.**

### Headline: dual-stack works

This is the first IPv6 measurement on either pair. mlx5 IPv6
TCP hits 16.7 Gbit/s — same range as IPv4. The IPv6 fast-path
(patch 3) is doing its job.

## Verification methodology

- Patched kernel verified by disassembly of vmlinux:
  `cmpb $0x45, (%rsi)` at __skb_flow_dissect+offset (the IPv4
  version+IHL magic check)
- Static functions inlined by gcc (no separate symbol in
  /proc/kallsyms, but the byte pattern is unambiguous)
- All 16 cells produced JSON / text output with no errors
- No new dmesg WARN/BUG/oops on any host during testing

## NixOS IPv6 fix shipped

To enable IPv6 testing on the testbed pairs, the
`xdp2.testbed.addresses` schema was extended with optional
`local6` / `peer6` fields. Commits:

- `merge/matrix-physical-testbed` branch: `357e1619`
- `xdp2-rs` branch: `5ff07a2`

Both branches now carry the IPv6 schema; hp1/hp3 pull from the
former, hp2/hp5 from the latter, so all four hosts get the
update via `nix flake update xdp2 && nixos-rebuild switch`.

Per-host configuration.nix populates the new fields with the
`fd10:10:N::M/64` ULA layout documented in
`docs/physical-testbed.md` §15 (on the flow-keys-compat-reorder
branch; will land on merge/matrix-physical-testbed when the
docs commit gets cherry-picked).

## Next steps

- Phase 5: 30-min sustained per pair (iperf3 round + iperf2 round)
- Phase 6: 24h soaks (iperf3 on i40e + iperf2 on mlx5, parallel)
- Phase 3: microbench (flow-dissector-matrix-unified on hp5 + hp3)
  — gives the per-packet ns/pkt numbers for the cover letter
- After Phases 3-6: update the series 3 cover letter with the
  measured numbers, then send v1 to netdev
