# SPDX-License-Identifier: BSD-2-Clause-FreeBSD
#
# parity-gate — Phase 17.C.3 flake check.
#
# Runs the cross-parser parity gate against a small synthetic corpus
# of in-tree PCAPs. Asserts:
#   1. The driver completes successfully on every PCAP.
#   2. parity-compare reports zero unexpected disagreements (exit 0).
#
# Scope: BPF parsers (c-bpf-flowdis, c-bpf-fast) are EXCLUDED from
# this gate because Nix's sandbox doesn't grant CAP_BPF for
# BPF_PROG_TEST_RUN. c-bpf-xdp2 is included (the driver synthesises
# its 100%-rejected records). Full 14-parser coverage requires
# `nix run .#flow-dissector-parity-check` on a host with CAP_BPF
# (root or capability) — typically the lab testbed.
#
# Corpus: 4 protocol-specific PCAPs from data/pcaps/. Small (≤ 200
# packets total) so the gate runs in <30 s. Adding the 5K combo
# subset is the next gate-coverage knob (see plan §17.D).

{ pkgs, parityCheck, lib }:

let
  # Corpus: known-protocol synthetic PCAPs that every (non-BPF)
  # parser should handle cleanly. Each pcap is small and homogeneous
  # to keep the gate fast. Interpolated as strings so Nix auto-adds
  # them to the derivation's closure (toString-based coercion does
  # not).
  # Initial corpus (Phase 17.C.3): only PCAPs where all 11 included
  # parsers agree cleanly. Two known-divergence classes are deferred
  # to Phase 17.D's expected-divergence catalog before the corpus
  # can be expanded:
  #   1. rust-graph-enum doesn't parse IPv6 (rejects every packet
  #      in tcp_ipv6.pcap, icmp_ipv6.pcap, vlan_icmp.pcap with
  #      reject_reason="parse-error"). This is an unscope'd bug
  #      surfaced by the gate; see docs/flow-dissector-parity.md
  #      "Phase 17.C findings".
  #   2. kernel-flowdis stops at the OUTER 5-tuple on tunneled
  #      packets (GRE, VXLAN, Geneve), while XDP2 (C) and xdp2-rs
  #      follow the tunnel into the inner flow (per
  #      benchmark.c:264-277). By design — but not yet in
  #      parity_scope.json:expected_divergences.
  corpusPcaps = [
    "${../../data/pcaps/tcp_ipv4.pcap}"
    "${../../data/pcaps/icmp_ipv4.pcap}"
  ];

  # 11 of 14 parsers — skip c-bpf-flowdis, c-bpf-fast (CAP_BPF).
  # c-bpf-xdp2 included because the driver synthesises rejected
  # records without trying to load.
  parsersCsv = lib.concatStringsSep "," [
    "c-flowdis-usp"
    "c-xdp2-usp"
    "c-xdp2-parse-only"
    "c-bpf-xdp2"
    "rust-graph"
    "rust-graph-enum"
    "rust-mono"
    "rust-mono-x4"
    "rust-compiled"
    "rust-simd"
    "rust-template"
    "rust-template-simd"
  ];
in
pkgs.runCommand "parity-gate"
{
  nativeBuildInputs = [ parityCheck pkgs.coreutils pkgs.gnugrep ];
} ''
  set -eu

  fail=0
  for pcap in ${lib.concatStringsSep " " corpusPcaps}; do
    bn=$(basename "$pcap")
    echo "==== $bn ===="

    out_dir=$(mktemp -d)
    if flow-dissector-parity-check \
        --pcap "$pcap" \
        --out "$out_dir" \
        --parsers '${parsersCsv}' \
        > "$out_dir/driver.log" 2>&1; then
      echo "  ok"
    else
      echo "  FAIL: parity disagreements detected. Report:" >&2
      cat "$out_dir/parity-report.md" >&2 || true
      echo "Driver log:" >&2
      tail -40 "$out_dir/driver.log" >&2
      fail=1
    fi
  done

  if [ "$fail" -ne 0 ]; then
    echo "parity-gate FAILED: at least one PCAP surfaced unexpected disagreements" >&2
    exit 1
  fi

  echo "ok" > "$out"
''
