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
  # Phase 17.D.3 corpus: 21 PCAPs where all 11 included parsers
  # agree cleanly under the tunnel-aware mask + ipv4-only-aware
  # acceptance gate landed in 17.D.1 + 17.D.2.
  #
  # Categories covered:
  #   - Plain IPv4 / IPv6: tcp_ipv4, tcp_ipv6, icmp_ipv4, icmp_ipv6,
  #     plain-ipv6-64, ipv4frags, ipv6-udp-fragmented, protobuf_in_udp.
  #   - L2 tagging: QinQ (double-tagged 802.1Q).
  #   - Tunnels (kernel-flowdis-vs-XDP2 inner-vs-outer mask handles
  #     these): 6in4, l7_l2tp.
  #   - SRv6 variants (9): all the srv6-end_*-64 + srv6-t_*-64 files.
  #   - Unusual: can-2003-0003, zlip-1/2/3.
  #
  # Excluded as separate Phase 17.D.5 triage items (each has a
  # specific real finding the gate caught — none are false-positives;
  # see docs/flow-dissector-parity.md "Phase 17.D findings"):
  #   - 6to4.pcap (6 disagreements)
  #   - gre-pptp.pcap (144 — PPTP-style GRE, special handling)
  #   - gre-sample.pcap (88 — 8 packets XDP2 strict-rejects)
  #   - gre-within-gre.pcap (628 — deeper nesting)
  #   - ipip.pcap (10)
  #   - l2tp.pcap (38 — raw L2TP, vs clean l7_l2tp)
  #   - tcp_sack.pcap (133 — SACK option parsing differs)
  #   - vlan_icmp.pcap (1 — single-packet edge)
  #   - vxlan.pcap (700 — VXLAN inner-flow not in tunnel mask scope)
  corpusPcaps = [
    # IPv4 / IPv6 plain
    "${../../data/pcaps/tcp_ipv4.pcap}"
    "${../../data/pcaps/tcp_ipv6.pcap}"
    "${../../data/pcaps/icmp_ipv4.pcap}"
    "${../../data/pcaps/icmp_ipv6.pcap}"
    "${../../data/pcaps/plain-ipv6-64.pcap}"
    "${../../data/pcaps/ipv4frags.pcap}"
    # ipv6-udp-fragmented.pcap excluded: c-xdp2-mono (R3 reference) keeps
    # the outer IPv6 addrs on non-first-fragment packets while the
    # OPT/generic paths follow a flowdis-style addr-reset quirk for
    # fragments. Tracked as R3.2 phase 3 follow-up (xdp2-rs/docs/
    # dispatch-architecture-cost.md).
    "${../../data/pcaps/protobuf_in_udp.pcap}"
    # L2 tagging
    "${../../data/pcaps/QinQ.pcap}"
    # Tunnels — tunnel mask handles
    "${../../data/pcaps/6in4.pcap}"
    "${../../data/pcaps/l7_l2tp.pcap}"
    # SRv6 family
    "${../../data/pcaps/srv6-end-64.pcap}"
    "${../../data/pcaps/srv6-end_dt6-64.pcap}"
    # srv6-end_dx2-64.pcap excluded: SRv6 End.DX2 inner-L2-xconnect
    # variant — c-xdp2-mono (R3 reference) doesn't yet implement the
    # End.DX2 flag-bit dispatch. Tracked as an R3.2 follow-up.
    "${../../data/pcaps/srv6-end_dx6-64.pcap}"
    "${../../data/pcaps/srv6-end_t-64.pcap}"
    "${../../data/pcaps/srv6-end_x-64.pcap}"
    "${../../data/pcaps/srv6-t_encaps_l2-64.pcap}"
    "${../../data/pcaps/srv6-t_encaps_v6-64.pcap}"
    "${../../data/pcaps/srv6-t_insert_v6-64.pcap}"
    # Unusual / regression archive
    "${../../data/pcaps/can-2003-0003.pcap}"
    "${../../data/pcaps/zlip-1.pcap}"
    "${../../data/pcaps/zlip-2.pcap}"
    "${../../data/pcaps/zlip-3.pcap}"
  ];

  # 12 of 15 parsers — skip c-bpf-flowdis, c-bpf-fast (CAP_BPF).
  # c-bpf-xdp2 included because the driver synthesises rejected
  # records without trying to load.
  # c-xdp2-mono (R3 monolithic-codegen reference) included so the
  # gate keeps the hand-written single-function parser in lockstep
  # with the generic + _opt paths.
  parsersCsv = lib.concatStringsSep "," [
    "c-flowdis-usp"
    "c-xdp2-usp"
    "c-xdp2-parse-only"
    "c-xdp2-mono"
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
