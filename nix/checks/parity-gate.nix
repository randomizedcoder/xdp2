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
  # PCAP corpus is declared in data/pcap-manifest.toml — single
  # source of truth for which pcaps are gated vs which are
  # documented-and-excluded. See `pcap-manifest.toml` for rationale
  # on each excluded pcap (Phase 17.D findings: 6to4, gre-*,
  # ipip, l2tp, tcp_sack, vlan_icmp, vxlan, ipv6-udp-fragmented,
  # srv6-end_dx2-64) and the broader categorisation.
  #
  # Loaded at eval time via builtins.fromTOML, no IFD, no runtime
  # dep. Adding/removing a pcap is a one-line edit in the manifest;
  # this Nix file does not change.
  repoRoot = ../..;
  manifest = builtins.fromTOML (builtins.readFile (repoRoot + "/data/pcap-manifest.toml"));
  # Filter to pcaps whose `included_in` includes "parity_gate".
  gateEntries = lib.filterAttrs
    (_: e: builtins.elem "parity_gate" (e.included_in or []))
    manifest.pcap;
  # Resolve each manifest path (repo-rooted, e.g. "data/pcaps/tcp_ipv4.pcap")
  # to a Nix store path. Interpolate as string so the file is
  # auto-copied into the derivation's closure.
  corpusPcaps = lib.mapAttrsToList
    (_: e: "${repoRoot + "/${e.path}"}")
    gateEntries;

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
