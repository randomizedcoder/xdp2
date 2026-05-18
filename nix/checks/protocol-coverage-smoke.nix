# SPDX-License-Identifier: BSD-2-Clause-FreeBSD
#
# protocol-coverage-smoke — Phase 4 flake check of the
# protocol-coverage-matrix plan (see
# /home/das/.claude/profiles/personal/plans/in-this-folder-is-fuzzy-wigderson.md).
#
# Gates `nix flake check` on a curated 33-protocol subset of the
# proto_audit pcap templates. The subset (declared in
# samples/flow_dissector/parity_scope.json under
# `protocol_coverage_smoke_subset`) is hand-picked so that every
# (protocol, parser) cell is OK or REJ-expected under the current
# `expected_protocol_acceptance` schema (Phase 3). Any cell that
# becomes REJ-unexpected — for example, a parser starts rejecting
# a packet shape it used to accept — fails this check.
#
# Scope: same parser set as nix/checks/parity-gate.nix
# (excludes c-bpf-flowdis + c-bpf-fast which need CAP_BPF).
# c-bpf-xdp2 is included as the documented synthetic
# all-rejected baseline.

{ pkgs, lib, coverageMatrix }:

let
  scopeFile = ../../samples/flow_dissector/parity_scope.json;
  scopeRaw  = builtins.fromJSON (builtins.readFile scopeFile);
  subset    = scopeRaw.protocol_coverage_smoke_subset.protocols;
  subsetCsv = lib.concatStringsSep "," subset;
in
pkgs.runCommand "protocol-coverage-smoke"
{
  nativeBuildInputs = [ coverageMatrix pkgs.coreutils ];
  __noChroot = false;
  meta = {
    description = "Gate flake check on a curated 33-protocol subset of the coverage matrix";
  };
} ''
  set -eu
  OUT=$(mktemp -d)
  echo "[smoke] subset=${toString (builtins.length subset)} protocols"
  echo "[smoke] out=$OUT"

  # --require-expectations: any REJ-unexpected cell fails. Subset
  # was curated so today the gate passes; future regressions trip it.
  if protocol-coverage-matrix \
        --out "$OUT" \
        --protocols '${subsetCsv}' \
        --require-expectations \
        --jobs 4; then
    echo "[smoke] OK"
  else
    echo "[smoke] FAIL: REJ-unexpected cells in matrix:" >&2
    grep -E "REJ-unexpected" "$OUT/report/matrix.csv" >&2 || true
    echo "[smoke] See full matrix at $OUT/report/matrix.md" >&2
    exit 1
  fi

  cp "$OUT/report/matrix.md" "$out"
''
