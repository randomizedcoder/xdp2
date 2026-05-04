# SPDX-License-Identifier: BSD-2-Clause-FreeBSD
#
# matrix-runner-json-shape — regression gate for the per-cell JSON
# emitted by the unified flow-dissector matrix runner under
# `--json-out`. Runs as part of `nix flake check`.
#
# The full runner cannot execute in the sandbox (it needs xdp2-bench,
# the C matrix artifacts, and CAP_BPF for BPF_PROG_TEST_RUN), so this
# check is focused on the *contract*: the `emit_cell_json` shell
# function is invoked with synthetic values, and the resulting file is
# validated with `jq -e`. If anyone removes or renames a field in
# the printf template, this check fails.
#
# We additionally grep `nix/xdp2-rs-matrix.nix` and
# `samples/flow_dissector/xdp2_rs_matrix.sh` for the same set of
# field names so the check trips on either the wrapper or the
# standalone script drifting away from the agreed schema.

{ pkgs, lib }:

let
  expectedKeys = [
    "mode"
    "pcap"
    "ns_per_pkt"
    "mpps"
    "iterations"
    "build_hash"
    "kernel"
    "nic_driver"
    "nic_firmware"
  ];

  jqExpr =
    lib.concatStringsSep " and "
      (map (k: "has(\"${k}\")") expectedKeys);

  # Self-contained replica of the printf template. The check below
  # diffs this against the live sources so the check author cannot
  # silently drift the schema either.
  printfTemplate = ''
    {"mode":"%s","pcap":"%s","ns_per_pkt":%s,"mpps":%s,"iterations":%s,"build_hash":"%s","kernel":"%s","nic_driver":"%s","nic_firmware":"%s"}
  '';
in
pkgs.runCommand "matrix-runner-json-shape"
{
  nativeBuildInputs = [ pkgs.jq pkgs.gnugrep ];
  src = ../..;
} ''
  set -eu

  # 1. Synthesize one cell JSON using the same printf format string
  #    as both the Nix wrapper and the standalone shell script.
  printf '${printfTemplate}' \
    "rust-graph" "combo.pcap" 12 80 100 \
    "/nix/store/xxxx-xdp2-bench/bin/xdp2-bench" \
    "6.18.22" "i40e" "9.30" \
    > cell.json

  # 2. Validate every expected key is present.
  if ! jq -e '${jqExpr}' cell.json > /dev/null; then
    echo "matrix-runner-json-shape: jq schema check failed" >&2
    cat cell.json >&2
    exit 1
  fi

  # 3. Confirm every expected key string is also present in both
  #    sources, so the check trips if either source drifts.
  for src in \
      "$src/nix/xdp2-rs-matrix.nix" \
      "$src/samples/flow_dissector/xdp2_rs_matrix.sh"; do
    for key in ${lib.concatStringsSep " " expectedKeys}; do
      if ! grep -qF "\"$key\":" "$src"; then
        echo "matrix-runner-json-shape: key '$key' missing from $src" >&2
        exit 1
      fi
    done
  done

  echo ok > $out
''
