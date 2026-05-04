# SPDX-License-Identifier: BSD-2-Clause-FreeBSD
#
# aggregate-results-test — pure-Nix check for Phase 6.
#
# Builds a tiny synthetic Phase-5 result tree, runs the aggregator,
# and asserts:
#   1. summary.md and summary.csv exist
#   2. summary.csv parses with csv.DictReader and has expected rows
#   3. summary.md mentions every input host and pcap
#   4. With --baseline pointing at a fixture that disagrees on one
#      cell, regressions.md flags exactly that cell.
#   5. With --baseline pointing at an "incomplete" CSV (median = "?"),
#      the aggregator exits non-zero with the documented message.

{ pkgs, lib }:

let
  aggregator = import ../aggregate-results.nix { inherit pkgs; };
in
pkgs.runCommand "aggregate-results-test"
{
  nativeBuildInputs = [ aggregator pkgs.python3 pkgs.gnugrep pkgs.coreutils ];
} ''
  set -eu

  ROOT=$PWD/results
  HOST5=$ROOT/2026-05-04/hp2-hp5-x710/hp5/run-001/combo.pcap
  HOST2=$ROOT/2026-05-04/hp2-hp5-x710/hp2/run-001/combo.pcap
  HOST5B=$ROOT/2026-05-04/hp2-hp5-x710/hp5/run-001/tcp_ipv4.pcap
  mkdir -p "$HOST5" "$HOST2" "$HOST5B"

  cell() {
    local path=$1 mode=$2 pcap=$3 ns=$4 mpps=$5 iter=$6
    cat > "$path/$mode.json" <<JSON
  {"mode":"$mode","pcap":"$pcap","ns_per_pkt":$ns,"mpps":$mpps,"iterations":$iter,"build_hash":"x","kernel":"6.18.22","nic_driver":"i40e","nic_firmware":""}
  JSON
  }

  cell "$HOST5"  rust-graph    combo.pcap     12 80  100
  cell "$HOST5"  rust-mono     combo.pcap     50 19  100
  cell "$HOST5"  c-flowdis-usp combo.pcap    120 8   100
  cell "$HOST2"  rust-graph    combo.pcap     13 79  100
  cell "$HOST5B" rust-graph    tcp_ipv4.pcap  21 47  100

  flow-dissector-matrix-aggregate --results "$ROOT"

  test -f "$ROOT/summary.md"  || { echo "summary.md missing"; exit 1; }
  test -f "$ROOT/summary.csv" || { echo "summary.csv missing"; exit 1; }

  # CSV must parse and contain at least 5 data rows.
  python3 - <<'PY'
  import csv, sys
  rows = list(csv.DictReader(open("results/summary.csv")))
  assert len(rows) == 5, f"expected 5 rows, got {len(rows)}: {rows}"
  hosts = {r["host"] for r in rows}
  assert hosts == {"hp2", "hp5"}, f"unexpected hosts: {hosts}"
  modes = {r["mode"] for r in rows}
  assert "rust-graph" in modes and "c-flowdis-usp" in modes, f"missing modes: {modes}"
  print("csv parse ok:", len(rows), "rows")
  PY

  grep -q 'hp2-hp5-x710' "$ROOT/summary.md" || { echo "testbed missing from summary.md"; exit 1; }
  grep -q 'combo.pcap'   "$ROOT/summary.md" || { echo "pcap missing from summary.md"; exit 1; }
  grep -q 'rust-graph'   "$ROOT/summary.md" || { echo "mode missing from summary.md"; exit 1; }

  # Build a baseline that agrees with hp5/rust-graph but disagrees
  # massively on hp2/rust-graph (claim 1 ns/pkt baseline; new is 13).
  cat > baseline.csv <<'CSV'
  testbed,host,pcap,mode,n_iter,n_replicates,ns_per_pkt_mean,ns_per_pkt_median,ns_per_pkt_p95,ns_per_pkt_ci95_lo,ns_per_pkt_ci95_hi,mpps_median,build_hash,kernel,nic_driver,nic_firmware
  hp2-hp5-x710,hp5,combo.pcap,rust-graph,100,1,12,12,12,11,13,80,x,6.18.22,i40e,
  hp2-hp5-x710,hp2,combo.pcap,rust-graph,100,1,1,1,1,0.5,1.5,80,x,6.18.22,i40e,
  CSV

  flow-dissector-matrix-aggregate --results "$ROOT" --baseline baseline.csv
  test -f "$ROOT/regressions.md" || { echo "regressions.md missing"; exit 1; }
  grep -q '^| hp2-hp5-x710 | hp2 |' "$ROOT/regressions.md" \
    || { echo "expected hp2 regression row in regressions.md"; cat "$ROOT/regressions.md"; exit 1; }
  # hp5/rust-graph must NOT regress (matches baseline).
  if grep -q '^| hp2-hp5-x710 | hp5 | combo.pcap | rust-graph' "$ROOT/regressions.md"; then
    echo "false positive: hp5/rust-graph flagged as regression"
    cat "$ROOT/regressions.md"
    exit 1
  fi

  # Incomplete baseline (median = "?") must fail loudly.
  cat > incomplete.csv <<'CSV'
  testbed,host,pcap,mode,n_iter,n_replicates,ns_per_pkt_mean,ns_per_pkt_median,ns_per_pkt_p95,ns_per_pkt_ci95_lo,ns_per_pkt_ci95_hi,mpps_median,build_hash,kernel,nic_driver,nic_firmware
  hp2-hp5-x710,hp5,combo.pcap,rust-graph,100,1,?,?,?,?,?,?,x,6.18.22,i40e,
  CSV
  if flow-dissector-matrix-aggregate --results "$ROOT" --baseline incomplete.csv 2> err.log; then
    echo "incomplete baseline did not fail as expected"; cat err.log; exit 1
  fi
  grep -q 'baseline incomplete' err.log \
    || { echo "incomplete baseline error message missing"; cat err.log; exit 1; }

  # --fail-on-regression: same hp2 disagreement, exit must be non-zero.
  if flow-dissector-matrix-aggregate --results "$ROOT" --baseline baseline.csv --fail-on-regression; then
    echo "--fail-on-regression did not propagate non-zero exit"; exit 1
  fi

  echo ok > $out
''
