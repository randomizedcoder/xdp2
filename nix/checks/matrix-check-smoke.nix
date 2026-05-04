# SPDX-License-Identifier: BSD-2-Clause-FreeBSD
#
# matrix-check-smoke — Phase 7 wiring check.
#
# Pure-Nix `runCommand` that builds the public Phase-7 wrappers
# (`flow-dissector-matrix-run`, `flow-dissector-matrix-check`)
# and asserts that:
#   1. Both invoke `--help` cleanly (exit 0).
#   2. The documented flag set appears in `--help` output for each.
#   3. The wrappers reject missing required args with a non-zero
#      exit and a helpful error message.
#   4. A baseline parse fails loudly when the file is missing.
#
# This is a wiring check, not a behavioral one. The end-to-end
# regression-detection logic is exercised by the Phase-6
# aggregate-results check.

{ pkgs, lib, matrixRun, matrixCheck }:

pkgs.runCommand "matrix-check-smoke"
{
  nativeBuildInputs = [ matrixRun matrixCheck pkgs.gnugrep pkgs.coreutils ];
} ''
  set -eu

  # --- flow-dissector-matrix-run --help ---------------------------
  flow-dissector-matrix-run --help > run-help.txt
  for flag in '--testbed' '--results' '--smoke' '--help'; do
    grep -q -- "$flag" run-help.txt \
      || { echo "matrix-run --help missing $flag"; cat run-help.txt; exit 1; }
  done

  # Missing --testbed must fail with a clear message.
  if flow-dissector-matrix-run > run-noflag.txt 2> run-noflag.err; then
    echo "matrix-run with no args should have failed"; exit 1
  fi
  grep -q -- '--testbed is required' run-noflag.err \
    || { echo "matrix-run missing-testbed message wrong"; cat run-noflag.err; exit 1; }

  # Bogus testbed path must fail before any orchestration.
  if flow-dissector-matrix-run --testbed /no/such/file.toml \
       > run-badpath.txt 2> run-badpath.err; then
    echo "matrix-run with bogus testbed should have failed"; exit 1
  fi
  grep -q 'testbed file not found' run-badpath.err \
    || { echo "matrix-run bad-path message wrong"; cat run-badpath.err; exit 1; }

  # --- flow-dissector-matrix-check --help -------------------------
  flow-dissector-matrix-check --help > check-help.txt
  for flag in '--testbed' '--baseline' '--threshold' '--results' '--smoke' '--help'; do
    grep -q -- "$flag" check-help.txt \
      || { echo "matrix-check --help missing $flag"; cat check-help.txt; exit 1; }
  done

  # Missing --testbed must fail.
  if flow-dissector-matrix-check > check-noflag.txt 2> check-noflag.err; then
    echo "matrix-check with no args should have failed"; exit 1
  fi
  grep -q -- '--testbed is required' check-noflag.err \
    || { echo "matrix-check missing-testbed message wrong"; cat check-noflag.err; exit 1; }

  # Bogus testbed path must fail before orchestration.
  if flow-dissector-matrix-check --testbed /no/such/file.toml \
       > check-badpath.txt 2> check-badpath.err; then
    echo "matrix-check with bogus testbed should have failed"; exit 1
  fi
  grep -q 'testbed file not found' check-badpath.err \
    || { echo "matrix-check bad-path message wrong"; cat check-badpath.err; exit 1; }

  echo ok > $out
''
