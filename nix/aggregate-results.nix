# SPDX-License-Identifier: BSD-2-Clause-FreeBSD
#
# flow-dissector-matrix-aggregate — Phase 6 of the matrix plan
# (docs/flow-dissector-matrix-implementation-plan.md §10).
#
# Walks a Phase-5 result tree of per-cell JSONs and emits
# summary.{md,csv} plus regressions.md (when --baseline is given).
# Stdlib-only Python; no pandas/numpy dependency.
#
# The Python implementation lives in nix/scripts/aggregate-results.py
# so it stays editable as a normal source file (single-file
# argparse → walk → group → stats → emit).

{ pkgs }:

pkgs.writeShellApplication {
  name = "flow-dissector-matrix-aggregate";

  runtimeInputs = [
    pkgs.python3
    pkgs.coreutils
  ];

  text = ''
    exec ${pkgs.python3}/bin/python3 ${./scripts/aggregate-results.py} "$@"
  '';

  meta = {
    description =
      "Aggregate Phase-5 per-cell JSONs into summary.md / summary.csv / regressions.md";
    mainProgram = "flow-dissector-matrix-aggregate";
  };
}
