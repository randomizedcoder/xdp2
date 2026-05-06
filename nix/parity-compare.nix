# SPDX-License-Identifier: BSD-2-Clause-FreeBSD
#
# parity-compare — Python comparator wrapper. Phase 17.C of
# /home/das/.claude/profiles/personal/plans/das-l-downloads-xdp2-find-name-fizzy-ocean.md.
# Mirrors nix/aggregate-results.nix's pattern: a writeShellApplication
# that execs python3 against the script in the source tree, with
# `mainProgram` so `nix run .#parity-compare` works.
#
# The default --scope path resolves the repo-vendored
# samples/flow_dissector/parity_scope.json by reading it from the Nix
# store at build time so the wrapper is hermetic — callers can run
# the comparator without a checked-out repo as long as Nix has the
# scope file.

{ pkgs }:

pkgs.writeShellApplication {
  name = "parity-compare";

  runtimeInputs = [ pkgs.python3 ];

  text = ''
    SCRIPT="${../nix/scripts/parity-compare.py}"
    DEFAULT_SCOPE="${../samples/flow_dissector/parity_scope.json}"

    # Default --scope to the vendored copy if the caller didn't pass one.
    has_scope=0
    for arg in "$@"; do
      if [ "$arg" = "--scope" ]; then has_scope=1; break; fi
    done
    if [ "$has_scope" -eq 0 ]; then
      exec python3 "$SCRIPT" --scope "$DEFAULT_SCOPE" "$@"
    else
      exec python3 "$SCRIPT" "$@"
    fi
  '';

  meta = {
    description =
      "Cross-parser parity comparator (Python wrapper for nix/scripts/parity-compare.py)";
    mainProgram = "parity-compare";
  };
}
