# SPDX-License-Identifier: BSD-2-Clause-FreeBSD
#
# aggregate-afxdp — Phase L4 wrapper. Walks <results>/<date>/<testbed>/afxdp/
# and emits summary-afxdp.{md,csv}. Parallel to nix/aggregate-results.nix
# (which handles the PCAP-replay matrix); kept separate because the two
# campaigns measure different things and one CSV column-set gets ugly fast.

{ pkgs }:

pkgs.writeShellApplication {
  name = "flow-dissector-afxdp-aggregate";

  runtimeInputs = [ pkgs.python3 ];

  text = ''
    exec ${pkgs.python3}/bin/python3 ${../nix/scripts/aggregate-afxdp.py} "$@"
  '';

  meta = {
    description = "Aggregate live-wire AF_XDP per-cell JSONs into summary tables";
    mainProgram = "flow-dissector-afxdp-aggregate";
  };
}
