# nix/flow-dissector-matrix-smoke.nix
#
# Build-time execution smoke for the 6-way flow-dissector matrix.
#
# The existing `.#flow-dissector-matrix` output is a shell-application
# *wrapper* — `nix build` only validates that the wrapper and its BPF
# objects compile, not that the matrix actually runs. This derivation
# closes that gap by invoking `xdp2-flow-dissector-matrix` against the
# in-tree PCAP `data/pcaps/tcp_ipv4.pcap` during its build phase and
# capturing the resulting matrix table to `$out/matrix.txt`.
#
# Sandbox caveat: `BPF_PROG_TEST_RUN` (ways 4–6) needs `CAP_BPF`, which
# the Nix build sandbox strips even when nix-daemon runs as root. Inside
# the sandbox:
#   - ways 1–3 (userspace):  execute, capture ns/pkt + Mpps
#   - ways 4–6 (BPF):        degrade to "N/A" via the matrix runner's
#                            existing graceful-failure path
#
# The smoke asserts that at least one userspace way produced timing
# output (`ns/pkt`) — that's sufficient as a build-time gate. Full 6-way
# execution still requires `nix run .#flow-dissector-matrix` under sudo
# on a host (hp2/hp5) with `CAP_BPF`.
#
# Typical use:
#   nix build .#flow-dissector-matrix-smoke
#   cat result/matrix.txt
#
# Or via the physical-testbed runner:
#   nix run .#run-on-host -- hp5 -- flow-dissector-matrix-smoke

{ pkgs
, matrix          # `matrix` output from nix/flow-dissector-matrix.nix
}:

let
  lib = pkgs.lib;
  # Tiny in-tree PCAP — TCP/IPv4, 1 KiB. Every userspace dissector
  # handles it; the test isn't about the PCAP content, just about
  # exercising the matrix plumbing.
  smokePcap = ../data/pcaps/tcp_ipv4.pcap;
in
pkgs.stdenv.mkDerivation {
  pname = "xdp2-flow-dissector-matrix-smoke";
  version = "0.1.0";

  dontUnpack = true;
  dontConfigure = true;
  dontInstall = true;

  nativeBuildInputs = [ matrix ];

  buildPhase = ''
    runHook preBuild
    mkdir -p $out

    # `|| true` — ways 4–6 will warn "need root / CAP_BPF?" inside the
    # sandbox but the runner exits 0 (it only returns non-zero if the
    # userspace benchmark fails outright).
    xdp2-flow-dissector-matrix -n 10 -N 100 ${smokePcap} \
      > $out/matrix.txt 2>&1 || true

    # Minimum success criterion: at least one userspace way produced a
    # "N ns/pkt" measurement. If every cell is N/A the smoke is dead.
    if ! grep -q 'ns/pkt' $out/matrix.txt; then
      echo "flow-dissector-matrix-smoke: no ns/pkt measurements captured" >&2
      echo "---- matrix.txt ----" >&2
      cat $out/matrix.txt >&2
      exit 1
    fi

    # Record which ways ran for review. Degrades to empty files if a way
    # was N/A — those are still useful as negative evidence.
    grep 'Kernel flowdis:'  $out/matrix.txt > $out/way1-kernel-flowdis.txt  || true
    grep 'XDP2 parser:'     $out/matrix.txt > $out/way2-xdp2-parser.txt     || true
    grep 'XDP2 parse-only:' $out/matrix.txt > $out/way3-xdp2-parse-only.txt || true

    runHook postBuild
  '';

  meta = {
    description = "Build-time execution smoke for the 6-way flow-dissector matrix";
    platforms = lib.platforms.linux;
  };
}
