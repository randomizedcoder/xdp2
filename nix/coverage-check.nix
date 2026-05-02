# nix/coverage-check.nix
#
# Protocol coverage verification targets.
#
# Targets:
#   nix run .#coverage-check            — acceptance rate + chain histogram on combo.pcap
#   nix run .#coverage-check -- <pcap>  — custom PCAP
#   nix run .#coverage-check-all        — acceptance rate on all data/pcaps/*.pcap
#
# These targets verify that the stop-leaf wildcard changes are working:
# unknown protocols are accepted with partial metadata rather than rejected.
#

{ pkgs, xdp2Rs, test-pcap }:

{
  # ── Single PCAP coverage check ──────────────────────────────────
  #
  # Reports acceptance rate and chain-signature histogram for a PCAP.
  # Default: combo.pcap (500K packets, all protocol permutations).
  #
  # Usage:
  #   nix run .#coverage-check
  #   nix run .#coverage-check -- /path/to/custom.pcap
  check = pkgs.writeShellApplication {
    name = "xdp2-coverage-check";
    runtimeInputs = [ xdp2Rs.build pkgs.coreutils ];
    text = ''
      set -euo pipefail

      PCAP="''${1:-${test-pcap}/combo.pcap}"

      echo "=== XDP2 Protocol Coverage Check ==="
      echo "PCAP: $PCAP"
      echo ""

      echo "--- Acceptance Rate ---"
      xdp2-bench --pcap "$PCAP" --iterations 1 2>&1

      echo ""
      echo "--- Chain Histogram (top 30) ---"
      xdp2-bench --pcap "$PCAP" --chain-histogram --top 30 2>&1
    '';
  };

  # ── All-PCAPs coverage sweep ────────────────────────────────────
  #
  # Reports acceptance rate for every .pcap file in data/pcaps/.
  # Quick sanity check that no PCAP regressed after protocol changes.
  #
  # Usage:
  #   nix run .#coverage-check-all
  check-all = pkgs.writeShellApplication {
    name = "xdp2-coverage-check-all";
    runtimeInputs = [ xdp2Rs.build pkgs.coreutils ];
    text = ''
      set -euo pipefail

      PCAP_DIR="${../data/pcaps}"
      echo "=== XDP2 Protocol Coverage — All PCAPs ==="
      echo ""
      printf "%-40s %s\n" "PCAP" "Acceptance"
      printf "%-40s %s\n" "----" "----------"

      total_ok=0
      total_all=0

      for pcap in "$PCAP_DIR"/*.pcap; do
        name="$(basename "$pcap")"
        line=$(xdp2-bench --pcap "$pcap" --iterations 1 2>&1 | grep "^Filtered:" || true)
        if [ -n "$line" ]; then
          printf "%-40s %s\n" "$name" "$line"
          # Extract counts for summary
          ok=$(echo "$line" | sed 's|Filtered: \([0-9]*\)/.*|\1|')
          all=$(echo "$line" | sed 's|Filtered: [0-9]*/\([0-9]*\).*|\1|')
          total_ok=$((total_ok + ok))
          total_all=$((total_all + all))
        else
          err=$(xdp2-bench --pcap "$pcap" --iterations 1 2>&1 | tail -1)
          printf "%-40s %s\n" "$name" "ERROR: $err"
        fi
      done

      echo ""
      if [ "$total_all" -gt 0 ]; then
        pct=$(awk "BEGIN { printf \"%.1f\", 100.0 * $total_ok / $total_all }")
        echo "Total: $total_ok/$total_all packets parseable ($pct%)"
      fi
    '';
  };
}
