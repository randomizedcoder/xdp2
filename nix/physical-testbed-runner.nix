# SPDX-License-Identifier: BSD-2-Clause-FreeBSD
#
# nix run .#run-on-host -- HOST [HOST...] -- TARGET [TARGET...]
#
# Drives physical-testbed runs (hp2/hp5 today, any host with the xdp2
# repo and nix-flakes installed) by:
#
#   1. rsync the working tree to root@host:~/xdp2/
#   2. ssh root@host 'cd ~/xdp2 && nix build|run .#TARGET'
#   3. rsync ~/xdp2/result/ back to perf-results/${host}/${target}-<ts>/
#   4. emit a summary table to stdout
#
# Multiple hosts run in parallel; targets within a host run sequentially
# (so they don't fight over /sys/fs/bpf or NIC queues). A failure on one
# (host, target) pair is reported but does not abort siblings — final
# wrapper exit is non-zero if *any* pair failed.
#
# See docs/physical-testbed.md §9 for the design contract.

{ pkgs }:

pkgs.writeShellApplication {
  name = "xdp2-run-on-host";

  runtimeInputs = [
    pkgs.rsync
    pkgs.openssh
    pkgs.coreutils
    pkgs.jq
    pkgs.gawk
  ];

  text = ''
    set -u
    # NOT set -e: per-(host,target) failures are tracked, not fatal.

    print_usage() {
      cat <<'EOF'
    Usage: xdp2-run-on-host HOST [HOST...] -- TARGET [TARGET...]

      HOST    SSH-reachable host (e.g. hp2, hp5, root@1.2.3.4).
              Bare names are connected to as root@HOST.
      TARGET  flake attribute (e.g. xdp2-rs-test, flow-dissector-matrix,
              perf-analysis-all). Tried as a package first
              (nix build .#TARGET), then as an app (nix run .#TARGET)
              if the package build fails.

    Examples:
      xdp2-run-on-host hp5 -- xdp2-rs-test
      xdp2-run-on-host hp2 hp5 -- xdp2-rs-test flow-dissector-matrix
      xdp2-run-on-host hp5 -- perf-analysis-all
    EOF
    }

    if [ "$#" -lt 3 ]; then
      print_usage >&2
      exit 2
    fi

    HOSTS=()
    TARGETS=()
    seen_sep=0
    for arg in "$@"; do
      if [ "$arg" = "--" ]; then
        seen_sep=1
        continue
      fi
      if [ "$seen_sep" -eq 0 ]; then
        HOSTS+=("$arg")
      else
        TARGETS+=("$arg")
      fi
    done

    if [ "$seen_sep" -eq 0 ] || [ "''${#HOSTS[@]}" -eq 0 ] || [ "''${#TARGETS[@]}" -eq 0 ]; then
      print_usage >&2
      exit 2
    fi

    # Locate the xdp2 working tree to rsync from.
    # XDP2_SRC overrides; otherwise PWD must contain flake.nix.
    SRC="''${XDP2_SRC:-$PWD}"
    if [ ! -f "$SRC/flake.nix" ]; then
      echo "xdp2-run-on-host: $SRC does not look like the xdp2 repo (no flake.nix)" >&2
      echo "  set XDP2_SRC=/path/to/xdp2 or run from the repo root" >&2
      exit 2
    fi

    # Per-host result directory under perf-results/.
    RESULTS_ROOT="''${XDP2_RESULTS_ROOT:-$SRC/perf-results}"
    mkdir -p "$RESULTS_ROOT"

    # Each (host, target) pair writes one TSV row to this file; main
    # process renders the table at the end.
    SUMMARY=$(mktemp)
    trap 'rm -f "$SUMMARY"' EXIT

    # SSH/rsync defaults: BatchMode=yes — fail fast if no key, never
    # prompt; ControlMaster reuses one TCP connection per host.
    SSH_OPTS="-o BatchMode=yes -o StrictHostKeyChecking=accept-new"
    SSH_CMD="ssh $SSH_OPTS"

    # Resolve "hp5" -> "root@hp5"; leave "user@host" alone.
    sshtarget() {
      case "$1" in
        *@*) echo "$1" ;;
        *)   echo "root@$1" ;;
      esac
    }

    run_host() {
      local host="$1"; shift
      local sshto; sshto=$(sshtarget "$host")
      local remote_path="xdp2"  # ~/xdp2 on the remote
      local host_failed=0

      echo "[$host] rsync -> $sshto:~/$remote_path/" >&2
      # NOTE: .git/ is intentionally NOT excluded. Nix flakes use
      # git-tracked-path semantics to decide which files feed the source
      # derivation hash; without .git/ the remote Nix falls back to
      # hashing the whole directory (including gitignored cruft),
      # producing derivation hashes that differ from the local build and
      # breaking binary-cache sharing. See 2026-04-20 flow-dissector
      # matrix smoke diagnosis.
      # --no-owner/--no-group: we SSH in as root but the source tree is
      # owned by the dev-box user; preserving ownership makes libgit2
      # reject the repo (safe.directory check, "repository path is not
      # owned by current user"). Landing everything as root-on-remote
      # sidesteps that and matches what a native `git clone` would do.
      if ! rsync -az --delete --no-owner --no-group \
            -e "$SSH_CMD" \
            --exclude="result" \
            --exclude="result-*" \
            --exclude="perf-results/" \
            --exclude="target/" \
            --exclude="*.swp" \
            "$SRC/" "$sshto:$remote_path/"; then
        echo "[$host] rsync failed — skipping all targets on this host" >&2
        for target in "$@"; do
          printf '%s\t%s\t-\t1\trsync-failed\n' "$host" "$target" >> "$SUMMARY"
        done
        return 1
      fi

      for target in "$@"; do
        local ts; ts=$(date -u +%Y%m%dT%H%M%SZ)
        local outdir="$RESULTS_ROOT/$host/$target-$ts"
        local logfile="$outdir.log"
        mkdir -p "$RESULTS_ROOT/$host"

        echo "[$host] -> $target  (log: $logfile)" >&2
        local start end wall exit_code
        start=$(date +%s)

        # Try `nix build` first (idempotent, cacheable). If it fails
        # with "is not a derivation" or similar, fall back to `nix run`
        # for app-style targets. We can't easily distinguish without
        # `nix flake show --json` (which is slow on first run), so we
        # just try both and report the second result if the first fails.
        if $SSH_CMD "$sshto" \
              "cd ~/$remote_path && nix build .#$target --print-build-logs --no-link --print-out-paths" \
              >"$logfile" 2>&1; then
          exit_code=0
        elif $SSH_CMD "$sshto" \
              "cd ~/$remote_path && nix run .#$target --print-build-logs" \
              >>"$logfile" 2>&1; then
          exit_code=0
        else
          exit_code=1
        fi

        end=$(date +%s)
        wall=$((end - start))

        # Pull back result/ if it exists. We use --ignore-missing-args
        # equivalent (test for presence first) since not every target
        # produces a result/ tree.
        local rsync_path="-"
        if $SSH_CMD "$sshto" "test -e ~/$remote_path/result" 2>/dev/null; then
          mkdir -p "$outdir"
          if rsync -az -e "$SSH_CMD" \
                "$sshto:$remote_path/result/" "$outdir/"; then
            rsync_path="$outdir"
          else
            rsync_path="rsync-back-failed"
            exit_code=1
          fi
        fi

        printf '%s\t%s\t%ds\t%d\t%s\n' \
          "$host" "$target" "$wall" "$exit_code" "$rsync_path" \
          >> "$SUMMARY"

        if [ "$exit_code" -ne 0 ]; then
          host_failed=1
          echo "[$host] $target FAILED (exit=$exit_code, see $logfile)" >&2
        fi
      done

      return "$host_failed"
    }

    # Fan out: one background job per host, each runs its targets
    # sequentially. Hosts are independent so this is safe.
    pids=()
    for host in "''${HOSTS[@]}"; do
      run_host "$host" "''${TARGETS[@]}" &
      pids+=("$!")
    done

    overall=0
    for pid in "''${pids[@]}"; do
      if ! wait "$pid"; then
        overall=1
      fi
    done

    # Render the summary table.
    echo
    echo "===================== xdp2-run-on-host summary ====================="
    printf '%-12s  %-32s  %6s  %4s  %s\n' "HOST" "TARGET" "WALL" "EXIT" "RESULT"
    printf '%-12s  %-32s  %6s  %4s  %s\n' "----" "------" "----" "----" "------"
    awk -F'\t' '{ printf "%-12s  %-32s  %6s  %4s  %s\n", $1, $2, $3, $4, $5 }' \
      "$SUMMARY" | sort

    # JSON sibling for downstream tools (testbed-index follow-up).
    INDEX_JSON="$RESULTS_ROOT/INDEX.json"
    jq -Rn --slurpfile prev <(test -s "$INDEX_JSON" && cat "$INDEX_JSON" || echo "[]") '
      [ inputs | split("\t") | { host: .[0], target: .[1], wall: .[2], exit: (.[3]|tonumber), path: .[4], ts: now|todate } ] as $new
      | ($prev[0] + $new)
    ' < "$SUMMARY" > "$INDEX_JSON.tmp" 2>/dev/null && mv "$INDEX_JSON.tmp" "$INDEX_JSON" || true

    exit "$overall"
  '';

  meta = {
    description = "Drive xdp2 nix targets on the physical testbed (hp2/hp5) via rsync+ssh";
    mainProgram = "xdp2-run-on-host";
  };
}
