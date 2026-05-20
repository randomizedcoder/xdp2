# SPDX-License-Identifier: BSD-2-Clause-FreeBSD
#
# flow-dissector-icache-sweep — collects per-parser-mode CPU
# performance counters (icache misses + branch misses + cycles +
# instructions) for the flow_dissector benchmark.
#
# Built to answer the open question from the 2026-05-19 perf
# investigation (perf-results/2026-05-19-O3-march-native-flto/
# comparison.md): is the remaining c-xdp2-mono vs rust-mono gap
# on tunneled workloads caused by icache pressure? The L2 mono
# entry function is 10,388 asm instructions (~62 KB) — about 2×
# the size of Zen 1's 32 KB L1i.
#
# What it does:
#   - For each (host, workload, parser-mode), runs
#       perf stat -e l1-icache-load-misses,instructions,cycles,branch-misses,iTLB-load-misses \
#           ./benchmark -p -<mode> -n <iters> <pcap>
#   - Captures the counters + the benchmark's ns/pkt output.
#   - Emits a markdown table (icache misses per packet, cycles
#     per packet, miss rate %) for analysis.
#
# Usage:
#   nix run .#flow-dissector-icache-sweep -- \
#       --testbed testbeds/hp2-hp5-x710.toml \
#       [--workloads CSV] [--modes CSV] [--iters N] [--results DIR]
#
# Default modes: M (mono), O (opt), S (slow/generic). Skip F
# (xdp2_parse_fast) since it's the NIC fast-path reference, not
# a parser variant.
#
# Requires:
#   - root or kernel.perf_event_paranoid <= 1 on the target host
#   - perf installed (NixOS has it via pkgs.perf)
#
# Output tree:
#   $RESULTS/<date>/<testbed>/<host>/icache/
#     <workload>/<mode>.txt         raw perf stat output + bench output
#     <workload>/<mode>.json        parsed counters
#   $RESULTS/icache-summary.md      aggregated markdown table

{ pkgs
, workloadPcaps
, lib
}:

let
  defaultWorkloads = lib.concatStringsSep "," (builtins.attrNames workloadPcaps);
  defaultWorkloadsSpaced = lib.concatStringsSep " " (builtins.attrNames workloadPcaps);

  # Workload → pcap path. Pre-baked into the script (same shape as
  # matrix-sweep) so the harness is fully hermetic.
  pcapMapEntries = lib.concatStringsSep "\n" (lib.mapAttrsToList
    (name: drv: ''    PCAP_OF["${name}"]="${drv}/${name}.pcap"'')
    workloadPcaps);
in
pkgs.writeShellApplication {
  name = "flow-dissector-icache-sweep";

  runtimeInputs = [
    pkgs.coreutils
    pkgs.openssh
    pkgs.jq
    pkgs.python3
  ];

  text = ''
    set -euo pipefail

    usage() {
      cat <<'USAGE'
Usage:
  flow-dissector-icache-sweep --testbed PATH [OPTIONS]

Collects per-parser-mode CPU counters (icache misses, branches,
cycles, instructions, iTLB misses) for the flow_dissector
benchmark across a workload set and a parser-mode set. Used to
answer code-size / icache hypotheses.

Options:
  --testbed PATH    testbed-config TOML (required).
  --results DIR     Result tree root. Default: $XDP2_RESULTS_ROOT
                    or ./perf-results.
  --workloads CSV   Comma-separated workload names. Default: all 6.
  --modes CSV       Parser modes to test (single letters as
                    benchmark.c accepts). Default: M,O,S.
  --iters N         Iterations per benchmark run. Default: 100.
  -h, --help        This help.

Modes:
  M  monolithic (R3.4 fast-path + goto-state, default since 2026-05-19)
  O  optimized (XDP2_OPTIMIZED dispatch via opt parser)
  S  slow / generic (__xdp2_parse engine; diagnostic only)
  F  fast (xdp2_parse_fast — NIC-classified, requires F-path-compat
                              graph; included for completeness)

Available workloads:
USAGE
      for w in ${defaultWorkloadsSpaced}; do
        echo "  - $w"
      done
    }

    TESTBED=""
    RESULTS=""
    WORKLOADS="${defaultWorkloads}"
    MODES="M,O,S"
    ITERS="100"

    while [ $# -gt 0 ]; do
      case "$1" in
        -h|--help) usage; exit 0 ;;
        --testbed) TESTBED="$2"; shift 2 ;;
        --results) RESULTS="$2"; shift 2 ;;
        --workloads) WORKLOADS="$2"; shift 2 ;;
        --modes) MODES="$2"; shift 2 ;;
        --iters) ITERS="$2"; shift 2 ;;
        *) echo "icache-sweep: unknown arg '$1'" >&2; usage >&2; exit 2 ;;
      esac
    done

    if [ -z "$TESTBED" ]; then
      echo "icache-sweep: --testbed required" >&2
      exit 2
    fi
    [ -f "$TESTBED" ] || { echo "icache-sweep: testbed not found: $TESTBED" >&2; exit 2; }

    if [ -z "$RESULTS" ]; then
      RESULTS="''${XDP2_RESULTS_ROOT:-$PWD/perf-results}"
    fi
    DATE=$(date -u +%Y-%m-%d)
    TB_NAME=$(grep -E '^\s*name\s*=' "$TESTBED" | head -1 \
              | sed -E 's/.*"([^"]+)".*/\1/')
    OUT_ROOT="$RESULTS/$DATE/$TB_NAME"
    mkdir -p "$OUT_ROOT"

    declare -A PCAP_OF
${pcapMapEntries}

    mapfile -t HOSTS < <(grep -E '^\s*hostname\s*=' "$TESTBED" \
                          | sed -E 's/.*"([^"]+)".*/\1/')
    if [ ''${#HOSTS[@]} -eq 0 ]; then
      echo "icache-sweep: no hostnames in $TESTBED" >&2
      exit 2
    fi

    echo "[icache] testbed=$TESTBED hosts=''${HOSTS[*]} results=$OUT_ROOT"
    echo "[icache] workloads=$WORKLOADS modes=$MODES iters=$ITERS"

    IFS=',' read -ra WLIST <<< "$WORKLOADS"
    IFS=',' read -ra MLIST <<< "$MODES"

    # Pre-stage pcaps + benchmark binary on every host.
    BENCH_NIX_PATH=$(nix build --no-link --print-out-paths \
                       .#flow-dissector-matrix-artifacts 2>/dev/null \
                     | tail -1)
    BENCH_BIN="$BENCH_NIX_PATH/bin/benchmark"
    [ -x "$BENCH_BIN" ] || { echo "icache-sweep: benchmark not found at $BENCH_BIN" >&2; exit 2; }

    for h in "''${HOSTS[@]}"; do
      echo "[stage] benchmark → root@$h:/tmp/benchmark"
      scp -q -o BatchMode=yes "$BENCH_BIN" "root@$h:/tmp/benchmark"
      ssh -o BatchMode=yes "root@$h" "chmod +x /tmp/benchmark"
      for w in "''${WLIST[@]}"; do
        src="''${PCAP_OF[$w]:-}"
        [ -n "$src" ] || { echo "icache-sweep: unknown workload '$w'" >&2; exit 2; }
        echo "[stage] $w → root@$h:/tmp/$w.pcap"
        scp -q -o BatchMode=yes "$src" "root@$h:/tmp/$w.pcap"
      done
    done

    # Per-cell: ssh runs `perf stat ./benchmark` and we capture
    # both stdout (benchmark ns/pkt) and stderr (perf stat
    # counters). Parsed into JSON later.
    EVENTS="l1-icache-load-misses,instructions,cycles,branch-misses,iTLB-load-misses"
    for h in "''${HOSTS[@]}"; do
      mkdir -p "$OUT_ROOT/$h/icache"
      for w in "''${WLIST[@]}"; do
        mkdir -p "$OUT_ROOT/$h/icache/$w"
        for m in "''${MLIST[@]}"; do
          # Validate mode is one of MOSF.
          case "$m" in
            M|O|S|F) ;;
            *) echo "icache-sweep: bad mode '$m'" >&2; exit 2 ;;
          esac
          out="$OUT_ROOT/$h/icache/$w/$m.txt"
          echo "[run] $h / $w / -$m → $out"
          # 2>&1 because perf stat writes counters to stderr.
          ssh -o BatchMode=yes "root@$h" \
              "perf stat --field-separator=, -e $EVENTS \
                /tmp/benchmark -p -$m -n $ITERS /tmp/$w.pcap" \
              > "$out" 2>&1 || true
        done
      done
    done

    # Parse + aggregate. python is in runtimeInputs.
    python3 <<PYEOF
import csv, json, os, re, sys
from pathlib import Path

OUT_ROOT = Path("$OUT_ROOT")
EVENTS = "l1-icache-load-misses instructions cycles branch-misses iTLB-load-misses".split()
NSPP_RE = re.compile(r'XDP2 parser:\s*(\d+) ns/pkt')
HITRATE_RE = re.compile(r'hits=(\d+)/(\d+)')

def parse_perf_stat_csv(text):
    """perf stat --field-separator=, emits one row per event:
       count,,event,run_time,run_pct,...
    Header lines start with '#' or blank."""
    counts = {}
    for line in text.splitlines():
        if not line or line.startswith('#'):
            continue
        parts = line.split(',')
        if len(parts) < 3:
            continue
        try:
            cnt = int(parts[0]) if parts[0] and parts[0] != '<not supported>' else None
        except ValueError:
            cnt = None
        event = parts[2].strip()
        if event in EVENTS:
            counts[event] = cnt
    return counts

rows = []
for host_dir in sorted(OUT_ROOT.iterdir()):
    if not host_dir.is_dir() or host_dir.name == 'icache':
        continue
    icache_dir = host_dir / "icache"
    if not icache_dir.exists():
        continue
    for workload_dir in sorted(icache_dir.iterdir()):
        for txt in sorted(workload_dir.glob("*.txt")):
            mode = txt.stem
            text = txt.read_text(errors='replace')
            counts = parse_perf_stat_csv(text)
            m = NSPP_RE.search(text)
            ns_per_pkt = int(m.group(1)) if m else None
            row = {
                "host": host_dir.name,
                "workload": workload_dir.name,
                "mode": mode,
                "ns_per_pkt": ns_per_pkt,
                **{e: counts.get(e) for e in EVENTS},
            }
            rows.append(row)
            (workload_dir / f"{mode}.json").write_text(
                json.dumps(row, indent=2))

# Aggregate markdown table.
out_md = OUT_ROOT / "icache-summary.md"
BT = chr(96)  # backtick — kept out of the source literal so the
              # outer shellcheck pass doesn't misread these strings
              # as legacy command substitution.
lines = [
    "# Icache / branch sweep — perf counters per parser mode",
    "",
    "Source: " + BT + "flow-dissector-icache-sweep" + BT + ". One row per",
    "(host, workload, mode) cell. Counters are TOTAL across the",
    "benchmark loop (iters x packets); divide by iters x packets",
    "for per-packet equivalents.",
    "",
    "Headers:",
    "  ns/pkt        XDP2 parser line from benchmark output",
    "  icache-miss   L1 icache load misses (total)",
    "  branch-miss   branch misses (total)",
    "  cycles        cycles (total)",
    "  instr         instructions retired (total)",
    "  iTLB-miss     iTLB load misses (total)",
    "  IPC           instr/cycles",
    "  miss/Mi       icache-miss per million instructions",
    "",
    "| host | workload | mode | ns/pkt | icache-miss | branch-miss | cycles | instr | iTLB-miss | IPC | miss/Mi |",
    "|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|",
]
for r in rows:
    ic = r["l1-icache-load-misses"]
    br = r["branch-misses"]
    cy = r["cycles"]
    ii = r["instructions"]
    it = r["iTLB-load-misses"]
    ipc = f"{ii/cy:.2f}" if (cy and ii) else "—"
    mpm = f"{ic/ii*1e6:.0f}" if (ic and ii) else "—"
    lines.append(
        f"| {r['host']} | {r['workload']} | -{r['mode']} | "
        f"{r['ns_per_pkt'] or '—'} | "
        f"{ic or '—':,} | {br or '—':,} | "
        f"{cy or '—':,} | {ii or '—':,} | "
        f"{it or '—':,} | {ipc} | {mpm} |".replace(
            'or —:,', 'or —')
    )

out_md.write_text("\n".join(lines) + "\n")
print(f"[icache] wrote {out_md}")
PYEOF

    echo "[icache] summary at $OUT_ROOT/icache-summary.md"
  '';

  meta = {
    description = "Perf-counter sweep (icache/branch/cycles) per parser mode per workload, via ssh + perf stat";
    mainProgram = "flow-dissector-icache-sweep";
  };
}
