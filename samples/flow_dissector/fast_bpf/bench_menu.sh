#!/usr/bin/env bash
#
# bench_menu.sh — benchmark + Gold gate for the per-encapsulation
# xdp2-flow-ebpf menu (kernel-patches/series6-common-case/ebpf-menu.md).
#
# Per menu object:
#   - benchmark_bpf (BPF_PROG_TEST_RUN, needs root/CAP_BPF) on that shape's
#     corpus pcap -> ns/pkt, vs the in-tree bpf_flow.kern.o on the same pcap;
#   - GOLD gate: parity_test -D dumps the extracted inner 5-tuple per hit;
#     diff against the golden CSV (ground-truth-by-construction — the corpus
#     pcaps are synthetic with known inner flows, so the golden IS the correct
#     answer). GOLD = every hit matches and all packets hit; FAIL otherwise.
#
# Emits CSV (shape,pcap,fast_ns,intree_ns,parity) to stdout, a table to
# stderr. Exit non-zero if any Gold gate fails.
#
# Paths from the environment (baked by nix/flow-menu-bench.nix), in-tree
# defaults otherwise:
#   BENCHMARK_BPF  PARITY_TEST  OBJDIR (fast_flow_<shape>.bpf.o + bpf_flow.kern.o)
#   CORPUS (<shape>.pcap + gold/<shape>.csv)   BPF_REPEAT (default 1000)

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BENCHMARK_BPF="${BENCHMARK_BPF:-$here/../benchmark_bpf}"
PARITY_TEST="${PARITY_TEST:-$here/parity_test}"
OBJDIR="${OBJDIR:-$here}"
CORPUS="${CORPUS:-$here/corpus}"
BPF_REPEAT="${BPF_REPEAT:-1000}"
ORACLE="$OBJDIR/bpf_flow.kern.o"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

SHAPES="eth_ip vlan qinq mpls ipip gre pppoe vxlan geneve gtpu gue fou"

nspkt() { grep -oE '[0-9]+ ns/pkt' <<<"${1:-}" | head -1 | grep -oE '[0-9]+' || true; }
bench() { # label objpath pcap -> ns/pkt
  local out
  out=$("$BENCHMARK_BPF" -p -n "$BPF_REPEAT" -l "$1" -b "$2" "$3" 2>/dev/null) || return 0
  nspkt "$out"
}

echo "shape,pcap,fast_ns_pkt,intree_ns_pkt,parity"
printf '%-8s %-12s %8s %9s  %s\n' shape pcap fast_ns intree_ns parity >&2

fail=0
for shape in $SHAPES; do
  obj="$OBJDIR/fast_flow_${shape}.bpf.o"
  cap="$CORPUS/${shape}.pcap"
  gold="$CORPUS/gold/${shape}.csv"
  if [[ ! -f "$obj" || ! -f "$cap" ]]; then
    printf '%-8s %-12s %8s %9s  %s\n' "$shape" "$shape.pcap" - - "MISSING" >&2
    echo "$shape,$shape.pcap,,,MISSING"; continue
  fi

  fast_ns=$(bench "fast_$shape" "$obj" "$cap")
  intree_ns=$(bench "intree" "$ORACLE" "$cap")

  # GOLD gate: our extracted inner 5-tuple must equal the golden, for every packet.
  parity="SKIP(no-gold)"
  if [[ -f "$gold" ]]; then
    "$PARITY_TEST" -D -f "$obj" "$cap" 2>/dev/null | sort > "$TMP/our"
    sort "$gold" > "$TMP/gold"
    if diff -q "$TMP/gold" "$TMP/our" >/dev/null 2>&1; then
      parity="GOLD"
    else
      parity="FAIL"; fail=1
    fi
  fi

  printf '%-8s %-12s %8s %9s  %s\n' "$shape" "$shape.pcap" "${fast_ns:-?}" "${intree_ns:-?}" "$parity" >&2
  echo "$shape,$shape.pcap,${fast_ns:-},${intree_ns:-},$parity"
done

exit "$fail"
