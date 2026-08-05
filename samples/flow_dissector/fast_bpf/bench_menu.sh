#!/usr/bin/env bash
#
# bench_menu.sh — benchmark + parity for the per-encapsulation
# xdp2-flow-ebpf menu (kernel-patches/series6-common-case/ebpf-menu.md).
#
# For each menu object it runs benchmark_bpf (BPF_PROG_TEST_RUN, needs
# root / CAP_BPF) on that shape's corpus pcap to get ns/pkt, runs the
# in-tree bpf_flow.kern.o oracle on the same pcap for comparison, and —
# where an in-tree BPF oracle exists — runs parity_test as a Gold gate.
#
# Emits a CSV (shape,pcap,fast_ns,intree_ns,parity) to stdout, and a
# human table to stderr. Exit non-zero if any Gold parity gate fails.
#
# Paths come from the environment (baked by nix/flow-menu-bench.nix) with
# in-tree defaults so it also runs from a `make bpf` working tree:
#   BENCHMARK_BPF  path to benchmark_bpf
#   PARITY_TEST    path to parity_test
#   OBJDIR         dir with fast_flow_<shape>.bpf.o + bpf_flow.kern.o
#   CORPUS         dir with <shape>.pcap
#   BPF_REPEAT     BPF_PROG_TEST_RUN repeat count (default 1000)

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BENCHMARK_BPF="${BENCHMARK_BPF:-$here/../benchmark_bpf}"
PARITY_TEST="${PARITY_TEST:-$here/parity_test}"
OBJDIR="${OBJDIR:-$here}"
CORPUS="${CORPUS:-$here/corpus}"
BPF_REPEAT="${BPF_REPEAT:-1000}"
ORACLE="$OBJDIR/bpf_flow.kern.o"

# shape | corpus basename | oracle kind (intree | series2 | cdis)
# cdis  = descent-patched/single-label C dissector: no BPF oracle, bench only.
# series2 = needs the series2-patched bpf_flow oracle (built separately).
MENU=(
  "eth_ip|eth_ip.pcap|intree"
  "vlan|vlan.pcap|intree"
  "qinq|qinq.pcap|intree"
  "ipip|ipip.pcap|intree"
  "gre|gre.pcap|intree"
  "mpls|mpls.pcap|cdis"
  "pppoe|pppoe.pcap|series2"
  "vxlan|vxlan.pcap|cdis"
  "geneve|geneve.pcap|cdis"
  "gtpu|gtpu.pcap|cdis"
)

nspkt() { grep -oE '[0-9]+ ns/pkt' <<<"${1:-}" | head -1 | grep -oE '[0-9]+' || true; }

bench() { # label objpath pcap -> ns/pkt (or empty)
  local out
  out=$("$BENCHMARK_BPF" -p -n "$BPF_REPEAT" -l "$1" -b "$2" "$3" 2>/dev/null) || return 0
  nspkt "$out"
}

echo "shape,pcap,fast_ns_pkt,intree_ns_pkt,parity"
printf '%-8s %-14s %10s %10s  %s\n' shape pcap fast_ns intree_ns parity >&2

fail=0
for row in "${MENU[@]}"; do
  IFS='|' read -r shape pcap kind <<<"$row"
  obj="$OBJDIR/fast_flow_${shape}.bpf.o"
  cap="$CORPUS/$pcap"
  if [[ ! -f "$obj" || ! -f "$cap" ]]; then
    printf '%-8s %-14s %10s %10s  %s\n' "$shape" "$pcap" "-" "-" "MISSING(obj/pcap)" >&2
    echo "$shape,$pcap,,,MISSING"
    continue
  fi

  fast_ns=$(bench "fast_$shape" "$obj" "$cap")
  intree_ns=$(bench "intree" "$ORACLE" "$cap")

  parity="SKIP"
  if [[ "$kind" == "intree" ]]; then
    if "$PARITY_TEST" -f "$obj" -r "$ORACLE" "$cap" >/dev/null 2>&1; then
      parity="GOLD"
    else
      parity="FAIL"; fail=1
    fi
  elif [[ "$kind" == "series2" ]]; then
    parity="SKIP(series2-oracle)"
  else
    parity="SKIP(c-dissector)"
  fi

  printf '%-8s %-14s %10s %10s  %s\n' \
    "$shape" "$pcap" "${fast_ns:-?}" "${intree_ns:-?}" "$parity" >&2
  echo "$shape,$pcap,${fast_ns:-},${intree_ns:-},$parity"
done

exit "$fail"
