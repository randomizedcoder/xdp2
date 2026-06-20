# nix/series3-summary-report.nix
#
# Cover-letter table generator. Reads one or more matrix.csv files
# emitted by series3-extensions-soak.nix or series3-cpu-bound-soak.nix
# and writes a kernel-team-ready summary table to stdout.
#
# Auto-detects which orchestrator wrote each CSV by inspecting the
# column header. Groups rows by (sysctl_path, pair, scenario, proto)
# — proto is "udp" for Phase G (pktgen) since pktgen is UDP-only.
# For each group, computes mean + sample stddev across all N
# replicate rows for the slow path (sysctl=0) and the fast path
# (sysctl=1), then derives Δ and % improvement.
#
# Output: a single markdown document with:
#   1. Headline: the strongest single |% improvement| line (the
#      number that should open the cover letter)
#   2. Phase F table (recv_soft_pct, mbps): one row per
#      (sysctl, pair, scen, proto)
#   3. Phase G table (cycles_per_pkt, ins_per_pkt): one row per
#      (sysctl, pair, scen)
#   4. Coverage footer: any (sysctl, pair) combos that never had a
#      successful row, with the count + reason
#
# Rows where |Δ| < 2 × pooled_stddev get a "(noise)" tag so reviewers
# know which deltas are signal vs variance.
#
# Usage:
#   nix run .#series3-summary-report -- <path-to-matrix.csv> [more matrix.csv files...]
#   nix run .#series3-summary-report -- \
#       perf-results/2026-XX-iperf3/matrix.csv \
#       perf-results/2026-XX-pktgen/matrix.csv \
#     > perf-results/2026-XX/SUMMARY-cover-letter.md

{ pkgs }:

pkgs.writeShellApplication {
  name = "series3-summary-report";

  runtimeInputs = with pkgs; [ coreutils gawk ];

  text = ''
    if [ "$#" -lt 1 ]; then
      echo "usage: series3-summary-report <matrix.csv> [more...]" >&2
      exit 64
    fi

    # ── Map scenario name to the sysctl path we toggle for it ──────
    sysctl_for() {
      case "$1" in
        eth_ip) echo "net.flow_dissector.eth_ip" ;;
        vlan)   echo "net.flow_dissector.vlan" ;;
        qinq)   echo "net.flow_dissector.qinq" ;;
        vxlan)  echo "net.flow_dissector.vxlan_inner" ;;
        pppoe)  echo "net.flow_dissector.pppoe" ;;
        mpls)   echo "net.flow_dissector.mpls" ;;
        ipip)   echo "net.flow_dissector.ipip" ;;
        gre)    echo "net.flow_dissector.gre" ;;
        geneve) echo "net.flow_dissector.geneve_inner" ;;
        gtpu)   echo "net.flow_dissector.gtpu_inner" ;;
        *)      echo "net.flow_dissector.UNKNOWN" ;;
      esac
    }

    # ── Awk program: group by key, compute mean + sample stddev ───
    # Stdin: a CSV stream prefixed by a "kind" column distinguishing
    # phase-F vs phase-G rows. Output: a TSV with one row per group.
    AWK_AGG=$(cat <<'EOF'
BEGIN { FS=OFS="\t" }
# Skip header (the calling shell already drops it)
NR == 1 { next }
{
  kind=$1; pair=$2; scen=$3; proto=$4; sysctl=$5; status=$6
  # Per-kind metric columns:
  #   F: $7=mbps  $8=recv_soft_pct
  #   G: $7=pps_recv  $8=cycles_per_pkt  $9=ins_per_pkt
  key = kind "|" pair "|" scen "|" proto "|" sysctl

  # Skip failed cells (status != ok AND status != overlay-unsupported
  # — but overlay-unsupported rows have zeroed metrics so they'd skew
  # the aggregation; explicitly skip those too).
  if (status != "ok") { skip[key]++; skip_reason[key]=status; next }

  n[key]++
  if (kind == "F") {
    sum_a[key]  += $7;  sumsq_a[key]  += $7 * $7
    sum_b[key]  += $8;  sumsq_b[key]  += $8 * $8
  } else {
    sum_a[key]  += $8;  sumsq_a[key]  += $8 * $8   # cycles_per_pkt
    sum_b[key]  += $9;  sumsq_b[key]  += $9 * $9   # ins_per_pkt
    sum_pps[key] += $7
  }
}
END {
  for (k in n) {
    cnt = n[k]
    ma = sum_a[k] / cnt
    mb = sum_b[k] / cnt
    # Sample stddev: sqrt((sum_sq - n*mean^2) / (n-1)), guarded for n=1
    if (cnt > 1) {
      var_a = (sumsq_a[k] - cnt * ma * ma) / (cnt - 1)
      var_b = (sumsq_b[k] - cnt * mb * mb) / (cnt - 1)
      sa = (var_a > 0) ? sqrt(var_a) : 0
      sb = (var_b > 0) ? sqrt(var_b) : 0
    } else { sa = 0; sb = 0 }
    pps = (sum_pps[k] > 0) ? sum_pps[k] / cnt : 0
    print k, cnt, ma, sa, mb, sb, pps
  }
  # Emit skipped-group manifest on separate stream marker
  for (k in skip) {
    print "SKIP", k, skip[k], skip_reason[k]
  }
}
EOF
)

    # ── Per-file preprocessor: detect phase from header, emit
    # normalised TSV rows (kind, pair, scen, proto, sysctl, status,
    # plus the metric columns in a kind-specific layout). ──────────
    preprocess() {
      local csv="$1"
      local header
      header=$(head -1 "$csv")
      local kind=""
      case "$header" in
        *cycles_per_pkt*) kind=G ;;
        *recv_soft_pct*)  kind=F ;;
        *) echo "WARN: unknown matrix.csv header in $csv, skipping" >&2; return ;;
      esac

      # has_rep=1 for post-H.2 matrices that include the `rep` column
      # after `cell`. Older matrices lack it; column indices shift.
      local has_rep=0
      case "$header" in
        *cell,rep,*) has_rep=1 ;;
      esac

      # Phase F columns:
      #   without rep: 1:pair 2:scen 3:cell 4:proto 5:sysctl 6:dur 7:iface 8:v4
      #                9:mbps 10:retr 11:recv_sys 12:recv_soft 13-16:consumers
      #                17:has_sysctl 18:status
      #   with rep:    1:pair 2:scen 3:cell 4:rep 5:proto 6:sysctl 7:dur 8:iface
      #                9:v4 10:mbps 11:retr 12:recv_sys 13:recv_soft 14-17:consumers
      #                18:has_sysctl 19:status
      # Phase G columns:
      #   without rep: 1:pair 2:scen 3:cell 4:sysctl 5:dur 6:pkt 7:thr 8:iface
      #                9:mac 10:pps_s 11:pps_r 12:cyc 13:ins 14:br 15:brmiss
      #                16:cyc/p 17:ins/p 18:brm/p 19:recv_sys 20:recv_soft
      #                21-24:consumers 25:has_sysctl 26:status
      #   with rep:    +1 to every index after cell
      if [ "$kind" = F ]; then
        if [ "$has_rep" = 1 ]; then
          awk -F, -v kind=F '
            NR == 1 { next }
            { print kind "\t" $1 "\t" $2 "\t" $5 "\t" $6 "\t" $19 "\t" $10 "\t" $13 }
          ' "$csv"
        else
          awk -F, -v kind=F '
            NR == 1 { next }
            { print kind "\t" $1 "\t" $2 "\t" $4 "\t" $5 "\t" $18 "\t" $9 "\t" $12 }
          ' "$csv"
        fi
      else
        if [ "$has_rep" = 1 ]; then
          awk -F, -v kind=G '
            NR == 1 { next }
            { print kind "\t" $1 "\t" $2 "\t" "udp" "\t" $5 "\t" $27 "\t" $12 "\t" $17 "\t" $18 }
          ' "$csv"
        else
          awk -F, -v kind=G '
            NR == 1 { next }
            { print kind "\t" $1 "\t" $2 "\t" "udp" "\t" $4 "\t" $26 "\t" $11 "\t" $16 "\t" $17 }
          ' "$csv"
        fi
      fi
    }

    # ── Drive: preprocess all input CSVs, awk-aggregate, then format ──
    tmp_agg=$(mktemp)
    trap 'rm -f "$tmp_agg"' EXIT
    { echo "header-placeholder-for-NR==1-skip"
      for csv in "$@"; do preprocess "$csv"; done
    } | awk "$AWK_AGG" > "$tmp_agg"

    # ── Pretty-print ───────────────────────────────────────────────
    today=$(date +%Y-%m-%d)
    cat <<MD
# Cover-letter summary: flow_dissector fast-path measurements ($today)

Mean ± sample stddev across replicates. sysctl=0 reproduces pre-patch kernel behavior (slow path); sysctl=1 enables the new fast-path. Per-cell run-to-run variance is the noise floor; "(noise)" tags rows where the slow→fast delta is within 2× pooled stddev.

MD

    # Headline: strongest |% improvement| line in Phase G cycles
    # (Phase G cycles_per_pkt is the architecture-independent
    # cover-letter signal). Compute it pre-table.
    headline=$(awk -F'\t' '
      /^SKIP/ { next }
      {
        split($1, parts, "|")
        kind=parts[1]; pair=parts[2]; scen=parts[3]; proto=parts[4]; sysctl=parts[5]
        ma=$3; sa=$4
        key=kind "|" pair "|" scen "|" proto
        if (sysctl == "0") { slow_ma[key]=ma; slow_sa[key]=sa }
        else               { fast_ma[key]=ma; fast_sa[key]=sa }
      }
      END {
        best_key=""; best_pct=0
        for (k in slow_ma) {
          if (!(k in fast_ma)) continue
          if (slow_ma[k] <= 0) continue
          delta = fast_ma[k] - slow_ma[k]
          pct = (delta / slow_ma[k]) * 100
          if (k ~ /^G\|/) {  # cycles_per_pkt — bigger drop = better
            if (-pct > best_pct) { best_pct = -pct; best_key=k; best_delta=delta; best_slow=slow_ma[k]; best_fast=fast_ma[k] }
          }
        }
        if (best_key != "") {
          split(best_key, p, "|")
          printf "**Headline:** on %s %s UDP (Phase G pktgen), the fast-path saves %.0f cycles/packet (%.1f%% reduction, %.0f → %.0f).\n", p[2], p[3], -best_delta, best_pct, best_slow, best_fast
        } else {
          print "**Headline:** no measurable Phase G signal in the supplied matrices."
        }
      }
    ' "$tmp_agg")
    echo "$headline"
    echo

    # ── Phase G table (cycles/pkt) ────────────────────────────────
    echo "## Phase G — cycles per packet (kernel pktgen, ksoftirqd perf-stat)"
    echo
    echo "| sysctl | pair | scen | slow_path | fast_path | Δ cyc/pkt | % improvement |"
    echo "|---|---|---|---|---|---|---|"
    awk -F'\t' -v sysctl_eth_ip="$(sysctl_for eth_ip)" \
                -v sysctl_vlan="$(sysctl_for vlan)" \
                -v sysctl_qinq="$(sysctl_for qinq)" \
                -v sysctl_vxlan="$(sysctl_for vxlan)" \
                -v sysctl_mpls="$(sysctl_for mpls)" \
                -v sysctl_ipip="$(sysctl_for ipip)" \
                -v sysctl_gre="$(sysctl_for gre)" \
                -v sysctl_geneve="$(sysctl_for geneve)" '
      function sysctl_for(scen) {
        if (scen == "eth_ip") return sysctl_eth_ip
        if (scen == "vlan")   return sysctl_vlan
        if (scen == "qinq")   return sysctl_qinq
        if (scen == "vxlan")  return sysctl_vxlan
        if (scen == "mpls")   return sysctl_mpls
        if (scen == "ipip")   return sysctl_ipip
        if (scen == "gre")    return sysctl_gre
        if (scen == "geneve") return sysctl_geneve
        return "net.flow_dissector.UNKNOWN"
      }
      /^SKIP/ { next }
      {
        split($1, parts, "|")
        kind=parts[1]; pair=parts[2]; scen=parts[3]; proto=parts[4]; sysctl=parts[5]
        if (kind != "G") next
        ma=$3; sa=$4
        key=pair "|" scen
        if (sysctl == "0") { slow_ma[key]=ma; slow_sa[key]=sa }
        else               { fast_ma[key]=ma; fast_sa[key]=sa }
      }
      END {
        # Emit sorted by |% improvement| desc
        n=0
        for (k in slow_ma) {
          if (!(k in fast_ma)) continue
          if (slow_ma[k] <= 0) continue
          delta = fast_ma[k] - slow_ma[k]
          pct = (delta / slow_ma[k]) * 100
          n++; keys[n]=k; abspct[n] = pct < 0 ? -pct : pct
        }
        # Simple selection sort desc
        for (i=1; i<=n; i++) {
          best=i
          for (j=i+1; j<=n; j++) if (abspct[j] > abspct[best]) best=j
          if (best != i) {
            t=keys[i]; keys[i]=keys[best]; keys[best]=t
            t=abspct[i]; abspct[i]=abspct[best]; abspct[best]=t
          }
        }
        for (i=1; i<=n; i++) {
          k=keys[i]
          split(k, p, "|")
          pair=p[1]; scen=p[2]
          delta = fast_ma[k] - slow_ma[k]
          pct = (delta / slow_ma[k]) * 100
          pooled = (slow_sa[k] + fast_sa[k]) / 2
          dabs = delta < 0 ? -delta : delta
          flag = ""
          if (dabs < 2 * pooled) flag = " (noise)"
          printf "| %s | %s | %s | %.0f ± %.0f cyc/pkt | %.0f ± %.0f cyc/pkt | %+.0f%s | %+.1f%%%s |\n", \
            sysctl_for(scen), pair, scen, slow_ma[k], slow_sa[k], fast_ma[k], fast_sa[k], delta, flag, pct, flag
        }
      }
    ' "$tmp_agg"
    echo

    # ── Phase F table (recv_soft_pct) ──────────────────────────────
    echo "## Phase F — receiver softirq % (iperf3 + RPS/CAKE/FLOWER loaded)"
    echo
    echo "| sysctl | pair | scen | proto | slow_path | fast_path | Δ pp | % improvement |"
    echo "|---|---|---|---|---|---|---|---|"
    awk -F'\t' -v sysctl_eth_ip="$(sysctl_for eth_ip)" \
                -v sysctl_vlan="$(sysctl_for vlan)" \
                -v sysctl_qinq="$(sysctl_for qinq)" \
                -v sysctl_vxlan="$(sysctl_for vxlan)" \
                -v sysctl_pppoe="$(sysctl_for pppoe)" \
                -v sysctl_mpls="$(sysctl_for mpls)" \
                -v sysctl_ipip="$(sysctl_for ipip)" \
                -v sysctl_gre="$(sysctl_for gre)" \
                -v sysctl_geneve="$(sysctl_for geneve)" \
                -v sysctl_gtpu="$(sysctl_for gtpu)" '
      function sysctl_for(scen) {
        if (scen == "eth_ip") return sysctl_eth_ip
        if (scen == "vlan")   return sysctl_vlan
        if (scen == "qinq")   return sysctl_qinq
        if (scen == "vxlan")  return sysctl_vxlan
        if (scen == "pppoe")  return sysctl_pppoe
        if (scen == "mpls")   return sysctl_mpls
        if (scen == "ipip")   return sysctl_ipip
        if (scen == "gre")    return sysctl_gre
        if (scen == "geneve") return sysctl_geneve
        if (scen == "gtpu")   return sysctl_gtpu
        return "net.flow_dissector.UNKNOWN"
      }
      /^SKIP/ { next }
      {
        split($1, parts, "|")
        kind=parts[1]; pair=parts[2]; scen=parts[3]; proto=parts[4]; sysctl=parts[5]
        if (kind != "F") next
        # $5 is recv_soft_pct mean, $6 stddev
        mb=$5; sb=$6
        key=pair "|" scen "|" proto
        if (sysctl == "0") { slow_ma[key]=mb; slow_sa[key]=sb }
        else               { fast_ma[key]=mb; fast_sa[key]=sb }
      }
      END {
        n=0
        for (k in slow_ma) {
          if (!(k in fast_ma)) continue
          delta = fast_ma[k] - slow_ma[k]
          if (slow_ma[k] > 0.01) {
            pct = (delta / slow_ma[k]) * 100
          } else { pct = 0 }
          dabs = delta < 0 ? -delta : delta
          n++; keys[n]=k; dabs_arr[n]=dabs
        }
        for (i=1; i<=n; i++) {
          best=i
          for (j=i+1; j<=n; j++) if (dabs_arr[j] > dabs_arr[best]) best=j
          if (best != i) {
            t=keys[i]; keys[i]=keys[best]; keys[best]=t
            t=dabs_arr[i]; dabs_arr[i]=dabs_arr[best]; dabs_arr[best]=t
          }
        }
        for (i=1; i<=n; i++) {
          k=keys[i]
          split(k, p, "|")
          pair=p[1]; scen=p[2]; proto=p[3]
          delta = fast_ma[k] - slow_ma[k]
          if (slow_ma[k] > 0.01) {
            pct = (delta / slow_ma[k]) * 100
          } else { pct = 0 }
          pooled = (slow_sa[k] + fast_sa[k]) / 2
          dabs = delta < 0 ? -delta : delta
          flag = ""
          if (dabs < 2 * pooled || slow_ma[k] < 0.1) flag = " (noise)"
          printf "| %s | %s | %s | %s | %.2f ± %.2f%% | %.2f ± %.2f%% | %+.2fpp%s | %+.1f%%%s |\n", \
            sysctl_for(scen), pair, scen, proto, slow_ma[k], slow_sa[k], fast_ma[k], fast_sa[k], delta, flag, pct, flag
        }
      }
    ' "$tmp_agg"
    echo

    # ── Coverage footer ────────────────────────────────────────────
    echo "## Coverage footer (skipped cells)"
    echo
    skip_count=$(awk -F'\t' '/^SKIP/ { count++ } END { print count + 0 }' "$tmp_agg")
    if [ "$skip_count" -eq 0 ]; then
      echo "_(no cells skipped)_"
    else
      echo "| group | n | reason |"
      echo "|---|---|---|"
      awk -F'\t' '/^SKIP/ { print "| " $2 " | " $3 " | " $4 " |" }' "$tmp_agg"
    fi

    echo
    echo "---"
    echo "Generated by \`nix run .#series3-summary-report\`. Source matrices:"
    for csv in "$@"; do echo "- \`$csv\`"; done
  '';
}
