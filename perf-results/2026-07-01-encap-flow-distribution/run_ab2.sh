#!/usr/bin/env bash
# run_ab2.sh — comprehensive encapsulation flow-distribution matrix.
# Real kernel flow_hash_from_keys via test_parser; OUTER (today) vs INNER (patch).
set -euo pipefail
D="$(cd "$(dirname "$0")" && pwd)"; REPO="$(cd "$D/../.." && pwd)"
TP="$REPO/src/test/parser/test_parser"
P="$D/pcaps2"; H="$D/hashes2"; GEN="$D/gen_encap_dist2.py"; M="$D/dist_metrics2.py"
mkdir -p "$P" "$H"
PK="${PK:-10000}"

ab() { # name  -> dissect outer+inner, compare
  local name="$1" extra="${2:-}"
  [ -f "$P/$name.pcap" ] || return 0
  "$TP" -i "pcap,$P/$name.pcap"       -c flowdis -o text -H 2>/dev/null | grep -o 'hash=[0-9a-f]*' > "$H/$name.outer.txt"
  "$TP" -i "pcap,$P/$name.inner.pcap" -c flowdis -o text -H 2>/dev/null | grep -o 'hash=[0-9a-f]*' > "$H/$name.inner.txt"
  echo; echo "###### $name ######"
  python3 "$M" $extra --cmp "$H/$name.outer.txt" "$H/$name.inner.txt"
}

echo "############ PART 1 — address-family matrix (flows=2000, pkts=$PK) ############"
for af in "ipv4 ipv4" "ipv6 ipv4" "ipv4 ipv6" "ipv6 ipv6"; do
  set -- $af; IN=$1; OUT=$2; tag="in${IN}-out${OUT}"
  python3 "$GEN" --inner "$IN" --outer "$OUT" --flows 2000 --packets "$PK" \
    --encaps vxlan,gtpu --variants kernelsport,fixedsport --tag "$tag" --out "$P" >/dev/null
  for e in vxlan gtpu; do for v in kernelsport fixedsport; do
    [ "$e" = gtpu ] && [ "$v" = kernelsport ] && continue   # gtpu has no sport entropy
    ab "$e-$v-$tag"
  done; done
done

echo; echo "############ PART 2 — flow-count scaling (inner v4, vxlan-kernelsport & gtpu-fixedsport) ############"
echo "# shows the kernel-sport 14-bit source-port ceiling vs inner scaling"
for F in 100 1000 10000 50000; do
  pk=$(( F*4 )); [ "$pk" -gt 60000 ] && pk=60000
  python3 "$GEN" --inner ipv4 --outer ipv4 --flows "$F" --packets "$pk" \
    --encaps vxlan,gtpu --variants kernelsport,fixedsport --tag "f$F" --out "$P" >/dev/null
  echo "-- flows=$F --"
  for name in "vxlan-kernelsport-f$F" "gtpu-fixedsport-f$F"; do
    "$TP" -i "pcap,$P/$name.pcap"       -c flowdis -o text -H 2>/dev/null | grep -o 'hash=[0-9a-f]*' > "$H/$name.outer.txt"
    "$TP" -i "pcap,$P/$name.inner.pcap" -c flowdis -o text -H 2>/dev/null | grep -o 'hash=[0-9a-f]*' > "$H/$name.inner.txt"
    echo " [$name]"
    python3 "$M" --scaling --cmp "$H/$name.outer.txt" "$H/$name.inner.txt"
  done
done

echo; echo "############ PART 3 — VTEP-pair topology (vxlan-fixedsport, flows=2000, pkts=$PK) ############"
echo "# fixed-sport outer resolves ~#VTEP-pairs regardless of inner flow count"
for M_PAIRS in 1 4 16; do
  python3 "$GEN" --inner ipv4 --outer ipv4 --flows 2000 --packets "$PK" --vteps "$M_PAIRS" \
    --encaps vxlan --variants fixedsport --tag "vt$M_PAIRS" --out "$P" >/dev/null
  ab "vxlan-fixedsport-vt$M_PAIRS" --scaling
done

echo; echo "############ PART 4 — Cilium VXLAN port 8472 (patch-limit: descent hardcodes 4789) ############"
python3 "$GEN" --inner ipv4 --outer ipv4 --flows 2000 --packets "$PK" --vxlan-port 8472 \
  --encaps vxlan --variants kernelsport,fixedsport --tag "cilium8472" --out "$P" >/dev/null
echo "# NOTE: the descent patch matches dport==4789 only, so for 8472 it FALLS BACK"
echo "# to outer-only. The .inner column here is the *potential* if the port were"
echo "# recognised (the open per-netns port-config question), NOT current patch output."
ab "vxlan-fixedsport-cilium8472" --scaling
ab "vxlan-kernelsport-cilium8472" --scaling
echo; echo "DONE"
