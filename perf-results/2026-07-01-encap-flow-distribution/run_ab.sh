#!/usr/bin/env bash
# run_ab.sh — generate overlay pcaps, dissect outer vs inner with the real
# kernel flow_hash_from_keys (test_parser -c flowdis -H), report distribution.
set -euo pipefail
D="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$D/../.." && pwd)"
TP="$REPO/src/test/parser/test_parser"
PCAPS="$D/pcaps"; HASHES="$D/hashes"
mkdir -p "$PCAPS" "$HASHES"

FLOWS="${FLOWS:-2000}"; PACKETS="${PACKETS:-20000}"

echo "# generating pcaps (flows=$FLOWS packets=$PACKETS) ..."
python3 "$D/gen_encap_dist.py" --flows "$FLOWS" --packets "$PACKETS" --out "$PCAPS"

echo
echo "# flow-hash distribution: OUTER-only (today) vs INNER-descent (patch)"
echo "# real kernel flow_hash_from_keys via test_parser -c flowdis -H"
echo "# flows=$FLOWS packets=$PACKETS  (generated $(date -u +%Y-%m-%dT%H:%M:%SZ))"
for name in vxlan-kernelsport vxlan-fixedsport \
            geneve-kernelsport geneve-fixedsport gtpu-fixedsport; do
  [ -f "$PCAPS/$name.pcap" ] || { echo "skip $name (no pcap)"; continue; }
  "$TP" -i "pcap,$PCAPS/$name.pcap"       -c flowdis -o text -H 2>/dev/null \
      | grep -o 'hash=[0-9a-f]*' > "$HASHES/$name.outer.txt"
  "$TP" -i "pcap,$PCAPS/$name.inner.pcap" -c flowdis -o text -H 2>/dev/null \
      | grep -o 'hash=[0-9a-f]*' > "$HASHES/$name.inner.txt"
  echo
  echo "############################## $name ##############################"
  python3 "$D/dist_metrics.py" --cmp "$HASHES/$name.outer.txt" "$HASHES/$name.inner.txt"
done
