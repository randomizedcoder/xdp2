#!/usr/bin/env python3
# Demonstrates that per-shape traffic composition is measurable from the
# dissector's resolved keys — the exact classification the in-kernel counter
# would use (n_proto / ip_proto / encap flags). Reads `test_parser -H` output.
import re, sys, collections
n_proto=ip_proto=enc=None
tally=collections.Counter(); total=0
def classify(n,ip,enc):
    if enc: return "encap-inner"          # FLOW_DIS_ENCAPSULATION set (descent)
    if n in ("0800","86dd"):              # IPv4 / IPv6
        return "eth_ip"
    if n in ("8100","88a8"): return "vlan/qinq"
    if n=="8864": return "pppoe"
    if n in ("8847","8848"): return "mpls"
    return "other(%s)"%n
for line in sys.stdin:
    m=re.search(r'n_proto=([0-9a-f]+) ip_proto=([0-9a-f]+)',line)
    if m: n_proto,ip_proto=m.group(1),m.group(2)
    m=re.search(r'control:.*flags=([0-9a-fx]+)',line)
    if m: enc = (int(m.group(1),16)&0x1)!=0   # FLOW_DIS_ENCAPSULATION = bit0
    if line.startswith('hash=') or line.startswith('  hash') or 'hash=' in line and n_proto:
        tally[classify(n_proto,ip_proto,enc)]+=1; total+=1
        n_proto=ip_proto=None; enc=False
print("packets=%d"%total)
for k,v in tally.most_common(): print("  %-14s %6d  (%.1f%%)"%(k,v,100*v/total if total else 0))
