#!/usr/bin/env python3
# Break-even matching fraction p_be = C/(S+C) for auto-enabling a fast-path shape.
# S = per-match saving (allshapes microbench ns/pkt, baseline-patched).
# C = hot-path MISS cost (pcap-miss microbench: penalty a non-matching packet pays
#     when the gate is on and it falls through to the slow path).
# Model: enabled net-positive when frac*S > (1-frac)*C  =>  frac > C/(S+C).

# S ns/pkt, from perf-results/2026-06-25-series3-allshapes-microbench/matrix.csv
S = {  # uarch: {shape: saving_ns}
 "Zen2   (x86 OoO)":  {"eth_ip":2.32,"vlan":6.26,"qinq":7.09,"pppoe":3.15,"mpls":0.49,"ipip":7.41},
 "Skylake(x86 OoO)":  {"eth_ip":3.01,"vlan":3.37,"qinq":2.93,"pppoe":2.53,"mpls":0.52,"ipip":6.67},
 "Zen1   (x86 OoO)":  {"eth_ip":0.70,"vlan":3.91,"qinq":3.95,"pppoe":1.42,"mpls":0.70,"ipip":9.68},
 "A76    (ARM OoO)":  {"eth_ip":4.34,"vlan":7.82,"qinq":12.98,"pppoe":5.29,"mpls":1.25,"ipip":16.39},
 "A72    (ARM OoO)":  {"eth_ip":8.93,"vlan":16.90,"qinq":25.58,"pppoe":11.74,"mpls":2.17,"ipip":35.10},
 "A53  (ARM in-ord)": {"eth_ip":28.25,"vlan":52.86,"qinq":72.64,"pppoe":31.00,"mpls":2.94,"ipip":79.07},
 "X60 (RV in-ord)":   {"eth_ip":31.03,"vlan":45.30,"qinq":54.08,"pppoe":29.69,"mpls":4.24,"ipip":77.35},
}
# C ns/pkt miss cost, from pcap-miss microbench (2026-06-10-series3-pi3-pcap-microbench)
# + v1 cover letter cross-uarch table. X60's C was not measured -> assumed A53-like.
C = {"Zen2   (x86 OoO)":0.2,"Skylake(x86 OoO)":0.2,"Zen1   (x86 OoO)":0.2,
     "A76    (ARM OoO)":0.6,"A72    (ARM OoO)":0.6,"A53  (ARM in-ord)":6.7,
     "X60 (RV in-ord)":6.7}

shapes=["eth_ip","vlan","qinq","pppoe","mpls","ipip"]
print("break-even matching fraction p_be = C/(S+C)  (enable a shape when its")
print("eligible traffic fraction exceeds this).  '~assumed C' marks X60.\n")
hdr="uarch (C ns)        "+" ".join("%7s"%s for s in shapes)
print(hdr); print("-"*len(hdr))
for u in S:
    c=C[u]
    row="%-16s%5.1f "%(u,c)
    for s in shapes:
        p=100.0*c/(S[u][s]+c)
        row+=" %6.1f%%"%p
    print(row)
print("\nnote: p_be uses the exact model C/(S+C), not the C/S approximation.")
print("mpls is the high-bar shape (22-32%% OoO, 60-70%% in-order); on in-order")
print("cores it only pays off if mpls is the majority of traffic.")
