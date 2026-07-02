#!/usr/bin/env python3
# gen_encap_dist2.py — comprehensive overlay pcaps for the flow-distribution
# study. Extends gen_encap_dist.py across the axes a reviewer/operator probes:
#   --inner {ipv4,ipv6,mix}   inner flow address family
#   --outer {ipv4,ipv6}       tunnel transport address family (v6 underlay)
#   --flows N                 distinct inner flows (drive the scaling sweep)
#   --packets N               total packets
#   --vteps M                 number of tunnel-endpoint pairs (topology)
#   --encaps vxlan,geneve,gtpu
#   --variants kernelsport,fixedsport
#   --vxlan-port P            4789 (IANA) or 8472 (Cilium) — patch-limit demo
#
# For each (encap,variant) it writes <name>.pcap (overlay = outer-only dissect)
# and <name>.inner.pcap (inner frame alone = inner-descent, byte-equivalent for
# the hash). See ANALYSIS.md for the equivalence argument.
import argparse
import ipaddress
import os
import random
import zlib

try:
    from scapy.all import Ether, IP, IPv6, TCP, UDP, Raw, wrpcap
    from scapy.layers.vxlan import VXLAN
except Exception as e:
    raise SystemExit("scapy required (%s)" % e)
try:
    from scapy.contrib.geneve import GENEVE
except Exception:
    GENEVE = None
try:
    from scapy.contrib.gtp import GTP_U_Header
except Exception:
    GTP_U_Header = None

OUTER_SMAC, OUTER_DMAC = "02:00:00:00:00:01", "02:00:00:00:00:02"
VXLAN_PORT, GENEVE_PORT, GTPU_PORT = 4789, 6081, 2152
POD4 = ["10.244.%d." % i for i in range(0, 16)]
POD6 = ["fd00:%x::" % i for i in range(1, 16)]
SVC_DPORTS = [443, 50051, 8080, 9092, 6379, 53]


def _rng(seed):
    r = random.Random(); r.seed(seed); return r


def vtep_addrs(m, outer_af):
    """m distinct (src,dst) tunnel-endpoint pairs."""
    pairs = []
    for i in range(m):
        if outer_af == "ipv6":
            pairs.append(("2001:db8:a::%x" % (i + 1), "2001:db8:b::%x" % (i + 1)))
        else:
            pairs.append(("10.0.%d.1" % i, "10.0.%d.2" % i))
    return pairs


def make_inner_flows(n, inner_af, seed):
    r = _rng(seed)
    flows = []
    for _ in range(n):
        af = inner_af
        if inner_af == "mix":
            af = "ipv6" if r.random() < 0.4 else "ipv4"
        if af == "ipv6":
            src = r.choice(POD6) + "%x" % r.randint(2, 65000)
            dst = r.choice(POD6) + "%x" % r.randint(2, 65000)
        else:
            src = r.choice(POD4) + str(r.randint(2, 254))
            dst = r.choice(POD4) + str(r.randint(2, 254))
        proto = "tcp" if r.random() < 0.85 else "udp"
        flows.append((af, proto, src, dst, r.randint(1024, 65535),
                      r.choice(SVC_DPORTS)))
    return flows


def inner_l3l4(flow):
    af, proto, src, dst, sport, dport = flow
    l4 = (TCP(sport=sport, dport=dport, flags="A") if proto == "tcp"
          else UDP(sport=sport, dport=dport))
    ip = IPv6(src=src, dst=dst) if af == "ipv6" else IP(src=src, dst=dst)
    return ip / l4 / Raw(b"x" * 48)


def inner_eth_frame(flow):
    return (Ether(src="0a:00:00:00:00:01", dst="0a:00:00:00:00:02") /
            inner_l3l4(flow))


def kernel_sport(flow):
    key = ("|".join(str(x) for x in flow)).encode()
    return 49152 + (zlib.crc32(key) & 0xffffffff) % (65535 - 49152 + 1)


def outer_l3(src, dst, outer_af):
    base = Ether(src=OUTER_SMAC, dst=OUTER_DMAC)
    return base / (IPv6(src=src, dst=dst) if outer_af == "ipv6"
                   else IP(src=src, dst=dst))


def build(encap, variant, flows, vteps, packets, outer_af, vxlan_port, seed):
    r = _rng(seed ^ (zlib.crc32(("%s|%s" % (encap, variant)).encode())
                     & 0xffffffff))
    overlay, inner = [], []
    for _ in range(packets):
        f = r.choice(flows)
        vsrc, vdst = r.choice(vteps)
        osport = 12345 if variant == "fixedsport" else kernel_sport(f)
        ol3 = outer_l3(vsrc, vdst, outer_af)
        if encap == "vxlan":
            innerf = inner_eth_frame(f)
            pkt = ol3 / UDP(sport=osport, dport=vxlan_port) / \
                VXLAN(vni=r.randint(1, 4000), flags="Instance") / innerf
            inner.append(innerf)
        elif encap == "geneve":
            if GENEVE is None:
                raise SystemExit("no scapy geneve")
            innerf = inner_eth_frame(f)
            pkt = ol3 / UDP(sport=osport, dport=GENEVE_PORT) / \
                GENEVE(proto=0x6558) / innerf
            inner.append(innerf)
        elif encap == "gtpu":
            if GTP_U_Header is None:
                raise SystemExit("no scapy gtp")
            naked = inner_l3l4(f)               # GTP-U carries naked inner IP
            pkt = ol3 / UDP(sport=GTPU_PORT, dport=GTPU_PORT) / \
                GTP_U_Header(teid=r.randint(1, 100000)) / naked
            inner.append(Ether(src="0a:00:00:00:00:01",
                               dst="0a:00:00:00:00:02") / naked)
        else:
            raise SystemExit("unknown encap")
        overlay.append(pkt)
    return overlay, inner


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--inner", default="ipv4", choices=["ipv4", "ipv6", "mix"])
    ap.add_argument("--outer", default="ipv4", choices=["ipv4", "ipv6"])
    ap.add_argument("--flows", type=int, default=2000)
    ap.add_argument("--packets", type=int, default=20000)
    ap.add_argument("--vteps", type=int, default=1)
    ap.add_argument("--vxlan-port", type=int, default=VXLAN_PORT)
    ap.add_argument("--encaps", default="vxlan,geneve,gtpu")
    ap.add_argument("--variants", default="kernelsport,fixedsport")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--tag", default="")     # filename suffix
    ap.add_argument("--out", default=".")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    flows = make_inner_flows(a.flows, a.inner, a.seed)
    vteps = vtep_addrs(a.vteps, a.outer)
    tag = ("-" + a.tag) if a.tag else ""
    for encap in a.encaps.split(","):
        for variant in a.variants.split(","):
            try:
                ov, inr = build(encap, variant, flows, vteps, a.packets,
                                a.outer, a.vxlan_port, a.seed)
            except SystemExit as e:
                print("skip %s/%s: %s" % (encap, variant, e)); continue
            base = os.path.join(a.out, "%s-%s%s" % (encap, variant, tag))
            wrpcap(base + ".pcap", ov); wrpcap(base + ".inner.pcap", inr)
            print("wrote %s.pcap (%d flows, %d pkts, inner=%s outer=%s vteps=%d)"
                  % (base, len(flows), len(ov), a.inner, a.outer, a.vteps))


if __name__ == "__main__":
    main()
