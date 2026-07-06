#!/usr/bin/env python3
# gen_encap_dist.py — controlled overlay pcaps for the flow-distribution study.
#
# Question: does descending into the encapsulated INNER flow give the
# flow_dissector's consumers (RSS, RPS/RFS, ECMP/multipath, bonding/LAG,
# tc-flower, aRFS — everything that derives from skb->hash / flow_keys) a
# better flow identity than stopping at the OUTER tunnel header?
#
# We build a SINGLE VTEP pair (fixed outer src/dst IP + MACs) carrying many
# distinct inner flows, for VXLAN / GENEVE / GTP-U. For each we emit two pcaps:
#   <name>.pcap          the full overlay frame  -> "outer-only" (today's dissect)
#   <name>.inner.pcap    the inner frame alone   -> "inner-descent" (the patch)
# The inner-descent fast-path produces flow_keys (addrs/ports/basic) identical
# to dissecting the inner frame standalone, and flow_hash_from_keys() is over
# exactly those fields — so feeding the unmodified userspace dissector the inner
# frame is byte-equivalent (for the hash) to what the patch computes. That makes
# the A/B faithful with zero risk of a mis-ported descent.
#
# Outer UDP source-port variants (this is the crux of the honesty story):
#   kernelsport   outer sport = f(inner 5-tuple)  -> models real Linux VXLAN/
#                 GENEVE TX (udp_flow_src_port), where the outer tuple ALREADY
#                 carries per-inner-flow entropy. The HARD case.
#   fixedsport    outer sport pinned              -> HW VTEPs / configs that do
#                 not inner-hash the sport; genuine collapse.
# GTP-U has no sport-entropy mechanism (dport 2152), so it is generated fixed.
#
# Usage:  python3 gen_encap_dist.py --flows 2000 --packets 20000 --out .

import argparse
import os
import random
import zlib

try:
    from scapy.all import Ether, IP, IPv6, TCP, UDP, Raw, wrpcap
    from scapy.layers.vxlan import VXLAN
except Exception as e:  # pragma: no cover
    raise SystemExit("scapy required: run inside `nix develop` or "
                     "`nix shell nixpkgs#python3Packages.scapy`  (%s)" % e)

# GENEVE / GTP-U live in scapy.contrib
try:
    from scapy.contrib.geneve import GENEVE
except Exception:
    GENEVE = None
try:
    from scapy.contrib.gtp import GTP_U_Header, GTPPDUSessionContainer  # noqa
except Exception:
    GTP_U_Header = None

# ---- fixed single VTEP pair (the whole point: outer L3 does NOT vary) --------
OUTER_SMAC = "02:00:00:00:00:01"
OUTER_DMAC = "02:00:00:00:00:02"
OUTER_SIP = "10.0.0.1"      # VTEP A
OUTER_DIP = "10.0.0.2"      # VTEP B
VNI = 4711

VXLAN_PORT = 4789
GENEVE_PORT = 6081
GTPU_PORT = 2152

# ---- inner flow population (k8s-microservices-ish) ---------------------------
POD_NETS = ["10.244.%d." % i for i in range(0, 8)]     # /24 pod subnets
SVC_DPORTS = [443, 50051, 8080, 9092, 6379, 53]        # https/grpc/http/kafka/redis/dns


def _rng(seed):
    r = random.Random()
    r.seed(seed)
    return r


def make_inner_flows(n, seed):
    """n distinct inner 5-tuples (deterministic for a given seed)."""
    r = _rng(seed)
    flows = []
    for _ in range(n):
        src = r.choice(POD_NETS) + str(r.randint(2, 254))
        dst = r.choice(POD_NETS) + str(r.randint(2, 254))
        proto = "tcp" if r.random() < 0.85 else "udp"
        dport = r.choice(SVC_DPORTS)
        sport = r.randint(1024, 65535)
        flows.append((proto, src, dst, sport, dport))
    return flows


def inner_frame(flow):
    """Inner Ethernet frame (what VXLAN/GENEVE carry, and == the stripped pcap)."""
    proto, src, dst, sport, dport = flow
    l4 = (TCP(sport=sport, dport=dport, flags="A") if proto == "tcp"
          else UDP(sport=sport, dport=dport))
    # inner MACs are per-pod but irrelevant to the L3/L4 hash; vary lightly
    return (Ether(src="0a:00:00:00:00:01", dst="0a:00:00:00:00:02") /
            IP(src=src, dst=dst) / l4 / Raw(b"x" * 64))


def kernel_sport(flow):
    """Approximate Linux udp_flow_src_port(): outer sport is a function of the
    inner flow hash, mapped into the ephemeral range. Deterministic per flow."""
    proto, src, dst, sport, dport = flow
    key = ("%s|%s|%s|%d|%d" % (proto, src, dst, sport, dport)).encode()
    h = zlib.crc32(key) & 0xffffffff   # reproducible across runs
    # Linux maps into an ephemeral span; the range is what matters, not the exact
    # constant. Use the classic ephemeral span 49152..65535 (14 bits).
    return 49152 + (h % (65535 - 49152 + 1))


def build(encap, variant, flows, packets, seed):
    """Return (overlay_pkts, inner_pkts) for one encap/variant."""
    r = _rng(seed ^ (zlib.crc32(("%s|%s" % (encap, variant)).encode()) & 0xffffffff))
    overlay, inner = [], []
    for _ in range(packets):
        f = r.choice(flows)
        innerp = inner_frame(f)
        if variant == "fixedsport":
            osport = 12345
        else:  # kernelsport
            osport = kernel_sport(f)
        outer_l3 = (Ether(src=OUTER_SMAC, dst=OUTER_DMAC) /
                    IP(src=OUTER_SIP, dst=OUTER_DIP))
        if encap == "vxlan":
            pkt = (outer_l3 / UDP(sport=osport, dport=VXLAN_PORT) /
                   VXLAN(vni=VNI, flags="Instance") / innerp)
            inner.append(innerp)
        elif encap == "geneve":
            if GENEVE is None:
                raise SystemExit("scapy.contrib.geneve unavailable")
            pkt = (outer_l3 / UDP(sport=osport, dport=GENEVE_PORT) /
                   GENEVE(proto=0x6558) / innerp)     # 0x6558 = TEB
            inner.append(innerp)
        elif encap == "gtpu":
            if GTP_U_Header is None:
                raise SystemExit("scapy.contrib.gtp unavailable")
            # GTP-U carries naked inner IP (no inner Ether). For the stripped
            # pcap we wrap the inner IP in a dummy Ether so test_parser (which
            # starts at L2) can dissect it; the L3/L4 hash is unaffected.
            naked = innerp[IP]
            pkt = (outer_l3 / UDP(sport=GTPU_PORT, dport=GTPU_PORT) /
                   GTP_U_Header(teid=VNI) / naked)
            inner.append(Ether(src="0a:00:00:00:00:01",
                               dst="0a:00:00:00:00:02") / naked)
        else:
            raise SystemExit("unknown encap %s" % encap)
        overlay.append(pkt)
    return overlay, inner


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--flows", type=int, default=2000,
                    help="distinct inner flows")
    ap.add_argument("--packets", type=int, default=20000,
                    help="total packets per pcap")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--out", default=".")
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    flows = make_inner_flows(args.flows, args.seed)
    print("inner flows: %d distinct" % len(flows))

    jobs = [("vxlan", "kernelsport"), ("vxlan", "fixedsport"),
            ("geneve", "kernelsport"), ("geneve", "fixedsport"),
            ("gtpu", "fixedsport")]
    for encap, variant in jobs:
        try:
            overlay, inner = build(encap, variant, flows, args.packets, args.seed)
        except SystemExit as e:
            print("skip %s/%s: %s" % (encap, variant, e))
            continue
        base = os.path.join(args.out, "%s-%s" % (encap, variant))
        wrpcap(base + ".pcap", overlay)
        wrpcap(base + ".inner.pcap", inner)
        print("wrote %s.pcap (%d) + %s.inner.pcap (%d)"
              % (base, len(overlay), base, len(inner)))


if __name__ == "__main__":
    main()
