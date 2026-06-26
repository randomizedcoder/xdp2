#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause-FreeBSD
#
# Workload-specific PCAP generator for the fast-path dispatch exploration
# (see xdp2-rs/docs/fast-path-dispatch.md).
#
# Models realistic traffic distributions for three representative workloads
# rather than exhaustive protocol coverage. Used by the chain-histogram
# probe to validate the Zipfian hypothesis on workloads closer to what
# production deployments actually see.
#
# Workload profiles:
#   https-web          HTTPS-dominated web server (mostly TCP/443, some DNS/ARP)
#   nfs-server         NFS file server (mostly TCP/2049, some portmap/DNS)
#   k8s-microservices  Kubernetes cluster (gRPC + Kafka over VXLAN/IPIP overlay)
#
# Distributions are rough, representative, not measured. They exercise the
# chain-histogram probe and fast-path prototype with shapes each workload
# family is expected to produce. Tune with --list to see the mix.
#
# Usage:
#   python3 gen_workload_pcap.py --workload https-web -n 10000 -o https.pcap
#   python3 gen_workload_pcap.py --workload nfs-server -n 10000 -o nfs.pcap
#   python3 gen_workload_pcap.py --workload k8s-microservices -n 10000 -o k8s.pcap
#   python3 gen_workload_pcap.py --list

import argparse
import random
import sys

try:
    from scapy.config import conf
    conf.use_pcap = False
    conf.sniff_promisc = False

    from scapy.all import (
        Ether, IP, IPv6, TCP, UDP, ICMP, ICMPv6EchoRequest, ARP, Raw, wrpcap,
    )
    from scapy.layers.l2 import Dot1Q
    from scapy.layers.ppp import PPPoE, PPP
except ImportError:
    print("Error: scapy is required (pip install scapy)", file=sys.stderr)
    sys.exit(1)

try:
    from scapy.layers.vxlan import VXLAN
except ImportError:
    from scapy.all import Packet, BitField, XByteField, ThreeBytesField
    class VXLAN(Packet):
        name = "VXLAN"
        fields_desc = [
            BitField("flags", 0x08, 8),
            BitField("reserved1", 0, 24),
            ThreeBytesField("vni", 0),
            XByteField("reserved2", 0),
        ]


# ── Random helpers ───────────────────────────────────────────────

def rand_mac():
    octets = [random.randint(0, 255) for _ in range(6)]
    octets[0] = (octets[0] & 0xfc) | 0x02
    return "%02x:%02x:%02x:%02x:%02x:%02x" % tuple(octets)

def rand_rfc1918():
    """Enterprise-internal IPv4 (10.0.0.0/8 or 192.168.0.0/16)."""
    if random.random() < 0.7:
        return "10.%d.%d.%d" % (random.randint(0, 255), random.randint(0, 255),
                                 random.randint(1, 254))
    return "192.168.%d.%d" % (random.randint(0, 255), random.randint(1, 254))

def rand_public_ipv4():
    """Any plausible unicast IPv4, avoiding 10/8, 192.168/16, 127/8."""
    while True:
        a = random.randint(1, 223)
        if a in (10, 127):
            continue
        b = random.randint(0, 255)
        if a == 192 and b == 168:
            continue
        return "%d.%d.%d.%d" % (a, b, random.randint(0, 255),
                                 random.randint(1, 254))

def rand_ipv6_global():
    return "2001:db8:%x:%x::%x" % (random.randint(0, 0xffff),
                                    random.randint(0, 0xffff),
                                    random.randint(1, 0xffff))

def rand_ipv6_ula():
    """Kubernetes often runs IPv6 ULA (fc00::/7)."""
    return "fd%02x:%x:%x::%x" % (random.randint(0, 0xff),
                                  random.randint(0, 0xffff),
                                  random.randint(0, 0xffff),
                                  random.randint(1, 0xffff))

def rand_ephemeral_port():
    return random.randint(32768, 60999)

def bimodal_payload_len():
    """Request/response traffic is bimodal: small ACKs vs MTU-sized data."""
    # 55% small packets (control/ACK), 45% MTU-sized.
    if random.random() < 0.55:
        return random.randint(20, 200)
    return random.randint(1200, 1460)

def short_payload_len():
    return random.randint(20, 120)

def rand_payload(length):
    return Raw(bytes(random.getrandbits(8) for _ in range(max(0, length))))


# ── Chain builders ───────────────────────────────────────────────
#
# Each builder returns a single scapy packet with a randomized but
# well-formed header sequence for the named chain. Ethernet layer is
# always present (we're benchmarking a software parser on L2+ traffic).

def build_eth_ipv4_tcp(dport=None, server_side=True, port_fixed=True):
    """Plain Ether/IPv4/TCP. If server_side, sport=dport (service port)."""
    dst_port = dport if dport is not None else rand_ephemeral_port()
    if server_side:
        sport, dport = dst_port, rand_ephemeral_port()
    else:
        sport, dport = rand_ephemeral_port(), dst_port
    payload_len = bimodal_payload_len() if port_fixed else short_payload_len()
    return (Ether(src=rand_mac(), dst=rand_mac()) /
            IP(src=rand_public_ipv4(), dst=rand_public_ipv4()) /
            TCP(sport=sport, dport=dport, flags="A") /
            rand_payload(payload_len))

def build_eth_ipv4_tcp_internal(dport=443, server_side=True):
    """TCP/IPv4 between RFC1918 endpoints (internal / enterprise)."""
    if server_side:
        sport, dport = dport, rand_ephemeral_port()
    else:
        sport, dport = rand_ephemeral_port(), dport
    return (Ether(src=rand_mac(), dst=rand_mac()) /
            IP(src=rand_rfc1918(), dst=rand_rfc1918()) /
            TCP(sport=sport, dport=dport, flags="A") /
            rand_payload(bimodal_payload_len()))

def build_eth_ipv6_tcp(dport=443, server_side=True):
    if server_side:
        sport, dport = dport, rand_ephemeral_port()
    else:
        sport, dport = rand_ephemeral_port(), dport
    return (Ether(src=rand_mac(), dst=rand_mac()) /
            IPv6(src=rand_ipv6_global(), dst=rand_ipv6_global()) /
            TCP(sport=sport, dport=dport, flags="A") /
            rand_payload(bimodal_payload_len()))

def build_eth_ipv4_udp(dport=53):
    return (Ether(src=rand_mac(), dst=rand_mac()) /
            IP(src=rand_rfc1918(), dst=rand_rfc1918()) /
            UDP(sport=rand_ephemeral_port(), dport=dport) /
            rand_payload(random.randint(40, 200)))

def build_eth_ipv6_udp(dport=53):
    return (Ether(src=rand_mac(), dst=rand_mac()) /
            IPv6(src=rand_ipv6_ula(), dst=rand_ipv6_ula()) /
            UDP(sport=rand_ephemeral_port(), dport=dport) /
            rand_payload(random.randint(40, 200)))

def build_eth_ipv4_icmp():
    return (Ether(src=rand_mac(), dst=rand_mac()) /
            IP(src=rand_rfc1918(), dst=rand_rfc1918()) /
            ICMP(type=8) /
            rand_payload(random.randint(32, 64)))

def build_eth_arp():
    return (Ether(src=rand_mac(), dst="ff:ff:ff:ff:ff:ff") /
            ARP(op=1, psrc=rand_rfc1918(), pdst=rand_rfc1918(),
                hwsrc=rand_mac()))


# ── VLAN 802.1Q (R3.4.5b/c fast-paths) ───────────────────────────
#
# Single 802.1Q tag, carrier-ethernet style. Random VID for spread
# across the mod-4096 VID space; PCP=0 (best-effort) to keep
# packets typical. Matches the c-xdp2-mono fast-path matcher in
# src/templates/xdp2/mono_def.template.c (R3.4.5b/c blocks).

def build_eth_vlan_ipv4_tcp(dport=443, server_side=True):
    """Eth/VLAN/IPv4/TCP — hits R3.4.5b fast-path."""
    if server_side:
        sport, dport = dport, rand_ephemeral_port()
    else:
        sport, dport = rand_ephemeral_port(), dport
    return (Ether(src=rand_mac(), dst=rand_mac()) /
            Dot1Q(vlan=random.randint(1, 4094)) /
            IP(src=rand_public_ipv4(), dst=rand_public_ipv4()) /
            TCP(sport=sport, dport=dport, flags="A") /
            rand_payload(bimodal_payload_len()))

def build_eth_vlan_ipv6_tcp(dport=443, server_side=True):
    """Eth/VLAN/IPv6/TCP — hits R3.4.5c fast-path."""
    if server_side:
        sport, dport = dport, rand_ephemeral_port()
    else:
        sport, dport = rand_ephemeral_port(), dport
    return (Ether(src=rand_mac(), dst=rand_mac()) /
            Dot1Q(vlan=random.randint(1, 4094)) /
            IPv6(src=rand_ipv6_global(), dst=rand_ipv6_global()) /
            TCP(sport=sport, dport=dport, flags="A") /
            rand_payload(bimodal_payload_len()))

def build_eth_vlan_ipv4_icmp():
    """Eth/VLAN/IPv4/ICMP — hits R3.4.5b fast-path."""
    return (Ether(src=rand_mac(), dst=rand_mac()) /
            Dot1Q(vlan=random.randint(1, 4094)) /
            IP(src=rand_rfc1918(), dst=rand_rfc1918()) /
            ICMP(type=8) /
            rand_payload(random.randint(32, 64)))


# ── PPPoE (R3.4.5d/e fast-paths) ─────────────────────────────────
#
# Consumer-ISP-style traffic: every frame carries a PPPoE session
# header (8 bytes including the trailing PPP protocol field).
# Sessions are short-lived in real life; we sample a random
# session-id per packet for spread.

def build_eth_pppoe_ipv4_tcp(dport=443, server_side=True):
    """Eth/PPPoE/PPP/IPv4/TCP — hits R3.4.5d fast-path."""
    if server_side:
        sport, dport = dport, rand_ephemeral_port()
    else:
        sport, dport = rand_ephemeral_port(), dport
    # PPP protocol 0x0021 = IPv4 (handled by the inner PPP layer).
    return (Ether(src=rand_mac(), dst=rand_mac()) /
            PPPoE(sessionid=random.randint(1, 0xFFFF)) /
            PPP(proto=0x0021) /
            IP(src=rand_public_ipv4(), dst=rand_public_ipv4()) /
            TCP(sport=sport, dport=dport, flags="A") /
            rand_payload(bimodal_payload_len()))

def build_eth_pppoe_ipv6_tcp(dport=443, server_side=True):
    """Eth/PPPoE/PPP/IPv6/TCP — hits R3.4.5e fast-path."""
    if server_side:
        sport, dport = dport, rand_ephemeral_port()
    else:
        sport, dport = rand_ephemeral_port(), dport
    return (Ether(src=rand_mac(), dst=rand_mac()) /
            PPPoE(sessionid=random.randint(1, 0xFFFF)) /
            PPP(proto=0x0057) /
            IPv6(src=rand_ipv6_global(), dst=rand_ipv6_global()) /
            TCP(sport=sport, dport=dport, flags="A") /
            rand_payload(bimodal_payload_len()))

def build_eth_pppoe_ipv4_icmp():
    """Eth/PPPoE/PPP/IPv4/ICMP — hits R3.4.5d fast-path."""
    return (Ether(src=rand_mac(), dst=rand_mac()) /
            PPPoE(sessionid=random.randint(1, 0xFFFF)) /
            PPP(proto=0x0021) /
            IP(src=rand_rfc1918(), dst=rand_rfc1918()) /
            ICMP(type=8) /
            rand_payload(random.randint(32, 64)))


# ── VXLAN / IPIP tunneling (K8s overlay) ─────────────────────────

def wrap_vxlan(inner, vni=None):
    """Wrap an inner L2 frame in Eth/IPv4/UDP(4789)/VXLAN."""
    vni = vni if vni is not None else random.randint(1, 0xffffff)
    return (Ether(src=rand_mac(), dst=rand_mac()) /
            IP(src=rand_rfc1918(), dst=rand_rfc1918()) /
            UDP(sport=rand_ephemeral_port(), dport=4789) /
            VXLAN(vni=vni) /
            inner)

def build_k8s_vxlan_grpc():
    """Pod-to-pod gRPC through VXLAN overlay. Inner chain: Eth/IPv4/TCP/9090."""
    inner = (Ether(src=rand_mac(), dst=rand_mac()) /
             IP(src=rand_rfc1918(), dst=rand_rfc1918()) /
             TCP(sport=rand_ephemeral_port(), dport=9090, flags="A") /
             rand_payload(bimodal_payload_len()))
    return wrap_vxlan(inner)

def build_k8s_vxlan_kafka():
    inner = (Ether(src=rand_mac(), dst=rand_mac()) /
             IP(src=rand_rfc1918(), dst=rand_rfc1918()) /
             TCP(sport=rand_ephemeral_port(), dport=9092, flags="A") /
             rand_payload(bimodal_payload_len()))
    return wrap_vxlan(inner)

def build_k8s_vxlan_icmp():
    inner = (Ether(src=rand_mac(), dst=rand_mac()) /
             IP(src=rand_rfc1918(), dst=rand_rfc1918()) /
             ICMP(type=8) /
             rand_payload(32))
    return wrap_vxlan(inner)

def build_k8s_ipip_tcp():
    """Calico default: IPIP-encap TCP. Chain: Eth/IPv4/IPIP/IPv4/TCP."""
    inner_ip = (IP(src=rand_rfc1918(), dst=rand_rfc1918()) /
                TCP(sport=rand_ephemeral_port(), dport=9090, flags="A") /
                rand_payload(bimodal_payload_len()))
    return (Ether(src=rand_mac(), dst=rand_mac()) /
            IP(src=rand_rfc1918(), dst=rand_rfc1918(), proto=4) /
            inner_ip)

def build_k8s_liveness_probe():
    """Kubelet liveness probe: short TCP/HTTP to random container ports."""
    return (Ether(src=rand_mac(), dst=rand_mac()) /
            IP(src=rand_rfc1918(), dst=rand_rfc1918()) /
            TCP(sport=rand_ephemeral_port(),
                dport=random.choice([8080, 8081, 8443, 9100, 15020]),
                flags="S") /
            rand_payload(0))


# ── Workload profiles ────────────────────────────────────────────
#
# Each profile is a list of (weight, builder_fn) tuples. Weights are
# relative; builder_fn takes no args and returns a scapy packet.

WORKLOADS = {
    # Typical HTTPS-dominated web server. Heavy TCP/443 both directions,
    # modest IPv6 share, DNS, some ARP + ICMP.
    "https-web": [
        (45, lambda: build_eth_ipv4_tcp(dport=443, server_side=True)),
        (25, lambda: build_eth_ipv4_tcp(dport=443, server_side=False)),
        (10, lambda: build_eth_ipv6_tcp(dport=443, server_side=True)),
        ( 4, lambda: build_eth_ipv4_tcp(dport=80, server_side=True)),
        ( 6, lambda: build_eth_ipv4_udp(dport=53)),
        ( 2, lambda: build_eth_ipv6_udp(dport=53)),
        ( 3, lambda: build_eth_ipv4_icmp()),
        ( 3, lambda: build_eth_arp()),
        ( 2, lambda: build_eth_ipv4_tcp(dport=22, server_side=True)),
    ],

    # NFSv4 file server. Mostly TCP/2049 both directions; portmapper
    # (111) for NFSv3 residuals; DNS + ARP + occasional v6.
    "nfs-server": [
        (55, lambda: build_eth_ipv4_tcp_internal(dport=2049, server_side=True)),
        (30, lambda: build_eth_ipv4_tcp_internal(dport=2049, server_side=False)),
        ( 4, lambda: build_eth_ipv4_tcp_internal(dport=111, server_side=True)),
        ( 4, lambda: build_eth_ipv4_udp(dport=53)),
        ( 3, lambda: build_eth_arp()),
        ( 2, lambda: build_eth_ipv6_tcp(dport=2049, server_side=True)),
        ( 2, lambda: build_eth_ipv4_icmp()),
    ],

    # Kubernetes cluster with a VXLAN CNI (Flannel / Calico-VXLAN),
    # microservices talking gRPC + Kafka + some service mesh. A small
    # slice of IPIP models Calico's default mode.
    "k8s-microservices": [
        (30, build_k8s_vxlan_grpc),
        (15, build_k8s_vxlan_kafka),
        (10, lambda: build_eth_ipv4_tcp_internal(dport=9090, server_side=True)),
        (10, lambda: build_eth_ipv4_tcp_internal(dport=9092, server_side=True)),
        ( 8, lambda: build_eth_ipv4_udp(dport=53)),
        ( 5, build_k8s_vxlan_icmp),
        ( 5, build_k8s_liveness_probe),
        ( 5, build_k8s_ipip_tcp),
        ( 5, lambda: build_eth_ipv6_tcp(dport=9090, server_side=True)),
        ( 4, lambda: build_eth_ipv4_tcp_internal(dport=443, server_side=True)),
        ( 3, lambda: build_eth_arp()),
    ],

    # Carrier-ethernet / metro link — every frame carries a single
    # 802.1Q VLAN tag. Mix mirrors https-web's L3/L4 ratios so
    # vlan-tcp-mix vs https-web comparison isolates the VLAN cost.
    # Exercises R3.4.5b (eth+vlan+ipv4+TCP/ICMP) and R3.4.5c
    # (eth+vlan+ipv6+TCP) fast-paths.
    "vlan-tcp-mix": [
        (45, lambda: build_eth_vlan_ipv4_tcp(dport=443, server_side=True)),
        (25, lambda: build_eth_vlan_ipv4_tcp(dport=443, server_side=False)),
        (10, lambda: build_eth_vlan_ipv6_tcp(dport=443, server_side=True)),
        ( 6, lambda: build_eth_vlan_ipv4_tcp(dport=80, server_side=True)),
        ( 4, lambda: build_eth_vlan_ipv4_tcp(dport=22, server_side=True)),
        ( 4, lambda: build_eth_vlan_ipv4_icmp()),
        ( 6, lambda: build_eth_vlan_ipv6_tcp(dport=22, server_side=True)),
    ],

    # Consumer ISP PPPoE access — every frame is PPPoE-encapped
    # (PPP_IP for IPv4, PPP_IPV6 for IPv6). Exercises R3.4.5d
    # (eth+PPPoE+ipv4+TCP/ICMP) and R3.4.5e (eth+PPPoE+ipv6+TCP).
    "pppoe-isp": [
        (50, lambda: build_eth_pppoe_ipv4_tcp(dport=443, server_side=True)),
        (20, lambda: build_eth_pppoe_ipv4_tcp(dport=443, server_side=False)),
        (10, lambda: build_eth_pppoe_ipv6_tcp(dport=443, server_side=True)),
        ( 8, lambda: build_eth_pppoe_ipv4_tcp(dport=80, server_side=True)),
        ( 5, lambda: build_eth_pppoe_ipv4_icmp()),
        ( 4, lambda: build_eth_pppoe_ipv4_tcp(dport=22, server_side=True)),
        ( 3, lambda: build_eth_pppoe_ipv6_tcp(dport=80, server_side=True)),
    ],

    # All-VXLAN (no plain bypass). Forces every packet through the
    # slow-path tunnel walk so the perf number isolates the
    # post-R3.4.5b UDP-fast-path-drop cost (mono now correctly
    # walks into the inner Ethernet + IP + L4 instead of
    # short-circuiting at outer UDP).
    "vxlan-k8s-pure": [
        (60, build_k8s_vxlan_grpc),
        (25, build_k8s_vxlan_kafka),
        (10, build_k8s_vxlan_icmp),
        ( 5, build_k8s_liveness_probe),
    ],

    # Controlled-ratio mix workloads. Each has p% fast-path-eligible
    # packets (bare eth+IPv4/IPv6+TCP/443, IHL=5, no fragmentation)
    # and (1-p)% non-matching packets evenly split across three
    # decline-reasons: ICMP (protocol != TCP/UDP), VLAN (non-IP
    # ethertype), VXLAN-encap (outer UDP plus encap-port check).
    # The eligible share splits ~80/20 between v4 and v6 to
    # exercise both fast-path branches.
    #
    # Used by perf-results/2026-06-XX-series3-controlled-mix/ to
    # demonstrate the linear-scaling claim from the cover letter:
    # measured ns/pkt should sit at baseline + (1-p)*dispatcher_overhead
    # − p*fast_path_savings. A clean monotone curve at five p-points
    # confirms the per-packet cost model.
    "series3-fast-vs-slow-10": [
        ( 8, lambda: build_eth_ipv4_tcp(dport=443, server_side=True)),
        ( 2, lambda: build_eth_ipv6_tcp(dport=443, server_side=True)),
        (30, lambda: build_eth_ipv4_icmp()),
        (30, lambda: build_eth_vlan_ipv4_tcp(dport=443, server_side=True)),
        (30, build_k8s_vxlan_grpc),
    ],
    "series3-fast-vs-slow-25": [
        (20, lambda: build_eth_ipv4_tcp(dport=443, server_side=True)),
        ( 5, lambda: build_eth_ipv6_tcp(dport=443, server_side=True)),
        (25, lambda: build_eth_ipv4_icmp()),
        (25, lambda: build_eth_vlan_ipv4_tcp(dport=443, server_side=True)),
        (25, build_k8s_vxlan_grpc),
    ],
    "series3-fast-vs-slow-50": [
        (40, lambda: build_eth_ipv4_tcp(dport=443, server_side=True)),
        (10, lambda: build_eth_ipv6_tcp(dport=443, server_side=True)),
        (16, lambda: build_eth_ipv4_icmp()),
        (17, lambda: build_eth_vlan_ipv4_tcp(dport=443, server_side=True)),
        (17, build_k8s_vxlan_grpc),
    ],
    "series3-fast-vs-slow-75": [
        (60, lambda: build_eth_ipv4_tcp(dport=443, server_side=True)),
        (15, lambda: build_eth_ipv6_tcp(dport=443, server_side=True)),
        ( 8, lambda: build_eth_ipv4_icmp()),
        ( 8, lambda: build_eth_vlan_ipv4_tcp(dport=443, server_side=True)),
        ( 9, build_k8s_vxlan_grpc),
    ],
    "series3-fast-vs-slow-90": [
        (72, lambda: build_eth_ipv4_tcp(dport=443, server_side=True)),
        (18, lambda: build_eth_ipv6_tcp(dport=443, server_side=True)),
        ( 3, lambda: build_eth_ipv4_icmp()),
        ( 3, lambda: build_eth_vlan_ipv4_tcp(dport=443, server_side=True)),
        ( 4, build_k8s_vxlan_grpc),
    ],
}


# ── Generator driver ─────────────────────────────────────────────

def generate(workload, count, seed=None):
    if seed is not None:
        random.seed(seed)
    mix = WORKLOADS[workload]
    weights = [w for w, _ in mix]
    builders = [b for _, b in mix]
    pkts = []
    for _ in range(count):
        build = random.choices(builders, weights=weights, k=1)[0]
        pkts.append(build())
    return pkts


def print_mix(workload):
    mix = WORKLOADS[workload]
    total = sum(w for w, _ in mix)
    print(f"workload: {workload}  entries: {len(mix)}  total weight: {total}")
    for weight, builder in mix:
        pct = 100.0 * weight / total
        name = builder.__name__ if hasattr(builder, '__name__') else '<lambda>'
        print(f"  {pct:5.1f}%  ({weight:3d}/{total})  {name}")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--workload", choices=sorted(WORKLOADS.keys()),
                    help="Workload profile to synthesize")
    ap.add_argument("-n", "--count", type=int, default=10000,
                    help="Number of packets to generate (default: 10000)")
    ap.add_argument("-o", "--output", default="workload.pcap",
                    help="Output PCAP path (default: workload.pcap)")
    ap.add_argument("--seed", type=int, default=None,
                    help="Random seed for deterministic output")
    ap.add_argument("--list", action="store_true",
                    help="List workloads and their mixes, then exit")
    args = ap.parse_args()

    if args.list:
        for name in sorted(WORKLOADS.keys()):
            print_mix(name)
            print()
        return 0

    if not args.workload:
        ap.error("--workload is required (or pass --list)")

    pkts = generate(args.workload, args.count, seed=args.seed)
    wrpcap(args.output, pkts)
    print(f"Wrote {len(pkts)} packets to {args.output} (workload={args.workload})",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
