#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause-FreeBSD
#
# Generate a comprehensive PCAP with diverse packet types for testing
# the BPF flow dissector against the kernel flow dissector.
#
# Requires: scapy (pip install scapy)
#
# Usage:
#   python3 gen_test_pcap.py [-o output.pcap] [-n 10000]

import argparse
import random
import sys

try:
    from scapy.all import (
        Ether, IP, IPv6, TCP, UDP, ICMP, ICMPv6EchoRequest,
        GRE, MPLS, Raw, Dot1Q,
        IPv6ExtHdrHopByHop, IPv6ExtHdrDestOpt, IPv6ExtHdrFragment,
        IPv6ExtHdrRouting, PadN, wrpcap,
    )
except ImportError:
    print("Error: scapy is required. Install with: pip install scapy",
          file=sys.stderr)
    sys.exit(1)


def rand_ipv4():
    return "%d.%d.%d.%d" % (random.randint(1, 254), random.randint(0, 255),
                             random.randint(0, 255), random.randint(1, 254))


def rand_ipv6():
    return "2001:db8:%04x:%04x:%04x:%04x:%04x:%04x" % tuple(
        random.randint(0, 0xffff) for _ in range(6))


def rand_port():
    return random.randint(1024, 65535)


def rand_payload(min_len=20, max_len=100):
    length = random.randint(min_len, max_len)
    return Raw(bytes(random.getrandbits(8) for _ in range(length)))


def gen_ipv4_tcp(count):
    """IPv4 TCP packets with varied addresses and ports."""
    pkts = []
    for _ in range(count):
        pkt = (Ether() /
               IP(src=rand_ipv4(), dst=rand_ipv4(),
                  ttl=random.randint(32, 128)) /
               TCP(sport=rand_port(), dport=rand_port(),
                   flags=random.choice(["S", "SA", "A", "PA", "F"])) /
               rand_payload())
        pkts.append(pkt)
    return pkts


def gen_ipv4_udp(count):
    """IPv4 UDP packets."""
    pkts = []
    for _ in range(count):
        pkt = (Ether() /
               IP(src=rand_ipv4(), dst=rand_ipv4()) /
               UDP(sport=rand_port(), dport=rand_port()) /
               rand_payload())
        pkts.append(pkt)
    return pkts


def gen_ipv6_tcp(count):
    """IPv6 TCP packets."""
    pkts = []
    for _ in range(count):
        fl = random.randint(0, 0xfffff)
        pkt = (Ether() /
               IPv6(src=rand_ipv6(), dst=rand_ipv6(), fl=fl) /
               TCP(sport=rand_port(), dport=rand_port()) /
               rand_payload())
        pkts.append(pkt)
    return pkts


def gen_ipv6_udp(count):
    """IPv6 UDP packets."""
    pkts = []
    for _ in range(count):
        fl = random.randint(0, 0xfffff)
        pkt = (Ether() /
               IPv6(src=rand_ipv6(), dst=rand_ipv6(), fl=fl) /
               UDP(sport=rand_port(), dport=rand_port()) /
               rand_payload())
        pkts.append(pkt)
    return pkts


def gen_ipv4_icmp(count):
    """IPv4 ICMP echo packets."""
    pkts = []
    for _ in range(count):
        pkt = (Ether() /
               IP(src=rand_ipv4(), dst=rand_ipv4()) /
               ICMP(type=8, code=0, id=random.randint(1, 65535),
                    seq=random.randint(0, 65535)) /
               rand_payload(8, 56))
        pkts.append(pkt)
    return pkts


def gen_ipv6_icmpv6(count):
    """IPv6 ICMPv6 echo request packets."""
    pkts = []
    for _ in range(count):
        pkt = (Ether() /
               IPv6(src=rand_ipv6(), dst=rand_ipv6()) /
               ICMPv6EchoRequest(id=random.randint(1, 65535),
                                 seq=random.randint(0, 65535)) /
               rand_payload(8, 56))
        pkts.append(pkt)
    return pkts


def gen_vlan_tagged(count):
    """VLAN tagged packets (802.1Q and 802.1AD/QinQ)."""
    pkts = []
    for i in range(count):
        vid = random.randint(1, 4094)
        prio = random.randint(0, 7)

        if i < count // 3:
            # 802.1Q single tagged
            pkt = (Ether() /
                   Dot1Q(vlan=vid, prio=prio) /
                   IP(src=rand_ipv4(), dst=rand_ipv4()) /
                   TCP(sport=rand_port(), dport=rand_port()) /
                   rand_payload())
        elif i < 2 * count // 3:
            # 802.1Q single tagged IPv6
            pkt = (Ether() /
                   Dot1Q(vlan=vid, prio=prio) /
                   IPv6(src=rand_ipv6(), dst=rand_ipv6()) /
                   UDP(sport=rand_port(), dport=rand_port()) /
                   rand_payload())
        else:
            # 802.1AD (QinQ) double tagged
            outer_vid = random.randint(1, 4094)
            pkt = (Ether(type=0x88a8) /
                   Dot1Q(vlan=outer_vid, prio=random.randint(0, 7),
                         type=0x8100) /
                   Dot1Q(vlan=vid, prio=prio) /
                   IP(src=rand_ipv4(), dst=rand_ipv4()) /
                   TCP(sport=rand_port(), dport=rand_port()) /
                   rand_payload())
        pkts.append(pkt)
    return pkts


def gen_ipv4_frag(count):
    """IPv4 fragmented packets."""
    pkts = []
    for i in range(count):
        if i < count // 2:
            # First fragment (MF=1, offset=0)
            pkt = (Ether() /
                   IP(src=rand_ipv4(), dst=rand_ipv4(),
                      flags="MF", frag=0, id=random.randint(1, 65535)) /
                   UDP(sport=rand_port(), dport=rand_port()) /
                   rand_payload(20, 40))
        else:
            # Non-first fragment (offset > 0)
            pkt = (Ether() /
                   IP(src=rand_ipv4(), dst=rand_ipv4(),
                      flags="MF", frag=185, id=random.randint(1, 65535),
                      proto=17) /
                   rand_payload(20, 40))
        pkts.append(pkt)
    return pkts


def gen_ipv6_frag(count):
    """IPv6 fragmented packets."""
    pkts = []
    for i in range(count):
        if i < count // 2:
            # First fragment
            pkt = (Ether() /
                   IPv6(src=rand_ipv6(), dst=rand_ipv6()) /
                   IPv6ExtHdrFragment(nh=17, m=1, offset=0,
                                      id=random.randint(1, 0xffffffff)) /
                   UDP(sport=rand_port(), dport=rand_port()) /
                   rand_payload(8, 40))
        else:
            # Non-first fragment
            pkt = (Ether() /
                   IPv6(src=rand_ipv6(), dst=rand_ipv6()) /
                   IPv6ExtHdrFragment(nh=17, m=1, offset=185,
                                      id=random.randint(1, 0xffffffff)) /
                   rand_payload(20, 40))
        pkts.append(pkt)
    return pkts


def gen_ipv6_ext_headers(count):
    """IPv6 with extension headers (hop-by-hop, destination, routing)."""
    pkts = []
    for i in range(count):
        eh_type = i % 3
        if eh_type == 0:
            # Hop-by-hop options
            pkt = (Ether() /
                   IPv6(src=rand_ipv6(), dst=rand_ipv6()) /
                   IPv6ExtHdrHopByHop(options=[PadN(optdata=b'\x00' * 4)]) /
                   TCP(sport=rand_port(), dport=rand_port()) /
                   rand_payload())
        elif eh_type == 1:
            # Destination options
            pkt = (Ether() /
                   IPv6(src=rand_ipv6(), dst=rand_ipv6()) /
                   IPv6ExtHdrDestOpt(options=[PadN(optdata=b'\x00' * 4)]) /
                   UDP(sport=rand_port(), dport=rand_port()) /
                   rand_payload())
        else:
            # Routing header
            pkt = (Ether() /
                   IPv6(src=rand_ipv6(), dst=rand_ipv6()) /
                   IPv6ExtHdrRouting() /
                   TCP(sport=rand_port(), dport=rand_port()) /
                   rand_payload())
        pkts.append(pkt)
    return pkts


def gen_gre(count):
    """GRE v0 tunneled packets."""
    pkts = []
    for i in range(count):
        if i < count // 2:
            # GRE with no optional fields
            inner = (IP(src=rand_ipv4(), dst=rand_ipv4()) /
                     TCP(sport=rand_port(), dport=rand_port()) /
                     rand_payload())
            pkt = (Ether() /
                   IP(src=rand_ipv4(), dst=rand_ipv4(), proto=47) /
                   GRE() / inner)
        else:
            # GRE with key
            inner = (IP(src=rand_ipv4(), dst=rand_ipv4()) /
                     UDP(sport=rand_port(), dport=rand_port()) /
                     rand_payload())
            pkt = (Ether() /
                   IP(src=rand_ipv4(), dst=rand_ipv4(), proto=47) /
                   GRE(key_present=1, key=random.randint(1, 0xffffffff)) /
                   inner)
        pkts.append(pkt)
    return pkts


def gen_mpls(count):
    """MPLS labeled packets."""
    pkts = []
    for _ in range(count):
        label = random.randint(16, 0xfffff)
        pkt = (Ether(type=0x8847) /
               MPLS(label=label, s=1, ttl=random.randint(1, 255)) /
               IP(src=rand_ipv4(), dst=rand_ipv4()) /
               TCP(sport=rand_port(), dport=rand_port()) /
               rand_payload())
        pkts.append(pkt)
    return pkts


def gen_ipip(count):
    """IP-in-IP encapsulated packets (IPPROTO_IPIP and IPPROTO_IPV6)."""
    pkts = []
    for i in range(count):
        if i < count // 2:
            # IPv4-in-IPv4
            inner = (IP(src=rand_ipv4(), dst=rand_ipv4()) /
                     TCP(sport=rand_port(), dport=rand_port()) /
                     rand_payload())
            pkt = (Ether() /
                   IP(src=rand_ipv4(), dst=rand_ipv4(), proto=4) /
                   inner)
        else:
            # IPv6-in-IPv4
            inner = (IPv6(src=rand_ipv6(), dst=rand_ipv6()) /
                     TCP(sport=rand_port(), dport=rand_port()) /
                     rand_payload())
            pkt = (Ether() /
                   IP(src=rand_ipv4(), dst=rand_ipv4(), proto=41) /
                   inner)
        pkts.append(pkt)
    return pkts


def main():
    parser = argparse.ArgumentParser(
        description="Generate test PCAP for flow dissector benchmark")
    parser.add_argument("-o", "--output", default="test_flow_dissector.pcap",
                        help="Output PCAP file (default: test_flow_dissector.pcap)")
    parser.add_argument("-n", "--count", type=int, default=10000,
                        help="Total number of packets (default: 10000)")
    parser.add_argument("-s", "--seed", type=int, default=42,
                        help="Random seed (default: 42)")
    args = parser.parse_args()

    random.seed(args.seed)
    n = args.count

    # Packet distribution (proportional to total count)
    distribution = [
        ("IPv4 TCP",      gen_ipv4_tcp,          int(n * 0.30)),
        ("IPv4 UDP",      gen_ipv4_udp,          int(n * 0.20)),
        ("IPv6 TCP",      gen_ipv6_tcp,          int(n * 0.15)),
        ("IPv6 UDP",      gen_ipv6_udp,          int(n * 0.10)),
        ("IPv4 ICMP",     gen_ipv4_icmp,         int(n * 0.05)),
        ("IPv6 ICMPv6",   gen_ipv6_icmpv6,       int(n * 0.03)),
        ("VLAN tagged",   gen_vlan_tagged,        int(n * 0.05)),
        ("IPv4 fragment",  gen_ipv4_frag,         int(n * 0.03)),
        ("IPv6 fragment",  gen_ipv6_frag,         int(n * 0.02)),
        ("IPv6 ext hdrs", gen_ipv6_ext_headers,  int(n * 0.02)),
        ("GRE",           gen_gre,               int(n * 0.02)),
        ("MPLS",          gen_mpls,              int(n * 0.01)),
        ("IP-in-IP",      gen_ipip,              int(n * 0.01)),
    ]

    # Adjust last category to reach exact count
    allocated = sum(count for _, _, count in distribution)
    if allocated < n:
        name, gen, count = distribution[0]
        distribution[0] = (name, gen, count + (n - allocated))

    all_packets = []
    for name, gen_fn, count in distribution:
        if count > 0:
            pkts = gen_fn(count)
            all_packets.extend(pkts)
            print("  %-20s %5d packets" % (name, len(pkts)))

    # Shuffle for realistic traffic mix
    random.shuffle(all_packets)

    print("\nTotal: %d packets" % len(all_packets))
    print("Writing: %s" % args.output)

    wrpcap(args.output, all_packets)
    print("Done.")


if __name__ == "__main__":
    main()
