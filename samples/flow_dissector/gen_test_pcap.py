#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause-FreeBSD
#
# Combinatorial PCAP generator for the flow dissector benchmark.
#
# Generates packets covering all valid L2×L3×L4×tunnel permutations
# for carrier/telco-grade protocol coverage testing.
#
# Requires: scapy (pip install scapy)
#
# Usage:
#   python3 gen_test_pcap.py [-o output.pcap] [-n 10000]
#   python3 gen_test_pcap.py --list          # List all valid combinations
#   python3 gen_test_pcap.py --combo bare/ipv4/tcp  # Single combination

import argparse
import fnmatch
import random
import struct
import sys

try:
    # Configure scapy for offline PCAP generation before importing layers.
    # This avoids route/DNS lookups that fail in sandboxed environments.
    from scapy.config import conf
    conf.use_pcap = False        # No live capture needed
    conf.sniff_promisc = False   # No sniffing needed

    from scapy.all import (
        Ether, IP, IPv6, TCP, UDP, ICMP, ICMPv6EchoRequest,
        GRE, Raw, Dot1Q, ARP,
        IPv6ExtHdrHopByHop, IPv6ExtHdrDestOpt, IPv6ExtHdrFragment,
        IPv6ExtHdrRouting, PadN, wrpcap,
    )
    from scapy.contrib.geneve import GENEVE
    from scapy.contrib.igmp import IGMP
except ImportError:
    print("Error: scapy is required. Install with: pip install scapy",
          file=sys.stderr)
    sys.exit(1)

# MPLS may be in scapy.all or scapy.contrib.mpls depending on version
try:
    from scapy.all import MPLS
except ImportError:
    try:
        from scapy.contrib.mpls import MPLS
    except ImportError:
        from scapy.all import Packet, BitField
        class MPLS(Packet):
            name = "MPLS"
            fields_desc = [
                BitField("label", 3, 20),
                BitField("cos", 0, 3),
                BitField("s", 1, 1),
                BitField("ttl", 64, 8),
            ]

# Try importing VXLAN
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


# ─── Random value generators ───

def rand_mac():
    """Generate a random unicast locally-administered MAC address."""
    mac = [random.randint(0, 255) for _ in range(6)]
    mac[0] = (mac[0] & 0xfc) | 0x02  # Clear multicast, set locally-administered
    return "%02x:%02x:%02x:%02x:%02x:%02x" % tuple(mac)

def rand_ipv4():
    return "%d.%d.%d.%d" % (random.randint(1, 254), random.randint(0, 255),
                             random.randint(0, 255), random.randint(1, 254))

def rand_ipv6():
    return "2001:db8:%04x:%04x:%04x:%04x:%04x:%04x" % tuple(
        random.randint(0, 0xffff) for _ in range(6))

def rand_port():
    return random.randint(1024, 65535)

def rand_vlan():
    return random.randint(1, 4094)

def rand_prio():
    return random.randint(0, 7)

def rand_label():
    return random.randint(16, 0xfffff)

def rand_vni():
    return random.randint(1, 0xffffff)

def rand_spi():
    return random.randint(1, 0xffffffff)

def rand_session_id():
    return random.randint(1, 0xffffffff)

def rand_payload(min_len=20, max_len=60):
    length = random.randint(min_len, max_len)
    return Raw(bytes(random.getrandbits(8) for _ in range(length)))

def rand_fl():
    return random.randint(0, 0xfffff)

def rand_word():
    return random.randint(0, 0xffffffff)


# ─── PPPoE header (scapy doesn't have a good PPPoE/PPP combo) ───

try:
    from scapy.layers.ppp import PPPoE, PPP
    HAS_PPPOE = True
except ImportError:
    HAS_PPPOE = False

def make_pppoe_ipv4(inner):
    """Wrap inner IP payload in PPPoE/PPP."""
    if HAS_PPPOE:
        return (PPPoE(sessionid=random.randint(1, 0xffff)) /
                PPP(proto=0x0021) / inner)
    # Manual PPPoE header: ver=1, type=1, code=0, session_id, length, ppp_proto
    sid = random.randint(1, 0xffff)
    inner_bytes = bytes(inner)
    ppp_proto = b'\x00\x21'  # PPP_IP
    length = len(inner_bytes) + 2
    hdr = struct.pack("!BBHH", 0x11, 0x00, sid, length) + ppp_proto
    return Raw(hdr + inner_bytes)

def make_pppoe_ipv6(inner):
    """Wrap inner IPv6 payload in PPPoE/PPP."""
    if HAS_PPPOE:
        return (PPPoE(sessionid=random.randint(1, 0xffff)) /
                PPP(proto=0x0057) / inner)
    sid = random.randint(1, 0xffff)
    inner_bytes = bytes(inner)
    ppp_proto = b'\x00\x57'  # PPP_IPV6
    length = len(inner_bytes) + 2
    hdr = struct.pack("!BBHH", 0x11, 0x00, sid, length) + ppp_proto
    return Raw(hdr + inner_bytes)


# ─── ESP / AH headers (manual construction) ───

def make_esp(spi=None):
    """ESP header + fake encrypted payload."""
    if spi is None:
        spi = rand_spi()
    seq = random.randint(1, 0xffffffff)
    hdr = struct.pack("!II", spi, seq)
    # Fake encrypted payload
    payload = bytes(random.getrandbits(8) for _ in range(32))
    return Raw(hdr + payload)

def make_ah_tcp(spi=None):
    """AH header (nexthdr=TCP) + ICV + TCP payload."""
    if spi is None:
        spi = rand_spi()
    seq = random.randint(1, 0xffffffff)
    # AH: nexthdr=6(TCP), hdrlen=4 (total=(4+2)*4=24 bytes), reserved=0
    # ICV is 12 bytes (hdrlen=4 means 24 total - 12 fixed = 12 ICV bytes)
    icv = bytes(12)
    hdr = struct.pack("!BBH II", 6, 4, 0, spi, seq) + icv
    tcp = TCP(sport=rand_port(), dport=rand_port())
    return Raw(hdr + bytes(tcp / rand_payload()))

def make_ah_esp(spi_ah=None, spi_esp=None):
    """AH header (nexthdr=ESP) + ICV + ESP payload."""
    if spi_ah is None:
        spi_ah = rand_spi()
    if spi_esp is None:
        spi_esp = rand_spi()
    seq = random.randint(1, 0xffffffff)
    icv = bytes(12)
    hdr = struct.pack("!BBH II", 50, 4, 0, spi_ah, seq) + icv
    esp = make_esp(spi_esp)
    return Raw(hdr + bytes(esp))


# ─── L2TP session header ───

def make_l2tp_session():
    """L2TPv3 session header (just 4-byte session_id over IP)."""
    session_id = rand_session_id()
    return Raw(struct.pack("!I", session_id))


# ─── SCTP header (manual, since scapy's SCTP is incomplete) ───

def make_sctp():
    """Minimal SCTP header for port extraction."""
    sport = rand_port()
    dport = rand_port()
    vtag = random.randint(0, 0xffffffff)
    checksum = 0
    hdr = struct.pack("!HH II", sport, dport, vtag, checksum)
    return Raw(hdr + bytes(20))


# ─── TIPC header (manual) ───

def make_tipc():
    """TIPC basic header: 4 x __be32 words."""
    # Non-keepalive message (don't set keepalive mask)
    w0 = random.randint(0, 0xffffffff) & ~0x0e080000
    w1 = rand_word()
    w2 = rand_word()
    w3 = rand_word()  # Source node identity
    return Raw(struct.pack("!IIII", w0, w1, w2, w3))


# ─── Combination definitions ───

# Each combination is a tuple: (name, builder_function)
# The builder returns a list of scapy packets.

def build_pkt(l2_name, l3_inner, l4_inner, mpls_labels=0,
              tunnel=None, inner_l3=None, inner_l4=None):
    """Build a packet from layer specifications."""

    # Build innermost L4
    if inner_l4 == "tcp" or (l4_inner == "tcp" and not tunnel):
        l4 = l4_inner if not tunnel else inner_l4
        l4_pkt = TCP(sport=rand_port(), dport=rand_port(),
                     flags=random.choice(["S", "SA", "A", "PA"])) / rand_payload()
    elif inner_l4 == "udp" or (l4_inner == "udp" and not tunnel):
        l4_pkt = UDP(sport=rand_port(), dport=rand_port()) / rand_payload()
    else:
        l4_pkt = None

    # Build inner L3+L4 (for tunnel inner)
    if tunnel and inner_l3 and l4_pkt is not None:
        if "ipv4" in inner_l3:
            inner_pkt = IP(src=rand_ipv4(), dst=rand_ipv4()) / l4_pkt
        else:
            inner_pkt = IPv6(src=rand_ipv6(), dst=rand_ipv6(),
                             fl=rand_fl()) / l4_pkt
    else:
        inner_pkt = None

    # Build L3+L4 (main or outer)
    l3l4 = _build_l3l4(l3_inner, l4_inner, tunnel, inner_pkt)
    if l3l4 is None:
        return None

    # Add MPLS labels
    if mpls_labels > 0:
        mpls_stack = None
        for i in range(mpls_labels):
            s_bit = 1 if i == mpls_labels - 1 else 0
            label = MPLS(label=rand_label(), s=s_bit,
                         ttl=random.randint(1, 255))
            mpls_stack = label / mpls_stack if mpls_stack else label
        l3l4 = mpls_stack / l3l4

    # Build L2
    return _build_l2(l2_name, l3_inner, l3l4, mpls_labels)


def _build_l3l4(l3, l4, tunnel, inner_pkt):
    """Build L3 + L4 layers."""
    if l3 == "ipv4":
        ip = IP(src=rand_ipv4(), dst=rand_ipv4(),
                ttl=random.randint(32, 128))
    elif l3 == "ipv6":
        ip = IPv6(src=rand_ipv6(), dst=rand_ipv6(), fl=rand_fl())
    elif l3 == "ipv6_hbh":
        ip = (IPv6(src=rand_ipv6(), dst=rand_ipv6(), fl=rand_fl()) /
              IPv6ExtHdrHopByHop(options=[PadN(optdata=b'\x00' * 4)]))
    elif l3 == "ipv6_dst":
        ip = (IPv6(src=rand_ipv6(), dst=rand_ipv6(), fl=rand_fl()) /
              IPv6ExtHdrDestOpt(options=[PadN(optdata=b'\x00' * 4)]))
    elif l3 == "ipv6_routing":
        ip = (IPv6(src=rand_ipv6(), dst=rand_ipv6(), fl=rand_fl()) /
              IPv6ExtHdrRouting())
    elif l3 == "ipv6_frag_first":
        ip = (IPv6(src=rand_ipv6(), dst=rand_ipv6(), fl=rand_fl()) /
              IPv6ExtHdrFragment(nh=17, m=1, offset=0,
                                 id=random.randint(1, 0xffffffff)))
    elif l3 == "ipv6_frag_mid":
        ip = (IPv6(src=rand_ipv6(), dst=rand_ipv6(), fl=rand_fl()) /
              IPv6ExtHdrFragment(nh=17, m=1, offset=185,
                                 id=random.randint(1, 0xffffffff)))
    elif l3 == "ipv6_hbh_dst":
        ip = (IPv6(src=rand_ipv6(), dst=rand_ipv6(), fl=rand_fl()) /
              IPv6ExtHdrHopByHop(options=[PadN(optdata=b'\x00' * 4)]) /
              IPv6ExtHdrDestOpt(options=[PadN(optdata=b'\x00' * 4)]))
    elif l3 == "ipv4_frag_first":
        ip = IP(src=rand_ipv4(), dst=rand_ipv4(), flags="MF", frag=0,
                id=random.randint(1, 65535))
    elif l3 == "ipv4_frag_mid":
        ip = IP(src=rand_ipv4(), dst=rand_ipv4(), flags="MF", frag=185,
                id=random.randint(1, 65535), proto=17)
        # No L4 header for mid-fragment
        return ip / rand_payload()
    else:
        return None

    # Build L4
    if tunnel == "gre":
        return ip / GRE() / inner_pkt
    elif tunnel == "gre_key":
        return ip / GRE(key_present=1,
                        key=random.randint(1, 0xffffffff)) / inner_pkt
    elif tunnel == "ipip_v4":
        return ip / inner_pkt  # proto=4 set by scapy
    elif tunnel == "ipip_v6":
        return ip / inner_pkt  # proto=41 set by scapy
    elif tunnel == "vxlan":
        return (ip / UDP(sport=rand_port(), dport=4789) /
                VXLAN(vni=rand_vni()) /
                Ether(src=rand_mac(), dst=rand_mac()) / inner_pkt)
    elif tunnel == "geneve":
        return (ip / UDP(sport=rand_port(), dport=6081) /
                GENEVE(vni=rand_vni()) /
                Ether(src=rand_mac(), dst=rand_mac()) / inner_pkt)

    # No tunnel — direct L4
    if l4 == "tcp":
        return ip / TCP(sport=rand_port(), dport=rand_port(),
                        flags=random.choice(["S", "SA", "A", "PA"])) / \
               rand_payload()
    elif l4 == "udp":
        return ip / UDP(sport=rand_port(), dport=rand_port()) / rand_payload()
    elif l4 == "icmp":
        return ip / ICMP(type=8, code=0, id=random.randint(1, 65535),
                         seq=random.randint(0, 65535)) / rand_payload(8, 56)
    elif l4 == "icmpv6":
        return ip / ICMPv6EchoRequest(id=random.randint(1, 65535),
                                      seq=random.randint(0, 65535)) / \
               rand_payload(8, 56)
    elif l4 == "sctp":
        return ip / make_sctp()
    elif l4 == "esp":
        return IP(src=rand_ipv4(), dst=rand_ipv4(), proto=50,
                  ttl=random.randint(32, 128)) / make_esp() if l3 == "ipv4" \
               else IPv6(src=rand_ipv6(), dst=rand_ipv6(), nh=50,
                         fl=rand_fl()) / make_esp()
    elif l4 == "ah_tcp":
        base_ip = IP(src=rand_ipv4(), dst=rand_ipv4(), proto=51,
                     ttl=random.randint(32, 128)) if "ipv4" in l3 \
                  else IPv6(src=rand_ipv6(), dst=rand_ipv6(), nh=51,
                            fl=rand_fl())
        return base_ip / make_ah_tcp()
    elif l4 == "ah_esp":
        base_ip = IP(src=rand_ipv4(), dst=rand_ipv4(), proto=51,
                     ttl=random.randint(32, 128)) if "ipv4" in l3 \
                  else IPv6(src=rand_ipv6(), dst=rand_ipv6(), nh=51,
                            fl=rand_fl())
        return base_ip / make_ah_esp()
    elif l4 == "l2tp":
        return IP(src=rand_ipv4(), dst=rand_ipv4(), proto=115,
                  ttl=random.randint(32, 128)) / make_l2tp_session()
    elif l4 == "udp_frag":
        return ip / UDP(sport=rand_port(), dport=rand_port()) / rand_payload()
    elif l4 == "none":
        return ip / rand_payload()
    else:
        return ip / rand_payload()

    return None


def _build_l2(l2_name, l3_name, inner, mpls_labels):
    """Build L2 encapsulation around L3+L4 payload."""

    # Determine ethertype
    if mpls_labels > 0:
        etype = 0x8847  # ETH_P_MPLS_UC
    elif "ipv6" in l3_name:
        etype = 0x86DD  # ETH_P_IPV6
    elif "ipv4" in l3_name:
        etype = 0x0800  # ETH_P_IP
    else:
        etype = 0x0800

    sm, dm = rand_mac(), rand_mac()
    if l2_name == "bare":
        return Ether(src=sm, dst=dm, type=etype) / inner
    elif l2_name == "vlan_p0":
        return Ether(src=sm, dst=dm) / Dot1Q(vlan=rand_vlan(), prio=0, type=etype) / inner
    elif l2_name == "vlan_p3":
        return Ether(src=sm, dst=dm) / Dot1Q(vlan=rand_vlan(), prio=3, type=etype) / inner
    elif l2_name == "vlan_p7":
        return Ether(src=sm, dst=dm) / Dot1Q(vlan=rand_vlan(), prio=7, type=etype) / inner
    elif l2_name == "qinq":
        return (Ether(src=sm, dst=dm, type=0x88a8) /
                Dot1Q(vlan=rand_vlan(), prio=rand_prio(), type=0x8100) /
                Dot1Q(vlan=rand_vlan(), prio=rand_prio(), type=etype) /
                inner)
    elif l2_name == "pppoe":
        if "ipv6" in l3_name:
            return Ether(src=sm, dst=dm, type=0x8864) / make_pppoe_ipv6(inner)
        else:
            return Ether(src=sm, dst=dm, type=0x8864) / make_pppoe_ipv4(inner)
    elif l2_name == "vlan_pppoe":
        if "ipv6" in l3_name:
            return (Ether(src=sm, dst=dm) /
                    Dot1Q(vlan=rand_vlan(), prio=rand_prio(), type=0x8864) /
                    make_pppoe_ipv6(inner))
        else:
            return (Ether(src=sm, dst=dm) /
                    Dot1Q(vlan=rand_vlan(), prio=rand_prio(), type=0x8864) /
                    make_pppoe_ipv4(inner))
    elif l2_name == "qinq_pppoe":
        if "ipv6" in l3_name:
            return (Ether(src=sm, dst=dm, type=0x88a8) /
                    Dot1Q(vlan=rand_vlan(), prio=rand_prio(), type=0x8100) /
                    Dot1Q(vlan=rand_vlan(), prio=rand_prio(), type=0x8864) /
                    make_pppoe_ipv6(inner))
        else:
            return (Ether(src=sm, dst=dm, type=0x88a8) /
                    Dot1Q(vlan=rand_vlan(), prio=rand_prio(), type=0x8100) /
                    Dot1Q(vlan=rand_vlan(), prio=rand_prio(), type=0x8864) /
                    make_pppoe_ipv4(inner))
    return None


# ─── L2-only packet builders ───

def build_arp(l2_name, op):
    """Build ARP packet."""
    sm = rand_mac()
    # ARP requests broadcast; replies are unicast to a specific MAC
    dm = "ff:ff:ff:ff:ff:ff" if op == "who-has" else rand_mac()
    hwsrc = sm
    hwdst = "00:00:00:00:00:00" if op == "who-has" else rand_mac()
    arp = ARP(op=op, hwsrc=hwsrc, hwdst=hwdst,
              psrc=rand_ipv4(), pdst=rand_ipv4())
    if l2_name == "bare":
        return Ether(src=sm, dst=dm, type=0x0806) / arp
    elif l2_name.startswith("vlan"):
        return (Ether(src=sm, dst=dm) /
                Dot1Q(vlan=rand_vlan(), prio=rand_prio(), type=0x0806) / arp)
    elif l2_name == "qinq":
        return (Ether(src=sm, dst=dm, type=0x88a8) /
                Dot1Q(vlan=rand_vlan(), prio=rand_prio(), type=0x8100) /
                Dot1Q(vlan=rand_vlan(), prio=rand_prio(), type=0x0806) / arp)
    return None

def build_igmp(l2_name, igmp_type):
    """Build IGMP packet (Membership Query or v2 Report)."""
    sm = rand_mac()
    # IGMP uses multicast destination MACs
    if igmp_type == "query":
        dm = "01:00:5e:00:00:01"  # All-hosts
        igmp_pkt = IP(src=rand_ipv4(), dst="224.0.0.1", ttl=1) / \
                   IGMP(type=0x11, gaddr="0.0.0.0")  # Membership Query
    else:  # report
        group = "239.%d.%d.%d" % (random.randint(0, 255),
                                   random.randint(0, 255),
                                   random.randint(1, 254))
        dm = "01:00:5e:%02x:%02x:%02x" % (
            int(group.split('.')[1]) & 0x7f,
            int(group.split('.')[2]),
            int(group.split('.')[3]))
        igmp_pkt = IP(src=rand_ipv4(), dst=group, ttl=1) / \
                   IGMP(type=0x16, gaddr=group)  # v2 Membership Report

    if l2_name == "bare":
        return Ether(src=sm, dst=dm) / igmp_pkt
    elif l2_name.startswith("vlan"):
        return (Ether(src=sm, dst=dm) /
                Dot1Q(vlan=rand_vlan(), prio=rand_prio(), type=0x0800) / igmp_pkt)
    elif l2_name == "qinq":
        return (Ether(src=sm, dst=dm, type=0x88a8) /
                Dot1Q(vlan=rand_vlan(), prio=rand_prio(), type=0x8100) /
                Dot1Q(vlan=rand_vlan(), prio=rand_prio(), type=0x0800) / igmp_pkt)
    return None

def build_tipc(l2_name):
    """Build TIPC packet."""
    sm, dm = rand_mac(), rand_mac()
    tipc = make_tipc()
    if l2_name == "bare":
        return Ether(src=sm, dst=dm, type=0x88CA) / tipc
    elif l2_name.startswith("vlan"):
        return (Ether(src=sm, dst=dm) /
                Dot1Q(vlan=rand_vlan(), prio=rand_prio(), type=0x88CA) /
                tipc)
    return None


# ─── L2 leaf protocol helper ───

def _build_l2_leaf(l2_name, etype, payload):
    """Wrap a raw payload in L2 framing with the given ethertype."""
    sm, dm = rand_mac(), rand_mac()
    if l2_name == "bare":
        return Ether(src=sm, dst=dm, type=etype) / payload
    elif l2_name.startswith("vlan"):
        return (Ether(src=sm, dst=dm) /
                Dot1Q(vlan=rand_vlan(), prio=rand_prio(), type=etype) /
                payload)
    elif l2_name == "qinq":
        return (Ether(src=sm, dst=dm, type=0x88a8) /
                Dot1Q(vlan=rand_vlan(), prio=rand_prio(), type=0x8100) /
                Dot1Q(vlan=rand_vlan(), prio=rand_prio(), type=etype) /
                payload)
    return None


# ─── New L2 leaf protocol builders ───

def build_rarp(l2_name):
    """Build RARP packet (same format as ARP, op=3 or 4)."""
    sm = rand_mac()
    arp = ARP(op=random.choice([3, 4]), hwtype=1, ptype=0x0800,
              hwlen=6, plen=4, hwsrc=sm, hwdst=rand_mac(),
              psrc=rand_ipv4(), pdst=rand_ipv4())
    return _build_l2_leaf(l2_name, 0x8035, arp)

def build_fcoe(l2_name):
    """Build FCoE packet (38-byte header + payload)."""
    # FCoE: version(4) + reserved(100) + SOF(8) + FC frame
    hdr = struct.pack("!B", 0x00) + bytes(37) + rand_payload(20, 40).load
    return _build_l2_leaf(l2_name, 0x8906, Raw(hdr))

def build_lldp(l2_name):
    """Build LLDP packet (TLV-based)."""
    # Chassis ID TLV: type=1, length=7, subtype=4, value
    tlv1 = struct.pack("!HB", (1 << 9) | 7, 4) + bytes(6)
    # Port ID TLV: type=2, length=5, subtype=3, value
    tlv2 = struct.pack("!HB", (2 << 9) | 5, 3) + bytes(4)
    # TTL TLV: type=3, length=2, value=120
    tlv3 = struct.pack("!HH", (3 << 9) | 2, 120)
    # End TLV: type=0, length=0
    tlv_end = struct.pack("!H", 0)
    return _build_l2_leaf(l2_name, 0x88CC, Raw(tlv1 + tlv2 + tlv3 + tlv_end))

def build_slow(l2_name, subtype=1):
    """Build Slow Protocol packet (LACP=1, Marker=2, OAM=3)."""
    hdr = struct.pack("!BB", subtype, 1) + bytes(40)
    return _build_l2_leaf(l2_name, 0x8809, Raw(hdr))

def build_mac_control(l2_name, opcode=1):
    """Build MAC Control packet (Pause=1, PFC=0x0101)."""
    hdr = struct.pack("!HH", opcode, random.randint(0, 0xffff)) + bytes(40)
    return _build_l2_leaf(l2_name, 0x8808, Raw(hdr))

def build_eapol(l2_name):
    """Build EAPOL packet."""
    # version=2, type=0 (EAP-Packet), body_length=5, EAP data
    hdr = struct.pack("!BBH", 2, 0, 5) + bytes(5)
    return _build_l2_leaf(l2_name, 0x888E, Raw(hdr))

def build_ptp(l2_name, msg_type=0):
    """Build PTP packet (Sync=0, Delay_Req=1, Follow_Up=8)."""
    # 34-byte common header
    tsmt = (0 << 4) | (msg_type & 0x0f)
    ver = 0x02
    hdr = struct.pack("!BBH", tsmt, ver, 44)  # msg_length=44
    hdr += bytes(30)  # rest of common header
    hdr += bytes(10)  # some message-specific fields
    return _build_l2_leaf(l2_name, 0x88F7, Raw(hdr))

def build_mvrp(l2_name):
    """Build MVRP/MRP packet."""
    hdr = struct.pack("!B", 0) + bytes(20)  # protocol_version=0
    return _build_l2_leaf(l2_name, 0x88F5, Raw(hdr))

def build_cfm(l2_name, opcode=1):
    """Build CFM/OAM packet (CCM=1, LBR=2, LBM=3)."""
    mdl_ver = (7 << 5) | 0  # MD level 7, version 0
    hdr = struct.pack("!BBBB", mdl_ver, opcode, 0, 70) + bytes(70)
    return _build_l2_leaf(l2_name, 0x8902, Raw(hdr))

def build_fip(l2_name):
    """Build FIP packet."""
    # ver(1)+opcode(2)+subcode(1)+desc_len(2)+flags(2) = 10 bytes
    hdr = struct.pack("!HHHH HH", 0x1000, 1, 0x0100, 0, 0, 0) + bytes(20)
    return _build_l2_leaf(l2_name, 0x8914, Raw(hdr[:10] + bytes(20)))

def build_macsec(l2_name):
    """Build MACsec packet."""
    tci_an = 0x2C  # V=0, ES=1, SC=0, SCB=1, E=1, C=0, AN=0
    sl = 0
    pn = random.randint(1, 0xffffffff)
    hdr = struct.pack("!BBI", tci_an, sl, pn) + bytes(32)
    return _build_l2_leaf(l2_name, 0x88E5, Raw(hdr))

def build_ethercat(l2_name):
    """Build EtherCAT packet."""
    # len_type: length (11 bits) | reserved (1 bit) | type (4 bits)
    len_type = (44 & 0x7FF) | (1 << 12)  # length=44, type=1
    hdr = struct.pack("<H", len_type) + bytes(44)
    return _build_l2_leaf(l2_name, 0x88A4, Raw(hdr))


# ─── Chainable L2 protocol builders ───

def _make_inner_ip_tcp():
    """Standard inner IPv4/TCP payload for chainable protocols."""
    return (IP(src=rand_ipv4(), dst=rand_ipv4()) /
            TCP(sport=rand_port(), dport=rand_port()) / rand_payload())

def _make_inner_ipv6_tcp():
    """Standard inner IPv6/TCP payload for chainable protocols."""
    return (IPv6(src=rand_ipv6(), dst=rand_ipv6(), fl=rand_fl()) /
            TCP(sport=rand_port(), dport=rand_port()) / rand_payload())

def _make_inner_ip_udp():
    """Standard inner IPv4/UDP payload for chainable protocols."""
    return (IP(src=rand_ipv4(), dst=rand_ipv4()) /
            UDP(sport=rand_port(), dport=rand_port()) / rand_payload())

def build_batman(l2_name, inner_type="v4tcp"):
    """Build Batman unicast packet with inner Ethernet frame."""
    if inner_type == "v4tcp":
        inner = _make_inner_ip_tcp()
    elif inner_type == "v6tcp":
        inner = _make_inner_ipv6_tcp()
    else:
        inner = _make_inner_ip_udp()
    inner_ether = Ether(src=rand_mac(), dst=rand_mac()) / inner
    inner_bytes = bytes(inner_ether)
    # batadv_unicast_packet: type=0x40, version=15, ttl=50, ttvn=0, dest(6)
    batadv_hdr = struct.pack("!BBBB", 0x40, 15, 50, 0) + bytes(6)
    return _build_l2_leaf(l2_name, 0x4305, Raw(batadv_hdr + inner_bytes))

def build_pbb(l2_name, inner_type="v4tcp"):
    """Build PBB/MAC-in-MAC packet with inner Ethernet frame."""
    if inner_type == "v4tcp":
        inner = _make_inner_ip_tcp()
    elif inner_type == "v6tcp":
        inner = _make_inner_ipv6_tcp()
    else:
        inner = _make_inner_ip_udp()
    inner_ether = Ether(src=rand_mac(), dst=rand_mac()) / inner
    inner_bytes = bytes(inner_ether)
    # I-TAG: 4 bytes (I-PCP, I-DEI, UCA, Res, I-SID)
    isid = random.randint(1, 0xffffff)
    itag = struct.pack("!I", isid & 0x00ffffff)
    return _build_l2_leaf(l2_name, 0x88E7, Raw(itag + inner_bytes))

def build_trill(l2_name, inner_type="v4tcp"):
    """Build TRILL packet with inner Ethernet frame."""
    if inner_type == "v4tcp":
        inner = _make_inner_ip_tcp()
    elif inner_type == "v6tcp":
        inner = _make_inner_ipv6_tcp()
    else:
        inner = _make_inner_ip_udp()
    inner_ether = Ether(src=rand_mac(), dst=rand_mac()) / inner
    inner_bytes = bytes(inner_ether)
    # TRILL header: 6 bytes (flags_hopcount, egress_nick, ingress_nick)
    flags_hop = (2 << 14) | random.randint(1, 63)  # V=2, HopCount
    trill_hdr = struct.pack("!HHH", flags_hop,
                            random.randint(1, 0xffff),
                            random.randint(1, 0xffff))
    return _build_l2_leaf(l2_name, 0x22F3, Raw(trill_hdr + inner_bytes))

def build_hsr(l2_name, inner_type="v4tcp"):
    """Build HSR packet with inner protocol."""
    if inner_type == "v4tcp":
        inner = _make_inner_ip_tcp()
        etype = 0x0800
    elif inner_type == "v6tcp":
        inner = _make_inner_ipv6_tcp()
        etype = 0x86DD
    else:
        inner = _make_inner_ip_udp()
        etype = 0x0800
    inner_bytes = bytes(inner)
    # HSR tag: path_LSDU(2) + seq_nr(2) + encap_proto(2)
    path_lsdu = (0xA << 12) | (len(inner_bytes) + 6)  # NetId=A, LSDU size
    hsr_tag = struct.pack("!HHH", path_lsdu & 0xffff,
                          random.randint(0, 0xffff), etype)
    return _build_l2_leaf(l2_name, 0x892F, Raw(hsr_tag + inner_bytes))

def build_nsh(l2_name, inner_type="v4tcp"):
    """Build NSH packet with inner protocol."""
    if inner_type == "v4tcp":
        inner = _make_inner_ip_tcp()
        next_proto = 1  # IPv4
    elif inner_type == "v6tcp":
        inner = _make_inner_ipv6_tcp()
        next_proto = 2  # IPv6
    else:
        inner = _make_inner_ip_udp()
        next_proto = 1
    inner_bytes = bytes(inner)
    # NSH base header: 8 bytes
    # ver(2)+OAM(1)+UN(1)+TTL(6)+Len(6) = 16 bits
    ver_flags = (0 << 14) | (0 << 13) | (0 << 12) | (63 << 6) | 6
    spi = random.randint(1, 0xffffff)
    si = random.randint(1, 255)
    spi_si = (spi << 8) | si
    nsh_hdr = struct.pack("!HBB I", ver_flags, 1, next_proto, spi_si)
    return _build_l2_leaf(l2_name, 0x894F, Raw(nsh_hdr + inner_bytes))


# ─── LLC/SNAP/STP builders ───

def build_stp(l2_name, bpdu_type="config"):
    """Build STP BPDU packet via LLC framing."""
    # LLC header: DSAP=0x42, SSAP=0x42, Control=0x03
    llc = struct.pack("!BBB", 0x42, 0x42, 0x03)
    if bpdu_type == "config":
        # Config BPDU: protocol_id=0, version=0, type=0, flags, ...
        bpdu = struct.pack("!HBB", 0, 0, 0) + bytes(32)
    else:
        # TCN BPDU: protocol_id=0, version=0, type=0x80
        bpdu = struct.pack("!HBB", 0, 0, 0x80)
    payload = Raw(llc + bpdu)
    # LLC frames use length field (<=1500) instead of ethertype
    frame_len = len(llc) + len(bpdu)
    sm, dm = rand_mac(), rand_mac()
    if l2_name == "bare":
        return Ether(src=sm, dst=dm, type=frame_len) / payload
    elif l2_name.startswith("vlan"):
        return (Ether(src=sm, dst=dm) /
                Dot1Q(vlan=rand_vlan(), prio=rand_prio(), type=frame_len) /
                payload)
    return None

def build_snap(l2_name, inner_type="v4tcp"):
    """Build SNAP-encapsulated packet via LLC framing."""
    if inner_type == "v4tcp":
        inner = _make_inner_ip_tcp()
        snap_etype = 0x0800
    elif inner_type == "v6tcp":
        inner = _make_inner_ipv6_tcp()
        snap_etype = 0x86DD
    else:
        inner = _make_inner_ip_udp()
        snap_etype = 0x0800
    inner_bytes = bytes(inner)
    # LLC header: DSAP=0xAA, SSAP=0xAA, Control=0x03
    llc = struct.pack("!BBB", 0xAA, 0xAA, 0x03)
    # SNAP header: OUI=00:00:00, protocol=ethertype
    snap = struct.pack("!3sH", bytes(3), snap_etype)
    payload = Raw(llc + snap + inner_bytes)
    frame_len = len(llc) + len(snap) + len(inner_bytes)
    if frame_len > 1500:
        frame_len = 1500
    sm, dm = rand_mac(), rand_mac()
    if l2_name == "bare":
        return Ether(src=sm, dst=dm, type=frame_len) / payload
    elif l2_name.startswith("vlan"):
        return (Ether(src=sm, dst=dm) /
                Dot1Q(vlan=rand_vlan(), prio=rand_prio(), type=frame_len) /
                payload)
    return None


# ─── Combination enumeration ───

L2_TYPES = ["bare", "vlan_p0", "vlan_p3", "vlan_p7", "qinq",
            "pppoe", "vlan_pppoe", "qinq_pppoe"]

L3_TYPES = ["ipv4", "ipv6", "ipv6_hbh", "ipv6_dst", "ipv6_routing",
            "ipv6_frag_first", "ipv6_frag_mid", "ipv6_hbh_dst",
            "ipv4_frag_first", "ipv4_frag_mid"]

L4_TYPES = ["tcp", "udp", "icmp", "icmpv6", "sctp",
            "esp", "ah_tcp", "ah_esp", "l2tp"]

TUNNEL_TYPES = ["gre", "gre_key", "ipip_v4", "ipip_v6",
                "vxlan", "geneve"]

MPLS_COUNTS = [1, 2, 3, 4]

# L2 types that support MPLS (not PPPoE)
MPLS_L2 = ["bare", "vlan_p0", "vlan_p3", "vlan_p7", "qinq"]

# L2 types that support ARP
ARP_L2 = ["bare", "vlan_p0", "vlan_p3", "qinq"]

# L2 types that support IGMP (IPv4-only, same as ARP)
IGMP_L2 = ["bare", "vlan_p0", "vlan_p3", "qinq"]

# L2 types that support TIPC
TIPC_L2 = ["bare", "vlan_p0"]

# L2 types for new leaf protocols (bare, vlan, qinq)
LEAF_L2 = ["bare", "vlan_p3", "qinq"]

# L2 types for chainable encap protocols
CHAIN_L2 = ["bare", "vlan_p3", "qinq"]

# Inner protocol variants for chainable L2
CHAIN_INNER = ["v4tcp", "v6tcp", "v4udp"]

# L2 types for LLC/STP (bare, vlan — no qinq for LLC)
LLC_L2 = ["bare", "vlan_p3"]


def is_valid_combo(l2, l3, l4, tunnel=None, mpls=0):
    """Check if a combination is valid."""

    # PPPoE only wraps IP/IPv6
    if l2 in ("pppoe", "vlan_pppoe", "qinq_pppoe"):
        if l3 not in ("ipv4", "ipv6"):
            return False

    # ICMPv6 only with IPv6
    if l4 == "icmpv6" and "ipv6" not in l3:
        return False

    # ICMP only with IPv4
    if l4 == "icmp" and "ipv4" not in l3:
        return False

    # Fragment mid: no L4 header
    if l3 in ("ipv4_frag_mid", "ipv6_frag_mid") and l4 != "none":
        return False

    # L2TP only with IPv4, no tunnel
    if l4 == "l2tp":
        if l3 != "ipv4" or tunnel:
            return False

    # ESP/AH: no tunnel wrapping
    if l4 in ("esp", "ah_tcp", "ah_esp") and tunnel:
        return False

    # IP tunnels (GRE, IPIP) only with IPv4 outer
    if tunnel in ("gre", "gre_key", "ipip_v4", "ipip_v6"):
        if l3 != "ipv4":
            return False

    # VXLAN/Geneve: outer must be simple IPv4 or IPv6
    if tunnel in ("vxlan", "geneve"):
        if l3 not in ("ipv4", "ipv6"):
            return False

    # MPLS only with non-PPPoE L2
    if mpls > 0 and l2 not in MPLS_L2:
        return False

    # MPLS + tunnel doesn't make sense in this context
    if mpls > 0 and tunnel:
        return False

    # AH/ESP not with IPv6 extension headers
    if l4 in ("ah_tcp", "ah_esp", "esp") and l3 not in ("ipv4", "ipv6"):
        return False

    return True


def generate_combinations():
    """Generate all valid combinations as (name, builder_args) tuples."""
    combos = []

    # 1. L2-only terminals: ARP
    for l2 in ARP_L2:
        for op in ("who-has", "is-at"):
            op_name = "arp_request" if op == "who-has" else "arp_reply"
            name = "%s/%s" % (l2, op_name)
            combos.append((name, "arp", l2, op))

    # 1b. IGMP (IPv4 L3 protocol, like ARP)
    for l2 in IGMP_L2:
        for igmp_type, igmp_name in [("query", "igmp_query"), ("report", "igmp_report")]:
            name = "%s/%s" % (l2, igmp_name)
            combos.append((name, "igmp", l2, igmp_type))

    # 2. L2-only terminals: TIPC
    for l2 in TIPC_L2:
        name = "%s/tipc" % l2
        combos.append((name, "tipc", l2, None))

    # 3. Direct: L2 / L3 / L4 (no MPLS, no tunnel)
    for l2 in L2_TYPES:
        for l3 in L3_TYPES:
            for l4 in L4_TYPES:
                if not is_valid_combo(l2, l3, l4):
                    continue
                name = "%s/%s/%s" % (l2, l3, l4)
                combos.append((name, "direct", l2, l3, l4))

    # 4. Fragment mid-packets (no L4)
    for l2 in L2_TYPES:
        for l3 in ("ipv4_frag_mid", "ipv6_frag_mid"):
            if l2 in ("pppoe", "vlan_pppoe", "qinq_pppoe"):
                continue
            name = "%s/%s" % (l2, l3)
            combos.append((name, "direct", l2, l3, "none"))

    # 5. MPLS: L2 / MPLS×N / L3 / L4
    for l2 in MPLS_L2:
        for n in MPLS_COUNTS:
            for l3 in ("ipv4", "ipv6"):
                for l4 in ("tcp", "udp"):
                    name = "%s/mpls_%d/%s/%s" % (l2, n, l3, l4)
                    combos.append((name, "mpls", l2, l3, l4, n))

    # 6. MPLS VPLS: L2 / MPLS×2 / Ether / L3 / L4
    for l2 in ("bare", "vlan_p3"):
        for l3 in ("ipv4",):
            name = "%s/mpls_vpls/%s/tcp" % (l2, l3)
            combos.append((name, "mpls_vpls", l2, l3, "tcp"))

    # 7. IP tunnels: L2 / L3-outer / tunnel / L3-inner / L4
    for l2 in ("bare", "vlan_p3", "qinq"):
        for tun in ("gre", "gre_key"):
            for inner_l3 in ("ipv4", "ipv6"):
                for inner_l4 in ("tcp", "udp"):
                    name = "%s/ipv4/%s/%s/%s/%s" % (l2, tun,
                                                     inner_l3, inner_l4,
                                                     tun)
                    combos.append((name, "tunnel", l2, "ipv4",
                                   tun, inner_l3, inner_l4))

    # 8. IPIP tunnels
    for l2 in ("bare", "vlan_p3"):
        for tun, inner_l3 in [("ipip_v4", "ipv4"), ("ipip_v6", "ipv6")]:
            for inner_l4 in ("tcp",):
                name = "%s/ipv4/%s/%s" % (l2, tun, inner_l4)
                combos.append((name, "tunnel", l2, "ipv4",
                               tun, inner_l3, inner_l4))

    # 9. VXLAN/Geneve tunnels
    for l2 in ("bare", "vlan_p3"):
        for outer_l3 in ("ipv4", "ipv6"):
            for tun in ("vxlan", "geneve"):
                for inner_l3 in ("ipv4", "ipv6"):
                    for inner_l4 in ("tcp", "udp"):
                        name = "%s/%s/%s/%s/%s" % (l2, outer_l3, tun,
                                                    inner_l3, inner_l4)
                        combos.append((name, "tunnel", l2, outer_l3,
                                       tun, inner_l3, inner_l4))

    # ─── New L2 protocol combinations ───

    # 10. RARP
    for l2 in LEAF_L2:
        combos.append(("%s/rarp" % l2, "rarp", l2, None))

    # 11. FCoE
    for l2 in LEAF_L2:
        combos.append(("%s/fcoe" % l2, "fcoe", l2, None))

    # 12. LLDP
    for l2 in LEAF_L2:
        combos.append(("%s/lldp" % l2, "lldp", l2, None))

    # 13. Slow Protocols (LACP=1, Marker=2, OAM=3)
    for l2 in LEAF_L2:
        for sub, sub_name in [(1, "lacp"), (2, "marker"), (3, "oam")]:
            combos.append(("%s/slow_%s" % (l2, sub_name),
                           "slow", l2, sub))

    # 14. MAC Control (Pause=1, PFC=0x0101)
    for l2 in LEAF_L2:
        for op, op_name in [(1, "pause"), (0x0101, "pfc")]:
            combos.append(("%s/mac_control_%s" % (l2, op_name),
                           "mac_control", l2, op))

    # 15. EAPOL
    for l2 in LEAF_L2:
        combos.append(("%s/eapol" % l2, "eapol", l2, None))

    # 16. PTP (Sync=0, Delay_Req=1, Follow_Up=8)
    for l2 in LEAF_L2:
        for mt, mt_name in [(0, "sync"), (1, "delay_req"), (8, "follow_up")]:
            combos.append(("%s/ptp_%s" % (l2, mt_name),
                           "ptp", l2, mt))

    # 17. MVRP
    for l2 in LEAF_L2:
        combos.append(("%s/mvrp" % l2, "mvrp", l2, None))

    # 18. CFM/OAM (CCM=1, LBR=2, LBM=3)
    for l2 in LEAF_L2:
        for op, op_name in [(1, "ccm"), (2, "lbr"), (3, "lbm")]:
            combos.append(("%s/cfm_%s" % (l2, op_name),
                           "cfm", l2, op))

    # 19. FIP
    for l2 in LEAF_L2:
        combos.append(("%s/fip" % l2, "fip", l2, None))

    # 20. MACsec
    for l2 in LEAF_L2:
        combos.append(("%s/macsec" % l2, "macsec", l2, None))

    # 21. EtherCAT
    for l2 in LEAF_L2:
        combos.append(("%s/ethercat" % l2, "ethercat", l2, None))

    # 22. Batman (chainable with inner variants)
    for l2 in CHAIN_L2:
        for inner in CHAIN_INNER:
            combos.append(("%s/batman/%s" % (l2, inner),
                           "batman", l2, inner))

    # 23. PBB/MAC-in-MAC (chainable)
    for l2 in CHAIN_L2:
        for inner in CHAIN_INNER:
            combos.append(("%s/pbb/%s" % (l2, inner),
                           "pbb", l2, inner))

    # 24. TRILL (chainable)
    for l2 in CHAIN_L2:
        for inner in CHAIN_INNER:
            combos.append(("%s/trill/%s" % (l2, inner),
                           "trill", l2, inner))

    # 25. HSR (chainable)
    for l2 in CHAIN_L2:
        for inner in CHAIN_INNER:
            combos.append(("%s/hsr/%s" % (l2, inner),
                           "hsr", l2, inner))

    # 26. NSH (chainable)
    for l2 in CHAIN_L2:
        for inner in CHAIN_INNER:
            combos.append(("%s/nsh/%s" % (l2, inner),
                           "nsh", l2, inner))

    # 27. STP (via LLC, config + TCN BPDUs)
    for l2 in LLC_L2:
        for btype in ("config", "tcn"):
            combos.append(("%s/stp_%s" % (l2, btype),
                           "stp", l2, btype))

    # 28. SNAP (via LLC, inner IP variants)
    for l2 in LLC_L2:
        for inner in ("v4tcp", "v6tcp"):
            combos.append(("%s/snap/%s" % (l2, inner),
                           "snap", l2, inner))

    return combos


def build_combo_packet(combo):
    """Build a packet from a combination tuple."""
    kind = combo[1]

    if kind == "arp":
        _, _, l2, op = combo
        return build_arp(l2, op)
    elif kind == "igmp":
        _, _, l2, igmp_type = combo
        return build_igmp(l2, igmp_type)
    elif kind == "tipc":
        _, _, l2, _ = combo
        return build_tipc(l2)
    elif kind == "direct":
        _, _, l2, l3, l4 = combo
        return build_pkt(l2, l3, l4)
    elif kind == "mpls":
        _, _, l2, l3, l4, n = combo
        return build_pkt(l2, l3, l4, mpls_labels=n)
    elif kind == "mpls_vpls":
        _, _, l2, l3, l4 = combo
        # VPLS: MPLS → Ethernet → inner IP/TCP
        inner_ip = (IP(src=rand_ipv4(), dst=rand_ipv4()) /
                    TCP(sport=rand_port(), dport=rand_port()) /
                    rand_payload())
        inner_ether = Ether(src=rand_mac(), dst=rand_mac()) / inner_ip
        mpls_stack = (MPLS(label=rand_label(), s=0, ttl=64) /
                      MPLS(label=rand_label(), s=1, ttl=64))
        sm, dm = rand_mac(), rand_mac()
        pkt = Ether(src=sm, dst=dm, type=0x8847) / mpls_stack / inner_ether
        if l2 != "bare":
            # Add VLAN
            pkt = (Ether(src=sm, dst=dm) /
                   Dot1Q(vlan=rand_vlan(), prio=3, type=0x8847) /
                   mpls_stack / inner_ether)
        return pkt
    elif kind == "tunnel":
        _, _, l2, outer_l3, tun, inner_l3, inner_l4 = combo
        return build_pkt(l2, outer_l3, inner_l4, tunnel=tun,
                         inner_l3=inner_l3, inner_l4=inner_l4)
    # ─── New L2 protocol builders ───
    elif kind == "rarp":
        _, _, l2, _ = combo
        return build_rarp(l2)
    elif kind == "fcoe":
        _, _, l2, _ = combo
        return build_fcoe(l2)
    elif kind == "lldp":
        _, _, l2, _ = combo
        return build_lldp(l2)
    elif kind == "slow":
        _, _, l2, subtype = combo
        return build_slow(l2, subtype)
    elif kind == "mac_control":
        _, _, l2, opcode = combo
        return build_mac_control(l2, opcode)
    elif kind == "eapol":
        _, _, l2, _ = combo
        return build_eapol(l2)
    elif kind == "ptp":
        _, _, l2, msg_type = combo
        return build_ptp(l2, msg_type)
    elif kind == "mvrp":
        _, _, l2, _ = combo
        return build_mvrp(l2)
    elif kind == "cfm":
        _, _, l2, opcode = combo
        return build_cfm(l2, opcode)
    elif kind == "fip":
        _, _, l2, _ = combo
        return build_fip(l2)
    elif kind == "macsec":
        _, _, l2, _ = combo
        return build_macsec(l2)
    elif kind == "ethercat":
        _, _, l2, _ = combo
        return build_ethercat(l2)
    elif kind == "batman":
        _, _, l2, inner = combo
        return build_batman(l2, inner)
    elif kind == "pbb":
        _, _, l2, inner = combo
        return build_pbb(l2, inner)
    elif kind == "trill":
        _, _, l2, inner = combo
        return build_trill(l2, inner)
    elif kind == "hsr":
        _, _, l2, inner = combo
        return build_hsr(l2, inner)
    elif kind == "nsh":
        _, _, l2, inner = combo
        return build_nsh(l2, inner)
    elif kind == "stp":
        _, _, l2, bpdu_type = combo
        return build_stp(l2, bpdu_type)
    elif kind == "snap":
        _, _, l2, inner = combo
        return build_snap(l2, inner)

    return None


def main():
    parser = argparse.ArgumentParser(
        description="Combinatorial PCAP generator for flow dissector benchmark")
    parser.add_argument("-o", "--output", default="test_flow_dissector.pcap",
                        help="Output PCAP file (default: test_flow_dissector.pcap)")
    parser.add_argument("-n", "--count", type=int, default=10000,
                        help="Total number of packets (default: 10000)")
    parser.add_argument("-s", "--seed", type=int, default=42,
                        help="Random seed (default: 42)")
    parser.add_argument("--list", action="store_true",
                        help="List all valid combinations and exit")
    parser.add_argument("--combo", type=str, default=None,
                        help="Generate only matching combination(s)")
    parser.add_argument("--no-shuffle", action="store_true",
                        help="Don't shuffle packets (group by combination)")
    args = parser.parse_args()

    random.seed(args.seed)

    # Generate all valid combinations
    combos = generate_combinations()

    if args.list:
        print("Valid combinations (%d total):" % len(combos))
        for combo in combos:
            print("  %s" % combo[0])
        return

    # Filter by --combo if specified
    if args.combo:
        filtered = [c for c in combos
                    if fnmatch.fnmatch(c[0], args.combo)]
        if not filtered:
            print("No combinations match '%s'" % args.combo, file=sys.stderr)
            sys.exit(1)
        combos = filtered

    n = args.count
    n_combos = len(combos)

    if n_combos == 0:
        print("No valid combinations", file=sys.stderr)
        sys.exit(1)

    # Distribute packets across combinations
    per_combo = max(1, n // n_combos)
    remainder = n - per_combo * n_combos

    all_packets = []
    combo_stats = {}

    for i, combo in enumerate(combos):
        count = per_combo + (1 if i < remainder else 0)
        if count <= 0:
            continue

        generated = 0
        for _ in range(count):
            pkt = build_combo_packet(combo)
            if pkt is not None:
                all_packets.append(pkt)
                generated += 1

        if generated > 0:
            combo_stats[combo[0]] = generated

    # Shuffle for realistic traffic mix
    if not args.no_shuffle:
        random.shuffle(all_packets)

    # Print summary
    print("Combinations: %d valid, %d with packets" %
          (n_combos, len(combo_stats)))

    # Group by category
    categories = {}
    for name, count in combo_stats.items():
        parts = name.split("/")
        cat = parts[0] if len(parts) > 1 else name
        categories[cat] = categories.get(cat, 0) + count

    for cat in sorted(categories.keys()):
        print("  %-20s %5d packets" % (cat, categories[cat]))

    print("\nTotal: %d packets" % len(all_packets))
    print("Writing: %s" % args.output)

    wrpcap(args.output, all_packets)
    print("Done.")


if __name__ == "__main__":
    main()
