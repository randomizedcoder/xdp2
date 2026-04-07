#!/usr/bin/env python3
"""Generate PCAP template files for protocols that can't be auto-routed.

These are protocols that need special setup (TLS handshake, HTTP/2 preface,
etc.) or need valid application-layer content for tshark to dissect.

Usage:
    python3 gen_pcap_templates.py --output-dir pcap_templates/
"""

import argparse
import struct
import sys


# ═══════════════════════════════════════════════════════════════════════
# PCAP infrastructure
# ═══════════════════════════════════════════════════════════════════════

def pcap_global_header(link_type=1):
    """PCAP global header (little-endian)."""
    return struct.pack('<IHHiIII',
        0xa1b2c3d4,  # magic
        2, 4,         # version
        0,            # thiszone
        0,            # sigfigs
        65535,        # snaplen
        link_type,    # linktype
    )


def pcap_record(packet):
    """PCAP record header + packet data."""
    length = len(packet)
    header = struct.pack('<IIII', 0, 0, length, length)
    return header + packet


def write_pcap(path, link_type, packet):
    """Write a single-packet PCAP file."""
    with open(path, 'wb') as f:
        f.write(pcap_global_header(link_type))
        f.write(pcap_record(packet))
    print(f"  Wrote {path} ({len(packet)} bytes)", file=sys.stderr)


# ═══════════════════════════════════════════════════════════════════════
# Network layer helpers
# ═══════════════════════════════════════════════════════════════════════

def ethernet(dst=b'\x00' * 6, src=b'\x00' * 6, etype=0x0800):
    return dst + src + struct.pack('>H', etype)


def ipv4(proto=6, payload_len=0, src=b'\xc0\xa8\x01\x01', dst=b'\xc0\xa8\x01\x02'):
    """Minimal IPv4 header (20 bytes)."""
    total_len = 20 + payload_len
    hdr = struct.pack('>BBHHHBBH4s4s',
        0x45, 0,           # version/ihl, dscp
        total_len,         # total length
        0x1234, 0x4000,    # id, flags+offset
        64, proto,         # ttl, protocol
        0,                 # checksum (0 = let tshark recalc)
        src, dst,
    )
    return hdr


def ipv6(next_header=6, payload_len=0, src=None, dst=None):
    """Minimal IPv6 header (40 bytes)."""
    if src is None:
        src = b'\xfd\x00' + b'\x00' * 14
        src = src[:15] + b'\x01'
    if dst is None:
        dst = b'\xfd\x00' + b'\x00' * 14
        dst = dst[:15] + b'\x02'
    hdr = struct.pack('>IHBB16s16s',
        0x60000000,        # version=6, traffic_class=0, flow_label=0
        payload_len,       # payload length
        next_header,       # next header
        64,                # hop limit
        src, dst,
    )
    return hdr


def udp(sport=12345, dport=53, payload=b''):
    """Minimal UDP header (8 bytes) + payload."""
    length = 8 + len(payload)
    hdr = struct.pack('>HHHH', sport, dport, length, 0)
    return hdr + payload


def tcp(sport=12345, dport=443, payload=b'', seq=1000, ack=0, flags=0x18):
    """Minimal TCP header (20 bytes) + payload."""
    data_offset = 5 << 4  # 20 bytes, no options
    hdr = struct.pack('>HHIIBBHHH',
        sport, dport,
        seq, ack,
        data_offset, flags,
        65535,            # window
        0, 0,             # checksum, urgptr
    )
    return hdr + payload


def eth_ipv4_udp(dport, payload, sport=12345):
    """Ethernet → IPv4 → UDP → payload."""
    udp_seg = udp(sport=sport, dport=dport, payload=payload)
    ip_hdr = ipv4(proto=17, payload_len=len(udp_seg))
    return ethernet(etype=0x0800) + ip_hdr + udp_seg


def eth_ipv4_tcp(dport, payload, sport=12345, seq=1000, ack=0, flags=0x18):
    """Ethernet → IPv4 → TCP → payload."""
    tcp_seg = tcp(sport=sport, dport=dport, payload=payload, seq=seq, ack=ack, flags=flags)
    ip_hdr = ipv4(proto=6, payload_len=len(tcp_seg))
    return ethernet(etype=0x0800) + ip_hdr + tcp_seg


# ═══════════════════════════════════════════════════════════════════════
# Protocol payload generators
# ═══════════════════════════════════════════════════════════════════════

def gen_tls_client_hello():
    """TLS 1.2 ClientHello (minimal, enough for tshark to dissect as TLS)."""
    hello_body = (
        b'\x03\x03'             # client_version = TLS 1.2
        + b'\x00' * 32          # random (32 bytes)
        + b'\x00'               # session_id length = 0
        + b'\x00\x02\x00\xff'   # cipher_suites: 1 suite
        + b'\x01\x00'           # compression_methods: null
    )
    handshake = b'\x01' + struct.pack('>I', len(hello_body))[1:] + hello_body
    record = struct.pack('>BHH', 22, 0x0301, len(handshake)) + handshake
    return record


def gen_http2_preface():
    """HTTP/2 connection preface + SETTINGS frame."""
    preface = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'
    settings = struct.pack('>BBBBB', 0, 0, 0, 4, 0) + struct.pack('>I', 0)
    return preface + settings


def gen_dhcp_discover():
    """DHCP Discover message (enough for tshark to dissect as BOOTP/DHCP)."""
    # BOOTP header: op=1(request), htype=1(ethernet), hlen=6, hops=0
    msg = struct.pack('>BBBB', 1, 1, 6, 0)
    msg += struct.pack('>I', 0x12345678)  # xid
    msg += struct.pack('>HH', 0, 0)       # secs, flags
    msg += b'\x00' * 4                     # ciaddr
    msg += b'\x00' * 4                     # yiaddr
    msg += b'\x00' * 4                     # siaddr
    msg += b'\x00' * 4                     # giaddr
    msg += b'\x02\x00\x00\x00\x00\x01' + b'\x00' * 10  # chaddr (MAC + padding)
    msg += b'\x00' * 64                    # sname
    msg += b'\x00' * 128                   # file
    # DHCP magic cookie
    msg += b'\x63\x82\x53\x63'
    # Option 53: DHCP Message Type = Discover (1)
    msg += b'\x35\x01\x01'
    # Option 255: End
    msg += b'\xff'
    return msg


def gen_dhcpv6_solicit():
    """DHCPv6 Solicit message."""
    # msg-type=1 (Solicit), transaction-id=0x123456
    msg = struct.pack('>B', 1) + b'\x12\x34\x56'
    # Option 1: Client Identifier (DUID-LLT)
    # option-code=1, option-len=14
    msg += struct.pack('>HH', 1, 14)
    # DUID-LLT: type=1, hw-type=1, time=0, link-layer=00:00:00:00:00:01
    msg += struct.pack('>HHI', 1, 1, 0) + b'\x00\x00\x00\x00\x00\x01'
    # Option 8: Elapsed Time = 0
    msg += struct.pack('>HHH', 8, 2, 0)
    return msg


def gen_ntp_query():
    """NTP client query (version 4, mode 3)."""
    # LI=0, VN=4, Mode=3 → first byte = 0x23
    msg = struct.pack('>B', 0x23)
    msg += struct.pack('>B', 0)     # stratum
    msg += struct.pack('>b', 6)     # poll interval
    msg += struct.pack('>b', -20)   # precision
    msg += struct.pack('>I', 0)     # root delay
    msg += struct.pack('>I', 0)     # root dispersion
    msg += b'\x00' * 4              # reference ID
    msg += b'\x00' * 8              # reference timestamp
    msg += b'\x00' * 8              # origin timestamp
    msg += b'\x00' * 8              # receive timestamp
    msg += b'\x00' * 8              # transmit timestamp
    return msg


def gen_snmpv1_get():
    """SNMPv1 GetRequest (ASN.1 BER encoded)."""
    # sysDescr.0 OID: 1.3.6.1.2.1.1.1.0
    oid = b'\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00'
    # NULL value
    null_val = b'\x05\x00'
    # VarBind: SEQUENCE { oid, value }
    varbind = oid + null_val
    varbind = b'\x30' + bytes([len(varbind)]) + varbind
    # VarBindList: SEQUENCE { varbind }
    varbind_list = b'\x30' + bytes([len(varbind)]) + varbind
    # GetRequest-PDU (0xA0): request-id=1, error-status=0, error-index=0
    pdu_body = (
        b'\x02\x01\x01'   # request-id = 1
        + b'\x02\x01\x00' # error-status = 0
        + b'\x02\x01\x00' # error-index = 0
        + varbind_list
    )
    pdu = b'\xa0' + bytes([len(pdu_body)]) + pdu_body
    # Community string: "public"
    community = b'\x04\x06public'
    # Version: 0 (SNMPv1)
    version = b'\x02\x01\x00'
    # Top-level SEQUENCE
    msg_body = version + community + pdu
    msg = b'\x30' + bytes([len(msg_body)]) + msg_body
    return msg


def gen_radius_access_request():
    """RADIUS Access-Request (Code=1, minimal)."""
    # Code=1 (Access-Request), Identifier=1, Length=TBD, Authenticator=16 zeros
    authenticator = b'\x00' * 16
    # Attribute: User-Name (1) = "test"
    username = b'\x01\x06test'
    # Attribute: NAS-IP-Address (4) = 192.168.1.1
    nas_ip = b'\x04\x06\xc0\xa8\x01\x01'
    attrs = username + nas_ip
    length = 20 + len(attrs)
    msg = struct.pack('>BBH', 1, 1, length) + authenticator + attrs
    return msg


def gen_sip_invite():
    """SIP INVITE request (minimal, text-based)."""
    return (
        b'INVITE sip:bob@192.168.1.2 SIP/2.0\r\n'
        b'Via: SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bK776\r\n'
        b'From: <sip:alice@192.168.1.1>;tag=1928301774\r\n'
        b'To: <sip:bob@192.168.1.2>\r\n'
        b'Call-ID: a84b4c76e66710@192.168.1.1\r\n'
        b'CSeq: 314159 INVITE\r\n'
        b'Contact: <sip:alice@192.168.1.1>\r\n'
        b'Content-Length: 0\r\n'
        b'\r\n'
    )


def gen_rtp():
    """RTP packet (V=2, PT=0 PCMU, minimal)."""
    # V=2, P=0, X=0, CC=0 → 0x80; M=0, PT=0 → 0x00
    hdr = struct.pack('>BBHI',
        0x80, 0x00,    # V=2, PT=0
        1,             # sequence number
        160,           # timestamp
    )
    hdr += struct.pack('>I', 0x12345678)  # SSRC
    hdr += b'\x80' * 160  # 160 bytes of payload (20ms of PCMU)
    return hdr


def gen_rtcp_sr():
    """RTCP Sender Report (minimal)."""
    # V=2, P=0, RC=0, PT=200 (SR)
    hdr = struct.pack('>BBH', 0x80, 200, 6)  # length=6 (7 32-bit words - 1)
    hdr += struct.pack('>I', 0x12345678)  # SSRC
    hdr += struct.pack('>Q', 0)           # NTP timestamp
    hdr += struct.pack('>I', 0)           # RTP timestamp
    hdr += struct.pack('>I', 100)         # sender packet count
    hdr += struct.pack('>I', 16000)       # sender octet count
    return hdr


def gen_stun_binding():
    """STUN Binding Request (RFC 5389)."""
    # Type=0x0001 (Binding Request), Length=0, Magic Cookie, Transaction ID
    msg = struct.pack('>HH', 0x0001, 0)
    msg += struct.pack('>I', 0x2112A442)  # Magic cookie
    msg += b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c'  # Transaction ID (12 bytes)
    return msg


def gen_gtp_u_echo():
    """GTP-U Echo Request (v1)."""
    # Flags: version=1, PT=1, E=0, S=0, PN=0 → 0x30
    # Type: Echo Request = 1
    # Length: 0 (no payload after mandatory header)
    # TEID: 0
    msg = struct.pack('>BBHI', 0x30, 1, 0, 0)
    return msg


def gen_gtp_c_echo():
    """GTPv2-C Echo Request."""
    # Flags: version=2, P=0, T=0 → 0x40
    # Type: Echo Request = 1
    # Length: 4 (TEID present = no, so 4 bytes of seq+spare)
    msg = struct.pack('>BBH', 0x40, 1, 4)
    # Sequence number (3 bytes) + spare (1 byte)
    msg += struct.pack('>I', 0x00000100)
    return msg


def gen_netflow_v5():
    """NetFlow v5 (1 flow record)."""
    # Header: version=5, count=1, sys_uptime=1000, unix_secs=0, unix_nsecs=0
    # flow_sequence=1, engine_type=0, engine_id=0, sampling=0
    hdr = struct.pack('>HH', 5, 1)
    hdr += struct.pack('>I', 1000)   # sys_uptime
    hdr += struct.pack('>I', 0)      # unix_secs
    hdr += struct.pack('>I', 0)      # unix_nsecs
    hdr += struct.pack('>I', 1)      # flow_sequence
    hdr += struct.pack('>BBH', 0, 0, 0)  # engine_type, engine_id, sampling
    # Flow record (48 bytes)
    rec = b'\xc0\xa8\x01\x01'  # src_addr
    rec += b'\xc0\xa8\x01\x02' # dst_addr
    rec += b'\x00\x00\x00\x00' # nexthop
    rec += struct.pack('>HH', 1, 2)  # input, output
    rec += struct.pack('>I', 100)    # packets
    rec += struct.pack('>I', 10000)  # octets
    rec += struct.pack('>I', 0)      # first
    rec += struct.pack('>I', 1000)   # last
    rec += struct.pack('>HH', 80, 12345)  # src_port, dst_port
    rec += b'\x00'               # pad1
    rec += struct.pack('>B', 0x10)  # tcp_flags
    rec += struct.pack('>B', 6)     # prot (TCP)
    rec += struct.pack('>B', 0)     # tos
    rec += struct.pack('>HH', 0, 0) # src_as, dst_as
    rec += struct.pack('>BB', 24, 24) # src_mask, dst_mask
    rec += b'\x00\x00'             # pad2
    return hdr + rec


def gen_netflow_v9():
    """NetFlow v9 with a template + data flowset."""
    # Header: version=9, count=2, uptime=1000, unix_secs=0, seq=1, source_id=1
    hdr = struct.pack('>HH', 9, 2)
    hdr += struct.pack('>I', 1000)  # sys_uptime
    hdr += struct.pack('>I', 0)     # unix_secs
    hdr += struct.pack('>I', 1)     # sequence
    hdr += struct.pack('>I', 1)     # source_id
    # Template FlowSet (ID=0)
    tmpl = struct.pack('>HH', 0, 24)  # flowset_id=0, length=24
    tmpl += struct.pack('>HH', 256, 3) # template_id=256, field_count=3
    tmpl += struct.pack('>HH', 8, 4)   # SRC_ADDR (type=8, len=4)
    tmpl += struct.pack('>HH', 12, 4)  # DST_ADDR (type=12, len=4)
    tmpl += struct.pack('>HH', 2, 4)   # PKTS (type=2, len=4)
    # Data FlowSet (ID=256)
    data = struct.pack('>HH', 256, 16) # flowset_id=256, length=16
    data += b'\xc0\xa8\x01\x01'        # src_addr
    data += b'\xc0\xa8\x01\x02'        # dst_addr
    data += struct.pack('>I', 42)       # packets
    return hdr + tmpl + data


def gen_ipfix():
    """IPFIX message with template + data set."""
    # Message Header: version=10, length=TBD, export_time=0, seq=1, domain_id=1
    # Template Set (ID=2)
    tmpl = struct.pack('>HH', 2, 24)    # set_id=2, length=24
    tmpl += struct.pack('>HH', 256, 3)  # template_id=256, field_count=3
    tmpl += struct.pack('>HH', 8, 4)    # sourceIPv4Address
    tmpl += struct.pack('>HH', 12, 4)   # destinationIPv4Address
    tmpl += struct.pack('>HH', 2, 4)    # packetDeltaCount
    # Data Set (ID=256)
    data = struct.pack('>HH', 256, 16)
    data += b'\xc0\xa8\x01\x01'
    data += b'\xc0\xa8\x01\x02'
    data += struct.pack('>I', 42)
    body = tmpl + data
    hdr = struct.pack('>HHIII', 10, 16 + len(body), 0, 1, 1)
    return hdr + body


def gen_bacnet():
    """BACnet/IP (BVLC + NPDU + Who-Is)."""
    # BVLC: type=0x81, function=0x0b (Original-Broadcast-NPDU), length=TBD
    # NPDU: version=1, control=0x20 (expecting reply), DNET=0xFFFF, DLEN=0, hop_count=255
    npdu = struct.pack('>BB', 1, 0x20)
    npdu += struct.pack('>HBB', 0xFFFF, 0, 255)
    # APDU: PDU-type=1 (Unconfirmed-Request), service=8 (Who-Is)
    apdu = struct.pack('>BB', 0x10, 0x08)
    payload = npdu + apdu
    bvlc = struct.pack('>BBH', 0x81, 0x0b, 4 + len(payload))
    return bvlc + payload


def gen_mqtt_connect():
    """MQTT CONNECT packet (v3.1.1)."""
    # Variable header
    protocol_name = struct.pack('>H', 4) + b'MQTT'
    protocol_level = struct.pack('>B', 4)  # v3.1.1
    connect_flags = struct.pack('>B', 0x02)  # Clean Session
    keep_alive = struct.pack('>H', 60)
    # Payload: Client ID
    client_id = b'proto-audit'
    payload = struct.pack('>H', len(client_id)) + client_id
    var_header = protocol_name + protocol_level + connect_flags + keep_alive
    remaining = var_header + payload
    # Fixed header: type=1 (CONNECT), flags=0
    fixed = struct.pack('>B', 0x10)
    # Encode remaining length (simple case, < 128)
    fixed += struct.pack('>B', len(remaining))
    return fixed + remaining


def gen_modbus_tcp():
    """Modbus/TCP Read Holding Registers request."""
    # MBAP header: transaction_id=1, protocol_id=0, length=6, unit_id=1
    mbap = struct.pack('>HHHB', 1, 0, 6, 1)
    # PDU: function=3 (Read Holding Registers), start=0, quantity=10
    pdu = struct.pack('>BHH', 3, 0, 10)
    return mbap + pdu


def gen_dnp3():
    """DNP3 over TCP (minimal read request)."""
    # Transport header: FIN=1, FIR=1, SEQ=0 → 0xC0
    transport = b'\xc0'
    # Application: control=0xC0, function=1 (Read)
    app = struct.pack('>BB', 0xC0, 0x01)
    # Object header: group=1, variation=0, qualifier=0x06 (all)
    app += struct.pack('>BBB', 1, 0, 0x06)
    fragment = transport + app
    # Data link layer: start=0x0564, length, control=0xC0, dest=1, src=2
    dll_len = 5 + len(fragment)  # 5 = control + dest(2) + src(2)
    dll = struct.pack('>HB', 0x0564, dll_len)
    dll += struct.pack('<B', 0xC0)  # control: DIR=1, PRM=1, FCV=0, FCB=0, FC=0
    dll += struct.pack('<HH', 1, 2)  # destination, source (little-endian)
    # CRC (simplified, zeros — tshark still parses)
    dll += struct.pack('<H', 0)
    return dll + fragment + struct.pack('<H', 0)


def gen_enip_list_identity():
    """EtherNet/IP ListIdentity command."""
    # Command=0x0063 (ListIdentity), Length=0, Session=0, Status=0
    # Sender Context=0, Options=0
    hdr = struct.pack('<HHIHQ', 0x0063, 0, 0, 0, 0)
    hdr += struct.pack('<I', 0)  # options
    return hdr


def gen_http_get():
    """HTTP GET request (minimal)."""
    return (
        b'GET / HTTP/1.1\r\n'
        b'Host: 192.168.1.2\r\n'
        b'User-Agent: proto-audit/1.0\r\n'
        b'\r\n'
    )


def gen_bgp_open():
    """BGP OPEN message."""
    # Marker: 16 bytes of 0xFF
    marker = b'\xff' * 16
    # OPEN: version=4, my_as=65001, hold_time=180, bgp_id=192.168.1.1, opt_len=0
    open_body = struct.pack('>B', 4)          # version
    open_body += struct.pack('>H', 65001)     # my AS
    open_body += struct.pack('>H', 180)       # hold time
    open_body += b'\xc0\xa8\x01\x01'          # BGP identifier
    open_body += struct.pack('>B', 0)         # optional parameters length
    length = 19 + len(open_body)  # 16 (marker) + 2 (length) + 1 (type)
    msg = marker + struct.pack('>HB', length, 1) + open_body
    return msg


def gen_ssh_version():
    """SSH version string (triggers tshark SSH dissector)."""
    return b'SSH-2.0-proto-audit_1.0\r\n'


def gen_smtp_greeting():
    """SMTP server greeting."""
    return b'220 mail.example.com ESMTP proto-audit\r\n'


def gen_ftp_greeting():
    """FTP server greeting."""
    return b'220 ftp.example.com FTP proto-audit ready\r\n'


def gen_telnet_negotiation():
    """Telnet IAC negotiation."""
    # IAC WILL ECHO, IAC WILL SGA, IAC DO TERMINAL-TYPE
    return (
        b'\xff\xfb\x01'  # IAC WILL ECHO
        + b'\xff\xfb\x03'  # IAC WILL SGA
        + b'\xff\xfd\x18'  # IAC DO TERMINAL-TYPE
    )


def gen_imap_greeting():
    """IMAP server greeting."""
    return b'* OK [CAPABILITY IMAP4rev1] proto-audit IMAP ready\r\n'


def gen_ldap_bind():
    """LDAP Simple Bind Request (ASN.1 BER)."""
    # BindRequest: version=3, name="", authentication=simple("")
    version = b'\x02\x01\x03'         # INTEGER 3
    name = b'\x04\x00'                # OCTET STRING ""
    auth = b'\x80\x00'                # context[0] simple ""
    bind_body = version + name + auth
    # BindRequest [APPLICATION 0]
    bind_req = b'\x60' + bytes([len(bind_body)]) + bind_body
    # Message: messageID=1, protocolOp=BindRequest
    msg_id = b'\x02\x01\x01'
    msg_body = msg_id + bind_req
    # SEQUENCE
    msg = b'\x30' + bytes([len(msg_body)]) + msg_body
    return msg


def gen_diameter():
    """Diameter Capabilities-Exchange-Request (CER)."""
    # Header: version=1, length=TBD, flags=0x80 (R), command=257 (CER), app_id=0
    # hop-by-hop=1, end-to-end=1
    # AVP: Origin-Host (264), mandatory
    oh_value = b'proto-audit.example.com'
    oh_padding = (4 - len(oh_value) % 4) % 4
    oh_avp = struct.pack('>IIB', 264, 0x40 << 16 | (12 + len(oh_value)), 0)
    # Simplified: just use raw bytes for a minimal CER
    avps = b''
    # Origin-Host AVP (264): flags=M, length=8+len
    oh = b'proto-audit'
    oh_len = 8 + len(oh)
    oh_pad = (4 - oh_len % 4) % 4
    avps += struct.pack('>IBxH', 264, 0x40, oh_len) + oh + b'\x00' * oh_pad
    # Origin-Realm AVP (296)
    realm = b'example.com'
    or_len = 8 + len(realm)
    or_pad = (4 - or_len % 4) % 4
    avps += struct.pack('>IBxH', 296, 0x40, or_len) + realm + b'\x00' * or_pad
    # Header
    msg_len = 20 + len(avps)
    hdr = struct.pack('>B', 1)  # version
    hdr += struct.pack('>I', msg_len)[1:]  # length (3 bytes)
    hdr += struct.pack('>B', 0x80)  # flags: R
    hdr += struct.pack('>I', 257)[1:]  # command code (3 bytes)
    hdr += struct.pack('>III', 0, 1, 1)  # app_id, hop-by-hop, end-to-end
    return hdr + avps


def gen_amqp_protocol_header():
    """AMQP 0-9-1 protocol header."""
    return b'AMQP\x00\x00\x09\x01'


def gen_redis_ping():
    """Redis PING command (RESP protocol)."""
    return b'*1\r\n$4\r\nPING\r\n'


def gen_kafka_api_versions():
    """Kafka ApiVersions request (v0)."""
    # Request header: length=TBD, api_key=18 (ApiVersions), api_version=0
    # correlation_id=1, client_id="proto-audit"
    client_id = b'proto-audit'
    body = struct.pack('>HH', 18, 0)  # api_key, api_version
    body += struct.pack('>I', 1)       # correlation_id
    body += struct.pack('>H', len(client_id)) + client_id
    length = struct.pack('>I', len(body))
    return length + body


def gen_memcache_get():
    """Memcached text protocol GET."""
    return b'get proto-audit-key\r\n'


def gen_kerberos_as_req():
    """Kerberos AS-REQ (minimal, ASN.1)."""
    # This is a simplified ASN.1 structure for tshark recognition
    # [APPLICATION 10] SEQUENCE { pvno=5, msg-type=10, ... }
    pvno = b'\xa1\x03\x02\x01\x05'     # pvno [1] INTEGER 5
    msg_type = b'\xa2\x03\x02\x01\x0a' # msg-type [2] INTEGER 10
    # Minimal req-body [4] SEQUENCE { kdc-options, cname, realm, sname, till }
    kdc_options = b'\xa0\x07\x03\x05\x00\x00\x00\x00\x00'  # kdc-options [0] BIT STRING
    realm = b'\xa2\x0d\x1b\x0b\x45\x58\x41\x4d\x50\x4c\x45\x2e\x43\x4f\x4d'  # realm "EXAMPLE.COM"
    req_body_content = kdc_options + realm
    req_body = b'\xa4' + bytes([2 + len(req_body_content)]) + b'\x30' + bytes([len(req_body_content)]) + req_body_content
    inner = pvno + msg_type + req_body
    seq = b'\x30' + bytes([len(inner)]) + inner
    # APPLICATION 10
    msg = b'\x6a' + bytes([len(seq)]) + seq
    return msg


def gen_rtsp_describe():
    """RTSP DESCRIBE request."""
    return (
        b'DESCRIBE rtsp://192.168.1.2/stream RTSP/1.0\r\n'
        b'CSeq: 1\r\n'
        b'Accept: application/sdp\r\n'
        b'\r\n'
    )


def gen_opc_ua_hello():
    """OPC UA Hello message."""
    # MessageType="HEL", ChunkType='F'
    endpoint = b'opc.tcp://192.168.1.2:4840'
    msg = b'HELF'
    body = struct.pack('<I', 0)     # protocol version
    body += struct.pack('<I', 65535)  # receive buffer size
    body += struct.pack('<I', 65535)  # send buffer size
    body += struct.pack('<I', 0)     # max message size
    body += struct.pack('<I', 0)     # max chunk count
    body += struct.pack('<I', len(endpoint)) + endpoint
    msg_len = 8 + len(body)
    msg += struct.pack('<I', msg_len)
    return msg + body


def gen_wireguard_initiation():
    """WireGuard Initiation message (Type 1)."""
    msg = struct.pack('<I', 1)       # message type = initiation
    msg += struct.pack('<I', 28)     # sender index
    msg += b'\x00' * 32             # unencrypted ephemeral
    msg += b'\x00' * 48             # encrypted static
    msg += b'\x00' * 28             # encrypted timestamp
    msg += b'\x00' * 16             # mac1
    msg += b'\x00' * 16             # mac2
    return msg


def gen_vxlan():
    """VXLAN header with valid flags and VNI."""
    # Flags: I=1 (valid VNI), rest=0 → 0x08000000
    # VNI: 100, Reserved: 0
    msg = struct.pack('>I', 0x08000000)
    msg += struct.pack('>I', 100 << 8)  # VNI in upper 24 bits
    # Inner Ethernet frame
    msg += ethernet(etype=0x0800)
    msg += ipv4(proto=17, payload_len=8)
    msg += udp(dport=80)
    return msg


def gen_smb_negotiate():
    """SMB1 Negotiate Protocol request (triggers tshark SMB dissector)."""
    # NetBIOS session header: type=0 (message), length=TBD
    # SMB header (32 bytes)
    smb = b'\xff\x53\x4d\x42'  # \xFFSMB
    smb += struct.pack('<B', 0x72)  # command: Negotiate Protocol (0x72)
    smb += struct.pack('<I', 0)     # status
    smb += struct.pack('<B', 0x18)  # flags
    smb += struct.pack('<H', 0xc853)  # flags2
    smb += b'\x00' * 12             # PID high, signature, reserved
    smb += struct.pack('<H', 0)     # TID
    smb += struct.pack('<H', 1234)  # PID
    smb += struct.pack('<H', 0)     # UID
    smb += struct.pack('<H', 1)     # MID
    # Parameters: word_count=0
    smb += struct.pack('<B', 0)
    # Data: byte_count=TBD, dialect strings
    dialect = b'\x02NT LM 0.12\x00'
    smb += struct.pack('<H', len(dialect))
    smb += dialect
    # NetBIOS header
    nb = struct.pack('>BH', 0, len(smb))
    # Need 4-byte NetBIOS header
    nb = b'\x00' + struct.pack('>I', len(smb))[1:]
    return nb + smb


def gen_smb2_negotiate():
    """SMB2 Negotiate Protocol request."""
    # NetBIOS session header
    # SMB2 header (64 bytes)
    smb2 = b'\xfeSMB'              # protocol id
    smb2 += struct.pack('<H', 64)  # header length
    smb2 += struct.pack('<H', 0)   # credit charge
    smb2 += struct.pack('<I', 0)   # status
    smb2 += struct.pack('<H', 0)   # command: Negotiate (0)
    smb2 += struct.pack('<H', 1)   # credit request
    smb2 += struct.pack('<I', 0)   # flags
    smb2 += struct.pack('<I', 0)   # next command
    smb2 += struct.pack('<Q', 1)   # message id
    smb2 += struct.pack('<I', 0)   # reserved (process id)
    smb2 += struct.pack('<I', 0)   # tree id
    smb2 += struct.pack('<Q', 0)   # session id
    smb2 += b'\x00' * 16          # signature
    # Negotiate request body
    body = struct.pack('<H', 36)   # structure size
    body += struct.pack('<H', 1)   # dialect count
    body += struct.pack('<H', 0)   # security mode
    body += struct.pack('<H', 0)   # reserved
    body += struct.pack('<I', 0)   # capabilities
    body += b'\x00' * 16          # client GUID
    body += struct.pack('<I', 0)   # negotiate context offset
    body += struct.pack('<H', 0)   # negotiate context count
    body += struct.pack('<H', 0)   # reserved2
    body += struct.pack('<H', 0x0311)  # dialect: SMB 3.1.1
    smb2 += body
    # NetBIOS
    nb = b'\x00' + struct.pack('>I', len(smb2))[1:]
    return nb + smb2


def gen_tacacs():
    """TACACS+ Authentication START."""
    # Header: major=0xc0 (version major=12, minor=0), type=1 (authen),
    # seq_no=1, flags=0x01 (unencrypted), session_id=1, length=TBD
    body = struct.pack('>BBBB',
        1,     # action = LOGIN
        1,     # priv_lvl = minimum
        1,     # authen_type = ASCII
        1,     # authen_service = LOGIN
    )
    body += struct.pack('>BBBB', 4, 0, 0, 0)  # user_len=4, port_len, rem_addr_len, data_len
    body += b'test'  # user
    hdr = struct.pack('>BBBI', 0xc0, 1, 1, 0x01)
    hdr += struct.pack('>I', 1)           # session_id
    hdr += struct.pack('>I', len(body))   # length
    return hdr + body


def gen_skinny():
    """Skinny (SCCP) RegisterMessage."""
    # Message: length=TBD, reserved=0, message_id=1 (RegisterMessage)
    body = b'SEP001122334455'  # device name (15 chars)
    body += b'\x00'             # null terminator
    body += struct.pack('<I', 0) # station user id
    body += struct.pack('<I', 0) # station instance
    body += b'\xc0\xa8\x01\x01' # IP address
    body += struct.pack('<I', 12) # device type
    body += struct.pack('<I', 0)  # max streams
    msg = struct.pack('<III', len(body) + 4, 0, 1) + body
    return msg


def gen_dtls_client_hello():
    """DTLS 1.2 ClientHello."""
    # Record layer: ContentType=Handshake(22), Version=DTLS1.0(0xFEFF)
    # epoch=0, sequence_number=0
    hello_body = (
        b'\xfe\xfd'             # client_version = DTLS 1.2
        + b'\x00' * 32          # random
        + b'\x00'               # session_id length = 0
        + b'\x00'               # cookie length = 0
        + b'\x00\x02\x00\xff'   # cipher_suites
        + b'\x01\x00'           # compression_methods
    )
    # Handshake header: type=1 (ClientHello), length(3), msg_seq=0, frag_offset=0, frag_len
    hs_len = len(hello_body)
    handshake = struct.pack('>B', 1)
    handshake += struct.pack('>I', hs_len)[1:]  # length (3 bytes)
    handshake += struct.pack('>H', 0)            # message_seq
    handshake += struct.pack('>I', 0)[1:]        # fragment_offset (3 bytes)
    handshake += struct.pack('>I', hs_len)[1:]   # fragment_length (3 bytes)
    handshake += hello_body
    # Record header
    record = struct.pack('>BHH', 22, 0xFEFD, 0)  # content_type, version, epoch
    record += struct.pack('>HI', 0, 0)             # sequence_number (6 bytes as H+I)
    record += struct.pack('>H', len(handshake))
    record += handshake
    return record


def gen_iec_mms():
    """IEC MMS (ISO 8327 Session + MMS Initiate-Request, over TPKT+COTP)."""
    # TPKT: version=3, reserved=0, length=TBD
    # COTP: length=2, PDU_type=0xF0 (DT), TPDU_NR=0x80
    cotp = struct.pack('>BBB', 2, 0xF0, 0x80)
    # Minimal MMS Initiate-RequestPDU (simplified ASN.1)
    # Just enough for tshark to recognize as MMS
    mms = b'\xa8\x04\x80\x02\x00\x01'  # Initiate-Request with proposed max PDU size
    payload = cotp + mms
    tpkt = struct.pack('>BBH', 3, 0, 4 + len(payload))
    return tpkt + payload


def gen_zeromq_greeting():
    """ZeroMQ ZMTP 3.0 greeting."""
    # Signature: 0xFF + 8 bytes padding + 0x7F
    msg = b'\xff' + b'\x00' * 8 + b'\x7f'
    # Version: major=3, minor=0
    msg += struct.pack('>BB', 3, 0)
    # Mechanism: "NULL" + padding to 20 bytes
    msg += b'NULL' + b'\x00' * 16
    # As-server: 0
    msg += b'\x00'
    # Filler (31 bytes)
    msg += b'\x00' * 31
    return msg


def gen_iscsi_login():
    """iSCSI Login Request (minimal, for tshark recognition)."""
    # BHS (48 bytes)
    bhs = struct.pack('>B', 0x43)   # opcode=Login (0x03), I=1
    bhs += struct.pack('>B', 0x81)  # T=1, CSG=0, NSG=1
    bhs += struct.pack('>BB', 0, 0) # version-max, version-min
    bhs += struct.pack('>B', 0)     # total AHS length
    # Data segment length (3 bytes)
    bhs += struct.pack('>I', 0)[1:]
    bhs += b'\x00' * 8              # LUN
    bhs += struct.pack('>I', 1)     # Initiator Task Tag
    bhs += struct.pack('>H', 0)     # CID
    bhs += struct.pack('>H', 0)     # reserved
    bhs += struct.pack('>I', 1)     # CmdSN
    bhs += struct.pack('>I', 0)     # ExpStatSN
    bhs += b'\x00' * 16            # reserved
    return bhs


# ═══════════════════════════════════════════════════════════════════════
# Main: generate all templates
# ═══════════════════════════════════════════════════════════════════════

def gen_lldp():
    """Minimal LLDP frame (Chassis ID + Port ID + TTL + End TLVs)."""
    # Chassis ID TLV: type=1, len=7 (subtype=4=MAC, 6-byte MAC)
    chassis_id = struct.pack('>H', (1 << 9) | 7) + b'\x04' + b'\x00\x01\x02\x03\x04\x05'
    # Port ID TLV: type=2, len=7 (subtype=3=MAC, 6-byte MAC)
    port_id = struct.pack('>H', (2 << 9) | 7) + b'\x03' + b'\x00\x01\x02\x03\x04\x05'
    # TTL TLV: type=3, len=2
    ttl = struct.pack('>H', (3 << 9) | 2) + struct.pack('>H', 120)
    # End TLV: type=0, len=0
    end = struct.pack('>H', 0)
    return chassis_id + port_id + ttl + end


def gen_cdp():
    """Minimal CDP frame (requires LLC/SNAP encapsulation on Ethernet)."""
    # LLC header: DSAP=0xAA, SSAP=0xAA, Control=0x03 (SNAP)
    # SNAP: OUI=0x00000C (Cisco), PID=0x2000 (CDP)
    llc_snap = b'\xAA\xAA\x03\x00\x00\x0C\x20\x00'
    # CDP: version=2, TTL=180, checksum=0
    cdp_hdr = struct.pack('>BBH', 2, 180, 0)
    # Device ID TLV: type=1, len=12, "Router1"
    device_id = struct.pack('>HH', 1, 11) + b'Router1'
    return llc_snap + cdp_hdr + device_id


def gen_stp():
    """Minimal STP BPDU (Configuration BPDU)."""
    # LLC header for STP: DSAP=0x42, SSAP=0x42, Control=0x03
    llc = b'\x42\x42\x03'
    # STP: proto_id=0, version=0, type=0 (config BPDU)
    stp = struct.pack('>HBB', 0, 0, 0)
    # Flags + Root priority/bridge/cost/port + message age/max age/hello/forward delay
    stp += b'\x00'  # flags
    stp += struct.pack('>H', 0x8000)  # root priority
    stp += b'\x00\x01\x02\x03\x04\x05'  # root MAC
    stp += struct.pack('>I', 0)  # root path cost
    stp += struct.pack('>H', 0x8000)  # bridge priority
    stp += b'\x00\x01\x02\x03\x04\x05'  # bridge MAC
    stp += struct.pack('>H', 0x8001)  # port identifier
    stp += struct.pack('>HHHH', 0, 20, 2, 15)  # message age, max age, hello, fwd delay
    return llc + stp


def gen_eapol():
    """Minimal EAPOL Start frame."""
    # EAPOL: version=2, type=1 (Start), length=0
    return struct.pack('>BBH', 2, 1, 0)


def gen_eap():
    """Minimal EAP Request/Identity inside EAPOL."""
    # EAP: code=1 (Request), id=1, length=5, type=1 (Identity)
    eap = struct.pack('>BBHB', 1, 1, 5, 1)
    # EAPOL: version=2, type=0 (EAP-Packet), length=len(eap)
    eapol = struct.pack('>BBH', 2, 0, len(eap)) + eap
    return eapol


def gen_coap():
    """Minimal CoAP GET request."""
    # CoAP: ver=1, type=0 (CON), token_len=1, code=0.01 (GET)
    hdr = struct.pack('>BBH', 0x41, 0x01, 0x1234)  # msg_id=0x1234
    token = b'\xAB'
    # Option: Uri-Path "test" (option delta=11, length=4)
    option = struct.pack('>B', 0xB4) + b'test'
    return hdr + token + option


def gen_hsrp():
    """Minimal HSRPv1 Hello message (UDP:1985)."""
    # HSRPv1: version=0, opcode=0 (Hello), state=16 (Active), hellotime=3, holdtime=10
    # priority=100, group=1, auth=cisco\0\0\0
    hsrp = struct.pack('>BBBBBBB', 0, 0, 16, 3, 10, 100, 1)
    hsrp += b'\x00'  # reserved
    hsrp += b'cisco\x00\x00\x00'  # authentication (8 bytes)
    hsrp += b'\xc0\xa8\x01\x01'  # virtual IP
    return hsrp


def gen_ptp():
    """Minimal PTP Sync message (IEEE 1588)."""
    # PTP: transport=0, messageType=0 (Sync), version=2
    ptp = struct.pack('>BBHB', 0x00, 0x02, 44, 0)  # transportSpecific|messageType, versionPTP, messageLength, domainNumber
    ptp += b'\x00'  # reserved
    ptp += struct.pack('>H', 0x0200)  # flagField (two-step)
    ptp += struct.pack('>Q', 0) + struct.pack('>H', 0)  # correctionField (10 bytes)
    ptp += struct.pack('>I', 0)  # reserved
    ptp += b'\x00\x01\x02\xff\xfe\x03\x04\x05'  # sourcePortIdentity (8 bytes)
    ptp += struct.pack('>H', 1)  # sourcePortNumber (2 bytes)
    ptp += struct.pack('>H', 0)  # sequenceId
    ptp += struct.pack('>BB', 0, 0)  # controlField, logMessageInterval
    ptp += struct.pack('>Q', 0) + struct.pack('>H', 0)  # originTimestamp (10 bytes)
    return ptp


def gen_tftp():
    """Minimal TFTP Read Request."""
    # OpCode=1 (RRQ), filename="test.txt", mode="octet"
    return struct.pack('>H', 1) + b'test.txt\x00octet\x00'


def gen_syslog():
    """Minimal Syslog message (UDP:514)."""
    return b'<134>1 2024-01-01T00:00:00Z host app - - - Test message'


def gen_nbns():
    """Minimal NBNS name query (UDP:137)."""
    # Transaction ID, flags=0x0110 (standard query, recursion desired), questions=1
    hdr = struct.pack('>HHHHHH', 0x1234, 0x0110, 1, 0, 0, 0)
    # NBNS encoded name for "TEST" (32 bytes of encoded data + null + type + class)
    name = b'\x20'  # name length=32
    name += b'FEEFFCFGEFFCCACACACACACACACACACACA'[:32]  # encoded "TEST"
    name += b'\x00'  # null terminator
    name += struct.pack('>HH', 0x0020, 0x0001)  # type=NB, class=IN
    return hdr + name


def gen_mgcp():
    """Minimal MGCP AuditEndpoint command (UDP:2727)."""
    return b'AUEP 1234 aaln/1@gw1.example.com MGCP 1.0\r\n\r\n'


def gen_openflow():
    """Minimal OpenFlow 1.3 Hello message (TCP:6653)."""
    # Type=0 (Hello), version=4 (OF 1.3), length=8, xid=1
    return struct.pack('>BBHI', 4, 0, 8, 1)


def gen_bfd():
    """Minimal BFD Control packet (UDP:3784)."""
    # Version=1, Diag=0, State=1 (Down), flags=0
    # Detect Mult=3, Length=24
    # My Discriminator, Your Discriminator
    # Desired Min TX, Required Min RX, Required Min Echo RX
    bfd = struct.pack('>BBB', 0x20, 0x40, 24)  # ver=1|diag=0, sta=1|flags, length
    bfd += struct.pack('>B', 3)  # detect mult
    bfd += struct.pack('>II', 1, 0)  # my/your discriminator
    bfd += struct.pack('>III', 1000000, 1000000, 0)  # min TX, min RX, min echo
    return bfd


def main():
    parser = argparse.ArgumentParser(description='Generate PCAP templates')
    parser.add_argument('--output-dir', required=True, help='Output directory')
    args = parser.parse_args()

    import os
    os.makedirs(args.output_dir, exist_ok=True)

    count = 0

    def emit(name, link_type, packet):
        nonlocal count
        write_pcap(os.path.join(args.output_dir, f'{name}.pcap'), link_type, packet)
        count += 1

    # ── TLS ──
    emit('tls', 1, eth_ipv4_tcp(443, gen_tls_client_hello()))

    # ── HTTP/2 ──
    emit('http2', 1, eth_ipv4_tcp(8080, gen_http2_preface()))

    # ── DHCP (UDP:67) ──
    emit('dhcp', 1, eth_ipv4_udp(67, gen_dhcp_discover(), sport=68))

    # ── DHCPv6 (UDP:547) ──
    dhcpv6_payload = gen_dhcpv6_solicit()
    dhcpv6_udp = udp(sport=546, dport=547, payload=dhcpv6_payload)
    dhcpv6_ipv6 = ipv6(next_header=17, payload_len=len(dhcpv6_udp))
    emit('dhcpv6', 1, ethernet(etype=0x86DD) + dhcpv6_ipv6 + dhcpv6_udp)

    # ── NTP (UDP:123) ──
    emit('ntp', 1, eth_ipv4_udp(123, gen_ntp_query()))

    # ── SNMP (UDP:161) ──
    emit('snmp', 1, eth_ipv4_udp(161, gen_snmpv1_get()))

    # ── RADIUS (UDP:1812) ──
    emit('radius', 1, eth_ipv4_udp(1812, gen_radius_access_request()))

    # ── SIP (UDP:5060) ──
    emit('sip', 1, eth_ipv4_udp(5060, gen_sip_invite()))

    # ── RTP (UDP:5004) ──
    emit('rtp', 1, eth_ipv4_udp(5004, gen_rtp(), sport=5004))

    # ── RTCP (UDP:5005) ──
    emit('rtcp', 1, eth_ipv4_udp(5005, gen_rtcp_sr(), sport=5005))

    # ── STUN (UDP:3478) ──
    emit('stun', 1, eth_ipv4_udp(3478, gen_stun_binding()))

    # ── GTP-U (UDP:2152) ──
    emit('gtp_u', 1, eth_ipv4_udp(2152, gen_gtp_u_echo()))

    # ── GTP-C (UDP:2123) ──
    emit('gtp_c', 1, eth_ipv4_udp(2123, gen_gtp_c_echo()))

    # ── NetFlow v5 (UDP:2055) ──
    emit('netflow_v5', 1, eth_ipv4_udp(2055, gen_netflow_v5()))

    # ── NetFlow v9 (UDP:2055) — separate template ──
    emit('netflow_v9', 1, eth_ipv4_udp(2055, gen_netflow_v9()))

    # ── IPFIX (UDP:4739) ──
    emit('ipfix', 1, eth_ipv4_udp(4739, gen_ipfix()))

    # ── BACnet (UDP:47808) ──
    emit('bacnet', 1, eth_ipv4_udp(47808, gen_bacnet()))

    # ── MQTT (TCP:1883) ──
    emit('mqtt', 1, eth_ipv4_tcp(1883, gen_mqtt_connect()))

    # ── Modbus/TCP (TCP:502) ──
    emit('modbus_tcp', 1, eth_ipv4_tcp(502, gen_modbus_tcp()))

    # ── DNP3 (TCP:20000) ──
    emit('dnp3', 1, eth_ipv4_tcp(20000, gen_dnp3()))

    # ── EtherNet/IP (UDP:44818 for ListIdentity) ──
    emit('enip', 1, eth_ipv4_udp(44818, gen_enip_list_identity()))

    # ── HTTP (TCP:80) ──
    emit('http', 1, eth_ipv4_tcp(80, gen_http_get()))

    # ── BGP (TCP:179) ──
    emit('bgp', 1, eth_ipv4_tcp(179, gen_bgp_open()))

    # ── SSH (TCP:22) ──
    emit('ssh', 1, eth_ipv4_tcp(22, gen_ssh_version()))

    # ── SMTP (TCP:25) ──
    emit('smtp', 1, eth_ipv4_tcp(25, gen_smtp_greeting()))

    # ── FTP (TCP:21) ──
    emit('ftp', 1, eth_ipv4_tcp(21, gen_ftp_greeting()))

    # ── Telnet (TCP:23) ──
    emit('telnet', 1, eth_ipv4_tcp(23, gen_telnet_negotiation()))

    # ── IMAP (TCP:143) ──
    emit('imap', 1, eth_ipv4_tcp(143, gen_imap_greeting()))

    # ── LDAP (TCP:389) ──
    emit('ldap', 1, eth_ipv4_tcp(389, gen_ldap_bind()))

    # ── Diameter (TCP:3868) ──
    emit('diameter', 1, eth_ipv4_tcp(3868, gen_diameter()))

    # ── AMQP (TCP:5672) ──
    emit('amqp', 1, eth_ipv4_tcp(5672, gen_amqp_protocol_header()))

    # ── Redis (TCP:6379) ──
    emit('redis', 1, eth_ipv4_tcp(6379, gen_redis_ping()))

    # ── Kafka (TCP:9092) ──
    emit('kafka', 1, eth_ipv4_tcp(9092, gen_kafka_api_versions()))

    # ── Memcache (TCP:11211) ──
    emit('memcache', 1, eth_ipv4_tcp(11211, gen_memcache_get()))

    # ── Kerberos (TCP:88) ──
    # For TCP Kerberos, prepend 4-byte length prefix
    krb = gen_kerberos_as_req()
    krb_tcp = struct.pack('>I', len(krb)) + krb
    emit('kerberos', 1, eth_ipv4_tcp(88, krb_tcp))

    # ── RTSP (TCP:554) ──
    emit('rtsp', 1, eth_ipv4_tcp(554, gen_rtsp_describe()))

    # ── OPC UA (TCP:4840) ──
    emit('opc_ua', 1, eth_ipv4_tcp(4840, gen_opc_ua_hello()))

    # ── VXLAN (UDP:4789) ──
    emit('vxlan', 1, eth_ipv4_udp(4789, gen_vxlan()))

    # ── WireGuard (UDP:51820) ──
    emit('wireguard', 1, eth_ipv4_udp(51820, gen_wireguard_initiation()))

    # ── SMB (TCP:445) ──
    emit('smb', 1, eth_ipv4_tcp(445, gen_smb_negotiate()))

    # ── SMB2 (TCP:445) — separate template with SMB2 protocol ──
    emit('smb2', 1, eth_ipv4_tcp(445, gen_smb2_negotiate()))

    # ── TACACS+ (TCP:49) ──
    emit('tacacs', 1, eth_ipv4_tcp(49, gen_tacacs()))

    # ── Skinny/SCCP (TCP:2000) ──
    emit('skinny', 1, eth_ipv4_tcp(2000, gen_skinny()))

    # ── DTLS (UDP:4433) ──
    emit('dtls', 1, eth_ipv4_udp(4433, gen_dtls_client_hello()))

    # ── IEC MMS (TCP:102) ──
    emit('iec_mms', 1, eth_ipv4_tcp(102, gen_iec_mms()))

    # ── ZeroMQ (TCP:5555) ──
    emit('zeromq', 1, eth_ipv4_tcp(5555, gen_zeromq_greeting()))

    # ── iSCSI (TCP:3260) ──
    emit('iscsi', 1, eth_ipv4_tcp(3260, gen_iscsi_login()))

    # ── IKEv2 (UDP:500) ──
    # IKE_SA_INIT: initiator SPI=random, responder SPI=0
    # Next Payload=SA(33), MjVer=2, MnVer=0, Exchange=IKE_SA_INIT(34)
    # Flags=0x08 (Initiator), MsgID=0, Length=TBD
    ike_sa_payload = b'\x00' * 8  # minimal SA payload stub
    ike_body = struct.pack('>Q', 0x0102030405060708)  # initiator SPI
    ike_body += struct.pack('>Q', 0)                   # responder SPI
    ike_body += struct.pack('>BBBBI',
        33,    # next payload: SA
        0x20,  # version: 2.0
        34,    # exchange type: IKE_SA_INIT
        0x08,  # flags: Initiator
        0,     # message ID
    )
    ike_body += struct.pack('>I', 28 + len(ike_sa_payload))  # length
    ike_body += ike_sa_payload
    emit('ikev2', 1, eth_ipv4_udp(500, ike_body))

    # ── LLDP (EtherType 0x88CC) ──
    emit('lldp', 1, ethernet(dst=b'\x01\x80\xC2\x00\x00\x0E', etype=0x88CC) + gen_lldp())

    # ── CDP (LLC/SNAP on Ethernet, dst=01:00:0C:CC:CC:CC) ──
    cdp_frame = ethernet(dst=b'\x01\x00\x0C\xCC\xCC\xCC', etype=0x0000)  # length field
    # Replace etype with length for 802.3
    cdp_data = gen_cdp()
    cdp_len = len(cdp_data)
    cdp_frame = ethernet(dst=b'\x01\x00\x0C\xCC\xCC\xCC')[:12] + struct.pack('>H', cdp_len) + cdp_data
    emit('cdp', 1, cdp_frame)

    # ── STP (BPDU, dst=01:80:C2:00:00:00) ──
    stp_data = gen_stp()
    stp_frame = ethernet(dst=b'\x01\x80\xC2\x00\x00\x00')[:12] + struct.pack('>H', len(stp_data)) + stp_data
    emit('stp', 1, stp_frame)

    # ── EAPOL (EtherType 0x888E) ──
    emit('eapol', 1, ethernet(etype=0x888E) + gen_eapol())

    # ── EAP (inside EAPOL, EtherType 0x888E) ──
    emit('eap', 1, ethernet(etype=0x888E) + gen_eap())

    # ── CoAP (UDP:5683) ──
    emit('coap', 1, eth_ipv4_udp(5683, gen_coap()))

    # ── HSRP (UDP:1985) ──
    emit('hsrp', 1, eth_ipv4_udp(1985, gen_hsrp()))

    # ── PTP (EtherType 0x88F7, multicast dst) ──
    emit('ptp', 1, ethernet(dst=b'\x01\x1B\x19\x00\x00\x00', etype=0x88F7) + gen_ptp())

    # ── TFTP (UDP:69) ──
    emit('tftp', 1, eth_ipv4_udp(69, gen_tftp()))

    # ── Syslog (UDP:514) ──
    emit('syslog', 1, eth_ipv4_udp(514, gen_syslog()))

    # ── NBNS (UDP:137) ──
    emit('nbns', 1, eth_ipv4_udp(137, gen_nbns()))

    # ── MGCP (UDP:2727) ──
    emit('mgcp', 1, eth_ipv4_udp(2727, gen_mgcp()))

    # ── OpenFlow (TCP:6653) ──
    emit('openflow', 1, eth_ipv4_tcp(6653, gen_openflow()))

    # ── BFD (UDP:3784) ──
    emit('bfd', 1, eth_ipv4_udp(3784, gen_bfd()))

    print(f"\nGenerated {count} PCAP templates in {args.output_dir}", file=sys.stderr)


if __name__ == '__main__':
    main()
