#!/usr/bin/env python3
"""Generate PCAP templates for Bronze protocols that need valid content.

Creates minimal-but-valid packets that tshark can dissect.
"""

import argparse
import struct
import sys
import os

OUTPUT_DIR = os.path.join(os.path.dirname(__file__), '..', 'pcap_templates')


def pcap_global_header(link_type=1):
    return struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, link_type)


def pcap_record(packet):
    length = len(packet)
    return struct.pack('<IIII', 0, 0, length, length) + packet


def write_pcap(name, link_type, packet):
    path = os.path.join(OUTPUT_DIR, f'{name}.pcap')
    if os.path.exists(path):
        print(f"  SKIP {name} (already exists)", file=sys.stderr)
        return
    with open(path, 'wb') as f:
        f.write(pcap_global_header(link_type))
        f.write(pcap_record(packet))
    print(f"  Wrote {name}.pcap ({len(packet)} bytes)", file=sys.stderr)


# ── Network helpers ──

def ethernet(dst=b'\x00'*6, src=b'\x00'*6, etype=0x0800):
    return dst + src + struct.pack('>H', etype)


def ipv4(proto=6, payload_len=0, src=b'\xc0\xa8\x01\x01', dst=b'\xc0\xa8\x01\x02'):
    total_len = 20 + payload_len
    return struct.pack('>BBHHHBBH4s4s',
        0x45, 0, total_len, 0x1234, 0x4000, 64, proto, 0, src, dst)


def ipv6(next_header=6, payload_len=0):
    src = b'\xfd\x00' + b'\x00'*13 + b'\x01'
    dst = b'\xfd\x00' + b'\x00'*13 + b'\x02'
    return struct.pack('>IHBB16s16s', 0x60000000, payload_len, next_header, 64, src, dst)


def udp(sport=12345, dport=53, payload=b''):
    length = 8 + len(payload)
    return struct.pack('>HHHH', sport, dport, length, 0) + payload


def tcp(sport=12345, dport=443, payload=b'', seq=1000, ack=0, flags=0x18):
    data_offset = 5 << 4
    return struct.pack('>HHIIBBHHH',
        sport, dport, seq, ack, data_offset, flags, 65535, 0, 0) + payload


def sctp(sport=12345, dport=2905, payload=b''):
    """SCTP common header (12 bytes) + payload."""
    return struct.pack('>HHII', sport, dport, 0, 0) + payload


def sctp_data_chunk(payload=b'', tsn=1, stream=0, ssn=0, ppid=0):
    """SCTP DATA chunk wrapping payload."""
    chunk_len = 16 + len(payload)
    # type=0, flags=3 (B+E bits), length
    return struct.pack('>BBH', 0, 0x03, chunk_len) + \
           struct.pack('>IHHI', tsn, stream, ssn, ppid) + payload


def eth_ipv4_udp(dport, payload, sport=12345):
    udp_seg = udp(sport=sport, dport=dport, payload=payload)
    ip_hdr = ipv4(proto=17, payload_len=len(udp_seg))
    return ethernet(etype=0x0800) + ip_hdr + udp_seg


def eth_ipv4_tcp(dport, payload, sport=12345, seq=1000, ack=0, flags=0x18):
    tcp_seg = tcp(sport=sport, dport=dport, payload=payload, seq=seq, ack=ack, flags=flags)
    ip_hdr = ipv4(proto=6, payload_len=len(tcp_seg))
    return ethernet(etype=0x0800) + ip_hdr + tcp_seg


def eth_ipv6_udp(dport, payload, sport=12345):
    udp_seg = udp(sport=sport, dport=dport, payload=payload)
    ip_hdr = ipv6(next_header=17, payload_len=len(udp_seg))
    return ethernet(etype=0x86DD) + ip_hdr + udp_seg


def eth_ipv4_sctp(dport, payload, sport=12345):
    sctp_seg = sctp(sport=sport, dport=dport, payload=payload)
    ip_hdr = ipv4(proto=132, payload_len=len(sctp_seg))
    return ethernet(etype=0x0800) + ip_hdr + sctp_seg


# ── Protocol payload generators ──

def gen_radius_acct():
    """RADIUS Accounting-Request (code=4)."""
    code = 4  # Accounting-Request
    identifier = 1
    authenticator = b'\x00' * 16
    # NAS-IP-Address attribute (type=4, len=6)
    attr = struct.pack('>BB4s', 4, 6, b'\xc0\xa8\x01\x01')
    # Acct-Status-Type (type=40, len=6, value=1=Start)
    attr += struct.pack('>BBI', 40, 6, 1)
    length = 20 + len(attr)
    return struct.pack('>BBH16s', code, identifier, length, authenticator) + attr


def gen_radius_coa():
    """RADIUS CoA-Request (code=43)."""
    code = 43  # CoA-Request
    identifier = 1
    authenticator = b'\x00' * 16
    # NAS-IP-Address attribute (type=4, len=6)
    attr = struct.pack('>BB4s', 4, 6, b'\xc0\xa8\x01\x01')
    length = 20 + len(attr)
    return struct.pack('>BBH16s', code, identifier, length, authenticator) + attr


def gen_snmpv3():
    """SNMPv3 message (BER-encoded, minimal)."""
    # SNMPv3 = SEQUENCE { msgVersion INTEGER(3), msgGlobalData, ... }
    # Simplified: just enough for tshark to recognize as SNMPv3
    version = b'\x02\x01\x03'  # INTEGER 3
    # msgGlobalData SEQUENCE
    msg_id = b'\x02\x04\x00\x00\x00\x01'  # INTEGER 1
    msg_max_size = b'\x02\x02\x10\x00'  # INTEGER 4096
    msg_flags = b'\x04\x01\x00'  # OCTET STRING, noAuthNoPriv
    msg_security_model = b'\x02\x01\x03'  # INTEGER 3 (USM)
    global_data = msg_id + msg_max_size + msg_flags + msg_security_model
    global_data = b'\x30' + bytes([len(global_data)]) + global_data
    # msgSecurityParameters (empty OCTET STRING for noAuth)
    sec_params = b'\x04\x00'
    # msgData (plaintext, empty ScopedPDU)
    scoped_pdu = b'\x30\x0e' + b'\x04\x00' + b'\x04\x00' + \
                 b'\xa0\x08\x02\x04\x00\x00\x00\x01\x02\x01\x00\x30\x00'
    msg_data = scoped_pdu
    inner = version + global_data + sec_params + msg_data
    return b'\x30' + bytes([len(inner)]) + inner


def gen_pgm():
    """PGM (Pragmatic General Multicast) SPM packet."""
    # PGM header: sport(2), dport(2), type(1), options(1), checksum(2), gsi(6), tsdu_len(2)
    sport = 7500
    dport = 7500
    pgm_type = 0x00  # SPM
    options = 0x40   # network-significant
    checksum = 0
    gsi = b'\x01\x02\x03\x04\x05\x06'
    tsdu_len = 0
    hdr = struct.pack('>HHBBH6sH', sport, dport, pgm_type, options, checksum, gsi, tsdu_len)
    # SPM-specific: spm_sqn(4), spm_trail(4), spm_lead(4), nla_afi(2), reserved(2), nla(4)
    spm = struct.pack('>IIIHH4s', 1, 0, 1, 1, 0, b'\xc0\xa8\x01\x01')
    return hdr + spm


def gen_vrrp():
    """VRRPv3 packet for IPv6."""
    # VRRPv3: version(4bits)=3, type(4bits)=1(Advertisement), vrid=1
    # priority=100, count_ipaddr=1, (rsvd+max_adver_int)=100, checksum=0
    ver_type = 0x31  # version 3, type 1
    vrid = 1
    priority = 100
    count_ip = 1
    rsvd_max_adver = 100
    checksum = 0
    hdr = struct.pack('>BBBBBH', ver_type, vrid, priority, count_ip,
                      (rsvd_max_adver >> 8) & 0xFF, rsvd_max_adver & 0xFF)
    # Wait, let me redo this properly
    # Byte 0: ver(4) | type(4) = 0x31
    # Byte 1: VRID = 1
    # Byte 2: Priority = 100
    # Byte 3: Count IP Addrs = 1
    # Byte 4-5: (Rsvd 4 bits + Max Adver Int 12 bits) = 0x0064
    # Byte 6-7: Checksum = 0
    hdr = struct.pack('>BBBBHH', 0x31, 1, 100, 1, 0x0064, 0)
    # One IPv6 address
    ipv6_addr = b'\xfd\x00' + b'\x00' * 13 + b'\x01'
    return hdr + ipv6_addr


def gen_some_ip():
    """SOME/IP header (16 bytes minimum)."""
    # Message ID (service ID 0x0001 + method ID 0x0001)
    message_id = 0x00010001
    # Length (8 = header remainder)
    length = 8
    # Request ID (client ID 0x0001 + session ID 0x0001)
    request_id = 0x00010001
    # Protocol version=1, interface version=1, message type=0(REQUEST), return code=0
    proto_ver = 1
    iface_ver = 1
    msg_type = 0  # REQUEST
    return_code = 0
    return struct.pack('>IIIIBBBB', message_id, length, request_id,
                       0, proto_ver, iface_ver, msg_type, return_code)


def gen_babel():
    """Babel protocol Hello message."""
    # Babel header: magic=42, version=2, body_length
    # Hello TLV: type=4, length=6, seqno=1, interval=400
    hello_tlv = struct.pack('>BBHH', 4, 6, 0, 1) + struct.pack('>H', 400)
    body_length = len(hello_tlv)
    header = struct.pack('>BBH', 42, 2, body_length)
    return header + hello_tlv


def gen_bmp():
    """BMP Initiation Message."""
    # BMP v3: version=3, msg_length, msg_type=4(Initiation)
    # Initiation TLV: type=0(String), length=4, value="test"
    tlv = struct.pack('>HH', 0, 4) + b'test'
    msg_length = 6 + len(tlv)  # 6-byte common header
    return struct.pack('>BIBI', 3, msg_length, 4, 0) + tlv


def gen_pcep():
    """PCEP Open message."""
    # Common Header: version(3)+flags(5)=0x20, message_type=1(Open), length
    # Open Object: class=1, type=1, flags, length=4+24
    open_obj_value = struct.pack('>BBBB', 30, 120, 0, 0)  # keepalive, deadtimer, sid, reserved
    open_obj = struct.pack('>BBH', 1, 0x10, 4 + len(open_obj_value)) + open_obj_value
    msg_length = 4 + len(open_obj)
    return struct.pack('>BBH', 0x20, 1, msg_length) + open_obj


def gen_cops():
    """COPS Client-Open message."""
    # Header: version(4)+flags(4)=0x10, op_code=1(REQ), client_type=0, msg_length
    # COPS object: C-Type, C-Num, length, Handle
    handle_obj = struct.pack('>HHI', 0x0101, 8, 1)  # Handle object
    msg_length = 8 + len(handle_obj)
    return struct.pack('>BBHI', 0x10, 1, 0, msg_length) + handle_obj


def gen_collectd():
    """Collectd binary protocol packet."""
    # Part: type=0x0000(host), length, value
    host = b'localhost\x00'
    host_part = struct.pack('>HH', 0x0000, 4 + len(host)) + host
    # Part: type=0x0001(time), length=12, value
    time_part = struct.pack('>HHQ', 0x0001, 12, 1700000000)
    # Part: type=0x0002(plugin), length, value
    plugin = b'cpu\x00'
    plugin_part = struct.pack('>HH', 0x0002, 4 + len(plugin)) + plugin
    return host_part + time_part + plugin_part


def gen_megaco():
    """MEGACO/H.248 text message."""
    msg = b'!/1 [192.168.1.1]:2944\nP=1(A=test{M{O{MO=SR}}})\n'
    return msg


def gen_rpki_rtr():
    """RPKI-RTR Serial Notify (v1)."""
    # PDU Header: version=1, type=0(Serial Notify), session_id=1, length=12, serial=1
    return struct.pack('>BBHI I', 1, 0, 1, 12, 1)


def gen_mongodb():
    """MongoDB OP_MSG (since MongoDB 3.6+)."""
    # MsgHeader: messageLength, requestID, responseTo, opCode=2013(OP_MSG)
    body_section = b'\x00'  # kind=0 (body)
    # BSON document: {ping: 1}
    bson = b'\x13\x00\x00\x00'  # document length
    bson += b'\x10'  # type=int32
    bson += b'ping\x00'  # field name
    bson += struct.pack('<i', 1)  # value
    bson += b'\x00'  # terminator

    msg_body = struct.pack('<I', 0) + body_section + bson  # flagBits + section
    msg_length = 16 + len(msg_body)
    header = struct.pack('<iiiI', msg_length, 1, 0, 2013)
    return header + msg_body


def gen_mysql():
    """MySQL Server Greeting (Handshake v10)."""
    # Protocol version = 10
    proto = b'\x0a'
    # Server version
    version = b'8.0.0\x00'
    # Connection ID
    conn_id = struct.pack('<I', 1)
    # Auth-plugin-data part 1 (8 bytes)
    auth1 = b'\x01\x02\x03\x04\x05\x06\x07\x08'
    # Filler
    filler = b'\x00'
    # Capability flags (lower 2 bytes)
    cap_low = struct.pack('<H', 0xFFFF)
    # Character set
    charset = b'\x21'  # utf8
    # Status flags
    status = struct.pack('<H', 0x0002)
    # Capability flags (upper 2 bytes)
    cap_high = struct.pack('<H', 0x00FF)
    # Auth plugin data length
    auth_len = b'\x15'  # 21
    # Reserved (10 zeros)
    reserved = b'\x00' * 10
    # Auth-plugin-data part 2 (13 bytes)
    auth2 = b'\x00' * 13
    # Auth plugin name
    auth_plugin = b'mysql_native_password\x00'

    payload = proto + version + conn_id + auth1 + filler + cap_low + charset + \
              status + cap_high + auth_len + reserved + auth2 + auth_plugin
    # MySQL packet: length(3) + sequence_id(1) + payload
    pkt_len = struct.pack('<I', len(payload))[:3]
    return pkt_len + b'\x00' + payload


def gen_postgresql():
    """PostgreSQL Authentication OK message (from server)."""
    # AuthenticationOk: type='R', length=8, auth_type=0
    return struct.pack('>cIi', b'R', 8, 0)


def gen_cassandra():
    """Cassandra CQL STARTUP frame (v4)."""
    # Header: version=4(request), flags=0, stream=0, opcode=1(STARTUP), length
    body = b'\x00\x01'  # map with 1 entry
    body += b'\x00\x0b' + b'CQL_VERSION'  # key
    body += b'\x00\x05' + b'3.0.0'  # value
    return struct.pack('>BBHBI', 0x04, 0, 0, 1, len(body)) + body


def gen_pop3():
    """POP3 server greeting."""
    return b'+OK POP3 server ready\r\n'


def gen_nntp():
    """NNTP server greeting."""
    return b'200 NNTP Service Ready\r\n'


def gen_xmpp():
    """XMPP stream open."""
    return b"<?xml version='1.0'?><stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='example.com' version='1.0'>"


def gen_rtmp():
    """RTMP C0+C1 handshake."""
    # C0: version = 3
    c0 = b'\x03'
    # C1: timestamp(4) + zero(4) + random(1528)
    c1 = struct.pack('>II', 0, 0) + b'\x00' * 1528
    return c0 + c1


def gen_mrp():
    """MRP (Media Redundancy Protocol) test frame."""
    # MRP TLV: type=1(Common), length, sequence, domain UUID
    # Version 1
    tlv_type = 0x01  # MRP_Common
    tlv_len = 4 + 16 + 2  # seq(2) + uuid(16) + reserved(4)
    sequence = 1
    uuid = b'\x00' * 16
    common = struct.pack('>HH H', tlv_type, tlv_len, sequence) + uuid + b'\x00' * 2
    # End TLV
    end = struct.pack('>HH', 0x00, 0x00)
    return common + end


def gen_ecpri():
    """eCPRI message (type 0 = IQ Data)."""
    # Header: protocol_revision(4)+reserved(3)+C(1) = 0x10, message_type=0, payload_size
    payload = b'\x00' * 8  # minimal IQ data
    return struct.pack('>BBH', 0x10, 0, len(payload)) + payload


def gen_profinet_dcp():
    """PROFINET DCP Identify Request."""
    # PN-DCP: ServiceID=5(Identify), ServiceType=0(Request), Xid, ResponseDelay, DCPDataLength
    dcp_data = struct.pack('>BBH', 0xFF, 0xFF, 0x0000)  # option=0xFF, suboption=0xFF
    header = struct.pack('>BBIHH', 5, 0, 0x00000001, 0x0080, len(dcp_data))
    return header + dcp_data


def gen_ptp_v1():
    """PTPv1 Sync message."""
    # PTPv1 header: version(2)=1, network(2)=1, subdomain(16)
    # messageType(1)=1(Sync), etc
    hdr = struct.pack('>HH', 1, 1)  # versionPTP=1, versionNetwork=1
    hdr += b'_DFLT\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'  # subdomain (16 bytes)
    hdr += struct.pack('>B', 1)  # messageType = Sync
    hdr += struct.pack('>B', 0)  # sourceCommunicationTechnology
    hdr += b'\x00' * 6  # sourceUuid
    hdr += struct.pack('>H', 0)  # sourcePortId
    hdr += struct.pack('>H', 1)  # sequenceId
    hdr += struct.pack('>B', 0)  # control
    hdr += b'\x00'  # reserved
    hdr += struct.pack('>H', 0)  # flags
    return hdr


def gen_s7comm():
    """S7COMM Read SZL request over TPKT + COTP."""
    # S7COMM: protocol_id=0x32, msg_type=7(UserData), reserved=0, pdu_ref=1, param_len, data_len
    s7_param = struct.pack('>BBB', 0x00, 0x01, 0x12)  # header, param_length, data_type
    s7_param += struct.pack('>BBH', 4, 0x11, 0x0044)  # length, method, type+function
    s7_param += struct.pack('>BB', 0x01, 0x00)  # subfunction, seq

    s7_data = struct.pack('>BBH', 0xFF, 0x09, 4)  # return_code, transport_size, length
    s7_data += struct.pack('>HH', 0x0011, 0x0000)  # szl_id, szl_index

    s7 = struct.pack('>BBBHHHH', 0x32, 0x07, 0x00, 0x00, 0x0001, len(s7_param), len(s7_data))
    s7 += s7_param + s7_data

    # COTP DT (data transfer)
    cotp = struct.pack('>BBB', 0x02, 0xF0, 0x80)  # length, type=DT, TPDU_NR+EOT

    # TPKT
    tpkt_len = 4 + len(cotp) + len(s7)
    tpkt = struct.pack('>BBH', 3, 0, tpkt_len)

    return tpkt + cotp + s7


def gen_cflow():
    """NetFlow v9 header (CFLOW)."""
    # Version=9, Count=0, SysUptime=1000, UnixSecs, SeqNum=1, SourceID=1
    return struct.pack('>HHIIII', 9, 0, 1000, 1700000000, 1, 1)


def gen_sflow_v5():
    """sFlow v5 datagram."""
    # Version=5, agent_address_type=1(IPv4), agent_address, sub_agent_id, seq, uptime, samples=0
    return struct.pack('>II4sIIII', 5, 1, b'\xc0\xa8\x01\x01', 0, 1, 1000, 0)


def gen_amt():
    """AMT Discovery message."""
    # AMT Discovery: version(4)+type(4)=0x10, reserved=0, nonce(4)
    return struct.pack('>BBI', 0x10, 0, 0x12345678) + b'\x00' * 4


def gen_ayiya():
    """AYIYA identity header."""
    # AYIYA: id_len=4, id_type=0, sig_len=5, hash_method=2, auth_method=1, opcode=1
    # next_header=41(IPv6), epoch, identity(16), signature(20)
    header = struct.pack('>BBBBBB', 4, 0, 5, 2, 1, 1)
    header += struct.pack('>B', 41)  # next_header = IPv6
    header += b'\x00'  # reserved
    header += struct.pack('>I', 1700000000)  # epoch
    header += b'\x00' * 16  # identity
    header += b'\x00' * 20  # signature
    return header


def gen_iec_104():
    """IEC 60870-5-104 STARTDT act APDU."""
    # APCI: start=0x68, length, control fields
    # STARTDT act: type U, byte1=0x07, rest=0
    return struct.pack('>BBBBBb', 0x68, 4, 0x07, 0x00, 0x00, 0x00)


def gen_cmp():
    """CMP (Certificate Management Protocol) PKIMessage."""
    # Minimal ASN.1 SEQUENCE for a PKIMessage
    # This is a DER-encoded empty PKIMessage skeleton
    return b'\x30\x10\x30\x0e\xa0\x03\x02\x01\x02\xa1\x03\x02\x01\x00\xa2\x02\x30\x00'


def gen_lisp_control():
    """LISP Map-Request."""
    # Type=1(Map-Request), flags
    return struct.pack('>BBBB', 0x10, 0x00, 0x00, 0x01) + b'\x00' * 8 + \
           struct.pack('>I', 0x12345678) + struct.pack('>I', 0x56789ABC) + \
           b'\x00\x00\x01\x20' + b'\xc0\xa8\x01\x00'


def gen_doip():
    """DoIP Vehicle Identification Request."""
    # DoIP: version=0x02, inverse=0xFD, payload_type=0x0001, length=0
    return struct.pack('>BBHI', 0x02, 0xFD, 0x0001, 0)


def gen_t38():
    """T.38 UDPTL packet."""
    # Sequence number (2 bytes) + primary IFPC packet
    seq = struct.pack('>H', 1)
    # Primary IFP packet (minimal)
    ifp = b'\x00\x01'  # type indicator + data
    data_field = struct.pack('>H', len(ifp)) + ifp
    return seq + data_field


def gen_sua():
    """SUA CLDT (Connectionless Data Transfer) message."""
    # Common Header: version=1, reserved=0, message_class=7(CL), message_type=1(CLDT)
    # message_length includes header
    payload = struct.pack('>HHI', 0x0006, 8, 1)  # routing_context tag, len, value
    msg_length = 8 + len(payload)
    return struct.pack('>BBBBI', 1, 0, 7, 1, msg_length) + payload


def gen_s1ap():
    """S1AP InitiatingMessage (minimal ASN.1 PER)."""
    # S1AP uses ASN.1 PER. A minimal S1-SETUP-REQUEST:
    # First byte indicates initiating message
    return b'\x00\x11\x00\x15\x00\x00\x02\x00\x3b\x00\x08\x00' + \
           b'\x00\xf1\x10\x00\x00\x00\x01\x00\x40\x00\x03\x40\x01\x00'


def gen_ngap():
    """NGAP InitiatingMessage (minimal ASN.1 PER)."""
    # Similar to S1AP but for 5G
    return b'\x00\x15\x00\x15\x00\x00\x02\x00\x27\x00\x08\x00' + \
           b'\x00\xf1\x10\x00\x00\x00\x01\x00\x28\x00\x03\x40\x01\x00'


def gen_vxlan_gpb():
    """VXLAN with Group Policy Extension."""
    # VXLAN flags=0x88 (G+I bits), group_policy_id=1, reserved, VNI=100
    return struct.pack('>BBHBBBB', 0x88, 0x00, 0x0001, 0x00,
                       0x00, 0x64, 0x00)


def gen_lldp_cdp():
    """CDP frame (LLC/SNAP encapsulation)."""
    # LLC SNAP header: DSAP=0xAA, SSAP=0xAA, Control=0x03, OUI=00:00:0C, Type=0x2000
    llc_snap = struct.pack('>BBBBBHH', 0xAA, 0xAA, 0x03, 0x00, 0x00, 0x0C00, 0x2000)
    # CDP: version=2, ttl=180, checksum=0
    cdp = struct.pack('>BBH', 2, 180, 0)
    # Device-ID TLV: type=1, length=8, value="test"
    cdp += struct.pack('>HH', 1, 8) + b'test'
    return llc_snap + cdp


def gen_esp_null():
    """ESP NULL encryption (just SPI + Seq)."""
    # SPI=0x00000001, Seq=1, then some dummy payload
    return struct.pack('>II', 1, 1) + b'\x00' * 20


def gen_gre_wccpv2():
    """GRE encapsulating WCCPv2."""
    # GRE header: flags=0x0000, protocol=0x883E (WCCPv2)
    gre = struct.pack('>HH', 0x0000, 0x883E)
    # WCCPv2: type=2(Here_I_Am), version=2, length, ... minimal
    wccp = struct.pack('>IHH', 0x00020000, 0x0002, 0)
    return gre + wccp


def gen_l2tpv3():
    """L2TPv3 (IP proto 115) header."""
    # L2TPv3 over IP: session_id(4) + cookie(optional) + payload
    return struct.pack('>I', 0x00000001) + b'\x00' * 4


def gen_marker():
    """Slow Protocol - Marker (IEEE 802.3ad)."""
    # Slow protocol subtype = 2 (Marker)
    subtype = b'\x02'
    # Marker info TLV
    marker_info = struct.pack('>BB', 0x01, 16)  # type=1(Marker Information), length=16
    marker_info += struct.pack('>H', 0x0001)  # requester_port
    marker_info += b'\x00\x00\x00\x00\x00\x01'  # requester_system (MAC)
    marker_info += struct.pack('>I', 1)  # requester_transaction_id
    marker_info += b'\x00' * 2  # pad
    # Terminator TLV
    term = struct.pack('>BB', 0x00, 0x00)
    return subtype + marker_info + term


def gen_mpls_tp():
    """MPLS-TP (same as MPLS but with different label)."""
    # MPLS label stack entry: label(20)+TC(3)+S(1)+TTL(8)
    # Label=1000, TC=0, S=1(bottom), TTL=64
    label_entry = (1000 << 12) | (0 << 9) | (1 << 8) | 64
    return struct.pack('>I', label_entry) + b'\x00' * 20  # + dummy payload


def gen_fcoe_init():
    """FCoE Initialization Protocol (FIP) frame."""
    # FCoE Encapsulation: SOF + FC frame
    # Actually FCoE_Init may refer to FCoE login frames
    # FIP: version=1, reserved=0, code=1(Discovery), subcode=2(Solicitation), desc_list_len, flags
    return struct.pack('>BBHHHHH', 0x10, 0x00, 0x0001, 0x0002, 0x0000, 0x0000, 0x0000)


def gen_edsa():
    """Marvell EDSA tag."""
    # EDSA tag: 4 bytes, then another ethertype + payload
    # mode=0 (FROM_CPU), tagged=0, dev=0, port=1
    return struct.pack('>HH', 0xDADA, 0x0001) + struct.pack('>H', 0x0800) + b'\x00' * 20


def gen_ethertype_tsn():
    """IEEE 802.1CB R-tag (EtherType 0xF1C1)."""
    # R-tag: reserved(4)+sequence_number(16) = 4 bytes total
    # Then inner EtherType + payload
    return struct.pack('>HH', 0x0001, 0x0800) + b'\x00' * 20


def gen_ecpri_eth():
    """eCPRI frame (EtherType 0xAEFE)."""
    return gen_ecpri()


# ── Main ──

def main():
    global OUTPUT_DIR
    parser = argparse.ArgumentParser(description="Generate Bronze PCAP templates")
    parser.add_argument("--output-dir", default=OUTPUT_DIR,
                        help="Directory to write .pcap files")
    args = parser.parse_args()
    OUTPUT_DIR = args.output_dir
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    count = 0
    def emit(name, link_type, packet):
        nonlocal count
        write_pcap(name, link_type, packet)
        count += 1

    print("Generating Bronze protocol PCAP templates...", file=sys.stderr)

    # ── UDP protocols ──
    emit('radius_acct', 1, eth_ipv4_udp(1813, gen_radius_acct()))
    emit('radius_coa', 1, eth_ipv4_udp(3799, gen_radius_coa()))
    emit('snmpv3', 1, eth_ipv4_udp(161, gen_snmpv3()))
    emit('collectd', 1, eth_ipv4_udp(25826, gen_collectd()))
    emit('megaco', 1, eth_ipv4_udp(2944, gen_megaco()))
    emit('cflow', 1, eth_ipv4_udp(2055, gen_cflow()))
    emit('sflow_v5', 1, eth_ipv4_udp(6343, gen_sflow_v5()))
    emit('amt', 1, eth_ipv4_udp(2268, gen_amt()))
    emit('ayiya', 1, eth_ipv4_udp(5072, gen_ayiya()))
    emit('babel', 1, eth_ipv4_udp(6696, gen_babel()))
    emit('some_ip', 1, eth_ipv4_udp(30490, gen_some_ip()))
    emit('t38', 1, eth_ipv4_udp(4000, gen_t38()))
    emit('vxlan_gpb', 1, eth_ipv4_udp(4789, gen_vxlan_gpb()))

    # ── TCP protocols ──
    emit('bmp', 1, eth_ipv4_tcp(11019, gen_bmp()))
    emit('pcep', 1, eth_ipv4_tcp(4189, gen_pcep()))
    emit('cops', 1, eth_ipv4_tcp(3288, gen_cops()))
    emit('rpki_rtr', 1, eth_ipv4_tcp(323, gen_rpki_rtr()))
    emit('mongodb', 1, eth_ipv4_tcp(27017, gen_mongodb()))
    emit('mysql', 1, eth_ipv4_tcp(3306, gen_mysql(), sport=3306, ack=1, flags=0x18))
    emit('postgresql', 1, eth_ipv4_tcp(5432, gen_postgresql(), sport=5432, ack=1, flags=0x18))
    emit('cassandra', 1, eth_ipv4_tcp(9042, gen_cassandra()))
    emit('pop3', 1, eth_ipv4_tcp(110, gen_pop3(), sport=110, ack=1, flags=0x18))
    emit('nntp', 1, eth_ipv4_tcp(119, gen_nntp(), sport=119, ack=1, flags=0x18))
    emit('xmpp', 1, eth_ipv4_tcp(5222, gen_xmpp()))
    emit('rtmp', 1, eth_ipv4_tcp(1935, gen_rtmp()))
    emit('cmp', 1, eth_ipv4_tcp(829, gen_cmp()))
    emit('s7comm', 1, eth_ipv4_tcp(102, gen_s7comm()))
    emit('iec_104', 1, eth_ipv4_tcp(2404, gen_iec_104()))

    # ── SCTP protocols ──
    emit('s1ap', 1, eth_ipv4_sctp(36412, sctp_data_chunk(gen_s1ap(), ppid=18)))
    emit('ngap', 1, eth_ipv4_sctp(38412, sctp_data_chunk(gen_ngap(), ppid=60)))
    emit('sua', 1, eth_ipv4_sctp(14001, sctp_data_chunk(gen_sua(), ppid=4)))

    # ── IPv4/IPv6 protocol-level ──
    # PGM (IP proto 113)
    pgm_payload = gen_pgm()
    ip_hdr = ipv4(proto=113, payload_len=len(pgm_payload))
    emit('pgm', 1, ethernet(etype=0x0800) + ip_hdr + pgm_payload)

    # VRRP_IPv6 (IPv6 next_header 112)
    vrrp_payload = gen_vrrp()
    ip6_hdr = ipv6(next_header=112, payload_len=len(vrrp_payload))
    emit('vrrp_ipv6', 1, ethernet(etype=0x86DD) + ip6_hdr + vrrp_payload)

    # L2TPv3 (IP proto 115)
    l2tp_payload = gen_l2tpv3()
    ip_hdr = ipv4(proto=115, payload_len=len(l2tp_payload))
    emit('l2tpv3', 1, ethernet(etype=0x0800) + ip_hdr + l2tp_payload)

    # ESP_NULL (IP proto 50)
    esp_payload = gen_esp_null()
    ip_hdr = ipv4(proto=50, payload_len=len(esp_payload))
    emit('esp_null', 1, ethernet(etype=0x0800) + ip_hdr + esp_payload)

    # GRE_WCCPv2 (GRE proto 0x883E)
    gre_payload = gen_gre_wccpv2()
    ip_hdr = ipv4(proto=47, payload_len=len(gre_payload))
    emit('gre_wccpv2', 1, ethernet(etype=0x0800) + ip_hdr + gre_payload)

    # ── Ethernet-direct ──
    # MRP (EtherType 0x88E3)
    emit('mrp', 1, ethernet(dst=b'\x01\x15\x4E\x00\x00\x01', etype=0x88E3) + gen_mrp())

    # eCPRI (EtherType 0xAEFE)
    emit('ecpri', 1, ethernet(etype=0xAEFE) + gen_ecpri_eth())

    # PROFINET_DCP (EtherType 0x8892)
    emit('profinet_dcp', 1,
         ethernet(dst=b'\x01\x0E\xCF\x00\x00\x00', etype=0x8892) + gen_profinet_dcp())

    # PTP_V1 (EtherType 0x88F7)
    emit('ptp_v1', 1, ethernet(dst=b'\x01\x1B\x19\x00\x00\x00', etype=0x88F7) + gen_ptp_v1())

    # EDSA (EtherType 0xDADA)
    emit('edsa', 1, ethernet(etype=0xDADA) + gen_edsa())

    # EtherType_TSN (0xF1C1)
    emit('ethertype_tsn', 1, ethernet(etype=0xF1C1) + gen_ethertype_tsn())

    # FCoE_Init (EtherType 0x8906)
    emit('fcoe_init', 1, ethernet(dst=b'\x01\x10\x18\x01\x00\x01', etype=0x8906) + gen_fcoe_init())

    # MARKER (Slow Protocols, EtherType 0x8809)
    emit('marker', 1, ethernet(dst=b'\x01\x80\xC2\x00\x00\x02', etype=0x8809) + gen_marker())

    # MPLS_TP (EtherType 0x8847)
    emit('mpls_tp', 1, ethernet(etype=0x8847) + gen_mpls_tp())

    # MMRP (EtherType 0x88F6) -- minimal MRP PDU
    emit('mmrp', 1, ethernet(dst=b'\x01\x80\xC2\x00\x00\x20', etype=0x88F6) + b'\x00' * 8)

    # LISP_Control (UDP 4342)
    emit('lisp_control', 1, eth_ipv4_udp(4342, gen_lisp_control()))

    # MGCP_NCS (UDP 2727)
    emit('mgcp_ncs', 1, eth_ipv4_udp(2727, b'RQNT 1 aaln/1@example.com MGCP 1.0\r\n\r\n'))

    # DoT (TCP 853) - DNS over TLS, start with TLS ClientHello
    # Just use a DNS query payload for now
    dns_query = struct.pack('>HHHHHH', 0x1234, 0x0100, 1, 0, 0, 0)
    dns_query += b'\x07example\x03com\x00\x00\x01\x00\x01'
    emit('dot', 1, eth_ipv4_tcp(853, dns_query))

    print(f"\nGenerated {count} PCAP templates", file=sys.stderr)


if __name__ == '__main__':
    main()
