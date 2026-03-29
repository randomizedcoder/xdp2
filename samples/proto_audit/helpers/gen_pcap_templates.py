#!/usr/bin/env python3
"""Generate PCAP template files for protocols that can't be auto-routed.

These are protocols that need special setup (TLS handshake, HTTP/2 preface,
etc.) or run on ports already claimed by other protocols.

Usage:
    python3 gen_pcap_templates.py --output-dir pcap_templates/
"""

import argparse
import struct
import sys


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


def ethernet(dst=b'\x00' * 6, src=b'\x00' * 6, etype=0x0800):
    return dst + src + struct.pack('>H', etype)


def ipv4(proto=6, payload_len=0):
    """Minimal IPv4 header (20 bytes)."""
    total_len = 20 + payload_len
    hdr = struct.pack('>BBHHHBBH4s4s',
        0x45, 0,           # version/ihl, dscp
        total_len,         # total length
        0x1234, 0x4000,    # id, flags+offset
        64, proto,         # ttl, protocol
        0,                 # checksum (0 = let tshark recalc)
        b'\xc0\xa8\x01\x01',  # src
        b'\xc0\xa8\x01\x02',  # dst
    )
    return hdr


def tcp(sport=12345, dport=443, payload=b''):
    """Minimal TCP header (20 bytes) + payload."""
    data_offset = 5 << 4  # 20 bytes, no options
    hdr = struct.pack('>HHIIBBHHH',
        sport, dport,
        1000, 0,          # seq, ack
        data_offset, 0x18, # offset+flags (PSH+ACK)
        65535,            # window
        0, 0,             # checksum, urgptr
    )
    return hdr + payload


def gen_tls_client_hello():
    """TLS 1.2 ClientHello (minimal, enough for tshark to dissect as TLS)."""
    # TLS record: ContentType=Handshake(22), Version=TLS1.0(0x0301)
    # Handshake: ClientHello(1)
    hello_body = (
        b'\x03\x03'             # client_version = TLS 1.2
        + b'\x00' * 32          # random (32 bytes)
        + b'\x00'               # session_id length = 0
        + b'\x00\x02\x00\xff'   # cipher_suites: 1 suite (TLS_EMPTY_RENEGOTIATION_INFO_SCSV)
        + b'\x01\x00'           # compression_methods: null
    )
    handshake = b'\x01' + struct.pack('>I', len(hello_body))[1:] + hello_body
    record = struct.pack('>BHH', 22, 0x0301, len(handshake)) + handshake
    return record


def gen_http2_preface():
    """HTTP/2 connection preface + SETTINGS frame."""
    preface = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'
    # SETTINGS frame: 3-byte length (0) + 1-byte type (4) + 1-byte flags (0) + 4-byte stream_id (0)
    settings = struct.pack('>BBBBB', 0, 0, 0, 4, 0) + struct.pack('>I', 0)
    return preface + settings


def write_pcap(path, link_type, packet):
    """Write a single-packet PCAP file."""
    with open(path, 'wb') as f:
        f.write(pcap_global_header(link_type))
        f.write(pcap_record(packet))
    print(f"  Wrote {path} ({len(packet)} bytes)", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description='Generate PCAP templates')
    parser.add_argument('--output-dir', required=True, help='Output directory')
    args = parser.parse_args()

    import os
    os.makedirs(args.output_dir, exist_ok=True)

    # TLS: Ethernet → IPv4 → TCP:443 → TLS ClientHello
    tls_payload = gen_tls_client_hello()
    tcp_seg = tcp(dport=443, payload=tls_payload)
    ip_hdr = ipv4(proto=6, payload_len=len(tcp_seg))
    tls_packet = ethernet(etype=0x0800) + ip_hdr + tcp_seg
    write_pcap(os.path.join(args.output_dir, 'tls.pcap'), 1, tls_packet)

    # HTTP/2: Ethernet → IPv4 → TCP:8080 → HTTP/2 preface
    h2_payload = gen_http2_preface()
    tcp_seg = tcp(dport=8080, payload=h2_payload)
    ip_hdr = ipv4(proto=6, payload_len=len(tcp_seg))
    h2_packet = ethernet(etype=0x0800) + ip_hdr + tcp_seg
    write_pcap(os.path.join(args.output_dir, 'http2.pcap'), 1, h2_packet)

    print(f"Generated templates in {args.output_dir}", file=sys.stderr)


if __name__ == '__main__':
    main()
