#!/usr/bin/env python3
"""Dump Scapy protocol fields_desc as JSON for proto-audit.

Usage:
    python3 scapy_dump.py IP
    python3 scapy_dump.py TCP
    python3 scapy_dump.py --list        # list all known Packet classes

Output is a JSON object with: name, module, min_bytes, fields[].
Each field has: name, field_class, size_bits, default.
"""

import json
import sys


def get_packet_class(name):
    """Import and return the Scapy Packet class by name."""
    # Import scapy layers to register all packet classes
    import scapy.all  # noqa: F401
    # Contrib modules must be explicitly imported to register their packet classes
    for contrib in [
        'scapy.contrib.igmp',
        'scapy.contrib.igmpv3',
        'scapy.contrib.geneve',
        'scapy.contrib.macsec',
        'scapy.contrib.lldp',
        'scapy.contrib.erspan',
        'scapy.contrib.nsh',
        'scapy.contrib.hsr',
        'scapy.contrib.dot15d4',
        'scapy.contrib.cdp',
        'scapy.contrib.ospf',
        'scapy.contrib.isis',
        'scapy.contrib.bgp',
        'scapy.contrib.eigrp',
        'scapy.contrib.nfs',
        'scapy.contrib.mctp',
        'scapy.contrib.tipc',
        'scapy.contrib.phonet',
        'scapy.contrib.fcoe',
        'scapy.contrib.canxl',
        'scapy.contrib.infiniband',
        'scapy.contrib.ptp_v2',
        'scapy.contrib.aoe',
        'scapy.contrib.ethercat',
        'scapy.contrib.slowprot',
        'scapy.contrib.pnio',
        'scapy.contrib.mac_control',
        'scapy.contrib.oncrpc',
        'scapy.contrib.pbb',
        'scapy.contrib.trill',
        'scapy.contrib.mpeg_ts',
        'scapy.contrib.srt',
        'scapy.contrib.dsa',
        'scapy.contrib.batman',
        'scapy.contrib.cfm',
        'scapy.contrib.ncsi',
        'scapy.contrib.fip',
        'scapy.contrib.mvrp',
        'scapy.contrib.netlink_proto',
        'scapy.contrib.ipx',
        'scapy.contrib.appletalk',
        'scapy.contrib.x25',
        'scapy.contrib.atm',
        'scapy.contrib.iscsi',
        'scapy.contrib.nvme',
        'scapy.contrib.scsi',
        'scapy.contrib.iser',
        'scapy.contrib.wireguard',
        'scapy.contrib.lisp',
        'scapy.contrib.coap',
        'scapy.contrib.mqtt',
        'scapy.contrib.modbus',
        'scapy.contrib.scada.dnp3',
        'scapy.contrib.iec61850',
        'scapy.contrib.zigbee',
        'scapy.contrib.netflow',
        'scapy.contrib.bfd',
        'scapy.contrib.skinny',
        'scapy.contrib.bacnet',
        'scapy.contrib.enip',
        'scapy.contrib.cip',
        'scapy.contrib.diameter',
        'scapy.contrib.ldp',
        'scapy.contrib.rsvp',
        'scapy.contrib.openflow3',
        'scapy.contrib.pptp',
        'scapy.contrib.capwap',
        'scapy.contrib.lwapp',
        'scapy.contrib.dccp',
        'scapy.layers.bluetooth',
        'scapy.layers.eap',
        'scapy.layers.quic',
        'scapy.layers.tls',
        'scapy.layers.ipsec',
        'scapy.layers.radius',
        'scapy.layers.tftp',
        'scapy.layers.http',
    ]:
        try:
            __import__(contrib)
        except ImportError:
            pass
    from scapy.packet import Packet

    # Recursive search through all subclasses
    def search(cls):
        for sub in cls.__subclasses__():
            if sub.__name__ == name:
                return sub
            found = search(sub)
            if found is not None:
                return found
        return None

    return search(Packet)


def field_size_bits(field):
    """Extract the size in bits from a Scapy field."""
    cls_name = type(field).__name__

    # BitField family: size is in bits directly
    if hasattr(field, 'size') and 'Bit' in cls_name:
        return field.size

    if hasattr(field, 'sz'):
        return field.sz * 8

    # FlagsField stores size differently
    if cls_name == 'FlagsField':
        if hasattr(field, 'size'):
            return field.size
        return 8

    # Fallback: try fmt for struct-based fields
    if hasattr(field, 'fmt'):
        import struct
        try:
            return struct.calcsize(field.fmt) * 8
        except (struct.error, TypeError):
            pass

    return 0


def unwrap_field(field):
    """Unwrap decorator fields (Emph, ConditionalField, etc.) to get the real field."""
    # Emph wraps a field for display emphasis; .fld is the inner field
    # ConditionalField wraps a field with a condition; .fld is the inner field
    while hasattr(field, 'fld') and type(field).__name__ in ('Emph', 'ConditionalField'):
        field = field.fld
    return field


def dump_protocol(name):
    """Dump a single protocol's fields as JSON."""
    cls = get_packet_class(name)
    if cls is None:
        print(json.dumps({"error": f"Unknown protocol: {name}"}), file=sys.stderr)
        sys.exit(1)

    fields = []
    total_bits = 0
    for f in cls.fields_desc:
        inner = unwrap_field(f)
        bits = field_size_bits(inner)
        fields.append({
            "name": f.name,
            "field_class": type(inner).__name__,
            "size_bits": bits,
            "default": str(f.default) if f.default is not None else None,
        })
        total_bits += bits

    result = {
        "name": cls.__name__,
        "module": cls.__module__,
        "min_bytes": (total_bits + 7) // 8,
        "fields": fields,
    }
    print(json.dumps(result, indent=2))


def list_protocols():
    """List all known Scapy Packet subclasses."""
    import scapy.all  # noqa: F401
    from scapy.packet import Packet

    names = sorted(set(
        cls.__name__
        for cls in Packet.__subclasses__()
        if hasattr(cls, 'fields_desc') and cls.fields_desc
    ))
    print(json.dumps(names, indent=2))


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <ProtocolName>", file=sys.stderr)
        print(f"       {sys.argv[0]} --list", file=sys.stderr)
        sys.exit(1)

    arg = sys.argv[1]
    if arg == "--list":
        list_protocols()
    else:
        dump_protocol(arg)
