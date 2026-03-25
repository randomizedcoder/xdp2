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
    from scapy.packet import Packet

    # Search all subclasses
    for cls in Packet.__subclasses__():
        if cls.__name__ == name:
            return cls
    # Also search deeper (some are nested)
    for cls in Packet.__subclasses__():
        for sub in cls.__subclasses__():
            if sub.__name__ == name:
                return sub
    return None


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


def dump_protocol(name):
    """Dump a single protocol's fields as JSON."""
    cls = get_packet_class(name)
    if cls is None:
        print(json.dumps({"error": f"Unknown protocol: {name}"}), file=sys.stderr)
        sys.exit(1)

    fields = []
    total_bits = 0
    for f in cls.fields_desc:
        bits = field_size_bits(f)
        fields.append({
            "name": f.name,
            "field_class": type(f).__name__,
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
