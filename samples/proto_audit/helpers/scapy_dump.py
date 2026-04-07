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
        'scapy.contrib.gtp',
        'scapy.contrib.homeplugav',
        'scapy.contrib.http2',
        'scapy.layers.bluetooth',
        'scapy.layers.eap',
        'scapy.layers.quic',
        'scapy.layers.tls',
        'scapy.layers.tls.record',
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


def discover_all():
    """Discover ALL Scapy Packet subclasses by importing all contrib modules.

    Outputs a JSON mapping of class_name → module_path for every Packet
    subclass that has fields_desc defined.
    """
    import importlib
    import pkgutil
    import scapy.all  # noqa: F401
    import scapy.contrib
    import scapy.layers
    from scapy.packet import Packet

    # Walk and import all scapy.contrib.* and scapy.layers.* modules
    for pkg in [scapy.contrib, scapy.layers]:
        for _, modname, _ in pkgutil.walk_packages(
            pkg.__path__, prefix=pkg.__name__ + '.'
        ):
            try:
                importlib.import_module(modname)
            except Exception:
                pass

    # Enumerate all Packet subclasses recursively
    def all_subclasses(cls):
        result = set()
        for sub in cls.__subclasses__():
            result.add(sub)
            result.update(all_subclasses(sub))
        return result

    registry = {}
    for cls in all_subclasses(Packet):
        if hasattr(cls, 'fields_desc') and cls.fields_desc:
            registry[cls.__name__] = cls.__module__

    print(json.dumps(registry, indent=2))
    print(f"Discovered {len(registry)} Packet subclasses", file=sys.stderr)


def discover_all_rich():
    """Discover ALL Scapy Packet subclasses with enriched metadata.

    Outputs a JSON object per class with: module, field_names, bind_layers,
    docstring, and field_count. Used by auto-matcher for cross-source matching.
    """
    import importlib
    import pkgutil
    import scapy.all  # noqa: F401
    import scapy.contrib
    import scapy.layers
    from scapy.packet import Packet

    for pkg in [scapy.contrib, scapy.layers]:
        for _, modname, _ in pkgutil.walk_packages(
            pkg.__path__, prefix=pkg.__name__ + '.'
        ):
            try:
                importlib.import_module(modname)
            except Exception:
                pass

    def all_subclasses(cls):
        result = set()
        for sub in cls.__subclasses__():
            result.add(sub)
            result.update(all_subclasses(sub))
        return result

    # Collect bind_layers relationships
    from scapy.packet import bind_layers as _bl
    bind_map = {}  # class_name → [(parent_class, field_bindings)]
    try:
        from scapy.packet import _all_bindings
        # _all_bindings is a list of (cls1, cls2, fval_dict) tuples
        for b in _all_bindings:
            if len(b) >= 3:
                parent_name = b[0].__name__ if hasattr(b[0], '__name__') else str(b[0])
                child_name = b[1].__name__ if hasattr(b[1], '__name__') else str(b[1])
                bindings = {str(k): str(v) for k, v in b[2].items()} if b[2] else {}
                bind_map.setdefault(child_name, []).append({
                    'parent': parent_name,
                    'bindings': bindings,
                })
    except (ImportError, AttributeError):
        pass

    registry = {}
    for cls in all_subclasses(Packet):
        if not hasattr(cls, 'fields_desc') or not cls.fields_desc:
            continue

        field_names = []
        for f in cls.fields_desc:
            inner = unwrap_field(f)
            field_names.append(f.name)

        docstring = None
        if cls.__doc__:
            # First non-empty line of the docstring
            for line in cls.__doc__.split('\n'):
                line = line.strip()
                if line:
                    docstring = line
                    break

        entry = {
            'module': cls.__module__,
            'field_names': field_names,
            'field_count': len(field_names),
        }
        if docstring:
            entry['docstring'] = docstring
        if cls.__name__ in bind_map:
            entry['bind_layers'] = bind_map[cls.__name__]

        registry[cls.__name__] = entry

    print(json.dumps(registry, indent=2))
    print(f"Discovered {len(registry)} Packet subclasses (rich)", file=sys.stderr)


def safe_default(val):
    """Safely convert a Scapy field default to a string."""
    if val is None:
        return None
    try:
        return str(val)
    except Exception:
        return repr(val)


def dump_all():
    """Dump ALL protocols' fields in one subprocess call.

    Outputs a JSON array of protocol objects (same format as dump_protocol).
    For batch extraction to avoid per-protocol subprocess overhead.
    """
    import importlib
    import pkgutil
    import scapy.all  # noqa: F401
    import scapy.contrib
    import scapy.layers
    from scapy.packet import Packet

    # Import everything
    for pkg in [scapy.contrib, scapy.layers]:
        for _, modname, _ in pkgutil.walk_packages(
            pkg.__path__, prefix=pkg.__name__ + '.'
        ):
            try:
                importlib.import_module(modname)
            except Exception:
                pass

    def all_subclasses(cls):
        result = set()
        for sub in cls.__subclasses__():
            result.add(sub)
            result.update(all_subclasses(sub))
        return result

    results = []
    for cls in sorted(all_subclasses(Packet), key=lambda c: c.__name__):
        if not hasattr(cls, 'fields_desc') or not cls.fields_desc:
            continue
        fields = []
        total_bits = 0
        for f in cls.fields_desc:
            inner = unwrap_field(f)
            bits = field_size_bits(inner)
            fields.append({
                "name": f.name,
                "field_class": type(inner).__name__,
                "size_bits": bits,
                "default": safe_default(f.default),
            })
            total_bits += bits
        results.append({
            "name": cls.__name__,
            "module": cls.__module__,
            "min_bytes": (total_bits + 7) // 8,
            "fields": fields,
        })

    print(json.dumps(results, indent=2))
    print(f"Dumped {len(results)} protocols", file=sys.stderr)


def dissect_pcap(pcap_path):
    """Read a PCAP file, dissect with Scapy, output per-layer field values as JSON."""
    import scapy.all as sa  # noqa: F401
    # Also import contrib modules
    for contrib in [
        'scapy.contrib.igmp', 'scapy.contrib.igmpv3', 'scapy.contrib.geneve',
        'scapy.contrib.lldp', 'scapy.contrib.erspan', 'scapy.contrib.nsh',
        'scapy.contrib.ospf', 'scapy.contrib.bgp', 'scapy.contrib.ethercat',
    ]:
        try:
            __import__(contrib)
        except Exception:
            pass

    packets = sa.rdpcap(pcap_path)
    results = []
    for i, pkt in enumerate(packets):
        pkt_layers = []
        layer = pkt
        while layer:
            layer_name = type(layer).__name__
            fields = {}
            for f in layer.fields_desc:
                try:
                    val = layer.getfieldval(f.name)
                    if isinstance(val, bytes):
                        fields[f.name] = val.hex()
                    elif isinstance(val, (int, float, str, bool)):
                        fields[f.name] = val
                    else:
                        fields[f.name] = str(val)
                except Exception:
                    pass
            pkt_layers.append({
                "layer": layer_name,
                "fields": fields,
            })
            layer = layer.payload if layer.payload and not isinstance(layer.payload, sa.NoPayload) else None
        results.append({
            "packet": i,
            "layers": pkt_layers,
        })
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <ProtocolName>", file=sys.stderr)
        print(f"       {sys.argv[0]} --list", file=sys.stderr)
        print(f"       {sys.argv[0]} --discover-all", file=sys.stderr)
        print(f"       {sys.argv[0]} --dump-all", file=sys.stderr)
        print(f"       {sys.argv[0]} --dissect-pcap <file.pcap>", file=sys.stderr)
        print(f"       {sys.argv[0]} --extra <file.py> <ClassName>", file=sys.stderr)
        sys.exit(1)

    arg = sys.argv[1]
    if arg == "--list":
        list_protocols()
    elif arg == "--discover-all":
        discover_all()
    elif arg == "--discover-all-rich":
        discover_all_rich()
    elif arg == "--dump-all":
        dump_all()
    elif arg == "--dissect-pcap" and len(sys.argv) >= 3:
        dissect_pcap(sys.argv[2])
    elif arg == "--extra" and len(sys.argv) >= 4:
        # Load extra Python file, then dump the named class
        import importlib.util
        extra_path = sys.argv[2]
        class_name = sys.argv[3]
        spec = importlib.util.spec_from_file_location("extra_module", extra_path)
        mod = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(mod)
        except Exception as e:
            print(f"Error loading {extra_path}: {e}", file=sys.stderr)
            sys.exit(1)
        # The class should now be registered in Scapy's class registry
        dump_protocol(class_name)
    else:
        dump_protocol(arg)
