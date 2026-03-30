#!/usr/bin/env python3
"""Generate auto_mappings.json with bulk protocol entries.

This script produces a comprehensive set of protocol mappings
from well-known tshark dissector names, Scapy classes, and
common network protocols. Used to bootstrap the auto_mappings
database without requiring live registry access.

Output: data/auto_mappings.json
"""

import json
import os
import sys

# Existing curated protocols (from table.rs) — skip these
CURATED = {
    "AH", "AMQP", "AoE", "AppleTalk", "ARP", "ATM", "BACnet", "BATMAN",
    "BFD", "BGP", "BT_ATT", "BT_AVDTP", "BT_BNEP", "BT_RFCOMM", "BT_SDP",
    "BT_SMP", "CAN", "CAN_FD", "CAN_XL", "CAPWAP", "CARP", "CDP", "CFM",
    "CIP", "CoAP", "DCCP", "DHCP", "DHCPv6", "Diameter", "DNP3", "DNS",
    "DSA", "DTLS", "EAP", "EAPOL", "EDSA", "EIGRP", "ENIP", "ERF",
    "ERSPAN", "ESP", "EtherCAT", "Ethernet", "FC", "FCoE", "FIP", "FTP",
    "Geneve", "GenNetlink", "GLBP", "GRE", "GRE_PPTP", "GTP_C", "GTP_U",
    "GUE", "HCI", "HCI_ACL", "HCI_CMD", "HCI_Event", "HCI_ISO", "HCI_SCO",
    "HomePlug_AV", "HSR", "HSRP", "HTTP", "HTTP2", "IB_AETH", "IB_AtomicETH",
    "IB_BTH", "IB_DETH", "IB_GRH", "IB_ImmDt", "IB_LRH", "IB_MAD",
    "IB_RDETH", "IB_RETH", "ICMPv4", "ICMPv6", "IEC_GOOSE", "IEC_MMS",
    "IEC_SV", "IEEE802.11", "IEEE802154", "IGMP", "IGMPv3_Query",
    "IGMPv3_Report", "IKEv2", "IMAP", "IPFIX", "IP_in_IP", "IPv4", "IPv6",
    "IPv6_DestOpts", "IPv6_EH", "IPv6_Fragment", "IPv6_ND", "IPv6_Routing",
    "IPX", "iSCSI", "iSER", "ISIS", "Kafka", "Kerberos", "L2CAP", "L2TP",
    "LACP", "LDAP", "LDP", "LISP", "LLC", "LLDP", "LLMNR", "LLTD", "LWAPP",
    "MAC_Control", "MACsec", "MCTP", "mDNS", "Memcache", "MGCP", "MLD",
    "MLDv2_Query", "MLDv2_Report", "MODBUS_TCP", "MPEG_TS", "MPLS",
    "MPLS_OAM", "MQTT", "MVRP", "NBNS", "NC_SI", "NetFlow_v5", "NetFlow_v9",
    "Netlink", "NFS", "NLAttr", "NSH", "NTLMSSP", "NTP", "NVGRE", "NVMe",
    "OCSP", "ONC_RPC", "OPC_UA", "OpenFlow", "OSPF", "PBB", "Phonet", "PIM",
    "PPP", "PPPoE", "PPPoED", "PROFINET", "PTP", "QinQ", "QUIC", "RADIUS",
    "RARP", "Redis", "RIP", "RSVP", "RTCP", "RTP", "RTSP", "SCSI", "SCTP",
    "SCTP_Chunk", "SIP", "Skinny", "SLL", "SLL2", "Slow_Protocols", "SMB",
    "SMB2", "SMTP", "SNAP", "SNMP", "SRT", "SRv6", "SSH", "STP", "STT",
    "STUN", "Syslog", "TACACS", "TCP", "Telnet", "Teredo", "TFTP", "TIPC",
    "TLS", "TPLINK_SMARTHOME", "TRILL", "TZSP", "UDP", "UDPLite", "VLAN",
    "VRRP", "VXLAN", "VXLAN_GPE", "WireGuard", "WOL", "X25", "ZeroMQ",
    "Zigbee_APS", "Zigbee_NWK",
}


def proto(canonical, tshark=None, scapy=None, kernel_struct=None,
          kernel_header=None, min_hdr=0, variable=False, confidence=0.9,
          method="exact_normalized"):
    """Build a protocol entry dict."""
    entry = {"canonical": canonical}
    if tshark:
        entry["tshark"] = tshark
    if scapy:
        entry["scapy"] = scapy
    if kernel_struct:
        entry["kernel_struct"] = kernel_struct
    if kernel_header:
        entry["kernel_header"] = kernel_header
    entry["min_header_bytes"] = min_hdr
    if variable:
        entry["variable"] = True
    entry["confidence"] = confidence
    entry["match_method"] = method
    return entry


# ═══════════════════════════════════════════════════════════════
# Protocol definitions by category
# ═══════════════════════════════════════════════════════════════

PROTOCOLS = []

# ── Automotive ──
PROTOCOLS += [
    proto("SOME/IP", "someip", "SOMEIP", min_hdr=16, confidence=0.95),
    proto("SOME/IP-SD", "someipsd", "SD", min_hdr=12),
    proto("DoIP", "doip", "DoIP", min_hdr=8, confidence=0.95),
    proto("AVB/AVTP", "avtp", "AVTP", min_hdr=12),
    proto("TSN", "ieee8021cb", min_hdr=6, confidence=0.8, method="decode_table"),
    proto("J1939", "j1939", min_hdr=8),
    proto("LIN", "lin", min_hdr=2),
    proto("FlexRay", "flexray", min_hdr=5),
    proto("UDS", "uds", min_hdr=2, variable=True),
    proto("XCP", "xcp", min_hdr=4, variable=True, confidence=0.85),
    proto("OBD-II", "obd-ii", min_hdr=2, variable=True, confidence=0.8),
    proto("AUTOSAR E2E", "autosar", min_hdr=4, variable=True, confidence=0.7, method="long_name"),
]

# ── Industrial / SCADA ──
PROTOCOLS += [
    proto("S7comm", "s7comm", min_hdr=10, variable=True),
    proto("S7comm Plus", "s7comm-plus", min_hdr=4, variable=True, confidence=0.85),
    proto("OMRON FINS", "omron", min_hdr=12, confidence=0.85),
    proto("KNXnet/IP", "knxnetip", "KNXnetIP", min_hdr=6),
    proto("HART-IP", "hartip", min_hdr=8, confidence=0.85),
    proto("OPC HDA", "opchda", min_hdr=8, variable=True, confidence=0.8),
    proto("EtherCAT Mailbox", "ecat_mailbox", min_hdr=6, variable=True, confidence=0.85),
    proto("SERCOS III", "sercosiii", min_hdr=6, confidence=0.85),
    proto("CC-Link IE", "cclink", min_hdr=8, confidence=0.85),
    proto("PowerLink", "epl", min_hdr=4, variable=True, confidence=0.85),
    proto("DeviceNet", "devicenet", min_hdr=4, confidence=0.85),
    proto("ControlNet", "controlnet", min_hdr=8, confidence=0.85),
    proto("CANopen", "canopen", min_hdr=1, variable=True),
    proto("PROFINET DCP", "pn_dcp", min_hdr=4, variable=True, confidence=0.85),
    proto("PROFINET MRP", "pn_mrp", min_hdr=4, variable=True, confidence=0.85),
    proto("PROFINET PTCP", "pn_ptcp", min_hdr=12, confidence=0.85),
    proto("IEC 60870-5-104", "iec60870_104", min_hdr=6, variable=True, confidence=0.85),
    proto("IEC 60870-5-101", "iec60870_101", min_hdr=4, variable=True, confidence=0.85),
    proto("IEC 61850 GOOSE", "goose", "GOOSE", min_hdr=8, variable=True, confidence=0.85, method="decode_table"),
    proto("IEC 61850 SV", "sv", "SV", min_hdr=8, variable=True, confidence=0.85, method="decode_table"),
    proto("IEC 61850 MMS", "mms", min_hdr=4, variable=True, confidence=0.8),
    proto("TASE.2 / ICCP", "tase2", min_hdr=4, variable=True, confidence=0.7, method="long_name"),
    proto("Foundation Fieldbus HSE", "ff-hse", min_hdr=8, variable=True, confidence=0.7, method="long_name"),
    proto("Modbus RTU", "mbrtu", min_hdr=4, confidence=0.85),
    proto("Modbus ASCII", "mbascii", min_hdr=4, variable=True, confidence=0.8),
    proto("FINS TCP", "omron-fins-tcp", min_hdr=16, variable=True, confidence=0.8),
    proto("GE SRTP", "ge_srtp", min_hdr=8, variable=True, confidence=0.8),
    proto("MiCOM P14x", "micom", min_hdr=4, variable=True, confidence=0.7, method="long_name"),
]

# ── IoT / Smart Home ──
PROTOCOLS += [
    proto("Z-Wave", "zwave", min_hdr=10),
    proto("Thread", "thread", min_hdr=2, variable=True, confidence=0.85),
    proto("Matter", "matter", min_hdr=4, variable=True, confidence=0.85),
    proto("LoRaWAN", "lorawan", "LoRa", min_hdr=7, variable=True, confidence=0.85),
    proto("BLE", "btle", "BTLE", min_hdr=2, variable=True),
    proto("ZigBee ZCL", "zbee_zcl", "ZigbeeClusterLibrary", min_hdr=3, variable=True, confidence=0.85),
    proto("ZigBee ZDP", "zbee_zdp", min_hdr=2, variable=True, confidence=0.85),
    proto("ZigBee GP", "zbee_gp", min_hdr=1, variable=True, confidence=0.85),
    proto("EnOcean", "enocean", min_hdr=6, variable=True, confidence=0.85),
    proto("KNX", "knx", min_hdr=6, variable=True, confidence=0.85),
    proto("Insteon", "insteon", min_hdr=7, confidence=0.8),
    proto("ANT", "ant", min_hdr=5, variable=True, confidence=0.8),
    proto("DALI", "dali", min_hdr=2, confidence=0.8),
    proto("HomePlug GP", "homeplug_gp", min_hdr=4, variable=True, confidence=0.8),
    proto("Wi-SUN", "wisun", min_hdr=4, variable=True, confidence=0.8),
    proto("6LoWPAN", "6lowpan", "SixLoWPAN", min_hdr=1, variable=True, confidence=0.85),
    proto("6LoWPAN IPHC", "6lowpan.iphc", min_hdr=2, variable=True, confidence=0.8, method="decode_table"),
    proto("RPL", "rpl", min_hdr=4, variable=True, confidence=0.85),
    proto("CoAP Block", "coap.block", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("LwM2M", "lwm2m", min_hdr=1, variable=True, confidence=0.8),
    proto("CBOR", "cbor", min_hdr=1, variable=True, confidence=0.85),
    proto("COSE", "cose", min_hdr=1, variable=True, confidence=0.8),
]

# ── Telecom / Mobile ──
PROTOCOLS += [
    proto("GTP Prime", "gtp-prime", min_hdr=6, variable=True),
    proto("PFCP", "pfcp", "PFCP", min_hdr=8, variable=True, confidence=0.95),
    proto("LTE RRC", "lte-rrc", min_hdr=1, variable=True),
    proto("LTE NAS", "nas-eps", min_hdr=2, variable=True, confidence=0.85),
    proto("5G NR NAS", "nas-5gs", min_hdr=2, variable=True, confidence=0.85),
    proto("5G NR RRC", "nr-rrc", min_hdr=1, variable=True, confidence=0.85),
    proto("S1AP", "s1ap", min_hdr=4, variable=True, confidence=0.85),
    proto("NGAP", "ngap", min_hdr=4, variable=True, confidence=0.85),
    proto("X2AP", "x2ap", min_hdr=4, variable=True, confidence=0.85),
    proto("XnAP", "xnap", min_hdr=4, variable=True, confidence=0.85),
    proto("F1AP", "f1ap", min_hdr=4, variable=True, confidence=0.85),
    proto("E1AP", "e1ap", min_hdr=4, variable=True, confidence=0.85),
    proto("GTPv1-C", "gtpv1c", min_hdr=8, variable=True, confidence=0.85),
    proto("BSSGP", "bssgp", min_hdr=3, variable=True, confidence=0.85),
    proto("RANAP", "ranap", min_hdr=4, variable=True, confidence=0.85),
    proto("RNSAP", "rnsap", min_hdr=4, variable=True, confidence=0.8),
    proto("NBAP", "nbap", min_hdr=4, variable=True, confidence=0.8),
    proto("MAP", "gsm_map", min_hdr=2, variable=True, confidence=0.85),
    proto("CAP", "camel", min_hdr=2, variable=True, confidence=0.85),
    proto("TCAP", "tcap", min_hdr=2, variable=True, confidence=0.85),
    proto("SCCP", "sccp", min_hdr=3, variable=True, confidence=0.85),
    proto("M3UA", "m3ua", min_hdr=8, variable=True, confidence=0.9),
    proto("M2UA", "m2ua", min_hdr=8, variable=True, confidence=0.9),
    proto("M2PA", "m2pa", min_hdr=8, variable=True, confidence=0.9),
    proto("SUA", "sua", min_hdr=8, variable=True, confidence=0.85),
    proto("ISUP", "isup", min_hdr=3, variable=True, confidence=0.85),
    proto("BICC", "bicc", min_hdr=3, variable=True, confidence=0.85),
    proto("MTP3", "mtp3", min_hdr=4, confidence=0.9),
    proto("MTP2", "mtp2", min_hdr=3, confidence=0.9),
    proto("LAPD", "lapd", min_hdr=3, confidence=0.9),
    proto("V5DL", "v5dl", min_hdr=3, confidence=0.8),
    proto("GSM A-bis OML", "gsm_abis_oml", min_hdr=4, variable=True, confidence=0.8),
    proto("GSM A-bis RSL", "rsl", min_hdr=4, variable=True, confidence=0.8),
    proto("SMPP", "smpp", min_hdr=16, variable=True, confidence=0.85),
    proto("Diameter Gx", "diameter.3gpp", min_hdr=20, variable=True, confidence=0.7, method="long_name"),
    proto("GTP' CDR", "gtp-prime.cdr", min_hdr=4, variable=True, confidence=0.7, method="long_name"),
    proto("E.212", "e212", min_hdr=3, confidence=0.8),
    proto("E.164", "e164", min_hdr=1, variable=True, confidence=0.8),
]

# ── Data Center / Cloud ──
PROTOCOLS += [
    proto("RoCEv2", "infiniband", "BTH", min_hdr=12, confidence=0.85, method="decode_table"),
    proto("Ceph", "ceph", min_hdr=32, variable=True),
    proto("gRPC", "grpc", "GRPC", min_hdr=5, variable=True),
    proto("Protobuf", "protobuf", min_hdr=1, variable=True),
    proto("FabricPath", "fabricpath", min_hdr=16, confidence=0.85),
    proto("VXLAN-GBP", "vxlan", min_hdr=8, confidence=0.7, method="long_name"),
    proto("EVPN", "bgp.evpn", min_hdr=4, variable=True, confidence=0.8, method="decode_table"),
    proto("OVSDB", "ovsdb", min_hdr=1, variable=True, confidence=0.85),
    proto("OpenStack Neutron", "neutron", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("VRRP3", "vrrpv3", min_hdr=8, confidence=0.85),
    proto("MLAG", "mlag", min_hdr=8, variable=True, confidence=0.7, method="long_name"),
]

# ── SDN / Programmable Networks ──
PROTOCOLS += [
    proto("BIER", "bier", min_hdr=8, variable=True),
    proto("DetNet", "detnet", min_hdr=6, variable=True, confidence=0.85),
    proto("INT", "int", min_hdr=8, variable=True, confidence=0.85),
    proto("IOAM", "ioam", min_hdr=4, variable=True, confidence=0.85),
    proto("Segment Routing Header", "ipv6.routing.type.srh", min_hdr=8, variable=True, confidence=0.85, method="decode_table"),
    proto("MPLS Echo Request", "mpls_echo", min_hdr=4, variable=True, confidence=0.85),
    proto("PCEP", "pcep", min_hdr=4, variable=True),
    proto("LMP", "lmp", min_hdr=12, variable=True),
    proto("LISP Map", "lisp", min_hdr=4, variable=True, confidence=0.8, method="long_name"),
    proto("GENEVE Options", "geneve.options", min_hdr=4, variable=True, confidence=0.8, method="decode_table"),
    proto("NSH MD Type 2", "nsh.md.type2", min_hdr=4, variable=True, confidence=0.8, method="decode_table"),
    proto("P4Runtime", "p4runtime", min_hdr=5, variable=True, confidence=0.85),
    proto("gNMI", "gnmi", min_hdr=5, variable=True, confidence=0.85),
    proto("NetConf", "netconf", min_hdr=1, variable=True),
    proto("OpenFlow 1.3", "openflow_v4", min_hdr=8, variable=True, confidence=0.85),
    proto("OpenFlow 1.5", "openflow_v6", min_hdr=8, variable=True, confidence=0.85),
    proto("OF-Config", "of-config", min_hdr=1, variable=True, confidence=0.8),
    proto("OVSDB Monitor", "ovsdb.monitor", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("FlowSpec", "bgp.flowspec", min_hdr=2, variable=True, confidence=0.7, method="long_name"),
]

# ── Network Management / Monitoring ──
PROTOCOLS += [
    proto("TWAMP", "twamp", min_hdr=14),
    proto("OWAMP", "owamp", min_hdr=14),
    proto("STAMP", "stamp", min_hdr=44),
    proto("Ethernet OAM", "oam", min_hdr=4, confidence=0.85),
    proto("Y.1731", "cfm", min_hdr=4, confidence=0.8, method="long_name"),
    proto("LBMS", "lbm", min_hdr=4, variable=True, confidence=0.8),
    proto("IEEE 1588 PTP v2", "ptp", "PTP", min_hdr=34, confidence=0.85, method="long_name"),
    proto("MACsec Key Agreement", "mka", min_hdr=32, variable=True, confidence=0.85),
    proto("Wireguard Handshake", "wg", "Wireguard", min_hdr=4, variable=True, confidence=0.85),
    proto("sFlow", "sflow", min_hdr=28, variable=True, confidence=0.9),
    proto("NetFlow v1", "netflow.v1", min_hdr=16, confidence=0.8, method="long_name"),
    proto("IPFIX Options", "ipfix.options", min_hdr=4, variable=True, confidence=0.7, method="long_name"),
    proto("SNMP Trap", "snmp.trap", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("SNMPv3", "snmpv3", min_hdr=1, variable=True, confidence=0.8),
    proto("RMON", "rmon", min_hdr=1, variable=True, confidence=0.8),
    proto("NETCONF Notifications", "netconf.notification", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("YANG Push", "yang.push", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
]

# ── Routing (extensions) ──
PROTOCOLS += [
    proto("Babel", "babel", "Babel", min_hdr=4, variable=True),
    proto("LISP Control", "lisp-control", min_hdr=4, variable=True, confidence=0.85),
    proto("BGP-LS", "bgp-ls", min_hdr=4, variable=True, confidence=0.8, method="decode_table"),
    proto("BGP-4", "bgp.update", min_hdr=4, variable=True, confidence=0.8, method="long_name"),
    proto("OSPF LSA", "ospf.lsa", min_hdr=4, variable=True, confidence=0.7, method="long_name"),
    proto("IS-IS TLV", "isis.lsp", min_hdr=2, variable=True, confidence=0.7, method="long_name"),
    proto("RIPng", "ripng", min_hdr=4, variable=True, confidence=0.9),
    proto("NHRP", "nhrp", min_hdr=20, variable=True, confidence=0.85),
    proto("DVMRP", "dvmrp", min_hdr=4, variable=True, confidence=0.8),
    proto("PIM-SM", "pim.sm", min_hdr=4, variable=True, confidence=0.7, method="long_name"),
    proto("MOSPF", "mospf", min_hdr=4, variable=True, confidence=0.7, method="long_name"),
]

# ── Database / Middleware ──
PROTOCOLS += [
    proto("PostgreSQL", "pgsql", min_hdr=5, variable=True),
    proto("MySQL", "mysql", min_hdr=4, variable=True),
    proto("MongoDB Wire", "mongo", min_hdr=16, variable=True),
    proto("Cassandra", "cassandra", min_hdr=9, variable=True),
    proto("Thrift", "thrift", min_hdr=4, variable=True),
    proto("WebSocket", "websocket", min_hdr=2, variable=True),
    proto("NATS", "nats", min_hdr=4, variable=True, confidence=0.85),
    proto("RabbitMQ AMQP", "rabbitmq", min_hdr=8, variable=True, confidence=0.8, method="long_name"),
    proto("Apache Pulsar", "pulsar", min_hdr=4, variable=True, confidence=0.8),
    proto("CQL (Cassandra)", "cql", min_hdr=9, variable=True, confidence=0.85),
    proto("TDS (SQL Server)", "tds", min_hdr=8, variable=True, confidence=0.85),
    proto("TNS (Oracle)", "tns", min_hdr=8, variable=True, confidence=0.85),
    proto("DRDA (DB2)", "drda", min_hdr=10, variable=True, confidence=0.85),
    proto("MySQL X Protocol", "mysqlx", min_hdr=5, variable=True, confidence=0.85),
    proto("Bolt (Neo4j)", "bolt", min_hdr=2, variable=True, confidence=0.8),
    proto("ClickHouse Native", "clickhouse", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
]

# ── Application (misc) ──
PROTOCOLS += [
    proto("POP3", "pop", min_hdr=4, variable=True),
    proto("NNTP", "nntp", min_hdr=4, variable=True, confidence=0.85),
    proto("IRC", "irc", min_hdr=1, variable=True, confidence=0.85),
    proto("XMPP", "xmpp", min_hdr=1, variable=True, confidence=0.85),
    proto("BitTorrent", "bittorrent", min_hdr=20, variable=True, confidence=0.85),
    proto("Bitcoin", "bitcoin", min_hdr=24, variable=True, confidence=0.85),
    proto("Ethereum P2P", "eth_p2p", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("QUIC v1", "quic", min_hdr=1, variable=True, confidence=0.8, method="long_name"),
    proto("QUIC v2", "quic.v2", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("HTTP/3", "http3", min_hdr=1, variable=True, confidence=0.85),
    proto("DNS over HTTPS", "doh", min_hdr=12, variable=True, confidence=0.8, method="long_name"),
    proto("DNS over TLS", "dot", min_hdr=14, variable=True, confidence=0.8, method="long_name"),
    proto("DNS over QUIC", "doq", min_hdr=12, variable=True, confidence=0.7, method="long_name"),
    proto("ACME", "acme", min_hdr=1, variable=True, confidence=0.8),
    proto("GraphQL", "graphql", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("JSON-RPC", "jsonrpc", min_hdr=1, variable=True, confidence=0.8),
    proto("XML-RPC", "xmlrpc", min_hdr=1, variable=True, confidence=0.8),
    proto("SOAP", "soap", min_hdr=1, variable=True, confidence=0.8),
    proto("REST", "http", min_hdr=1, variable=True, confidence=0.5, method="long_name"),
    proto("MessagePack", "msgpack", min_hdr=1, variable=True, confidence=0.8),
    proto("Cap'n Proto", "capnp", min_hdr=8, variable=True, confidence=0.7, method="long_name"),
    proto("FlatBuffers", "flatbuf", min_hdr=4, variable=True, confidence=0.7, method="long_name"),
    proto("Avro", "avro", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
]

# ── Security / PKI ──
PROTOCOLS += [
    proto("DTLS 1.2", "dtls", "DTLS", min_hdr=13, confidence=0.8, method="long_name"),
    proto("TLS 1.3", "tls13", min_hdr=5, variable=True, confidence=0.8, method="long_name"),
    proto("OCSP Online", "ocsp", min_hdr=1, variable=True, confidence=0.8, method="long_name"),
    proto("PKCS#7 / CMS", "cms", min_hdr=1, variable=True, confidence=0.8),
    proto("X.509 Certificate", "x509af", min_hdr=1, variable=True, confidence=0.85),
    proto("X.509 CRL", "x509ce", min_hdr=1, variable=True, confidence=0.8),
    proto("PKIX", "pkix", min_hdr=1, variable=True, confidence=0.8),
    proto("WPA Key", "wlan_rsna_eapol", min_hdr=99, variable=True, confidence=0.8, method="decode_table"),
    proto("802.1X", "ieee8021x", min_hdr=4, confidence=0.85),
    proto("MACsec XPN", "macsec.xpn", min_hdr=8, confidence=0.7, method="long_name"),
    proto("IPsec IKEv1", "isakmp.v1", min_hdr=28, variable=True, confidence=0.8, method="long_name"),
    proto("SPNEGO", "spnego", min_hdr=1, variable=True, confidence=0.85),
    proto("GSS-API", "gssapi", min_hdr=1, variable=True, confidence=0.85),
    proto("SASL", "sasl", min_hdr=1, variable=True, confidence=0.8),
]

# ── VoIP / Multimedia ──
PROTOCOLS += [
    proto("SDP", "sdp", min_hdr=1, variable=True, confidence=0.9),
    proto("MEGACO / H.248", "megaco", min_hdr=1, variable=True, confidence=0.85),
    proto("H.225", "h225", min_hdr=4, variable=True, confidence=0.85),
    proto("H.245", "h245", min_hdr=4, variable=True, confidence=0.85),
    proto("H.323", "h323", min_hdr=4, variable=True, confidence=0.85),
    proto("T.38 Fax", "t38", min_hdr=1, variable=True, confidence=0.85),
    proto("RTSP 2.0", "rtsp2", min_hdr=1, variable=True, confidence=0.8, method="long_name"),
    proto("SRTP", "srtp", min_hdr=12, confidence=0.85),
    proto("RTCP XR", "rtcp.xr", min_hdr=4, variable=True, confidence=0.8, method="long_name"),
    proto("ZRTP", "zrtp", min_hdr=12, variable=True, confidence=0.85),
    proto("MSRP", "msrp", min_hdr=1, variable=True, confidence=0.85),
    proto("SIP over WebSocket", "sip.ws", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
]

# ── Wireless / Radio ──
PROTOCOLS += [
    proto("LTE MAC", "mac-lte", min_hdr=1, variable=True, confidence=0.85),
    proto("LTE PDCP", "pdcp-lte", min_hdr=1, variable=True, confidence=0.85),
    proto("LTE RLC", "rlc-lte", min_hdr=1, variable=True, confidence=0.85),
    proto("5G NR MAC", "mac-nr", min_hdr=1, variable=True, confidence=0.85),
    proto("5G NR PDCP", "pdcp-nr", min_hdr=1, variable=True, confidence=0.85),
    proto("5G NR RLC", "rlc-nr", min_hdr=1, variable=True, confidence=0.85),
    proto("NB-IoT", "nbiot", min_hdr=2, variable=True, confidence=0.8),
    proto("WiMax", "wimaxasncp", min_hdr=20, variable=True, confidence=0.7, method="long_name"),
    proto("Wi-Fi Direct", "wifi-direct", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("802.11 Radiotap", "radiotap", min_hdr=8, variable=True, confidence=0.9),
    proto("802.11 PPI", "ppi", min_hdr=8, variable=True, confidence=0.85),
    proto("Bluetooth HCI USB", "hci_usb", min_hdr=1, variable=True, confidence=0.85),
    proto("Bluetooth SBC", "sbc", min_hdr=4, variable=True, confidence=0.8),
    proto("LoRa PHY", "lora_phy", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("NR-DC", "nr-dc", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("PDCP NR", "pdcp.nr", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("SigFox", "sigfox", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
]

# ── Storage / SAN ──
PROTOCOLS += [
    proto("SMB3", "smb3", min_hdr=64, variable=True, confidence=0.85),
    proto("NFS v4", "nfs4", min_hdr=1, variable=True, confidence=0.85),
    proto("iSCSI Login", "iscsi.login", min_hdr=48, variable=True, confidence=0.8, method="long_name"),
    proto("NVMe over Fabrics", "nvme-of", min_hdr=24, variable=True, confidence=0.85),
    proto("NVMe-TCP", "nvme-tcp", min_hdr=8, variable=True, confidence=0.85),
    proto("Ceph Messenger v2", "ceph.msgr2", min_hdr=4, variable=True, confidence=0.8, method="long_name"),
    proto("S3 (AWS)", "s3", min_hdr=1, variable=True, confidence=0.5, method="long_name"),
    proto("CIFS", "cifs", min_hdr=1, variable=True, confidence=0.8, method="long_name"),
    proto("AFP", "afp", min_hdr=1, variable=True, confidence=0.85),
    proto("FTP Data", "ftp-data", min_hdr=0, variable=True, confidence=0.85),
    proto("TFTP Data", "tftp.data", min_hdr=4, confidence=0.8, method="long_name"),
]

# ── USB / Serial ──
PROTOCOLS += [
    proto("USB Bulk", "usb.bulk", min_hdr=0, variable=True, confidence=0.8, method="decode_table"),
    proto("USB HID", "usbhid", min_hdr=1, variable=True, confidence=0.85),
    proto("USB Mass Storage", "usbms", min_hdr=31, variable=True, confidence=0.85),
    proto("USB Audio", "usbaudio", min_hdr=1, variable=True, confidence=0.85),
    proto("USB Video", "usbvideo", min_hdr=1, variable=True, confidence=0.85),
    proto("USB CDC", "usb_cdc", min_hdr=1, variable=True, confidence=0.85),
    proto("USB CCID", "usbccid", min_hdr=10, variable=True, confidence=0.85),
    proto("HDLC", "hdlc", min_hdr=4, confidence=0.9),
    proto("SLIP", "slip", min_hdr=1, variable=True, confidence=0.9),
    proto("Frame Relay", "fr", min_hdr=2, variable=True, confidence=0.9),
    proto("PPP Multilink", "mp", min_hdr=4, variable=True, confidence=0.85),
    proto("PPP LCP", "lcp", min_hdr=4, variable=True, confidence=0.85),
    proto("PPP IPCP", "ipcp", min_hdr=4, variable=True, confidence=0.85),
    proto("PPP CCP", "ccp", min_hdr=4, variable=True, confidence=0.85),
]

# ── Layer 2 extensions ──
PROTOCOLS += [
    proto("TRILL Fine-Grained", "trill", min_hdr=6, confidence=0.7, method="long_name"),
    proto("SPB", "spb", min_hdr=8, confidence=0.85),
    proto("EVB/VDP", "evb", min_hdr=4, variable=True, confidence=0.8),
    proto("802.1BR", "ieee8021br", min_hdr=8, confidence=0.8),
    proto("802.3 OAM", "efm", min_hdr=4, variable=True, confidence=0.85),
    proto("MACSEC GCM-AES-256", "macsec.gcm256", min_hdr=8, confidence=0.7, method="long_name"),
    proto("STP BPDU", "stp.bpdu", min_hdr=4, variable=True, confidence=0.7, method="long_name"),
    proto("RSTP", "rstp", min_hdr=4, variable=True, confidence=0.85),
    proto("MSTP", "mstp", min_hdr=4, variable=True, confidence=0.85),
    proto("PVST+", "pvst", min_hdr=4, variable=True, confidence=0.85),
    proto("VTP", "vtp", min_hdr=4, variable=True, confidence=0.85),
    proto("DTP", "dtp", min_hdr=1, variable=True, confidence=0.85),
    proto("PAGP", "pagp", min_hdr=4, variable=True, confidence=0.85),
    proto("UDLD", "udld", min_hdr=8, variable=True, confidence=0.85),
]

# ── Tunneling extensions ──
PROTOCOLS += [
    proto("PWE3", "pw_eth", min_hdr=4, confidence=0.8, method="long_name"),
    proto("L2TPv3", "l2tpv3", min_hdr=12, variable=True, confidence=0.85),
    proto("GTP-U Extension", "gtp.ext", min_hdr=4, variable=True, confidence=0.8, method="decode_table"),
    proto("GRE ERSPAN Type III", "erspan3", min_hdr=12, confidence=0.85),
    proto("IP-in-IP v6", "ip6ip6", min_hdr=40, confidence=0.85,
          kernel_struct="ipv6hdr", kernel_header="linux/ipv6.h"),
    proto("Teredo v2", "teredo2", min_hdr=2, variable=True, confidence=0.7, method="long_name"),
    proto("AMT", "amt", min_hdr=8, variable=True, confidence=0.85),
    proto("AYIYA", "ayiya", min_hdr=44, confidence=0.85),
    proto("6in4", "6in4", min_hdr=20, confidence=0.85),
    proto("6to4", "6to4", min_hdr=20, confidence=0.85),
    proto("DS-Lite", "dslite", min_hdr=40, confidence=0.8),
    proto("MAP-E", "map-e", min_hdr=40, confidence=0.7, method="long_name"),
    proto("LISP GPE", "lisp-gpe", min_hdr=8, variable=True, confidence=0.85),
    proto("Geneve TLV", "geneve.tlv", min_hdr=4, variable=True, confidence=0.8, method="decode_table"),
    proto("ERSPAN Type II", "erspan2", min_hdr=8, confidence=0.85),
]

# ── DNS / DHCP extensions ──
PROTOCOLS += [
    proto("mDNS-SD", "mdns-sd", min_hdr=12, variable=True, confidence=0.7, method="long_name"),
    proto("LLMNR", "llmnr", min_hdr=12, confidence=0.8, method="long_name"),
    proto("NBNS", "nbns", min_hdr=12, confidence=0.8, method="long_name"),
    proto("WINS", "wins", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("DHCP Relay", "dhcp.relay", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("DHCPv6-PD", "dhcpv6.pd", min_hdr=4, variable=True, confidence=0.7, method="long_name"),
    proto("TSIG", "dns.tsig", min_hdr=1, variable=True, confidence=0.8, method="decode_table"),
    proto("DNSSEC", "dnssec", min_hdr=1, variable=True, confidence=0.8),
    proto("EDNS", "dns.opt", min_hdr=11, variable=True, confidence=0.8, method="decode_table"),
]

# ── Miscellaneous ──
PROTOCOLS += [
    proto("LLDP-MED", "lldp-med", min_hdr=2, variable=True, confidence=0.7, method="long_name"),
    proto("LDAPS", "ldaps", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("NTP Autokey", "ntp.autokey", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("PTPv1", "ptpv1", min_hdr=34, confidence=0.85),
    proto("ARP Probe", "arp.probe", min_hdr=28, confidence=0.7, method="long_name"),
    proto("WPAD", "wpad", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("mDNS Bonjour", "mdns.bonjour", min_hdr=12, variable=True, confidence=0.6, method="long_name"),
    proto("UPnP SSDP", "ssdp", min_hdr=1, variable=True, confidence=0.85),
    proto("DLNA", "dlna", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("Bonjour Sleep Proxy", "bsp", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("LPD", "lpd", min_hdr=1, variable=True, confidence=0.85),
    proto("IPP", "ipp", min_hdr=1, variable=True, confidence=0.85),
    proto("CUPS", "cups", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("AFP over TCP", "afp.tcp", min_hdr=4, variable=True, confidence=0.7, method="long_name"),
    proto("CLDAP", "cldap", min_hdr=1, variable=True, confidence=0.85),
    proto("DCE/RPC", "dcerpc", min_hdr=16, variable=True, confidence=0.9),
    proto("MSRPC", "msrpc", min_hdr=16, variable=True, confidence=0.8, method="long_name"),
    proto("NBSS", "nbss", min_hdr=4, confidence=0.9),
    proto("NetBIOS Datagram", "nbdgm", min_hdr=10, variable=True, confidence=0.9),
    proto("PPTP", "pptp", min_hdr=12, variable=True, confidence=0.9),
    proto("L2F", "l2f", min_hdr=6, variable=True, confidence=0.85),
    proto("EGP", "egp", min_hdr=10, confidence=0.9),
    proto("IGRP", "igrp", min_hdr=12, variable=True, confidence=0.85),
]

# ── ASN.1 / Encoding ──
PROTOCOLS += [
    proto("ASN.1 BER", "ber", min_hdr=2, variable=True, confidence=0.9),
    proto("ASN.1 PER", "per", min_hdr=1, variable=True, confidence=0.85),
    proto("ASN.1 OER", "oer", min_hdr=1, variable=True, confidence=0.8),
    proto("LDAP Bind", "ldap.bind", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("LDAP Search", "ldap.search", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
]

# ── Multicast ──
PROTOCOLS += [
    proto("PGM", "pgm", min_hdr=16, variable=True, confidence=0.9,
          kernel_struct="pgm_header", kernel_header="linux/pgm.h"),
    proto("NORM", "norm", min_hdr=8, variable=True, confidence=0.85),
    proto("LDP Multipoint", "ldp.mp", min_hdr=4, variable=True, confidence=0.7, method="long_name"),
    proto("IGMP Snooping", "igmp.snoop", min_hdr=8, confidence=0.7, method="long_name"),
    proto("MLD Snooping", "mld.snoop", min_hdr=8, confidence=0.7, method="long_name"),
    proto("SSM Mapping", "ssm", min_hdr=4, variable=True, confidence=0.7, method="long_name"),
    proto("MSDP", "msdp", min_hdr=3, variable=True, confidence=0.85),
    proto("BIDIR-PIM", "bidir-pim", min_hdr=4, variable=True, confidence=0.7, method="long_name"),
]

# ── Grid / HPC ──
PROTOCOLS += [
    proto("MPI", "mpi", min_hdr=4, variable=True, confidence=0.7, method="long_name"),
    proto("UCX", "ucx", min_hdr=8, variable=True, confidence=0.7, method="long_name"),
    proto("Lustre", "lustre", min_hdr=4, variable=True, confidence=0.85),
    proto("GPFS", "gpfs", min_hdr=4, variable=True, confidence=0.7, method="long_name"),
    proto("GlusterFS", "glusterfs", min_hdr=4, variable=True, confidence=0.85),
    proto("pNFS", "pnfs", min_hdr=1, variable=True, confidence=0.8),
    proto("iWARP", "iwarp", min_hdr=4, variable=True, confidence=0.85),
    proto("RDMA CM", "iwarp-mpa", min_hdr=16, variable=True, confidence=0.85),
]

# ── Streaming / Media ──
PROTOCOLS += [
    proto("MPEG-DASH", "dash", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("HLS", "hls", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("RTMP", "rtmp", min_hdr=12, variable=True, confidence=0.85),
    proto("RTMPS", "rtmps", min_hdr=12, variable=True, confidence=0.8, method="long_name"),
    proto("RTMFP", "rtmfp", min_hdr=4, variable=True, confidence=0.85),
    proto("WebRTC DTLS", "webrtc.dtls", min_hdr=13, variable=True, confidence=0.7, method="long_name"),
    proto("SCTP DTLS", "sctp.dtls", min_hdr=13, variable=True, confidence=0.7, method="long_name"),
    proto("ICE/STUN", "stun.ice", min_hdr=20, variable=True, confidence=0.7, method="long_name"),
    proto("TURN", "turn", min_hdr=20, variable=True, confidence=0.85),
    proto("RTP MIDI", "rtp-midi", min_hdr=4, variable=True, confidence=0.85),
    proto("AES67", "aes67", min_hdr=12, variable=True, confidence=0.7, method="long_name"),
    proto("Dante Audio", "dante", min_hdr=8, variable=True, confidence=0.7, method="long_name"),
    proto("NDI", "ndi", min_hdr=4, variable=True, confidence=0.7, method="long_name"),
    proto("SMPTE ST 2110", "smpte2110", min_hdr=12, variable=True, confidence=0.7, method="long_name"),
]

# ── Cisco / Vendor protocols ──
PROTOCOLS += [
    proto("Cisco ISL", "isl", min_hdr=26, confidence=0.85),
    proto("Cisco PVST", "pvst", min_hdr=4, variable=True, confidence=0.85),
    proto("Cisco GLBP", "glbp", min_hdr=12, variable=True, confidence=0.85),
    proto("Cisco WCCP", "wccp", min_hdr=8, variable=True, confidence=0.85),
    proto("Cisco FabricPath", "fabricpath", min_hdr=16, confidence=0.85),
    proto("Cisco OTV", "otv", min_hdr=8, confidence=0.85),
    proto("Cisco LISP", "lisp.cisco", min_hdr=8, variable=True, confidence=0.7, method="long_name"),
    proto("Cisco vPC", "vpc", min_hdr=4, variable=True, confidence=0.7, method="long_name"),
    proto("Cisco Smart Install", "smartinstall", min_hdr=8, variable=True, confidence=0.8),
    proto("Cisco ACI", "aci", min_hdr=4, variable=True, confidence=0.7, method="long_name"),
    proto("Juniper JNPR", "juniper", min_hdr=6, variable=True, confidence=0.85),
    proto("Arista EOS", "arista_eos", min_hdr=4, variable=True, confidence=0.7, method="long_name"),
    proto("Nokia SROS", "sros", min_hdr=4, variable=True, confidence=0.7, method="long_name"),
    proto("VMware VDP", "vmware_vdp", min_hdr=4, variable=True, confidence=0.7, method="long_name"),
    proto("Hyper-V VMBus", "vmbus", min_hdr=8, variable=True, confidence=0.7, method="long_name"),
]

# ── ICS / Building Automation extended ──
PROTOCOLS += [
    proto("BACnet/IP", "bacnet.ip", min_hdr=10, variable=True, confidence=0.8, method="decode_table"),
    proto("BACnet MSTP", "bacnet.mstp", min_hdr=8, variable=True, confidence=0.8, method="decode_table"),
    proto("LonTalk", "lon", min_hdr=6, variable=True, confidence=0.85),
    proto("M-Bus", "mbus", min_hdr=4, variable=True, confidence=0.85),
    proto("DALI-2", "dali2", min_hdr=2, confidence=0.7, method="long_name"),
    proto("ZigBee Green Power", "zbee_gp", min_hdr=1, variable=True, confidence=0.85),
    proto("Z-Wave S2", "zwave.s2", min_hdr=10, variable=True, confidence=0.7, method="long_name"),
    proto("Bluetooth Mesh", "btmesh", min_hdr=9, variable=True, confidence=0.85),
    proto("Thread 1.3", "thread.1.3", min_hdr=2, variable=True, confidence=0.7, method="long_name"),
]

# ── Power / Energy ──
PROTOCOLS += [
    proto("IEEE C37.118 Synchrophasor", "synchrophasor", min_hdr=14, variable=True, confidence=0.85),
    proto("IEEE 2030.5 SEP", "sep2", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("OpenADR", "openadr", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("DLMS/COSEM", "dlms", min_hdr=8, variable=True, confidence=0.85),
    proto("IEC 62056 OBIS", "obis", min_hdr=6, variable=True, confidence=0.8),
    proto("IEC 62351", "iec62351", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("DNP3 Secure Auth", "dnp3.sa", min_hdr=10, variable=True, confidence=0.7, method="long_name"),
]

# ── Aviation / Aerospace ──
PROTOCOLS += [
    proto("ARINC 429", "arinc429", min_hdr=4, confidence=0.85),
    proto("ARINC 664 AFDX", "afdx", min_hdr=14, confidence=0.85),
    proto("MIL-STD-1553", "milstd1553", min_hdr=3, confidence=0.85),
    proto("SpaceWire", "spacewire", min_hdr=4, variable=True, confidence=0.8),
    proto("CCSDS", "ccsds", min_hdr=6, variable=True, confidence=0.85),
    proto("ADS-B", "adsb", min_hdr=14, confidence=0.85),
    proto("ACARS", "acars", min_hdr=1, variable=True, confidence=0.85),
    proto("VDL Mode 2", "vdl2", min_hdr=3, variable=True, confidence=0.8),
]

# ── Medical ──
PROTOCOLS += [
    proto("DICOM", "dicom", min_hdr=6, variable=True, confidence=0.9),
    proto("HL7 v2", "hl7", min_hdr=1, variable=True, confidence=0.85),
    proto("FHIR", "fhir", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("IHE XDS", "xds", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
]

# ── Financial ──
PROTOCOLS += [
    proto("FIX", "fix", min_hdr=1, variable=True, confidence=0.85),
    proto("FAST", "fast", min_hdr=1, variable=True, confidence=0.85),
    proto("OUCH", "ouch", min_hdr=1, variable=True, confidence=0.8),
    proto("ITCH", "itch", min_hdr=1, variable=True, confidence=0.8),
    proto("SoupBinTCP", "soupbintcp", min_hdr=3, variable=True, confidence=0.85),
    proto("MoldUDP64", "moldudp64", min_hdr=20, variable=True, confidence=0.85),
    proto("BATS PITCH", "pitch", min_hdr=1, variable=True, confidence=0.8),
    proto("CME MDP 3.0", "cme_mdp3", min_hdr=12, variable=True, confidence=0.7, method="long_name"),
    proto("Eurex ETI", "eurex_eti", min_hdr=8, variable=True, confidence=0.7, method="long_name"),
    proto("SWIFT FIN", "swift", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
]

# ── Container / Orchestration ──
PROTOCOLS += [
    proto("Docker API", "docker", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("Kubernetes API", "k8s", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("etcd", "etcd", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("Consul", "consul", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("Envoy xDS", "envoy.xds", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("Cilium", "cilium", min_hdr=4, variable=True, confidence=0.7, method="long_name"),
    proto("Calico BIRD", "bird", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("WireGuard Tunnel", "wg.tunnel", min_hdr=32, confidence=0.7, method="long_name"),
]

# ── Time Sync ──
PROTOCOLS += [
    proto("PTP Transparent Clock", "ptp.tc", min_hdr=34, confidence=0.7, method="long_name"),
    proto("PTP Boundary Clock", "ptp.bc", min_hdr=34, confidence=0.7, method="long_name"),
    proto("NTPv5", "ntpv5", min_hdr=48, confidence=0.7, method="long_name"),
    proto("Roughtime", "roughtime", min_hdr=1, variable=True, confidence=0.8),
    proto("TimeSync IEEE 802.1AS", "ieee8021as", min_hdr=34, confidence=0.85),
]

# ── Link Aggregation / Redundancy ──
PROTOCOLS += [
    proto("MC-LAG", "mc-lag", min_hdr=4, variable=True, confidence=0.7, method="long_name"),
    proto("ICCP", "iccp", min_hdr=4, variable=True, confidence=0.8),
    proto("PRP", "prp", min_hdr=6, confidence=0.85),
    proto("DLR", "dlr", min_hdr=4, variable=True, confidence=0.85),
    proto("MRP", "mrp", min_hdr=4, variable=True, confidence=0.85),
    proto("ERPS", "erps", min_hdr=4, variable=True, confidence=0.85),
    proto("REP", "rep", min_hdr=4, variable=True, confidence=0.7, method="long_name"),
    proto("G.8032", "g8032", min_hdr=4, variable=True, confidence=0.8),
]

# ── MPLS extensions ──
PROTOCOLS += [
    proto("MPLS-TP OAM", "mpls-tp.oam", min_hdr=4, variable=True, confidence=0.8, method="decode_table"),
    proto("MPLS Entropy Label", "mpls.entropy", min_hdr=4, confidence=0.7, method="long_name"),
    proto("MPLS EVPN", "mpls.evpn", min_hdr=4, variable=True, confidence=0.7, method="long_name"),
    proto("MPLS L3VPN", "mpls.l3vpn", min_hdr=4, variable=True, confidence=0.7, method="long_name"),
    proto("MPLS L2VPN", "mpls.l2vpn", min_hdr=4, variable=True, confidence=0.7, method="long_name"),
    proto("MPLS-SR", "mpls.sr", min_hdr=4, confidence=0.7, method="long_name"),
    proto("MPLS FRR", "mpls.frr", min_hdr=4, variable=True, confidence=0.7, method="long_name"),
]

# ── DNS/Name Resolution extended ──
PROTOCOLS += [
    proto("DNS SRV", "dns.srv", min_hdr=12, variable=True, confidence=0.7, method="long_name"),
    proto("DNS NAPTR", "dns.naptr", min_hdr=12, variable=True, confidence=0.7, method="long_name"),
    proto("DNS CAA", "dns.caa", min_hdr=12, variable=True, confidence=0.7, method="long_name"),
    proto("DNS HTTPS", "dns.https", min_hdr=12, variable=True, confidence=0.7, method="long_name"),
    proto("DNS SVCB", "dns.svcb", min_hdr=12, variable=True, confidence=0.7, method="long_name"),
]

# ── Testing / Measurement ──
PROTOCOLS += [
    proto("Iperf3", "iperf3", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("Iperf UDP", "iperf.udp", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("Netperf", "netperf", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("LMAP", "lmap", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("Y.1564", "y1564", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("RFC 2544", "rfc2544", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
]


def main():
    # Deduplicate and remove curated
    seen = set()
    final = []
    for p in PROTOCOLS:
        name = p["canonical"]
        if name in CURATED:
            continue
        if name in seen:
            continue
        seen.add(name)
        final.append(p)

    final.sort(key=lambda p: p["canonical"])

    output = {"protocols": final}
    outpath = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                           "data", "auto_mappings.json")
    if not os.path.isdir(os.path.dirname(outpath)):
        outpath = "auto_mappings.json"

    with open(outpath, "w") as f:
        json.dump(output, f, indent=2)
        f.write("\n")

    print(f"Generated {len(final)} auto-mapped protocols → {outpath}", file=sys.stderr)

    # Stats by category confidence
    by_confidence = {}
    for p in final:
        c = p["confidence"]
        bucket = f"{c:.1f}"
        by_confidence[bucket] = by_confidence.get(bucket, 0) + 1
    print("  By confidence:", dict(sorted(by_confidence.items(), reverse=True)), file=sys.stderr)

    by_method = {}
    for p in final:
        m = p["match_method"]
        by_method[m] = by_method.get(m, 0) + 1
    print("  By method:", dict(sorted(by_method.items(), key=lambda x: -x[1])), file=sys.stderr)


if __name__ == "__main__":
    main()
