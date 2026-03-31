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
          method="exact_normalized", libpcap_name=None, libpcap_file=None):
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
    if libpcap_name:
        entry["libpcap_name"] = libpcap_name
    if libpcap_file:
        entry["libpcap_file"] = libpcap_file
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
    proto("LIN", "lin", scapy="LIN", min_hdr=2),
    proto("FlexRay", "flexray", scapy="FlexRay", min_hdr=5),
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
    proto("IEC 61850 MMS", "mms", scapy="MMS", min_hdr=4, variable=True, confidence=0.8),
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
    proto("GTPv1-C", "gtpv1c", scapy="GTPHeader", min_hdr=8, variable=True, confidence=0.85),
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
    proto("OVSDB", "ovsdb", scapy="OVSDB", min_hdr=1, variable=True, confidence=0.85),
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
    proto("sFlow", "sflow", scapy="sFlow5", min_hdr=28, variable=True, confidence=0.9),
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
    proto("Thrift", "thrift", scapy="Thrift", min_hdr=4, variable=True),
    proto("WebSocket", "websocket", scapy="WebSocket", min_hdr=2, variable=True),
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
    proto("IRC", "irc", scapy="IRC", min_hdr=1, variable=True, confidence=0.85),
    proto("XMPP", "xmpp", scapy="XMPP", min_hdr=1, variable=True, confidence=0.85),
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
    proto("SLIP", "slip", scapy="SLIP", min_hdr=1, variable=True, confidence=0.9),
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
    proto("PPTP", "pptp", scapy="PPTP", min_hdr=12, variable=True, confidence=0.9, kernel_struct="pptp_addr", kernel_header="linux/if_pppox.h"),
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
    proto("RTMP", "rtmp", scapy="RTMP", min_hdr=12, variable=True, confidence=0.85),
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
    proto("M-Bus", "mbus", scapy="MBus", min_hdr=4, variable=True, confidence=0.85),
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
    proto("CCSDS", "ccsds", scapy="CCSDS", min_hdr=6, variable=True, confidence=0.85),
    proto("ADS-B", "adsb", min_hdr=14, confidence=0.85),
    proto("ACARS", "acars", min_hdr=1, variable=True, confidence=0.85),
    proto("VDL Mode 2", "vdl2", min_hdr=3, variable=True, confidence=0.8),
]

# ── Medical ──
PROTOCOLS += [
    proto("DICOM", "dicom", scapy="DICOM", min_hdr=6, variable=True, confidence=0.9),
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

# ── RADIUS extensions ──
PROTOCOLS += [
    proto("RADIUS EAP", "radius.eap", min_hdr=20, variable=True, confidence=0.7, method="long_name"),
    proto("RADIUS Accounting", "radius.acct", min_hdr=20, variable=True, confidence=0.7, method="long_name"),
    proto("RADIUS CoA", "radius.coa", min_hdr=20, variable=True, confidence=0.7, method="long_name"),
    proto("RadSec", "radsec", min_hdr=20, variable=True, confidence=0.8),
    proto("Diameter Rx", "diameter.rx", min_hdr=20, variable=True, confidence=0.7, method="long_name"),
    proto("Diameter S6a/S6d", "diameter.s6a", min_hdr=20, variable=True, confidence=0.7, method="long_name"),
    proto("Diameter Cx/Dx", "diameter.cx", min_hdr=20, variable=True, confidence=0.7, method="long_name"),
    proto("Diameter Sh", "diameter.sh", min_hdr=20, variable=True, confidence=0.7, method="long_name"),
]

# ── SCTP extensions ──
PROTOCOLS += [
    proto("SCTP Init", "sctp.init", min_hdr=20, variable=True, confidence=0.7, method="long_name"),
    proto("SCTP Data", "sctp.data", min_hdr=16, variable=True, confidence=0.7, method="long_name"),
    proto("SCTP HB", "sctp.heartbeat", min_hdr=4, variable=True, confidence=0.7, method="long_name"),
    proto("SCTP ASCONF", "sctp.asconf", min_hdr=8, variable=True, confidence=0.7, method="long_name"),
    proto("SCTP Auth", "sctp.auth", min_hdr=8, variable=True, confidence=0.7, method="long_name"),
]

# ── TCP extensions ──
PROTOCOLS += [
    proto("TCP MD5", "tcp.md5", min_hdr=18, confidence=0.7, method="long_name"),
    proto("TCP AO", "tcp.ao", min_hdr=4, variable=True, confidence=0.7, method="long_name"),
    proto("TCP Fast Open", "tcp.tfo", min_hdr=4, variable=True, confidence=0.7, method="long_name"),
    proto("MPTCP", "mptcp", min_hdr=4, variable=True, confidence=0.85),
    proto("TCP BBR", "tcp.bbr", min_hdr=0, variable=True, confidence=0.6, method="long_name"),
]

# ── IPv6 extensions ──
PROTOCOLS += [
    proto("IPv6 HBH Options", "ipv6.hbh", min_hdr=8, variable=True, confidence=0.8, method="decode_table"),
    proto("IPv6 Mobility", "mipv6", min_hdr=8, variable=True, confidence=0.85),
    proto("IPv6 Shim6", "shim6", min_hdr=8, variable=True, confidence=0.85),
    proto("IPv6 HIP", "hip", min_hdr=40, variable=True, confidence=0.85),
    proto("IPv6 ILA", "ila", min_hdr=8, variable=True, confidence=0.7, method="long_name"),
]

# ── Additional VPN / Overlay ──
PROTOCOLS += [
    proto("OpenVPN", "openvpn", min_hdr=2, variable=True, confidence=0.85),
    proto("SoftEther", "softether", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("SSTP", "sstp", min_hdr=4, variable=True, confidence=0.85),
    proto("Tinc", "tinc", min_hdr=4, variable=True, confidence=0.7, method="long_name"),
    proto("Nebula", "nebula", min_hdr=16, variable=True, confidence=0.7, method="long_name"),
    proto("Tailscale", "tailscale", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("ZeroTier", "zerotier", min_hdr=16, variable=True, confidence=0.7, method="long_name"),
]

# ── Satellite / Space ──
PROTOCOLS += [
    proto("DVB-S2", "dvb-s2", min_hdr=10, variable=True, confidence=0.8),
    proto("DVB-T2", "dvb-t2", min_hdr=1, variable=True, confidence=0.8),
    proto("DVB-RCS2", "dvb-rcs2", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("CCSDS TM", "ccsds.tm", min_hdr=6, variable=True, confidence=0.7, method="long_name"),
    proto("CCSDS TC", "ccsds.tc", min_hdr=5, variable=True, confidence=0.7, method="long_name"),
    proto("CCSDS AOS", "ccsds.aos", min_hdr=6, variable=True, confidence=0.7, method="long_name"),
    proto("SpacePacket", "spacepacket", min_hdr=6, variable=True, confidence=0.8),
    proto("ProtoStar", "protostar", min_hdr=1, variable=True, confidence=0.6, method="long_name"),
]

# ── Smart Grid / AMI ──
PROTOCOLS += [
    proto("DLMS/COSEM HDLC", "dlms.hdlc", min_hdr=8, variable=True, confidence=0.7, method="long_name"),
    proto("DLMS/COSEM TCP", "dlms.tcp", min_hdr=8, variable=True, confidence=0.7, method="long_name"),
    proto("ANSI C12.18", "c12.18", min_hdr=8, variable=True, confidence=0.8),
    proto("ANSI C12.22", "c12.22", min_hdr=8, variable=True, confidence=0.8),
    proto("IEC 62056-21", "iec62056", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("IEC 62056-46", "iec62056.46", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
]

# ── Printing / Document ──
PROTOCOLS += [
    proto("IPP 2.0", "ipp2", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("JetDirect", "jetdirect", min_hdr=1, variable=True, confidence=0.8),
    proto("PJL", "pjl", min_hdr=1, variable=True, confidence=0.8),
    proto("PCL", "pcl", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("PostScript", "ps", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
]

# ── Email ──
PROTOCOLS += [
    proto("SMTP TLS", "smtp.tls", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("IMAP TLS", "imap.tls", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("DKIM", "dkim", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("SPF", "spf", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("DMARC", "dmarc", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("JMAP", "jmap", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("CalDAV", "caldav", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("CardDAV", "carddav", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("EWS", "ews", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("ActiveSync", "activesync", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
]

# ── Directory / Identity ──
PROTOCOLS += [
    proto("LDAP v3", "ldap3", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("LDAP StartTLS", "ldap.starttls", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("Kerberos AS", "krb.as", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("Kerberos TGS", "krb.tgs", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("Kerberos AP", "krb.ap", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("NTLM v2", "ntlmv2", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("OAuth 2.0", "oauth2", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("SAML", "saml", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("OpenID Connect", "oidc", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("SCIM", "scim", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
]

# ── Gaming / Real-time ──
PROTOCOLS += [
    proto("Steam", "steam", min_hdr=4, variable=True, confidence=0.7, method="long_name"),
    proto("Source Engine Query", "source_engine", min_hdr=5, variable=True, confidence=0.7, method="long_name"),
    proto("Minecraft", "minecraft", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("Mumble", "mumble", min_hdr=6, variable=True, confidence=0.8),
    proto("TeamSpeak", "teamspeak", min_hdr=4, variable=True, confidence=0.7, method="long_name"),
    proto("Discord", "discord", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
]

# ── IoT cloud ──
PROTOCOLS += [
    proto("AWS IoT Core", "aws_iot", min_hdr=1, variable=True, confidence=0.6, method="long_name"),
    proto("Azure IoT Hub", "azure_iot", min_hdr=1, variable=True, confidence=0.6, method="long_name"),
    proto("Google Cloud IoT", "gcp_iot", min_hdr=1, variable=True, confidence=0.6, method="long_name"),
    proto("AMQP 1.0", "amqp10", min_hdr=8, variable=True, confidence=0.8),
    proto("MQTT 5.0", "mqtt5", min_hdr=2, variable=True, confidence=0.8),
    proto("MQTT-SN", "mqtt-sn", min_hdr=2, variable=True, confidence=0.85),
    proto("XMPP IoT", "xmpp.iot", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("LWM2M Bootstrap", "lwm2m.bs", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
]

# ── Telemetry / Observability ──
PROTOCOLS += [
    proto("OpenTelemetry OTLP", "otlp", min_hdr=5, variable=True, confidence=0.7, method="long_name"),
    proto("Prometheus Remote Write", "prometheus.rw", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("StatsD", "statsd", min_hdr=1, variable=True, confidence=0.8),
    proto("Graphite", "graphite", min_hdr=1, variable=True, confidence=0.8),
    proto("InfluxDB Line", "influxdb", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("Fluentd Forward", "fluentd", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("Jaeger Thrift", "jaeger", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("Zipkin", "zipkin", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("Collectd", "collectd", min_hdr=4, variable=True, confidence=0.85),
]

# ── Configuration / Provisioning ──
PROTOCOLS += [
    proto("DHCP Snooping", "dhcp.snoop", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("ZTP", "ztp", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("SZTP", "sztp", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("RESTCONF", "restconf", min_hdr=1, variable=True, confidence=0.8),
    proto("CORECONF", "coreconf", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("CoMI", "comi", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
]

# ── Additional well-known tshark dissectors ──
PROTOCOLS += [
    proto("AJP13", "ajp13", scapy="AJP", min_hdr=4, variable=True, confidence=0.85),
    proto("Beanstalk", "beanstalk", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("Couchbase", "couchbase", min_hdr=24, variable=True, confidence=0.85),
    proto("DTCP", "dtcp", min_hdr=4, variable=True, confidence=0.85),
    proto("Elasticsearch", "elasticsearch", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("Finger", "finger", min_hdr=1, variable=True, confidence=0.85),
    proto("Gopher", "gopher", min_hdr=1, variable=True, confidence=0.85),
    proto("GRPC-Web", "grpc-web", min_hdr=5, variable=True, confidence=0.8),
    proto("HBase", "hbase", min_hdr=4, variable=True, confidence=0.7, method="long_name"),
    proto("Hazelcast", "hazelcast", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("IEC 104", "iec104", min_hdr=6, variable=True, confidence=0.85),
    proto("IPMI", "ipmi", min_hdr=6, variable=True, confidence=0.85),
    proto("Kademlia", "kademlia", min_hdr=1, variable=True, confidence=0.8),
    proto("Kazaa", "kazaa", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("Limelight", "limelight", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("LLRP", "llrp", min_hdr=10, variable=True, confidence=0.85),
    proto("Minecraft PE", "mcpe", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("Mongo Wire v1", "mongo.v1", min_hdr=16, variable=True, confidence=0.7, method="long_name"),
    proto("NBNS", "nbns", min_hdr=12, variable=True, confidence=0.85),
    proto("NIS/YP", "nis", min_hdr=1, variable=True, confidence=0.8),
    proto("OSPF TE", "ospf.te", min_hdr=4, variable=True, confidence=0.7, method="long_name"),
    proto("OPC AE", "opcae", min_hdr=8, variable=True, confidence=0.8),
    proto("Perforce", "p4", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("PCAP-over-IP", "pcapip", min_hdr=24, variable=True, confidence=0.8),
    proto("Portmap", "portmap", min_hdr=4, variable=True, confidence=0.85),
    proto("PPTP GRE", "pptp.gre", min_hdr=8, variable=True, confidence=0.7, method="long_name"),
    proto("QUIC Initial", "quic.initial", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("QUIC Handshake", "quic.handshake", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("RDP", "rdp", scapy="RDP", min_hdr=1, variable=True, confidence=0.85),
    proto("Rlogin", "rlogin", min_hdr=1, variable=True, confidence=0.85),
    proto("RSH", "rsh", min_hdr=1, variable=True, confidence=0.85),
    proto("RTPS", "rtps", min_hdr=20, variable=True, confidence=0.85),
    proto("RX", "rx", min_hdr=28, variable=True, confidence=0.85),
    proto("SAP RFC", "saprfc", min_hdr=1, variable=True, confidence=0.85),
    proto("SAP Router", "saprouter", min_hdr=1, variable=True, confidence=0.85),
    proto("SAP Diag", "sapdiag", min_hdr=1, variable=True, confidence=0.85),
    proto("SOCKS", "socks", scapy="SOCKS", min_hdr=3, variable=True, confidence=0.85),
    proto("Tor", "tor", min_hdr=5, variable=True, confidence=0.7, method="long_name"),
    proto("Tox", "tox", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("UDT", "udt", min_hdr=16, variable=True, confidence=0.85),
    proto("VNC", "vnc", min_hdr=1, variable=True, confidence=0.85),
    proto("Whois", "whois", min_hdr=1, variable=True, confidence=0.85),
    proto("X11", "x11", min_hdr=1, variable=True, confidence=0.85),
    proto("XDMCP", "xdmcp", min_hdr=6, variable=True, confidence=0.85),
    proto("YMSG", "ymsg", min_hdr=20, variable=True, confidence=0.8),
    proto("ZAP", "zap", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("ZooKeeper", "zookeeper", min_hdr=4, variable=True, confidence=0.85),
]

# ── RPC / IPC ──
PROTOCOLS += [
    proto("SunRPC", "rpc", min_hdr=24, variable=True, confidence=0.85),
    proto("NFS v3", "nfs3", min_hdr=1, variable=True, confidence=0.85),
    proto("NFS v2", "nfs2", min_hdr=1, variable=True, confidence=0.85),
    proto("NLM", "nlm", min_hdr=1, variable=True, confidence=0.85),
    proto("NSM", "nsm", min_hdr=1, variable=True, confidence=0.85),
    proto("Mount", "mount", min_hdr=1, variable=True, confidence=0.85),
    proto("KLM", "klm", min_hdr=1, variable=True, confidence=0.8),
    proto("D-Bus", "dbus", min_hdr=12, variable=True, confidence=0.85),
    proto("Binder", "binder", min_hdr=4, variable=True, confidence=0.7, method="long_name"),
    proto("Cap'n Proto RPC", "capnproto", min_hdr=8, variable=True, confidence=0.7, method="long_name"),
]

# ── Additional Cisco ──
PROTOCOLS += [
    proto("Cisco EIGRP IPv6", "eigrp6", min_hdr=20, variable=True, confidence=0.8),
    proto("Cisco NHRP", "nhrp", min_hdr=20, variable=True, confidence=0.85),
    proto("Cisco PAgP", "pagp", min_hdr=4, variable=True, confidence=0.85),
    proto("Cisco UDLD", "udld", min_hdr=8, variable=True, confidence=0.85),
    proto("Cisco MACsec", "cisco_macsec", min_hdr=8, variable=True, confidence=0.7, method="long_name"),
    proto("Cisco CTS SGT", "cts", min_hdr=8, confidence=0.7, method="long_name"),
]

# ── Additional Telecom / Mobile ──
PROTOCOLS += [
    proto("GTPv1-C", "gtpv1c", scapy="GTPHeader", min_hdr=8, variable=True, confidence=0.85),
    proto("GTPv0", "gtpv0", min_hdr=20, variable=True, confidence=0.8),
    proto("GTP Prime", "gtp_prime", min_hdr=6, variable=True, confidence=0.8),
    proto("GPRS LLC", "gprs_llc", scapy="GprsLlc", min_hdr=3, variable=True, confidence=0.85),
    proto("GPRS SNDCP", "sndcp", min_hdr=4, variable=True, confidence=0.85),
    proto("GSM A BSSMAP", "gsm_a_bssmap", min_hdr=1, variable=True, confidence=0.8),
    proto("GSM A DTAP", "gsm_a_dtap", min_hdr=2, variable=True, confidence=0.8),
    proto("GSM A SACCH", "gsm_a_sacch", min_hdr=2, variable=True, confidence=0.7, method="long_name"),
    proto("GSM RLC/MAC", "gsm_rlcmac", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("GSM RR", "gsm_a_rr", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("GSM SMS", "gsm_sms", min_hdr=1, variable=True, confidence=0.8),
    proto("GSM SIM", "gsm_sim", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("LTE RRC", "lte_rrc", min_hdr=1, variable=True, confidence=0.85),
    proto("NR RRC", "nr_rrc", min_hdr=1, variable=True, confidence=0.85),
    proto("NAS 5GS MM", "nas_5gs_mm", min_hdr=3, variable=True, confidence=0.8),
    proto("NAS 5GS SM", "nas_5gs_sm", min_hdr=3, variable=True, confidence=0.8),
    proto("NAS EPS EMM", "nas_eps_emm", min_hdr=2, variable=True, confidence=0.8),
    proto("NAS EPS ESM", "nas_eps_esm", min_hdr=2, variable=True, confidence=0.8),
    proto("NBAP", "nbap", min_hdr=1, variable=True, confidence=0.85),
    proto("RRC", "rrc", min_hdr=1, variable=True, confidence=0.85),
    proto("RNSAP", "rnsap", min_hdr=1, variable=True, confidence=0.8),
    proto("SABP", "sabp", min_hdr=1, variable=True, confidence=0.8),
    proto("SBC-AP", "sbc_ap", min_hdr=1, variable=True, confidence=0.8),
    proto("PCAP 3GPP", "pcap_3gpp", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("HNBAP", "hnbap", min_hdr=1, variable=True, confidence=0.8),
    proto("RUA", "rua", min_hdr=1, variable=True, confidence=0.8),
    proto("F1AP", "f1ap", min_hdr=1, variable=True, confidence=0.85),
    proto("E1AP", "e1ap", min_hdr=1, variable=True, confidence=0.85),
    proto("E2AP", "e2ap", min_hdr=1, variable=True, confidence=0.85),
    proto("XnAP", "xnap", min_hdr=1, variable=True, confidence=0.85),
    proto("NRUP", "nrup", min_hdr=4, variable=True, confidence=0.8),
    proto("MAC LTE", "mac_lte", min_hdr=1, variable=True, confidence=0.85),
    proto("MAC NR", "mac_nr", min_hdr=1, variable=True, confidence=0.85),
    proto("RLC LTE", "rlc_lte", min_hdr=1, variable=True, confidence=0.85),
    proto("RLC NR", "rlc_nr", min_hdr=1, variable=True, confidence=0.85),
    proto("PDCP LTE", "pdcp_lte", min_hdr=1, variable=True, confidence=0.85),
    proto("PDCP NR", "pdcp_nr", min_hdr=1, variable=True, confidence=0.85),
]

# ── Additional SS7 / SIGTRAN ──
PROTOCOLS += [
    proto("BICC", "bicc", min_hdr=1, variable=True, confidence=0.8),
    proto("BSSAP+", "bssap_plus", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("GSM MAP CH", "gsm_map_ch", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("GSM MAP SM", "gsm_map_sm", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("GSM MAP SS", "gsm_map_ss", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("H.248", "h248", min_hdr=1, variable=True, confidence=0.85),
    proto("HLR", "gsm_map_ms", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("IUA", "iua", min_hdr=8, variable=True, confidence=0.85),
    proto("M2PA", "m2pa", min_hdr=8, variable=True, confidence=0.85),
    proto("MAP Dialog", "gsm_map_dialogue", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("SCCP XUDT", "sccp_xudt", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("TCAP ANSI", "tcap_ansi", min_hdr=1, variable=True, confidence=0.8),
    proto("V5UA", "v5ua", min_hdr=8, variable=True, confidence=0.8),
    proto("DUA", "dua", min_hdr=8, variable=True, confidence=0.8),
]

# ── Additional VoIP / Multimedia ──
PROTOCOLS += [
    proto("IAX2", "iax2", scapy="IAX2", min_hdr=12, variable=True, confidence=0.85),
    proto("Skinny SCCP", "skinny", min_hdr=12, variable=True, confidence=0.85),
    proto("MGCP", "mgcp", scapy="MGCP", min_hdr=1, variable=True, confidence=0.85),
    proto("T.38", "t38", min_hdr=1, variable=True, confidence=0.85),
    proto("RTSP", "rtsp", scapy="RTSP", min_hdr=1, variable=True, confidence=0.85),
    proto("RTMP", "rtmp", scapy="RTMP", min_hdr=1, variable=True, confidence=0.85),
    proto("HLS", "hls", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("MPEG-TS", "mp2t", scapy="MPEG_TS", min_hdr=4, confidence=0.85),
    proto("MPEG-PES", "mpeg_pes", min_hdr=6, variable=True, confidence=0.8),
    proto("RTP MIDI", "rtp_midi", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("RTCP XR", "rtcp_xr", min_hdr=4, variable=True, confidence=0.7, method="long_name"),
    proto("SDP Security", "sdp_sec", min_hdr=1, variable=True, confidence=0.6, method="long_name"),
]

# ── Additional Security / AAA ──
PROTOCOLS += [
    proto("Kerberos", "kerberos", scapy="Kerberos", min_hdr=1, variable=True, confidence=0.85),
    proto("LDAP", "ldap", scapy="LDAP", min_hdr=1, variable=True, confidence=0.85),
    proto("LDAPS", "ldaps", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("NTLM", "ntlmssp", scapy="NTLM_Header", min_hdr=1, variable=True, confidence=0.85),
    proto("SASL", "sasl", min_hdr=1, variable=True, confidence=0.85),
    proto("OCSP", "ocsp", scapy="OCSP_Response", min_hdr=1, variable=True, confidence=0.85),
    proto("CMS", "cms", min_hdr=1, variable=True, confidence=0.85),
    proto("PKCS7", "pkcs7", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("PKCS12", "pkcs12", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("CRL", "x509crl", min_hdr=1, variable=True, confidence=0.8),
    proto("PKI", "pki", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("PKIX CMP", "cmp", min_hdr=1, variable=True, confidence=0.8),
    proto("DTLS 1.2", "dtls12", min_hdr=13, variable=True, confidence=0.8),
    proto("TLS 1.2", "tls12", min_hdr=5, variable=True, confidence=0.8),
    proto("WPA EAPOL Key", "eapol_key", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
]

# ── ASN.1 / X.400 / X.500 ──
PROTOCOLS += [
    proto("ASN.1 BER", "ber", min_hdr=2, variable=True, confidence=0.85),
    proto("ASN.1 PER", "per", min_hdr=1, variable=True, confidence=0.85),
    proto("X.400 P1", "p1", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("X.400 P7", "p7", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("X.500 DAP", "dap", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("X.500 DSP", "dsp", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("X.500 DISP", "disp", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("ACSE", "acse", min_hdr=1, variable=True, confidence=0.8),
    proto("PRES", "pres", min_hdr=1, variable=True, confidence=0.8),
    proto("SES", "ses", min_hdr=1, variable=True, confidence=0.8),
    proto("RTSE", "rtse", min_hdr=1, variable=True, confidence=0.8),
    proto("ROSE", "rose", min_hdr=1, variable=True, confidence=0.8),
]

# ── Fibre Channel / SAN ──
PROTOCOLS += [
    proto("FCoE", "fcoe", scapy="FCoE", min_hdr=14, variable=True, confidence=0.85, kernel_struct="fcoe_hdr", kernel_header="uapi/scsi/fc/fc_fcoe.h"),
    proto("FIP", "fip", scapy="FIP", min_hdr=10, variable=True, confidence=0.85),
    proto("FC ELS", "fcels", min_hdr=4, variable=True, confidence=0.8),
    proto("FC NS", "fcns", min_hdr=4, variable=True, confidence=0.7, method="long_name"),
    proto("FC FCS", "fcfcs", min_hdr=4, variable=True, confidence=0.7, method="long_name"),
    proto("FC CT", "fcct", min_hdr=16, variable=True, confidence=0.8),
    proto("FC SWILS", "fcswils", min_hdr=4, variable=True, confidence=0.7, method="long_name"),
    proto("FC SP", "fcsp", min_hdr=4, variable=True, confidence=0.7, method="long_name"),
    proto("FC DNS", "fcdns", min_hdr=16, variable=True, confidence=0.7, method="long_name"),
    proto("SCSI OSD", "scsi_osd", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("SCSI SBC", "scsi_sbc", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("SCSI SSC", "scsi_ssc", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
]

# ── Windows / Microsoft ──
PROTOCOLS += [
    proto("CLDAP", "cldap", min_hdr=1, variable=True, confidence=0.85),
    proto("DRSUAPI", "drsuapi", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("EPM", "epm", min_hdr=1, variable=True, confidence=0.8),
    proto("LSARPC", "lsarpc", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("NETLOGON", "netlogon", min_hdr=1, variable=True, confidence=0.85),
    proto("SAMR", "samr", min_hdr=1, variable=True, confidence=0.85),
    proto("SRVSVC", "srvsvc", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("WINREG", "winreg", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("WKSSVC", "wkssvc", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("SPOOLSS", "spoolss", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("BROWSER", "browser", min_hdr=1, variable=True, confidence=0.85),
    proto("LANMAN", "lanman", min_hdr=1, variable=True, confidence=0.85),
    proto("NBNS", "nbns", min_hdr=12, variable=True, confidence=0.85),
    proto("NBDS", "nbds", min_hdr=1, variable=True, confidence=0.85),
    proto("MS-EVEN6", "ms_even6", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("MS-DCOM", "dcom", min_hdr=1, variable=True, confidence=0.8),
    proto("TPKT", "tpkt", scapy="TPKT", min_hdr=4, confidence=0.85),
    proto("COTP", "cotp", scapy="COTP", min_hdr=7, variable=True, confidence=0.85),
]

# ── OPC / SCADA extended ──
PROTOCOLS += [
    proto("OPC DA", "opc_da", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("OPC HDA", "opc_hda", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("OPC AE", "opc_ae", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("IEC 61850 GOOSE", "goose", scapy="GOOSE", min_hdr=8, variable=True, confidence=0.85),
    proto("IEC 61850 SV", "sv", scapy="SV", min_hdr=8, variable=True, confidence=0.85),
    proto("IEC 61850 MMS", "mms", scapy="MMS", min_hdr=1, variable=True, confidence=0.85),
    proto("EtherCAT", "ecat", scapy="EtherCat", min_hdr=2, variable=True, confidence=0.85),
    proto("POWERLINK", "epl", min_hdr=4, variable=True, confidence=0.85),
    proto("CC-Link IE", "cclink", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("HART-IP", "hartip", min_hdr=8, variable=True, confidence=0.8),
    proto("FF HSE", "ff_hse", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("SERCOS III", "sercosiii", min_hdr=1, variable=True, confidence=0.8),
    proto("ECATF", "ecatf", min_hdr=2, variable=True, confidence=0.7, method="long_name"),
    proto("EtherCAT Reg", "ecat_reg", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
]

# ── Tunneling / Overlay extended ──
PROTOCOLS += [
    proto("GUE", "gue", min_hdr=4, variable=True, confidence=0.8),
    proto("ILA", "ila", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("IPIP", "ipip", min_hdr=20, variable=True, confidence=0.85),
    proto("IP in IP", "ip_in_ip", min_hdr=20, variable=True, confidence=0.8),
    proto("SIT", "sit", min_hdr=20, variable=True, confidence=0.7, method="long_name"),
    proto("4in6", "4in6", min_hdr=20, variable=True, confidence=0.7, method="long_name"),
    proto("6in4", "6in4", min_hdr=40, variable=True, confidence=0.7, method="long_name"),
    proto("Teredo", "teredo", min_hdr=8, variable=True, confidence=0.85),
    proto("AYIYA", "ayiya", min_hdr=8, variable=True, confidence=0.8),
    proto("AMT", "amt", min_hdr=1, variable=True, confidence=0.8),
    proto("DS-Lite", "dslite", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("MAP-E", "map_e", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("VXLAN GPE", "vxlan_gpe", min_hdr=8, confidence=0.85),
    proto("STT", "stt", min_hdr=18, variable=True, confidence=0.8),
    proto("Geneve Options", "geneve_opt", min_hdr=4, variable=True, confidence=0.7, method="long_name"),
]

# ── BGP extensions ──
PROTOCOLS += [
    proto("BGP UPDATE", "bgp_update", min_hdr=4, variable=True, confidence=0.8),
    proto("BGP OPEN", "bgp_open", min_hdr=10, variable=True, confidence=0.8),
    proto("BGP NOTIFICATION", "bgp_notification", min_hdr=2, variable=True, confidence=0.8),
    proto("BGP KEEPALIVE", "bgp_keepalive", min_hdr=0, confidence=0.8),
    proto("BGP ROUTE-REFRESH", "bgp_route_refresh", min_hdr=4, confidence=0.8),
    proto("BGP Capabilities", "bgp_cap", min_hdr=2, variable=True, confidence=0.7, method="long_name"),
    proto("BGP Flowspec", "bgp_flowspec", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("BGP EVPN", "bgp_evpn", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("BGP LS", "bgp_ls", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
]

# ── MPLS / SR extended ──
PROTOCOLS += [
    proto("MPLS TP OAM", "mpls_tp_oam", min_hdr=4, variable=True, confidence=0.8),
    proto("MPLS Echo", "mpls_echo", min_hdr=4, variable=True, confidence=0.8),
    proto("SRv6 SRH", "srv6_srh", min_hdr=8, variable=True, confidence=0.85),
    proto("MPLS PW Ethernet", "mpls_pw_eth", min_hdr=4, variable=True, confidence=0.7, method="long_name"),
    proto("MPLS PW ATM", "mpls_pw_atm", min_hdr=4, variable=True, confidence=0.7, method="long_name"),
    proto("MPLS PW FR", "mpls_pw_fr", min_hdr=4, variable=True, confidence=0.7, method="long_name"),
    proto("MPLS PW HDLC", "mpls_pw_hdlc", min_hdr=4, variable=True, confidence=0.7, method="long_name"),
    proto("MPLS PW CESoPSN", "mpls_pw_cesopsn", min_hdr=4, variable=True, confidence=0.7, method="long_name"),
]

# ── Additional routing / IGP ──
PROTOCOLS += [
    proto("IS-IS LSP", "isis_lsp", min_hdr=1, variable=True, confidence=0.8),
    proto("IS-IS Hello", "isis_hello", min_hdr=1, variable=True, confidence=0.8),
    proto("OSPF LSA", "ospf_lsa", min_hdr=20, variable=True, confidence=0.8),
    proto("OSPFv3", "ospfv3", min_hdr=16, variable=True, confidence=0.85),
    proto("RIPng", "ripng", min_hdr=4, variable=True, confidence=0.85),
    proto("RIPv2", "ripv2", min_hdr=4, variable=True, confidence=0.85),
    proto("BABEL", "babel", min_hdr=4, variable=True, confidence=0.85),
    proto("OLSR", "olsr", min_hdr=4, variable=True, confidence=0.85),
    proto("BATMAN Advanced", "batadv", min_hdr=4, variable=True, confidence=0.85),
    proto("RPL", "icmpv6_rpl", min_hdr=4, variable=True, confidence=0.8),
    proto("NHRP Registration", "nhrp_reg", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
]

# ── Additional DHCP / ARP ──
PROTOCOLS += [
    proto("BOOTP", "bootp", scapy="BOOTP", min_hdr=236, variable=True, confidence=0.85),
    proto("DHCPv4 Options", "dhcp_opts", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("DHCPv6 Options", "dhcpv6_opts", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("RARP", "rarp", scapy="RARP", min_hdr=28, confidence=0.85),
    proto("InARP", "inarp", min_hdr=28, confidence=0.8),
    proto("Gratuitous ARP", "garp", min_hdr=28, confidence=0.7, method="long_name"),
]

# ── Additional well-known protocols ──
PROTOCOLS += [
    proto("LLDP-MED", "lldp_med", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("CDP TLV", "cdp_tlv", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("PVST+", "pvst", min_hdr=4, variable=True, confidence=0.8),
    proto("RSTP", "rstp", min_hdr=35, confidence=0.85),
    proto("MSTP", "mstp", min_hdr=35, variable=True, confidence=0.85),
    proto("GVRP", "gvrp", min_hdr=1, variable=True, confidence=0.85),
    proto("GMRP", "gmrp", min_hdr=1, variable=True, confidence=0.85),
    proto("MMRP", "mmrp", min_hdr=1, variable=True, confidence=0.85),
    proto("MVRP", "mvrp", min_hdr=1, variable=True, confidence=0.85),
    proto("DTP", "dtp", min_hdr=1, variable=True, confidence=0.8),
    proto("VTP", "vtp", min_hdr=1, variable=True, confidence=0.8),
    proto("ISL", "isl", min_hdr=26, variable=True, confidence=0.85),
    proto("802.3 Slow", "slow", min_hdr=2, variable=True, confidence=0.8),
    proto("Marker", "marker", min_hdr=2, confidence=0.7, method="long_name"),
    proto("OAMPDU", "oampdu", min_hdr=2, variable=True, confidence=0.8),
    proto("E-LMI", "elmi", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("CFM", "cfm", min_hdr=4, variable=True, confidence=0.85),
    proto("Y.1731", "y1731", min_hdr=4, variable=True, confidence=0.8),
    proto("PTP", "ptp", min_hdr=34, variable=True, confidence=0.85),
    proto("NTP Extension", "ntp_ext", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("PTPv1", "ptpv1", min_hdr=34, variable=True, confidence=0.8),
]

# ── PCIe / Bus protocols ──
PROTOCOLS += [
    proto("PCIe TLP", "pcie_tlp", min_hdr=12, variable=True, confidence=0.7, method="long_name"),
    proto("PCIe DLLP", "pcie_dllp", min_hdr=6, confidence=0.7, method="long_name"),
    proto("USB HID", "usbhid", min_hdr=1, variable=True, confidence=0.85),
    proto("USB Mass Storage", "usbms", min_hdr=1, variable=True, confidence=0.8),
    proto("USB Audio", "usbaudio", min_hdr=1, variable=True, confidence=0.8),
    proto("USB Video", "usbvideo", min_hdr=1, variable=True, confidence=0.8),
    proto("USB CDC", "usb_cdc", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("I2C", "i2c", min_hdr=1, variable=True, confidence=0.85),
    proto("SPI", "spi", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
]

# ── Additional DNS / Name resolution ──
PROTOCOLS += [
    proto("DNS A", "dns_a", min_hdr=4, confidence=0.7, method="long_name"),
    proto("DNS AAAA", "dns_aaaa", min_hdr=16, confidence=0.7, method="long_name"),
    proto("DNS MX", "dns_mx", min_hdr=2, variable=True, confidence=0.7, method="long_name"),
    proto("DNS SRV", "dns_srv", min_hdr=6, variable=True, confidence=0.7, method="long_name"),
    proto("DNS TXT", "dns_txt", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("DNS SOA", "dns_soa", min_hdr=20, variable=True, confidence=0.7, method="long_name"),
    proto("DNS NS", "dns_ns", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("DNS PTR", "dns_ptr", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("DNS CAA", "dns_caa", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("DNSSEC DS", "dnssec_ds", min_hdr=4, variable=True, confidence=0.7, method="long_name"),
    proto("DNSSEC RRSIG", "dnssec_rrsig", min_hdr=18, variable=True, confidence=0.7, method="long_name"),
    proto("DNSSEC NSEC", "dnssec_nsec", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("DNSSEC NSEC3", "dnssec_nsec3", min_hdr=5, variable=True, confidence=0.7, method="long_name"),
    proto("DNSSEC DNSKEY", "dnssec_dnskey", min_hdr=4, variable=True, confidence=0.7, method="long_name"),
]

# ── Blockchain / Distributed ──
PROTOCOLS += [
    proto("Ethereum DevP2P", "eth_devp2p", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("Ethereum RLPx", "eth_rlpx", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("IPFS Bitswap", "ipfs_bitswap", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("libp2p", "libp2p", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("Raft", "raft", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("Paxos", "paxos", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
]

# ── Misc tshark dissectors ──
PROTOCOLS += [
    proto("AJP13", "ajp13", scapy="AJP", min_hdr=4, variable=True, confidence=0.85),
    proto("CPHA", "cpha", min_hdr=1, variable=True, confidence=0.8),
    proto("DISTCC", "distcc", min_hdr=1, variable=True, confidence=0.8),
    proto("Elasticsearch", "elasticsearch", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("FastCGI", "fcgi", min_hdr=8, variable=True, confidence=0.85),
    proto("FTP", "ftp", scapy="FTP", min_hdr=1, variable=True, confidence=0.85),
    proto("FTP-DATA", "ftp_data", min_hdr=1, variable=True, confidence=0.85),
    proto("Gnutella", "gnutella", min_hdr=23, variable=True, confidence=0.85),
    proto("Gopher", "gopher", min_hdr=1, variable=True, confidence=0.85),
    proto("HSMS", "hsms", min_hdr=14, variable=True, confidence=0.8),
    proto("IRC", "irc", scapy="IRC", min_hdr=1, variable=True, confidence=0.85),
    proto("JXTA", "jxta", min_hdr=1, variable=True, confidence=0.8),
    proto("LPD", "lpd", min_hdr=1, variable=True, confidence=0.85),
    proto("Memcached", "memcache", scapy="Memcached", min_hdr=24, variable=True, confidence=0.85),
    proto("NNTP", "nntp", min_hdr=1, variable=True, confidence=0.85),
    proto("POP", "pop", min_hdr=1, variable=True, confidence=0.85),
    proto("RSYNC", "rsync", min_hdr=1, variable=True, confidence=0.85),
    proto("SOCKS", "socks", scapy="SOCKS", min_hdr=3, variable=True, confidence=0.85),
    proto("Squid ICP", "icp", min_hdr=20, variable=True, confidence=0.85),
    proto("SVN", "svn", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("XMPP", "xmpp", scapy="XMPP", min_hdr=1, variable=True, confidence=0.85),
    proto("YMSG v16", "ymsg16", min_hdr=20, variable=True, confidence=0.7, method="long_name"),
]

# ── Push past 1,000 ──
PROTOCOLS += [
    proto("WCCP", "wccp", min_hdr=8, variable=True, confidence=0.85),
    proto("HSRP v2", "hsrpv2", min_hdr=8, variable=True, confidence=0.85),
    proto("GLBP", "glbp", min_hdr=1, variable=True, confidence=0.8),
    proto("REP", "rep", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("UDLD v2", "udld2", min_hdr=8, variable=True, confidence=0.7, method="long_name"),
    proto("Finger", "finger", min_hdr=1, variable=True, confidence=0.85),
    proto("Daytime", "daytime", min_hdr=1, variable=True, confidence=0.85),
    proto("Quote of the Day", "qotd", min_hdr=1, variable=True, confidence=0.85),
    proto("Chargen", "chargen", min_hdr=1, variable=True, confidence=0.85),
    proto("Echo", "echo", min_hdr=1, variable=True, confidence=0.85),
    proto("Discard", "discard", min_hdr=1, variable=True, confidence=0.85),
    proto("TCPMUX", "tcpmux", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("Wake-on-LAN", "wol", min_hdr=102, confidence=0.85),
    proto("LLTD", "lltd", min_hdr=14, variable=True, confidence=0.85),
    proto("LLTP", "lltp", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("HomePlug AV", "homeplug_av", scapy="HomePlugAV", min_hdr=1, variable=True, confidence=0.8),
    proto("HomePlug 1.0", "homeplug", scapy="HomePlug", min_hdr=1, variable=True, confidence=0.85),
    proto("IEEE 1905.1", "ieee1905", min_hdr=1, variable=True, confidence=0.8),
    proto("TIPC", "tipc", min_hdr=28, variable=True, confidence=0.85),
    proto("RDP", "rdp", scapy="RDP", min_hdr=1, variable=True, confidence=0.85),
    proto("PPTP", "pptp", scapy="PPTP", min_hdr=12, variable=True, confidence=0.85, kernel_struct="pptp_addr", kernel_header="linux/if_pppox.h"),
    proto("L2F", "l2f", min_hdr=8, variable=True, confidence=0.8),
    proto("TZSP", "tzsp", min_hdr=4, variable=True, confidence=0.85),
    proto("NetFlow v5", "netflow5", min_hdr=24, variable=True, confidence=0.8),
    proto("NetFlow v9", "netflow9", min_hdr=20, variable=True, confidence=0.8),
    proto("sFlow", "sflow", scapy="sFlow5", min_hdr=28, variable=True, confidence=0.85),
    proto("IPFIX", "ipfix", min_hdr=16, variable=True, confidence=0.85),
]

# ── Network Monitoring / Telemetry ──
PROTOCOLS += [
    proto("gNMI", "gnmi", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("gNOI", "gnoi", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("OpenConfig", "openconfig", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("YANG", "yang", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("NETCONF", "netconf", min_hdr=1, variable=True, confidence=0.85),
    proto("RESTCONF", "restconf", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("BMP", "bmp", min_hdr=6, variable=True, confidence=0.85),
    proto("IPFIX Options", "ipfix_opts", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("Cisco NetFlow Lite", "netflow_lite", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("ERSPAN Type II", "erspan2", min_hdr=8, variable=True, confidence=0.8),
    proto("ERSPAN Type III", "erspan3", min_hdr=12, variable=True, confidence=0.8),
    proto("INT", "int_md", min_hdr=8, variable=True, confidence=0.7, method="long_name"),
    proto("IFA", "ifa", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("IOAM", "ioam", min_hdr=4, variable=True, confidence=0.8),
]

# ── SDN / OpenFlow extended ──
PROTOCOLS += [
    proto("OpenFlow 1.0", "of10", min_hdr=8, variable=True, confidence=0.8),
    proto("OpenFlow 1.3", "of13", min_hdr=8, variable=True, confidence=0.8),
    proto("OpenFlow 1.5", "of15", min_hdr=8, variable=True, confidence=0.8),
    proto("P4Runtime", "p4rt", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("OVSDB", "ovsdb", scapy="OVSDB", min_hdr=1, variable=True, confidence=0.85),
    proto("VXLAN EVPN", "vxlan_evpn", min_hdr=8, variable=True, confidence=0.7, method="long_name"),
    proto("EVPN", "evpn", min_hdr=1, variable=True, confidence=0.85),
    proto("LISP Map Request", "lisp_map_request", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("LISP Map Reply", "lisp_map_reply", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("PCEP", "pcep", min_hdr=4, variable=True, confidence=0.85),
    proto("ForCES", "forces", min_hdr=24, variable=True, confidence=0.85),
    proto("I2RS", "i2rs", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
]

# ── WLAN / Wireless extended ──
PROTOCOLS += [
    proto("802.11 Beacon", "wlan_beacon", min_hdr=12, variable=True, confidence=0.7, method="long_name"),
    proto("802.11 Probe Req", "wlan_probe_req", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("802.11 Probe Resp", "wlan_probe_resp", min_hdr=12, variable=True, confidence=0.7, method="long_name"),
    proto("802.11 Auth", "wlan_auth", min_hdr=6, variable=True, confidence=0.7, method="long_name"),
    proto("802.11 Assoc Req", "wlan_assoc_req", min_hdr=4, variable=True, confidence=0.7, method="long_name"),
    proto("802.11 Assoc Resp", "wlan_assoc_resp", min_hdr=6, variable=True, confidence=0.7, method="long_name"),
    proto("802.11 Action", "wlan_action", min_hdr=2, variable=True, confidence=0.7, method="long_name"),
    proto("802.11s Mesh", "wlan_mesh", min_hdr=6, variable=True, confidence=0.7, method="long_name"),
    proto("WPS", "wps", min_hdr=4, variable=True, confidence=0.85),
    proto("Wi-Fi Direct", "wifi_p2p", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("WiMAX", "wimaxasncp", min_hdr=1, variable=True, confidence=0.85),
    proto("WiMAX MAC", "wmx_mac", min_hdr=6, variable=True, confidence=0.7, method="long_name"),
    proto("LTE RLC AM", "rlc_lte_am", min_hdr=2, variable=True, confidence=0.7, method="long_name"),
    proto("LTE RLC UM", "rlc_lte_um", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("NR SDAP", "sdap_nr", min_hdr=1, variable=True, confidence=0.8),
    proto("NR BWP", "nr_bwp", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
]

# ── Automotive extended ──
PROTOCOLS += [
    proto("CAN ISO-TP", "iso_tp", scapy="ISOTP", min_hdr=1, variable=True, confidence=0.85),
    proto("CAN J1939 PGN", "j1939_pgn", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("CAN J1939 DM", "j1939_dm", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("CAN NM", "can_nm", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("FlexRay", "flexray", scapy="FlexRay", min_hdr=5, variable=True, confidence=0.85),
    proto("FlexRay TP", "flexray_tp", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("LIN", "lin", scapy="LIN", min_hdr=1, variable=True, confidence=0.85),
    proto("SENT", "sent", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("PSI5", "psi5", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("MOST", "most", min_hdr=1, variable=True, confidence=0.85),
    proto("MOST50", "most50", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("MOST150", "most150", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("DoIP Header", "doip_hdr", min_hdr=8, confidence=0.8),
]

# ── Cloud / Container networking ──
PROTOCOLS += [
    proto("Cilium", "cilium", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("Calico BIRD", "calico_bird", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("Flannel VXLAN", "flannel_vxlan", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("Weave Net", "weave", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("CNI", "cni", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("Consul DNS", "consul_dns", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("etcd", "etcd", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("Envoy xDS", "envoy_xds", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("Istio", "istio", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
]

# ── Serial / Legacy extended ──
PROTOCOLS += [
    proto("SLIP", "slip", scapy="SLIP", min_hdr=1, variable=True, confidence=0.85),
    proto("CSLIP", "cslip", min_hdr=1, variable=True, confidence=0.8),
    proto("PPP CCP", "ppp_ccp", min_hdr=4, variable=True, confidence=0.8),
    proto("PPP CHAP", "ppp_chap", min_hdr=4, variable=True, confidence=0.85),
    proto("PPP PAP", "ppp_pap", min_hdr=4, variable=True, confidence=0.85),
    proto("PPP ECP", "ppp_ecp", min_hdr=4, variable=True, confidence=0.8),
    proto("PPP MP", "ppp_mp", min_hdr=4, variable=True, confidence=0.8),
    proto("PPP IPv6CP", "ppp_ipv6cp", min_hdr=4, variable=True, confidence=0.8),
    proto("PPP BACP", "ppp_bacp", min_hdr=4, variable=True, confidence=0.7, method="long_name"),
    proto("SDLC", "sdlc", min_hdr=3, variable=True, confidence=0.85),
    proto("BSC", "bsc", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("X.21", "x21", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("V.110", "v110", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("LAPB", "lapb", min_hdr=2, variable=True, confidence=0.85),
    proto("LAPD", "lapd", min_hdr=3, variable=True, confidence=0.85),
    proto("LAPF", "lapf", min_hdr=2, variable=True, confidence=0.8),
]

# ── ATM / Frame Relay extended ──
PROTOCOLS += [
    proto("AAL1", "aal1", min_hdr=1, variable=True, confidence=0.85),
    proto("AAL2", "aal2", min_hdr=3, variable=True, confidence=0.85),
    proto("AAL3/4", "aal3_4", min_hdr=4, variable=True, confidence=0.8),
    proto("AAL5", "aal5", min_hdr=8, variable=True, confidence=0.85),
    proto("ATM OAM", "atm_oam", min_hdr=5, variable=True, confidence=0.8),
    proto("ATM Signaling", "q2931", min_hdr=9, variable=True, confidence=0.8),
    proto("ILMI", "ilmi", min_hdr=1, variable=True, confidence=0.8),
    proto("LANE", "lane", min_hdr=2, variable=True, confidence=0.8),
    proto("Frame Relay LMI", "fr_lmi", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("FR SVC", "fr_svc", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("SMDS", "smds", min_hdr=1, variable=True, confidence=0.85),
]

# ── ISDN / PSTN ──
PROTOCOLS += [
    proto("Q.921", "q921", min_hdr=3, variable=True, confidence=0.85),
    proto("Q.931", "q931", min_hdr=3, variable=True, confidence=0.85),
    proto("Q.933", "q933", min_hdr=1, variable=True, confidence=0.8),
    proto("QSIG", "qsig", min_hdr=1, variable=True, confidence=0.8),
    proto("DPNSS", "dpnss", min_hdr=1, variable=True, confidence=0.8),
    proto("DSS1", "dss1", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("V5.2", "v52", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("GR-303", "gr303", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("PRI", "isdn_pri", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("BRI", "isdn_bri", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
]

# ── Power / Smart Grid ──
PROTOCOLS += [
    proto("IEC 60870-5-101", "iec101", min_hdr=1, variable=True, confidence=0.8),
    proto("IEC 60870-5-103", "iec103", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("IEC 62351", "iec62351", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("C12.18", "c1218", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("C12.22", "c1222", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("DLMS/COSEM", "dlms", min_hdr=1, variable=True, confidence=0.85),
    proto("SEP 2.0", "sep2", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("OpenADR", "openadr", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("CIM", "cim", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("IEEE C37.118", "c37118", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("DNP3 Application", "dnp3_app", min_hdr=2, variable=True, confidence=0.7, method="long_name"),
    proto("DNP3 Transport", "dnp3_transport", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
]

# ── Building Automation extended ──
PROTOCOLS += [
    proto("BACnet/IP", "bacnet_ip", min_hdr=4, variable=True, confidence=0.8),
    proto("BACnet MSTP", "bacnet_mstp", min_hdr=8, variable=True, confidence=0.8),
    proto("BACnet APDU", "bacnet_apdu", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("BACnet NPDU", "bacnet_npdu", min_hdr=2, variable=True, confidence=0.7, method="long_name"),
    proto("DALI", "dali", min_hdr=2, confidence=0.7, method="long_name"),
    proto("EnOcean ESP3", "enocean_esp3", min_hdr=6, variable=True, confidence=0.7, method="long_name"),
    proto("LON", "lon", min_hdr=1, variable=True, confidence=0.85),
    proto("M-Bus", "mbus", scapy="MBus", min_hdr=4, variable=True, confidence=0.85),
    proto("wM-Bus", "wmbus", min_hdr=1, variable=True, confidence=0.85),
]

# ── Medical / Healthcare ──
PROTOCOLS += [
    proto("DICOM", "dicom", scapy="DICOM", min_hdr=1, variable=True, confidence=0.85),
    proto("HL7 v2", "hl7", min_hdr=1, variable=True, confidence=0.85),
    proto("HL7 FHIR", "hl7_fhir", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("IHE PIX", "ihe_pix", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("IHE PDQ", "ihe_pdq", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("POCT1-A", "poct1a", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("ISO/IEEE 11073", "ieee11073", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
]

# ── Aviation / Aerospace ──
PROTOCOLS += [
    proto("ARINC 429", "arinc429", min_hdr=4, confidence=0.85),
    proto("ARINC 664 (AFDX)", "afdx", min_hdr=1, variable=True, confidence=0.85),
    proto("MIL-STD-1553", "milstd1553", min_hdr=1, variable=True, confidence=0.8),
    proto("STANAG 4586", "stanag4586", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("ADS-B", "adsb", min_hdr=14, variable=True, confidence=0.85),
    proto("Mode S", "mode_s", min_hdr=7, variable=True, confidence=0.85),
    proto("UAT", "uat978", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("ACARS", "acars", min_hdr=1, variable=True, confidence=0.85),
    proto("VDL Mode 2", "vdl2", min_hdr=1, variable=True, confidence=0.8),
    proto("ASTERIX", "asterix", min_hdr=3, variable=True, confidence=0.85),
]

# ── SCADA / PLC extended ──
PROTOCOLS += [
    proto("Modbus RTU", "modbus_rtu", min_hdr=4, variable=True, confidence=0.8),
    proto("Modbus ASCII", "modbus_ascii", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("FINS UDP", "omron_fins_udp", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("FINS TCP", "omron_fins_tcp", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("Mitsubishi MELSEC", "melsec", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("Allen-Bradley PCCC", "pccc", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("GE SRTP", "ge_srtp", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("Emerson ROC", "roc", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("Schneider UMAS", "umas", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("IEC 61131-3", "iec61131", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
]

# ── Financial / Trading ──
PROTOCOLS += [
    proto("FIX 4.4", "fix44", min_hdr=1, variable=True, confidence=0.8),
    proto("FIX 5.0", "fix50", min_hdr=1, variable=True, confidence=0.8),
    proto("FAST", "fast", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("ITCH 5.0", "itch50", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("OUCH", "ouch", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("BATS PITCH", "bats_pitch", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("ARCA XDP", "arca_xdp", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("SBE", "sbe", min_hdr=8, variable=True, confidence=0.7, method="long_name"),
    proto("MMTP", "mmtp", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("MoldUDP64", "moldudp64", min_hdr=20, variable=True, confidence=0.8),
]

# ── Satellite / Space extended ──
PROTOCOLS += [
    proto("CCSDS Space Packet", "ccsds", scapy="CCSDS", min_hdr=6, variable=True, confidence=0.85),
    proto("CCSDS TM", "ccsds_tm", min_hdr=6, variable=True, confidence=0.8),
    proto("CCSDS TC", "ccsds_tc", min_hdr=5, variable=True, confidence=0.8),
    proto("CCSDS AOS", "ccsds_aos", min_hdr=6, variable=True, confidence=0.7, method="long_name"),
    proto("DVB-S2", "dvbs2", min_hdr=1, variable=True, confidence=0.8),
    proto("DVB-T2", "dvbt2", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("MPEG2-TS Teletext", "teletext", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("IRIG 106", "irig106", min_hdr=24, variable=True, confidence=0.8),
    proto("SpaceWire", "spacewire", min_hdr=1, variable=True, confidence=0.85),
    proto("SpaceFibre", "spacefibre", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
]

# ── Multimedia / Codecs ──
PROTOCOLS += [
    proto("H.264 NAL", "h264", scapy="H264_NAL", min_hdr=1, variable=True, confidence=0.85),
    proto("H.265 NAL", "h265", scapy="H265_NAL", min_hdr=2, variable=True, confidence=0.85),
    proto("VP8", "vp8", min_hdr=3, variable=True, confidence=0.85),
    proto("VP9", "vp9", min_hdr=1, variable=True, confidence=0.85),
    proto("AV1", "av1", min_hdr=1, variable=True, confidence=0.85),
    proto("Opus", "opus", min_hdr=1, variable=True, confidence=0.85),
    proto("AAC", "aac", min_hdr=7, variable=True, confidence=0.85),
    proto("FLAC", "flac", min_hdr=4, variable=True, confidence=0.85),
    proto("Ogg", "ogg", min_hdr=27, variable=True, confidence=0.85),
    proto("WebM", "webm", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("MIDI", "midi", min_hdr=1, variable=True, confidence=0.85),
]

# ── Additional well-known application protocols ──
PROTOCOLS += [
    proto("WebSocket", "websocket", scapy="WebSocket", min_hdr=2, variable=True, confidence=0.85),
    proto("SSE", "sse", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("GraphQL", "graphql", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("Thrift", "thrift", scapy="Thrift", min_hdr=1, variable=True, confidence=0.85),
    proto("Avro", "avro", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("Protocol Buffers", "protobuf", scapy="Protobuf", min_hdr=1, variable=True, confidence=0.85),
    proto("FlatBuffers", "flatbuffers", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("MessagePack", "msgpack", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("CBOR", "cbor", min_hdr=1, variable=True, confidence=0.85),
    proto("BSON", "bson", min_hdr=4, variable=True, confidence=0.85),
    proto("Arrow IPC", "arrow_ipc", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("Parquet", "parquet", min_hdr=4, variable=True, confidence=0.7, method="long_name"),
]


# ═══════════════════════════════════════════════════════════════
# Phase 2: Push to 1,500+ protocols
# ═══════════════════════════════════════════════════════════════

# ── 3GPP / LTE / 5G NR extended ──
PROTOCOLS += [
    proto("GTPv2 IE", "gtpv2_ie", min_hdr=4, variable=True, confidence=0.7, method="long_name"),
    proto("GTP IE", "gtp_ie", min_hdr=2, variable=True, confidence=0.7, method="long_name"),
    proto("Diameter AVP", "diameter_avp", min_hdr=8, variable=True, confidence=0.8),
    proto("Diameter 3GPP", "diameter_3gpp", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("PFCP IE", "pfcp_ie", min_hdr=4, variable=True, confidence=0.7, method="long_name"),
    proto("NGAP IE", "ngap_ie", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("S1AP IE", "s1ap_ie", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("NAS 5GS Common", "nas_5gs_common", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("GTPv1-U", "gtpv1u", min_hdr=8, variable=True, confidence=0.8),
    proto("SIP Transport", "sip_transport", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("RTP H.264", "rtp_h264", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("RTP H.265", "rtp_h265", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("RTP VP8", "rtp_vp8", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("RTP VP9", "rtp_vp9", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("RTP Opus", "rtp_opus", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("GTP TEID", "gtp_teid", min_hdr=4, confidence=0.7, method="long_name"),
]

# ── IEEE 802 family extended ──
PROTOCOLS += [
    proto("802.1AX LACP", "lacp_marker", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("802.1CB FRER", "frer", min_hdr=6, variable=True, confidence=0.7, method="long_name"),
    proto("802.1Qat SRP", "srp", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("802.1Qav CBS", "cbs", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("802.1Qbv TAS", "tas", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("802.1Qbu Frame Preemption", "frame_preempt", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("802.1Qcc", "ieee8021qcc", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("802.1AS gPTP", "gptp", min_hdr=34, variable=True, confidence=0.8),
    proto("802.3br", "ieee8023br", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("802.11k RRM", "wlan_rrm", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("802.11r FT", "wlan_ft", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("802.11v WNM", "wlan_wnm", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("802.11w PMF", "wlan_pmf", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("802.15.4 MAC", "wpan_mac", min_hdr=5, variable=True, confidence=0.8),
    proto("802.15.4g SUN", "wpan_sun", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
]

# ── DNS extended (record types as sub-protocols) ──
PROTOCOLS += [
    proto("DNS CNAME", "dns_cname", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("DNS NAPTR", "dns_naptr", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("DNS TLSA", "dns_tlsa", min_hdr=3, variable=True, confidence=0.7, method="long_name"),
    proto("DNS HTTPS", "dns_https", min_hdr=4, variable=True, confidence=0.7, method="long_name"),
    proto("DNS SVCB", "dns_svcb", min_hdr=4, variable=True, confidence=0.7, method="long_name"),
    proto("DNS LOC", "dns_loc", min_hdr=16, confidence=0.7, method="long_name"),
    proto("DNS CERT", "dns_cert", min_hdr=5, variable=True, confidence=0.7, method="long_name"),
    proto("DNS DNAME", "dns_dname", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("DNS OPT (EDNS0)", "dns_opt", min_hdr=11, variable=True, confidence=0.7, method="long_name"),
    proto("DNS TSIG", "dns_tsig", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("DNS TKEY", "dns_tkey", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("DNS IPSECKEY", "dns_ipseckey", min_hdr=3, variable=True, confidence=0.7, method="long_name"),
    proto("DNS OPENPGPKEY", "dns_openpgpkey", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
]

# ── ICMPv4/v6 message types ──
PROTOCOLS += [
    proto("ICMPv4 Echo", "icmp_echo", min_hdr=8, confidence=0.7, method="long_name"),
    proto("ICMPv4 Unreachable", "icmp_unreach", min_hdr=8, variable=True, confidence=0.7, method="long_name"),
    proto("ICMPv4 Redirect", "icmp_redirect", min_hdr=8, variable=True, confidence=0.7, method="long_name"),
    proto("ICMPv4 Time Exceeded", "icmp_timeexceeded", min_hdr=8, variable=True, confidence=0.7, method="long_name"),
    proto("ICMPv4 Timestamp", "icmp_timestamp", min_hdr=20, confidence=0.7, method="long_name"),
    proto("ICMPv6 Echo", "icmpv6_echo", min_hdr=8, confidence=0.7, method="long_name"),
    proto("ICMPv6 RS", "icmpv6_rs", min_hdr=8, variable=True, confidence=0.7, method="long_name"),
    proto("ICMPv6 RA", "icmpv6_ra", min_hdr=16, variable=True, confidence=0.7, method="long_name"),
    proto("ICMPv6 NS", "icmpv6_ns", min_hdr=24, variable=True, confidence=0.7, method="long_name"),
    proto("ICMPv6 NA", "icmpv6_na", min_hdr=24, variable=True, confidence=0.7, method="long_name"),
    proto("ICMPv6 Redirect", "icmpv6_redirect", min_hdr=40, variable=True, confidence=0.7, method="long_name"),
]

# ── TLS extensions / cipher suites ──
PROTOCOLS += [
    proto("TLS Certificate", "tls_cert", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("TLS Client Hello", "tls_client_hello", min_hdr=34, variable=True, confidence=0.7, method="long_name"),
    proto("TLS Server Hello", "tls_server_hello", min_hdr=34, variable=True, confidence=0.7, method="long_name"),
    proto("TLS Alert", "tls_alert", min_hdr=2, confidence=0.7, method="long_name"),
    proto("TLS Change Cipher", "tls_change_cipher", min_hdr=1, confidence=0.7, method="long_name"),
    proto("TLS Heartbeat", "tls_heartbeat", min_hdr=3, variable=True, confidence=0.7, method="long_name"),
    proto("TLS 1.3", "tls13", min_hdr=5, variable=True, confidence=0.8),
    proto("DTLS 1.3", "dtls13", min_hdr=14, variable=True, confidence=0.8),
    proto("QUIC Initial", "quic_initial", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("QUIC Handshake", "quic_handshake", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("QUIC 0-RTT", "quic_0rtt", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("QUIC Retry", "quic_retry", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
]

# ── HTTP/2 and HTTP/3 frame types ──
PROTOCOLS += [
    proto("HTTP/2 DATA", "http2_data", min_hdr=9, variable=True, confidence=0.7, method="long_name"),
    proto("HTTP/2 HEADERS", "http2_headers", min_hdr=9, variable=True, confidence=0.7, method="long_name"),
    proto("HTTP/2 SETTINGS", "http2_settings", min_hdr=9, variable=True, confidence=0.7, method="long_name"),
    proto("HTTP/2 PUSH_PROMISE", "http2_push_promise", min_hdr=13, variable=True, confidence=0.7, method="long_name"),
    proto("HTTP/2 GOAWAY", "http2_goaway", min_hdr=17, variable=True, confidence=0.7, method="long_name"),
    proto("HTTP/2 WINDOW_UPDATE", "http2_window_update", min_hdr=13, confidence=0.7, method="long_name"),
    proto("HTTP/2 PING", "http2_ping", min_hdr=17, confidence=0.7, method="long_name"),
    proto("HTTP/3 Frame", "http3_frame", min_hdr=2, variable=True, confidence=0.7, method="long_name"),
    proto("HTTP/3 QPACK", "http3_qpack", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
]

# ── RADIUS attributes ──
PROTOCOLS += [
    proto("RADIUS Access-Request", "radius_access_request", min_hdr=20, variable=True, confidence=0.7, method="long_name"),
    proto("RADIUS Access-Accept", "radius_access_accept", min_hdr=20, variable=True, confidence=0.7, method="long_name"),
    proto("RADIUS Accounting", "radius_accounting", min_hdr=20, variable=True, confidence=0.7, method="long_name"),
    proto("RADIUS CoA", "radius_coa", min_hdr=20, variable=True, confidence=0.7, method="long_name"),
    proto("RADIUS EAP", "radius_eap", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
]

# ── SNMP versions ──
PROTOCOLS += [
    proto("SNMPv1", "snmpv1", min_hdr=1, variable=True, confidence=0.8),
    proto("SNMPv2c", "snmpv2c", min_hdr=1, variable=True, confidence=0.8),
    proto("SNMPv3", "snmpv3", min_hdr=1, variable=True, confidence=0.85),
    proto("SNMP Trap", "snmp_trap", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("SNMP Inform", "snmp_inform", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
]

# ── Additional IoT protocols ──
PROTOCOLS += [
    proto("Matter", "matter", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("HomeKit", "homekit", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("Weave", "weave", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("LwM2M", "lwm2m", min_hdr=1, variable=True, confidence=0.85),
    proto("LWP", "lwp", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("OCF", "ocf", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("AllJoyn", "alljoyn", min_hdr=1, variable=True, confidence=0.85),
    proto("AMQP 1.0", "amqp10", min_hdr=8, variable=True, confidence=0.8),
    proto("STOMP", "stomp", min_hdr=1, variable=True, confidence=0.85),
    proto("CoAP Block", "coap_block", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("CoAP Observe", "coap_observe", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("LPWan", "lpwan", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("Sigfox", "sigfox", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("NB-IoT", "nb_iot", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("LoRaWAN MAC", "lorawan_mac", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("Bluetooth Mesh", "btmesh", min_hdr=1, variable=True, confidence=0.85),
    proto("Bluetooth Mesh Provisioning", "btmesh_prov", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("Bluetooth Mesh Proxy", "btmesh_proxy", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("BLE GATT", "btatt_gatt", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("BLE GAP", "btatt_gap", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("BLE SM", "btsmp", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("Zigbee Cluster", "zbee_zcl", min_hdr=3, variable=True, confidence=0.85),
    proto("Zigbee GP", "zbee_gp", min_hdr=1, variable=True, confidence=0.8),
    proto("Zigbee SE", "zbee_se", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
]

# ── Industrial / SCADA extended ──
PROTOCOLS += [
    proto("OPC UA Secure Channel", "opcua_sc", min_hdr=12, variable=True, confidence=0.7, method="long_name"),
    proto("OPC UA Binary", "opcua_binary", min_hdr=8, variable=True, confidence=0.7, method="long_name"),
    proto("OPC UA Services", "opcua_services", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("CIP Safety", "cip_safety", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("CIP Motion", "cip_motion", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("EtherNet/IP Encap", "enip_encap", min_hdr=24, variable=True, confidence=0.8),
    proto("EtherNet/IP CPF", "enip_cpf", min_hdr=4, variable=True, confidence=0.7, method="long_name"),
    proto("PROFINET IO", "pn_io", min_hdr=1, variable=True, confidence=0.85),
    proto("PROFINET RT", "pn_rt", min_hdr=4, variable=True, confidence=0.85),
    proto("PROFINET IRT", "pn_irt", min_hdr=4, variable=True, confidence=0.8),
    proto("PROFINET CM", "pn_cm", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("Modbus TCP Unit ID", "modbus_uid", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("DNP3 Link", "dnp3_link", min_hdr=10, variable=True, confidence=0.7, method="long_name"),
    proto("IEC 61850 SCL", "iec61850_scl", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("TSN Frame", "tsn", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("OPC UA PubSub", "opcua_pubsub", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
]

# ── Cisco / Vendor extended ──
PROTOCOLS += [
    proto("Cisco FabricPath", "fabricpath", min_hdr=16, variable=True, confidence=0.8),
    proto("Cisco OTV", "otv", min_hdr=8, variable=True, confidence=0.8),
    proto("Cisco VN-Tag", "vntag", min_hdr=4, confidence=0.85),
    proto("Cisco IST", "cisco_ist", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("Cisco IAPP", "cisco_iapp", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("Cisco WLCCP", "wlccp", min_hdr=1, variable=True, confidence=0.85),
    proto("Cisco ACI", "cisco_aci", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("Cisco NSF", "cisco_nsf", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("Cisco Smart Install", "cisco_smartinstall", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("Juniper JNX", "juniper", min_hdr=1, variable=True, confidence=0.85),
    proto("Juniper Packet Mirror", "jmirror", min_hdr=8, variable=True, confidence=0.8),
    proto("Nokia SROS", "nokia_sros", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("Arista DANZ", "arista_danz", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("F5 iRule", "f5_irule", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("Brocade ISL", "brocade_isl", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
]

# ── Database / Middleware extended ──
PROTOCOLS += [
    proto("Oracle TNS", "tns", min_hdr=8, variable=True, confidence=0.85),
    proto("Oracle Net8", "net8", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("MSSQL TDS", "tds", min_hdr=8, variable=True, confidence=0.85),
    proto("Sybase TDS", "sybase_tds", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("CouchDB", "couchdb", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("HBase", "hbase", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("Couchbase MCBP", "couchbase", min_hdr=24, variable=True, confidence=0.8),
    proto("InfluxDB", "influxdb", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("ClickHouse", "clickhouse", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("ScyllaDB CQL", "scylladb", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("RabbitMQ", "rabbitmq", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("ActiveMQ OpenWire", "activemq", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("Apache Pulsar", "pulsar", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("NATS", "nats", min_hdr=1, variable=True, confidence=0.85),
]

# ── Container / Orchestration extended ──
PROTOCOLS += [
    proto("Docker API", "docker_api", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("containerd", "containerd", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("CRI-O", "crio", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("Kubernetes API", "k8s_api", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("Kubernetes DNS", "k8s_dns", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("Linkerd", "linkerd", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("Consul", "consul", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("Vault", "vault", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("Nomad", "nomad", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("Prometheus Remote Write", "prom_remote_write", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("OpenTelemetry OTLP", "otlp", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("Jaeger Thrift", "jaeger_thrift", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("Zipkin", "zipkin", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
]

# ── Routing protocol extensions ──
PROTOCOLS += [
    proto("BGP MP-REACH-NLRI", "bgp_mp_reach", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("BGP MP-UNREACH-NLRI", "bgp_mp_unreach", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("BGP Extended Community", "bgp_ext_community", min_hdr=8, confidence=0.7, method="long_name"),
    proto("BGP Large Community", "bgp_large_community", min_hdr=12, confidence=0.7, method="long_name"),
    proto("OSPF Hello", "ospf_hello", min_hdr=20, variable=True, confidence=0.7, method="long_name"),
    proto("OSPF DB Description", "ospf_dbdesc", min_hdr=8, variable=True, confidence=0.7, method="long_name"),
    proto("OSPF LS Request", "ospf_lsr", min_hdr=12, variable=True, confidence=0.7, method="long_name"),
    proto("OSPF LS Update", "ospf_lsu", min_hdr=4, variable=True, confidence=0.7, method="long_name"),
    proto("OSPF LS Ack", "ospf_lsack", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("IS-IS CSN", "isis_csnp", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("IS-IS PSN", "isis_psnp", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("IS-IS TLV", "isis_tlv", min_hdr=2, variable=True, confidence=0.7, method="long_name"),
    proto("LDP Hello", "ldp_hello", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("LDP Address", "ldp_address", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("LDP Label Mapping", "ldp_label_mapping", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("RSVP Path", "rsvp_path", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("RSVP Resv", "rsvp_resv", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("RSVP-TE", "rsvp_te", min_hdr=1, variable=True, confidence=0.8),
    proto("PIM Hello", "pim_hello", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("PIM Join/Prune", "pim_join_prune", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("PIM Register", "pim_register", min_hdr=8, variable=True, confidence=0.7, method="long_name"),
    proto("MSDP", "msdp", min_hdr=1, variable=True, confidence=0.85),
]

# ── Security / Crypto extended ──
PROTOCOLS += [
    proto("IKEv1", "isakmp_v1", min_hdr=28, variable=True, confidence=0.8),
    proto("IKEv2 AUTH", "ikev2_auth", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("IKEv2 SA Init", "ikev2_sa_init", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("EAP-TLS", "eap_tls", min_hdr=1, variable=True, confidence=0.8),
    proto("EAP-TTLS", "eap_ttls", min_hdr=1, variable=True, confidence=0.8),
    proto("EAP-PEAP", "eap_peap", min_hdr=1, variable=True, confidence=0.8),
    proto("EAP-SIM", "eap_sim", min_hdr=1, variable=True, confidence=0.8),
    proto("EAP-AKA", "eap_aka", min_hdr=1, variable=True, confidence=0.8),
    proto("EAP-FAST", "eap_fast", min_hdr=1, variable=True, confidence=0.8),
    proto("MACsec SecY", "macsec_secy", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("MACsec SecTAG", "macsec_sectag", min_hdr=8, variable=True, confidence=0.7, method="long_name"),
    proto("WPA3 SAE", "wpa3_sae", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("WPA3 OWE", "wpa3_owe", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("IEEE 802.1AE", "ieee8021ae", min_hdr=8, variable=True, confidence=0.8),
    proto("RADIUS/TLS", "radsec", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("Wireguard Handshake Init", "wg_init", min_hdr=148, confidence=0.7, method="long_name"),
    proto("Wireguard Handshake Resp", "wg_resp", min_hdr=92, confidence=0.7, method="long_name"),
    proto("Wireguard Transport", "wg_transport", min_hdr=16, variable=True, confidence=0.7, method="long_name"),
]

# ── Multicast / Anycast ──
PROTOCOLS += [
    proto("PIM-SM", "pim_sm", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("PIM-DM", "pim_dm", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("PIM-SSM", "pim_ssm", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("PIM-BIDIR", "pim_bidir", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("IGMP Membership Query", "igmp_query", min_hdr=8, variable=True, confidence=0.7, method="long_name"),
    proto("IGMP Membership Report", "igmp_report", min_hdr=8, confidence=0.7, method="long_name"),
    proto("IGMP Leave", "igmp_leave", min_hdr=8, confidence=0.7, method="long_name"),
    proto("MLD Query", "mld_query", min_hdr=24, variable=True, confidence=0.7, method="long_name"),
    proto("MLD Report", "mld_report", min_hdr=24, confidence=0.7, method="long_name"),
    proto("DVMRP", "dvmrp", min_hdr=1, variable=True, confidence=0.85),
    proto("MOSPF", "mospf", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("AMT Relay", "amt_relay", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
]

# ── IPv6 extensions ──
PROTOCOLS += [
    proto("IPv6 HBH Options", "ipv6_hbh", min_hdr=8, variable=True, confidence=0.8),
    proto("IPv6 MH", "mipv6", min_hdr=8, variable=True, confidence=0.85),
    proto("IPv6 Shim6", "shim6", min_hdr=1, variable=True, confidence=0.85),
    proto("IPv6 HIP", "hip", min_hdr=40, variable=True, confidence=0.85),
    proto("IPv6 ILNPv6", "ilnpv6", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("IPv6 SRH TLV", "srv6_tlv", min_hdr=2, variable=True, confidence=0.7, method="long_name"),
]

# ── Well-known tshark dissectors batch 2 ──
PROTOCOLS += [
    proto("ANCP", "ancp", min_hdr=4, variable=True, confidence=0.85),
    proto("ASAP", "asap", min_hdr=1, variable=True, confidence=0.85),
    proto("BEEP", "beep", min_hdr=1, variable=True, confidence=0.85),
    proto("BACnet BVLC", "bvlc", min_hdr=4, variable=True, confidence=0.85),
    proto("CAPWAP Data", "capwap_data", min_hdr=8, variable=True, confidence=0.8),
    proto("COPS", "cops", min_hdr=8, variable=True, confidence=0.85),
    proto("DCCP Service Code", "dccp_sc", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("DIS", "dis", min_hdr=12, variable=True, confidence=0.85),
    proto("DTCP", "dtcp", min_hdr=1, variable=True, confidence=0.85),
    proto("ENRP", "enrp", min_hdr=1, variable=True, confidence=0.85),
    proto("FCIP", "fcip", min_hdr=1, variable=True, confidence=0.85),
    proto("iFCP", "ifcp", min_hdr=1, variable=True, confidence=0.85),
    proto("FORCES FE", "forces_fe", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("GTP' CDR", "gtp_cdr", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("HiQnet", "hiqnet", min_hdr=1, variable=True, confidence=0.85),
    proto("HL7 MLLP", "hl7_mllp", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("IPDC", "ipdc", min_hdr=1, variable=True, confidence=0.85),
    proto("L2TP AVP", "l2tp_avp", min_hdr=6, variable=True, confidence=0.7, method="long_name"),
    proto("LISP Control", "lisp_control", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("LMP", "lmp", min_hdr=12, variable=True, confidence=0.85),
    proto("Mojito", "mojito", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("MPTCP", "mptcp", min_hdr=4, variable=True, confidence=0.85),
    proto("NCS", "ncs", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("NORM", "norm", min_hdr=1, variable=True, confidence=0.85),
    proto("OMAPI", "omapi", min_hdr=24, variable=True, confidence=0.85),
    proto("PCP", "pcp", min_hdr=24, variable=True, confidence=0.85),
    proto("PKTC", "pktc", min_hdr=1, variable=True, confidence=0.85),
    proto("R-GOOSE", "r_goose", min_hdr=1, variable=True, confidence=0.8),
    proto("R-SV", "r_sv", min_hdr=1, variable=True, confidence=0.8),
    proto("RELOAD", "reload", min_hdr=1, variable=True, confidence=0.85),
    proto("ROC", "roc", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("RSERPOOL", "rserpool", min_hdr=1, variable=True, confidence=0.85),
    proto("SABP", "sabp_proto", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("SCTP Init", "sctp_init", min_hdr=16, variable=True, confidence=0.7, method="long_name"),
    proto("SCTP Data", "sctp_data", min_hdr=16, variable=True, confidence=0.7, method="long_name"),
    proto("SCTP SACK", "sctp_sack", min_hdr=16, variable=True, confidence=0.7, method="long_name"),
    proto("SLP", "srvloc", min_hdr=1, variable=True, confidence=0.85),
    proto("SMPP Operations", "smpp_ops", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("TALI", "tali", min_hdr=16, variable=True, confidence=0.85),
    proto("TCP Option MSS", "tcp_mss", min_hdr=4, confidence=0.7, method="long_name"),
    proto("TCP Option Window Scale", "tcp_ws", min_hdr=3, confidence=0.7, method="long_name"),
    proto("TCP Option SACK", "tcp_sack", min_hdr=2, variable=True, confidence=0.7, method="long_name"),
    proto("TCP Option Timestamp", "tcp_ts", min_hdr=10, confidence=0.7, method="long_name"),
    proto("TCP Option Fast Open", "tcp_tfo", min_hdr=2, variable=True, confidence=0.7, method="long_name"),
    proto("TURN", "turn", min_hdr=20, variable=True, confidence=0.85),
    proto("ULP", "ulp", min_hdr=1, variable=True, confidence=0.85),
    proto("V5DL", "v5dl", min_hdr=1, variable=True, confidence=0.85),
    proto("VINES IP", "vines_ip", min_hdr=18, variable=True, confidence=0.85),
    proto("VUZE DHT", "vuze_dht", min_hdr=1, variable=True, confidence=0.85),
    proto("WBXML", "wbxml", min_hdr=1, variable=True, confidence=0.85),
    proto("WTP", "wtp", min_hdr=3, variable=True, confidence=0.85),
    proto("XMPP IQ", "xmpp_iq", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("XMPP Message", "xmpp_message", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("XMPP Presence", "xmpp_presence", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("YAMI", "yami", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
]


# ── MPLS applications ──
PROTOCOLS += [
    proto("MPLS LDP FEC", "ldp_fec", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("MPLS RSVP-TE ERO", "rsvp_ero", min_hdr=4, variable=True, confidence=0.7, method="long_name"),
    proto("MPLS RSVP-TE RRO", "rsvp_rro", min_hdr=4, variable=True, confidence=0.7, method="long_name"),
    proto("MPLS BFD", "mpls_bfd", min_hdr=24, variable=True, confidence=0.7, method="long_name"),
    proto("MPLS TE Tunnel", "mpls_te_tunnel", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("MPLS VPN", "mpls_vpn", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("VPLS", "vpls", min_hdr=1, variable=True, confidence=0.85),
    proto("EVPN VXLAN", "evpn_vxlan", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("L3VPN", "l3vpn", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("L2VPN", "l2vpn", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("MVPN", "mvpn", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
]

# ── Network Testing / Measurement ──
PROTOCOLS += [
    proto("TWAMP", "twamp", min_hdr=14, variable=True, confidence=0.85),
    proto("TWAMP Test", "twamp_test", min_hdr=14, variable=True, confidence=0.7, method="long_name"),
    proto("OWAMP", "owamp", min_hdr=1, variable=True, confidence=0.85),
    proto("Y.1564", "y1564", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("RFC 2544", "rfc2544", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("LBMS", "lbms", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("ETH-LB", "eth_lb", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("ETH-LT", "eth_lt", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("ETH-AIS", "eth_ais", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("ETH-LCK", "eth_lck", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
]

# ── Segment Routing ──
PROTOCOLS += [
    proto("SR-MPLS", "sr_mpls", min_hdr=4, variable=True, confidence=0.8),
    proto("SRv6 End", "srv6_end", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("SRv6 End.X", "srv6_end_x", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("SRv6 End.T", "srv6_end_t", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("SRv6 End.DT4", "srv6_end_dt4", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("SRv6 End.DT6", "srv6_end_dt6", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("SRv6 End.B6", "srv6_end_b6", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("SRv6 H.Encaps", "srv6_h_encaps", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("SR Policy", "sr_policy", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("SR TE", "sr_te", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
]

# ── Data Center extended ──
PROTOCOLS += [
    proto("RoCEv1", "rocev1", min_hdr=1, variable=True, confidence=0.8),
    proto("iWARP", "iwarp", min_hdr=1, variable=True, confidence=0.85),
    proto("iWARP MPA", "iwarp_mpa", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("iWARP DDP", "iwarp_ddp", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("iWARP RDMAP", "iwarp_rdmap", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("DCB", "dcb", min_hdr=1, variable=True, confidence=0.85),
    proto("DCBx", "dcbx", min_hdr=1, variable=True, confidence=0.85),
    proto("PFC", "pfc", min_hdr=1, variable=True, confidence=0.85),
    proto("ETS", "ets", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("CNM", "cnm", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("DCQCN", "dcqcn", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("ECN", "ecn", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("DCTCP", "dctcp", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("NVMe over TCP", "nvme_tcp", min_hdr=8, variable=True, confidence=0.85),
    proto("NVMe over RDMA", "nvme_rdma", min_hdr=1, variable=True, confidence=0.8),
    proto("NVMe over FC", "nvme_fc", min_hdr=1, variable=True, confidence=0.8),
]

# ── GPS / Timing ──
PROTOCOLS += [
    proto("NMEA 0183", "nmea0183", min_hdr=1, variable=True, confidence=0.85),
    proto("NMEA 2000", "nmea2000", min_hdr=1, variable=True, confidence=0.85),
    proto("IRIG-B", "irig_b", min_hdr=1, variable=True, confidence=0.8),
    proto("PPS", "pps", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("White Rabbit", "white_rabbit", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("PTP Announce", "ptp_announce", min_hdr=34, variable=True, confidence=0.7, method="long_name"),
    proto("PTP Sync", "ptp_sync", min_hdr=34, confidence=0.7, method="long_name"),
    proto("PTP Follow Up", "ptp_followup", min_hdr=34, confidence=0.7, method="long_name"),
    proto("PTP Delay Req", "ptp_delay_req", min_hdr=34, confidence=0.7, method="long_name"),
    proto("PTP Delay Resp", "ptp_delay_resp", min_hdr=34, confidence=0.7, method="long_name"),
    proto("PTP Signaling", "ptp_signaling", min_hdr=34, variable=True, confidence=0.7, method="long_name"),
    proto("PTP Management", "ptp_management", min_hdr=34, variable=True, confidence=0.7, method="long_name"),
]

# ── NFV / Virtualization ──
PROTOCOLS += [
    proto("VIRTIO Net", "virtio_net", min_hdr=10, variable=True, confidence=0.85),
    proto("VHOST-USER", "vhost_user", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("AF_XDP", "af_xdp", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("DPDK", "dpdk", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("VPP", "vpp", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("eBPF", "ebpf", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("SR-IOV", "sriov", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("Open vSwitch NX", "ovs_nx", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
]

# ── Energy / Smart Meter ──
PROTOCOLS += [
    proto("ANSI C12.19", "c1219", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("IEC 62056-21", "iec62056_21", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("COSEM APDU", "cosem_apdu", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("PRIME PLC", "prime_plc", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("G3-PLC", "g3_plc", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("HomePlug Green PHY", "homeplug_gp", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("IEEE 1901", "ieee1901", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
]

# ── Printing / Document extended ──
PROTOCOLS += [
    proto("JetDirect", "jetdirect", min_hdr=1, variable=True, confidence=0.85),
    proto("LPR", "lpr", min_hdr=1, variable=True, confidence=0.85),
    proto("CUPS", "cups", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("Bonjour", "bonjour", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("WSD", "wsd", min_hdr=1, variable=True, confidence=0.85),
    proto("BJNP", "bjnp", min_hdr=1, variable=True, confidence=0.85),
]

# ── Acoustic / Audio networking ──
PROTOCOLS += [
    proto("AES67", "aes67", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("Dante Audio", "dante", min_hdr=1, variable=True, confidence=0.85),
    proto("AVB AVTP", "avtp", min_hdr=12, variable=True, confidence=0.85),
    proto("IEEE 1722", "ieee1722", min_hdr=12, variable=True, confidence=0.8),
    proto("Livewire", "livewire", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("Ravenna", "ravenna", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("AES70 (OCA)", "aes70", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("MIDI over IP (RTP-MIDI)", "rtpmidi", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
]

# ── Video / Broadcast ──
PROTOCOLS += [
    proto("SMPTE 2022", "smpte2022", min_hdr=1, variable=True, confidence=0.8),
    proto("SMPTE 2110", "smpte2110", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("SMPTE ST 2059 (PTP Profile)", "smpte2059", min_hdr=34, variable=True, confidence=0.7, method="long_name"),
    proto("NDI", "ndi", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("SRT (Secure Reliable Transport)", "srt_proto", min_hdr=16, variable=True, confidence=0.8),
    proto("RIST", "rist", min_hdr=1, variable=True, confidence=0.85),
    proto("Zixi", "zixi", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("SCTE-35", "scte35", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("DVB-CI+", "dvb_ci_plus", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("HbbTV", "hbbtv", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
]

# ── Cloud / Object Storage ──
PROTOCOLS += [
    proto("S3 (HTTP)", "s3_http", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("Swift (HTTP)", "swift_http", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("Ceph RADOS", "ceph_rados", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("Ceph RBD", "ceph_rbd", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("MinIO", "minio", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("GlusterFS", "glusterfs", min_hdr=1, variable=True, confidence=0.85),
    proto("Lustre", "lustre", min_hdr=1, variable=True, confidence=0.85),
    proto("HDFS", "hdfs", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("MapR-FS", "maprfs", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
]

# ── DNS-over-X ──
PROTOCOLS += [
    proto("DNS-over-HTTPS (DoH)", "doh", min_hdr=1, variable=True, confidence=0.8),
    proto("DNS-over-TLS (DoT)", "dot", min_hdr=1, variable=True, confidence=0.8),
    proto("DNS-over-QUIC (DoQ)", "doq", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("DNSCrypt", "dnscrypt", min_hdr=1, variable=True, confidence=0.85),
    proto("Oblivious DoH (ODoH)", "odoh", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
]

# ── Peer-to-peer / File sharing ──
PROTOCOLS += [
    proto("BitTorrent DHT", "bt_dht", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("BitTorrent PEX", "bt_pex", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("BitTorrent uTP", "bt_utp", min_hdr=20, variable=True, confidence=0.85),
    proto("eDonkey", "edonkey", min_hdr=1, variable=True, confidence=0.85),
    proto("Kad", "kad", min_hdr=1, variable=True, confidence=0.85),
    proto("IPFS", "ipfs", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("libp2p Noise", "libp2p_noise", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("libp2p Yamux", "libp2p_yamux", min_hdr=12, variable=True, confidence=0.7, method="long_name"),
]

# ── QUIC applications ──
PROTOCOLS += [
    proto("QUIC DATAGRAM", "quic_datagram", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("WebTransport", "webtransport", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("MASQUE", "masque", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("QUIC-LB", "quic_lb", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
]

# ── Additional Bluetooth ──
PROTOCOLS += [
    proto("BLE L2CAP CoC", "ble_l2cap_coc", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("BLE ISO", "ble_iso", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("BLE CIS", "ble_cis", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("BLE BIS", "ble_bis", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("Bluetooth BR/EDR", "bt_bredr", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("Bluetooth LMP", "bt_lmp", min_hdr=1, variable=True, confidence=0.85),
    proto("Bluetooth Baseband", "bt_baseband", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
]

# ── TSN (Time-Sensitive Networking) ──
PROTOCOLS += [
    proto("IEEE 802.1Qbv Gate Control", "tsn_gate", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("IEEE 802.1Qci PSFP", "tsn_psfp", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("IEEE 802.1Qch CQF", "tsn_cqf", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("IEEE 802.1CB FRER R-Tag", "frer_rtag", min_hdr=6, confidence=0.7, method="long_name"),
    proto("DetNet", "detnet", min_hdr=1, variable=True, confidence=0.85),
    proto("DetNet MPLS", "detnet_mpls", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("DetNet IP", "detnet_ip", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
]

# ── Misc well-known ──
PROTOCOLS += [
    proto("ARPD", "arpd", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("CDP TLV Power", "cdp_power", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("CIFS", "cifs", min_hdr=1, variable=True, confidence=0.85),
    proto("DDP", "ddp", min_hdr=1, variable=True, confidence=0.85),
    proto("DHCP Relay", "dhcp_relay", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("DRBD", "drbd", min_hdr=1, variable=True, confidence=0.85),
    proto("Ganglia", "ganglia", min_hdr=1, variable=True, confidence=0.85),
    proto("Git Protocol", "git", min_hdr=1, variable=True, confidence=0.85),
    proto("LLDP-MIB", "lldp_mib", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("NAT-PMP", "nat_pmp", min_hdr=2, variable=True, confidence=0.85),
    proto("UPnP IGD", "upnp_igd", min_hdr=1, variable=True, confidence=0.7, method="long_name"),
    proto("mDNS-SD", "dns_sd", min_hdr=12, variable=True, confidence=0.8),
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
