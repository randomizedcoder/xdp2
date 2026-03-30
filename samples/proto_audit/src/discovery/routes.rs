//! Auto-STACK_ROUTES: derive protocol stacking from tshark decode tables.
//!
//! Maps tshark decode table names to parent protocols and dispatch fields,
//! enabling PCAP generation for discovered-tier protocols.

use super::tshark_registry::TsharkRegistry;

/// A discovered stack route (same semantics as the curated STACK_ROUTES entries).
#[derive(Debug, Clone)]
pub struct StackRoute {
    pub child: String,
    pub parent: String,
    pub dispatch_field: String,
    pub dispatch_value: u64,
}

/// Known decode table → (parent_protocol, dispatch_field) mappings.
///
/// These are the tshark decode tables we know how to map to PCAP stack routes.
const DECODE_TABLE_MAP: &[(&str, &str, &str)] = &[
    // ── Core L2 ──
    ("ethertype",           "Ethernet",       "ether_type"),
    ("wtap_encap",          "Ethernet",       "ether_type"),
    ("sll.ltype",           "SLL",            "protocol"),
    ("llc.dsap",            "LLC",            "dsap"),
    ("llc.type",            "LLC",            "type"),
    ("snap.type",           "SNAP",           "type"),
    ("vlan.etype",          "VLAN",           "ether_type"),
    ("pbb.etype",           "PBB",            "ether_type"),
    // ── Core L3 ──
    ("ip.proto",            "IPv4",           "protocol"),
    ("ipv6.nxt",            "IPv6",           "next_header"),
    ("arp.opcode",          "ARP",            "opcode"),
    // ── Core L4 ──
    ("udp.port",            "UDP",            "dst_port"),
    ("tcp.port",            "TCP",            "dst_port"),
    ("sctp.port",           "SCTP",           "dst_port"),
    ("sctp.ppi",            "SCTP",           "ppid"),
    ("dccp.port",           "DCCP",           "dst_port"),
    ("udplite.port",        "UDPLite",        "dst_port"),
    // ── Tunneling ──
    ("gre.proto",           "GRE",            "protocol_type"),
    ("ppp.protocol",        "PPP",            "protocol"),
    ("pppoe.session",       "PPPoE",          "session_id"),
    ("l2tp.pw_type",        "L2TP",           "pw_type"),
    ("geneve.protocol",     "Geneve",         "protocol_type"),
    ("mpls.label",          "MPLS",           "label"),
    ("vxlan.vni",           "VXLAN",          "vni"),
    ("nsh.next_proto",      "NSH",            "next_protocol"),
    ("gtp.message_type",    "GTP_U",          "message_type"),
    ("gtpv2.message_type",  "GTP_C",          "message_type"),
    // ── IPv6 Extensions ──
    ("ipv6.routing.type",   "IPv6_Routing",   "routing_type"),
    ("ipv6.opt.type",       "IPv6_EH",        "option_type"),
    // ── Security ──
    ("tls.handshake.type",  "TLS",            "content_type"),
    ("dtls.record.content_type", "DTLS",      "content_type"),
    ("isakmp.nextpayload",  "IKEv2",          "next_payload"),
    ("eap.type",            "EAP",            "type"),
    // ── Bluetooth ──
    ("bthci_cmd.opcode",    "HCI_CMD",        "opcode"),
    ("btl2cap.cid",         "L2CAP",          "cid"),
    ("btl2cap.psm",         "L2CAP",          "psm"),
    ("btrfcomm.dlci",       "BT_RFCOMM",      "dlci"),
    ("btbnep.type",         "BT_BNEP",        "type"),
    // ── InfiniBand ──
    ("infiniband.opcode",   "IB_BTH",         "opcode"),
    ("infiniband.mad.class", "IB_MAD",        "mgmt_class"),
    // ── CAN ──
    ("can.id",              "CAN",            "id"),
    // ── Management ──
    ("lldp.tlv.type",       "LLDP",           "tlv_type"),
    // ── IoT / Industrial ──
    ("mqtt.msgtype",        "MQTT",           "message_type"),
    ("coap.code",           "CoAP",           "code"),
    ("modbus.func_code",    "MODBUS_TCP",     "function_code"),
    ("bacnet.function",     "BACnet",         "function"),
    ("dnp3.ctl.func",       "DNP3",           "function"),
    ("zbee_nwk.frame_type", "Zigbee_NWK",     "frame_type"),
    // ── Storage ──
    ("fc.type",             "FC",             "type"),
    ("iscsi.opcode",        "iSCSI",          "opcode"),
    // ── Routing ──
    ("bgp.type",            "BGP",            "type"),
    ("ospf.msg",            "OSPF",           "message_type"),
    ("isis.type",           "ISIS",           "pdu_type"),
    ("rip.command",         "RIP",            "command"),
    ("pim.type",            "PIM",            "type"),
    ("bfd.version",         "BFD",            "version"),
    ("ldp.msg.type",        "LDP",            "message_type"),
    ("rsvp.msg",            "RSVP",           "message_type"),
    // ── VoIP ──
    ("sip.method",          "SIP",            "method"),
    ("rtp.p_type",          "RTP",            "payload_type"),
    ("rtcp.pt",             "RTCP",           "packet_type"),
    ("stun.type",           "STUN",           "message_type"),
    // ── Network Management ──
    ("radius.code",         "RADIUS",         "code"),
    ("diameter.cmd.code",   "Diameter",       "command_code"),
    ("snmp.version",        "SNMP",           "version"),
    // ── Application ──
    ("http.request.method", "HTTP",           "method"),
    ("http2.type",          "HTTP2",          "type"),
    ("dns.qry.type",        "DNS",            "query_type"),
    ("amqp.type",           "AMQP",           "type"),
    ("kafka.api_key",       "Kafka",          "api_key"),
    // ── Additional L2 / WLAN ──
    ("wlan.fc.type_subtype", "IEEE_802_11",   "type_subtype"),
    ("wlan_mgt.tag.number", "IEEE_802_11",    "tag_number"),
    ("eapol.type",          "EAPOL",          "type"),
    ("macsec.an",           "MACsec",         "an"),
    // ── Additional Tunneling ──
    ("erspan.ver",          "ERSPAN",         "version"),
    ("lisp.type",           "LISP",           "type"),
    ("capwap.control.msg_type", "CAPWAP",     "message_type"),
    ("nvgre.vsid",          "NVGRE",          "vsid"),
    ("wireguard.type",      "WireGuard",      "type"),
    ("gre.key",             "GRE",            "key"),
    // ── Additional Routing ──
    ("eigrp.opcode",        "EIGRP",          "opcode"),
    ("vrrp.type",           "VRRP",           "type"),
    ("hsrp.opcode",         "HSRP",           "opcode"),
    ("lacp.type",           "LACP",           "type"),
    // ── Data Center / Fabric ──
    ("roce.opcode",         "RoCEv2",         "opcode"),
    ("ceph.type",           "Ceph",           "type"),
    ("grpc.message_type",   "gRPC",           "message_type"),
    ("quic.long.packet_type", "QUIC",         "packet_type"),
    // ── IoT / Industrial extended ──
    ("enip.command",        "EtherNetIP",     "command"),
    ("cip.service",         "CIP",            "service"),
    ("opcua.transport.type", "OPC_UA",        "transport_type"),
    ("s7comm.rosctr",       "S7comm",         "rosctr"),
    ("profinet.frame_id",   "PROFINET",       "frame_id"),
    ("knxnetip.service_type", "KNXnetIP",     "service_type"),
    ("omron.command",       "OMRON_FINS",     "command"),
    // ── MPLS / Segment Routing ──
    ("mpls_pm.query_type",  "MPLS_PM",        "query_type"),
    ("sr.nai.type",         "SRv6",           "nai_type"),
    // ── DNS / DHCP extended ──
    ("dhcp.option.type",    "DHCP",           "option_type"),
    ("dhcpv6.msgtype",      "DHCPv6",         "message_type"),
    ("dns.resp.type",       "DNS",            "response_type"),
    ("mdns.qry.type",       "mDNS",           "query_type"),
    ("llmnr.qry.type",      "LLMNR",          "query_type"),
    // ── Network services ──
    ("ntp.flags.mode",      "NTP",            "mode"),
    ("syslog.facility",     "Syslog",         "facility"),
    ("tftp.opcode",         "TFTP",           "opcode"),
    ("telnet.cmd",          "Telnet",         "command"),
    ("ssh.message_code",    "SSH",            "message_code"),
    // ── USB ──
    ("usb.transfer_type",   "USB",            "transfer_type"),
    ("usb.bInterfaceClass", "USB",            "interface_class"),
    // ── Telecom / SS7 ──
    ("mtp3.opc",            "MTP3",           "opc"),
    ("sccp.msg_type",       "SCCP",           "message_type"),
    ("tcap.tag",            "TCAP",           "tag"),
    ("gsm_map.operation",   "MAP",            "operation"),
    ("camel.opcode",        "CAP",            "opcode"),
    ("isup.msg_type",       "ISUP",           "message_type"),
    ("m3ua.message_type",   "M3UA",           "message_type"),
    ("m2ua.message_type",   "M2UA",           "message_type"),
    ("sua.message_type",    "SUA",            "message_type"),
    ("s1ap.procedureCode",  "S1AP",           "procedure_code"),
    ("ngap.procedureCode",  "NGAP",           "procedure_code"),
    ("x2ap.procedureCode",  "X2AP",           "procedure_code"),
    ("ranap.procedureCode", "RANAP",          "procedure_code"),
    ("bssgp.pdu_type",     "BSSGP",          "pdu_type"),
    ("smpp.command_id",     "SMPP",           "command_id"),
    ("nas-eps.msg_type",    "LTE NAS",        "message_type"),
    ("nas-5gs.msg_type",    "5G NR NAS",      "message_type"),
    ("pfcp.msg_type",       "PFCP",           "message_type"),
    // ── Industrial extended ──
    ("s7comm.param.func",   "S7comm",         "function"),
    ("iec60870_104.type",   "IEC 60870-5-104", "type"),
    ("pn_dcp.service_type", "PROFINET DCP",   "service_type"),
    ("pn_mrp.type",         "PROFINET MRP",   "type"),
    ("ecat_mailbox.type",   "EtherCAT Mailbox", "type"),
    ("canopen.function",    "CANopen",        "function_code"),
    // ── Security extended ──
    ("x509af.type",         "X.509 Certificate", "type"),
    ("spnego.negResult",    "SPNEGO",         "neg_result"),
    ("gssapi.oid",          "GSS-API",        "oid"),
    ("ieee8021x.type",      "802.1X",         "type"),
    // ── VoIP extended ──
    ("sdp.media",           "SDP",            "media"),
    ("h225.cs_type",        "H.225",          "type"),
    ("h245.msg_type",       "H.245",          "message_type"),
    ("megaco.cmd",          "MEGACO / H.248", "command"),
    ("zrtp.msg_type",       "ZRTP",           "message_type"),
    // ── Storage extended ──
    ("nvme.cmd.opc",        "NVMe",           "opcode"),
    ("smb.cmd",             "SMB",            "command"),
    ("smb2.cmd",            "SMB2",           "command"),
    ("nfs.procedure_v4",    "NFS v4",         "procedure"),
    // ── Application extended ──
    ("pgsql.type",          "PostgreSQL",     "type"),
    ("mysql.command",       "MySQL",          "command"),
    ("mongo.opcode",        "MongoDB Wire",   "opcode"),
    ("cassandra.opcode",    "Cassandra",      "opcode"),
    ("bitcoin.command",     "Bitcoin",        "command"),
    ("bittorrent.msg_type", "BitTorrent",     "message_type"),
    ("dcerpc.opnum",        "DCE/RPC",        "opnum"),
    ("nbss.type",           "NBSS",           "type"),
    ("ssdp.method",         "UPnP SSDP",      "method"),
    ("ipp.operation",       "IPP",            "operation"),
    // ── Serial / Legacy ──
    ("hdlc.type",           "HDLC",           "type"),
    ("fr.nlpid",            "Frame Relay",    "nlpid"),
    ("lcp.code",            "PPP LCP",        "code"),
    ("ipcp.code",           "PPP IPCP",       "code"),
    // ── IoT extended ──
    ("6lowpan.pattern",     "6LoWPAN",        "dispatch"),
    ("zbee_zdp.cluster",    "ZigBee ZDP",     "cluster"),
    ("lorawan.mtype",       "LoRaWAN",        "message_type"),
    ("thread.cmd",          "Thread",         "command"),
    ("btle.advertising_header.pdu_type", "BLE", "pdu_type"),
    // ── Wireless extended ──
    ("radiotap.present",    "802.11 Radiotap", "present"),
    ("mac-lte.rnti-type",   "LTE MAC",        "rnti_type"),
    ("pdcp-lte.direction",  "LTE PDCP",       "direction"),
    ("mac-nr.rnti-type",    "5G NR MAC",      "rnti_type"),
    // ── Fibre Channel / SAN ──
    ("fcoe.ver",            "FCoE",           "version"),
    ("fip.opcode",          "FIP",            "opcode"),
    ("fcels.opcode",        "FC ELS",         "opcode"),
    ("fcct.revision",       "FC CT",          "revision"),
    // ── Windows / DCERPC ──
    ("browser.command",     "BROWSER",        "command"),
    // ── ASN.1 / OSI ──
    ("acse.oid",            "ACSE",           "oid"),
    ("pres.context_id",     "PRES",           "context_id"),
    ("cotp.pdu_type",       "COTP",           "pdu_type"),
    ("tpkt.version",        "TPKT",           "version"),
    // ── VoIP extended ──
    ("iax2.type",           "IAX2",           "type"),
    ("skinny.msg_id",       "Skinny SCCP",    "message_id"),
    ("mgcp.req_verb",       "MGCP",           "verb"),
    ("rtsp.method",         "RTSP",           "method"),
    // ── GTP extended ──
    ("gtpv1.message_type",  "GTPv1-C",        "message_type"),
    ("gtp.ext_hdr.type",    "GTP_U",          "ext_header_type"),
    // ── Automotive ──
    ("someip.messageid",    "SOME/IP",        "message_id"),
    ("doip.type",           "DoIP",           "type"),
    ("uds.service",         "UDS",            "service_id"),
    ("j1939.pgn",           "SAE J1939",      "pgn"),
    // ── IEC / Power ──
    ("goose.appid",         "IEC 61850 GOOSE", "appid"),
    ("sv.appid",            "IEC 61850 SV",   "appid"),
    ("mms.confirmedServiceRequest", "IEC 61850 MMS", "service"),
    ("dlms.type",           "DLMS/COSEM",     "type"),
    // ── PPP extensions ──
    ("ppp_chap.code",       "PPP CHAP",       "code"),
    ("ppp_pap.code",        "PPP PAP",        "code"),
    ("ppp_ccp.code",        "PPP CCP",        "code"),
    ("ppp_ipv6cp.code",     "PPP IPv6CP",     "code"),
    // ── ISDN / Legacy ──
    ("q931.message_type",   "Q.931",          "message_type"),
    ("q921.control",        "Q.921",          "control"),
    ("lapb.control",        "LAPB",           "control"),
    ("lapd.control",        "LAPD",           "control"),
    // ── ATM ──
    ("aal5.uu",             "AAL5",           "uu"),
    ("atm.vpi",             "ATM",            "vpi"),
    // ── Application extended ──
    ("websocket.opcode",    "WebSocket",      "opcode"),
    ("ajp13.type",          "AJP13",          "type"),
    ("memcache.opcode",     "Memcached",      "opcode"),
    ("irc.command",         "IRC",            "command"),
    ("xmpp.type",           "XMPP",           "type"),
    ("ftp.request.command",  "FTP",           "command"),
    ("pop.command",         "POP",            "command"),
    ("imap.command",        "IMAP",           "command"),
    // ── Satellite / Space ──
    ("ccsds.version",       "CCSDS Space Packet", "version"),
    // ── Multimedia ──
    ("mp2t.pid",            "MPEG-TS",        "pid"),
    ("h264.nal_unit_type",  "H.264 NAL",      "nal_unit_type"),
    ("h265.nal_unit_type",  "H.265 NAL",      "nal_unit_type"),
    // ── Network Monitoring ──
    ("sflow.sample_type",   "sFlow",          "sample_type"),
    ("ipfix.version",       "IPFIX",          "version"),
    ("bmp.type",            "BMP",            "type"),
];

/// Number of entries in the decode table map.
pub fn decode_table_count() -> usize {
    DECODE_TABLE_MAP.len()
}

/// Try to find a stack route for a discovered protocol using tshark decode tables.
///
/// Returns None if the protocol is not found in any known decode table.
pub fn discovered_route(
    tshark_filter: &str,
    registry: &TsharkRegistry,
) -> Option<StackRoute> {
    let (table_name, value_str) = registry.find_route_to(tshark_filter)?;

    // Find the decode table mapping
    let (_, parent, dispatch_field) = DECODE_TABLE_MAP
        .iter()
        .find(|(table, _, _)| *table == table_name)?;

    // Parse the dispatch value (handles both decimal and hex)
    let dispatch_value = parse_dispatch_value(&value_str)?;

    Some(StackRoute {
        child: tshark_filter.to_string(),
        parent: parent.to_string(),
        dispatch_field: dispatch_field.to_string(),
        dispatch_value,
    })
}

/// Parse a dispatch value string (decimal or hex) into u64.
fn parse_dispatch_value(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.starts_with("0x") || s.starts_with("0X") {
        u64::from_str_radix(&s[2..], 16).ok()
    } else {
        s.parse::<u64>().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_dispatch_value() {
        assert_eq!(parse_dispatch_value("53"), Some(53));
        assert_eq!(parse_dispatch_value("0x0800"), Some(0x0800));
        assert_eq!(parse_dispatch_value("0X86DD"), Some(0x86DD));
        assert_eq!(parse_dispatch_value("6"), Some(6));
    }

    #[test]
    fn test_decode_table_map_coverage() {
        // Ensure we have mappings for the most common decode tables
        let tables: Vec<&str> = DECODE_TABLE_MAP.iter().map(|(t, _, _)| *t).collect();
        assert!(tables.contains(&"ethertype"));
        assert!(tables.contains(&"ip.proto"));
        assert!(tables.contains(&"udp.port"));
        assert!(tables.contains(&"tcp.port"));
    }

    #[test]
    fn test_decode_table_map_no_duplicates() {
        let mut seen = std::collections::HashSet::new();
        for (table, parent, field) in DECODE_TABLE_MAP {
            let key = format!("{}:{}:{}", table, parent, field);
            assert!(
                seen.insert(key.clone()),
                "Duplicate decode table entry: {}",
                key
            );
        }
    }

    #[test]
    fn test_decode_table_map_new_categories() {
        let tables: Vec<&str> = DECODE_TABLE_MAP.iter().map(|(t, _, _)| *t).collect();
        // Automotive
        assert!(tables.contains(&"someip.messageid"));
        assert!(tables.contains(&"doip.type"));
        // Fibre Channel
        assert!(tables.contains(&"fcoe.ver"));
        // IEC/Power
        assert!(tables.contains(&"goose.appid"));
        // Application
        assert!(tables.contains(&"websocket.opcode"));
        // Multimedia
        assert!(tables.contains(&"h264.nal_unit_type"));
    }

    #[test]
    fn test_decode_table_count() {
        assert!(
            decode_table_count() >= 210,
            "Expected 210+ decode table entries, got {}",
            decode_table_count()
        );
    }
}
