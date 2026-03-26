//! Protocol name mapping across all four sources.
//!
//! Each source uses different names for the same protocol. This module
//! provides a canonical mapping table so extractors can normalize protocol
//! names to a single canonical form.

use std::collections::HashMap;

/// A protocol's names across all sources.
#[derive(Debug, Clone)]
pub struct ProtocolNames {
    /// Canonical display name (e.g., "IPv4")
    pub canonical: &'static str,
    /// XDP2 proto_def variable name (e.g., "xdp2_parse_ipv4")
    pub xdp2: Option<&'static str>,
    /// Linux kernel UAPI struct name (e.g., "iphdr")
    pub kernel_struct: Option<&'static str>,
    /// Linux kernel header include (e.g., "linux/ip.h")
    pub kernel_header: Option<&'static str>,
    /// Scapy class name (e.g., "IP")
    pub scapy: Option<&'static str>,
    /// tshark dissector filter name (e.g., "ip")
    pub tshark: Option<&'static str>,
    /// Minimum header size in bytes
    pub min_header_bytes: u32,
    /// Whether header length is variable
    pub variable_length: bool,
}

/// Build the complete protocol name mapping table.
pub fn protocol_table() -> Vec<ProtocolNames> {
    vec![
        // ── Layer 2 ──
        ProtocolNames {
            canonical: "Ethernet",
            xdp2: Some("xdp2_parse_ether"),
            kernel_struct: Some("ethhdr"),
            kernel_header: Some("linux/if_ether.h"),
            scapy: Some("Ether"),
            tshark: Some("eth"),
            min_header_bytes: 14,
            variable_length: false,
        },
        ProtocolNames {
            canonical: "VLAN",
            xdp2: Some("xdp2_parse_vlan"),
            kernel_struct: Some("vlan_hdr"),
            kernel_header: Some("linux/if_vlan.h"),
            scapy: Some("Dot1Q"),
            tshark: Some("vlan"),
            min_header_bytes: 4,
            variable_length: false,
        },
        ProtocolNames {
            canonical: "PBB",
            xdp2: Some("xdp2_parse_pbb"),
            kernel_struct: None,
            kernel_header: None,
            scapy: None,
            tshark: Some("ieee8021ah"),
            min_header_bytes: 18,
            variable_length: false,
        },
        // ── Layer 3 ──
        ProtocolNames {
            canonical: "IPv4",
            xdp2: Some("xdp2_parse_ipv4"),
            kernel_struct: Some("iphdr"),
            kernel_header: Some("linux/ip.h"),
            scapy: Some("IP"),
            tshark: Some("ip"),
            min_header_bytes: 20,
            variable_length: true,
        },
        ProtocolNames {
            canonical: "IPv6",
            xdp2: Some("xdp2_parse_ipv6"),
            kernel_struct: Some("ipv6hdr"),
            kernel_header: Some("linux/ipv6.h"),
            scapy: Some("IPv6"),
            tshark: Some("ipv6"),
            min_header_bytes: 40,
            variable_length: false,
        },
        ProtocolNames {
            canonical: "ARP",
            xdp2: Some("xdp2_parse_arp"),
            kernel_struct: Some("arphdr"),
            kernel_header: Some("linux/if_arp.h"),
            scapy: Some("ARP"),
            tshark: Some("arp"),
            min_header_bytes: 8,
            variable_length: true,
        },
        ProtocolNames {
            canonical: "ICMPv4",
            xdp2: Some("xdp2_parse_icmpv4"),
            kernel_struct: Some("icmphdr"),
            kernel_header: Some("linux/icmp.h"),
            scapy: Some("ICMP"),
            tshark: Some("icmp"),
            min_header_bytes: 8,
            variable_length: false,
        },
        ProtocolNames {
            canonical: "ICMPv6",
            xdp2: Some("xdp2_parse_icmpv6"),
            kernel_struct: Some("icmp6hdr"),
            kernel_header: Some("linux/icmpv6.h"),
            scapy: Some("ICMPv6Unknown"),
            tshark: Some("icmpv6"),
            min_header_bytes: 8,
            variable_length: false,
        },
        ProtocolNames {
            canonical: "IGMP",
            xdp2: Some("xdp2_parse_igmp"),
            kernel_struct: Some("igmphdr"),
            kernel_header: Some("linux/igmp.h"),
            scapy: Some("IGMP"),
            tshark: Some("igmp"),
            min_header_bytes: 8,
            variable_length: false,
        },
        // ── Layer 4 ──
        ProtocolNames {
            canonical: "TCP",
            xdp2: Some("xdp2_parse_tcp_notlvs"),
            kernel_struct: Some("tcphdr"),
            kernel_header: Some("linux/tcp.h"),
            scapy: Some("TCP"),
            tshark: Some("tcp"),
            min_header_bytes: 20,
            variable_length: true,
        },
        ProtocolNames {
            canonical: "UDP",
            xdp2: Some("xdp2_parse_udp"),
            kernel_struct: Some("udphdr"),
            kernel_header: Some("linux/udp.h"),
            scapy: Some("UDP"),
            tshark: Some("udp"),
            min_header_bytes: 8,
            variable_length: false,
        },
        // ── Tunneling ──
        ProtocolNames {
            canonical: "GRE",
            xdp2: Some("xdp2_parse_gre"),
            kernel_struct: Some("gre_base_hdr"),
            kernel_header: Some("linux/gre.h"),
            scapy: Some("GRE"),
            tshark: Some("gre"),
            min_header_bytes: 4,
            variable_length: true,
        },
        ProtocolNames {
            canonical: "VXLAN",
            xdp2: Some("xdp2_parse_vxlan"),
            kernel_struct: Some("vxlanhdr"),
            kernel_header: Some("linux/vxlan.h"),
            scapy: Some("VXLAN"),
            tshark: Some("vxlan"),
            min_header_bytes: 8,
            variable_length: false,
        },
        ProtocolNames {
            canonical: "Geneve",
            xdp2: Some("xdp2_parse_geneve"),
            kernel_struct: Some("genevehdr"),
            kernel_header: Some("linux/geneve.h"),
            scapy: Some("GENEVE"),
            tshark: Some("geneve"),
            min_header_bytes: 8,
            variable_length: true,
        },
        ProtocolNames {
            canonical: "MPLS",
            xdp2: Some("xdp2_parse_mpls"),
            kernel_struct: Some("mpls_label"),
            kernel_header: Some("linux/mpls.h"),
            scapy: Some("MPLS"),
            tshark: Some("mpls"),
            min_header_bytes: 4,
            variable_length: false,
        },
        ProtocolNames {
            canonical: "PPP",
            xdp2: Some("xdp2_parse_ppp"),
            kernel_struct: None,
            kernel_header: Some("linux/ppp_defs.h"),
            scapy: Some("PPP"),
            tshark: Some("ppp"),
            min_header_bytes: 2,
            variable_length: false,
        },
        ProtocolNames {
            canonical: "PPPoE",
            xdp2: Some("xdp2_parse_pppoe"),
            kernel_struct: Some("pppoe_hdr"),
            kernel_header: Some("linux/ppp_defs.h"),
            scapy: Some("PPPoE"),
            tshark: Some("pppoes"),
            min_header_bytes: 6,
            variable_length: false,
        },
        ProtocolNames {
            canonical: "L2TP",
            xdp2: Some("xdp2_parse_l2tp"),
            kernel_struct: Some("l2tp_control_hdr"),
            kernel_header: Some("linux/l2tp.h"),
            scapy: Some("L2TP"),
            tshark: Some("l2tp"),
            min_header_bytes: 6,
            variable_length: true,
        },
        ProtocolNames {
            canonical: "ERSPAN",
            xdp2: Some("xdp2_parse_erspan"),
            kernel_struct: Some("erspan_base_hdr"),
            kernel_header: Some("linux/erspan.h"),
            scapy: Some("ERSPAN"),
            tshark: Some("erspan"),
            min_header_bytes: 8,
            variable_length: false,
        },
        ProtocolNames {
            canonical: "NSH",
            xdp2: Some("xdp2_parse_nsh"),
            kernel_struct: Some("nshhdr"),
            kernel_header: Some("linux/nsh.h"),
            scapy: Some("NSH"),
            tshark: Some("nsh"),
            min_header_bytes: 8,
            variable_length: true,
        },
        ProtocolNames {
            canonical: "HSR",
            xdp2: Some("xdp2_parse_hsr"),
            kernel_struct: Some("hsr_tag"),
            kernel_header: Some("linux/hsr_tag.h"),
            scapy: Some("HSRTag"),
            tshark: Some("hsr"),
            min_header_bytes: 6,
            variable_length: false,
        },
        // ── Security ──
        ProtocolNames {
            canonical: "ESP",
            xdp2: Some("xdp2_parse_esp"),
            kernel_struct: Some("ip_esp_hdr"),
            kernel_header: Some("linux/ip.h"),
            scapy: Some("ESP"),
            tshark: Some("esp"),
            min_header_bytes: 8,
            variable_length: true,
        },
        ProtocolNames {
            canonical: "AH",
            xdp2: Some("xdp2_parse_ah"),
            kernel_struct: Some("ip_auth_hdr"),
            kernel_header: Some("linux/ip.h"),
            scapy: Some("AH"),
            tshark: Some("ah"),
            min_header_bytes: 12,
            variable_length: true,
        },
        ProtocolNames {
            canonical: "MACsec",
            xdp2: Some("xdp2_parse_macsec"),
            kernel_struct: Some("macsec_sci"),
            kernel_header: Some("linux/if_macsec.h"),
            scapy: Some("MACsecSCI"),
            tshark: Some("macsec"),
            min_header_bytes: 8,
            variable_length: false,
        },
        // ── Management ──
        ProtocolNames {
            canonical: "LLDP",
            xdp2: Some("xdp2_parse_lldp"),
            kernel_struct: None,
            kernel_header: None,
            scapy: Some("LLDPDU"),
            tshark: Some("lldp"),
            min_header_bytes: 2,
            variable_length: true,
        },
        ProtocolNames {
            canonical: "PTP",
            xdp2: Some("xdp2_parse_ptp"),
            kernel_struct: Some("ptp_header"),
            kernel_header: Some("linux/ptp_classify.h"),
            scapy: None,
            tshark: Some("ptp"),
            min_header_bytes: 34,
            variable_length: false,
        },
        // ── SRv6 ──
        ProtocolNames {
            canonical: "SRv6",
            xdp2: Some("xdp2_parse_srv6"),
            kernel_struct: Some("ipv6_sr_hdr"),
            kernel_header: Some("linux/seg6.h"),
            scapy: Some("IPv6ExtHdrSegmentRouting"),
            tshark: Some("ipv6.routing.srh"),
            min_header_bytes: 8,
            variable_length: true,
        },
        // ── Storage ──
        ProtocolNames {
            canonical: "AoE",
            xdp2: Some("xdp2_parse_aoe"),
            kernel_struct: Some("aoe_hdr"),
            kernel_header: Some("linux/aoe.h"),
            scapy: None,
            tshark: Some("aoe"),
            min_header_bytes: 10,
            variable_length: true,
        },
        ProtocolNames {
            canonical: "FCoE",
            xdp2: Some("xdp2_parse_fcoe"),
            kernel_struct: Some("fcoe_hdr"),
            kernel_header: Some("linux/fcoe.h"),
            scapy: None,
            tshark: Some("fcoe"),
            min_header_bytes: 14,
            variable_length: false,
        },
        ProtocolNames {
            canonical: "EtherCAT",
            xdp2: Some("xdp2_parse_ethercat"),
            kernel_struct: None,
            kernel_header: None,
            scapy: None,
            tshark: Some("ecat"),
            min_header_bytes: 2,
            variable_length: true,
        },
        // ── Wireless ──
        ProtocolNames {
            canonical: "IEEE802.11",
            xdp2: Some("xdp2_parse_ieee80211"),
            kernel_struct: Some("ieee80211_hdr"),
            kernel_header: Some("linux/ieee80211.h"),
            scapy: Some("Dot11"),
            tshark: Some("wlan"),
            min_header_bytes: 24,
            variable_length: true,
        },
        // ── CAN bus ──
        ProtocolNames {
            canonical: "CAN",
            xdp2: Some("xdp2_parse_can"),
            kernel_struct: Some("can_frame"),
            kernel_header: Some("linux/can.h"),
            scapy: Some("CAN"),
            tshark: Some("can"),
            min_header_bytes: 16,
            variable_length: false,
        },
        ProtocolNames {
            canonical: "CAN_FD",
            xdp2: Some("xdp2_parse_canfd"),
            kernel_struct: Some("canfd_frame"),
            kernel_header: Some("linux/can.h"),
            scapy: Some("CANFD"),
            tshark: Some("can"),
            min_header_bytes: 72,
            variable_length: false,
        },
        // ── Bluetooth ──
        ProtocolNames {
            canonical: "HCI",
            xdp2: Some("xdp2_parse_hci"),
            kernel_struct: Some("hci_command_hdr"),
            kernel_header: Some("net/bluetooth/hci.h"),
            scapy: Some("HCI_Hdr"),
            tshark: Some("bthci_cmd"),
            min_header_bytes: 1,
            variable_length: true,
        },
        ProtocolNames {
            canonical: "L2CAP",
            xdp2: Some("xdp2_parse_l2cap"),
            kernel_struct: Some("l2cap_hdr"),
            kernel_header: Some("net/bluetooth/l2cap.h"),
            scapy: Some("L2CAP_Hdr"),
            tshark: Some("btl2cap"),
            min_header_bytes: 4,
            variable_length: true,
        },
        // ── InfiniBand ──
        ProtocolNames {
            canonical: "IB_LRH",
            xdp2: Some("xdp2_parse_ib_lrh"),
            kernel_struct: None,
            kernel_header: None,
            scapy: None,
            tshark: Some("infiniband.lrh"),
            min_header_bytes: 8,
            variable_length: false,
        },
        ProtocolNames {
            canonical: "IB_GRH",
            xdp2: Some("xdp2_parse_ib_grh"),
            kernel_struct: None,
            kernel_header: None,
            scapy: None,
            tshark: Some("infiniband.grh"),
            min_header_bytes: 40,
            variable_length: false,
        },
        ProtocolNames {
            canonical: "IB_BTH",
            xdp2: Some("xdp2_parse_ib_bth"),
            kernel_struct: None,
            kernel_header: None,
            scapy: Some("BTH"),
            tshark: Some("infiniband.bth"),
            min_header_bytes: 12,
            variable_length: false,
        },
        // ── Netlink ──
        ProtocolNames {
            canonical: "Netlink",
            xdp2: Some("xdp2_parse_netlink"),
            kernel_struct: Some("nlmsghdr"),
            kernel_header: Some("linux/netlink.h"),
            scapy: None,
            tshark: Some("netlink"),
            min_header_bytes: 16,
            variable_length: true,
        },
        // ── Legacy ──
        ProtocolNames {
            canonical: "IPX",
            xdp2: Some("xdp2_parse_ipx"),
            kernel_struct: Some("ipxhdr"),
            kernel_header: Some("linux/ipx.h"),
            scapy: None,
            tshark: Some("ipx"),
            min_header_bytes: 30,
            variable_length: false,
        },
        ProtocolNames {
            canonical: "AppleTalk",
            xdp2: Some("xdp2_parse_atalk"),
            kernel_struct: Some("atalk_addr"),
            kernel_header: Some("linux/atalk.h"),
            scapy: None,
            tshark: Some("ddp"),
            min_header_bytes: 5,
            variable_length: false,
        },
    ]
}

/// Look up a protocol by canonical name (case-insensitive).
pub fn find_by_canonical(name: &str) -> Option<ProtocolNames> {
    let lower = name.to_lowercase();
    protocol_table()
        .into_iter()
        .find(|p| p.canonical.to_lowercase() == lower)
}

/// Look up a protocol by its XDP2 parse node name.
pub fn find_by_xdp2_name(name: &str) -> Option<ProtocolNames> {
    protocol_table()
        .into_iter()
        .find(|p| p.xdp2 == Some(name))
}

/// Look up a protocol by its kernel struct name.
pub fn find_by_kernel_struct(name: &str) -> Option<ProtocolNames> {
    protocol_table()
        .into_iter()
        .find(|p| p.kernel_struct == Some(name))
}

/// Look up a protocol by its Scapy class name.
pub fn find_by_scapy_name(name: &str) -> Option<ProtocolNames> {
    protocol_table()
        .into_iter()
        .find(|p| p.scapy == Some(name))
}

/// Look up a protocol by its tshark filter name.
pub fn find_by_tshark_name(name: &str) -> Option<ProtocolNames> {
    protocol_table()
        .into_iter()
        .find(|p| p.tshark == Some(name))
}

/// Build a HashMap from source-specific name → canonical name.
///
/// `source` must be one of: "xdp2", "kernel", "scapy", "tshark"
pub fn source_to_canonical_map(source: &str) -> HashMap<String, String> {
    let table = protocol_table();
    let mut map = HashMap::new();
    for p in &table {
        let name = match source {
            "xdp2" => p.xdp2.map(|s| s.to_string()),
            "kernel" => p.kernel_struct.map(|s| s.to_string()),
            "scapy" => p.scapy.map(|s| s.to_string()),
            "tshark" => p.tshark.map(|s| s.to_string()),
            _ => None,
        };
        if let Some(n) = name {
            map.insert(n, p.canonical.to_string());
        }
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_ipv4_by_canonical() {
        let p = find_by_canonical("IPv4").unwrap();
        assert_eq!(p.kernel_struct, Some("iphdr"));
        assert_eq!(p.scapy, Some("IP"));
        assert_eq!(p.tshark, Some("ip"));
        assert_eq!(p.min_header_bytes, 20);
        assert!(p.variable_length);
    }

    #[test]
    fn test_find_by_canonical_case_insensitive() {
        assert!(find_by_canonical("ipv4").is_some());
        assert!(find_by_canonical("IPV4").is_some());
        assert!(find_by_canonical("tcp").is_some());
    }

    #[test]
    fn test_find_by_xdp2_name() {
        let p = find_by_xdp2_name("xdp2_parse_tcp_notlvs").unwrap();
        assert_eq!(p.canonical, "TCP");
    }

    #[test]
    fn test_find_by_kernel_struct() {
        let p = find_by_kernel_struct("tcphdr").unwrap();
        assert_eq!(p.canonical, "TCP");
    }

    #[test]
    fn test_find_by_scapy_name() {
        let p = find_by_scapy_name("Ether").unwrap();
        assert_eq!(p.canonical, "Ethernet");
    }

    #[test]
    fn test_source_to_canonical_map() {
        let map = source_to_canonical_map("scapy");
        assert_eq!(map.get("IP"), Some(&"IPv4".to_string()));
        assert_eq!(map.get("TCP"), Some(&"TCP".to_string()));
        assert_eq!(map.get("Ether"), Some(&"Ethernet".to_string()));
    }

    #[test]
    fn test_protocol_table_no_duplicates() {
        let table = protocol_table();
        let mut seen = std::collections::HashSet::new();
        for p in &table {
            assert!(
                seen.insert(p.canonical),
                "Duplicate canonical name: {}",
                p.canonical
            );
        }
    }
}
