//! Protocol name mapping across all six sources.
//!
//! Each source uses different names for the same protocol. This module
//! provides a canonical mapping table so extractors can normalize protocol
//! names to a single canonical form.

pub mod auto_matcher;
pub mod auto_table;
mod table;

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
    /// etherparse Rust struct name (e.g., "Ethernet2Header")
    pub etherparse_struct: Option<&'static str>,
    /// etherparse source file (relative to crate root)
    pub etherparse_file: Option<&'static str>,
    /// libpcap name for gencode/struct lookup (e.g., "IPv4", "vlan_tag")
    pub libpcap_name: Option<&'static str>,
    /// libpcap source file (e.g., "gencode.c", "pcap/vlan.h")
    pub libpcap_file: Option<&'static str>,
    /// Kaitai Struct KSY id (e.g., "dns_packet")
    pub kaitai_id: Option<&'static str>,
    /// Kaitai Struct KSY filename (e.g., "dns_packet.ksy")
    pub kaitai_file: Option<&'static str>,
    /// Suricata parser module name (e.g., "dns")
    pub suricata_module: Option<&'static str>,
    /// Suricata struct name (e.g., "DnsHeader")
    pub suricata_struct: Option<&'static str>,
    /// OMI c-struct typedef name (e.g., "NonCrossTradeMessageT")
    pub omi_struct: Option<&'static str>,
    /// OMI c-struct source file (e.g., "nasdaq/Nasdaq.Equities.TotalView.Itch.v5.0.h")
    pub omi_file: Option<&'static str>,
    /// OMI Wireshark Lua dissector path (e.g., "Nasdaq/Nasdaq_NsmEquities_TotalView_Itch_v5_0_Dissector.lua")
    pub omi_lua: Option<&'static str>,
    /// OMI sample PCAP path (relative to omi-data-packets root, e.g.
    /// "Nasdaq/Nasdaq.Equities.TotalView.Itch.v5.0/AddOrderNoMpidAttributionMessage.pcap")
    pub omi_pcap: Option<&'static str>,
    /// OMI per-message PDML field name (e.g.
    /// "nasdaq.nsmequities.totalview.itch.v5.0.addordernompidattributionmessage").
    /// When set, tshark extraction descends into this field under the outer
    /// Lua proto instead of returning the whole-packet superset.
    pub omi_tshark_field: Option<&'static str>,
    /// DPDK struct name (e.g., "rte_tcp_hdr")
    pub dpdk_struct: Option<&'static str>,
    /// DPDK header file (e.g., "rte_tcp.h")
    pub dpdk_header: Option<&'static str>,
    /// nDPI struct name (e.g., "ndpi_tcphdr")
    pub ndpi_struct: Option<&'static str>,
    /// nDPI header file (e.g., "ndpi_typedefs.h")
    pub ndpi_header: Option<&'static str>,
    /// pppd protocol name (e.g., "PPP", "LCP")
    pub pppd_proto: Option<&'static str>,
    /// Minimum header size in bytes
    pub min_header_bytes: u32,
    /// Whether header length is variable
    pub variable_length: bool,
    /// Defining and updating RFC numbers (first = defines, rest = updates)
    pub rfc_numbers: &'static [u32],
    /// IEEE standard identifiers (e.g., "802.1Q-2022")
    pub ieee_standards: &'static [&'static str],
    /// IANA registry name for dispatch field (e.g., "protocol-numbers")
    pub iana_registry: Option<&'static str>,
}

impl ProtocolNames {
    /// Create a new entry with canonical name and minimum header bytes.
    /// All source fields default to `None`, `variable_length` defaults to `false`.
    pub const fn new(canonical: &'static str, min_header_bytes: u32) -> Self {
        ProtocolNames {
            canonical,
            xdp2: None,
            kernel_struct: None,
            kernel_header: None,
            scapy: None,
            tshark: None,
            etherparse_struct: None,
            etherparse_file: None,
            libpcap_name: None,
            libpcap_file: None,
            kaitai_id: None,
            kaitai_file: None,
            suricata_module: None,
            suricata_struct: None,
            omi_struct: None,
            omi_file: None,
            omi_lua: None,
            omi_pcap: None,
            omi_tshark_field: None,
            dpdk_struct: None,
            dpdk_header: None,
            ndpi_struct: None,
            ndpi_header: None,
            pppd_proto: None,
            min_header_bytes,
            variable_length: false,
            rfc_numbers: &[],
            ieee_standards: &[],
            iana_registry: None,
        }
    }

    pub const fn xdp2(mut self, name: &'static str) -> Self {
        self.xdp2 = Some(name);
        self
    }

    /// Set both kernel struct name and header file.
    pub const fn kernel(mut self, struct_name: &'static str, header: &'static str) -> Self {
        self.kernel_struct = Some(struct_name);
        self.kernel_header = Some(header);
        self
    }

    /// Set kernel header only (no struct, e.g. PPP).
    pub const fn kernel_header_only(mut self, header: &'static str) -> Self {
        self.kernel_header = Some(header);
        self
    }

    pub const fn scapy(mut self, name: &'static str) -> Self {
        self.scapy = Some(name);
        self
    }

    pub const fn tshark(mut self, name: &'static str) -> Self {
        self.tshark = Some(name);
        self
    }

    /// Set both etherparse struct name and source file.
    pub const fn etherparse(mut self, struct_name: &'static str, file: &'static str) -> Self {
        self.etherparse_struct = Some(struct_name);
        self.etherparse_file = Some(file);
        self
    }

    /// Set both libpcap name and source file.
    pub const fn libpcap(mut self, name: &'static str, file: &'static str) -> Self {
        self.libpcap_name = Some(name);
        self.libpcap_file = Some(file);
        self
    }

    /// Set both Kaitai Struct KSY id and filename.
    pub const fn kaitai(mut self, id: &'static str, file: &'static str) -> Self {
        self.kaitai_id = Some(id);
        self.kaitai_file = Some(file);
        self
    }

    /// Set both Suricata module name and struct name.
    pub const fn suricata(mut self, module: &'static str, struct_name: &'static str) -> Self {
        self.suricata_module = Some(module);
        self.suricata_struct = Some(struct_name);
        self
    }

    /// Set both OMI c-struct typedef name and source file path.
    pub const fn omi(mut self, struct_name: &'static str, file: &'static str) -> Self {
        self.omi_struct = Some(struct_name);
        self.omi_file = Some(file);
        self
    }

    /// Set OMI Wireshark Lua dissector path + sample PCAP path + per-message
    /// PDML field name. The Lua/PCAP paths are relative to the roots of their
    /// respective OMI repositories (`wireshark-lua` and `omi-data-packets`).
    /// The field name is what tshark reports as `<field name="X">` under the
    /// outer Lua proto once the dissector is loaded — proto-audit descends to
    /// this field so extraction yields the per-message wire layout (not the
    /// whole packet including session/seq/header).
    pub const fn omi_tshark(
        mut self,
        lua: &'static str,
        pcap: &'static str,
        field: &'static str,
    ) -> Self {
        self.omi_lua = Some(lua);
        self.omi_pcap = Some(pcap);
        self.omi_tshark_field = Some(field);
        self
    }

    /// Set both DPDK struct name and header file.
    pub const fn dpdk(mut self, struct_name: &'static str, header: &'static str) -> Self {
        self.dpdk_struct = Some(struct_name);
        self.dpdk_header = Some(header);
        self
    }

    /// Set both nDPI struct name and header file.
    pub const fn ndpi(mut self, struct_name: &'static str, header: &'static str) -> Self {
        self.ndpi_struct = Some(struct_name);
        self.ndpi_header = Some(header);
        self
    }

    /// Set pppd protocol name.
    pub const fn pppd(mut self, proto: &'static str) -> Self {
        self.pppd_proto = Some(proto);
        self
    }

    pub const fn variable(mut self) -> Self {
        self.variable_length = true;
        self
    }

    /// Set RFC numbers: first = defining RFC, rest = updates.
    pub const fn rfcs(mut self, numbers: &'static [u32]) -> Self {
        self.rfc_numbers = numbers;
        self
    }

    /// Set IEEE standard identifiers.
    pub const fn ieee(mut self, standards: &'static [&'static str]) -> Self {
        self.ieee_standards = standards;
        self
    }

    /// Set IANA registry name for dispatch field.
    pub const fn iana_registry(mut self, name: &'static str) -> Self {
        self.iana_registry = Some(name);
        self
    }
}

pub use table::protocol_table;

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

/// Look up a protocol by its etherparse struct name.
pub fn find_by_etherparse_struct(name: &str) -> Option<ProtocolNames> {
    protocol_table()
        .into_iter()
        .find(|p| p.etherparse_struct == Some(name))
}

/// Look up a protocol by its libpcap name.
pub fn find_by_libpcap_name(name: &str) -> Option<ProtocolNames> {
    protocol_table()
        .into_iter()
        .find(|p| p.libpcap_name == Some(name))
}

/// Look up a protocol by its Kaitai Struct KSY id.
pub fn find_by_kaitai_id(id: &str) -> Option<ProtocolNames> {
    protocol_table()
        .into_iter()
        .find(|p| p.kaitai_id == Some(id))
}

/// Look up a protocol by its Suricata struct name.
pub fn find_by_suricata_struct(name: &str) -> Option<ProtocolNames> {
    protocol_table()
        .into_iter()
        .find(|p| p.suricata_struct == Some(name))
}

/// Look up a protocol by its OMI c-struct typedef name.
pub fn find_by_omi_struct(name: &str) -> Option<ProtocolNames> {
    protocol_table()
        .into_iter()
        .find(|p| p.omi_struct == Some(name))
}

/// Look up a protocol by its DPDK struct name.
pub fn find_by_dpdk_struct(name: &str) -> Option<ProtocolNames> {
    protocol_table()
        .into_iter()
        .find(|p| p.dpdk_struct == Some(name))
}

/// Look up a protocol by its nDPI struct name.
pub fn find_by_ndpi_struct(name: &str) -> Option<ProtocolNames> {
    protocol_table()
        .into_iter()
        .find(|p| p.ndpi_struct == Some(name))
}

/// Look up a protocol by its pppd protocol name.
pub fn find_by_pppd_proto(name: &str) -> Option<ProtocolNames> {
    protocol_table()
        .into_iter()
        .find(|p| p.pppd_proto == Some(name))
}

/// Build a HashMap from source-specific name → canonical name.
///
/// `source` must be one of: "xdp2", "kernel", "scapy", "tshark", "etherparse", "libpcap"
pub fn source_to_canonical_map(source: &str) -> HashMap<String, String> {
    let table = protocol_table();
    let mut map = HashMap::new();
    for p in &table {
        let name = match source {
            "xdp2" => p.xdp2.map(|s| s.to_string()),
            "kernel" => p.kernel_struct.map(|s| s.to_string()),
            "scapy" => p.scapy.map(|s| s.to_string()),
            "tshark" => p.tshark.map(|s| s.to_string()),
            "etherparse" => p.etherparse_struct.map(|s| s.to_string()),
            "libpcap" => p.libpcap_name.map(|s| s.to_string()),
            "kaitai" => p.kaitai_id.map(|s| s.to_string()),
            "suricata" => p.suricata_struct.map(|s| s.to_string()),
            "omi" => p.omi_struct.map(|s| s.to_string()),
            "dpdk" => p.dpdk_struct.map(|s| s.to_string()),
            "ndpi" => p.ndpi_struct.map(|s| s.to_string()),
            "pppd" => p.pppd_proto.map(|s| s.to_string()),
            _ => None,
        };
        if let Some(n) = name {
            map.entry(n).or_insert_with(|| p.canonical.to_string());
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

    #[test]
    fn test_rfc_metadata() {
        let p = find_by_canonical("IPv4").unwrap();
        assert!(p.rfc_numbers.contains(&791));
        assert!(p.rfc_numbers.contains(&2474));
        assert_eq!(p.iana_registry, Some("protocol-numbers"));
    }

    #[test]
    fn test_ieee_metadata() {
        let p = find_by_canonical("VLAN").unwrap();
        assert!(!p.ieee_standards.is_empty());
        assert!(p.ieee_standards.contains(&"802.1Q-2022"));
    }

    #[test]
    fn test_tcp_rfcs() {
        let p = find_by_canonical("TCP").unwrap();
        // TCP should have RFC 9293 (current defining) and RFC 793 (original)
        assert!(p.rfc_numbers.contains(&9293));
        assert!(p.rfc_numbers.contains(&793));
        assert_eq!(p.iana_registry, Some("service-name-port-numbers"));
    }

    #[test]
    fn test_protocols_without_rfcs() {
        // Proprietary/vendor protocols should have empty RFC lists
        let p = find_by_canonical("EtherCAT").unwrap();
        assert!(p.rfc_numbers.is_empty());
        assert!(p.ieee_standards.is_empty());
    }

    #[test]
    fn test_auto_table_loads() {
        let mappings = auto_table::load_auto_mappings();
        // Just verify it loads without panic
        let _ = mappings.protocols.len();
    }
}
