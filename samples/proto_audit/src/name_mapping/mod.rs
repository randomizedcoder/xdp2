//! Protocol name mapping across all six sources.
//!
//! Each source uses different names for the same protocol. This module
//! provides a canonical mapping table so extractors can normalize protocol
//! names to a single canonical form.

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
    /// Minimum header size in bytes
    pub min_header_bytes: u32,
    /// Whether header length is variable
    pub variable_length: bool,
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
            min_header_bytes,
            variable_length: false,
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

    pub const fn variable(mut self) -> Self {
        self.variable_length = true;
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
