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
    ("ethertype",     "Ethernet",  "ether_type"),
    ("ip.proto",      "IPv4",      "protocol"),
    ("ipv6.nxt",      "IPv6",      "next_header"),
    ("udp.port",      "UDP",       "dst_port"),
    ("tcp.port",      "TCP",       "dst_port"),
    ("sctp.port",     "SCTP",      "dst_port"),
    ("sctp.ppi",      "SCTP",      "ppid"),
    ("gre.proto",     "GRE",       "protocol_type"),
    ("ppp.protocol",  "PPP",       "protocol"),
    ("wtap_encap",    "Ethernet",  "ether_type"),
    ("dccp.port",     "DCCP",      "dst_port"),
    ("l2tp.pw_type",  "L2TP",      "pw_type"),
];

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
}
