//! Code generators: IR ProtocolDef → target language output.
//!
//! Supports four targets:
//! - **C** (XDP2 proto_def header): the original generator
//! - **etherparse** (Rust struct): generates `pub struct` with derives
//! - **Scapy** (Python Packet class): generates `fields_desc` + `bind_layers`
//! - **PCAP** (wire bytes): generates a PCAP file with one packet for round-trip validation

mod c;
mod etherparse;
pub mod pcap;
mod scapy;

pub use c::generate_proto_def;
pub use etherparse::generate_etherparse;
pub use pcap::{generate_pcap, is_root, stack_route_for, PcapOutput};
pub use scapy::generate_scapy;

// ── Shared helpers ──

/// Convert "IPv4" → "ipv4", "TCP" → "tcp", "IEEE802.11" → "ieee802_11"
pub(crate) fn canonical_to_snake(name: &str) -> String {
    name.to_lowercase()
        .replace('.', "_")
        .replace('-', "_")
        .replace(' ', "_")
}

/// Convert "IPv4" → "IPV4", "TCP" → "TCP"
pub(crate) fn canonical_to_upper(name: &str) -> String {
    name.to_uppercase()
        .replace('.', "_")
        .replace('-', "_")
        .replace(' ', "_")
}

/// "IPv4" → "Ipv4", "TCP" → "Tcp", "IEEE802.1Q" → "Ieee8021Q"
pub(crate) fn canonical_to_pascal(name: &str) -> String {
    // For Scapy/class compatibility, return the canonical name with separators removed
    name.replace('.', "").replace('-', "").replace(' ', "")
}

/// Determine smallest Rust integer type for a given bit width.
pub(crate) fn rust_type_for_bits(bits: u32) -> String {
    match bits {
        0..=1 => "bool".to_string(),
        2..=8 => "u8".to_string(),
        9..=16 => "u16".to_string(),
        17..=32 => "u32".to_string(),
        33..=64 => "u64".to_string(),
        _ => "u128".to_string(),
    }
}

/// Convert field name to valid Rust identifier.
pub(crate) fn field_name_rust(name: &str) -> String {
    let name = name
        .to_lowercase()
        .replace('.', "_")
        .replace('-', "_")
        .replace(' ', "_");
    // Avoid Rust keywords
    match name.as_str() {
        "type" => "r#type".to_string(),
        "mod" => "r#mod".to_string(),
        "ref" => "r#ref".to_string(),
        _ => name,
    }
}

/// Check if a field is byte-aligned (both offset and size are multiples of 8).
pub(crate) fn is_byte_aligned(offset_bits: u32, size_bits: u32) -> bool {
    offset_bits % 8 == 0 && size_bits % 8 == 0
}

/// Flush accumulated bitfield entries as a comment + packed field.
pub(crate) fn flush_bitfield_group(out: &mut String, group: &mut Vec<(&str, u32)>) {
    if group.is_empty() {
        return;
    }
    let total_bits: u32 = group.iter().map(|(_, b)| b).sum();
    let rust_type = rust_type_for_bits(total_bits);
    out.push_str("    /// Packed bitfield:\n");
    for (name, bits) in group.iter() {
        out.push_str(&format!("    ///   {} ({} bits)\n", name, bits));
    }
    let field_name = group[0].0;
    out.push_str(&format!("    pub {}_raw: {},\n", field_name_rust(field_name), rust_type));
    group.clear();
}

/// Format a dispatch value: use hex for values >= 256.
pub(crate) fn format_value(v: u32) -> String {
    if v >= 256 {
        format!("0x{:04x}", v)
    } else {
        v.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canonical_to_snake() {
        assert_eq!(canonical_to_snake("IPv4"), "ipv4");
        assert_eq!(canonical_to_snake("TCP"), "tcp");
        assert_eq!(canonical_to_snake("IEEE802.11"), "ieee802_11");
        assert_eq!(canonical_to_snake("CAN_FD"), "can_fd");
    }

    #[test]
    fn test_canonical_to_pascal() {
        assert_eq!(canonical_to_pascal("IPv4"), "IPv4");
        assert_eq!(canonical_to_pascal("TCP"), "TCP");
        assert_eq!(canonical_to_pascal("IEEE802.1Q"), "IEEE8021Q");
    }

    #[test]
    fn test_rust_type_for_bits() {
        assert_eq!(rust_type_for_bits(1), "bool");
        assert_eq!(rust_type_for_bits(8), "u8");
        assert_eq!(rust_type_for_bits(16), "u16");
        assert_eq!(rust_type_for_bits(32), "u32");
        assert_eq!(rust_type_for_bits(64), "u64");
    }

    #[test]
    fn test_field_name_rust() {
        assert_eq!(field_name_rust("type"), "r#type");
        assert_eq!(field_name_rust("src_addr"), "src_addr");
        assert_eq!(field_name_rust("Total-Length"), "total_length");
    }
}
