//! PCAP generator: IR ProtocolDef → wire bytes in PCAP format.
//!
//! Generates a complete PCAP file containing one minimal packet for a target
//! protocol, building the full encapsulation stack (Ethernet → IPv4 → TCP, etc.).
//! The generated PCAP can be fed back to tshark for round-trip validation.

mod embedded;
pub(crate) mod routing;
mod serialize;

#[cfg(test)]
mod tests;

// Public API (what external callers already use)
pub use embedded::embedded_proto;
pub use routing::{is_root, load_pcap_template, stack_route_for, PcapTemplate};
pub use serialize::{generate_pcap, generate_pcap_with_discovery, hex_dump, ipv4_checksum, pack_field, serialize_header, PcapOutput};
