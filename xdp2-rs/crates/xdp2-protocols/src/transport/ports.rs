//! Generic transport-with-ports protocol definition.
//!
//! Provides a minimal 4-byte header that extracts source and destination
//! ports, shared by TCP, UDP, SCTP, DCCP, etc. Used as a quick-match
//! leaf node when only port information is needed.
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `PortHeader` | `proto_defs/transport/proto_ports.h:20-28` | `struct port_hdr` |
//! | `PortsOps` | `proto_ports.h:30-33` | `xdp2_parse_ports` |
//!
//! ## Behavioral Differences
//! - None. Byte-for-byte compatible with C implementation.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// Generic transport header with source and destination ports (4 bytes).
///
/// Reimplements: `struct port_hdr` in `proto_ports.h:20-28`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct PortHeader {
    /// Source port
    pub sport: [u8; 2],
    /// Destination port
    pub dport: [u8; 2],
}

impl PortHeader {
    pub fn src_port(&self) -> u16 {
        u16::from_be_bytes(self.sport)
    }

    pub fn dst_port(&self) -> u16 {
        u16::from_be_bytes(self.dport)
    }
}

/// Generic ports protocol operations (leaf node).
///
/// Reimplements: `xdp2_parse_ports` in `proto_ports.h:30-33`
pub struct PortsOps;

impl ProtocolOps for PortsOps {
    const MIN_LEN: usize = 4; // sizeof(struct port_hdr)
    const NAME: &'static str = "Transport with ports";

    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto) // Leaf node
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ports_fixed_length() {
        let ops = PortsOps;
        assert_eq!(ops.header_len(&[0; 4], 100).unwrap(), 4);
    }

    #[test]
    fn ports_extraction() {
        let hdr = [0x00, 0x50, 0x01, 0xBB]; // sport=80, dport=443
        let ph = PortHeader::ref_from_prefix(&hdr).unwrap().0;
        assert_eq!(ph.src_port(), 80);
        assert_eq!(ph.dst_port(), 443);
    }
}
