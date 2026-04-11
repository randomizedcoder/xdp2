//! UDP protocol definition.
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `UdpHeader` | `<linux/udp.h>` | `struct udphdr` |
//! | `UdpOps` | `proto_defs/transport/proto_udp.h` | `xdp2_parse_udp` |
//!
//! ## Behavioral Differences
//! - None. Byte-for-byte compatible with C implementation.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout, NetworkEndian, U16};

/// UDP header (fixed 8 bytes).
///
/// Reimplements: `struct udphdr` from `<linux/udp.h>`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct UdpHeader {
    /// Source port
    pub source: U16<NetworkEndian>,
    /// Destination port
    pub dest: U16<NetworkEndian>,
    /// Datagram length (header + payload)
    pub len: U16<NetworkEndian>,
    /// Checksum
    pub check: [u8; 2],
}

impl UdpHeader {
    pub fn src_port(&self) -> u16 {
        self.source.get()
    }

    pub fn dst_port(&self) -> u16 {
        self.dest.get()
    }

    pub fn length(&self) -> u16 {
        self.len.get()
    }
}

/// UDP protocol operations (leaf node — no next protocol).
///
/// Reimplements: `xdp2_parse_udp` in `proto_defs/transport/proto_udp.h`
///
/// Fixed 8-byte header. UDP is typically a leaf node.
pub struct UdpOps;

impl ProtocolOps for UdpOps {
    const MIN_LEN: usize = 8; // sizeof(struct udphdr)
    const NAME: &'static str = "UDP";

    /// UDP is a leaf — no next protocol.
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_udp_header(src_port: u16, dst_port: u16, length: u16) -> [u8; 8] {
        let mut hdr = [0u8; 8];
        let src = src_port.to_be_bytes();
        let dst = dst_port.to_be_bytes();
        let len = length.to_be_bytes();
        hdr[0] = src[0];
        hdr[1] = src[1];
        hdr[2] = dst[0];
        hdr[3] = dst[1];
        hdr[4] = len[0];
        hdr[5] = len[1];
        hdr
    }

    #[test]
    fn udp_header_fields() {
        let hdr = make_udp_header(53, 1024, 42);
        let udp = UdpHeader::ref_from_prefix(&hdr).unwrap().0;
        assert_eq!(udp.src_port(), 53);
        assert_eq!(udp.dst_port(), 1024);
        assert_eq!(udp.length(), 42);
    }

    #[test]
    fn udp_fixed_length() {
        let ops = UdpOps;
        assert_eq!(ops.header_len(&[0u8; 8], 100).unwrap(), 8);
    }

    #[test]
    fn udp_is_leaf() {
        let ops = UdpOps;
        assert!(ops.next_proto(&[0u8; 8]).is_err());
    }
}
