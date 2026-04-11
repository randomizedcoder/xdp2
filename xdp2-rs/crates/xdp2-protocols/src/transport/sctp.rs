//! SCTP (Stream Control Transmission Protocol) definition.
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `SctpHeader` | `<linux/sctp.h>` | `struct sctphdr` |
//! | `SctpOps` | `proto_defs/transport/proto_sctp.h:20-23` | `xdp2_parse_sctp` |
//!
//! ## Behavioral Differences
//! - None. Byte-for-byte compatible with C implementation.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// SCTP common header (12 bytes).
///
/// Reimplements: `struct sctphdr` from `<linux/sctp.h>`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct SctpHeader {
    /// Source port
    pub src_port: [u8; 2],
    /// Destination port
    pub dst_port: [u8; 2],
    /// Verification tag
    pub vtag: [u8; 4],
    /// Checksum
    pub checksum: [u8; 4],
}

impl SctpHeader {
    pub fn src_port(&self) -> u16 {
        u16::from_be_bytes(self.src_port)
    }

    pub fn dst_port(&self) -> u16 {
        u16::from_be_bytes(self.dst_port)
    }

    pub fn vtag(&self) -> u32 {
        u32::from_be_bytes(self.vtag)
    }
}

/// SCTP protocol operations (leaf node).
///
/// Reimplements: `xdp2_parse_sctp` in `proto_sctp.h:20-23`
pub struct SctpOps;

impl ProtocolOps for SctpOps {
    const MIN_LEN: usize = 12; // sizeof(struct sctphdr)
    const NAME: &'static str = "SCTP";

    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto) // Leaf node
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sctp_fixed_length() {
        let ops = SctpOps;
        assert_eq!(ops.header_len(&[0; 12], 100).unwrap(), 12);
    }

    #[test]
    fn sctp_ports() {
        let mut hdr = [0u8; 12];
        hdr[0..2].copy_from_slice(&2049u16.to_be_bytes()); // src port
        hdr[2..4].copy_from_slice(&80u16.to_be_bytes()); // dst port
        let sh = SctpHeader::ref_from_prefix(&hdr).unwrap().0;
        assert_eq!(sh.src_port(), 2049);
        assert_eq!(sh.dst_port(), 80);
    }

    #[test]
    fn sctp_is_leaf() {
        let ops = SctpOps;
        assert!(ops.next_proto(&[0; 12]).is_err());
    }
}
