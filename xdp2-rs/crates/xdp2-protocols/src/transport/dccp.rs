//! DCCP (Datagram Congestion Control Protocol) definition.
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `DccpHeader` | `<linux/dccp.h>` | `struct dccp_hdr` |
//! | `DccpOps` | `proto_defs/transport/proto_dccp.h:62-66` | `xdp2_parse_dccp` |
//! | `DccpOps::header_len` | `proto_dccp.h:48-51` | `dccp_len()` |
//!
//! ## Behavioral Differences
//! - None. Byte-for-byte compatible with C implementation.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// DCCP header (12 bytes minimum).
///
/// Reimplements: `struct dccp_hdr` from `<linux/dccp.h>`
///
/// Variable-length header; total length = `dccph_doff * 4`.
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct DccpHeader {
    /// Source port
    pub dccph_sport: [u8; 2],
    /// Destination port
    pub dccph_dport: [u8; 2],
    /// Data offset (header length in 32-bit words)
    pub dccph_doff: u8,
    /// CCVal(4) + CsCov(4)
    pub dccph_ccval_cscov: u8,
    /// Checksum
    pub dccph_checksum: [u8; 2],
    /// Reserved(3) + Type(4) + X(1)
    pub dccph_type_x: u8,
    /// Reserved
    pub dccph_reserved: u8,
    /// Sequence number (high 16 bits; low 32 in extended header)
    pub dccph_seq_high: [u8; 2],
}

impl DccpHeader {
    /// Source port.
    pub fn src_port(&self) -> u16 {
        u16::from_be_bytes(self.dccph_sport)
    }

    /// Destination port.
    pub fn dst_port(&self) -> u16 {
        u16::from_be_bytes(self.dccph_dport)
    }

    /// Header length in bytes.
    pub fn header_length(&self) -> usize {
        self.dccph_doff as usize * 4
    }
}

/// DCCP protocol operations (leaf node with variable length).
///
/// Reimplements: `xdp2_parse_dccp` in `proto_dccp.h:62-66`
///
/// Variable-length header determined by `dccph_doff` field (in 32-bit words).
pub struct DccpOps;

impl ProtocolOps for DccpOps {
    const MIN_LEN: usize = 12; // sizeof(struct dccp_hdr)
    const NAME: &'static str = "DCCP";

    /// Return header length from data offset field.
    ///
    /// Reimplements: `dccp_len()` in `proto_dccp.h:48-51`
    #[inline]
    fn header_len(&self, hdr: &[u8], _maxlen: usize) -> Result<usize, ParseError> {
        let dccp = DccpHeader::ref_from_prefix(hdr)
            .map_err(|_| ParseError::Length)?
            .0;
        Ok(dccp.header_length())
    }

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto) // Leaf node
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_dccp_header(doff: u8) -> [u8; 12] {
        let mut hdr = [0u8; 12];
        hdr[4] = doff; // dccph_doff
        hdr
    }

    #[test]
    fn dccp_variable_length() {
        let hdr = make_dccp_header(5); // 5 * 4 = 20 bytes
        let ops = DccpOps;
        assert_eq!(ops.header_len(&hdr, 100).unwrap(), 20);
    }

    #[test]
    fn dccp_min_length() {
        let hdr = make_dccp_header(3); // 3 * 4 = 12 bytes (minimum)
        let ops = DccpOps;
        assert_eq!(ops.header_len(&hdr, 100).unwrap(), 12);
    }

    #[test]
    fn dccp_is_leaf() {
        let ops = DccpOps;
        assert!(ops.next_proto(&[0u8; 12]).is_err());
    }

    #[test]
    fn dccp_ports() {
        let mut hdr = [0u8; 12];
        hdr[0..2].copy_from_slice(&1234u16.to_be_bytes());
        hdr[2..4].copy_from_slice(&5678u16.to_be_bytes());
        let dccp = DccpHeader::ref_from_prefix(&hdr).unwrap().0;
        assert_eq!(dccp.src_port(), 1234);
        assert_eq!(dccp.dst_port(), 5678);
    }
}
