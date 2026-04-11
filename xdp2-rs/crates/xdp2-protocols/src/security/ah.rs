//! AH (Authentication Header, RFC 4302) protocol definition.
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `AhHeader` | `proto_defs/security/proto_ah.h` | `struct ip_auth_hdr` (linux/ip.h) |
//! | `AhOps` | `proto_ah.h:56-61` | `xdp2_parse_ah` |
//! | `AhOps::header_len` | `proto_ah.h:41-44` | `ah_len()` |
//! | `AhOps::next_proto` | `proto_ah.h:36-39` | `ah_next_proto()` |
//!
//! ## Behavioral Differences
//! - None. Byte-for-byte compatible with C implementation.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// AH header (12 bytes minimum).
///
/// Reimplements: `struct ip_auth_hdr` (linux/ip.h) referenced in `proto_ah.h`
///
/// Layout:
/// - nexthdr (1 byte): next protocol
/// - hdrlen (1 byte): payload length in 4-byte units minus 2
/// - reserved (2 bytes)
/// - spi (4 bytes): Security Parameters Index
/// - seq_no (4 bytes): Sequence number
/// - auth_data (variable): ICV, not included in base struct
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct AhHeader {
    pub nexthdr: u8,
    pub hdrlen: u8,
    pub reserved: [u8; 2],
    pub spi: [u8; 4],
    pub seq_no: [u8; 4],
}

impl AhHeader {
    /// Security Parameters Index.
    pub fn spi(&self) -> u32 {
        u32::from_be_bytes(self.spi)
    }

    /// Sequence number.
    pub fn seq_no(&self) -> u32 {
        u32::from_be_bytes(self.seq_no)
    }
}

/// AH protocol operations.
///
/// Reimplements: `xdp2_parse_ah` in `proto_ah.h:56-61`
///
/// AH chains to the next IP protocol via the `nexthdr` field.
/// Header length is variable: `(hdrlen + 2) * 4`.
pub struct AhOps;

impl ProtocolOps for AhOps {
    const MIN_LEN: usize = 12; // sizeof(struct ip_auth_hdr)
    const NAME: &'static str = "AH";

    /// Return AH header length: `(hdrlen + 2) * 4`.
    ///
    /// Reimplements: `ah_len()` in `proto_ah.h:41-44`
    fn header_len(&self, hdr: &[u8], _maxlen: usize) -> Result<usize, ParseError> {
        if hdr.len() < 2 {
            return Err(ParseError::Length);
        }
        Ok(((hdr[1] as usize) + 2) * 4)
    }

    /// Return next IP protocol from `nexthdr` field.
    ///
    /// Reimplements: `ah_next_proto()` in `proto_ah.h:36-39`
    fn next_proto(&self, hdr: &[u8]) -> Result<i32, ParseError> {
        if hdr.is_empty() {
            return Err(ParseError::Length);
        }
        Ok(hdr[0] as i32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ah_header(nexthdr: u8, hdrlen: u8) -> [u8; 12] {
        let mut hdr = [0u8; 12];
        hdr[0] = nexthdr;
        hdr[1] = hdrlen;
        hdr
    }

    #[test]
    fn ah_standard_length() {
        let ops = AhOps;
        // hdrlen=4 → (4+2)*4 = 24 bytes (12B base + 12B ICV)
        assert_eq!(ops.header_len(&make_ah_header(6, 4), 100).unwrap(), 24);
    }

    #[test]
    fn ah_minimum_length() {
        let ops = AhOps;
        // hdrlen=1 → (1+2)*4 = 12 bytes (minimum)
        assert_eq!(ops.header_len(&make_ah_header(6, 1), 100).unwrap(), 12);
    }

    #[test]
    fn ah_next_proto_tcp() {
        let ops = AhOps;
        assert_eq!(ops.next_proto(&make_ah_header(6, 4)).unwrap(), 6);
    }

    #[test]
    fn ah_next_proto_udp() {
        let ops = AhOps;
        assert_eq!(ops.next_proto(&make_ah_header(17, 4)).unwrap(), 17);
    }

    #[test]
    fn ah_spi_seq() {
        let mut hdr = [0u8; 12];
        hdr[4] = 0x12;
        hdr[5] = 0x34;
        hdr[6] = 0x56;
        hdr[7] = 0x78;
        hdr[8] = 0xAA;
        hdr[9] = 0xBB;
        hdr[10] = 0xCC;
        hdr[11] = 0xDD;
        let ah = AhHeader::ref_from_prefix(&hdr).unwrap().0;
        assert_eq!(ah.spi(), 0x12345678);
        assert_eq!(ah.seq_no(), 0xAABBCCDD);
    }
}
