//! CAN XL (CAN with Extended data Length) protocol definition.
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `CanXlHeader` | `proto_defs/can/proto_canxl.h:38-44` | `struct canxl_frame_hdr` |
//! | `CanXlOps` | `proto_canxl.h:64-68` | `xdp2_parse_canxl` |
//! | `CanXlOps::next_proto` | `proto_canxl.h:50-53` | `canxl_proto()` |
//!
//! ## Behavioral Differences
//! - None. Byte-for-byte compatible with C implementation.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// CAN XL frame header (12 bytes).
///
/// Reimplements: `struct canxl_frame_hdr` in `proto_canxl.h:38-44`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct CanXlHeader {
    pub prio: [u8; 4],
    pub flags: u8,
    pub sdt: u8,
    pub len: [u8; 2],
    pub af: [u8; 4],
}

impl CanXlHeader {
    pub fn prio(&self) -> u32 {
        u32::from_le_bytes(self.prio)
    }
    pub fn len(&self) -> u16 {
        u16::from_be_bytes(self.len)
    }
    pub fn af(&self) -> u32 {
        u32::from_le_bytes(self.af)
    }
}

/// CAN XL protocol operations.
///
/// Reimplements: `xdp2_parse_canxl` in `proto_canxl.h:64-68`
///
/// Dispatches on the SDT (SDU type) field.
pub struct CanXlOps;

impl ProtocolOps for CanXlOps {
    const MIN_LEN: usize = 12;
    const NAME: &'static str = "CAN XL";

    /// Return SDT field for dispatch.
    ///
    /// Reimplements: `canxl_proto()` in `proto_canxl.h:50-53`
    #[inline]
    fn next_proto(&self, hdr: &[u8]) -> Result<i32, ParseError> {
        let xl = CanXlHeader::ref_from_prefix(hdr)
            .map_err(|_| ParseError::Length)?
            .0;
        Ok(xl.sdt as i32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_canxl(sdt: u8) -> [u8; 12] {
        let mut hdr = [0u8; 12];
        hdr[5] = sdt;
        hdr
    }

    #[test]
    fn canxl_dispatch() {
        let ops = CanXlOps;
        assert_eq!(ops.next_proto(&make_canxl(0x05)).unwrap(), 5);
        assert_eq!(ops.next_proto(&make_canxl(0xFF)).unwrap(), 255);
    }

    #[test]
    fn canxl_short_header() {
        let ops = CanXlOps;
        assert!(ops.next_proto(&[0u8; 4]).is_err());
    }
}
