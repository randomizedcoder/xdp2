//! InfiniBand Local Route Header (LRH) protocol definition.
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `IbLrhHeader` | `proto_defs/infiniband/proto_ib_lrh.h` | `struct ib_lrh` |
//! | `IbLrhOps` | `proto_ib_lrh.h:68-72` | `xdp2_parse_ib_lrh` |
//! | `IbLrhOps::next_proto` | `proto_ib_lrh.h:54-57` | `ib_lrh_proto()` |
//!
//! ## Behavioral Differences
//! - None. Byte-for-byte compatible with C implementation.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// LNH (Link Next Header) constants.
pub const IB_LNH_RAW: i32 = 0;
pub const IB_LNH_IPV6: i32 = 1;
pub const IB_LNH_BTH: i32 = 2;
pub const IB_LNH_GRH: i32 = 3;

/// InfiniBand LRH header (8 bytes).
///
/// Reimplements: `struct ib_lrh` in `proto_ib_lrh.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct IbLrhHeader {
    pub vl_lver_sl_lnh: [u8; 2],
    pub dlid: [u8; 2],
    pub pktlen: [u8; 2],
    pub slid: [u8; 2],
}

impl IbLrhHeader {
    /// Link Next Header (2-bit field).
    pub fn lnh(&self) -> u8 {
        let val = u16::from_be_bytes(self.vl_lver_sl_lnh);
        (val & 0x0003) as u8
    }
    pub fn dlid(&self) -> u16 {
        u16::from_be_bytes(self.dlid)
    }
    pub fn slid(&self) -> u16 {
        u16::from_be_bytes(self.slid)
    }
    /// Packet length in 4-byte words.
    pub fn pktlen(&self) -> u16 {
        u16::from_be_bytes(self.pktlen)
    }
}

/// IB LRH protocol operations.
///
/// Reimplements: `xdp2_parse_ib_lrh` in `proto_ib_lrh.h:68-72`
///
/// Dispatches on LNH (Link Next Header) field.
pub struct IbLrhOps;

impl ProtocolOps for IbLrhOps {
    const MIN_LEN: usize = 8;
    const NAME: &'static str = "IB LRH";

    /// Return LNH field for dispatch.
    ///
    /// Reimplements: `ib_lrh_proto()` in `proto_ib_lrh.h:54-57`
    fn next_proto(&self, hdr: &[u8]) -> Result<i32, ParseError> {
        let lrh = IbLrhHeader::ref_from_prefix(hdr)
            .map_err(|_| ParseError::Length)?
            .0;
        Ok(lrh.lnh() as i32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_lrh(lnh: u8) -> [u8; 8] {
        let mut hdr = [0u8; 8];
        // LNH is in bits 1:0 of the 16-bit field
        let val: u16 = (lnh as u16) & 0x0003;
        hdr[0..2].copy_from_slice(&val.to_be_bytes());
        hdr
    }

    #[test]
    fn ib_lrh_dispatch_bth() {
        assert_eq!(IbLrhOps.next_proto(&make_lrh(2)).unwrap(), IB_LNH_BTH);
    }

    #[test]
    fn ib_lrh_dispatch_grh() {
        assert_eq!(IbLrhOps.next_proto(&make_lrh(3)).unwrap(), IB_LNH_GRH);
    }

    #[test]
    fn ib_lrh_dispatch_ipv6() {
        assert_eq!(IbLrhOps.next_proto(&make_lrh(1)).unwrap(), IB_LNH_IPV6);
    }

    #[test]
    fn ib_lrh_dispatch_raw() {
        assert_eq!(IbLrhOps.next_proto(&make_lrh(0)).unwrap(), IB_LNH_RAW);
    }
}
