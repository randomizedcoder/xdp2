//! BT BNEP (Bluetooth Network Encapsulation Protocol) protocol definition.
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `BtBnepHeader` | `proto_defs/bluetooth/proto_bt_bnep.h` | `struct bt_bnep_hdr` |
//! | `BtBnepOps` | `proto_bt_bnep.h:56-60` | `xdp2_parse_bt_bnep` |
//! | `BtBnepOps::next_proto` | `proto_bt_bnep.h:42-45` | `bt_bnep_proto()` |
//!
//! ## Behavioral Differences
//! - None. Byte-for-byte compatible with C implementation.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// BT BNEP header (3 bytes).
///
/// Reimplements: `struct bt_bnep_hdr` in `proto_bt_bnep.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct BtBnepHeader {
    pub pkt_type: u8,
    pub protocol: [u8; 2],
}

impl BtBnepHeader {
    /// Encapsulated EtherType.
    pub fn protocol(&self) -> u16 {
        u16::from_be_bytes(self.protocol)
    }
}

/// BT BNEP protocol operations.
///
/// Reimplements: `xdp2_parse_bt_bnep` in `proto_bt_bnep.h:56-60`
///
/// Dispatches on the EtherType `protocol` field.
pub struct BtBnepOps;

impl ProtocolOps for BtBnepOps {
    const MIN_LEN: usize = 3;
    const NAME: &'static str = "BT BNEP";

    /// Return EtherType for dispatch.
    ///
    /// Reimplements: `bt_bnep_proto()` in `proto_bt_bnep.h:42-45`
    #[inline]
    fn next_proto(&self, hdr: &[u8]) -> Result<i32, ParseError> {
        let bnep = BtBnepHeader::ref_from_prefix(hdr)
            .map_err(|_| ParseError::Length)?
            .0;
        Ok(bnep.protocol() as i32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_bnep(ethertype: u16) -> [u8; 3] {
        let mut hdr = [0u8; 3];
        hdr[1..3].copy_from_slice(&ethertype.to_be_bytes());
        hdr
    }

    #[test]
    fn bnep_dispatch_ipv4() {
        assert_eq!(BtBnepOps.next_proto(&make_bnep(0x0800)).unwrap(), 0x0800);
    }

    #[test]
    fn bnep_dispatch_ipv6() {
        assert_eq!(BtBnepOps.next_proto(&make_bnep(0x86DD)).unwrap(), 0x86DD);
    }

    #[test]
    fn bnep_short() {
        assert!(BtBnepOps.next_proto(&[0u8; 2]).is_err());
    }
}
