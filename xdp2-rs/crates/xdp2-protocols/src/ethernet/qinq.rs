//! Q-in-Q (IEEE 802.1ad) double VLAN tagging protocol definition.
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `QinQOps` | `proto_defs/ethernet/proto_qinq.h:49-53` | `xdp2_parse_qinq` |
//! | `QinQOps::next_proto` | `proto_vlan.h:20-23` | `vlan_proto()` (reused) |
//!
//! ## Behavioral Differences
//! - None. Structurally identical to VLAN — same 4-byte header, same
//!   `vlan_proto()` for next protocol extraction. The only difference is the
//!   outer EtherType: Q-in-Q uses 0x88a8 (ETH_P_8021AD) instead of 0x8100.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::FromBytes;

use super::vlan::VlanHeader;

/// Q-in-Q (802.1ad) protocol operations.
///
/// Reimplements: `xdp2_parse_qinq` in `proto_qinq.h:49-53`
///
/// Structurally identical to VLAN — same 4-byte `vlan_hdr`, dispatches on
/// `h_vlan_encapsulated_proto`. The outer EtherType 0x88a8 distinguishes
/// Q-in-Q from regular VLAN (0x8100) at the Ethernet dispatch level.
pub struct QinQOps;

impl ProtocolOps for QinQOps {
    const MIN_LEN: usize = 4; // sizeof(struct vlan_hdr)
    const NAME: &'static str = "QinQ";

    /// Return encapsulated EtherType (typically 0x8100 for inner VLAN).
    ///
    /// Reimplements: `vlan_proto()` in `proto_vlan.h:20-23` (reused by QinQ)
    #[inline]
    fn next_proto(&self, hdr: &[u8]) -> Result<i32, ParseError> {
        let vh = VlanHeader::ref_from_prefix(hdr)
            .map_err(|_| ParseError::Length)?
            .0;
        Ok(vh.encapsulated_proto() as i32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qinq_fixed_length() {
        let hdr = [0u8; 4];
        let ops = QinQOps;
        assert_eq!(ops.header_len(&hdr, 100).unwrap(), 4);
    }

    #[test]
    fn qinq_next_proto_inner_vlan() {
        // Q-in-Q typically encapsulates 0x8100 (inner VLAN)
        let mut hdr = [0u8; 4];
        hdr[2] = 0x81;
        hdr[3] = 0x00;
        let ops = QinQOps;
        assert_eq!(ops.next_proto(&hdr).unwrap(), 0x8100);
    }

    #[test]
    fn qinq_next_proto_ipv4() {
        // Q-in-Q can also directly encapsulate IPv4
        let mut hdr = [0u8; 4];
        hdr[2] = 0x08;
        hdr[3] = 0x00;
        let ops = QinQOps;
        assert_eq!(ops.next_proto(&hdr).unwrap(), 0x0800);
    }

    #[test]
    fn qinq_too_short() {
        let ops = QinQOps;
        assert!(ops.next_proto(&[0x81]).is_err());
    }
}
