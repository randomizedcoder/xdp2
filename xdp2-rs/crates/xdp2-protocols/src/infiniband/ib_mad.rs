//! InfiniBand MAD (Management Datagram) protocol definition (leaf node).
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `IbMadHeader` | `proto_defs/infiniband/proto_ib_mad.h` | `struct ib_mad_hdr` |
//!
//! ## Behavioral Differences
//! - None. Leaf node.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

// ---------------------------------------------------------------------------
// IB MAD (Management Datagram) — 24 bytes
// ---------------------------------------------------------------------------

#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct IbMadHeader {
    pub base_version: u8,
    pub mgmt_class: u8,
    pub class_version: u8,
    pub method: u8,
    pub status: [u8; 2],
    pub class_specific: [u8; 2],
    pub tid: [u8; 8],
    pub attr_id: [u8; 2],
    pub resv: [u8; 2],
    pub attr_mod: [u8; 4],
}

pub struct IbMadOps;

impl ProtocolOps for IbMadOps {
    const MIN_LEN: usize = 24;
    const NAME: &'static str = "IB MAD";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ib_mad_is_leaf() {
        assert!(matches!(
            IbMadOps.next_proto(&[0u8; 24]),
            Err(ParseError::UnknownProto)
        ));
    }
}
