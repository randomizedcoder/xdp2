//! L2CAP protocol definition (leaf node).
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `L2capHeader` | `proto_defs/bluetooth/proto_l2cap.h` | `struct l2cap_hdr` |
//!
//! ## Behavioral Differences
//! - None. Leaf node.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

// ---------------------------------------------------------------------------
// L2CAP
// ---------------------------------------------------------------------------

/// L2CAP header (4 bytes).
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct L2capHeader {
    pub len: [u8; 2],
    pub cid: [u8; 2],
}

impl L2capHeader {
    pub fn len(&self) -> u16 {
        u16::from_le_bytes(self.len)
    }
    pub fn cid(&self) -> u16 {
        u16::from_le_bytes(self.cid)
    }
}

pub struct L2capOps;

impl ProtocolOps for L2capOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "L2CAP";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn l2cap_is_leaf() {
        assert!(matches!(L2capOps.next_proto(&[0u8; 4]), Err(ParseError::UnknownProto)));
    }
}
