//! SNAP (Sub-Network Access Protocol) definition (leaf node).
//!
//! SNAP extends LLC with a 5-byte header (3-byte OUI + 2-byte protocol ID).

use xdp2_core::{ParseError, ProtocolOps};

// ---------------------------------------------------------------------------
// SNAP
// ---------------------------------------------------------------------------

/// SNAP protocol operations (leaf).
pub struct SnapOps;

impl ProtocolOps for SnapOps {
    const MIN_LEN: usize = 5;
    const NAME: &'static str = "SNAP";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snap_is_leaf() {
        assert!(matches!(
            SnapOps.next_proto(&[0u8; 5]),
            Err(ParseError::UnknownProto)
        ));
    }
}
