//! RADIUS variant protocol leaf definitions.

use xdp2_core::{ParseError, ProtocolOps};

/// RADIUS Accounting protocol operations (leaf, MIN_LEN = 20).
pub struct RadiusAcctOps;
impl ProtocolOps for RadiusAcctOps {
    const MIN_LEN: usize = 20;
    const NAME: &'static str = "RADIUS_ACCT";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// RADIUS Change-of-Authorization protocol operations (leaf, MIN_LEN = 20).
pub struct RadiusCoaOps;
impl ProtocolOps for RadiusCoaOps {
    const MIN_LEN: usize = 20;
    const NAME: &'static str = "RADIUS_COA";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}
