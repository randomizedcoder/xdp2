//! QUIC variant protocol leaf definitions.

use xdp2_core::{ParseError, ProtocolOps};

/// QUIC Initial packet protocol operations (leaf, MIN_LEN = 1).
pub struct QuicInitialOps;
impl ProtocolOps for QuicInitialOps {
    const MIN_LEN: usize = 1;
    const NAME: &'static str = "QUIC_Initial";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// QUIC Retry packet protocol operations (leaf, MIN_LEN = 1).
pub struct QuicRetryOps;
impl ProtocolOps for QuicRetryOps {
    const MIN_LEN: usize = 1;
    const NAME: &'static str = "QUIC_Retry";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}
