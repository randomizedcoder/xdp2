//! Simple service protocol leaf definitions (RFC 864 family).

use xdp2_core::{ParseError, ProtocolOps};

/// CHARGEN protocol operations (leaf, MIN_LEN = 1).
pub struct ChargenOps;
impl ProtocolOps for ChargenOps {
    const MIN_LEN: usize = 1;
    const NAME: &'static str = "CHARGEN";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// DAYTIME protocol operations (leaf, MIN_LEN = 1).
pub struct DaytimeOps;
impl ProtocolOps for DaytimeOps {
    const MIN_LEN: usize = 1;
    const NAME: &'static str = "DAYTIME";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// DISCARD protocol operations (leaf, MIN_LEN = 1).
pub struct DiscardOps;
impl ProtocolOps for DiscardOps {
    const MIN_LEN: usize = 1;
    const NAME: &'static str = "DISCARD";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// ECHO protocol operations (leaf, MIN_LEN = 1).
pub struct EchoOps;
impl ProtocolOps for EchoOps {
    const MIN_LEN: usize = 1;
    const NAME: &'static str = "ECHO";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// TIME protocol operations (leaf, MIN_LEN = 4).
pub struct TimeOps;
impl ProtocolOps for TimeOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "TIME";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}
