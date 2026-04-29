//! Industrial protocol leaf definitions.

use xdp2_core::{ParseError, ProtocolOps};

/// EtherNet/IP protocol operations (leaf, MIN_LEN = 24).
pub struct EnipOps;
impl ProtocolOps for EnipOps {
    const MIN_LEN: usize = 24;
    const NAME: &'static str = "ENIP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// SOME/IP protocol operations (leaf, MIN_LEN = 8).
pub struct SomeIpOps;
impl ProtocolOps for SomeIpOps {
    const MIN_LEN: usize = 8;
    const NAME: &'static str = "SOME_IP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// DoIP protocol operations (leaf, MIN_LEN = 8).
pub struct DoipOps;
impl ProtocolOps for DoipOps {
    const MIN_LEN: usize = 8;
    const NAME: &'static str = "DoIP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}
