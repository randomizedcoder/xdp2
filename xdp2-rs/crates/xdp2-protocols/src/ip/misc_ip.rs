//! Miscellaneous IP protocol leaf definitions (Silver+Bronze tier).

use xdp2_core::{ParseError, ProtocolOps};

pub struct Ipv6MobileIpOps;
impl ProtocolOps for Ipv6MobileIpOps {
    const MIN_LEN: usize = 6;
    const NAME: &'static str = "IPv6_MobileIP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct Ioam6Ops;
impl ProtocolOps for Ioam6Ops {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "IOAM6";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}
