//! Miscellaneous management protocol leaf definitions (Silver+Bronze tier).

use xdp2_core::{ParseError, ProtocolOps};

pub struct FcpOps;
impl ProtocolOps for FcpOps {
    const MIN_LEN: usize = 24;
    const NAME: &'static str = "FCP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct GvrpOps;
impl ProtocolOps for GvrpOps {
    const MIN_LEN: usize = 2;
    const NAME: &'static str = "GVRP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct IsupOps;
impl ProtocolOps for IsupOps {
    const MIN_LEN: usize = 3;
    const NAME: &'static str = "ISUP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct PdcpOps;
impl ProtocolOps for PdcpOps {
    const MIN_LEN: usize = 2;
    const NAME: &'static str = "PDCP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}
