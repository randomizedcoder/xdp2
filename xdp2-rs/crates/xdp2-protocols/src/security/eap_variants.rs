//! EAP authentication variant protocol leaf definitions (Silver tier).

use xdp2_core::{ParseError, ProtocolOps};

pub struct EapPeapOps;
impl ProtocolOps for EapPeapOps {
    const MIN_LEN: usize = 6;
    const NAME: &'static str = "EAP_PEAP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct EapTlsOps;
impl ProtocolOps for EapTlsOps {
    const MIN_LEN: usize = 6;
    const NAME: &'static str = "EAP_TLS";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct EapTtlsOps;
impl ProtocolOps for EapTtlsOps {
    const MIN_LEN: usize = 6;
    const NAME: &'static str = "EAP_TTLS";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}
