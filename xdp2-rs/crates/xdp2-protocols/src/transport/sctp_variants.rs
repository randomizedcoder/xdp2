//! SCTP variant and chunk protocol leaf definitions.

use xdp2_core::{ParseError, ProtocolOps};

pub struct SctpChunkOps;
impl ProtocolOps for SctpChunkOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "SCTP_Chunk";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct SctpDataOps;
impl ProtocolOps for SctpDataOps {
    const MIN_LEN: usize = 16;
    const NAME: &'static str = "SCTP_Data";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct SctpInitOps;
impl ProtocolOps for SctpInitOps {
    const MIN_LEN: usize = 20;
    const NAME: &'static str = "SCTP_Init";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct SctpSackOps;
impl ProtocolOps for SctpSackOps {
    const MIN_LEN: usize = 16;
    const NAME: &'static str = "SCTP_Sack";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}
