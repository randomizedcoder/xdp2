//! SoupBinTCP protocol leaf definitions (Bronze tier).

use xdp2_core::{ParseError, ProtocolOps};

pub struct SoupBinTcpLoginAcceptedOps;
impl ProtocolOps for SoupBinTcpLoginAcceptedOps {
    const MIN_LEN: usize = 30;
    const NAME: &'static str = "SoupBinTCP_LoginAccepted";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct SoupBinTcpLoginRejectedOps;
impl ProtocolOps for SoupBinTcpLoginRejectedOps {
    const MIN_LEN: usize = 1;
    const NAME: &'static str = "SoupBinTCP_LoginRejected";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct SoupBinTcpLoginRequestOps;
impl ProtocolOps for SoupBinTcpLoginRequestOps {
    const MIN_LEN: usize = 46;
    const NAME: &'static str = "SoupBinTCP_LoginRequest";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct SoupBinTcpPacketHeaderOps;
impl ProtocolOps for SoupBinTcpPacketHeaderOps {
    const MIN_LEN: usize = 3;
    const NAME: &'static str = "SoupBinTCP_PacketHeader";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct SoupBinTcpSequencedDataOps;
impl ProtocolOps for SoupBinTcpSequencedDataOps {
    const MIN_LEN: usize = 1;
    const NAME: &'static str = "SoupBinTCP_SequencedData";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}
