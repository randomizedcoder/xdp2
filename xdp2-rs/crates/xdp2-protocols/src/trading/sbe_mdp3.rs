//! SBE MDP3 (Simple Binary Encoding / Market Data Protocol 3) leaf definitions (Bronze tier).

use xdp2_core::{ParseError, ProtocolOps};

pub struct SbeMdp3BinaryPacketHeaderOps;
impl ProtocolOps for SbeMdp3BinaryPacketHeaderOps {
    const MIN_LEN: usize = 12;
    const NAME: &'static str = "SBE_MDP3_BinaryPacketHeader";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct SbeMdp3MessageHeaderOps;
impl ProtocolOps for SbeMdp3MessageHeaderOps {
    const MIN_LEN: usize = 8;
    const NAME: &'static str = "SBE_MDP3_MessageHeader";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}
