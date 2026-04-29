//! CAN bus variant protocol leaf definitions (Silver tier).

use xdp2_core::{ParseError, ProtocolOps};

pub struct CanJ1939Ops;
impl ProtocolOps for CanJ1939Ops {
    const MIN_LEN: usize = 8;
    const NAME: &'static str = "CAN_J1939";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct CanObd2Ops;
impl ProtocolOps for CanObd2Ops {
    const MIN_LEN: usize = 8;
    const NAME: &'static str = "CAN_OBD2";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct CanTpOps;
impl ProtocolOps for CanTpOps {
    const MIN_LEN: usize = 1;
    const NAME: &'static str = "CAN_TP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}
