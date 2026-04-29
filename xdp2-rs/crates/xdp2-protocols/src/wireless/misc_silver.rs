//! Miscellaneous wireless protocol leaf definitions (Silver+Bronze tier).

use xdp2_core::{ParseError, ProtocolOps};

pub struct PpiOps;
impl ProtocolOps for PpiOps {
    const MIN_LEN: usize = 8;
    const NAME: &'static str = "PPI";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct Ieee80211DataOps;
impl ProtocolOps for Ieee80211DataOps {
    const MIN_LEN: usize = 24;
    const NAME: &'static str = "IEEE802_11_Data";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct SixlowpanOps;
impl ProtocolOps for SixlowpanOps {
    const MIN_LEN: usize = 1;
    const NAME: &'static str = "SixLoWPAN";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct ZigbeeZclOps;
impl ProtocolOps for ZigbeeZclOps {
    const MIN_LEN: usize = 3;
    const NAME: &'static str = "Zigbee_ZCL";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct ZigbeeZdpOps;
impl ProtocolOps for ZigbeeZdpOps {
    const MIN_LEN: usize = 2;
    const NAME: &'static str = "Zigbee_ZDP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct MatterOps;
impl ProtocolOps for MatterOps {
    const MIN_LEN: usize = 1;
    const NAME: &'static str = "Matter";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}
