//! Telecom signaling and mobile core protocol leaf definitions.

use xdp2_core::{ParseError, ProtocolOps};

pub struct SccpOps;
impl ProtocolOps for SccpOps {
    const MIN_LEN: usize = 5;
    const NAME: &'static str = "SCCP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct M2paOps;
impl ProtocolOps for M2paOps {
    const MIN_LEN: usize = 8;
    const NAME: &'static str = "M2PA";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct M3uaOps;
impl ProtocolOps for M3uaOps {
    const MIN_LEN: usize = 8;
    const NAME: &'static str = "M3UA";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct SuaOps;
impl ProtocolOps for SuaOps {
    const MIN_LEN: usize = 8;
    const NAME: &'static str = "SUA";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct MegacoOps;
impl ProtocolOps for MegacoOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "MEGACO";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct H225Ops;
impl ProtocolOps for H225Ops {
    const MIN_LEN: usize = 3;
    const NAME: &'static str = "H225";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct NgapOps;
impl ProtocolOps for NgapOps {
    const MIN_LEN: usize = 3;
    const NAME: &'static str = "NGAP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct S1apOps;
impl ProtocolOps for S1apOps {
    const MIN_LEN: usize = 3;
    const NAME: &'static str = "S1AP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct RanapOps;
impl ProtocolOps for RanapOps {
    const MIN_LEN: usize = 3;
    const NAME: &'static str = "RANAP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct NasEpsOps;
impl ProtocolOps for NasEpsOps {
    const MIN_LEN: usize = 2;
    const NAME: &'static str = "NAS_EPS";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct Nas5gsOps;
impl ProtocolOps for Nas5gsOps {
    const MIN_LEN: usize = 2;
    const NAME: &'static str = "NAS_5GS";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct BssgpOps;
impl ProtocolOps for BssgpOps {
    const MIN_LEN: usize = 3;
    const NAME: &'static str = "BSSGP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}
