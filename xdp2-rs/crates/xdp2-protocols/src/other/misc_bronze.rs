//! Miscellaneous protocol leaf definitions (Bronze tier).

use xdp2_core::{ParseError, ProtocolOps};

pub struct CmpOps;
impl ProtocolOps for CmpOps {
    const MIN_LEN: usize = 3;
    const NAME: &'static str = "CMP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct Dtls13Ops;
impl ProtocolOps for Dtls13Ops {
    const MIN_LEN: usize = 1;
    const NAME: &'static str = "DTLS_13";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct DohOps;
impl ProtocolOps for DohOps {
    const MIN_LEN: usize = 1;
    const NAME: &'static str = "DoH";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct FcoeInitOps;
impl ProtocolOps for FcoeInitOps {
    const MIN_LEN: usize = 36;
    const NAME: &'static str = "FCoE_Init";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct GreWccpv2Ops;
impl ProtocolOps for GreWccpv2Ops {
    const MIN_LEN: usize = 8;
    const NAME: &'static str = "GRE_WCCPv2";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct H245Ops;
impl ProtocolOps for H245Ops {
    const MIN_LEN: usize = 3;
    const NAME: &'static str = "H245";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct H323Ops;
impl ProtocolOps for H323Ops {
    const MIN_LEN: usize = 3;
    const NAME: &'static str = "H323";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct Http3Ops;
impl ProtocolOps for Http3Ops {
    const MIN_LEN: usize = 1;
    const NAME: &'static str = "HTTP3";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct Higig2Ops;
impl ProtocolOps for Higig2Ops {
    const MIN_LEN: usize = 16;
    const NAME: &'static str = "HiGig2";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct Nfsv4Ops;
impl ProtocolOps for Nfsv4Ops {
    const MIN_LEN: usize = 12;
    const NAME: &'static str = "NFSv4";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct OcspResponseOps;
impl ProtocolOps for OcspResponseOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "OCSP_Response";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct RdmaCmOps;
impl ProtocolOps for RdmaCmOps {
    const MIN_LEN: usize = 36;
    const NAME: &'static str = "RDMA_CM";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct RGooseOps;
impl ProtocolOps for RGooseOps {
    const MIN_LEN: usize = 8;
    const NAME: &'static str = "R_GOOSE";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct S7commOps;
impl ProtocolOps for S7commOps {
    const MIN_LEN: usize = 10;
    const NAME: &'static str = "S7COMM";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct T38Ops;
impl ProtocolOps for T38Ops {
    const MIN_LEN: usize = 2;
    const NAME: &'static str = "T38";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct TcapOps;
impl ProtocolOps for TcapOps {
    const MIN_LEN: usize = 2;
    const NAME: &'static str = "TCAP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct UdsOps;
impl ProtocolOps for UdsOps {
    const MIN_LEN: usize = 3;
    const NAME: &'static str = "UDS";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct XcpOps;
impl ProtocolOps for XcpOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "XCP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}
