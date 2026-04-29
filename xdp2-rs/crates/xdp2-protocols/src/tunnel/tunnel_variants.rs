//! Tunnel variant and extension protocol leaf definitions.

use xdp2_core::{ParseError, ProtocolOps};

pub struct AmtOps;
impl ProtocolOps for AmtOps {
    const MIN_LEN: usize = 8;
    const NAME: &'static str = "AMT";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct AyiyaOps;
impl ProtocolOps for AyiyaOps {
    const MIN_LEN: usize = 8;
    const NAME: &'static str = "AYIYA";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct GreOps;
impl ProtocolOps for GreOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "GRE";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct GreCiscoOps;
impl ProtocolOps for GreCiscoOps {
    const MIN_LEN: usize = 8;
    const NAME: &'static str = "GRE_Cisco";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct GtpV0Ops;
impl ProtocolOps for GtpV0Ops {
    const MIN_LEN: usize = 20;
    const NAME: &'static str = "GTP_V0";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct L2tpOps;
impl ProtocolOps for L2tpOps {
    const MIN_LEN: usize = 6;
    const NAME: &'static str = "L2TP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct L2tpAvpOps;
impl ProtocolOps for L2tpAvpOps {
    const MIN_LEN: usize = 6;
    const NAME: &'static str = "L2TP_AVP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct LispControlOps;
impl ProtocolOps for LispControlOps {
    const MIN_LEN: usize = 8;
    const NAME: &'static str = "LISP_Control";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct TzspV2Ops;
impl ProtocolOps for TzspV2Ops {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "TZSP_V2";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct GeneveOps;
impl ProtocolOps for GeneveOps {
    const MIN_LEN: usize = 8;
    const NAME: &'static str = "Geneve";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct GeneveOptOps;
impl ProtocolOps for GeneveOptOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "GENEVE_OPT";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct VxlanGbpOps;
impl ProtocolOps for VxlanGbpOps {
    const MIN_LEN: usize = 8;
    const NAME: &'static str = "VXLAN_GBP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct VxlanGpbOps;
impl ProtocolOps for VxlanGpbOps {
    const MIN_LEN: usize = 8;
    const NAME: &'static str = "VXLAN_GPB";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct PppCcpOps;
impl ProtocolOps for PppCcpOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "PPP_CCP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct PppChapOps;
impl ProtocolOps for PppChapOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "PPP_CHAP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct PppIpcpOps;
impl ProtocolOps for PppIpcpOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "PPP_IPCP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct PppIpv6cpOps;
impl ProtocolOps for PppIpv6cpOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "PPP_IPv6CP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct PppLcpOps;
impl ProtocolOps for PppLcpOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "PPP_LCP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct PppPapOps;
impl ProtocolOps for PppPapOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "PPP_PAP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct PppoedOps;
impl ProtocolOps for PppoedOps {
    const MIN_LEN: usize = 6;
    const NAME: &'static str = "PPPoED";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct ErspanV3Ops;
impl ProtocolOps for ErspanV3Ops {
    const MIN_LEN: usize = 12;
    const NAME: &'static str = "ERSPAN_V3";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}
