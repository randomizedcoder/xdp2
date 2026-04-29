//! OAM, spanning tree, LLDP extension, and MPLS management leaf definitions.

use xdp2_core::{ParseError, ProtocolOps};

pub struct OamLbmOps;
impl ProtocolOps for OamLbmOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "OAM_LBM";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct OamLtmOps;
impl ProtocolOps for OamLtmOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "OAM_LTM";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct Y1731Ops;
impl ProtocolOps for Y1731Ops {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "Y1731";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct G8032Ops;
impl ProtocolOps for G8032Ops {
    const MIN_LEN: usize = 32;
    const NAME: &'static str = "G8032";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct ElmiOps;
impl ProtocolOps for ElmiOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "ELMI";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct DcbxOps;
impl ProtocolOps for DcbxOps {
    const MIN_LEN: usize = 2;
    const NAME: &'static str = "DCBX";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct MarkerOps;
impl ProtocolOps for MarkerOps {
    const MIN_LEN: usize = 50;
    const NAME: &'static str = "MARKER";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct MmrpOps;
impl ProtocolOps for MmrpOps {
    const MIN_LEN: usize = 2;
    const NAME: &'static str = "MMRP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct MrpOps;
impl ProtocolOps for MrpOps {
    const MIN_LEN: usize = 3;
    const NAME: &'static str = "MRP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct RstpOps;
impl ProtocolOps for RstpOps {
    const MIN_LEN: usize = 36;
    const NAME: &'static str = "RSTP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct MstpOps;
impl ProtocolOps for MstpOps {
    const MIN_LEN: usize = 38;
    const NAME: &'static str = "MSTP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct PvstOps;
impl ProtocolOps for PvstOps {
    const MIN_LEN: usize = 35;
    const NAME: &'static str = "PVST";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct MplsEchoOps;
impl ProtocolOps for MplsEchoOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "MPLS_Echo";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct MplsTpOps;
impl ProtocolOps for MplsTpOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "MPLS_TP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct Lldp8021abOps;
impl ProtocolOps for Lldp8021abOps {
    const MIN_LEN: usize = 2;
    const NAME: &'static str = "LLDP_802_1AB";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct LldpCdpOps;
impl ProtocolOps for LldpCdpOps {
    const MIN_LEN: usize = 2;
    const NAME: &'static str = "LLDP_CDP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct LldpExtDot1Ops;
impl ProtocolOps for LldpExtDot1Ops {
    const MIN_LEN: usize = 2;
    const NAME: &'static str = "LLDP_EXT_DOT1";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct LldpExtDot3Ops;
impl ProtocolOps for LldpExtDot3Ops {
    const MIN_LEN: usize = 2;
    const NAME: &'static str = "LLDP_EXT_DOT3";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct LmpOps;
impl ProtocolOps for LmpOps {
    const MIN_LEN: usize = 12;
    const NAME: &'static str = "LMP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}
