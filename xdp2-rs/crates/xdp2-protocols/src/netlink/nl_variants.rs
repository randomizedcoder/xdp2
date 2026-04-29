//! Netlink variant protocol leaf definitions (Silver+Bronze tier).

use xdp2_core::{ParseError, ProtocolOps};

pub struct NlDiagInetOps;
impl ProtocolOps for NlDiagInetOps {
    const MIN_LEN: usize = 72;
    const NAME: &'static str = "NL_Diag_Inet";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct NlDiagNetlinkOps;
impl ProtocolOps for NlDiagNetlinkOps {
    const MIN_LEN: usize = 28;
    const NAME: &'static str = "NL_Diag_Netlink";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct NlDiagReqV2Ops;
impl ProtocolOps for NlDiagReqV2Ops {
    const MIN_LEN: usize = 56;
    const NAME: &'static str = "NL_Diag_ReqV2";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct NlDiagSockIdOps;
impl ProtocolOps for NlDiagSockIdOps {
    const MIN_LEN: usize = 48;
    const NAME: &'static str = "NL_Diag_SockID";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct NlDiagUnixOps;
impl ProtocolOps for NlDiagUnixOps {
    const MIN_LEN: usize = 16;
    const NAME: &'static str = "NL_Diag_Unix";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct NlIfStatsOps;
impl ProtocolOps for NlIfStatsOps {
    const MIN_LEN: usize = 12;
    const NAME: &'static str = "NL_IfStats";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct NlLinkOps;
impl ProtocolOps for NlLinkOps {
    const MIN_LEN: usize = 16;
    const NAME: &'static str = "NL_Link";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct NlRouteOps;
impl ProtocolOps for NlRouteOps {
    const MIN_LEN: usize = 12;
    const NAME: &'static str = "NL_Route";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct NlRuleOps;
impl ProtocolOps for NlRuleOps {
    const MIN_LEN: usize = 12;
    const NAME: &'static str = "NL_Rule";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct NlTcOps;
impl ProtocolOps for NlTcOps {
    const MIN_LEN: usize = 20;
    const NAME: &'static str = "NL_TC";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct NlAddrOps;
impl ProtocolOps for NlAddrOps {
    const MIN_LEN: usize = 8;
    const NAME: &'static str = "NL_Addr";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct NlBridgePortOps;
impl ProtocolOps for NlBridgePortOps {
    const MIN_LEN: usize = 5;
    const NAME: &'static str = "NL_Bridge_Port";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct NlDcbOps;
impl ProtocolOps for NlDcbOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "NL_DCB";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct NlDiagPragueInfoOps;
impl ProtocolOps for NlDiagPragueInfoOps {
    const MIN_LEN: usize = 36;
    const NAME: &'static str = "NL_Diag_PragueInfo";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct NlNeighOps;
impl ProtocolOps for NlNeighOps {
    const MIN_LEN: usize = 12;
    const NAME: &'static str = "NL_Neigh";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct NlNetfilterOps;
impl ProtocolOps for NlNetfilterOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "NL_Netfilter";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct NlNexthopOps;
impl ProtocolOps for NlNexthopOps {
    const MIN_LEN: usize = 8;
    const NAME: &'static str = "NL_Nexthop";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct NlPrefixOps;
impl ProtocolOps for NlPrefixOps {
    const MIN_LEN: usize = 12;
    const NAME: &'static str = "NL_Prefix";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct NlXfrmPolicyOps;
impl ProtocolOps for NlXfrmPolicyOps {
    const MIN_LEN: usize = 164;
    const NAME: &'static str = "NL_XFRM_Policy";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct NlXfrmSaOps;
impl ProtocolOps for NlXfrmSaOps {
    const MIN_LEN: usize = 217;
    const NAME: &'static str = "NL_XFRM_SA";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}
