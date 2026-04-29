//! IPv6-related variant and extension protocol leaf definitions.

use xdp2_core::{ParseError, ProtocolOps};

pub struct Ipv6DestOptsOps;
impl ProtocolOps for Ipv6DestOptsOps {
    const MIN_LEN: usize = 2;
    const NAME: &'static str = "IPv6_DestOpts";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct Ipv6FragmentOps;
impl ProtocolOps for Ipv6FragmentOps {
    const MIN_LEN: usize = 8;
    const NAME: &'static str = "IPv6_Fragment";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct Ipv6HopByHopOps;
impl ProtocolOps for Ipv6HopByHopOps {
    const MIN_LEN: usize = 2;
    const NAME: &'static str = "IPv6_HopByHop";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct Ipv6NdOps;
impl ProtocolOps for Ipv6NdOps {
    const MIN_LEN: usize = 24;
    const NAME: &'static str = "IPv6_ND";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct Ipv6RplOps;
impl ProtocolOps for Ipv6RplOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "IPv6_RPL";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct Ipv6RoutingOps;
impl ProtocolOps for Ipv6RoutingOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "IPv6_Routing";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct MldReportV1Ops;
impl ProtocolOps for MldReportV1Ops {
    const MIN_LEN: usize = 20;
    const NAME: &'static str = "MLD_Report_v1";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct PimAssertOps;
impl ProtocolOps for PimAssertOps {
    const MIN_LEN: usize = 12;
    const NAME: &'static str = "PIM_Assert";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct PimBsrOps;
impl ProtocolOps for PimBsrOps {
    const MIN_LEN: usize = 8;
    const NAME: &'static str = "PIM_BSR";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct Pimv6Ops;
impl ProtocolOps for Pimv6Ops {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "PIMv6";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct Vrrp3Ops;
impl ProtocolOps for Vrrp3Ops {
    const MIN_LEN: usize = 8;
    const NAME: &'static str = "VRRP3";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct VrrpIpv6Ops;
impl ProtocolOps for VrrpIpv6Ops {
    const MIN_LEN: usize = 8;
    const NAME: &'static str = "VRRP_IPv6";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct EspNullOps;
impl ProtocolOps for EspNullOps {
    const MIN_LEN: usize = 8;
    const NAME: &'static str = "ESP_NULL";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct Ikev1Ops;
impl ProtocolOps for Ikev1Ops {
    const MIN_LEN: usize = 28;
    const NAME: &'static str = "IKEv1";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}
