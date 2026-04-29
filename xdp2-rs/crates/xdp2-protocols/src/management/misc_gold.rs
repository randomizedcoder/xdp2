//! Miscellaneous Gold-tier management protocol leaf definitions.

use xdp2_core::{ParseError, ProtocolOps};

/// BMP protocol operations (leaf, MIN_LEN = 6).
pub struct BmpOps;
impl ProtocolOps for BmpOps {
    const MIN_LEN: usize = 6;
    const NAME: &'static str = "BMP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// COPS protocol operations (leaf, MIN_LEN = 8).
pub struct CopsOps;
impl ProtocolOps for CopsOps {
    const MIN_LEN: usize = 8;
    const NAME: &'static str = "COPS";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// Collectd protocol operations (leaf, MIN_LEN = 4).
pub struct CollectdOps;
impl ProtocolOps for CollectdOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "Collectd";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// NNTP protocol operations (leaf, MIN_LEN = 1).
pub struct NntpOps;
impl ProtocolOps for NntpOps {
    const MIN_LEN: usize = 1;
    const NAME: &'static str = "NNTP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// NTS protocol operations (leaf, MIN_LEN = 4).
pub struct NtsOps;
impl ProtocolOps for NtsOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "NTS";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// PCP protocol operations (leaf, MIN_LEN = 24).
pub struct PcpOps;
impl ProtocolOps for PcpOps {
    const MIN_LEN: usize = 24;
    const NAME: &'static str = "PCP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// PCEP protocol operations (leaf, MIN_LEN = 4).
pub struct PcepOps;
impl ProtocolOps for PcepOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "PCEP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// RPKI-RTR protocol operations (leaf, MIN_LEN = 8).
pub struct RpkiRtrOps;
impl ProtocolOps for RpkiRtrOps {
    const MIN_LEN: usize = 8;
    const NAME: &'static str = "RPKI_RTR";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// Babel routing protocol operations (leaf, MIN_LEN = 4).
pub struct BabelOps;
impl ProtocolOps for BabelOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "Babel";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// MSDP Source-Active protocol operations (leaf, MIN_LEN = 20).
pub struct MsdpSaOps;
impl ProtocolOps for MsdpSaOps {
    const MIN_LEN: usize = 20;
    const NAME: &'static str = "MSDP_SA";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// SDP protocol operations (leaf, MIN_LEN = 4).
pub struct SdpOps;
impl ProtocolOps for SdpOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "SDP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// MGCP NCS protocol operations (leaf, MIN_LEN = 1).
pub struct MgcpNcsOps;
impl ProtocolOps for MgcpNcsOps {
    const MIN_LEN: usize = 1;
    const NAME: &'static str = "MGCP_NCS";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// PROFINET DCP protocol operations (leaf, MIN_LEN = 10).
pub struct ProfinetDcpOps;
impl ProtocolOps for ProfinetDcpOps {
    const MIN_LEN: usize = 10;
    const NAME: &'static str = "PROFINET_DCP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// AVTP protocol operations (leaf, MIN_LEN = 12).
pub struct AvtpOps;
impl ProtocolOps for AvtpOps {
    const MIN_LEN: usize = 12;
    const NAME: &'static str = "AVTP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// EtherType TSN protocol operations (leaf, MIN_LEN = 14).
pub struct EtherTypeTsnOps;
impl ProtocolOps for EtherTypeTsnOps {
    const MIN_LEN: usize = 14;
    const NAME: &'static str = "EtherType_TSN";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// GOOSE protocol operations (leaf, MIN_LEN = 8).
pub struct GooseOps;
impl ProtocolOps for GooseOps {
    const MIN_LEN: usize = 8;
    const NAME: &'static str = "GOOSE";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// IEC 60870-5-104 protocol operations (leaf, MIN_LEN = 6).
pub struct Iec104Ops;
impl ProtocolOps for Iec104Ops {
    const MIN_LEN: usize = 6;
    const NAME: &'static str = "IEC_104";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// FCoE FIP protocol operations (leaf, MIN_LEN = 2).
pub struct FcoeFipOps;
impl ProtocolOps for FcoeFipOps {
    const MIN_LEN: usize = 2;
    const NAME: &'static str = "FCOE_FIP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}
