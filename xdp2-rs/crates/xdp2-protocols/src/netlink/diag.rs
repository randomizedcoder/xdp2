//! Netlink diagnostic and attribute protocol definitions (leaf nodes).
//!
//! These correspond to the Gold-tier protocols validated by proto-audit:
//! NLAttr, GenNetlink, and the NL_Diag_* family of sock_diag responses.

use xdp2_core::{ParseError, ProtocolOps};

// ---------------------------------------------------------------------------
// NLAttr
// ---------------------------------------------------------------------------

/// Netlink attribute operations (leaf).
pub struct NlAttrOps;

impl ProtocolOps for NlAttrOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "NLAttr";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

// ---------------------------------------------------------------------------
// GenNetlink
// ---------------------------------------------------------------------------

/// Generic Netlink operations (leaf).
pub struct GenNetlinkOps;

impl ProtocolOps for GenNetlinkOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "GenNetlink";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

// ---------------------------------------------------------------------------
// NL_Diag_BBRInfo
// ---------------------------------------------------------------------------

/// Netlink diagnostics BBR info operations (leaf).
pub struct NlDiagBbrInfoOps;

impl ProtocolOps for NlDiagBbrInfoOps {
    const MIN_LEN: usize = 20;
    const NAME: &'static str = "NL_Diag_BBRInfo";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

// ---------------------------------------------------------------------------
// NL_Diag_DCTCPInfo
// ---------------------------------------------------------------------------

/// Netlink diagnostics DCTCP info operations (leaf).
pub struct NlDiagDctcpInfoOps;

impl ProtocolOps for NlDiagDctcpInfoOps {
    const MIN_LEN: usize = 16;
    const NAME: &'static str = "NL_Diag_DCTCPInfo";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

// ---------------------------------------------------------------------------
// NL_Diag_MemInfo
// ---------------------------------------------------------------------------

/// Netlink diagnostics memory info operations (leaf).
pub struct NlDiagMemInfoOps;

impl ProtocolOps for NlDiagMemInfoOps {
    const MIN_LEN: usize = 16;
    const NAME: &'static str = "NL_Diag_MemInfo";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

// ---------------------------------------------------------------------------
// NL_Diag_SkMemInfo
// ---------------------------------------------------------------------------

/// Netlink diagnostics socket memory info operations (leaf).
pub struct NlDiagSkMemInfoOps;

impl ProtocolOps for NlDiagSkMemInfoOps {
    const MIN_LEN: usize = 36;
    const NAME: &'static str = "NL_Diag_SkMemInfo";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

// ---------------------------------------------------------------------------
// NL_Diag_TCPInfo
// ---------------------------------------------------------------------------

/// Netlink diagnostics TCP info operations (leaf).
pub struct NlDiagTcpInfoOps;

impl ProtocolOps for NlDiagTcpInfoOps {
    const MIN_LEN: usize = 248;
    const NAME: &'static str = "NL_Diag_TCPInfo";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

// ---------------------------------------------------------------------------
// NL_Diag_VegasInfo
// ---------------------------------------------------------------------------

/// Netlink diagnostics Vegas info operations (leaf).
pub struct NlDiagVegasInfoOps;

impl ProtocolOps for NlDiagVegasInfoOps {
    const MIN_LEN: usize = 16;
    const NAME: &'static str = "NL_Diag_VegasInfo";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nlattr_is_leaf() {
        assert!(matches!(
            NlAttrOps.next_proto(&[0u8; 4]),
            Err(ParseError::UnknownProto)
        ));
    }

    #[test]
    fn gen_netlink_is_leaf() {
        assert!(matches!(
            GenNetlinkOps.next_proto(&[0u8; 4]),
            Err(ParseError::UnknownProto)
        ));
    }

    #[test]
    fn nl_diag_bbrinfo_is_leaf() {
        assert!(matches!(
            NlDiagBbrInfoOps.next_proto(&[0u8; 20]),
            Err(ParseError::UnknownProto)
        ));
    }

    #[test]
    fn nl_diag_dctcpinfo_is_leaf() {
        assert!(matches!(
            NlDiagDctcpInfoOps.next_proto(&[0u8; 16]),
            Err(ParseError::UnknownProto)
        ));
    }

    #[test]
    fn nl_diag_meminfo_is_leaf() {
        assert!(matches!(
            NlDiagMemInfoOps.next_proto(&[0u8; 16]),
            Err(ParseError::UnknownProto)
        ));
    }

    #[test]
    fn nl_diag_skmeminfo_is_leaf() {
        assert!(matches!(
            NlDiagSkMemInfoOps.next_proto(&[0u8; 36]),
            Err(ParseError::UnknownProto)
        ));
    }

    #[test]
    fn nl_diag_tcpinfo_is_leaf() {
        assert!(matches!(
            NlDiagTcpInfoOps.next_proto(&[0u8; 248]),
            Err(ParseError::UnknownProto)
        ));
    }

    #[test]
    fn nl_diag_vegasinfo_is_leaf() {
        assert!(matches!(
            NlDiagVegasInfoOps.next_proto(&[0u8; 16]),
            Err(ParseError::UnknownProto)
        ));
    }
}
