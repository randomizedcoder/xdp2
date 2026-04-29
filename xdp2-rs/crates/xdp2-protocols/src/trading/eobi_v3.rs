//! EOBI v3 (Enhanced Order Book Interface) protocol leaf definitions (Silver+Bronze tier).

use xdp2_core::{ParseError, ProtocolOps};

pub struct EobiV3HeartbeatOps;
impl ProtocolOps for EobiV3HeartbeatOps {
    const MIN_LEN: usize = 8;
    const NAME: &'static str = "EOBI_v3_Heartbeat";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct EobiV3OrderAddOps;
impl ProtocolOps for EobiV3OrderAddOps {
    const MIN_LEN: usize = 40;
    const NAME: &'static str = "EOBI_v3_OrderAdd";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct EobiV3SnapshotOrderOps;
impl ProtocolOps for EobiV3SnapshotOrderOps {
    const MIN_LEN: usize = 24;
    const NAME: &'static str = "EOBI_v3_SnapshotOrder";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

pub struct EobiTradeReportOps;
impl ProtocolOps for EobiTradeReportOps {
    const MIN_LEN: usize = 16;
    const NAME: &'static str = "EOBI_TradeReport";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}
