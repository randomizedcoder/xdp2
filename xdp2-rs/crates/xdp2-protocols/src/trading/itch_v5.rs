//! ITCH v5 (Nasdaq TotalView) message types.
//!
//! All ITCH v5 messages are fixed-size leaf protocols — they are terminal
//! message types identified by a single-byte MessageType character in the
//! enclosing MoldUDP64/SoupBinTCP frame.
//!
//! Struct layouts from OMI (Open Markets Initiative) Nasdaq definitions.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

// --- ITCH v5 SystemEvent (6 bytes, type 'S') ---

#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct ItchV5SystemEventHeader {
    pub stock_locate: [u8; 2],
    pub tracking_number: [u8; 2],
    pub timestamp_hi: [u8; 2],
    // Note: timestamps split across fields per OMI spec
}

pub struct ItchV5SystemEventOps;

impl ProtocolOps for ItchV5SystemEventOps {
    const MIN_LEN: usize = 6;
    const NAME: &'static str = "ITCH_v5_SystemEvent";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

// --- ITCH v5 StockDirectory (26 bytes, type 'R') ---

#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct ItchV5StockDirectoryHeader {
    pub stock_locate: [u8; 2],
    pub tracking_number: [u8; 2],
    pub timestamp_hi: [u8; 2],
    pub stock: [u8; 8],
    pub market_category: u8,
    pub financial_status: u8,
    pub round_lot_size: [u8; 4],
    pub round_lots_only: u8,
    pub issue_classification: u8,
    pub issue_subtype: [u8; 2],
    pub authenticity: u8,
    pub short_sale_threshold: u8,
}

pub struct ItchV5StockDirectoryOps;

impl ProtocolOps for ItchV5StockDirectoryOps {
    const MIN_LEN: usize = 26;
    const NAME: &'static str = "ITCH_v5_StockDirectory";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

// --- ITCH v5 StockTradingAction (19 bytes, type 'H') ---

#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct ItchV5StockTradingActionHeader {
    pub stock_locate: [u8; 2],
    pub tracking_number: [u8; 2],
    pub timestamp_hi: [u8; 2],
    pub stock: [u8; 8],
    pub trading_state: u8,
    pub reserved: u8,
    pub reason: [u8; 4],
}

pub struct ItchV5StockTradingActionOps;

impl ProtocolOps for ItchV5StockTradingActionOps {
    const MIN_LEN: usize = 19;
    const NAME: &'static str = "ITCH_v5_StockTradingAction";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

// --- ITCH v5 AddOrder (30 bytes, type 'A') ---

#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct ItchV5AddOrderHeader {
    pub stock_locate: [u8; 2],
    pub tracking_number: [u8; 2],
    pub timestamp_hi: [u8; 2],
    pub order_ref: [u8; 8],
    pub side: u8,
    pub shares: [u8; 4],
    pub stock: [u8; 8],
    pub price: [u8; 4],
}

pub struct ItchV5AddOrderOps;

impl ProtocolOps for ItchV5AddOrderOps {
    const MIN_LEN: usize = 30;
    const NAME: &'static str = "ITCH_v5_AddOrder";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

// --- ITCH v5 AddOrderMPID (34 bytes, type 'F') ---

#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct ItchV5AddOrderMpidHeader {
    pub stock_locate: [u8; 2],
    pub tracking_number: [u8; 2],
    pub timestamp_hi: [u8; 2],
    pub order_ref: [u8; 8],
    pub side: u8,
    pub shares: [u8; 4],
    pub stock: [u8; 8],
    pub price: [u8; 4],
    pub attribution: [u8; 4],
}

pub struct ItchV5AddOrderMpidOps;

impl ProtocolOps for ItchV5AddOrderMpidOps {
    const MIN_LEN: usize = 34;
    const NAME: &'static str = "ITCH_v5_AddOrderMPID";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

// --- ITCH v5 OrderExecuted (25 bytes, type 'E') ---

#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct ItchV5OrderExecutedHeader {
    pub stock_locate: [u8; 2],
    pub tracking_number: [u8; 2],
    pub timestamp_hi: [u8; 2],
    pub order_ref: [u8; 8],
    pub executed_shares: [u8; 4],
    pub match_number: [u8; 8],
}

pub struct ItchV5OrderExecutedOps;

impl ProtocolOps for ItchV5OrderExecutedOps {
    const MIN_LEN: usize = 25;
    const NAME: &'static str = "ITCH_v5_OrderExecuted";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

// --- ITCH v5 OrderExecutedWithPrice (30 bytes, type 'C') ---

#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct ItchV5OrderExecutedWithPriceHeader {
    pub stock_locate: [u8; 2],
    pub tracking_number: [u8; 2],
    pub timestamp_hi: [u8; 2],
    pub order_ref: [u8; 8],
    pub executed_shares: [u8; 4],
    pub match_number: [u8; 8],
    pub printable: u8,
    pub execution_price: [u8; 4],
}

pub struct ItchV5OrderExecutedWithPriceOps;

impl ProtocolOps for ItchV5OrderExecutedWithPriceOps {
    const MIN_LEN: usize = 30;
    const NAME: &'static str = "ITCH_v5_OrderExecutedWithPrice";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

// --- ITCH v5 OrderCancel (17 bytes, type 'X') ---

#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct ItchV5OrderCancelHeader {
    pub stock_locate: [u8; 2],
    pub tracking_number: [u8; 2],
    pub timestamp_hi: [u8; 2],
    pub order_ref: [u8; 8],
    pub cancelled_shares: [u8; 4],
}

pub struct ItchV5OrderCancelOps;

impl ProtocolOps for ItchV5OrderCancelOps {
    const MIN_LEN: usize = 17;
    const NAME: &'static str = "ITCH_v5_OrderCancel";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

// --- ITCH v5 OrderDelete (13 bytes, type 'D') ---

#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct ItchV5OrderDeleteHeader {
    pub stock_locate: [u8; 2],
    pub tracking_number: [u8; 2],
    pub timestamp_hi: [u8; 2],
    pub order_ref: [u8; 8],
}

pub struct ItchV5OrderDeleteOps;

impl ProtocolOps for ItchV5OrderDeleteOps {
    const MIN_LEN: usize = 13;
    const NAME: &'static str = "ITCH_v5_OrderDelete";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

// --- ITCH v5 OrderReplace (29 bytes, type 'U') ---

#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct ItchV5OrderReplaceHeader {
    pub stock_locate: [u8; 2],
    pub tracking_number: [u8; 2],
    pub timestamp_hi: [u8; 2],
    pub original_order_ref: [u8; 8],
    pub new_order_ref: [u8; 8],
    pub shares: [u8; 4],
    pub price: [u8; 4],
}

pub struct ItchV5OrderReplaceOps;

impl ProtocolOps for ItchV5OrderReplaceOps {
    const MIN_LEN: usize = 29;
    const NAME: &'static str = "ITCH_v5_OrderReplace";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

// --- ITCH v5 NonCrossTrade (38 bytes, type 'P') ---

#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct ItchV5NonCrossTradeHeader {
    pub stock_locate: [u8; 2],
    pub tracking_number: [u8; 2],
    pub timestamp_hi: [u8; 2],
    pub order_ref: [u8; 8],
    pub side: u8,
    pub shares: [u8; 4],
    pub stock: [u8; 8],
    pub price: [u8; 4],
    pub match_number: [u8; 8],
}

pub struct ItchV5NonCrossTradeOps;

impl ProtocolOps for ItchV5NonCrossTradeOps {
    const MIN_LEN: usize = 38;
    const NAME: &'static str = "ITCH_v5_NonCrossTrade";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

// --- ITCH v5 CrossTrade (39 bytes, type 'Q') ---

#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct ItchV5CrossTradeHeader {
    pub stock_locate: [u8; 2],
    pub tracking_number: [u8; 2],
    pub timestamp_hi: [u8; 2],
    pub shares: [u8; 8],
    pub stock: [u8; 8],
    pub cross_price: [u8; 4],
    pub match_number: [u8; 8],
    pub cross_type: u8,
}

pub struct ItchV5CrossTradeOps;

impl ProtocolOps for ItchV5CrossTradeOps {
    const MIN_LEN: usize = 39;
    const NAME: &'static str = "ITCH_v5_CrossTrade";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

// --- ITCH v5 BrokenTrade (19 bytes, type 'B') ---

#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct ItchV5BrokenTradeHeader {
    pub stock_locate: [u8; 2],
    pub tracking_number: [u8; 2],
    pub timestamp_hi: [u8; 2],
    pub match_number: [u8; 8],
}

pub struct ItchV5BrokenTradeOps;

impl ProtocolOps for ItchV5BrokenTradeOps {
    const MIN_LEN: usize = 19;
    const NAME: &'static str = "ITCH_v5_BrokenTrade";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_event_is_leaf() {
        assert!(matches!(
            ItchV5SystemEventOps.next_proto(&[0u8; 6]),
            Err(ParseError::UnknownProto)
        ));
    }

    #[test]
    fn add_order_is_leaf() {
        assert!(matches!(
            ItchV5AddOrderOps.next_proto(&[0u8; 30]),
            Err(ParseError::UnknownProto)
        ));
    }

    #[test]
    fn order_executed_is_leaf() {
        assert!(matches!(
            ItchV5OrderExecutedOps.next_proto(&[0u8; 25]),
            Err(ParseError::UnknownProto)
        ));
    }

    #[test]
    fn cross_trade_is_leaf() {
        assert!(matches!(
            ItchV5CrossTradeOps.next_proto(&[0u8; 39]),
            Err(ParseError::UnknownProto)
        ));
    }

    #[test]
    fn non_cross_trade_is_leaf() {
        assert!(matches!(
            ItchV5NonCrossTradeOps.next_proto(&[0u8; 38]),
            Err(ParseError::UnknownProto)
        ));
    }

    #[test]
    fn order_delete_is_leaf() {
        assert!(matches!(
            ItchV5OrderDeleteOps.next_proto(&[0u8; 13]),
            Err(ParseError::UnknownProto)
        ));
    }

    #[test]
    fn broken_trade_is_leaf() {
        assert!(matches!(
            ItchV5BrokenTradeOps.next_proto(&[0u8; 19]),
            Err(ParseError::UnknownProto)
        ));
    }

    #[test]
    fn header_sizes_match_spec() {
        assert_eq!(ItchV5SystemEventOps::MIN_LEN, 6);
        assert_eq!(ItchV5StockDirectoryOps::MIN_LEN, 26);
        assert_eq!(ItchV5StockTradingActionOps::MIN_LEN, 19);
        assert_eq!(ItchV5AddOrderOps::MIN_LEN, 30);
        assert_eq!(ItchV5AddOrderMpidOps::MIN_LEN, 34);
        assert_eq!(ItchV5OrderExecutedOps::MIN_LEN, 25);
        assert_eq!(ItchV5OrderExecutedWithPriceOps::MIN_LEN, 30);
        assert_eq!(ItchV5OrderCancelOps::MIN_LEN, 17);
        assert_eq!(ItchV5OrderDeleteOps::MIN_LEN, 13);
        assert_eq!(ItchV5OrderReplaceOps::MIN_LEN, 29);
        assert_eq!(ItchV5NonCrossTradeOps::MIN_LEN, 38);
        assert_eq!(ItchV5CrossTradeOps::MIN_LEN, 39);
        assert_eq!(ItchV5BrokenTradeOps::MIN_LEN, 19);
    }
}
