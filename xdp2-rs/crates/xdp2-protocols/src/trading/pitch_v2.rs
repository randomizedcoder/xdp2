//! PITCH v2 (Cboe BYX/BZX) message types.
//!
//! All PITCH v2 messages are fixed-size leaf protocols.
//! Struct layouts from OMI Cboe definitions.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

// --- PITCH v2 AddOrderLong (34 bytes, type 0x21) ---

#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct PitchV2AddOrderLongHeader {
    pub time_offset: [u8; 4],
    pub order_id: [u8; 8],
    pub side: u8,
    pub quantity: [u8; 4],
    pub symbol: [u8; 6],
    pub price: [u8; 8],
    pub flags: u8,
    pub firm_id: [u8; 4],
}

pub struct PitchV2AddOrderLongOps;

impl ProtocolOps for PitchV2AddOrderLongOps {
    const MIN_LEN: usize = 34;
    const NAME: &'static str = "PITCH_v2_AddOrderLong";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

// --- PITCH v2 AddOrderShort (26 bytes, type 0x22) ---

#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct PitchV2AddOrderShortHeader {
    pub time_offset: [u8; 4],
    pub order_id: [u8; 8],
    pub side: u8,
    pub quantity: [u8; 2],
    pub symbol: [u8; 6],
    pub price: [u8; 2],
    pub flags: u8,
    pub firm_id: [u8; 4],
}

pub struct PitchV2AddOrderShortOps;

impl ProtocolOps for PitchV2AddOrderShortOps {
    const MIN_LEN: usize = 26;
    const NAME: &'static str = "PITCH_v2_AddOrderShort";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

// --- PITCH v2 OrderExecuted (26 bytes, type 0x23) ---

#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct PitchV2OrderExecutedHeader {
    pub time_offset: [u8; 4],
    pub order_id: [u8; 8],
    pub executed_quantity: [u8; 4],
    pub execution_id: [u8; 8],
    pub trade_condition: u8,
}

pub struct PitchV2OrderExecutedOps;

impl ProtocolOps for PitchV2OrderExecutedOps {
    const MIN_LEN: usize = 26;
    const NAME: &'static str = "PITCH_v2_OrderExecuted";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_order_long_is_leaf() {
        assert!(matches!(
            PitchV2AddOrderLongOps.next_proto(&[0u8; 34]),
            Err(ParseError::UnknownProto)
        ));
    }

    #[test]
    fn add_order_short_is_leaf() {
        assert!(matches!(
            PitchV2AddOrderShortOps.next_proto(&[0u8; 26]),
            Err(ParseError::UnknownProto)
        ));
    }

    #[test]
    fn order_executed_is_leaf() {
        assert!(matches!(
            PitchV2OrderExecutedOps.next_proto(&[0u8; 26]),
            Err(ParseError::UnknownProto)
        ));
    }

    #[test]
    fn header_sizes_match_spec() {
        assert_eq!(PitchV2AddOrderLongOps::MIN_LEN, 34);
        assert_eq!(PitchV2AddOrderShortOps::MIN_LEN, 26);
        assert_eq!(PitchV2OrderExecutedOps::MIN_LEN, 26);
    }
}
