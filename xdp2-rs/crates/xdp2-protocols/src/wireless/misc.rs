//! Wireless sub-protocol definitions (leaf nodes).
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `Ieee80211DataOps` | `proto_defs/wireless/proto_ieee80211_data.h` | `xdp2_parse_ieee80211_data` |
//! | `Ieee80211MgmtOps` | `proto_defs/wireless/proto_ieee80211_mgmt.h` | `xdp2_parse_ieee80211_mgmt` |
//!
//! ## Behavioral Differences
//! - None. Both are leaf nodes with zero-byte headers (payload markers).

use xdp2_core::{ParseError, ProtocolOps};

/// IEEE 802.11 Data payload operations (leaf).
///
/// Reimplements: `xdp2_parse_ieee80211_data` in `proto_ieee80211_data.h`
pub struct Ieee80211DataOps;

impl ProtocolOps for Ieee80211DataOps {
    const MIN_LEN: usize = 0;
    const NAME: &'static str = "802.11 Data";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// IEEE 802.11 Management frame operations (leaf).
///
/// Reimplements: `xdp2_parse_ieee80211_mgmt` in `proto_ieee80211_mgmt.h`
pub struct Ieee80211MgmtOps;

impl ProtocolOps for Ieee80211MgmtOps {
    const MIN_LEN: usize = 0;
    const NAME: &'static str = "802.11 Mgmt";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ieee80211_data_is_leaf() {
        assert!(matches!(
            Ieee80211DataOps.next_proto(&[]),
            Err(ParseError::UnknownProto)
        ));
    }

    #[test]
    fn ieee80211_mgmt_is_leaf() {
        assert!(matches!(
            Ieee80211MgmtOps.next_proto(&[]),
            Err(ParseError::UnknownProto)
        ));
    }
}
