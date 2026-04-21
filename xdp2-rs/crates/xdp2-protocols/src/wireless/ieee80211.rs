//! IEEE 802.11 (Wi-Fi) MAC header protocol definition.
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `Ieee80211Header` | `proto_defs/wireless/proto_ieee80211.h` | `struct ieee80211_hdr` |
//! | `Ieee80211Ops` | `proto_ieee80211.h:72-76` | `xdp2_parse_ieee80211` |
//! | `Ieee80211Ops::next_proto` | `proto_ieee80211.h:58-61` | `ieee80211_proto()` |
//!
//! ## Behavioral Differences
//! - None. Byte-for-byte compatible with C implementation.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// IEEE 802.11 frame type constants.
pub const IEEE80211_FTYPE_MGMT: i32 = 0x0000;
pub const IEEE80211_FTYPE_CTL: i32 = 0x0004;
pub const IEEE80211_FTYPE_DATA: i32 = 0x0008;
pub const IEEE80211_FTYPE_EXT: i32 = 0x000C;

/// Frame control type mask.
const IEEE80211_FCTL_FTYPE: u16 = 0x000C;

/// IEEE 802.11 MAC header (24 bytes, 3-address form).
///
/// Reimplements: `struct ieee80211_hdr` in `proto_ieee80211.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct Ieee80211Header {
    pub frame_control: [u8; 2],
    pub duration_id: [u8; 2],
    pub addr1: [u8; 6],
    pub addr2: [u8; 6],
    pub addr3: [u8; 6],
    pub seq_ctrl: [u8; 2],
}

impl Ieee80211Header {
    /// Frame control field (little-endian).
    pub fn frame_control(&self) -> u16 {
        u16::from_le_bytes(self.frame_control)
    }
    /// Frame type (2 bits).
    pub fn frame_type(&self) -> u16 {
        self.frame_control() & IEEE80211_FCTL_FTYPE
    }
}

/// IEEE 802.11 protocol operations.
///
/// Reimplements: `xdp2_parse_ieee80211` in `proto_ieee80211.h:72-76`
///
/// Dispatches on frame type field.
pub struct Ieee80211Ops;

impl ProtocolOps for Ieee80211Ops {
    const MIN_LEN: usize = 24;
    const NAME: &'static str = "IEEE 802.11";

    /// Return frame type for dispatch.
    ///
    /// Reimplements: `ieee80211_proto()` in `proto_ieee80211.h:58-61`
    #[inline]
    fn next_proto(&self, hdr: &[u8]) -> Result<i32, ParseError> {
        let wifi = Ieee80211Header::ref_from_prefix(hdr)
            .map_err(|_| ParseError::Length)?
            .0;
        Ok((wifi.frame_control() & IEEE80211_FCTL_FTYPE) as i32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_80211(fc: u16) -> [u8; 24] {
        let mut hdr = [0u8; 24];
        hdr[0..2].copy_from_slice(&fc.to_le_bytes());
        hdr
    }

    #[test]
    fn ieee80211_mgmt() {
        let ops = Ieee80211Ops;
        assert_eq!(
            ops.next_proto(&make_80211(0x0000)).unwrap(),
            IEEE80211_FTYPE_MGMT
        );
    }

    #[test]
    fn ieee80211_data() {
        let ops = Ieee80211Ops;
        assert_eq!(
            ops.next_proto(&make_80211(0x0008)).unwrap(),
            IEEE80211_FTYPE_DATA
        );
    }

    #[test]
    fn ieee80211_ctl() {
        let ops = Ieee80211Ops;
        assert_eq!(
            ops.next_proto(&make_80211(0x0004)).unwrap(),
            IEEE80211_FTYPE_CTL
        );
    }

    #[test]
    fn ieee80211_ext() {
        let ops = Ieee80211Ops;
        assert_eq!(
            ops.next_proto(&make_80211(0x000C)).unwrap(),
            IEEE80211_FTYPE_EXT
        );
    }
}
