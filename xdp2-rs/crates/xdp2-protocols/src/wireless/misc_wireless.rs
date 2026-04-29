//! Miscellaneous wireless protocol definitions (leaf nodes).
//!
//! These correspond to Gold-tier protocols validated by proto-audit:
//! Radiotap, BLE_LL, LoRaWAN, IEEE802154, PTP_V1, gPTP, eCPRI, WPA_EAPOL_Key.

use xdp2_core::{ParseError, ProtocolOps};

// ---------------------------------------------------------------------------
// Radiotap
// ---------------------------------------------------------------------------

/// Radiotap header operations (leaf).
pub struct RadiotapOps;

impl ProtocolOps for RadiotapOps {
    const MIN_LEN: usize = 8;
    const NAME: &'static str = "Radiotap";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

// ---------------------------------------------------------------------------
// BLE_LL
// ---------------------------------------------------------------------------

/// Bluetooth Low Energy Link Layer operations (leaf).
pub struct BleLlOps;

impl ProtocolOps for BleLlOps {
    const MIN_LEN: usize = 2;
    const NAME: &'static str = "BLE_LL";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

// ---------------------------------------------------------------------------
// LoRaWAN
// ---------------------------------------------------------------------------

/// LoRaWAN MAC operations (leaf).
pub struct LorawanOps;

impl ProtocolOps for LorawanOps {
    const MIN_LEN: usize = 1;
    const NAME: &'static str = "LoRaWAN";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

// ---------------------------------------------------------------------------
// IEEE802154
// ---------------------------------------------------------------------------

/// IEEE 802.15.4 operations (leaf).
pub struct Ieee802154Ops;

impl ProtocolOps for Ieee802154Ops {
    const MIN_LEN: usize = 3;
    const NAME: &'static str = "IEEE802154";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

// ---------------------------------------------------------------------------
// PTP_V1
// ---------------------------------------------------------------------------

/// Precision Time Protocol v1 operations (leaf).
pub struct PtpV1Ops;

impl ProtocolOps for PtpV1Ops {
    const MIN_LEN: usize = 40;
    const NAME: &'static str = "PTP_V1";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

// ---------------------------------------------------------------------------
// gPTP
// ---------------------------------------------------------------------------

/// Generalized Precision Time Protocol operations (leaf).
pub struct GptpOps;

impl ProtocolOps for GptpOps {
    const MIN_LEN: usize = 34;
    const NAME: &'static str = "gPTP";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

// ---------------------------------------------------------------------------
// eCPRI
// ---------------------------------------------------------------------------

/// Enhanced Common Public Radio Interface operations (leaf).
pub struct EcpriOps;

impl ProtocolOps for EcpriOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "eCPRI";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

// ---------------------------------------------------------------------------
// WPA_EAPOL_Key
// ---------------------------------------------------------------------------

/// WPA EAPOL Key frame operations (leaf).
pub struct WpaEapolKeyOps;

impl ProtocolOps for WpaEapolKeyOps {
    const MIN_LEN: usize = 95;
    const NAME: &'static str = "WPA_EAPOL_Key";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn radiotap_is_leaf() {
        assert!(matches!(
            RadiotapOps.next_proto(&[0u8; 8]),
            Err(ParseError::UnknownProto)
        ));
    }

    #[test]
    fn ble_ll_is_leaf() {
        assert!(matches!(
            BleLlOps.next_proto(&[0u8; 2]),
            Err(ParseError::UnknownProto)
        ));
    }

    #[test]
    fn lorawan_is_leaf() {
        assert!(matches!(
            LorawanOps.next_proto(&[0u8; 1]),
            Err(ParseError::UnknownProto)
        ));
    }

    #[test]
    fn ieee802154_is_leaf() {
        assert!(matches!(
            Ieee802154Ops.next_proto(&[0u8; 3]),
            Err(ParseError::UnknownProto)
        ));
    }

    #[test]
    fn ptp_v1_is_leaf() {
        assert!(matches!(
            PtpV1Ops.next_proto(&[0u8; 40]),
            Err(ParseError::UnknownProto)
        ));
    }

    #[test]
    fn gptp_is_leaf() {
        assert!(matches!(
            GptpOps.next_proto(&[0u8; 34]),
            Err(ParseError::UnknownProto)
        ));
    }

    #[test]
    fn ecpri_is_leaf() {
        assert!(matches!(
            EcpriOps.next_proto(&[0u8; 4]),
            Err(ParseError::UnknownProto)
        ));
    }

    #[test]
    fn wpa_eapol_key_is_leaf() {
        assert!(matches!(
            WpaEapolKeyOps.next_proto(&[0u8; 95]),
            Err(ParseError::UnknownProto)
        ));
    }
}
