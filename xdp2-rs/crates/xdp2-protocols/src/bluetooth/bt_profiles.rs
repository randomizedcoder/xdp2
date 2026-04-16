//! Bluetooth profile protocol definitions (leaf nodes).
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `BtRfcommHeader` | `proto_defs/bluetooth/proto_bt_rfcomm.h` | `struct bt_rfcomm_hdr` |
//! | `BtSdpHeader` | `proto_defs/bluetooth/proto_bt_sdp.h` | `struct bt_sdp_hdr` |
//! | `BtAttHeader` | `proto_defs/bluetooth/proto_bt_att.h` | `struct bt_att_hdr` |
//! | `BtSmpHeader` | `proto_defs/bluetooth/proto_bt_smp.h` | `struct bt_smp_hdr` |
//! | `BtAvdtpHeader` | `proto_defs/bluetooth/proto_bt_avdtp.h` | `struct bt_avdtp_hdr` |
//!
//! ## Behavioral Differences
//! - None. All are leaf nodes.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

// ---------------------------------------------------------------------------
// BT RFCOMM
// ---------------------------------------------------------------------------

/// BT RFCOMM header (2 bytes).
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct BtRfcommHeader {
    pub addr: u8,
    pub control: u8,
}

pub struct BtRfcommOps;

impl ProtocolOps for BtRfcommOps {
    const MIN_LEN: usize = 2;
    const NAME: &'static str = "BT RFCOMM";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

// ---------------------------------------------------------------------------
// BT SDP
// ---------------------------------------------------------------------------

/// BT SDP header (5 bytes).
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct BtSdpHeader {
    pub pdu_id: u8,
    pub tid: [u8; 2],
    pub plen: [u8; 2],
}

pub struct BtSdpOps;

impl ProtocolOps for BtSdpOps {
    const MIN_LEN: usize = 5;
    const NAME: &'static str = "BT SDP";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

// ---------------------------------------------------------------------------
// BT ATT (Attribute Protocol)
// ---------------------------------------------------------------------------

/// BT ATT header (1 byte).
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct BtAttHeader {
    pub opcode: u8,
}

pub struct BtAttOps;

impl ProtocolOps for BtAttOps {
    const MIN_LEN: usize = 1;
    const NAME: &'static str = "BT ATT";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

// ---------------------------------------------------------------------------
// BT SMP (Security Manager Protocol)
// ---------------------------------------------------------------------------

/// BT SMP header (1 byte).
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct BtSmpHeader {
    pub code: u8,
}

pub struct BtSmpOps;

impl ProtocolOps for BtSmpOps {
    const MIN_LEN: usize = 1;
    const NAME: &'static str = "BT SMP";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

// ---------------------------------------------------------------------------
// BT AVDTP (Audio/Video Distribution Transport Protocol)
// ---------------------------------------------------------------------------

/// BT AVDTP header (2 bytes).
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct BtAvdtpHeader {
    pub msg_type_pkt_type: u8,
    pub signal_id: u8,
}

pub struct BtAvdtpOps;

impl ProtocolOps for BtAvdtpOps {
    const MIN_LEN: usize = 2;
    const NAME: &'static str = "BT AVDTP";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bt_rfcomm_is_leaf() {
        assert!(matches!(BtRfcommOps.next_proto(&[0u8; 2]), Err(ParseError::UnknownProto)));
    }

    #[test]
    fn bt_sdp_is_leaf() {
        assert!(matches!(BtSdpOps.next_proto(&[0u8; 5]), Err(ParseError::UnknownProto)));
    }

    #[test]
    fn bt_att_is_leaf() {
        assert!(matches!(BtAttOps.next_proto(&[0u8; 1]), Err(ParseError::UnknownProto)));
    }

    #[test]
    fn bt_smp_is_leaf() {
        assert!(matches!(BtSmpOps.next_proto(&[0u8; 1]), Err(ParseError::UnknownProto)));
    }

    #[test]
    fn bt_avdtp_is_leaf() {
        assert!(matches!(BtAvdtpOps.next_proto(&[0u8; 2]), Err(ParseError::UnknownProto)));
    }
}
