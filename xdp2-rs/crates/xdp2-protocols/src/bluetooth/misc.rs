//! Bluetooth sub-protocol definitions (leaf nodes).
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `HciCommandHeader` | `proto_defs/bluetooth/proto_hci_cmd.h` | `struct hci_command_hdr` |
//! | `HciEventHeader` | `proto_defs/bluetooth/proto_hci_event.h` | `struct hci_event_hdr` |
//! | `HciAclHeader` | `proto_defs/bluetooth/proto_hci_acl.h` | `struct hci_acl_hdr` |
//! | `HciScoHeader` | `proto_defs/bluetooth/proto_hci_sco.h` | `struct hci_sco_hdr` |
//! | `HciIsoHeader` | `proto_defs/bluetooth/proto_hci_iso.h` | `struct hci_iso_hdr` |
//! | `L2capHeader` | `proto_defs/bluetooth/proto_l2cap.h` | `struct l2cap_hdr` |
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
// HCI Command
// ---------------------------------------------------------------------------

/// HCI command header (3 bytes).
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct HciCommandHeader {
    pub opcode: [u8; 2],
    pub plen: u8,
}

pub struct HciCommandOps;

impl ProtocolOps for HciCommandOps {
    const MIN_LEN: usize = 3;
    const NAME: &'static str = "HCI Command";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

// ---------------------------------------------------------------------------
// HCI Event
// ---------------------------------------------------------------------------

/// HCI event header (2 bytes).
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct HciEventHeader {
    pub evt: u8,
    pub plen: u8,
}

pub struct HciEventOps;

impl ProtocolOps for HciEventOps {
    const MIN_LEN: usize = 2;
    const NAME: &'static str = "HCI Event";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

// ---------------------------------------------------------------------------
// HCI ACL
// ---------------------------------------------------------------------------

/// HCI ACL data header (4 bytes).
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct HciAclHeader {
    pub handle_flags: [u8; 2],
    pub dlen: [u8; 2],
}

pub struct HciAclOps;

impl ProtocolOps for HciAclOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "HCI ACL";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

// ---------------------------------------------------------------------------
// HCI SCO
// ---------------------------------------------------------------------------

/// HCI SCO data header (3 bytes).
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct HciScoHeader {
    pub handle: [u8; 2],
    pub dlen: u8,
}

pub struct HciScoOps;

impl ProtocolOps for HciScoOps {
    const MIN_LEN: usize = 3;
    const NAME: &'static str = "HCI SCO";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

// ---------------------------------------------------------------------------
// HCI ISO
// ---------------------------------------------------------------------------

/// HCI ISO data header (4 bytes).
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct HciIsoHeader {
    pub handle_flags: [u8; 2],
    pub dlen: [u8; 2],
}

pub struct HciIsoOps;

impl ProtocolOps for HciIsoOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "HCI ISO";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

// ---------------------------------------------------------------------------
// L2CAP
// ---------------------------------------------------------------------------

/// L2CAP header (4 bytes).
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct L2capHeader {
    pub len: [u8; 2],
    pub cid: [u8; 2],
}

impl L2capHeader {
    pub fn len(&self) -> u16 {
        u16::from_le_bytes(self.len)
    }
    pub fn cid(&self) -> u16 {
        u16::from_le_bytes(self.cid)
    }
}

pub struct L2capOps;

impl ProtocolOps for L2capOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "L2CAP";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

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
    fn hci_cmd_is_leaf() {
        assert!(matches!(HciCommandOps.next_proto(&[0u8; 3]), Err(ParseError::UnknownProto)));
    }

    #[test]
    fn hci_event_is_leaf() {
        assert!(matches!(HciEventOps.next_proto(&[0u8; 2]), Err(ParseError::UnknownProto)));
    }

    #[test]
    fn hci_acl_is_leaf() {
        assert!(matches!(HciAclOps.next_proto(&[0u8; 4]), Err(ParseError::UnknownProto)));
    }

    #[test]
    fn hci_sco_is_leaf() {
        assert!(matches!(HciScoOps.next_proto(&[0u8; 3]), Err(ParseError::UnknownProto)));
    }

    #[test]
    fn hci_iso_is_leaf() {
        assert!(matches!(HciIsoOps.next_proto(&[0u8; 4]), Err(ParseError::UnknownProto)));
    }

    #[test]
    fn l2cap_is_leaf() {
        assert!(matches!(L2capOps.next_proto(&[0u8; 4]), Err(ParseError::UnknownProto)));
    }

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
