//! HCI sub-header protocol definitions (leaf nodes).
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hci_cmd_is_leaf() {
        assert!(matches!(
            HciCommandOps.next_proto(&[0u8; 3]),
            Err(ParseError::UnknownProto)
        ));
    }

    #[test]
    fn hci_event_is_leaf() {
        assert!(matches!(
            HciEventOps.next_proto(&[0u8; 2]),
            Err(ParseError::UnknownProto)
        ));
    }

    #[test]
    fn hci_acl_is_leaf() {
        assert!(matches!(
            HciAclOps.next_proto(&[0u8; 4]),
            Err(ParseError::UnknownProto)
        ));
    }

    #[test]
    fn hci_sco_is_leaf() {
        assert!(matches!(
            HciScoOps.next_proto(&[0u8; 3]),
            Err(ParseError::UnknownProto)
        ));
    }

    #[test]
    fn hci_iso_is_leaf() {
        assert!(matches!(
            HciIsoOps.next_proto(&[0u8; 4]),
            Err(ParseError::UnknownProto)
        ));
    }
}
