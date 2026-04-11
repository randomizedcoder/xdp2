//! HCI (Host Controller Interface) packet indicator protocol definition.
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `HciHeader` | `proto_defs/bluetooth/proto_hci.h` | `struct hci_pkt_indicator` |
//! | `HciOps` | `proto_hci.h:65-69` | `xdp2_parse_hci` |
//! | `HciOps::next_proto` | `proto_hci.h:51-54` | `hci_proto()` |
//!
//! ## Behavioral Differences
//! - None. Byte-for-byte compatible with C implementation.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// HCI packet type constants.
pub const HCI_COMMAND_PKT: u8 = 0x01;
pub const HCI_ACLDATA_PKT: u8 = 0x02;
pub const HCI_SCODATA_PKT: u8 = 0x03;
pub const HCI_EVENT_PKT: u8 = 0x04;
pub const HCI_ISODATA_PKT: u8 = 0x05;

/// HCI packet indicator (1 byte).
///
/// Reimplements: `struct hci_pkt_indicator` in `proto_hci.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct HciHeader {
    pub pkt_type: u8,
}

/// HCI protocol operations.
///
/// Reimplements: `xdp2_parse_hci` in `proto_hci.h:65-69`
///
/// Dispatches on packet type byte.
pub struct HciOps;

impl ProtocolOps for HciOps {
    const MIN_LEN: usize = 1;
    const NAME: &'static str = "HCI";

    /// Return HCI packet type for dispatch.
    ///
    /// Reimplements: `hci_proto()` in `proto_hci.h:51-54`
    fn next_proto(&self, hdr: &[u8]) -> Result<i32, ParseError> {
        if hdr.is_empty() {
            return Err(ParseError::Length);
        }
        Ok(hdr[0] as i32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hci_dispatch_command() {
        assert_eq!(HciOps.next_proto(&[HCI_COMMAND_PKT]).unwrap(), 1);
    }

    #[test]
    fn hci_dispatch_acl() {
        assert_eq!(HciOps.next_proto(&[HCI_ACLDATA_PKT]).unwrap(), 2);
    }

    #[test]
    fn hci_dispatch_event() {
        assert_eq!(HciOps.next_proto(&[HCI_EVENT_PKT]).unwrap(), 4);
    }

    #[test]
    fn hci_dispatch_iso() {
        assert_eq!(HciOps.next_proto(&[HCI_ISODATA_PKT]).unwrap(), 5);
    }

    #[test]
    fn hci_short() {
        assert!(HciOps.next_proto(&[]).is_err());
    }
}
