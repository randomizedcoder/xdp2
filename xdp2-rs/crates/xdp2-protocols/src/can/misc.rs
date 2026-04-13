//! CAN and CAN FD frame definitions (leaf nodes).
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `CanFrame` | `proto_defs/can/proto_can.h` | `struct can_frame` |
//! | `CanOps` | `proto_can.h` | `xdp2_parse_can` |
//! | `CanFdFrame` | `proto_defs/can/proto_canfd.h` | `struct canfd_frame` |
//! | `CanFdOps` | `proto_canfd.h` | `xdp2_parse_canfd` |
//!
//! ## Behavioral Differences
//! - None. Both are leaf nodes.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

// ---------------------------------------------------------------------------
// CAN (Classical)
// ---------------------------------------------------------------------------

/// CAN frame (16 bytes).
///
/// Reimplements: `struct can_frame` in `proto_can.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct CanFrame {
    pub can_id: [u8; 4],
    pub can_dlc: u8,
    pub __pad: u8,
    pub __res0: u8,
    pub len8_dlc: u8,
    pub data: [u8; 8],
}

impl CanFrame {
    pub fn can_id(&self) -> u32 {
        u32::from_le_bytes(self.can_id)
    }
}

/// CAN protocol operations (leaf).
pub struct CanOps;

impl ProtocolOps for CanOps {
    const MIN_LEN: usize = 16;
    const NAME: &'static str = "CAN";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

// ---------------------------------------------------------------------------
// CAN FD (Flexible Data-rate)
// ---------------------------------------------------------------------------

/// CAN FD frame (72 bytes).
///
/// Reimplements: `struct canfd_frame` in `proto_canfd.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct CanFdFrame {
    pub can_id: [u8; 4],
    pub len: u8,
    pub flags: u8,
    pub __res0: u8,
    pub __res1: u8,
    pub data: [u8; 64],
}

impl CanFdFrame {
    pub fn can_id(&self) -> u32 {
        u32::from_le_bytes(self.can_id)
    }
}

/// CAN FD protocol operations (leaf).
pub struct CanFdOps;

impl ProtocolOps for CanFdOps {
    const MIN_LEN: usize = 72;
    const NAME: &'static str = "CAN FD";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_is_leaf() {
        assert!(matches!(CanOps.next_proto(&[0u8; 16]), Err(ParseError::UnknownProto)));
    }

    #[test]
    fn canfd_is_leaf() {
        assert!(matches!(CanFdOps.next_proto(&[0u8; 72]), Err(ParseError::UnknownProto)));
    }
}
