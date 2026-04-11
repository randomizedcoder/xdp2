//! TIPC (Transparent Inter-Process Communication) protocol definition.
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `TipcHeader` | `proto_defs/transport/proto_tipc.h:39-41` | `struct tipc_basic_hdr` |
//! | `TipcOps` | `proto_tipc.h:51-54` | `xdp2_parse_tipc` |
//!
//! ## Behavioral Differences
//! - None. Byte-for-byte compatible with C implementation.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// TIPC keepalive message mask.
pub const TIPC_KEEPALIVE_MSG_MASK: u32 = 0x0e08_0000;

/// TIPC basic header (16 bytes).
///
/// Reimplements: `struct tipc_basic_hdr` in `proto_tipc.h:39-41`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct TipcHeader {
    /// 4 words of header data
    pub w: [u8; 16],
}

/// TIPC protocol operations (leaf node).
///
/// Reimplements: `xdp2_parse_tipc` in `proto_tipc.h:51-54`
pub struct TipcOps;

impl ProtocolOps for TipcOps {
    const MIN_LEN: usize = 16; // sizeof(struct tipc_basic_hdr) = 4 * 4
    const NAME: &'static str = "TIPC";

    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto) // Leaf node
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tipc_is_leaf() {
        let ops = TipcOps;
        assert!(ops.next_proto(&[0u8; 16]).is_err());
    }

    #[test]
    fn tipc_fixed_length() {
        let ops = TipcOps;
        assert_eq!(ops.header_len(&[0u8; 16], 100).unwrap(), 16);
    }
}
