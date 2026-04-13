//! InfiniBand Reliable Datagram Extended Transport Header (RDETH).
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `IbRdethHeader` | `proto_defs/infiniband/proto_ib_rdeth.h` | `struct ib_rdeth` |
//! | `IbRdethOps` | `proto_ib_rdeth.h:59-63` | `xdp2_parse_ib_rdeth` |
//! | `IbRdethOps::next_proto` | `proto_ib_rdeth.h:43-49` | `ib_rdeth_proto()` |
//!
//! ## Behavioral Differences
//! - None. Byte-for-byte compatible with C implementation.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// IB RDETH header (4 bytes).
///
/// Reimplements: `struct ib_rdeth` in `proto_ib_rdeth.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct IbRdethHeader {
    pub ee_context: [u8; 4],
}

impl IbRdethHeader {
    /// EE Context (lower 24 bits).
    pub fn ee_context(&self) -> u32 {
        u32::from_be_bytes(self.ee_context) & 0x00FFFFFF
    }
}

/// IB RDETH protocol operations.
///
/// Reimplements: `xdp2_parse_ib_rdeth` in `proto_ib_rdeth.h:59-63`
///
/// Always chains to DETH (returns constant 1).
pub struct IbRdethOps;

impl ProtocolOps for IbRdethOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "IB RDETH";

    /// Return constant 1 (always chains to DETH).
    ///
    /// Reimplements: `ib_rdeth_proto()` in `proto_ib_rdeth.h:43-49`
    #[inline]
    fn next_proto(&self, hdr: &[u8]) -> Result<i32, ParseError> {
        if hdr.len() < 4 {
            return Err(ParseError::Length);
        }
        Ok(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ib_rdeth_always_deth() {
        assert_eq!(IbRdethOps.next_proto(&[0u8; 4]).unwrap(), 1);
    }

    #[test]
    fn ib_rdeth_short() {
        assert!(IbRdethOps.next_proto(&[0u8; 2]).is_err());
    }
}
