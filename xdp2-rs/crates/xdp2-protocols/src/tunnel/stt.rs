//! STT (Stateless Transport Tunneling) protocol definition.
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `SttHeader` | `proto_stt.h:37-45` | `struct stthdr` |
//! | `SttOps` | `proto_stt.h:61-66` | `xdp2_parse_stt` |
//!
//! ## Behavioral Differences
//! - None. Byte-for-byte compatible with C implementation.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

const ETH_P_TEB: i32 = 0x6558;

/// STT header (18 bytes).
///
/// Reimplements: `struct stthdr` in `proto_stt.h:37-45`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct SttHeader {
    pub version: u8,
    pub flags: u8,
    pub l4_offset: u8,
    pub reserved: u8,
    pub max_seg_size: [u8; 2],
    pub pv: [u8; 2],
    pub context_id: [u8; 8],
}

/// STT protocol operations (encap — always Ethernet).
///
/// Reimplements: `xdp2_parse_stt` in `proto_stt.h:61-66`
pub struct SttOps;

impl ProtocolOps for SttOps {
    const MIN_LEN: usize = 18;
    const NAME: &'static str = "STT";
    const ENCAP: bool = true;

    /// Always returns ETH_P_TEB (inner is Ethernet).
    ///
    /// Reimplements: `stt_proto()` in `proto_stt.h:47-50`
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Ok(ETH_P_TEB)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stt_always_teb() {
        assert_eq!(SttOps.next_proto(&[0u8; 18]).unwrap(), ETH_P_TEB);
    }

    #[test]
    fn stt_is_encap() {
        assert!(SttOps::ENCAP);
    }
}
