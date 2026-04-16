//! LISP (Locator/ID Separation Protocol) protocol definition.
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `LispHeader` | `proto_lisp.h:38-41` | `struct lisphdr` |
//! | `LispOps` | `proto_lisp.h:68-73` | `xdp2_parse_lisp` |
//!
//! ## Behavioral Differences
//! - None. Byte-for-byte compatible with C implementation.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

const ETH_P_IP: i32 = 0x0800;
const ETH_P_IPV6: i32 = 0x86DD;

/// LISP header (8 bytes).
///
/// Reimplements: `struct lisphdr` in `proto_lisp.h:38-41`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct LispHeader {
    pub flags_nonce: [u8; 4],
    pub lsb: [u8; 4],
}

/// LISP protocol operations (encap).
///
/// Reimplements: `xdp2_parse_lisp` in `proto_lisp.h:68-73`
pub struct LispOps;

impl ProtocolOps for LispOps {
    const MIN_LEN: usize = 8;
    const NAME: &'static str = "LISP";
    const ENCAP: bool = true;

    /// Determine inner protocol from first nibble of payload.
    ///
    /// Reimplements: `lisp_proto()` in `proto_lisp.h:44-57`
    #[inline]
    fn next_proto(&self, hdr: &[u8]) -> Result<i32, ParseError> {
        if hdr.len() < 9 {
            return Err(ParseError::Length);
        }
        let version = hdr[8] >> 4;
        Ok(match version {
            4 => ETH_P_IP,
            6 => ETH_P_IPV6,
            _ => 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lisp_inner_ipv4() {
        let mut hdr = [0u8; 9];
        hdr[8] = 0x45;
        assert_eq!(LispOps.next_proto(&hdr).unwrap(), ETH_P_IP);
    }

    #[test]
    fn lisp_inner_ipv6() {
        let mut hdr = [0u8; 9];
        hdr[8] = 0x60;
        assert_eq!(LispOps.next_proto(&hdr).unwrap(), ETH_P_IPV6);
    }

    #[test]
    fn lisp_is_encap() {
        assert!(LispOps::ENCAP);
    }
}
