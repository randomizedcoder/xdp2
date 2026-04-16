//! Kerberos (RFC 4120) protocol definition.
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `KerberosHeader` | `proto_kerberos.h:38-39` | `struct kerberos_hdr` |
//! | `KerberosOps` | `proto_kerberos.h:46-51` | `xdp2_parse_kerberos` |
//!
//! ## Behavioral Differences
//! - None. Leaf node — byte-for-byte compatible with C implementation.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// Kerberos header (1 byte marker).
///
/// Reimplements: `struct kerberos_hdr` in `proto_kerberos.h:38-39`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct KerberosHeader {
    pub marker: u8,
}

/// Kerberos protocol operations (leaf).
///
/// Reimplements: `xdp2_parse_kerberos` in `proto_kerberos.h:46-51`
pub struct KerberosOps;

impl ProtocolOps for KerberosOps {
    const MIN_LEN: usize = 1;
    const NAME: &'static str = "Kerberos";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kerberos_is_leaf() {
        let ops = KerberosOps;
        assert!(matches!(ops.next_proto(&[0u8; 1]), Err(ParseError::UnknownProto)));
    }
}
