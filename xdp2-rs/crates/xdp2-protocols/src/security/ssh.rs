//! SSH (Secure Shell) protocol definition.
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `SshHeader` | `proto_ssh.h:38-41` | `struct ssh_hdr` |
//! | `SshOps` | `proto_ssh.h:48-53` | `xdp2_parse_ssh` |
//!
//! ## Behavioral Differences
//! - None. Leaf node — byte-for-byte compatible with C implementation.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// SSH packet header (5 bytes).
///
/// Reimplements: `struct ssh_hdr` in `proto_ssh.h:38-41`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct SshHeader {
    pub packet_length: [u8; 4],
    pub padding_length: u8,
}

impl SshHeader {
    pub fn packet_length(&self) -> u32 {
        u32::from_be_bytes(self.packet_length)
    }
}

/// SSH protocol operations (leaf).
///
/// Reimplements: `xdp2_parse_ssh` in `proto_ssh.h:48-53`
pub struct SshOps;

impl ProtocolOps for SshOps {
    const MIN_LEN: usize = 5;
    const NAME: &'static str = "SSH";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_is_leaf() {
        let ops = SshOps;
        assert!(matches!(
            ops.next_proto(&[0u8; 5]),
            Err(ParseError::UnknownProto)
        ));
    }

    #[test]
    fn ssh_header_fields() {
        let mut hdr = [0u8; 5];
        hdr[0..4].copy_from_slice(&100u32.to_be_bytes());
        hdr[4] = 8;
        let ssh = SshHeader::ref_from_prefix(&hdr).unwrap().0;
        assert_eq!(ssh.packet_length(), 100);
        assert_eq!(ssh.padding_length, 8);
    }
}
