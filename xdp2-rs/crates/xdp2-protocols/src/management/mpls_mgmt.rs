//! MPLS Management protocol definitions.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// LDP header (10 bytes). Reimplements: `struct ldp_hdr` in `proto_ldp.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct LdpHeader {
    pub version: [u8; 2],
    pub pdu_len: [u8; 2],
    pub lsr_id: [u8; 4],
    pub label_space: [u8; 2],
}
pub struct LdpOps;
impl ProtocolOps for LdpOps {
    const MIN_LEN: usize = 10;
    const NAME: &'static str = "LDP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
}

/// MPLS OAM header (4 bytes). Reimplements: `struct mpls_oam_hdr` in `proto_mpls_oam.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct MplsOamHeader {
    pub ver_flags: u8,
    pub msg_type: u8,
    pub reply_mode: u8,
    pub return_code: u8,
}
pub struct MplsOamOps;
impl ProtocolOps for MplsOamOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "MPLS OAM";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ldp_is_leaf() {
        assert!(matches!(LdpOps.next_proto(&[0u8; 10]), Err(ParseError::UnknownProto)));
    }
}
