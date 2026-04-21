//! Connectivity Fault Management (CFM) protocol definitions.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// CFM header (4 bytes). Reimplements: `struct cfm_hdr` in `proto_cfm.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct CfmHeader {
    pub md_level_version: u8,
    pub opcode: u8,
    pub flags: u8,
    pub first_tlv_offset: u8,
}
pub struct CfmOps;
impl ProtocolOps for CfmOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "CFM";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cfm_is_leaf() {
        assert!(matches!(
            CfmOps.next_proto(&[0u8; 4]),
            Err(ParseError::UnknownProto)
        ));
    }
}
