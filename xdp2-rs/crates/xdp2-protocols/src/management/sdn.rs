//! SDN / OpenFlow protocol definitions.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// OpenFlow header (8 bytes). Reimplements: `struct openflow_hdr` in `proto_openflow.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct OpenflowHeader {
    pub version: u8,
    pub msg_type: u8,
    pub length: [u8; 2],
    pub xid: [u8; 4],
}
pub struct OpenflowOps;
impl ProtocolOps for OpenflowOps {
    const MIN_LEN: usize = 8;
    const NAME: &'static str = "OpenFlow";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// HomePlug AV header (1 byte). Reimplements: `struct homeplug_av_hdr` in `proto_homeplug_av.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct HomePlugAvHeader {
    pub version: u8,
}
pub struct HomePlugAvOps;
impl ProtocolOps for HomePlugAvOps {
    const MIN_LEN: usize = 1;
    const NAME: &'static str = "HomePlug AV";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn openflow_is_leaf() {
        assert!(matches!(
            OpenflowOps.next_proto(&[0u8; 8]),
            Err(ParseError::UnknownProto)
        ));
    }
}
