//! EtherIP protocol definition.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// EtherIP header (2 bytes). Reimplements: `struct etherip_hdr` in `proto_etherip.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct EtherIpHeader {
    pub ver_reserved: [u8; 2],
}
pub struct EtherIpOps;
impl ProtocolOps for EtherIpOps {
    const MIN_LEN: usize = 2;
    const NAME: &'static str = "EtherIP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}
