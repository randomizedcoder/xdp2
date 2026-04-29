//! IPComp protocol definition.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// IPComp header (4 bytes). Reimplements: `struct ipcomp_hdr` in `proto_ipcomp.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct IpCompHeader {
    pub next_header: u8,
    pub flags: u8,
    pub cpi: [u8; 2],
}
pub struct IpCompOps;
impl ProtocolOps for IpCompOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "IPComp";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}
