//! GRE6 protocol definition.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// GRE6 header (4 bytes). Reimplements: `struct gre6_hdr` in `proto_gre6.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct Gre6Header {
    pub flags: [u8; 2],
    pub protocol: [u8; 2],
}
pub struct Gre6Ops;
impl ProtocolOps for Gre6Ops {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "GRE6";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}
