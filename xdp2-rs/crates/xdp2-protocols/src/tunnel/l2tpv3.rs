//! L2TPv3 protocol definition.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// L2TPv3 header (12 bytes). Reimplements: `struct l2tpv3_hdr` in `proto_l2tpv3.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct L2tpv3Header {
    pub session_id: [u8; 4],
    pub cookie: [u8; 8],
}
pub struct L2tpv3Ops;
impl ProtocolOps for L2tpv3Ops {
    const MIN_LEN: usize = 12;
    const NAME: &'static str = "L2TPv3";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}
