//! PGM protocol definition.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// PGM header (16 bytes). Reimplements: `struct pgm_hdr` in `proto_pgm.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct PgmHeader {
    pub sport: [u8; 2],
    pub dport: [u8; 2],
    pub type_: u8,
    pub options: u8,
    pub checksum: [u8; 2],
    pub gsi: [u8; 6],
    pub tsdu_len: [u8; 2],
}
pub struct PgmOps;
impl ProtocolOps for PgmOps {
    const MIN_LEN: usize = 16;
    const NAME: &'static str = "PGM";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}
