//! X.25 protocol leaf definition (Silver tier).

use xdp2_core::{ParseError, ProtocolOps};

pub struct X25Ops;
impl ProtocolOps for X25Ops {
    const MIN_LEN: usize = 3;
    const NAME: &'static str = "X25";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}
