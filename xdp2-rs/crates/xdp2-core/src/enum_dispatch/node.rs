//! The `NodeOps` trait — static-dispatch counterpart to `ParseNodeDyn`.
//!
//! Implementations are not object-safe (they reference `Self` in edges),
//! which is precisely the point: callers parameterize the engine over a
//! concrete `N: NodeOps<M>` so the compiler can monomorphize every match
//! arm and inline trivial accessors.

use crate::enum_dispatch::table::ProtoTableEnum;
use crate::types::{CtrlData, NodeType, ParseError};

/// Static-dispatch parse node interface.
///
/// Mirrors [`crate::parse_node::ParseNodeDyn`] but with `Self`-typed edges
/// so the engine can be fully monomorphized. Implemented by the user's
/// node enum.
pub trait NodeOps<M: 'static>: Sized + 'static {
    fn min_len(&self) -> usize;
    fn name(&self) -> &'static str;
    fn node_type(&self) -> NodeType;
    fn is_encap(&self) -> bool;
    fn is_overlay(&self) -> bool;

    fn header_len(&self, hdr: &[u8], maxlen: usize) -> Result<usize, ParseError>;
    fn next_proto(&self, hdr: &[u8]) -> Result<i32, ParseError>;

    fn extract_metadata(&self, hdr: &[u8], hdr_len: usize, metadata: &mut M, ctrl: &CtrlData);
    fn handler(
        &self,
        hdr: &[u8],
        hdr_len: usize,
        metadata: &mut M,
        ctrl: &CtrlData,
    ) -> Result<(), ParseError>;
    fn post_handler(
        &self,
        hdr: &[u8],
        hdr_len: usize,
        metadata: &mut M,
        ctrl: &CtrlData,
    ) -> Result<(), ParseError>;

    /// Sub-structure parsing (TLVs, flag-fields, arrays).
    ///
    /// Default is a no-op — variants that need sub-parsing override this.
    #[inline]
    fn sub_parse(
        &self,
        _hdr: &[u8],
        _hdr_len: usize,
        _metadata: &mut M,
        _ctrl: &CtrlData,
    ) -> Result<(), ParseError> {
        Ok(())
    }

    /// Protocol table for next-node lookup (`None` = leaf).
    fn proto_table(&self) -> Option<&'static ProtoTableEnum<M, Self>>;

    /// Wildcard node used when a proto number isn't in the table.
    fn wildcard_node(&self) -> Option<&'static Self>;

    /// Error code to return when the next proto isn't found and there is no wildcard.
    fn unknown_ret(&self) -> ParseError;
}
