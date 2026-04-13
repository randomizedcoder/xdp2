//! Parse node definitions — graph nodes in the parse graph.
//!
//! A `ParseNode` binds a protocol definition (`ProtocolOps`) to parse-time
//! callbacks (extract_metadata, handler, post_handler) and graph edges
//! (proto_table, wildcard_node).
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `ExtractMetadataFn` | `parser_types.h:222-224` | `extract_metadata` fn ptr |
//! | `HandlerFn` | `parser_types.h:225-226` | `handler` fn ptr |
//! | `PostHandlerFn` | `parser_types.h:227-228` | `post_handler` fn ptr |
//! | `ParseNodeOps` | `parser_types.h:221-229` | `struct xdp2_parse_node_ops` |
//! | `ParseNode` | `parser_types.h:270-281` | `struct xdp2_parse_node` |

use crate::proto_def::ProtocolOps;
use crate::proto_table::ProtoTable;
use crate::types::{CtrlData, NodeType, ParseError};

/// Callback for extracting metadata from a protocol header.
///
/// Reimplements: `xdp2_parse_node_ops.extract_metadata` in `parser_types.h:222-224`
///
/// # Arguments
/// - `hdr`: Protocol header bytes
/// - `hdr_len`: Actual header length (from `ProtocolOps::header_len`)
/// - `metadata`: User-defined metadata structure
/// - `ctrl`: Control data for the parse operation
pub type ExtractMetadataFn<M> =
    fn(hdr: &[u8], hdr_len: usize, metadata: &mut M, ctrl: &CtrlData);

/// Callback for per-protocol handling (arbitrary processing).
///
/// Reimplements: `xdp2_parse_node_ops.handler` in `parser_types.h:225-226`
///
/// Returns `Ok(())` to continue, or `Err(ParseError)` to stop parsing.
pub type HandlerFn<M> =
    fn(hdr: &[u8], hdr_len: usize, metadata: &mut M, ctrl: &CtrlData) -> Result<(), ParseError>;

/// Callback for post-processing after sub-structure parsing (TLVs, etc.).
///
/// Reimplements: `xdp2_parse_node_ops.post_handler` in `parser_types.h:227-228`
pub type PostHandlerFn<M> =
    fn(hdr: &[u8], hdr_len: usize, metadata: &mut M, ctrl: &CtrlData) -> Result<(), ParseError>;

/// Parse node operations — optional callbacks for metadata extraction and handling.
///
/// Reimplements: `struct xdp2_parse_node_ops` in `parser_types.h:221-229`
///
/// In C, NULL function pointers mean "skip this callback". In Rust, `Option<fn>`
/// provides the same semantics.
#[derive(Clone)]
pub struct ParseNodeOps<M: 'static> {
    pub extract_metadata: Option<ExtractMetadataFn<M>>,
    pub handler: Option<HandlerFn<M>>,
    pub post_handler: Option<PostHandlerFn<M>>,
}

impl<M: 'static> Default for ParseNodeOps<M> {
    fn default() -> Self {
        Self {
            extract_metadata: None,
            handler: None,
            post_handler: None,
        }
    }
}

/// A node in the parse graph.
///
/// Reimplements: `struct xdp2_parse_node` in `parser_types.h:270-281`
///
/// Binds a protocol definition to callbacks and graph edges. The `proto_table`
/// maps next-protocol numbers to child nodes; `wildcard_node` is used when
/// the protocol number isn't found in the table.
///
/// ## Differences from C
///
/// - `node_type` is derived from `P::NODE_TYPE` instead of being a separate field
/// - `proto_def` is a generic type parameter `P` instead of a pointer
/// - `unknown_ret` defaults to `ParseError::UnknownProto` instead of being configurable
///   per-node (can be overridden in future if needed)
pub struct ParseNode<M: 'static, P: ProtocolOps = DynProtocol> {
    /// Protocol definition (operations + metadata)
    pub proto: P,
    /// Parse node operations (callbacks)
    pub ops: ParseNodeOps<M>,
    /// Protocol table for next-protocol lookup (None = leaf node)
    pub proto_table: Option<&'static ProtoTable<M>>,
    /// Wildcard node used when protocol number not found in table
    pub wildcard_node: Option<&'static dyn ParseNodeDyn<M>>,
    /// Return code for unknown protocol (default: UnknownProto)
    pub unknown_ret: ParseError,
    /// Human-readable name for debugging
    pub name: &'static str,
}

/// Type-erased parse node interface for use in protocol tables.
///
/// Since `ParseNode` is generic over `P: ProtocolOps`, protocol tables
/// need a common trait object type. This trait provides the dynamic dispatch
/// interface used by the parse engine.
pub trait ParseNodeDyn<M: 'static>: Send + Sync {
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
    /// Dispatch sub-structure parsing (TLVs, flag-fields, arrays).
    ///
    /// Reimplements: `switch (parse_node->node_type)` in `parser.c:528-575`
    ///
    /// Plain nodes return Ok(()) immediately. Wrapper node types
    /// (ParseTlvsNode, ParseFlagFieldsNode, ParseArrayNode) override this
    /// to call their respective sub-parsing functions.
    fn sub_parse(
        &self,
        _hdr: &[u8],
        _hdr_len: usize,
        _metadata: &mut M,
        _ctrl: &CtrlData,
    ) -> Result<(), ParseError> {
        Ok(())
    }
    fn proto_table(&self) -> Option<&'static ProtoTable<M>>;
    fn wildcard_node(&self) -> Option<&'static dyn ParseNodeDyn<M>>;
    fn unknown_ret(&self) -> ParseError;
}

impl<M: 'static, P: ProtocolOps> ParseNodeDyn<M> for ParseNode<M, P> {
    #[inline]
    fn min_len(&self) -> usize {
        P::MIN_LEN
    }

    #[inline]
    fn name(&self) -> &'static str {
        self.name
    }

    #[inline]
    fn node_type(&self) -> NodeType {
        P::NODE_TYPE
    }

    #[inline]
    fn is_encap(&self) -> bool {
        P::ENCAP
    }

    #[inline]
    fn is_overlay(&self) -> bool {
        P::OVERLAY
    }

    #[inline]
    fn header_len(&self, hdr: &[u8], maxlen: usize) -> Result<usize, ParseError> {
        self.proto.header_len(hdr, maxlen)
    }

    #[inline]
    fn next_proto(&self, hdr: &[u8]) -> Result<i32, ParseError> {
        self.proto.next_proto(hdr)
    }

    #[inline]
    fn extract_metadata(&self, hdr: &[u8], hdr_len: usize, metadata: &mut M, ctrl: &CtrlData) {
        if let Some(f) = self.ops.extract_metadata {
            f(hdr, hdr_len, metadata, ctrl);
        }
    }

    #[inline]
    fn handler(
        &self,
        hdr: &[u8],
        hdr_len: usize,
        metadata: &mut M,
        ctrl: &CtrlData,
    ) -> Result<(), ParseError> {
        match self.ops.handler {
            Some(f) => f(hdr, hdr_len, metadata, ctrl),
            None => Ok(()),
        }
    }

    #[inline]
    fn post_handler(
        &self,
        hdr: &[u8],
        hdr_len: usize,
        metadata: &mut M,
        ctrl: &CtrlData,
    ) -> Result<(), ParseError> {
        match self.ops.post_handler {
            Some(f) => f(hdr, hdr_len, metadata, ctrl),
            None => Ok(()),
        }
    }

    #[inline]
    fn proto_table(&self) -> Option<&'static ProtoTable<M>> {
        self.proto_table
    }

    #[inline]
    fn wildcard_node(&self) -> Option<&'static dyn ParseNodeDyn<M>> {
        self.wildcard_node
    }

    #[inline]
    fn unknown_ret(&self) -> ParseError {
        self.unknown_ret
    }
}

/// Placeholder protocol type used when type erasure is needed.
/// Not intended for direct use — prefer concrete protocol types.
pub struct DynProtocol;

impl ProtocolOps for DynProtocol {
    const MIN_LEN: usize = 0;
    const NAME: &'static str = "dynamic";

    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::Fail)
    }
}

impl<M: 'static, P: ProtocolOps> ParseNode<M, P> {
    /// Create a new parse node with a protocol definition.
    pub fn new(name: &'static str, proto: P) -> Self {
        Self {
            proto,
            ops: ParseNodeOps::default(),
            proto_table: None,
            wildcard_node: None,
            unknown_ret: ParseError::UnknownProto,
            name,
        }
    }

    /// Set the extract_metadata callback.
    pub fn with_extract_metadata(mut self, f: ExtractMetadataFn<M>) -> Self {
        self.ops.extract_metadata = Some(f);
        self
    }

    /// Set the handler callback.
    pub fn with_handler(mut self, f: HandlerFn<M>) -> Self {
        self.ops.handler = Some(f);
        self
    }

    /// Set the protocol table for next-protocol lookup.
    pub fn with_proto_table(mut self, table: &'static ProtoTable<M>) -> Self {
        self.proto_table = Some(table);
        self
    }

    /// Set the wildcard node.
    pub fn with_wildcard(mut self, node: &'static dyn ParseNodeDyn<M>) -> Self {
        self.wildcard_node = Some(node);
        self
    }
}
