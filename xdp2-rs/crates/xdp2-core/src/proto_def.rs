//! Protocol definition traits and types.
//!
//! The `ProtocolOps` trait is the central abstraction for protocol definitions,
//! replacing C's `struct xdp2_parse_ops` function pointers and the static fields
//! of `struct xdp2_proto_def`.
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `ProtocolOps` | `parser_types.h:133-137` | `struct xdp2_parse_ops` |
//! | `ProtocolOps` (constants) | `parser_types.h:153-160` | `struct xdp2_proto_def` fields |
//! | `ProtocolOps::header_len` | `parser_types.h:134` | `ops.len` function pointer |
//! | `ProtocolOps::next_proto` | `parser_types.h:135` | `ops.next_proto` function pointer |

use crate::types::{NodeType, ParseError};

/// Protocol parsing operations and metadata.
///
/// Reimplements both `struct xdp2_parse_ops` (function pointers) and the static
/// fields of `struct xdp2_proto_def` (min_len, name, node_type, encap, overlay).
///
/// In C, these are split across two structs because `xdp2_proto_def` contains
/// an embedded `xdp2_parse_ops`. In Rust, traits unify both: associated constants
/// replace the static fields, and trait methods replace the function pointers.
///
/// ## C/C++ Cross-Reference
///
/// | Trait Item | C Field | C Location |
/// |-----------|---------|------------|
/// | `MIN_LEN` | `xdp2_proto_def.min_len` | `parser_types.h:157` |
/// | `NAME` | `xdp2_proto_def.name` | `parser_types.h:158` |
/// | `NODE_TYPE` | `xdp2_proto_def.node_type` | `parser_types.h:154` |
/// | `ENCAP` | `xdp2_proto_def.encap` | `parser_types.h:155` |
/// | `OVERLAY` | `xdp2_proto_def.overlay` | `parser_types.h:156` |
/// | `header_len()` | `xdp2_parse_ops.len` | `parser_types.h:134` |
/// | `next_proto()` | `xdp2_parse_ops.next_proto` | `parser_types.h:135` |
pub trait ProtocolOps: Send + Sync {
    /// Minimum header length in bytes.
    /// If `header_len()` is not overridden, this is used as the fixed header length.
    const MIN_LEN: usize;

    /// Human-readable protocol name (for debugging/logging).
    const NAME: &'static str;

    /// Node type — determines which sub-parsing system is used (TLV, flag-fields, array).
    /// Default: `NodeType::Plain` (no sub-structures).
    const NODE_TYPE: NodeType = NodeType::Plain;

    /// Whether this protocol represents an encapsulation boundary (e.g., IPIP, GRE).
    /// When true, the parser increments the frame pointer for separate metadata.
    const ENCAP: bool = false;

    /// Whether this is an overlay node that doesn't consume bytes.
    /// Used for version-check dispatch (e.g., IP version → IPv4 or IPv6).
    const OVERLAY: bool = false;

    /// Return the actual header length for this packet.
    ///
    /// Reimplements: `xdp2_parse_ops.len` in `parser_types.h:134`
    ///
    /// Default implementation returns `MIN_LEN` (fixed-length protocols).
    /// Variable-length protocols (e.g., IPv4 with IHL, TCP with data offset)
    /// must override this.
    ///
    /// In C, a NULL `ops.len` means "use min_len". Here, the default impl
    /// provides the same behavior.
    ///
    /// # Arguments
    /// - `hdr`: Packet bytes starting at this protocol header (guaranteed >= MIN_LEN)
    /// - `maxlen`: Maximum remaining packet bytes
    fn header_len(&self, _hdr: &[u8], _maxlen: usize) -> Result<usize, ParseError> {
        Ok(Self::MIN_LEN)
    }

    /// Return the next protocol number for table lookup.
    ///
    /// Reimplements: `xdp2_parse_ops.next_proto` in `parser_types.h:135`
    ///
    /// Returns `Ok(proto_number)` for table lookup, or `Err(ParseError)` to stop.
    /// Leaf protocols (no next layer) should return `Err(ParseError::UnknownProto)`
    /// or this method should not be called (leaf nodes have no proto_table).
    ///
    /// In C, a NULL `ops.next_proto` means "this is a leaf". In Rust, leaf nodes
    /// are identified by having `proto_table: None` on the `ParseNode`.
    fn next_proto(&self, hdr: &[u8]) -> Result<i32, ParseError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FixedProto;

    impl ProtocolOps for FixedProto {
        const MIN_LEN: usize = 14;
        const NAME: &'static str = "FixedTest";

        fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
            Ok(0x0800)
        }
    }

    struct OverlayProto;

    impl ProtocolOps for OverlayProto {
        const MIN_LEN: usize = 1;
        const NAME: &'static str = "Overlay";
        const OVERLAY: bool = true;

        fn next_proto(&self, hdr: &[u8]) -> Result<i32, ParseError> {
            Ok(hdr[0] as i32)
        }
    }

    #[test]
    fn fixed_proto_defaults() {
        let proto = FixedProto;
        assert_eq!(proto.header_len(&[0u8; 14], 100).unwrap(), 14);
        assert_eq!(FixedProto::NODE_TYPE, NodeType::Plain);
        assert!(!FixedProto::ENCAP);
        assert!(!FixedProto::OVERLAY);
    }

    #[test]
    fn overlay_proto_flag() {
        assert!(OverlayProto::OVERLAY);
        let proto = OverlayProto;
        assert_eq!(proto.next_proto(&[4]).unwrap(), 4);
    }
}
