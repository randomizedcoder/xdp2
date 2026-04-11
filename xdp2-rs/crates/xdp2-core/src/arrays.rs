//! Array parsing system.
//!
//! Provides types and functions for parsing protocol headers that contain
//! arrays of fixed-size elements (e.g., SRv6 segment lists, MPLS label stacks).
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `ArrayOps` | `arrays.h:59-63` | `struct xdp2_proto_array_opts` |
//! | `ParseArrayElNodeOps` | `arrays.h:78-84` | `struct xdp2_parse_arrel_node_ops` |
//! | `ParseArrayElNode` | `arrays.h:89-92` | `struct xdp2_parse_arrel_node` |
//! | `ArrayTableEntry` | `arrays.h:98-101` | `struct xdp2_proto_array_table_entry` |
//! | `ArrayTable` | `arrays.h:108-111` | `struct xdp2_proto_array_table` |
//! | `ParseArrayNode` | `arrays.h:126+` | `struct xdp2_parse_array_node` |
//! | `parse_array()` | `parser.c:360-448` | `xdp2_parse_array()` |

use crate::types::{CtrlData, ParseError};

/// Operations for parsing array headers.
///
/// Reimplements: `struct xdp2_proto_array_opts` in `arrays.h:59-63`
pub struct ArrayOps {
    /// Return the number of elements in the array
    pub num_els: fn(hdr: &[u8], hdr_len: usize) -> usize,
    /// Return the type of an array element (negative = error/end marker)
    pub el_type: fn(el_hdr: &[u8]) -> Result<i32, ParseError>,
    /// Return the start offset of the array within the enclosing header
    pub start_offset: fn(hdr: &[u8]) -> usize,
}

/// Per-element callbacks for metadata extraction and handling.
///
/// Reimplements: `struct xdp2_parse_arrel_node_ops` in `arrays.h:78-84`
pub struct ParseArrayElNodeOps<M: 'static> {
    pub extract_metadata:
        Option<fn(el_hdr: &[u8], hdr_len: usize, metadata: &mut M, ctrl: &CtrlData)>,
    pub handler:
        Option<fn(el_hdr: &[u8], hdr_len: usize, metadata: &mut M, ctrl: &CtrlData) -> Result<(), ParseError>>,
}

/// Parse node for a single array element type.
///
/// Reimplements: `struct xdp2_parse_arrel_node` in `arrays.h:89-92`
pub struct ParseArrayElNode<M: 'static> {
    pub ops: ParseArrayElNodeOps<M>,
    pub name: &'static str,
}

/// One entry in an array element type table.
///
/// Reimplements: `struct xdp2_proto_array_table_entry` in `arrays.h:98-101`
pub struct ArrayTableEntry<M: 'static> {
    pub el_type: i32,
    pub node: &'static ParseArrayElNode<M>,
}

/// Array table mapping element types to parse nodes.
///
/// Reimplements: `struct xdp2_proto_array_table` in `arrays.h:108-111`
pub struct ArrayTable<M: 'static> {
    pub entries: &'static [ArrayTableEntry<M>],
}

impl<M: 'static> ArrayTable<M> {
    /// Look up an array element parse node by type (linear scan).
    pub fn lookup(&self, el_type: i32) -> Option<&'static ParseArrayElNode<M>> {
        for entry in self.entries {
            if entry.el_type == el_type {
                return Some(entry.node);
            }
        }
        None
    }
}

/// Parse an array of elements within a protocol header.
///
/// Reimplements: `xdp2_parse_array()` in `src/lib/xdp2/parser.c:360-448`
///
/// Iterates over `num_els` elements starting at `start_offset`, looking up
/// each element's type in the table and calling its callbacks.
pub fn parse_array<M>(
    hdr: &[u8],
    hdr_len: usize,
    array_ops: &ArrayOps,
    array_table: &ArrayTable<M>,
    el_length: usize,
    max_els: usize,
    metadata: &mut M,
    ctrl: &CtrlData,
) -> Result<(), ParseError> {
    let start = (array_ops.start_offset)(hdr);
    let num_els = (array_ops.num_els)(hdr, hdr_len).min(max_els);
    let mut pos = start;

    for _ in 0..num_els {
        if pos + el_length > hdr_len {
            return Err(ParseError::Length);
        }

        let el_hdr = &hdr[pos..pos + el_length];
        let el_type = (array_ops.el_type)(el_hdr)?;

        if let Some(el_node) = array_table.lookup(el_type) {
            if let Some(extract) = el_node.ops.extract_metadata {
                extract(el_hdr, el_length, metadata, ctrl);
            }
            if let Some(handler) = el_node.ops.handler {
                handler(el_hdr, el_length, metadata, ctrl)?;
            }
        }

        pos += el_length;
    }

    Ok(())
}
