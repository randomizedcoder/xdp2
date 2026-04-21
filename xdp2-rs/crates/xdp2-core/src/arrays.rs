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
//! | `ParseArrayNode` | `arrays.h:126-132` | `struct xdp2_parse_array_node` |
//! | `ProtoArrayDef` | `arrays.h:140-144` | `struct xdp2_proto_array_def` |
//! | `parse_array()` | `parser.c:360-448` | `xdp2_parse_array()` |

use crate::parse_node::ParseNodeDyn;
use crate::proto_table::ProtoTable;
use crate::types::{CtrlData, NodeType, ParseError};

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
    pub handler: Option<
        fn(
            el_hdr: &[u8],
            hdr_len: usize,
            metadata: &mut M,
            ctrl: &CtrlData,
        ) -> Result<(), ParseError>,
    >,
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
    ///
    /// Reimplements: `lookup_array_node()` in `parser.c:64-74`
    pub fn lookup(&self, el_type: i32) -> Option<&'static ParseArrayElNode<M>> {
        for entry in self.entries {
            if entry.el_type == el_type {
                return Some(entry.node);
            }
        }
        None
    }
}

/// Wrapper parse node for protocols with array sub-structures.
///
/// Reimplements: `struct xdp2_parse_array_node` in `arrays.h:126-132`
///
/// In C, this is a "super struct" containing an embedded `xdp2_parse_node`
/// plus array-specific configuration. In Rust, it wraps a `dyn ParseNodeDyn`
/// and overrides `sub_parse()` to dispatch to `parse_array()`.
pub struct ParseArrayNode<M: 'static> {
    /// The inner parse node (provides all standard ParseNodeDyn methods)
    pub inner: &'static dyn ParseNodeDyn<M>,
    /// Array element lookup table
    pub array_proto_table: &'static ArrayTable<M>,
    /// Array parsing operations
    pub array_ops: &'static ArrayOps,
    /// Length of each array element in bytes
    pub el_length: usize,
    /// Maximum number of elements to parse
    pub max_els: usize,
    /// Return code for unknown element types
    pub unknown_array_type_ret: ParseError,
    /// Wildcard element node used if type is not found in table
    pub array_wildcard_node: Option<&'static ParseArrayElNode<M>>,
}

impl<M: 'static> ParseNodeDyn<M> for ParseArrayNode<M> {
    fn min_len(&self) -> usize {
        self.inner.min_len()
    }
    fn name(&self) -> &'static str {
        self.inner.name()
    }
    fn node_type(&self) -> NodeType {
        NodeType::Array
    }
    fn is_encap(&self) -> bool {
        self.inner.is_encap()
    }
    fn is_overlay(&self) -> bool {
        self.inner.is_overlay()
    }

    fn header_len(&self, hdr: &[u8], maxlen: usize) -> Result<usize, ParseError> {
        self.inner.header_len(hdr, maxlen)
    }
    fn next_proto(&self, hdr: &[u8]) -> Result<i32, ParseError> {
        self.inner.next_proto(hdr)
    }
    fn extract_metadata(&self, hdr: &[u8], hdr_len: usize, metadata: &mut M, ctrl: &CtrlData) {
        self.inner.extract_metadata(hdr, hdr_len, metadata, ctrl);
    }
    fn handler(
        &self,
        hdr: &[u8],
        hdr_len: usize,
        metadata: &mut M,
        ctrl: &CtrlData,
    ) -> Result<(), ParseError> {
        self.inner.handler(hdr, hdr_len, metadata, ctrl)
    }
    fn post_handler(
        &self,
        hdr: &[u8],
        hdr_len: usize,
        metadata: &mut M,
        ctrl: &CtrlData,
    ) -> Result<(), ParseError> {
        self.inner.post_handler(hdr, hdr_len, metadata, ctrl)
    }

    /// Dispatch array sub-parsing.
    ///
    /// Reimplements: `case XDP2_NODE_TYPE_ARRAY:` in `parser.c:561-574`
    fn sub_parse(
        &self,
        hdr: &[u8],
        hdr_len: usize,
        metadata: &mut M,
        ctrl: &CtrlData,
    ) -> Result<(), ParseError> {
        parse_array(
            hdr,
            hdr_len,
            self.array_ops,
            self.array_proto_table,
            self.el_length,
            self.max_els,
            metadata,
            ctrl,
        )
    }

    fn proto_table(&self) -> Option<&'static ProtoTable<M>> {
        self.inner.proto_table()
    }
    fn wildcard_node(&self) -> Option<&'static dyn ParseNodeDyn<M>> {
        self.inner.wildcard_node()
    }
    fn unknown_ret(&self) -> ParseError {
        self.inner.unknown_ret()
    }
}

// SAFETY: ParseArrayNode delegates all state to &'static references which are inherently Send+Sync
unsafe impl<M: 'static> Send for ParseArrayNode<M> {}
unsafe impl<M: 'static> Sync for ParseArrayNode<M> {}

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

#[cfg(test)]
mod tests {
    use super::*;

    /// Simple test metadata: counts elements and records their types.
    #[derive(Default)]
    struct TestMeta {
        count: usize,
        types: Vec<i32>,
    }

    static TEST_EL_NODE_A: ParseArrayElNode<TestMeta> = ParseArrayElNode {
        ops: ParseArrayElNodeOps {
            extract_metadata: Some(|_hdr, _len, meta, _ctrl| {
                meta.count += 1;
                meta.types.push(1);
            }),
            handler: None,
        },
        name: "el-type-a",
    };

    static TEST_EL_NODE_B: ParseArrayElNode<TestMeta> = ParseArrayElNode {
        ops: ParseArrayElNodeOps {
            extract_metadata: Some(|_hdr, _len, meta, _ctrl| {
                meta.count += 1;
                meta.types.push(2);
            }),
            handler: None,
        },
        name: "el-type-b",
    };

    static TEST_TABLE: ArrayTable<TestMeta> = ArrayTable {
        entries: &[
            ArrayTableEntry {
                el_type: 1,
                node: &TEST_EL_NODE_A,
            },
            ArrayTableEntry {
                el_type: 2,
                node: &TEST_EL_NODE_B,
            },
        ],
    };

    static TEST_OPS: ArrayOps = ArrayOps {
        num_els: |_hdr, _len| 3,
        el_type: |el_hdr| Ok(el_hdr[0] as i32),
        start_offset: |_hdr| 0,
    };

    #[test]
    fn lookup_finds_known_type() {
        assert_eq!(TEST_TABLE.lookup(1).unwrap().name, "el-type-a");
        assert_eq!(TEST_TABLE.lookup(2).unwrap().name, "el-type-b");
    }

    #[test]
    fn lookup_returns_none_for_unknown() {
        assert!(TEST_TABLE.lookup(99).is_none());
    }

    #[test]
    fn parse_array_processes_elements() {
        // 3 elements of 4 bytes each: type=1, type=2, type=1
        let hdr = [1, 0, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0];
        let mut meta = TestMeta::default();
        let ctrl = CtrlData::default();

        let result = parse_array(
            &hdr,
            hdr.len(),
            &TEST_OPS,
            &TEST_TABLE,
            4,
            10,
            &mut meta,
            &ctrl,
        );
        assert!(result.is_ok());
        assert_eq!(meta.count, 3);
        assert_eq!(meta.types, vec![1, 2, 1]);
    }

    #[test]
    fn parse_array_respects_max_els() {
        let hdr = [1, 0, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0];
        let mut meta = TestMeta::default();
        let ctrl = CtrlData::default();
        let ops = ArrayOps {
            num_els: |_hdr, _len| 3,
            el_type: |el_hdr| Ok(el_hdr[0] as i32),
            start_offset: |_hdr| 0,
        };

        let result = parse_array(&hdr, hdr.len(), &ops, &TEST_TABLE, 4, 2, &mut meta, &ctrl);
        assert!(result.is_ok());
        assert_eq!(meta.count, 2); // capped at max_els=2
    }

    #[test]
    fn parse_array_truncated_returns_error() {
        // Only 6 bytes but claims 3 elements of 4 bytes
        let hdr = [1, 0, 0, 0, 2, 0];
        let mut meta = TestMeta::default();
        let ctrl = CtrlData::default();

        let result = parse_array(
            &hdr,
            hdr.len(),
            &TEST_OPS,
            &TEST_TABLE,
            4,
            10,
            &mut meta,
            &ctrl,
        );
        assert!(result.is_err());
        assert_eq!(meta.count, 1); // first element parsed before truncation
    }

    #[test]
    fn parse_array_skips_unknown_types() {
        // type=99 is not in table — should be silently skipped
        let hdr = [99, 0, 0, 0, 1, 0, 0, 0];
        let mut meta = TestMeta::default();
        let ctrl = CtrlData::default();
        let ops = ArrayOps {
            num_els: |_hdr, _len| 2,
            el_type: |el_hdr| Ok(el_hdr[0] as i32),
            start_offset: |_hdr| 0,
        };

        let result = parse_array(&hdr, hdr.len(), &ops, &TEST_TABLE, 4, 10, &mut meta, &ctrl);
        assert!(result.is_ok());
        assert_eq!(meta.count, 1); // only type=1 matched
    }
}
