//! TLV (Type-Length-Value) parsing system.
//!
//! Provides types and functions for parsing protocol headers that contain
//! TLV-encoded options (e.g., TCP options, IPv6 Hop-by-Hop options, Geneve).
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `TlvOps` | `tlvs.h:64-68` | `struct xdp2_proto_tlvs_opts` |
//! | `ParseTlvNodeOps` | `tlvs.h:83-89` | `struct xdp2_parse_tlv_node_ops` |
//! | `ParseTlvNode` | `tlvs.h:94-102` | `struct xdp2_parse_tlv_node` |
//! | `TlvTableEntry` | `tlvs.h:108-111` | `struct xdp2_proto_tlvs_table_entry` |
//! | `TlvTable` | `tlvs.h:117-120` | `struct xdp2_proto_tlvs_table` |
//! | `ParseTlvsNode` | `tlvs.h:136-143` | `struct xdp2_parse_tlvs_node` |
//! | `ProtoTlvsDef` | `tlvs.h:158-166` | `struct xdp2_proto_tlvs_def` |
//! | `parse_tlvs()` | `parser.c:97-185` | `xdp2_parse_tlvs()` |
//! | `parse_one_tlv()` | `parser.c:50-96` | `xdp2_parse_one_tlv()` |

use crate::parse_node::ParseNodeDyn;
use crate::proto_def::ProtocolOps;
use crate::proto_table::ProtoTable;
use crate::types::{CtrlData, NodeType, ParseError};

/// Operations for parsing TLV headers.
///
/// Reimplements: `struct xdp2_proto_tlvs_opts` in `tlvs.h:64-68`
pub struct TlvOps {
    /// Return length of a TLV option
    pub len: fn(hdr: &[u8], maxlen: usize) -> Result<usize, ParseError>,
    /// Return the type code of a TLV option
    pub type_fn: fn(hdr: &[u8]) -> Result<i32, ParseError>,
    /// Return the start offset for TLV data within the enclosing header
    pub start_offset: fn(hdr: &[u8]) -> usize,
}

/// Per-TLV-type callbacks for metadata extraction and handling.
///
/// Reimplements: `struct xdp2_parse_tlv_node_ops` in `tlvs.h:83-89`
pub struct ParseTlvNodeOps<M: 'static> {
    pub extract_metadata:
        Option<fn(hdr: &[u8], hdr_len: usize, metadata: &mut M, ctrl: &CtrlData)>,
    pub handler:
        Option<fn(hdr: &[u8], hdr_len: usize, metadata: &mut M, ctrl: &CtrlData) -> Result<(), ParseError>>,
}

/// Parse node for a single TLV type.
///
/// Reimplements: `struct xdp2_parse_tlv_node` in `tlvs.h:94-102`
pub struct ParseTlvNode<M: 'static> {
    pub ops: ParseTlvNodeOps<M>,
    pub name: &'static str,
}

/// One entry in a TLV table: maps TLV type to parse node.
///
/// Reimplements: `struct xdp2_proto_tlvs_table_entry` in `tlvs.h:108-111`
pub struct TlvTableEntry<M: 'static> {
    pub tlv_type: i32,
    pub node: &'static ParseTlvNode<M>,
}

/// TLV table mapping TLV types to parse nodes.
///
/// Reimplements: `struct xdp2_proto_tlvs_table` in `tlvs.h:117-120`
pub struct TlvTable<M: 'static> {
    pub entries: &'static [TlvTableEntry<M>],
}

impl<M: 'static> TlvTable<M> {
    /// Look up a TLV parse node by type code (linear scan).
    ///
    /// Reimplements: `lookup_tlv_node()` in `parser.c:51-61`
    pub fn lookup(&self, tlv_type: i32) -> Option<&'static ParseTlvNode<M>> {
        for entry in self.entries {
            if entry.tlv_type == tlv_type {
                return Some(entry.node);
            }
        }
        None
    }
}

/// TLV protocol definition — extends ProtocolOps with TLV-specific configuration.
///
/// Reimplements: `struct xdp2_proto_tlvs_def` in `tlvs.h:158-166`
///
/// In C, this is a "super struct" that embeds `xdp2_proto_def` plus TLV ops
/// and config. In Rust, it wraps a protocol ops impl with TLV-specific fields.
pub struct ProtoTlvsDef<P: ProtocolOps> {
    /// Base protocol operations
    pub proto: P,
    /// TLV parsing operations (len, type, start_offset)
    pub ops: TlvOps,
    /// Type value for single-byte padding (e.g., 0 for IPv6 HBH)
    pub pad1_val: u8,
    /// Whether pad1 detection is enabled
    pub pad1_enable: bool,
    /// Type value indicating end of TLV list
    pub eol_val: u8,
    /// Whether end-of-list detection is enabled
    pub eol_enable: bool,
    /// Minimum length of a TLV option
    pub min_len: usize,
}

/// Wrapper parse node for protocols with TLV sub-structures.
///
/// Reimplements: `struct xdp2_parse_tlvs_node` in `tlvs.h:136-143`
///
/// In C, this is a "super struct" containing an embedded `xdp2_parse_node`
/// plus TLV-specific configuration. In Rust, it wraps a `dyn ParseNodeDyn`
/// and overrides `sub_parse()` to dispatch to `parse_tlvs()`.
pub struct ParseTlvsNode<M: 'static> {
    /// The inner parse node (provides all standard ParseNodeDyn methods)
    pub inner: &'static dyn ParseNodeDyn<M>,
    /// TLV lookup table
    pub tlv_proto_table: &'static TlvTable<M>,
    /// TLV parsing operations
    pub tlv_ops: &'static TlvOps,
    /// Maximum number of TLVs to parse
    pub max_tlvs: usize,
    /// Maximum length allowed for any single TLV
    pub max_tlv_len: usize,
    /// Return code for unknown TLV types
    pub unknown_tlv_type_ret: ParseError,
    /// Wildcard TLV node used if type is not found in table
    pub tlv_wildcard_node: Option<&'static ParseTlvNode<M>>,
}

impl<M: 'static> ParseNodeDyn<M> for ParseTlvsNode<M> {
    fn min_len(&self) -> usize { self.inner.min_len() }
    fn name(&self) -> &'static str { self.inner.name() }
    fn node_type(&self) -> NodeType { NodeType::Tlvs }
    fn is_encap(&self) -> bool { self.inner.is_encap() }
    fn is_overlay(&self) -> bool { self.inner.is_overlay() }

    fn header_len(&self, hdr: &[u8], maxlen: usize) -> Result<usize, ParseError> {
        self.inner.header_len(hdr, maxlen)
    }
    fn next_proto(&self, hdr: &[u8]) -> Result<i32, ParseError> {
        self.inner.next_proto(hdr)
    }
    fn extract_metadata(&self, hdr: &[u8], hdr_len: usize, metadata: &mut M, ctrl: &CtrlData) {
        self.inner.extract_metadata(hdr, hdr_len, metadata, ctrl);
    }
    fn handler(&self, hdr: &[u8], hdr_len: usize, metadata: &mut M, ctrl: &CtrlData) -> Result<(), ParseError> {
        self.inner.handler(hdr, hdr_len, metadata, ctrl)
    }
    fn post_handler(&self, hdr: &[u8], hdr_len: usize, metadata: &mut M, ctrl: &CtrlData) -> Result<(), ParseError> {
        self.inner.post_handler(hdr, hdr_len, metadata, ctrl)
    }

    /// Dispatch TLV sub-parsing.
    ///
    /// Reimplements: `case XDP2_NODE_TYPE_TLVS:` in `parser.c:532-544`
    fn sub_parse(&self, hdr: &[u8], hdr_len: usize, metadata: &mut M, ctrl: &CtrlData) -> Result<(), ParseError> {
        parse_tlvs(hdr, hdr_len, self.tlv_ops, &self.tlv_proto_table, self.max_tlvs, metadata, ctrl)
    }

    fn proto_table(&self) -> Option<&'static ProtoTable<M>> { self.inner.proto_table() }
    fn wildcard_node(&self) -> Option<&'static dyn ParseNodeDyn<M>> { self.inner.wildcard_node() }
    fn unknown_ret(&self) -> ParseError { self.inner.unknown_ret() }
}

// SAFETY: ParseTlvsNode delegates all state to &'static references which are inherently Send+Sync
unsafe impl<M: 'static> Send for ParseTlvsNode<M> {}
unsafe impl<M: 'static> Sync for ParseTlvsNode<M> {}

/// Parse TLVs within a protocol header.
///
/// Reimplements: `xdp2_parse_tlvs()` in `src/lib/xdp2/parser.c:97-185`
///
/// Iterates over TLV options in `hdr[start_offset..hdr_len]`, looking up
/// each TLV type in the table and calling its callbacks.
///
/// # Arguments
/// - `hdr`: The enclosing protocol header bytes
/// - `hdr_len`: Length of the enclosing header
/// - `tlv_ops`: Operations for parsing individual TLV headers
/// - `tlv_table`: Table mapping TLV types to parse nodes
/// - `max_tlvs`: Maximum number of TLVs to parse
/// - `metadata`: User-defined metadata
/// - `ctrl`: Control data
pub fn parse_tlvs<M>(
    hdr: &[u8],
    hdr_len: usize,
    tlv_ops: &TlvOps,
    tlv_table: &TlvTable<M>,
    max_tlvs: usize,
    metadata: &mut M,
    ctrl: &CtrlData,
) -> Result<(), ParseError> {
    let start = (tlv_ops.start_offset)(hdr);
    let mut pos = start;
    let mut count = 0;

    while pos < hdr_len && count < max_tlvs {
        let tlv_hdr = &hdr[pos..];
        let remaining = hdr_len - pos;

        if remaining == 0 {
            break;
        }

        // Get TLV type
        let tlv_type = (tlv_ops.type_fn)(tlv_hdr)?;

        // Get TLV length
        let tlv_len = (tlv_ops.len)(tlv_hdr, remaining)?;
        if tlv_len == 0 || tlv_len > remaining {
            return Err(ParseError::TlvLength);
        }

        // Look up TLV node
        if let Some(tlv_node) = tlv_table.lookup(tlv_type) {
            let tlv_bytes = &tlv_hdr[..tlv_len];

            if let Some(extract) = tlv_node.ops.extract_metadata {
                extract(tlv_bytes, tlv_len, metadata, ctrl);
            }
            if let Some(handler) = tlv_node.ops.handler {
                handler(tlv_bytes, tlv_len, metadata, ctrl)?;
            }
        }

        pos += tlv_len;
        count += 1;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Simple test metadata: tracks parsed TLV types.
    #[derive(Default)]
    struct TestMeta {
        types: Vec<i32>,
    }

    static TEST_TLV_NODE_A: ParseTlvNode<TestMeta> = ParseTlvNode {
        ops: ParseTlvNodeOps {
            extract_metadata: Some(|_hdr, _len, meta, _ctrl| {
                meta.types.push(1);
            }),
            handler: None,
        },
        name: "tlv-type-a",
    };

    static TEST_TLV_NODE_B: ParseTlvNode<TestMeta> = ParseTlvNode {
        ops: ParseTlvNodeOps {
            extract_metadata: Some(|_hdr, _len, meta, _ctrl| {
                meta.types.push(2);
            }),
            handler: None,
        },
        name: "tlv-type-b",
    };

    static TEST_TLV_TABLE: TlvTable<TestMeta> = TlvTable {
        entries: &[
            TlvTableEntry { tlv_type: 1, node: &TEST_TLV_NODE_A },
            TlvTableEntry { tlv_type: 2, node: &TEST_TLV_NODE_B },
        ],
    };

    // Simple TLV format: [type, length, ...data]
    // length includes the type+length bytes themselves
    static TEST_TLV_OPS: TlvOps = TlvOps {
        len: |hdr, maxlen| {
            if maxlen < 2 { return Err(ParseError::TlvLength); }
            Ok(hdr[1] as usize)
        },
        type_fn: |hdr| Ok(hdr[0] as i32),
        start_offset: |_hdr| 0,
    };

    #[test]
    fn tlv_lookup_finds_known_type() {
        assert_eq!(TEST_TLV_TABLE.lookup(1).unwrap().name, "tlv-type-a");
        assert_eq!(TEST_TLV_TABLE.lookup(2).unwrap().name, "tlv-type-b");
    }

    #[test]
    fn tlv_lookup_returns_none_for_unknown() {
        assert!(TEST_TLV_TABLE.lookup(99).is_none());
    }

    #[test]
    fn parse_tlvs_processes_entries() {
        // TLV: [type=1, len=3, data=0xAA], [type=2, len=4, data=0xBB, 0xCC]
        let hdr = [1, 3, 0xAA, 2, 4, 0xBB, 0xCC];
        let mut meta = TestMeta::default();
        let ctrl = CtrlData::default();

        let result = parse_tlvs(&hdr, hdr.len(), &TEST_TLV_OPS, &TEST_TLV_TABLE, 10, &mut meta, &ctrl);
        assert!(result.is_ok());
        assert_eq!(meta.types, vec![1, 2]);
    }

    #[test]
    fn parse_tlvs_respects_max_tlvs() {
        let hdr = [1, 3, 0xAA, 2, 4, 0xBB, 0xCC];
        let mut meta = TestMeta::default();
        let ctrl = CtrlData::default();

        let result = parse_tlvs(&hdr, hdr.len(), &TEST_TLV_OPS, &TEST_TLV_TABLE, 1, &mut meta, &ctrl);
        assert!(result.is_ok());
        assert_eq!(meta.types, vec![1]); // stopped after 1
    }

    #[test]
    fn parse_tlvs_zero_length_returns_error() {
        // TLV with length=0 is invalid
        let hdr = [1, 0];
        let mut meta = TestMeta::default();
        let ctrl = CtrlData::default();

        let result = parse_tlvs(&hdr, hdr.len(), &TEST_TLV_OPS, &TEST_TLV_TABLE, 10, &mut meta, &ctrl);
        assert!(result.is_err());
    }

    #[test]
    fn parse_tlvs_length_exceeds_remaining() {
        // TLV claims len=10 but only 3 bytes remain
        let hdr = [1, 10, 0xAA];
        let mut meta = TestMeta::default();
        let ctrl = CtrlData::default();

        let result = parse_tlvs(&hdr, hdr.len(), &TEST_TLV_OPS, &TEST_TLV_TABLE, 10, &mut meta, &ctrl);
        assert!(result.is_err());
    }

    #[test]
    fn parse_tlvs_skips_unknown_types() {
        // type=99 not in table — skipped, type=1 processed
        let hdr = [99, 2, 1, 3, 0xAA];
        let mut meta = TestMeta::default();
        let ctrl = CtrlData::default();

        let result = parse_tlvs(&hdr, hdr.len(), &TEST_TLV_OPS, &TEST_TLV_TABLE, 10, &mut meta, &ctrl);
        assert!(result.is_ok());
        assert_eq!(meta.types, vec![1]);
    }

    #[test]
    fn parse_tlvs_empty_is_ok() {
        let hdr: [u8; 0] = [];
        let mut meta = TestMeta::default();
        let ctrl = CtrlData::default();

        let result = parse_tlvs(&hdr, 0, &TEST_TLV_OPS, &TEST_TLV_TABLE, 10, &mut meta, &ctrl);
        assert!(result.is_ok());
        assert!(meta.types.is_empty());
    }
}
