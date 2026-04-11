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
//! | `parse_tlvs()` | `parser.c:97-185` | `xdp2_parse_tlvs()` |
//! | `parse_one_tlv()` | `parser.c:50-96` | `xdp2_parse_one_tlv()` |

use crate::types::{CtrlData, ParseError};

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
    pub fn lookup(&self, tlv_type: i32) -> Option<&'static ParseTlvNode<M>> {
        for entry in self.entries {
            if entry.tlv_type == tlv_type {
                return Some(entry.node);
            }
        }
        None
    }
}

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
