//! Flag-fields parsing system.
//!
//! Flag-fields encode optional data fields whose presence is indicated by
//! bit flags in a header word. The fields are fixed-length and ordered by
//! flag position (e.g., GRE v0, GUE).
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `FlagField` | `flag_fields.h:64-68` | `struct xdp2_flag_field` |
//! | `FlagFields` | `flag_fields.h:78-81` | `struct xdp2_flag_fields` |
//! | `FlagFieldsOps` | `flag_fields.h:162-165` | `struct xdp2_proto_flag_fields_ops` |
//! | `ParseFlagFieldNode` | `flag_fields.h:189-192` | `struct xdp2_parse_flag_field_node` |
//! | `FlagFieldsTableEntry` | `flag_fields.h:198-201` | `struct xdp2_proto_flag_fields_table_entry` |
//! | `FlagFieldsTable` | `flag_fields.h:209-212` | `struct xdp2_proto_flag_fields_table` |
//! | `flag_fields_offset()` | `flag_fields.h:116-130` | `xdp2_flag_fields_offset()` |
//! | `flag_fields_length()` | `flag_fields.h:107-113` | `xdp2_flag_fields_length()` |
//! | `flag_fields_check_invalid()` | `flag_fields.h:133-136` | `xdp2_flag_fields_check_invalid()` |
//! | `parse_flag_fields()` | `parser.c:298-358` | `xdp2_parse_flag_fields()` |

use crate::parse_node::ParseNodeDyn;
use crate::proto_table::ProtoTable;
use crate::types::{CtrlData, NodeType, ParseError};

/// One descriptor for a flag-field.
///
/// Reimplements: `struct xdp2_flag_field` in `flag_fields.h:64-68`
#[derive(Debug, Clone, Copy)]
pub struct FlagField {
    /// Protocol flag value
    pub flag: u32,
    /// Mask to apply (0 means use flag as mask)
    pub mask: u32,
    /// Size of the corresponding data field in bytes
    pub size: usize,
}

/// A set of flag-field descriptors for one protocol.
///
/// Reimplements: `struct xdp2_flag_fields` in `flag_fields.h:78-81`
pub struct FlagFields {
    pub fields: &'static [FlagField],
}

impl FlagFields {
    /// Compute the byte offset of a particular flag's data field.
    ///
    /// Reimplements: `__xdp2_flag_fields_offset()` in `flag_fields.h:84-101`
    ///
    /// Scans all fields before `targ_idx`, summing the sizes of present fields.
    fn offset_of(&self, targ_idx: usize, flags: u32) -> usize {
        let mut offset = 0;
        for i in 0..targ_idx {
            let field = &self.fields[i];
            let mask = if field.mask != 0 {
                field.mask
            } else {
                field.flag
            };
            if (flags & mask) == field.flag {
                offset += field.size;
            }
        }
        offset
    }

    /// Compute the total length of optional fields present given a flag word.
    ///
    /// Reimplements: `xdp2_flag_fields_length()` in `flag_fields.h:107-113`
    ///
    /// This is equivalent to the offset of the theoretical field after the last one.
    pub fn length(&self, flags: u32) -> usize {
        self.offset_of(self.fields.len(), flags)
    }

    /// Determine the byte offset of a specific flag's data field.
    ///
    /// Reimplements: `xdp2_flag_fields_offset()` in `flag_fields.h:116-130`
    ///
    /// Returns `None` if the flag is not set (C returns -1).
    pub fn offset(&self, targ_idx: usize, flags: u32) -> Option<usize> {
        if targ_idx >= self.fields.len() {
            return None;
        }
        let field = &self.fields[targ_idx];
        let mask = if field.mask != 0 {
            field.mask
        } else {
            field.flag
        };
        if (flags & mask) != field.flag {
            return None; // Flag not set
        }
        Some(self.offset_of(targ_idx, flags))
    }

    /// Check if any illegal flags are set.
    ///
    /// Reimplements: `xdp2_flag_fields_check_invalid()` in `flag_fields.h:133-136`
    pub fn check_invalid(&self, flags: u32, valid_mask: u32) -> bool {
        (flags & !valid_mask) != 0
    }
}

/// Operations for parsing flag-fields in a protocol header.
///
/// Reimplements: `struct xdp2_proto_flag_fields_ops` in `flag_fields.h:162-165`
pub struct FlagFieldsOps {
    /// Extract the flags word from the protocol header.
    pub get_flags: fn(hdr: &[u8]) -> u32,
    /// Return the byte offset where flag-field data starts within the header.
    pub start_fields_offset: fn(hdr: &[u8]) -> usize,
}

/// Per-flag-field callbacks for metadata extraction and handling.
///
/// Reimplements: `struct xdp2_parse_flag_field_node_ops` in `flag_fields.h:180-186`
pub struct ParseFlagFieldNodeOps<M: 'static> {
    pub extract_metadata: Option<fn(hdr: &[u8], hdr_len: usize, metadata: &mut M, ctrl: &CtrlData)>,
    pub handler: Option<
        fn(hdr: &[u8], hdr_len: usize, metadata: &mut M, ctrl: &CtrlData) -> Result<(), ParseError>,
    >,
}

/// A parse node for a single flag-field.
///
/// Reimplements: `struct xdp2_parse_flag_field_node` in `flag_fields.h:189-192`
pub struct ParseFlagFieldNode<M: 'static> {
    pub ops: ParseFlagFieldNodeOps<M>,
    pub name: &'static str,
}

/// One entry in a flag-fields protocol table: maps field index to parse node.
///
/// Reimplements: `struct xdp2_proto_flag_fields_table_entry` in `flag_fields.h:198-201`
pub struct FlagFieldsTableEntry<M: 'static> {
    /// Flag-field index (index in the flag-fields descriptor table)
    pub index: i32,
    /// Parse node for this flag-field
    pub node: &'static ParseFlagFieldNode<M>,
}

/// Flag-fields table mapping field indices to parse nodes.
///
/// Reimplements: `struct xdp2_proto_flag_fields_table` in `flag_fields.h:209-212`
pub struct FlagFieldsTable<M: 'static> {
    pub entries: &'static [FlagFieldsTableEntry<M>],
}

impl<M: 'static> FlagFieldsTable<M> {
    /// Look up a flag-field parse node by index (linear scan).
    ///
    /// Reimplements: `lookup_flag_field_node()` in `parser.c:85-96`
    pub fn lookup(&self, index: i32) -> Option<&'static ParseFlagFieldNode<M>> {
        for entry in self.entries {
            if entry.index == index {
                return Some(entry.node);
            }
        }
        None
    }
}

/// Wrapper parse node for protocols with flag-field sub-structures.
///
/// Reimplements: `struct xdp2_parse_flag_fields_node` in `flag_fields.h:217-220`
///
/// In C, this is a "super struct" containing an embedded `xdp2_parse_node`
/// plus a pointer to the flag-fields protocol table. In Rust, it wraps a
/// `dyn ParseNodeDyn` and overrides `sub_parse()` to dispatch to `parse_flag_fields()`.
pub struct ParseFlagFieldsNode<M: 'static> {
    /// The inner parse node (provides all standard ParseNodeDyn methods)
    pub inner: &'static dyn ParseNodeDyn<M>,
    /// Flag-field parse node lookup table
    pub ff_proto_table: &'static FlagFieldsTable<M>,
    /// Flag-field descriptors (defines which flags exist and their sizes)
    pub flag_fields: &'static FlagFields,
    /// Operations for extracting flags and field start offset
    pub ff_ops: &'static FlagFieldsOps,
}

impl<M: 'static> ParseNodeDyn<M> for ParseFlagFieldsNode<M> {
    fn min_len(&self) -> usize {
        self.inner.min_len()
    }
    fn name(&self) -> &'static str {
        self.inner.name()
    }
    fn node_type(&self) -> NodeType {
        NodeType::FlagFields
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

    /// Dispatch flag-fields sub-parsing.
    ///
    /// Reimplements: `case XDP2_NODE_TYPE_FLAG_FIELDS:` in `parser.c:546-559`
    fn sub_parse(
        &self,
        hdr: &[u8],
        hdr_len: usize,
        metadata: &mut M,
        ctrl: &CtrlData,
    ) -> Result<(), ParseError> {
        parse_flag_fields(
            hdr,
            hdr_len,
            self.flag_fields,
            self.ff_ops,
            self.ff_proto_table,
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

// SAFETY: ParseFlagFieldsNode delegates all state to &'static references which are inherently Send+Sync
unsafe impl<M: 'static> Send for ParseFlagFieldsNode<M> {}
unsafe impl<M: 'static> Sync for ParseFlagFieldsNode<M> {}

/// Parse flag-fields within a protocol header.
///
/// Reimplements: `xdp2_parse_flag_fields()` in `src/lib/xdp2/parser.c:298-358`
///
/// Iterates over all flag-field descriptors, checking which flags are present.
/// For each present flag, looks up the parse node by index and calls its
/// extract_metadata and handler callbacks with the field data.
///
/// # Arguments
/// - `hdr`: The enclosing protocol header bytes
/// - `hdr_len`: Length of the enclosing header
/// - `flag_fields`: Flag-field descriptors (defines which flags exist)
/// - `ff_ops`: Operations for getting flags and start offset
/// - `ff_table`: Table mapping flag-field indices to parse nodes
/// - `metadata`: User-defined metadata
/// - `ctrl`: Control data
pub fn parse_flag_fields<M>(
    hdr: &[u8],
    _hdr_len: usize,
    flag_fields: &FlagFields,
    ff_ops: &FlagFieldsOps,
    ff_table: &FlagFieldsTable<M>,
    metadata: &mut M,
    ctrl: &CtrlData,
) -> Result<(), ParseError> {
    let flags = (ff_ops.get_flags)(hdr);
    let start = (ff_ops.start_fields_offset)(hdr);
    let field_data = &hdr[start..];

    for (i, field_desc) in flag_fields.fields.iter().enumerate() {
        // Check if this flag-field is present
        let offset = match flag_fields.offset(i, flags) {
            Some(off) => off,
            None => continue,
        };

        // Look up parse node by index
        if let Some(ff_node) = ff_table.lookup(i as i32) {
            let cp = &field_data[offset..];
            let field_size = field_desc.size;

            if let Some(extract) = ff_node.ops.extract_metadata {
                extract(cp, field_size, metadata, ctrl);
            }
            if let Some(handler) = ff_node.ops.handler {
                handler(cp, field_size, metadata, ctrl)?;
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // GRE v0 flag-fields (simplified)
    // Bit 15 (0x8000): Checksum present (4 bytes: checksum + reserved)
    // Bit 13 (0x2000): Key present (4 bytes)
    // Bit 12 (0x1000): Sequence present (4 bytes)
    static GRE_FLAGS: FlagFields = FlagFields {
        fields: &[
            FlagField {
                flag: 0x8000,
                mask: 0,
                size: 4,
            }, // checksum
            FlagField {
                flag: 0x2000,
                mask: 0,
                size: 4,
            }, // key
            FlagField {
                flag: 0x1000,
                mask: 0,
                size: 4,
            }, // sequence
        ],
    };

    #[test]
    fn no_flags_set() {
        assert_eq!(GRE_FLAGS.length(0x0000), 0);
    }

    #[test]
    fn all_flags_set() {
        assert_eq!(GRE_FLAGS.length(0x8000 | 0x2000 | 0x1000), 12);
    }

    #[test]
    fn key_only() {
        let flags = 0x2000;
        assert_eq!(GRE_FLAGS.length(flags), 4);
        // Key is at index 1, but checksum (index 0) is not present
        assert_eq!(GRE_FLAGS.offset(1, flags), Some(0));
    }

    #[test]
    fn checksum_and_key() {
        let flags = 0x8000 | 0x2000;
        assert_eq!(GRE_FLAGS.length(flags), 8);
        // Checksum at offset 0
        assert_eq!(GRE_FLAGS.offset(0, flags), Some(0));
        // Key at offset 4 (after checksum)
        assert_eq!(GRE_FLAGS.offset(1, flags), Some(4));
        // Sequence not present
        assert_eq!(GRE_FLAGS.offset(2, flags), None);
    }

    #[test]
    fn invalid_flags() {
        let valid_mask = 0x8000 | 0x2000 | 0x1000;
        assert!(!GRE_FLAGS.check_invalid(0x2000, valid_mask));
        assert!(GRE_FLAGS.check_invalid(0x0001, valid_mask));
    }

    #[test]
    fn parse_flag_fields_with_table() {
        // Test parse_flag_fields with a simple GRE-like header
        // Header: 2 bytes flags + 2 bytes protocol + optional fields
        // flags = 0x2000 (key present) → 4 bytes key data after base header

        static KEY_NODE: ParseFlagFieldNode<Vec<u32>> = ParseFlagFieldNode {
            ops: ParseFlagFieldNodeOps {
                extract_metadata: Some(|hdr, _len, meta, _ctrl| {
                    let key = u32::from_be_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
                    meta.push(key);
                }),
                handler: None,
            },
            name: "gre-key",
        };

        static FF_TABLE: FlagFieldsTable<Vec<u32>> = FlagFieldsTable {
            entries: &[
                FlagFieldsTableEntry {
                    index: 1,
                    node: &KEY_NODE,
                }, // key is index 1
            ],
        };

        static FF_OPS: FlagFieldsOps = FlagFieldsOps {
            get_flags: |hdr| u16::from_be_bytes([hdr[0], hdr[1]]) as u32,
            start_fields_offset: |_hdr| 4, // fields start after 4-byte base header
        };

        // Build a GRE-like header: flags=0x2000, proto=0x0800, key=0xDEADBEEF
        let hdr = [
            0x20, 0x00, // flags: key present
            0x08, 0x00, // protocol: IPv4
            0xDE, 0xAD, 0xBE, 0xEF, // key
        ];

        let mut metadata = Vec::new();
        let ctrl = CtrlData::default();

        parse_flag_fields(
            &hdr,
            hdr.len(),
            &GRE_FLAGS,
            &FF_OPS,
            &FF_TABLE,
            &mut metadata,
            &ctrl,
        )
        .unwrap();

        assert_eq!(metadata, vec![0xDEADBEEF]);
    }
}
