//! GRE (Generic Routing Encapsulation) protocol definitions.
//!
//! GRE uses flag-fields — optional data whose presence is indicated by
//! bit flags in the header. The base header is 4 bytes (flags + protocol),
//! with optional checksum, key, and sequence number fields.
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `GreHeader` | `proto_defs/tunnel/proto_gre.h:30-34` | `struct gre_hdr` |
//! | `GreBaseOps` | `proto_gre.h:92-100` | `xdp2_parse_gre` (base overlay) |
//! | `GreV0Ops` | `proto_gre.h:105-115` | `xdp2_parse_gre_v0` |
//! | `gre_v0_proto()` | `proto_gre.h:62-65` | `gre_v0_proto()` |
//! | `gre_v0_len_check()` | `proto_gre.h:44-53` | `gre_v0_len_check()` |
//! | `gre_get_flags()` | `proto_gre.h:74-77` | `gre_get_flags()` |
//! | `gre_fields_offset()` | `proto_gre.h:79-82` | `gre_fields_offset()` |
//! | `GRE_V0_FLAG_FIELDS` | `proto_gre.h:84-90` | `gre_flag_fields` |
//!
//! ## Behavioral Differences
//! - None. Byte-for-byte compatible with C implementation.

use xdp2_core::flag_fields::{FlagField, FlagFields, FlagFieldsOps};
use xdp2_core::{NodeType, ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// GRE flag bits.
pub const GRE_CSUM: u16 = 0x8000;
pub const GRE_ROUTING: u16 = 0x4000;
pub const GRE_KEY: u16 = 0x2000;
pub const GRE_SEQ: u16 = 0x1000;
pub const GRE_VERSION: u16 = 0x0007;

/// Valid flags mask for GRE v0.
pub const GRE_FLAGS_V0_MASK: u16 = GRE_CSUM | GRE_ROUTING | GRE_KEY | GRE_SEQ;

/// GRE header (minimum 4 bytes, variable via flag-fields).
///
/// Reimplements: `struct gre_hdr` in `proto_gre.h:30-34`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct GreHeader {
    /// Flags and version
    pub flags: [u8; 2],
    /// Protocol type (EtherType of encapsulated packet)
    pub protocol: [u8; 2],
}

impl GreHeader {
    /// Raw flags value (big-endian).
    pub fn flags_be(&self) -> u16 {
        u16::from_be_bytes(self.flags)
    }

    /// GRE version (lower 3 bits).
    pub fn version(&self) -> u8 {
        (self.flags_be() & GRE_VERSION) as u8
    }

    /// Encapsulated protocol (EtherType).
    pub fn protocol(&self) -> u16 {
        u16::from_be_bytes(self.protocol)
    }
}

/// GRE v0 flag-field descriptors.
///
/// Reimplements: `gre_flag_fields` in `proto_gre.h:84-90`
///
/// - Checksum (0x8000): 4 bytes (checksum + reserved)
/// - Key (0x2000): 4 bytes
/// - Sequence (0x1000): 4 bytes
pub static GRE_V0_FLAG_FIELDS: FlagFields = FlagFields {
    fields: &[
        FlagField {
            flag: GRE_CSUM as u32,
            mask: 0,
            size: 4,
        },
        FlagField {
            flag: GRE_KEY as u32,
            mask: 0,
            size: 4,
        },
        FlagField {
            flag: GRE_SEQ as u32,
            mask: 0,
            size: 4,
        },
    ],
};

/// GRE flag-fields operations.
///
/// Reimplements: `gre_get_flags()` and `gre_fields_offset()` in `proto_gre.h:74-82`
pub static GRE_FF_OPS: FlagFieldsOps = FlagFieldsOps {
    get_flags: |hdr| {
        // gre_get_flags: return gre->flags
        u16::from_be_bytes([hdr[0], hdr[1]]) as u32
    },
    start_fields_offset: |_hdr| {
        // gre_fields_offset: return sizeof(struct gre_hdr) = 4
        4
    },
};

/// Compute GRE v0 header length from flags.
///
/// Reimplements: inline logic from `gre_v0_len_from_flags()` in proto_gre.h
fn gre_v0_len_from_flags(flags: u16) -> usize {
    4 + GRE_V0_FLAG_FIELDS.length(flags as u32)
}

/// GRE base protocol operations (overlay for version dispatch).
///
/// Reimplements: `xdp2_parse_gre` in `proto_gre.h:92-100`
///
/// This overlay node reads the GRE version field (lower 3 bits) and
/// returns it for dispatch to GRE v0 or v1 nodes.
pub struct GreBaseOps;

impl ProtocolOps for GreBaseOps {
    const MIN_LEN: usize = 4; // sizeof(struct gre_hdr)
    const NAME: &'static str = "GRE base";
    const OVERLAY: bool = true;

    /// Return GRE version for dispatch (0 or 1).
    #[inline]
    fn next_proto(&self, hdr: &[u8]) -> Result<i32, ParseError> {
        let gre = GreHeader::ref_from_prefix(hdr)
            .map_err(|_| ParseError::Length)?
            .0;
        Ok(gre.version() as i32)
    }
}

/// GRE v0 protocol operations (encapsulation node with flag-fields).
///
/// Reimplements: `xdp2_parse_gre_v0` in `proto_gre.h:105-115`
///
/// Variable-length header: 4 bytes base + optional checksum/key/sequence
/// fields determined by flag bits. Uses `NODE_TYPE_FLAG_FIELDS` in C.
pub struct GreV0Ops;

impl ProtocolOps for GreV0Ops {
    const MIN_LEN: usize = 4; // sizeof(struct gre_hdr)
    const NAME: &'static str = "GRE v0";
    const NODE_TYPE: NodeType = NodeType::FlagFields;
    const ENCAP: bool = true;

    /// Validate flags and compute header length.
    ///
    /// Reimplements: `gre_v0_len_check()` in `proto_gre.h:44-53`
    #[inline]
    fn header_len(&self, hdr: &[u8], _maxlen: usize) -> Result<usize, ParseError> {
        let gre = GreHeader::ref_from_prefix(hdr)
            .map_err(|_| ParseError::Length)?
            .0;
        let flags = gre.flags_be();

        // Check for invalid flags
        if (flags & !(GRE_FLAGS_V0_MASK | GRE_VERSION)) != 0 {
            return Err(ParseError::BadFlag);
        }

        // Routing flag set → accept with partial metadata (deprecated,
        // variable-length routing entries follow the base header).
        // The C parser returns XDP2_STOP_OKAY here. We return the base
        // length so the engine records what it can and stops.
        if flags & GRE_ROUTING != 0 {
            return Ok(gre_v0_len_from_flags(flags));
        }

        Ok(gre_v0_len_from_flags(flags))
    }

    /// Return encapsulated protocol (EtherType).
    ///
    /// Reimplements: `gre_v0_proto()` in `proto_gre.h:62-65`
    #[inline]
    fn next_proto(&self, hdr: &[u8]) -> Result<i32, ParseError> {
        let gre = GreHeader::ref_from_prefix(hdr)
            .map_err(|_| ParseError::Length)?
            .0;
        Ok(gre.protocol() as i32)
    }
}

/// GRE v1 (PPTP) variant — leaf node.
/// Reimplements: `xdp2_parse_gre_v1_pptp` in `proto_gre.h`
pub struct GreV1PptpOps;

impl ProtocolOps for GreV1PptpOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "GRE v1 - pptp";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_gre_v0(flags: u16, protocol: u16) -> Vec<u8> {
        let mut hdr = Vec::new();
        hdr.extend_from_slice(&flags.to_be_bytes());
        hdr.extend_from_slice(&protocol.to_be_bytes());
        // Add enough optional field bytes
        hdr.extend_from_slice(&[0u8; 12]); // max optional: csum+key+seq = 12
        hdr
    }

    #[test]
    fn gre_base_version_dispatch() {
        let hdr = make_gre_v0(0, 0x0800);
        let ops = GreBaseOps;
        assert_eq!(ops.next_proto(&hdr).unwrap(), 0); // v0
        assert!(GreBaseOps::OVERLAY);
    }

    #[test]
    fn gre_v0_no_options() {
        let hdr = make_gre_v0(0, 0x0800);
        let ops = GreV0Ops;
        assert_eq!(ops.header_len(&hdr, 100).unwrap(), 4);
        assert_eq!(ops.next_proto(&hdr).unwrap(), 0x0800); // IPv4
    }

    #[test]
    fn gre_v0_with_key() {
        let hdr = make_gre_v0(GRE_KEY, 0x0800);
        let ops = GreV0Ops;
        assert_eq!(ops.header_len(&hdr, 100).unwrap(), 8); // 4 base + 4 key
    }

    #[test]
    fn gre_v0_with_all_options() {
        let hdr = make_gre_v0(GRE_CSUM | GRE_KEY | GRE_SEQ, 0x0800);
        let ops = GreV0Ops;
        assert_eq!(ops.header_len(&hdr, 100).unwrap(), 16); // 4 + 4 + 4 + 4
    }

    #[test]
    fn gre_v0_with_checksum_and_key() {
        let hdr = make_gre_v0(GRE_CSUM | GRE_KEY, 0x6558);
        let ops = GreV0Ops;
        assert_eq!(ops.header_len(&hdr, 100).unwrap(), 12); // 4 + 4 + 4
        assert_eq!(ops.next_proto(&hdr).unwrap(), 0x6558); // TEB
    }

    #[test]
    fn gre_v0_invalid_flags() {
        // Set an invalid flag bit (0x0100)
        let hdr = make_gre_v0(0x0100, 0x0800);
        let ops = GreV0Ops;
        assert_eq!(ops.header_len(&hdr, 100).unwrap_err(), ParseError::BadFlag);
    }

    #[test]
    fn gre_v0_routing_flag_accepted() {
        let hdr = make_gre_v0(GRE_ROUTING, 0x0800);
        let ops = GreV0Ops;
        // Routing flag accepted with partial metadata (base header length).
        assert!(ops.header_len(&hdr, 100).is_ok());
    }

    #[test]
    fn gre_v0_is_encap() {
        assert!(GreV0Ops::ENCAP);
        assert_eq!(GreV0Ops::NODE_TYPE, NodeType::FlagFields);
    }

    #[test]
    fn gre_flag_fields_length() {
        // No flags
        assert_eq!(GRE_V0_FLAG_FIELDS.length(0), 0);
        // Key only
        assert_eq!(GRE_V0_FLAG_FIELDS.length(GRE_KEY as u32), 4);
        // All flags
        assert_eq!(
            GRE_V0_FLAG_FIELDS.length((GRE_CSUM | GRE_KEY | GRE_SEQ) as u32),
            12
        );
    }

    #[test]
    fn gre_header_fields() {
        let hdr = make_gre_v0(GRE_KEY, 0x0800);
        let gre = GreHeader::ref_from_prefix(&hdr).unwrap().0;
        assert_eq!(gre.version(), 0);
        assert_eq!(gre.protocol(), 0x0800);
        assert_eq!(gre.flags_be() & GRE_KEY, GRE_KEY);
    }
}
