//! Geneve (Generic Network Virtualization Encapsulation) protocol definitions.
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `GeneveHeader` | `proto_defs/tunnel/proto_geneve.h:34-62` | `struct geneve_hdr` |
//! | `GeneveOptHeader` | `proto_geneve.h:64-76` | `struct geneve_opt` |
//! | `GeneveBaseOps` | `proto_geneve.h:131-136` | `xdp2_parse_geneve_base` |
//! | `GeneveV0Ops` | `proto_geneve.h:139-150` | `xdp2_parse_geneve_v0` |
//! | `GeneveV0Ops::header_len` | `proto_geneve.h:90-95` | `geneve_len_v0()` |
//! | `GeneveV0Ops::next_proto` | `proto_geneve.h:85-88` | `geneve_proto_v0()` |
//!
//! ## Behavioral Differences
//! - None. Byte-for-byte compatible with C implementation.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// Geneve version mask (upper 2 bits of byte 0).
pub const GENEVE_VERSION_MASK: u8 = 0xC0;

/// Geneve header (8 bytes, big-endian layout).
///
/// Reimplements: `struct geneve_hdr` in `proto_geneve.h:34-62`
///
/// Layout (big-endian): ver(2) + optlen(6) | O(1) + C(1) + rsvd(6) | protocol(16) | vni(24) + rsvd(8)
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct GeneveHeader {
    /// Version (2 bits) + Options length (6 bits, in 4-byte units)
    pub ver_optlen: u8,
    /// O-bit (1) + C-bit (1) + Reserved (6)
    pub flags: u8,
    /// Protocol type (EtherType of inner frame)
    pub protocol: [u8; 2],
    /// VNI (24 bits) + Reserved (8 bits)
    pub vni_reserved: [u8; 4],
}

impl GeneveHeader {
    /// Geneve version (upper 2 bits).
    pub fn version(&self) -> u8 {
        self.ver_optlen >> 6
    }

    /// Options length in 4-byte units (lower 6 bits).
    pub fn opt_len_words(&self) -> u8 {
        self.ver_optlen & 0x3F
    }

    /// Total header length: 8 + 4 * optlen.
    pub fn header_length(&self) -> usize {
        8 + 4 * self.opt_len_words() as usize
    }

    /// Protocol type (EtherType).
    pub fn protocol(&self) -> u16 {
        u16::from_be_bytes(self.protocol)
    }

    /// VNI (24-bit Virtual Network Identifier).
    pub fn vni(&self) -> u32 {
        ((self.vni_reserved[0] as u32) << 16)
            | ((self.vni_reserved[1] as u32) << 8)
            | (self.vni_reserved[2] as u32)
    }
}

/// Geneve option header (4 bytes).
///
/// Reimplements: `struct geneve_opt` in `proto_geneve.h:64-76`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct GeneveOptHeader {
    /// Option class
    pub option_class: [u8; 2],
    /// Option type
    pub opt_type: u8,
    /// Reserved (3 bits) + Length (5 bits, in 4-byte units)
    pub rsvd_length: u8,
}

impl GeneveOptHeader {
    /// Option class.
    pub fn option_class(&self) -> u16 {
        u16::from_be_bytes(self.option_class)
    }

    /// Option data length in 4-byte units (lower 5 bits).
    pub fn length_words(&self) -> u8 {
        self.rsvd_length & 0x1F
    }

    /// Total option length in bytes: 4 + 4 * length.
    ///
    /// Reimplements: `geneve_tlv_len()` in `proto_geneve.h:97-102`
    pub fn total_length(&self) -> usize {
        4 + 4 * self.length_words() as usize
    }
}

/// Geneve base protocol operations (overlay for version dispatch).
///
/// Reimplements: `xdp2_parse_geneve_base` in `proto_geneve.h:131-136`
///
/// Overlay node that reads the version field (upper 2 bits of byte 0)
/// for version-specific dispatch.
pub struct GeneveBaseOps;

impl ProtocolOps for GeneveBaseOps {
    const MIN_LEN: usize = 1;
    const NAME: &'static str = "Geneve base";
    const OVERLAY: bool = true;

    /// Return Geneve version (upper 2 bits, shifted to 0xC0/0x00).
    ///
    /// Reimplements: `geneve_base_proto()` in `proto_geneve.h:80-83`
    #[inline]
    fn next_proto(&self, hdr: &[u8]) -> Result<i32, ParseError> {
        if hdr.is_empty() {
            return Err(ParseError::Length);
        }
        Ok((hdr[0] & GENEVE_VERSION_MASK) as i32)
    }
}

/// Geneve version 0 protocol operations (encap with TLV options).
///
/// Reimplements: `xdp2_parse_geneve_v0` in `proto_geneve.h:139-150`
///
/// Variable-length header: 8 bytes base + 4*optlen bytes of options.
/// TLV options follow the fixed header. In C this is a `proto_tlvs_def`.
pub struct GeneveV0Ops;

impl ProtocolOps for GeneveV0Ops {
    const MIN_LEN: usize = 8; // sizeof(struct geneve_hdr)
    const NAME: &'static str = "Geneve version 0";
    const ENCAP: bool = true;

    /// Return variable header length: 8 + 4 * optlen.
    ///
    /// Reimplements: `geneve_len_v0()` in `proto_geneve.h:90-95`
    #[inline]
    fn header_len(&self, hdr: &[u8], _maxlen: usize) -> Result<usize, ParseError> {
        let geneve = GeneveHeader::ref_from_prefix(hdr)
            .map_err(|_| ParseError::Length)?
            .0;
        Ok(geneve.header_length())
    }

    /// Return protocol field (EtherType).
    ///
    /// Reimplements: `geneve_proto_v0()` in `proto_geneve.h:85-88`
    #[inline]
    fn next_proto(&self, hdr: &[u8]) -> Result<i32, ParseError> {
        let geneve = GeneveHeader::ref_from_prefix(hdr)
            .map_err(|_| ParseError::Length)?
            .0;
        Ok(geneve.protocol() as i32)
    }
}

/// TLV operations for Geneve option parsing.
///
/// Provides parameters for use with `ParseTlvsNode`.
pub struct GeneveTlvOps;

impl GeneveTlvOps {
    /// Minimum option size.
    pub const MIN_TLV_LEN: usize = 4; // sizeof(struct geneve_opt)

    /// Offset where TLV options begin (after Geneve header).
    ///
    /// Reimplements: `geneve_tlvs_start_offset()` in `proto_geneve.h:114-117`
    pub const START_OFFSET: usize = 8;

    /// Get TLV type (option_class).
    ///
    /// Reimplements: `geneve_tlv_type()` in `proto_geneve.h:104-107`
    pub fn tlv_type(hdr: &[u8]) -> Result<u16, ParseError> {
        let opt = GeneveOptHeader::ref_from_prefix(hdr)
            .map_err(|_| ParseError::Length)?
            .0;
        Ok(opt.option_class())
    }

    /// Get TLV length in bytes.
    ///
    /// Reimplements: `geneve_tlv_len()` in `proto_geneve.h:97-102`
    pub fn tlv_len(hdr: &[u8]) -> Result<usize, ParseError> {
        let opt = GeneveOptHeader::ref_from_prefix(hdr)
            .map_err(|_| ParseError::Length)?
            .0;
        Ok(opt.total_length())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_geneve_header(version: u8, optlen: u8, protocol: u16) -> [u8; 8] {
        let mut hdr = [0u8; 8];
        hdr[0] = (version << 6) | (optlen & 0x3F);
        let proto_bytes = protocol.to_be_bytes();
        hdr[2] = proto_bytes[0];
        hdr[3] = proto_bytes[1];
        hdr
    }

    #[test]
    fn geneve_base_version_0() {
        let hdr = make_geneve_header(0, 0, 0x6558);
        let ops = GeneveBaseOps;
        assert_eq!(ops.next_proto(&hdr).unwrap(), 0); // version 0 << 6 & mask = 0
    }

    #[test]
    fn geneve_base_is_overlay() {
        assert!(GeneveBaseOps::OVERLAY);
    }

    #[test]
    fn geneve_v0_fixed_no_options() {
        let hdr = make_geneve_header(0, 0, 0x6558);
        let ops = GeneveV0Ops;
        assert_eq!(ops.header_len(&hdr, 100).unwrap(), 8);
    }

    #[test]
    fn geneve_v0_with_options() {
        // optlen=2 → 8 + 2*4 = 16 bytes
        let hdr = make_geneve_header(0, 2, 0x6558);
        let ops = GeneveV0Ops;
        assert_eq!(ops.header_len(&hdr, 100).unwrap(), 16);
    }

    #[test]
    fn geneve_v0_next_proto_teb() {
        let hdr = make_geneve_header(0, 0, 0x6558);
        let ops = GeneveV0Ops;
        assert_eq!(ops.next_proto(&hdr).unwrap(), 0x6558);
    }

    #[test]
    fn geneve_v0_is_encap() {
        assert!(GeneveV0Ops::ENCAP);
    }

    #[test]
    fn geneve_vni() {
        let mut hdr = make_geneve_header(0, 0, 0x6558);
        hdr[4] = 0x12;
        hdr[5] = 0x34;
        hdr[6] = 0x56;
        let g = GeneveHeader::ref_from_prefix(&hdr).unwrap().0;
        assert_eq!(g.vni(), 0x123456);
    }

    #[test]
    fn geneve_opt_length() {
        let mut opt = [0u8; 4];
        opt[3] = 2; // length=2 → 4 + 2*4 = 12 bytes
        let o = GeneveOptHeader::ref_from_prefix(&opt).unwrap().0;
        assert_eq!(o.total_length(), 12);
    }
}
