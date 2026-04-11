//! L2TP (Layer 2 Tunnelling Protocol) definitions.
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `L2tpBaseOps` | `proto_defs/transport/proto_l2tp.h:57-63` | `xdp2_parse_l2tp_base` |
//! | `L2tpBaseOps::next_proto` | `proto_l2tp.h:36-39` | `l2tp_proto_version()` |
//! | `L2tpV0BaseOps` | `proto_defs/transport/proto_l2tp_v0.h:106-111` | `xdp_parse_l2tp_v0_base` |
//! | `L2tpV0BaseOps::header_len` | `proto_l2tp_v0.h:80-83` | `l2tp_v0_base_len_check()` |
//! | `L2tpV0OffszOps` | `proto_l2tp_v0.h:113-117` | `xdp2_parse_l2tp_v0_offsz` |
//!
//! ## Behavioral Differences
//! - None. Byte-for-byte compatible with C implementation.

use xdp2_core::{ParseError, ProtocolOps};

/// IP protocol number for L2TP.
pub const IPPROTO_L2TP: u8 = 115;

/// L2TP flag bits (big-endian).
pub const L2TP_F_TYPE: u16 = 0x8000;
pub const L2TP_F_LENGTH: u16 = 0x4000;
pub const L2TP_F_NSNR: u16 = 0x0800;
pub const L2TP_F_OFFSZ: u16 = 0x0200;
pub const L2TP_F_PRIORITY: u16 = 0x0100;

/// L2TP base protocol operations (overlay + encap).
///
/// Reimplements: `xdp2_parse_l2tp_base` in `proto_l2tp.h:57-63`
///
/// Overlay node that reads the version from the flags/version field
/// (lower 4 bits of byte 1) for version dispatch (0, 2, or 3).
pub struct L2tpBaseOps;

impl ProtocolOps for L2tpBaseOps {
    const MIN_LEN: usize = 2;
    const NAME: &'static str = "L2TP base";
    const OVERLAY: bool = true;
    const ENCAP: bool = true;

    /// Return L2TP version (lower 4 bits of byte 1).
    ///
    /// Reimplements: `l2tp_proto_version()` in `proto_l2tp.h:36-39`
    fn next_proto(&self, hdr: &[u8]) -> Result<i32, ParseError> {
        if hdr.len() < 2 {
            return Err(ParseError::Length);
        }
        Ok((hdr[1] & 0x0F) as i32)
    }
}

/// L2TP v0 base protocol operations.
///
/// Reimplements: `xdp_parse_l2tp_v0_base` in `proto_l2tp_v0.h:106-111`
///
/// Variable-length header computed from flag-fields. Base size is 6 bytes
/// (2 flags + 4 tunnel/session), plus optional length (2) and Ns/Nr (4)
/// fields based on flags.
pub struct L2tpV0BaseOps;

impl L2tpV0BaseOps {
    /// Compute header length from flags.
    ///
    /// Reimplements: `l2tp_v0_base_len_from_flags()` in `proto_l2tp_v0.h:74-78`
    fn len_from_flags(flags: u16) -> usize {
        let mut len = 2 + 4; // flags(2) + tunnel_id(2) + session_id(2)
        if flags & L2TP_F_LENGTH != 0 {
            len += 2; // optional length field
        }
        if flags & L2TP_F_NSNR != 0 {
            len += 4; // optional Ns(2) + Nr(2)
        }
        len
    }
}

impl ProtocolOps for L2tpV0BaseOps {
    const MIN_LEN: usize = 2;
    const NAME: &'static str = "L2TP v0";

    /// Compute variable header length from flags.
    ///
    /// Reimplements: `l2tp_v0_base_len_check()` in `proto_l2tp_v0.h:80-83`
    fn header_len(&self, hdr: &[u8], _maxlen: usize) -> Result<usize, ParseError> {
        if hdr.len() < 2 {
            return Err(ParseError::Length);
        }
        let flags = u16::from_be_bytes([hdr[0], hdr[1]]);
        Ok(Self::len_from_flags(flags))
    }

    /// Return whether offset-size field is present.
    ///
    /// Reimplements: `l2tp_v0_base_proto_version()` in `proto_l2tp_v0.h:85-88`
    fn next_proto(&self, hdr: &[u8]) -> Result<i32, ParseError> {
        if hdr.len() < 2 {
            return Err(ParseError::Length);
        }
        let flags = u16::from_be_bytes([hdr[0], hdr[1]]);
        Ok(if flags & L2TP_F_OFFSZ != 0 { 1 } else { 0 })
    }
}

/// L2TP v0 offset-size field operations.
///
/// Reimplements: `xdp2_parse_l2tp_v0_offsz` in `proto_l2tp_v0.h:113-117`
///
/// 2-byte offset size + offset padding bytes. Total length = 2 + offset_size.
pub struct L2tpV0OffszOps;

impl ProtocolOps for L2tpV0OffszOps {
    const MIN_LEN: usize = 2;
    const NAME: &'static str = "L2TP offset-size field";

    /// Return offset-size field length: 2 + value.
    ///
    /// Reimplements: `l2tp_v0_offsz_len()` in `proto_l2tp_v0.h:90-93`
    fn header_len(&self, hdr: &[u8], _maxlen: usize) -> Result<usize, ParseError> {
        if hdr.len() < 2 {
            return Err(ParseError::Length);
        }
        let offset_size = u16::from_be_bytes([hdr[0], hdr[1]]) as usize;
        Ok(2 + offset_size)
    }

    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto) // Leaf node
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn l2tp_base_version() {
        // Version 2 (L2TPv2): byte[1] low nibble = 2
        let hdr = [0x00u8, 0x02];
        let ops = L2tpBaseOps;
        assert_eq!(ops.next_proto(&hdr).unwrap(), 2);
    }

    #[test]
    fn l2tp_base_is_overlay_encap() {
        assert!(L2tpBaseOps::OVERLAY);
        assert!(L2tpBaseOps::ENCAP);
    }

    #[test]
    fn l2tp_v0_base_minimal() {
        // No optional fields: just flags(2) + tunnel(2) + session(2) = 6
        let hdr = [0x00u8, 0x02, 0, 0, 0, 0];
        let ops = L2tpV0BaseOps;
        assert_eq!(ops.header_len(&hdr, 100).unwrap(), 6);
    }

    #[test]
    fn l2tp_v0_base_with_length() {
        // L2TP_F_LENGTH set: flags(2) + tunnel(2) + session(2) + length(2) = 8
        let flags = L2TP_F_LENGTH.to_be_bytes();
        let hdr = [flags[0], flags[1] | 0x02, 0, 0, 0, 0, 0, 0];
        let ops = L2tpV0BaseOps;
        assert_eq!(ops.header_len(&hdr, 100).unwrap(), 8);
    }

    #[test]
    fn l2tp_v0_base_with_nsnr() {
        // L2TP_F_NSNR set: flags(2) + tunnel(2) + session(2) + Ns/Nr(4) = 10
        let flags = L2TP_F_NSNR.to_be_bytes();
        let hdr = [flags[0], flags[1] | 0x02, 0, 0, 0, 0, 0, 0, 0, 0];
        let ops = L2tpV0BaseOps;
        assert_eq!(ops.header_len(&hdr, 100).unwrap(), 10);
    }

    #[test]
    fn l2tp_v0_offsz_present() {
        let flags = L2TP_F_OFFSZ.to_be_bytes();
        let hdr = [flags[0], flags[1]];
        let ops = L2tpV0BaseOps;
        assert_eq!(ops.next_proto(&hdr).unwrap(), 1);
    }

    #[test]
    fn l2tp_v0_offsz_absent() {
        let hdr = [0x00u8, 0x02];
        let ops = L2tpV0BaseOps;
        assert_eq!(ops.next_proto(&hdr).unwrap(), 0);
    }

    #[test]
    fn l2tp_v0_offsz_length() {
        // offset_size = 4, total = 2 + 4 = 6
        let mut hdr = [0u8; 6];
        hdr[0..2].copy_from_slice(&4u16.to_be_bytes());
        let ops = L2tpV0OffszOps;
        assert_eq!(ops.header_len(&hdr, 100).unwrap(), 6);
    }
}
