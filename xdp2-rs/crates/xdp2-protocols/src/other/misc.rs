//! Miscellaneous protocols (all leaf nodes).
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `ErfHeader` | `proto_defs/other/proto_erf.h` | `struct erf_hdr` |
//! | `ErfOps` | `proto_erf.h` | `xdp2_parse_erf` |
//! | `MpegTsHeader` | `proto_defs/other/proto_mpeg_ts.h` | `struct mpeg_ts_hdr` |
//! | `MpegTsOps` | `proto_mpeg_ts.h` | `xdp2_parse_mpeg_ts` |
//! | `SrtHeader` | `proto_defs/other/proto_srt.h` | `struct srt_hdr` |
//! | `SrtOps` | `proto_srt.h` | `xdp2_parse_srt` |
//! | `TplinkSmarthomeHeader` | `proto_defs/other/proto_tplink_smarthome.h` | `struct tplink_smarthome_hdr` |
//! | `TplinkSmarthomeOps` | `proto_tplink_smarthome.h` | `xdp2_parse_tplink_smarthome` |
//!
//! ## Behavioral Differences
//! - None. All are leaf nodes.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

// ---------------------------------------------------------------------------
// ERF (Endace Record Format)
// ---------------------------------------------------------------------------

/// ERF header (16 bytes).
///
/// Reimplements: `struct erf_hdr` in `proto_erf.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct ErfHeader {
    pub timestamp: [u8; 8],
    pub record_type: u8,
    pub flags: u8,
    pub rlen: [u8; 2],
    pub lctr: [u8; 2],
    pub wlen: [u8; 2],
}

impl ErfHeader {
    pub fn rlen(&self) -> u16 {
        u16::from_be_bytes(self.rlen)
    }
    pub fn wlen(&self) -> u16 {
        u16::from_be_bytes(self.wlen)
    }
}

/// ERF protocol operations (leaf).
pub struct ErfOps;

impl ProtocolOps for ErfOps {
    const MIN_LEN: usize = 16;
    const NAME: &'static str = "ERF";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

// ---------------------------------------------------------------------------
// MPEG-TS (MPEG Transport Stream)
// ---------------------------------------------------------------------------

/// MPEG-TS header (4 bytes).
///
/// Reimplements: `struct mpeg_ts_hdr` in `proto_mpeg_ts.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct MpegTsHeader {
    pub sync_tei_pusi_pri_pid: [u8; 3],
    pub tsc_afc_cc: u8,
}

/// MPEG-TS protocol operations (leaf).
pub struct MpegTsOps;

impl ProtocolOps for MpegTsOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "MPEG-TS";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

// ---------------------------------------------------------------------------
// SRT (Secure Reliable Transport)
// ---------------------------------------------------------------------------

/// SRT header (12 bytes).
///
/// Reimplements: `struct srt_hdr` in `proto_srt.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct SrtHeader {
    pub flags: [u8; 4],
    pub timestamp: [u8; 4],
    pub dst_socket_id: [u8; 4],
}

impl SrtHeader {
    pub fn timestamp(&self) -> u32 {
        u32::from_be_bytes(self.timestamp)
    }
    pub fn dst_socket_id(&self) -> u32 {
        u32::from_be_bytes(self.dst_socket_id)
    }
}

/// SRT protocol operations (leaf).
pub struct SrtOps;

impl ProtocolOps for SrtOps {
    const MIN_LEN: usize = 12;
    const NAME: &'static str = "SRT";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

// ---------------------------------------------------------------------------
// TP-Link SmartHome
// ---------------------------------------------------------------------------

/// TP-Link SmartHome header (4 bytes).
///
/// Reimplements: `struct tplink_smarthome_hdr` in `proto_tplink_smarthome.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct TplinkSmarthomeHeader {
    pub length: [u8; 4],
}

impl TplinkSmarthomeHeader {
    pub fn length(&self) -> u32 {
        u32::from_be_bytes(self.length)
    }
}

/// TP-Link SmartHome protocol operations (leaf).
pub struct TplinkSmarthomeOps;

impl ProtocolOps for TplinkSmarthomeOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "TP-Link SmartHome";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn erf_is_leaf() {
        assert!(matches!(ErfOps.next_proto(&[0u8; 16]), Err(ParseError::UnknownProto)));
    }

    #[test]
    fn mpeg_ts_is_leaf() {
        assert!(matches!(MpegTsOps.next_proto(&[0u8; 4]), Err(ParseError::UnknownProto)));
    }

    #[test]
    fn srt_is_leaf() {
        assert!(matches!(SrtOps.next_proto(&[0u8; 12]), Err(ParseError::UnknownProto)));
    }

    #[test]
    fn tplink_is_leaf() {
        assert!(matches!(
            TplinkSmarthomeOps.next_proto(&[0u8; 4]),
            Err(ParseError::UnknownProto)
        ));
    }
}
