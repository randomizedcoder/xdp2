//! Fibre Channel (FC) frame header protocol definition.
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `FcHeader` | `proto_defs/storage/proto_fc.h` | `struct fc_frame_header` |
//! | `FcOps` | `proto_fc.h:74-78` | `xdp2_parse_fc` |
//! | `FcOps::next_proto` | `proto_fc.h:60-63` | `fc_frame_type()` |
//!
//! ## Behavioral Differences
//! - None. Byte-for-byte compatible with C implementation.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// FC type constants.
pub const FC_TYPE_BLS: i32 = 0x00;
pub const FC_TYPE_ELS: i32 = 0x01;
pub const FC_TYPE_FCP: i32 = 0x08;
pub const FC_TYPE_CT: i32 = 0x20;

/// Fibre Channel frame header (24 bytes).
///
/// Reimplements: `struct fc_frame_header` in `proto_fc.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct FcHeader {
    pub fh_r_ctl: u8,
    pub fh_d_id: [u8; 3],
    pub fh_cs_ctl: u8,
    pub fh_s_id: [u8; 3],
    pub fh_type: u8,
    pub fh_f_ctl: [u8; 3],
    pub fh_seq_id: u8,
    pub fh_df_ctl: u8,
    pub fh_seq_cnt: [u8; 2],
    pub fh_ox_id: [u8; 2],
    pub fh_rx_id: [u8; 2],
    pub fh_parm_offset: [u8; 4],
}

impl FcHeader {
    pub fn d_id(&self) -> u32 {
        ((self.fh_d_id[0] as u32) << 16)
            | ((self.fh_d_id[1] as u32) << 8)
            | (self.fh_d_id[2] as u32)
    }
    pub fn s_id(&self) -> u32 {
        ((self.fh_s_id[0] as u32) << 16)
            | ((self.fh_s_id[1] as u32) << 8)
            | (self.fh_s_id[2] as u32)
    }
    pub fn seq_cnt(&self) -> u16 {
        u16::from_be_bytes(self.fh_seq_cnt)
    }
    pub fn ox_id(&self) -> u16 {
        u16::from_be_bytes(self.fh_ox_id)
    }
    pub fn rx_id(&self) -> u16 {
        u16::from_be_bytes(self.fh_rx_id)
    }
}

/// Fibre Channel protocol operations.
///
/// Reimplements: `xdp2_parse_fc` in `proto_fc.h:74-78`
///
/// Dispatches on `fh_type` field.
pub struct FcOps;

impl ProtocolOps for FcOps {
    const MIN_LEN: usize = 24;
    const NAME: &'static str = "FC";

    /// Return FC type for dispatch.
    ///
    /// Reimplements: `fc_frame_type()` in `proto_fc.h:60-63`
    #[inline]
    fn next_proto(&self, hdr: &[u8]) -> Result<i32, ParseError> {
        let fc = FcHeader::ref_from_prefix(hdr)
            .map_err(|_| ParseError::Length)?
            .0;
        Ok(fc.fh_type as i32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_fc(fh_type: u8) -> [u8; 24] {
        let mut hdr = [0u8; 24];
        hdr[8] = fh_type;
        hdr
    }

    #[test]
    fn fc_dispatch_fcp() {
        let ops = FcOps;
        assert_eq!(ops.next_proto(&make_fc(0x08)).unwrap(), FC_TYPE_FCP);
    }

    #[test]
    fn fc_dispatch_els() {
        let ops = FcOps;
        assert_eq!(ops.next_proto(&make_fc(0x01)).unwrap(), FC_TYPE_ELS);
    }

    #[test]
    fn fc_dispatch_ct() {
        let ops = FcOps;
        assert_eq!(ops.next_proto(&make_fc(0x20)).unwrap(), FC_TYPE_CT);
    }
}
