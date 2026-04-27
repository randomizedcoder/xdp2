//! Serial Attached SCSI (SAS) and ATA FIS protocol definitions.
//! All SAS/ATA frames are leaf protocols.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// SSP Frame Header (24 bytes).
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct SspFrameHeader {
    pub frame_type: u8,
    pub hashed_dest_addr: [u8; 3],
    pub _r_a: u8,
    pub hashed_src_addr: [u8; 3],
    pub _r_b: [u8; 2],
    pub flags1: u8,
    pub flags2: u8,
    pub _r_e: [u8; 4],
    pub tag: [u8; 2],
    pub tptt: [u8; 2],
    pub data_offs: [u8; 4],
}

pub struct SspFrameOps;

impl ProtocolOps for SspFrameOps {
    const MIN_LEN: usize = 24;
    const NAME: &'static str = "SSP_Frame";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// SSP Command IU (28 bytes).
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct SspCommandHeader {
    pub lun: [u8; 8],
    pub _r_a: u8,
    pub efb_prio_attr: u8,
    pub _r_b: u8,
    pub add_cdb_len_flags: u8,
    pub cdb: [u8; 16],
}

pub struct SspCommandOps;

impl ProtocolOps for SspCommandOps {
    const MIN_LEN: usize = 28;
    const NAME: &'static str = "SSP_Command";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// ATA Host-to-Device FIS (Register FIS, 20 bytes).
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct AtaH2dFisHeader {
    pub fis_type: u8,
    pub flags: u8,
    pub command: u8,
    pub features: u8,
    pub lbal: u8,
    pub lbam: u8,
    pub lbah: u8,
    pub device: u8,
    pub lbal_exp: u8,
    pub lbam_exp: u8,
    pub lbah_exp: u8,
    pub features_exp: u8,
    pub sector_count: u8,
    pub sector_count_exp: u8,
    pub _r_a: u8,
    pub control: u8,
    pub _r_b: [u8; 4],
}

pub struct AtaH2dFisOps;

impl ProtocolOps for AtaH2dFisOps {
    const MIN_LEN: usize = 20;
    const NAME: &'static str = "ATA_H2D_FIS";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// ATA Device-to-Host FIS (20 bytes).
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct AtaD2hFisHeader {
    pub fis_type: u8,
    pub flags: u8,
    pub status: u8,
    pub error: u8,
    pub lbal: u8,
    pub lbam: u8,
    pub lbah: u8,
    pub device: u8,
    pub lbal_exp: u8,
    pub lbam_exp: u8,
    pub lbah_exp: u8,
    pub _r_a: u8,
    pub sector_count: u8,
    pub sector_count_exp: u8,
    pub _r_b: u8,
    pub _r_c: u8,
    pub _r_d: [u8; 4],
}

pub struct AtaD2hFisOps;

impl ProtocolOps for AtaD2hFisOps {
    const MIN_LEN: usize = 20;
    const NAME: &'static str = "ATA_D2H_FIS";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// SAS Identify Address Frame (32 bytes).
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct SasIdentifyHeader {
    pub frame_type_dev_type: u8,
    pub _un1: u8,
    pub initiator_bits: u8,
    pub target_bits: u8,
    pub _un4_11: [u8; 8],
    pub sas_addr: [u8; 8],
    pub phy_id: u8,
    pub _un21_27: [u8; 7],
}

pub struct SasIdentifyOps;

impl ProtocolOps for SasIdentifyOps {
    const MIN_LEN: usize = 28;
    const NAME: &'static str = "SAS_Identify";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sas_ata_all_are_leaves() {
        assert!(SspFrameOps.next_proto(&[0u8; 24]).is_err());
        assert!(SspCommandOps.next_proto(&[0u8; 28]).is_err());
        assert!(AtaH2dFisOps.next_proto(&[0u8; 20]).is_err());
        assert!(AtaD2hFisOps.next_proto(&[0u8; 20]).is_err());
        assert!(SasIdentifyOps.next_proto(&[0u8; 28]).is_err());
    }
}
