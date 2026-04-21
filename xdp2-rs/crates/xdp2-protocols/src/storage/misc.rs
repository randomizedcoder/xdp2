//! Storage sub-protocol definitions (leaf nodes).
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `ScsiHeader` | `proto_defs/storage/proto_scsi.h` | `struct fcp_cmnd` |
//! | `ScsiOps` | `proto_scsi.h` | `xdp2_parse_scsi` |
//! | `IscsiHeader` | `proto_defs/storage/proto_iscsi.h` | `struct iscsi_hdr` |
//! | `IscsiOps` | `proto_iscsi.h` | `xdp2_parse_iscsi` |
//! | `IserHeader` | `proto_defs/storage/proto_iser.h` | `struct iser_ctrl` |
//! | `IserOps` | `proto_iser.h` | `xdp2_parse_iser` |
//! | `AoeHeader` | `proto_defs/storage/proto_aoe.h` | `struct aoe_hdr` |
//! | `AoeOps` | `proto_aoe.h` | `xdp2_parse_aoe` |
//! | `EthercatHeader` | `proto_defs/storage/proto_ethercat.h` | `struct ethercat_hdr` |
//! | `EthercatOps` | `proto_ethercat.h` | `xdp2_parse_ethercat` |
//! | `NvmeHeader` | `proto_defs/storage/proto_nvme.h` | `struct nvme_common_command` |
//! | `NvmeOps` | `proto_nvme.h` | `xdp2_parse_nvme` |
//!
//! ## Behavioral Differences
//! - None. All are leaf nodes.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

// ---------------------------------------------------------------------------
// SCSI (over Fibre Channel)
// ---------------------------------------------------------------------------

/// SCSI FCP command header (32 bytes minimum).
///
/// Reimplements: `struct fcp_cmnd` in `proto_scsi.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct ScsiHeader {
    pub lun: [u8; 8],
    pub crn: u8,
    pub task_attr: u8,
    pub task_mgmt: u8,
    pub add_len: u8,
    pub cdb: [u8; 16],
    pub dl: [u8; 4],
}

pub struct ScsiOps;

impl ProtocolOps for ScsiOps {
    const MIN_LEN: usize = 32;
    const NAME: &'static str = "SCSI";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

// ---------------------------------------------------------------------------
// iSCSI
// ---------------------------------------------------------------------------

/// iSCSI BHS header (48 bytes).
///
/// Reimplements: `struct iscsi_hdr` in `proto_iscsi.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct IscsiHeader {
    pub opcode: u8,
    pub flags: u8,
    pub spec1: [u8; 2],
    pub ahs_len: u8,
    pub data_len: [u8; 3],
    pub lun_or_opaque: [u8; 8],
    pub itt: [u8; 4],
    pub ttt_or_opaque: [u8; 4],
    pub statsn: [u8; 4],
    pub exp_statsn: [u8; 4],
    pub max_statsn: [u8; 4],
    pub misc: [u8; 12],
}

pub struct IscsiOps;

impl ProtocolOps for IscsiOps {
    const MIN_LEN: usize = 48;
    const NAME: &'static str = "iSCSI";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

// ---------------------------------------------------------------------------
// iSER (iSCSI Extensions for RDMA)
// ---------------------------------------------------------------------------

/// iSER control header (28 bytes).
///
/// Reimplements: `struct iser_ctrl` in `proto_iser.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct IserHeader {
    pub flags: u8,
    pub rsvd: [u8; 3],
    pub write_stag: [u8; 4],
    pub write_va: [u8; 8],
    pub read_stag: [u8; 4],
    pub read_va: [u8; 8],
}

pub struct IserOps;

impl ProtocolOps for IserOps {
    const MIN_LEN: usize = 28;
    const NAME: &'static str = "iSER";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

// ---------------------------------------------------------------------------
// AoE (ATA over Ethernet)
// ---------------------------------------------------------------------------

/// AoE header (8 bytes).
///
/// Reimplements: `struct aoe_hdr` in `proto_aoe.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct AoeHeader {
    pub ver_flags: u8,
    pub error: u8,
    pub major: [u8; 2],
    pub minor: u8,
    pub command: u8,
    pub tag: [u8; 4],
}

pub struct AoeOps;

impl ProtocolOps for AoeOps {
    const MIN_LEN: usize = 10;
    const NAME: &'static str = "AoE";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

// ---------------------------------------------------------------------------
// EtherCAT
// ---------------------------------------------------------------------------

/// EtherCAT header (2 bytes).
///
/// Reimplements: `struct ethercat_hdr` in `proto_ethercat.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct EthercatHeader {
    pub len_type: [u8; 2],
}

pub struct EthercatOps;

impl ProtocolOps for EthercatOps {
    const MIN_LEN: usize = 2;
    const NAME: &'static str = "EtherCAT";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

// ---------------------------------------------------------------------------
// NVMe
// ---------------------------------------------------------------------------

/// NVMe common command header (64 bytes).
///
/// Reimplements: `struct nvme_common_command` in `proto_nvme.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct NvmeHeader {
    pub opcode: u8,
    pub flags: u8,
    pub command_id: [u8; 2],
    pub nsid: [u8; 4],
    pub cdw2: [u8; 4],
    pub cdw3: [u8; 4],
    pub metadata: [u8; 8],
    pub prp1: [u8; 8],
    pub prp2: [u8; 8],
    pub cdw10_15: [u8; 24],
}

pub struct NvmeOps;

impl ProtocolOps for NvmeOps {
    const MIN_LEN: usize = 64;
    const NAME: &'static str = "NVMe";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scsi_is_leaf() {
        assert!(matches!(
            ScsiOps.next_proto(&[0u8; 32]),
            Err(ParseError::UnknownProto)
        ));
    }

    #[test]
    fn iscsi_is_leaf() {
        assert!(matches!(
            IscsiOps.next_proto(&[0u8; 48]),
            Err(ParseError::UnknownProto)
        ));
    }

    #[test]
    fn iser_is_leaf() {
        assert!(matches!(
            IserOps.next_proto(&[0u8; 28]),
            Err(ParseError::UnknownProto)
        ));
    }

    #[test]
    fn aoe_is_leaf() {
        assert!(matches!(
            AoeOps.next_proto(&[0u8; 10]),
            Err(ParseError::UnknownProto)
        ));
    }

    #[test]
    fn ethercat_is_leaf() {
        assert!(matches!(
            EthercatOps.next_proto(&[0u8; 2]),
            Err(ParseError::UnknownProto)
        ));
    }

    #[test]
    fn nvme_is_leaf() {
        assert!(matches!(
            NvmeOps.next_proto(&[0u8; 64]),
            Err(ParseError::UnknownProto)
        ));
    }
}
