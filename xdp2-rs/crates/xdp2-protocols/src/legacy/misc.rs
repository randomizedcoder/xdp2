//! Legacy sub-protocol definitions (leaf nodes).
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `Ieee802154Header` | `proto_defs/legacy/proto_ieee802154.h` | `struct ieee802154_hdr_fc` |
//! | `MctpHeader` | `proto_defs/legacy/proto_mctp.h` | `struct mctp_hdr` |
//! | `AtmHeader` | `proto_defs/legacy/proto_atm.h` | `struct atm_cell_hdr` |
//! | `PhonetHeader` | `proto_defs/legacy/proto_phonet.h` | `struct phonethdr` |
//! | `AppletalkHeader` | `proto_defs/legacy/proto_appletalk.h` | `struct atalk_ddp_hdr` |
//! | `ProtobufHeader` | `proto_defs/legacy/proto_protobuf.h` | (variable-length TLV) |
//! | `DsaHeader` | `proto_defs/legacy/proto_dsa.h` | `struct dsa_tag` |
//! | `X25Header` | `proto_defs/legacy/proto_x25.h` | `struct x25_hdr` |
//!
//! ## Behavioral Differences
//! - None. All are leaf nodes.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

// ---------------------------------------------------------------------------
// IEEE 802.15.4
// ---------------------------------------------------------------------------

/// IEEE 802.15.4 frame control header (4 bytes).
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct Ieee802154Header {
    pub frame_control: [u8; 2],
    pub seq_no: u8,
    pub reserved: u8,
}

pub struct Ieee802154Ops;

impl ProtocolOps for Ieee802154Ops {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "IEEE 802.15.4";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

// ---------------------------------------------------------------------------
// MCTP (Management Component Transport Protocol)
// ---------------------------------------------------------------------------

/// MCTP header (4 bytes).
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct MctpHeader {
    pub ver: u8,
    pub dest: u8,
    pub src: u8,
    pub flags_seq_tag: u8,
}

pub struct MctpOps;

impl ProtocolOps for MctpOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "MCTP";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

// ---------------------------------------------------------------------------
// ATM
// ---------------------------------------------------------------------------

/// ATM cell header (5 bytes).
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct AtmHeader {
    pub gfc_vpi: u8,
    pub vpi_vci1: u8,
    pub vci2: u8,
    pub vci3_pt_clp: u8,
    pub hec: u8,
}

pub struct AtmOps;

impl ProtocolOps for AtmOps {
    const MIN_LEN: usize = 5;
    const NAME: &'static str = "ATM";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

// ---------------------------------------------------------------------------
// Phonet
// ---------------------------------------------------------------------------

/// Phonet header (7 bytes).
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct PhonetHeader {
    pub pn_rdev: u8,
    pub pn_sdev: u8,
    pub pn_res: u8,
    pub pn_length: [u8; 2],
    pub pn_robj: u8,
    pub pn_sobj: u8,
}

pub struct PhonetOps;

impl ProtocolOps for PhonetOps {
    const MIN_LEN: usize = 7;
    const NAME: &'static str = "Phonet";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

// ---------------------------------------------------------------------------
// AppleTalk (DDP)
// ---------------------------------------------------------------------------

/// AppleTalk DDP header (13 bytes).
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct AppletalkHeader {
    pub len_hop: [u8; 2],
    pub dstnet: [u8; 2],
    pub srcnet: [u8; 2],
    pub dstnode: u8,
    pub srcnode: u8,
    pub dstsocket: u8,
    pub srcsocket: u8,
    pub ddp_type: u8,
    pub reserved: [u8; 2],
}

pub struct AppletalkOps;

impl ProtocolOps for AppletalkOps {
    const MIN_LEN: usize = 13;
    const NAME: &'static str = "AppleTalk";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

// ---------------------------------------------------------------------------
// Protobuf
// ---------------------------------------------------------------------------

/// Protobuf marker header (1 byte).
///
/// Variable-length TLV with varint encoding in the C implementation.
/// We treat it as a leaf boundary marker.
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct ProtobufHeader {
    pub marker: u8,
}

pub struct ProtobufOps;

impl ProtocolOps for ProtobufOps {
    const MIN_LEN: usize = 1;
    const NAME: &'static str = "Protobuf";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

// ---------------------------------------------------------------------------
// DSA (Distributed Switch Architecture)
// ---------------------------------------------------------------------------

/// DSA tag header (4 bytes).
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct DsaHeader {
    pub tag: [u8; 4],
}

pub struct DsaOps;

impl ProtocolOps for DsaOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "DSA";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

// ---------------------------------------------------------------------------
// X.25
// ---------------------------------------------------------------------------

/// X.25 header (3 bytes).
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct X25Header {
    pub gfi_lcn: [u8; 2],
    pub pkt_type: u8,
}

pub struct X25Ops;

impl ProtocolOps for X25Ops {
    const MIN_LEN: usize = 3;
    const NAME: &'static str = "X.25";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ieee802154_is_leaf() {
        assert!(matches!(
            Ieee802154Ops.next_proto(&[0u8; 4]),
            Err(ParseError::UnknownProto)
        ));
    }

    #[test]
    fn mctp_is_leaf() {
        assert!(matches!(
            MctpOps.next_proto(&[0u8; 4]),
            Err(ParseError::UnknownProto)
        ));
    }

    #[test]
    fn atm_is_leaf() {
        assert!(matches!(
            AtmOps.next_proto(&[0u8; 5]),
            Err(ParseError::UnknownProto)
        ));
    }

    #[test]
    fn phonet_is_leaf() {
        assert!(matches!(
            PhonetOps.next_proto(&[0u8; 7]),
            Err(ParseError::UnknownProto)
        ));
    }

    #[test]
    fn appletalk_is_leaf() {
        assert!(matches!(
            AppletalkOps.next_proto(&[0u8; 13]),
            Err(ParseError::UnknownProto)
        ));
    }

    #[test]
    fn protobuf_is_leaf() {
        assert!(matches!(
            ProtobufOps.next_proto(&[0u8; 1]),
            Err(ParseError::UnknownProto)
        ));
    }

    #[test]
    fn dsa_is_leaf() {
        assert!(matches!(
            DsaOps.next_proto(&[0u8; 4]),
            Err(ParseError::UnknownProto)
        ));
    }

    #[test]
    fn x25_is_leaf() {
        assert!(matches!(
            X25Ops.next_proto(&[0u8; 3]),
            Err(ParseError::UnknownProto)
        ));
    }
}
