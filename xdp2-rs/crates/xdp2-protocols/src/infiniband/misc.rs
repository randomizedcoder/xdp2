//! InfiniBand sub-protocol definitions (leaf nodes).
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `IbGrhHeader` | `proto_defs/infiniband/proto_ib_grh.h` | `struct ib_grh` |
//! | `IbBthHeader` | `proto_defs/infiniband/proto_ib_bth.h` | `struct ib_bth` |
//! | `IbRethHeader` | `proto_defs/infiniband/proto_ib_reth.h` | `struct ib_reth` |
//! | `IbAethHeader` | `proto_defs/infiniband/proto_ib_aeth.h` | `struct ib_aeth` |
//! | `IbDethHeader` | `proto_defs/infiniband/proto_ib_deth.h` | `struct ib_deth` |
//! | `IbImmdtHeader` | `proto_defs/infiniband/proto_ib_immdt.h` | `struct ib_immdt` |
//! | `IbAtomicethHeader` | `proto_defs/infiniband/proto_ib_atomiceth.h` | `struct ib_atomiceth` |
//! | `IbMadHeader` | `proto_defs/infiniband/proto_ib_mad.h` | `struct ib_mad_hdr` |
//!
//! ## Behavioral Differences
//! - None. All are leaf nodes.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

// ---------------------------------------------------------------------------
// IB GRH (Global Route Header) — 40 bytes, IPv6-like
// ---------------------------------------------------------------------------

#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct IbGrhHeader {
    pub ver_tc_fl: [u8; 4],
    pub paylen: [u8; 2],
    pub next_hdr: u8,
    pub hop_limit: u8,
    pub sgid: [u8; 16],
    pub dgid: [u8; 16],
}

pub struct IbGrhOps;

impl ProtocolOps for IbGrhOps {
    const MIN_LEN: usize = 40;
    const NAME: &'static str = "IB GRH";

    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

// ---------------------------------------------------------------------------
// IB BTH (Base Transport Header) — 12 bytes
// ---------------------------------------------------------------------------

#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct IbBthHeader {
    pub opcode: u8,
    pub se_m_pad_tver: u8,
    pub pkey: [u8; 2],
    pub reserved_destqp: [u8; 4],
    pub ack_psn: [u8; 4],
}

impl IbBthHeader {
    pub fn pkey(&self) -> u16 {
        u16::from_be_bytes(self.pkey)
    }
    /// Destination QP (lower 24 bits).
    pub fn dest_qp(&self) -> u32 {
        u32::from_be_bytes(self.reserved_destqp) & 0x00FFFFFF
    }
}

pub struct IbBthOps;

impl ProtocolOps for IbBthOps {
    const MIN_LEN: usize = 12;
    const NAME: &'static str = "IB BTH";

    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

// ---------------------------------------------------------------------------
// IB RETH (RDMA Extended Transport Header) — 16 bytes
// ---------------------------------------------------------------------------

#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct IbRethHeader {
    pub va: [u8; 8],
    pub rkey: [u8; 4],
    pub dmalen: [u8; 4],
}

pub struct IbRethOps;

impl ProtocolOps for IbRethOps {
    const MIN_LEN: usize = 16;
    const NAME: &'static str = "IB RETH";

    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

// ---------------------------------------------------------------------------
// IB AETH (ACK Extended Transport Header) — 4 bytes
// ---------------------------------------------------------------------------

#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct IbAethHeader {
    pub syndrome_msn: [u8; 4],
}

pub struct IbAethOps;

impl ProtocolOps for IbAethOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "IB AETH";

    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

// ---------------------------------------------------------------------------
// IB DETH (Datagram Extended Transport Header) — 8 bytes
// ---------------------------------------------------------------------------

#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct IbDethHeader {
    pub qkey: [u8; 4],
    pub reserved_srcqp: [u8; 4],
}

impl IbDethHeader {
    pub fn qkey(&self) -> u32 {
        u32::from_be_bytes(self.qkey)
    }
    pub fn src_qp(&self) -> u32 {
        u32::from_be_bytes(self.reserved_srcqp) & 0x00FFFFFF
    }
}

pub struct IbDethOps;

impl ProtocolOps for IbDethOps {
    const MIN_LEN: usize = 8;
    const NAME: &'static str = "IB DETH";

    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

// ---------------------------------------------------------------------------
// IB ImmDt (Immediate Data) — 4 bytes
// ---------------------------------------------------------------------------

#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct IbImmdtHeader {
    pub imm_data: [u8; 4],
}

impl IbImmdtHeader {
    pub fn imm_data(&self) -> u32 {
        u32::from_be_bytes(self.imm_data)
    }
}

pub struct IbImmdtOps;

impl ProtocolOps for IbImmdtOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "IB ImmDt";

    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

// ---------------------------------------------------------------------------
// IB AtomicETH — 28 bytes
// ---------------------------------------------------------------------------

#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct IbAtomicethHeader {
    pub va: [u8; 8],
    pub rkey: [u8; 4],
    pub swap_or_add: [u8; 8],
    pub compare: [u8; 8],
}

pub struct IbAtomicethOps;

impl ProtocolOps for IbAtomicethOps {
    const MIN_LEN: usize = 28;
    const NAME: &'static str = "IB AtomicETH";

    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

// ---------------------------------------------------------------------------
// IB MAD (Management Datagram) — 24 bytes
// ---------------------------------------------------------------------------

#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct IbMadHeader {
    pub base_version: u8,
    pub mgmt_class: u8,
    pub class_version: u8,
    pub method: u8,
    pub status: [u8; 2],
    pub class_specific: [u8; 2],
    pub tid: [u8; 8],
    pub attr_id: [u8; 2],
    pub resv: [u8; 2],
    pub attr_mod: [u8; 4],
}

pub struct IbMadOps;

impl ProtocolOps for IbMadOps {
    const MIN_LEN: usize = 24;
    const NAME: &'static str = "IB MAD";

    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ib_grh_is_leaf() {
        assert!(matches!(IbGrhOps.next_proto(&[0u8; 40]), Err(ParseError::UnknownProto)));
    }

    #[test]
    fn ib_bth_is_leaf() {
        assert!(matches!(IbBthOps.next_proto(&[0u8; 12]), Err(ParseError::UnknownProto)));
    }

    #[test]
    fn ib_reth_is_leaf() {
        assert!(matches!(IbRethOps.next_proto(&[0u8; 16]), Err(ParseError::UnknownProto)));
    }

    #[test]
    fn ib_aeth_is_leaf() {
        assert!(matches!(IbAethOps.next_proto(&[0u8; 4]), Err(ParseError::UnknownProto)));
    }

    #[test]
    fn ib_deth_is_leaf() {
        assert!(matches!(IbDethOps.next_proto(&[0u8; 8]), Err(ParseError::UnknownProto)));
    }

    #[test]
    fn ib_immdt_is_leaf() {
        assert!(matches!(IbImmdtOps.next_proto(&[0u8; 4]), Err(ParseError::UnknownProto)));
    }

    #[test]
    fn ib_atomiceth_is_leaf() {
        assert!(matches!(IbAtomicethOps.next_proto(&[0u8; 28]), Err(ParseError::UnknownProto)));
    }

    #[test]
    fn ib_mad_is_leaf() {
        assert!(matches!(IbMadOps.next_proto(&[0u8; 24]), Err(ParseError::UnknownProto)));
    }
}
