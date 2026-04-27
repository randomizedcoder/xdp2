//! NVMe over RDMA (NVMe/RDMA) connection manager private data.
//! All CM messages are leaf protocols.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// NVMe/RDMA CM Request (32 bytes).
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct NvmeRdmaCmReqHeader {
    pub recfmt: [u8; 2],
    pub qid: [u8; 2],
    pub hrqsize: [u8; 2],
    pub hsqsize: [u8; 2],
    pub cntlid: [u8; 2],
    pub rsvd: [u8; 22],
}

pub struct NvmeRdmaCmReqOps;

impl ProtocolOps for NvmeRdmaCmReqOps {
    const MIN_LEN: usize = 32;
    const NAME: &'static str = "NVMe_RDMA_CM_REQ";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// NVMe/RDMA CM Reply (32 bytes).
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct NvmeRdmaCmRepHeader {
    pub recfmt: [u8; 2],
    pub crqsize: [u8; 2],
    pub rsvd: [u8; 28],
}

pub struct NvmeRdmaCmRepOps;

impl ProtocolOps for NvmeRdmaCmRepOps {
    const MIN_LEN: usize = 32;
    const NAME: &'static str = "NVMe_RDMA_CM_REP";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// NVMe/RDMA CM Reject (4 bytes).
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct NvmeRdmaCmRejHeader {
    pub recfmt: [u8; 2],
    pub sts: [u8; 2],
}

pub struct NvmeRdmaCmRejOps;

impl ProtocolOps for NvmeRdmaCmRejOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "NVMe_RDMA_CM_REJ";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nvme_rdma_all_are_leaves() {
        assert!(NvmeRdmaCmReqOps.next_proto(&[0u8; 32]).is_err());
        assert!(NvmeRdmaCmRepOps.next_proto(&[0u8; 32]).is_err());
        assert!(NvmeRdmaCmRejOps.next_proto(&[0u8; 4]).is_err());
    }
}
