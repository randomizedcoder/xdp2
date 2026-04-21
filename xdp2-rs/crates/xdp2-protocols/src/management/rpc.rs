//! RPC / File Services protocol definitions.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// ONC RPC header (24 bytes). Reimplements: `struct onc_rpc_hdr` in `proto_onc_rpc.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct OncRpcHeader {
    pub xid: [u8; 4],
    pub msg_type: [u8; 4],
    pub rpc_version: [u8; 4],
    pub program: [u8; 4],
    pub prog_version: [u8; 4],
    pub procedure: [u8; 4],
}
pub struct OncRpcOps;
impl ProtocolOps for OncRpcOps {
    const MIN_LEN: usize = 24;
    const NAME: &'static str = "ONC RPC";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// NFS header (4 bytes). Reimplements: `struct nfs_hdr` in `proto_nfs.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct NfsHeader {
    pub fragment: [u8; 4],
}
pub struct NfsOps;
impl ProtocolOps for NfsOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "NFS";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// LDAP header (2 bytes). Reimplements: `struct ldap_hdr` in `proto_ldap.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct LdapHeader {
    pub tag: u8,
    pub length: u8,
}
pub struct LdapOps;
impl ProtocolOps for LdapOps {
    const MIN_LEN: usize = 2;
    const NAME: &'static str = "LDAP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// SMB header (4 bytes). Reimplements: `struct smb_hdr` in `proto_smb.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct SmbHeader {
    pub protocol: [u8; 4],
}
pub struct SmbOps;
impl ProtocolOps for SmbOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "SMB";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// SMB2 header (4 bytes). Reimplements: `struct smb2_hdr` in `proto_smb2.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct Smb2Header {
    pub protocol: [u8; 4],
}
pub struct Smb2Ops;
impl ProtocolOps for Smb2Ops {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "SMB2";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn onc_rpc_is_leaf() {
        assert!(matches!(
            OncRpcOps.next_proto(&[0u8; 24]),
            Err(ParseError::UnknownProto)
        ));
    }
}
