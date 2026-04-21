//! Application Layer protocol definitions.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// SIP header (1 byte marker). Reimplements: `struct sip_hdr` in `proto_sip.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct SipHeader {
    pub marker: u8,
}
pub struct SipOps;
impl ProtocolOps for SipOps {
    const MIN_LEN: usize = 1;
    const NAME: &'static str = "SIP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// SMTP header (1 byte marker). Reimplements: `struct smtp_hdr` in `proto_smtp.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct SmtpHeader {
    pub marker: u8,
}
pub struct SmtpOps;
impl ProtocolOps for SmtpOps {
    const MIN_LEN: usize = 1;
    const NAME: &'static str = "SMTP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// IMAP header (1 byte marker). Reimplements: `struct imap_hdr` in `proto_imap.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct ImapHeader {
    pub marker: u8,
}
pub struct ImapOps;
impl ProtocolOps for ImapOps {
    const MIN_LEN: usize = 1;
    const NAME: &'static str = "IMAP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// Telnet header (1 byte marker). Reimplements: `struct telnet_hdr` in `proto_telnet.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct TelnetHeader {
    pub marker: u8,
}
pub struct TelnetOps;
impl ProtocolOps for TelnetOps {
    const MIN_LEN: usize = 1;
    const NAME: &'static str = "Telnet";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// TFTP header (4 bytes). Reimplements: `struct tftp_hdr` in `proto_tftp.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct TftpHeader {
    pub opcode: [u8; 2],
    pub block_or_error: [u8; 2],
}
pub struct TftpOps;
impl ProtocolOps for TftpOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "TFTP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sip_is_leaf() {
        assert!(matches!(
            SipOps.next_proto(&[0u8; 1]),
            Err(ParseError::UnknownProto)
        ));
    }
}
