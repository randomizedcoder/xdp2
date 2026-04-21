//! HTTP / Text-based Application protocol definitions.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// HTTP header (1 byte marker). Reimplements: `struct http_hdr` in `proto_http.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct HttpHeader {
    pub marker: u8,
}
pub struct HttpOps;
impl ProtocolOps for HttpOps {
    const MIN_LEN: usize = 1;
    const NAME: &'static str = "HTTP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// HTTP/2 header (9 bytes). Reimplements: `struct http2_hdr` in `proto_http2.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct Http2Header {
    pub length: [u8; 3],
    pub frame_type: u8,
    pub flags: u8,
    pub stream_id: [u8; 4],
}
pub struct Http2Ops;
impl ProtocolOps for Http2Ops {
    const MIN_LEN: usize = 9;
    const NAME: &'static str = "HTTP/2";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// RTSP header (1 byte marker). Reimplements: `struct rtsp_hdr` in `proto_rtsp.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct RtspHeader {
    pub marker: u8,
}
pub struct RtspOps;
impl ProtocolOps for RtspOps {
    const MIN_LEN: usize = 1;
    const NAME: &'static str = "RTSP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// FTP header (1 byte marker). Reimplements: `struct ftp_hdr` in `proto_ftp.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct FtpHeader {
    pub marker: u8,
}
pub struct FtpOps;
impl ProtocolOps for FtpOps {
    const MIN_LEN: usize = 1;
    const NAME: &'static str = "FTP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_is_leaf() {
        assert!(matches!(
            HttpOps.next_proto(&[0u8; 1]),
            Err(ParseError::UnknownProto)
        ));
    }
}
