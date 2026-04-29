//! Application-layer protocol leaf definitions.

use xdp2_core::{ParseError, ProtocolOps};

/// HTTP/2 protocol operations (leaf, MIN_LEN = 9).
pub struct Http2Ops;
impl ProtocolOps for Http2Ops {
    const MIN_LEN: usize = 9;
    const NAME: &'static str = "HTTP2";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// RTMP protocol operations (leaf, MIN_LEN = 12).
pub struct RtmpOps;
impl ProtocolOps for RtmpOps {
    const MIN_LEN: usize = 12;
    const NAME: &'static str = "RTMP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// RTCP Sender Report protocol operations (leaf, MIN_LEN = 24).
pub struct RtcpSrOps;
impl ProtocolOps for RtcpSrOps {
    const MIN_LEN: usize = 24;
    const NAME: &'static str = "RTCP_SR";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// RTP H.264 protocol operations (leaf, MIN_LEN = 1).
pub struct RtpH264Ops;
impl ProtocolOps for RtpH264Ops {
    const MIN_LEN: usize = 1;
    const NAME: &'static str = "RTP_H264";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// RTP H.265 protocol operations (leaf, MIN_LEN = 2).
pub struct RtpH265Ops;
impl ProtocolOps for RtpH265Ops {
    const MIN_LEN: usize = 2;
    const NAME: &'static str = "RTP_H265";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// RTP MPEG protocol operations (leaf, MIN_LEN = 4).
pub struct RtpMpegOps;
impl ProtocolOps for RtpMpegOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "RTP_MPEG";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// RTP Opus protocol operations (leaf, MIN_LEN = 1).
pub struct RtpOpusOps;
impl ProtocolOps for RtpOpusOps {
    const MIN_LEN: usize = 1;
    const NAME: &'static str = "RTP_OPUS";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// WebSocket protocol operations (leaf, MIN_LEN = 2).
pub struct WebSocketOps;
impl ProtocolOps for WebSocketOps {
    const MIN_LEN: usize = 2;
    const NAME: &'static str = "WebSocket";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// XMPP protocol operations (leaf, MIN_LEN = 1).
pub struct XmppOps;
impl ProtocolOps for XmppOps {
    const MIN_LEN: usize = 1;
    const NAME: &'static str = "XMPP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// IRC protocol operations (leaf, MIN_LEN = 1).
pub struct IrcOps;
impl ProtocolOps for IrcOps {
    const MIN_LEN: usize = 1;
    const NAME: &'static str = "IRC";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// WHOIS protocol operations (leaf, MIN_LEN = 1).
pub struct WhoisOps;
impl ProtocolOps for WhoisOps {
    const MIN_LEN: usize = 1;
    const NAME: &'static str = "WHOIS";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// gRPC protocol operations (leaf, MIN_LEN = 5).
pub struct GrpcOps;
impl ProtocolOps for GrpcOps {
    const MIN_LEN: usize = 5;
    const NAME: &'static str = "gRPC";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// gNMI protocol operations (leaf, MIN_LEN = 1).
pub struct GnmiOps;
impl ProtocolOps for GnmiOps {
    const MIN_LEN: usize = 1;
    const NAME: &'static str = "gNMI";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// gNOI protocol operations (leaf, MIN_LEN = 1).
pub struct GnoiOps;
impl ProtocolOps for GnoiOps {
    const MIN_LEN: usize = 1;
    const NAME: &'static str = "gNOI";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// DNS over TCP protocol operations (leaf, MIN_LEN = 12).
pub struct DnsTcpOps;
impl ProtocolOps for DnsTcpOps {
    const MIN_LEN: usize = 12;
    const NAME: &'static str = "DNS_TCP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// DNS over TLS protocol operations (leaf, MIN_LEN = 12).
pub struct DotOps;
impl ProtocolOps for DotOps {
    const MIN_LEN: usize = 12;
    const NAME: &'static str = "DoT";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// POP3 protocol operations (leaf, MIN_LEN = 1).
pub struct Pop3Ops;
impl ProtocolOps for Pop3Ops {
    const MIN_LEN: usize = 1;
    const NAME: &'static str = "POP3";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// TACACS+ protocol operations (leaf, MIN_LEN = 12).
pub struct TacacsOps;
impl ProtocolOps for TacacsOps {
    const MIN_LEN: usize = 12;
    const NAME: &'static str = "TACACS";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// SOCKS protocol operations (leaf, MIN_LEN = 3).
pub struct SocksOps;
impl ProtocolOps for SocksOps {
    const MIN_LEN: usize = 3;
    const NAME: &'static str = "SOCKS";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// CIFS protocol operations (leaf, MIN_LEN = 4).
pub struct CifsOps;
impl ProtocolOps for CifsOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "CIFS";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}
