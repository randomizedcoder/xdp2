//! Other/miscellaneous protocol family.
//!
//! ## C/C++ Cross-Reference
//! Source directory: `src/include/xdp2/proto_defs/other/`

pub mod app_protocols;
pub mod chargen;
pub mod industrial;
pub mod misc;
pub mod misc_bronze;
pub mod quic_variants;

pub use app_protocols::{
    CifsOps, DnsTcpOps, DotOps, GnmiOps, GnoiOps, GrpcOps, Http2Ops, IrcOps, Pop3Ops, RtcpSrOps,
    RtmpOps, RtpH264Ops, RtpH265Ops, RtpMpegOps, RtpOpusOps, SocksOps, TacacsOps, WebSocketOps,
    WhoisOps, XmppOps,
};
pub use chargen::{ChargenOps, DaytimeOps, DiscardOps, EchoOps, TimeOps};
pub use industrial::{DoipOps, EnipOps, SomeIpOps};
pub use misc::{
    ErfHeader, ErfOps, MpegTsHeader, MpegTsOps, SrtHeader, SrtOps, TplinkSmarthomeHeader,
    TplinkSmarthomeOps,
};
pub use misc_bronze::{
    CmpOps, DohOps, Dtls13Ops, FcoeInitOps, GreWccpv2Ops, H245Ops, H323Ops, Higig2Ops, Http3Ops,
    Nfsv4Ops, OcspResponseOps, RGooseOps, RdmaCmOps, S7commOps, T38Ops, TcapOps, UdsOps, XcpOps,
};
pub use quic_variants::{QuicInitialOps, QuicRetryOps};
