//! Management protocol family.
//!
//! ## C/C++ Cross-Reference
//! Source directory: `src/include/xdp2/proto_defs/management/`

pub mod misc;
pub mod trill;

pub use trill::{TrillHeader, TrillOps};
pub use misc::{
    AmqpHeader, AmqpOps, BacnetHeader, BacnetOps, BfdHeader, BfdOps, BgpHeader, BgpOps,
    CarpHeader, CarpOps, CdpHeader, CdpOps, CfmHeader, CfmOps, CipHeader, CipOps, CoapHeader,
    CoapOps, DhcpHeader, DhcpOps, Dhcpv6Header, Dhcpv6Ops, DiameterHeader, DiameterOps,
    DnsHeader, DnsOps, Dnp3Header, Dnp3Ops, EigrpHeader, EigrpOps, EnipHeader, EnipOps,
    FipHeader, FipOps, FtpHeader, FtpOps, GlbpHeader, GlbpOps, HomePlugAvHeader, HomePlugAvOps,
    HsrpHeader, HsrpOps, Http2Header, Http2Ops, HttpHeader, HttpOps, IecGooseHeader, IecGooseOps,
    IecMmsHeader, IecMmsOps, IecSvHeader, IecSvOps, ImapHeader, ImapOps, IpfixHeader, IpfixOps,
    IsisHeader, IsisOps, KafkaHeader, KafkaOps, LacpHeader, LacpOps, LdapHeader, LdapOps,
    LdpHeader, LdpOps, LldpHeader, LldpOps, LlmnrHeader, LlmnrOps, LltdHeader, LltdOps,
    MacControlHeader, MacControlOps, MdnsHeader, MdnsOps, MemcacheHeader, MemcacheOps,
    MgcpHeader, MgcpOps, ModbusHeader, ModbusOps, MplsOamHeader, MplsOamOps, MqttHeader,
    MqttOps, MvrpHeader, MvrpOps, NbnsHeader, NbnsOps, NcsiHeader, NcsiOps, NetflowV5Header,
    NetflowV5Ops, NetflowV9Header, NetflowV9Ops, NfsHeader, NfsOps, NtpHeader, NtpOps,
    OncRpcHeader, OncRpcOps, OpcUaHeader, OpcUaOps, OpenflowHeader, OpenflowOps, OspfHeader,
    OspfOps, ProfinetHeader, ProfinetOps, PtpHeader, PtpOps, RadiusHeader, RadiusOps,
    RedisHeader, RedisOps, RipHeader, RipOps, RtspHeader, RtspOps, SipHeader, SipOps,
    SkinnyHeader, SkinnyOps, SlowHeader, SlowOps, Smb2Header, Smb2Ops, SmbHeader, SmbOps,
    SmtpHeader, SmtpOps, SnmpHeader, SnmpOps, StpHeader, StpOps, StunHeader, StunOps,
    SyslogHeader, SyslogOps, TelnetHeader, TelnetOps, TftpHeader, TftpOps, VrrpHeader, VrrpOps,
    WolHeader, WolOps, ZeromqHeader, ZeromqOps, ZigbeeApsHeader, ZigbeeApsOps, ZigbeeNwkHeader,
    ZigbeeNwkOps,
};
