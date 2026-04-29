//! Management protocol family.
//!
//! ## C/C++ Cross-Reference
//! Source directory: `src/include/xdp2/proto_defs/management/`

pub mod app_proto;
pub mod auth;
pub mod cfm;
pub mod database;
pub mod dhcp;
pub mod dhcp_variants;
pub mod dns;
pub mod http;
pub mod industrial;
pub mod link_mgmt;
pub mod media;
pub mod messaging;
pub mod misc_gold;
pub mod misc_leaf;
pub mod misc_silver;
pub mod mpls_mgmt;
pub mod oam_mgmt;
pub mod radius_variants;
pub mod redundancy;
pub mod routing;
pub mod rpc;
pub mod sdn;
pub mod snmp_variants;
pub mod telecom;
pub mod trill;

pub use app_proto::{
    ImapHeader, ImapOps, SipHeader, SipOps, SmtpHeader, SmtpOps, TelnetHeader, TelnetOps,
    TftpHeader, TftpOps,
};
pub use auth::{DiameterHeader, DiameterOps, RadiusHeader, RadiusOps, SnmpHeader, SnmpOps};
pub use cfm::{CfmHeader, CfmOps};
pub use dhcp::{DhcpHeader, DhcpOps, Dhcpv6Header, Dhcpv6Ops, NtpHeader, NtpOps};
pub use dhcp_variants::{DhcpOptionOps, Dhcpv6OptionOps};
pub use dns::{DnsHeader, DnsOps, LlmnrHeader, LlmnrOps, MdnsHeader, MdnsOps, NbnsHeader, NbnsOps};
pub use http::{
    FtpHeader, FtpOps, Http2Header, Http2Ops, HttpHeader, HttpOps, RtspHeader, RtspOps,
};
pub use industrial::{
    BacnetHeader, BacnetOps, CipHeader, CipOps, CoapHeader, CoapOps, Dnp3Header, Dnp3Ops,
    EnipHeader, EnipOps, IecGooseHeader, IecGooseOps, IecMmsHeader, IecMmsOps, IecSvHeader,
    IecSvOps, ModbusHeader, ModbusOps, ProfinetHeader, ProfinetOps,
};
pub use link_mgmt::{
    LacpHeader, LacpOps, LldpHeader, LldpOps, MacControlHeader, MacControlOps, MvrpHeader, MvrpOps,
    SlowHeader, SlowOps, StpHeader, StpOps,
};
pub use media::{
    CflowHeader, CflowOps, IpfixHeader, IpfixOps, NetflowV5Header, NetflowV5Ops, NetflowV9Header,
    NetflowV9Ops, PtpHeader, PtpOps,
};
pub use messaging::{
    AmqpHeader, AmqpOps, KafkaHeader, KafkaOps, MemcacheHeader, MemcacheOps, MqttHeader, MqttOps,
    RedisHeader, RedisOps, ZeromqHeader, ZeromqOps,
};
pub use misc_leaf::{
    BfdHeader, BfdOps, CdpHeader, CdpOps, FipHeader, FipOps, LldpMedHeader, LldpMedOps,
    LltdHeader, LltdOps, MgcpHeader, MgcpOps, MsdpHeader, MsdpOps, NcsiHeader, NcsiOps,
    OpcUaHeader, OpcUaOps, OwampHeader, OwampOps, PfcpHeader, PfcpOps, PptpHeader, PptpOps,
    SflowHeader, SflowOps, SkinnyHeader, SkinnyOps, StunHeader, StunOps, SyslogHeader, SyslogOps,
    TwampHeader, TwampOps, WolHeader, WolOps, ZigbeeApsHeader, ZigbeeApsOps, ZigbeeNwkHeader,
    ZigbeeNwkOps,
};
pub use mpls_mgmt::{LdpHeader, LdpOps, MplsOamHeader, MplsOamOps};
pub use redundancy::{
    CarpHeader, CarpOps, GlbpHeader, GlbpOps, HsrpHeader, HsrpOps, VrrpHeader, VrrpOps,
};
pub use routing::{
    BgpHeader, BgpOps, DiameterS6aHeader, DiameterS6aOps, EigrpHeader, EigrpOps, IsisHeader,
    IsisOps, OspfHeader, OspfOps, Ospfv3Header, Ospfv3Ops, RipHeader, RipOps, RipngHeader,
    RipngOps, Vrrpv3Header, Vrrpv3Ops,
};
pub use rpc::{
    LdapHeader, LdapOps, NfsHeader, NfsOps, OncRpcHeader, OncRpcOps, Smb2Header, Smb2Ops,
    SmbHeader, SmbOps,
};
pub use sdn::{HomePlugAvHeader, HomePlugAvOps, OpenflowHeader, OpenflowOps};
pub use oam_mgmt::{
    DcbxOps, ElmiOps, G8032Ops, Lldp8021abOps, LldpCdpOps, LldpExtDot1Ops, LldpExtDot3Ops,
    LmpOps, MarkerOps, MmrpOps, MplsEchoOps, MplsTpOps, MrpOps, MstpOps, OamLbmOps, OamLtmOps,
    PvstOps, RstpOps, Y1731Ops,
};
pub use telecom::{
    BssgpOps, H225Ops, M2paOps, M3uaOps, MegacoOps, Nas5gsOps, NasEpsOps, NgapOps, RanapOps,
    S1apOps, SccpOps, SuaOps,
};
pub use database::{CassandraOps, ElasticsearchOps, MongodbOps, MysqlOps, PostgresqlOps};
pub use misc_gold::{
    AvtpOps, BabelOps, BmpOps, CollectdOps, CopsOps, EtherTypeTsnOps, FcoeFipOps, GooseOps,
    Iec104Ops, MgcpNcsOps, MsdpSaOps, NntpOps, NtsOps, PcepOps, PcpOps, ProfinetDcpOps,
    RpkiRtrOps, SdpOps,
};
pub use radius_variants::{RadiusAcctOps, RadiusCoaOps};
pub use snmp_variants::{SflowV5Ops, Snmpv3Ops, SnmpTrapOps};
pub use misc_silver::{FcpOps, GvrpOps, IsupOps, PdcpOps};
pub use trill::{TrillHeader, TrillOps};
