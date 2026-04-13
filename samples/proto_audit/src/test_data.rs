//! Shared test data constants for cross-module tests.
//!
//! Centralizes embedded protocol definitions used by roundtrip and
//! cross-source tests. Each constant is a realistic representation
//! of how each source defines a protocol.

// ── Kernel struct definitions ──

pub const KERNEL_IPHDR: &str = r#"
struct iphdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
    __u8    ihl:4, version:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
    __u8    version:4, ihl:4;
#endif
    __u8    tos;
    __be16  tot_len;
    __be16  id;
    __be16  frag_off;
    __u8    ttl;
    __u8    protocol;
    __sum16 check;
    __be32  saddr;
    __be32  daddr;
};
"#;

pub const KERNEL_ETHHDR: &str = r#"
struct ethhdr {
    unsigned char   h_dest[ETH_ALEN];
    unsigned char   h_source[ETH_ALEN];
    __be16          h_proto;
} __attribute__((packed));
"#;

pub const KERNEL_UDPHDR: &str = r#"
struct udphdr {
    __be16  source;
    __be16  dest;
    __be16  len;
    __sum16 check;
};
"#;

pub const KERNEL_TCPHDR: &str = r#"
struct tcphdr {
    __be16  source;
    __be16  dest;
    __be32  seq;
    __be32  ack_seq;
#if defined(__LITTLE_ENDIAN_BITFIELD)
    __u16   res1:4,
        doff:4,
        fin:1,
        syn:1,
        rst:1,
        psh:1,
        ack:1,
        urg:1,
        ece:1,
        cwr:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
    __u16   doff:4,
        res1:4,
        cwr:1,
        ece:1,
        urg:1,
        ack:1,
        psh:1,
        rst:1,
        syn:1,
        fin:1;
#endif
    __be16  window;
    __sum16 check;
    __be16  urg_ptr;
};
"#;

pub const KERNEL_ARPHDR: &str = r#"
struct arphdr {
	__be16		ar_hrd;		/* format of hardware address	*/
	__be16		ar_pro;		/* format of protocol address	*/
	unsigned char	ar_hln;		/* length of hardware address	*/
	unsigned char	ar_pln;		/* length of protocol address	*/
	__be16		ar_op;		/* ARP opcode (command)		*/

#if 0
	unsigned char		ar_sha[ETH_ALEN];
	unsigned char		ar_sip[4];
	unsigned char		ar_tha[ETH_ALEN];
	unsigned char		ar_tip[4];
#endif

};
"#;

pub const KERNEL_VLANHDR: &str = r#"
struct vlan_hdr {
    __be16  h_vlan_TCI;
    __be16  h_vlan_encapsulated_proto;
};
"#;

pub const KERNEL_ICMPHDR: &str = r#"
struct icmphdr {
    __u8    type;
    __u8    code;
    __sum16 checksum;
    __be16  id;
    __be16  sequence;
};
"#;

// ── Scapy JSON definitions ──

pub const SCAPY_IP_JSON: &str = r#"{
  "name": "IP", "module": "scapy.layers.inet", "min_bytes": 20,
  "fields": [
    {"name": "version", "field_class": "BitField", "size_bits": 4},
    {"name": "ihl", "field_class": "BitField", "size_bits": 4},
    {"name": "tos", "field_class": "XByteField", "size_bits": 8},
    {"name": "len", "field_class": "ShortField", "size_bits": 16},
    {"name": "id", "field_class": "ShortField", "size_bits": 16},
    {"name": "flags", "field_class": "FlagsField", "size_bits": 3},
    {"name": "frag", "field_class": "BitField", "size_bits": 13},
    {"name": "ttl", "field_class": "ByteField", "size_bits": 8},
    {"name": "proto", "field_class": "ByteEnumField", "size_bits": 8},
    {"name": "chksum", "field_class": "XShortField", "size_bits": 16},
    {"name": "src", "field_class": "SourceIPField", "size_bits": 32},
    {"name": "dst", "field_class": "DestIPField", "size_bits": 32}
  ]
}"#;

pub const SCAPY_TCP_JSON: &str = r#"{
  "name": "TCP", "module": "scapy.layers.inet", "min_bytes": 20,
  "fields": [
    {"name": "sport", "field_class": "ShortEnumField", "size_bits": 16},
    {"name": "dport", "field_class": "ShortEnumField", "size_bits": 16},
    {"name": "seq", "field_class": "IntField", "size_bits": 32},
    {"name": "ack", "field_class": "IntField", "size_bits": 32},
    {"name": "dataofs", "field_class": "BitField", "size_bits": 4},
    {"name": "reserved", "field_class": "BitField", "size_bits": 3},
    {"name": "flags", "field_class": "FlagsField", "size_bits": 9},
    {"name": "window", "field_class": "ShortField", "size_bits": 16},
    {"name": "chksum", "field_class": "XShortField", "size_bits": 16},
    {"name": "urgptr", "field_class": "ShortField", "size_bits": 16}
  ]
}"#;

pub const SCAPY_UDP_JSON: &str = r#"{
  "name": "UDP", "module": "scapy.layers.inet", "min_bytes": 8,
  "fields": [
    {"name": "sport", "field_class": "ShortEnumField", "size_bits": 16},
    {"name": "dport", "field_class": "ShortEnumField", "size_bits": 16},
    {"name": "len", "field_class": "ShortField", "size_bits": 16},
    {"name": "chksum", "field_class": "XShortField", "size_bits": 16}
  ]
}"#;

pub const SCAPY_ETHER_JSON: &str = r#"{
  "name": "Ether", "module": "scapy.layers.l2", "min_bytes": 14,
  "fields": [
    {"name": "dst", "field_class": "DestMACField", "size_bits": 48},
    {"name": "src", "field_class": "SourceMACField", "size_bits": 48},
    {"name": "type", "field_class": "XShortEnumField", "size_bits": 16}
  ]
}"#;

pub const SCAPY_ARP_JSON: &str = r#"{
  "name": "ARP", "module": "scapy.layers.l2", "min_bytes": 28,
  "fields": [
    {"name": "hwtype", "field_class": "XShortEnumField", "size_bits": 16},
    {"name": "ptype", "field_class": "XShortEnumField", "size_bits": 16},
    {"name": "hwlen", "field_class": "ByteField", "size_bits": 8},
    {"name": "plen", "field_class": "ByteField", "size_bits": 8},
    {"name": "op", "field_class": "ShortEnumField", "size_bits": 16},
    {"name": "hwsrc", "field_class": "SourceMACField", "size_bits": 48},
    {"name": "psrc", "field_class": "SourceIPField", "size_bits": 32},
    {"name": "hwdst", "field_class": "DestMACField", "size_bits": 48},
    {"name": "pdst", "field_class": "DestIPField", "size_bits": 32}
  ]
}"#;

// ── tshark PDML definitions ──

pub const TSHARK_ETH_IP_PDML: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<?xml-stylesheet type="text/xsl" href="pdml2html.xsl"?>
<pdml version="0" creator="wireshark/4.2.0">
<packet>
  <proto name="eth" showname="Ethernet II" pos="0" size="14">
    <field name="eth.dst" showname="Destination" pos="0" size="6" value="ffffffffffff" show="ff:ff:ff:ff:ff:ff"/>
    <field name="eth.src" showname="Source" pos="6" size="6" value="001122334455" show="00:11:22:33:44:55"/>
    <field name="eth.type" showname="Type" pos="12" size="2" value="0800" show="0x0800"/>
  </proto>
  <proto name="ip" showname="Internet Protocol Version 4" pos="14" size="20">
    <field name="ip.version" showname="Version" pos="14" size="1" value="45" show="4"/>
    <field name="ip.hdr_len" showname="Header Length" pos="14" size="1" value="45" show="20"/>
    <field name="ip.dsfield" showname="Differentiated Services" pos="15" size="1" value="00" show="0x00"/>
    <field name="ip.len" showname="Total Length" pos="16" size="2" value="003c" show="60"/>
    <field name="ip.id" showname="Identification" pos="18" size="2" value="1234" show="0x1234"/>
    <field name="ip.flags" showname="Flags" pos="20" size="1" value="40" show="0x40"/>
    <field name="ip.frag_offset" showname="Fragment Offset" pos="20" size="2" value="4000" show="0"/>
    <field name="ip.ttl" showname="Time to Live" pos="22" size="1" value="40" show="64"/>
    <field name="ip.proto" showname="Protocol" pos="23" size="1" value="06" show="6"/>
    <field name="ip.checksum" showname="Header Checksum" pos="24" size="2" value="0000" show="0x0000"/>
    <field name="ip.src" showname="Source Address" pos="26" size="4" value="c0a80001" show="192.168.0.1"/>
    <field name="ip.dst" showname="Destination Address" pos="30" size="4" value="c0a80002" show="192.168.0.2"/>
  </proto>
</packet>
</pdml>"#;

pub const TSHARK_UDP_PDML: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<pdml version="0" creator="wireshark/4.2.0">
<packet>
  <proto name="udp" showname="User Datagram Protocol" pos="34" size="8">
    <field name="udp.srcport" showname="Source Port" pos="34" size="2" value="d903" show="55555"/>
    <field name="udp.dstport" showname="Destination Port" pos="36" size="2" value="0035" show="53"/>
    <field name="udp.length" showname="Length" pos="38" size="2" value="002e" show="46"/>
    <field name="udp.checksum" showname="Checksum" pos="40" size="2" value="1234" show="0x1234"/>
    <field name="udp.checksum.status" showname="Checksum Status" pos="40" size="0" value="" show="2"/>
    <field name="udp.payload" showname="Payload" pos="42" size="25" value="abcd" show=""/>
  </proto>
</packet>
</pdml>"#;

// ── Etherparse Rust struct definitions ──

pub const ETHERPARSE_ETHERNET2_HEADER: &str = r#"
pub struct Ethernet2Header {
    pub source: [u8; 6],
    pub destination: [u8; 6],
    pub ether_type: EtherType,
}
"#;

pub const ETHERPARSE_UDP_HEADER: &str = r#"
pub struct UdpHeader {
    pub source_port: u16,
    pub destination_port: u16,
    pub length: u16,
    pub checksum: u16,
}
"#;

pub const ETHERPARSE_IPV4_HEADER: &str = r#"
pub struct Ipv4Header {
    pub dscp: IpDscp,
    pub ecn: IpEcn,
    pub total_len: u16,
    pub identification: u16,
    pub dont_fragment: bool,
    pub more_fragments: bool,
    pub fragment_offset: IpFragOffset,
    pub time_to_live: u8,
    pub protocol: IpNumber,
    pub header_checksum: u16,
    pub source: [u8; 4],
    pub destination: [u8; 4],
    pub options: Ipv4Options,
}
"#;

pub const ETHERPARSE_TCP_HEADER: &str = r#"
pub struct TcpHeader {
    pub source_port: u16,
    pub destination_port: u16,
    pub sequence_number: u32,
    pub acknowledgment_number: u32,
    pub ns: bool,
    pub fin: bool,
    pub syn: bool,
    pub rst: bool,
    pub psh: bool,
    pub ack: bool,
    pub urg: bool,
    pub ece: bool,
    pub cwr: bool,
    pub window_size: u16,
    pub checksum: u16,
    pub urgent_pointer: u16,
    pub options: TcpOptions,
}
"#;

pub const ETHERPARSE_IPV6_HEADER: &str = r#"
pub struct Ipv6Header {
    pub traffic_class: u8,
    pub flow_label: Ipv6FlowLabel,
    pub payload_length: u16,
    pub next_header: IpNumber,
    pub hop_limit: u8,
    pub source: [u8; 16],
    pub destination: [u8; 16],
}
"#;

// ── libpcap C struct definitions ──

pub const LIBPCAP_SLL_HEADER: &str = r#"
#define SLL_ADDRLEN 8

struct sll_header {
    uint16_t sll_pkttype;
    uint16_t sll_hatype;
    uint16_t sll_halen;
    uint8_t  sll_addr[SLL_ADDRLEN];
    uint16_t sll_protocol;
};
"#;

pub const LIBPCAP_VLAN_TAG: &str = r#"
struct vlan_tag {
    uint16_t vlan_tci;
    uint16_t vlan_tpid;
};
"#;

// ── Proto-audit overlay structs (etherparse) ──

pub const ETHERPARSE_GRE_HEADER: &str = r#"
pub struct GreHeader {
    pub checksum_present: bool,
    pub reserved0: bool,
    pub key_present: bool,
    pub sequence_present: bool,
    pub reserved1: Bits9,
    pub version: Bits3,
    pub protocol_type: u16,
}
"#;

pub const ETHERPARSE_SCTP_HEADER: &str = r#"
pub struct SctpHeader {
    pub source_port: u16,
    pub destination_port: u16,
    pub verification_tag: u32,
    pub checksum: u32,
}
"#;

pub const ETHERPARSE_ESP_HEADER: &str = r#"
pub struct EspHeader {
    pub spi: u32,
    pub seq_number: u32,
}
"#;

pub const ETHERPARSE_AH_HEADER: &str = r#"
pub struct AhHeader {
    pub next_header: u8,
    pub payload_len: u8,
    pub reserved: u16,
    pub spi: u32,
    pub seq_number: u32,
}
"#;

pub const ETHERPARSE_DNS_HEADER: &str = r#"
pub struct DnsHeader {
    pub id: u16,
    pub flags: u16,
    pub qd_count: u16,
    pub an_count: u16,
    pub ns_count: u16,
    pub ar_count: u16,
}
"#;

pub const ETHERPARSE_VXLAN_HEADER: &str = r#"
pub struct VxlanHeader {
    pub reserved_flags0: Bits4,
    pub vni_valid: bool,
    pub reserved_flags1: Bits3,
    pub reserved1: [u8; 3],
    pub vni: [u8; 3],
    pub reserved2: u8,
}
"#;

// ── Proto-audit overlay structs (libpcap) ──

pub const LIBPCAP_GRE_HEADER: &str = r#"
struct gre_header {
    uint16_t gre_checksum_present:1;
    uint16_t gre_reserved0:1;
    uint16_t gre_key_present:1;
    uint16_t gre_sequence_present:1;
    uint16_t gre_reserved1:9;
    uint16_t gre_version:3;
    uint16_t gre_protocol_type;
};
"#;

pub const LIBPCAP_ESP_HEADER: &str = r#"
struct esp_header {
    uint32_t esp_spi;
    uint32_t esp_seq;
};
"#;

pub const LIBPCAP_DNS_HEADER: &str = r#"
struct dns_header {
    uint16_t dns_id;
    uint16_t dns_flags;
    uint16_t dns_qd_count;
    uint16_t dns_an_count;
    uint16_t dns_ns_count;
    uint16_t dns_ar_count;
};
"#;

// ── OMI (Open Markets Initiative) trading protocols ──

/// SoupBinTCP packet header — transport for ITCH/OUCH.
/// 3 bytes: uint16 PacketLength (big-endian) + char PacketType.
pub const OMI_SOUPBIN_PACKET_HEADER: &str = r#"
#pragma pack(push, 1)
typedef struct {
    uint16_t PacketLength;
    char PacketType;
} PacketHeaderT;
#pragma pack(pop)
"#;

/// ITCH v5.0 NonCrossTrade message — the canonical worked example.
/// 38 bytes total, Nasdaq = big-endian.
pub const OMI_ITCH_NON_CROSS_TRADE: &str = r#"
#pragma pack(push, 1)
typedef struct {
    uint16_t StockLocate;
    uint16_t TrackingNumber;
    char Timestamp;
    uint64_t OrderReferenceNumber;
    char BuySellIndicator;
    uint32_t Shares;
    char Stock[8];
    uint32_t Price;
    uint64_t MatchNumber;
} NonCrossTradeMessageT;
#pragma pack(pop)
"#;

/// CME SBE MDP3 MessageHeader — little-endian by spec.
/// 8 bytes: four uint16_t fields.
pub const OMI_SBE_MESSAGE_HEADER: &str = r#"
#pragma pack(push, 1)
typedef struct {
    uint16_t BlockLength;
    uint16_t TemplateId;
    uint16_t SchemaId;
    uint16_t Version;
} MessageHeaderT;
#pragma pack(pop)
"#;
