//! tshark PDML XML extractor.
//!
//! Parses Protocol Description Markup Language (PDML) XML output from
//! `tshark -T pdml`. Each `<proto>` element contains `<field>` elements
//! with explicit position (`pos`) and size (`size`) attributes.
//!
//! Usage:
//!   tshark -r capture.pcap -T pdml -c 1 | proto-audit parse-pdml --proto ip

use anyhow::{Context, Result};
use roxmltree::Document;
use std::path::Path;
use std::process::Command;

use crate::ir::{Endian, FieldDef, FieldType, ProtocolDef, SourceInfo};
use crate::type_mapping::{self, TsharkMappings};

/// A field extracted from PDML XML.
#[derive(Debug, Clone)]
pub struct PdmlField {
    /// tshark filter name (e.g., "ip.version")
    pub name: String,
    /// Human-readable name (e.g., "Version")
    pub show_name: String,
    /// Byte position in packet
    pub pos: u32,
    /// Size in bytes
    pub size: u32,
    /// Raw hex value
    pub value: String,
    /// Display value
    pub show: String,
}

/// A protocol extracted from PDML XML.
#[derive(Debug, Clone)]
pub struct PdmlProtocol {
    /// tshark dissector name (e.g., "ip")
    pub name: String,
    /// Human-readable name (e.g., "Internet Protocol Version 4")
    pub show_name: String,
    /// Fields in this protocol layer
    pub fields: Vec<PdmlField>,
    /// Byte position in packet
    pub pos: u32,
    /// Size in bytes
    pub size: u32,
}

/// Run tshark and capture PDML output for a pcap file.
///
/// `pcap_path` is the path to the capture file.
/// `tshark_bin` is the tshark binary (default: "tshark").
/// `count` is the max number of packets to decode.
pub fn run_tshark(
    pcap_path: &Path,
    tshark_bin: &str,
    count: u32,
) -> Result<String> {
    run_tshark_with_hints(pcap_path, tshark_bin, count, &[])
}

/// Run tshark with optional decode-as hints.
///
/// `decode_as` entries are tshark `-d` arguments, e.g. `"udp.port==5004,rtp"`.
/// Multiple hints are passed as separate `-d` flags.
pub fn run_tshark_with_hints(
    pcap_path: &Path,
    tshark_bin: &str,
    count: u32,
    decode_as: &[&str],
) -> Result<String> {
    let mut cmd = Command::new(tshark_bin);
    cmd.args([
        "-r",
        &pcap_path.to_string_lossy(),
        "-T",
        "pdml",
        "-c",
        &count.to_string(),
    ]);
    for hint in decode_as {
        cmd.args(["-d", hint]);
    }
    let output = cmd
        .output()
        .with_context(|| format!("running tshark on {}", pcap_path.display()))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("tshark failed: {}", stderr.trim());
    }

    String::from_utf8(output.stdout).context("tshark output is not valid UTF-8")
}

/// Look up tshark decode-as hints for a protocol.
///
/// Some protocols need explicit `-d` hints because tshark can't detect them
/// heuristically from synthetic PCAP content (e.g., RTP on UDP/5004).
pub fn decode_as_hints(proto: &str) -> Vec<&'static str> {
    match proto {
        // UDP-based protocols that need port-based decode-as
        "RTP" => vec!["udp.port==5004,rtp"],
        "RTCP" => vec!["udp.port==5005,rtcp"],
        "LISP" => vec!["udp.port==4341,lisp"],
        "MGCP" => vec!["udp.port==2427,mgcp"],
        "SRT" => vec!["udp.port==1935,srt"],
        "HSRP" => vec!["udp.port==1985,hsrp"],
        "GLBP" => vec!["udp.port==3222,glbp"],
        "CARP" | "VRRP" => vec!["ip.proto==112,vrrp"],
        "Teredo" => vec!["udp.port==3544,teredo"],
        "MPLS_OAM" => vec!["udp.port==3503,mpls-echo"],
        "CAPWAP" => vec!["udp.port==5247,capwap-control"],
        "LWAPP" => vec!["udp.port==12222,lwapp"],
        "TZSP" => vec!["udp.port==37008,tzsp"],
        "GUE" => vec!["udp.port==6080,gue"],
        "TPLINK_SMARTHOME" => vec!["udp.port==9999,tplink-smarthome"],
        // TCP-based protocols that need port-based decode-as
        "TACACS" => vec!["tcp.port==49,tacplus"],
        "ZeroMQ" => vec!["tcp.port==5555,zmtp"],
        "NVMe" => vec!["tcp.port==4420,nvme-tcp"],
        "DNP3" => vec!["tcp.port==20000,dnp3"],
        "AMQP" => vec!["tcp.port==5672,amqp"],
        "ENIP" => vec!["tcp.port==44818,enip"],
        "FTP" => vec!["tcp.port==21,ftp"],
        "SMTP" => vec!["tcp.port==25,smtp"],
        "Telnet" => vec!["tcp.port==23,telnet"],
        "NFS" => vec!["tcp.port==2049,nfs"],
        "STT" => vec!["tcp.port==7471,stt"],
        "CIP" => vec!["tcp.port==44818,enip"],
        _ => vec![],
    }
}

/// Extract proto elements from a node, recursively finding nested protos
/// (e.g., IPv6 extension headers nested inside `<proto name="ipv6">`).
fn extract_protos_recursive(parent: &roxmltree::Node, protos: &mut Vec<PdmlProtocol>) {
    for proto_node in parent.children().filter(|n| n.has_tag_name("proto")) {
        let name = proto_node
            .attribute("name")
            .unwrap_or("")
            .to_string();
        let show_name = proto_node
            .attribute("showname")
            .unwrap_or("")
            .to_string();
        let pos: u32 = proto_node
            .attribute("pos")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let size: u32 = proto_node
            .attribute("size")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        let mut fields = Vec::new();
        for field_node in proto_node.children().filter(|n| n.has_tag_name("field")) {
            let field_name = field_node
                .attribute("name")
                .unwrap_or("")
                .to_string();
            // Skip unnamed fields and tree-structure fields
            if field_name.is_empty() || field_name == "_ws.expert" {
                continue;
            }

            fields.push(PdmlField {
                name: field_name,
                show_name: field_node
                    .attribute("showname")
                    .unwrap_or("")
                    .to_string(),
                pos: field_node
                    .attribute("pos")
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0),
                size: field_node
                    .attribute("size")
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0),
                value: field_node
                    .attribute("value")
                    .unwrap_or("")
                    .to_string(),
                show: field_node
                    .attribute("show")
                    .unwrap_or("")
                    .to_string(),
            });
        }

        protos.push(PdmlProtocol {
            name,
            show_name,
            fields,
            pos,
            size,
        });

        // Recurse into nested protos (e.g., IPv6 extension headers)
        extract_protos_recursive(&proto_node, protos);
    }
}

/// Parse PDML XML and extract all protocol layers.
pub fn parse_pdml(xml: &str) -> Result<Vec<Vec<PdmlProtocol>>> {
    let doc = Document::parse(xml).context("parsing PDML XML")?;
    let mut packets = Vec::new();

    for packet_node in doc
        .root()
        .children()
        .filter(|n| n.is_element())
        .flat_map(|n| n.children())
        .filter(|n| n.has_tag_name("packet"))
    {
        let mut protos = Vec::new();

        extract_protos_recursive(&packet_node, &mut protos);

        packets.push(protos);
    }

    Ok(packets)
}

/// Extract a single protocol layer from PDML, identified by dissector name.
///
/// If multiple packets contain the protocol, fields from the first occurrence
/// are used (since PDML fields include packet-specific values).
pub fn extract_protocol_from_pdml(
    packets: &[Vec<PdmlProtocol>],
    dissector_name: &str,
) -> Option<PdmlProtocol> {
    for packet in packets {
        for proto in packet {
            if proto.name == dissector_name {
                return Some(proto.clone());
            }
        }
    }
    None
}

/// Infer field type from tshark field name patterns using loaded mappings.
fn infer_field_type(name: &str, _show: &str, bits: u32, mappings: &TsharkMappings) -> FieldType {
    mappings.infer_field_type(name, bits)
}

/// Check if a tshark field name should be filtered out using loaded mappings.
fn is_blocked_tshark_field(name: &str, mappings: &TsharkMappings) -> bool {
    mappings.is_blocked(name)
}

/// Convert a PdmlProtocol to an IR ProtocolDef.
///
/// `proto_offset` is the byte offset of this protocol layer in the packet
/// (from PDML `pos` attribute). Field offsets are made relative to the
/// protocol header start.
pub fn to_protocol_def(pdml: &PdmlProtocol) -> ProtocolDef {
    let mappings = type_mapping::load_tshark_mappings(None)
        .expect("embedded tshark mappings should always parse");
    to_protocol_def_with(pdml, &mappings)
}

/// Convert using explicit mappings.
pub fn to_protocol_def_with(pdml: &PdmlProtocol, mappings: &TsharkMappings) -> ProtocolDef {
    let proto_byte_offset = pdml.pos;
    let mut fields = Vec::new();

    for pf in &pdml.fields {
        if pf.size == 0 {
            continue; // Skip zero-size fields (metadata)
        }

        // Skip payload/padding/trailer fields that aren't part of the header
        if is_blocked_tshark_field(&pf.name, mappings) {
            continue;
        }

        let rel_byte_offset = pf.pos.saturating_sub(proto_byte_offset);
        let offset_bits = rel_byte_offset * 8;
        let size_bits = pf.size * 8;

        let field_type = infer_field_type(&pf.name, &pf.show, size_bits, mappings);
        let endian = if size_bits <= 8 {
            Endian::Na
        } else {
            Endian::Big // Network protocols default to big-endian
        };

        fields.push(
            FieldDef::new(pf.name.clone(), offset_bits, size_bits, field_type)
                .with_endian(endian)
                .with_description(pf.show_name.clone())
                .with_source_name("tshark", pf.name.clone()),
        );
    }

    // Deduplicate fields with same offset (tshark sometimes expands bitfields)
    fields.sort_by_key(|f| (f.offset_bits, f.size_bits));
    fields.dedup_by(|a, b| a.offset_bits == b.offset_bits && a.size_bits == b.size_bits);

    let field_count = fields.len() as u32;

    ProtocolDef::new(pdml.name.clone(), pdml.size * 8)
        .with_fields(fields)
        .with_source("tshark", SourceInfo::new(pdml.name.clone())
            .with_field_count(field_count)
            .with_min_header_bytes(pdml.size))
}

/// Extract ALL protocols from pre-parsed PDML packets in one pass.
///
/// Returns a map from dissector name → ProtocolDef.
/// This eliminates per-protocol tshark subprocess calls for audit/matrix at scale.
pub fn extract_all_protocols_from_pdml(
    packets: &[Vec<PdmlProtocol>],
) -> std::collections::HashMap<String, ProtocolDef> {
    let mappings = type_mapping::load_tshark_mappings(None)
        .expect("embedded tshark mappings should always parse");

    let mut result = std::collections::HashMap::new();

    for packet in packets {
        for proto in packet {
            // Skip frame/data pseudo-protocols and already-seen ones
            if proto.name == "frame"
                || proto.name == "data"
                || proto.name == "_ws.malformed"
                || proto.name.is_empty()
            {
                continue;
            }

            // Keep the first occurrence (like extract_protocol_from_pdml)
            if result.contains_key(&proto.name) {
                continue;
            }

            let def = to_protocol_def_with(proto, &mappings);
            if !def.fields.is_empty() {
                result.insert(proto.name.clone(), def);
            }
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_PDML: &str = r#"<?xml version="1.0" encoding="utf-8"?>
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

    #[test]
    fn test_parse_pdml() {
        let packets = parse_pdml(SAMPLE_PDML).unwrap();
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].len(), 2); // eth + ip
    }

    #[test]
    fn test_extract_ip_from_pdml() {
        let packets = parse_pdml(SAMPLE_PDML).unwrap();
        let ip = extract_protocol_from_pdml(&packets, "ip").unwrap();
        assert_eq!(ip.name, "ip");
        assert_eq!(ip.size, 20);
        assert_eq!(ip.pos, 14);
        assert!(ip.fields.len() >= 10);
    }

    #[test]
    fn test_pdml_to_protocol_def() {
        let packets = parse_pdml(SAMPLE_PDML).unwrap();
        let ip = extract_protocol_from_pdml(&packets, "ip").unwrap();
        let proto = to_protocol_def(&ip);

        assert_eq!(proto.name, "ip");
        assert_eq!(proto.min_header_bits, 160);

        // Check that offsets are relative to protocol start
        let version = proto.fields.iter().find(|f| f.name == "ip.version").unwrap();
        assert_eq!(version.offset_bits, 0); // pos=14 - proto_pos=14 = 0

        let ttl = proto.fields.iter().find(|f| f.name == "ip.ttl").unwrap();
        assert_eq!(ttl.offset_bits, 64); // pos=22 - 14 = 8 bytes = 64 bits

        let src = proto.fields.iter().find(|f| f.name == "ip.src").unwrap();
        assert_eq!(src.offset_bits, 96);
        assert_eq!(src.field_type, FieldType::Ipv4Addr);
        assert_eq!(src.size_bits, 32);
    }

    #[test]
    fn test_payload_fields_filtered() {
        let pdml_with_payload = r#"<?xml version="1.0" encoding="utf-8"?>
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
        let packets = parse_pdml(pdml_with_payload).unwrap();
        let udp = extract_protocol_from_pdml(&packets, "udp").unwrap();
        let proto = to_protocol_def(&udp);

        // udp.payload and udp.checksum.status should be filtered out
        assert!(
            proto.fields.iter().all(|f| f.name != "udp.payload"),
            "udp.payload should be filtered"
        );
        assert!(
            proto.fields.iter().all(|f| f.name != "udp.checksum.status"),
            "udp.checksum.status should be filtered"
        );
        // Real header fields should remain
        assert!(proto.fields.iter().any(|f| f.name == "udp.srcport"));
        assert!(proto.fields.iter().any(|f| f.name == "udp.dstport"));
        assert!(proto.fields.iter().any(|f| f.name == "udp.length"));
        assert!(proto.fields.iter().any(|f| f.name == "udp.checksum"));
    }

    #[test]
    fn test_extract_eth_from_pdml() {
        let packets = parse_pdml(SAMPLE_PDML).unwrap();
        let eth = extract_protocol_from_pdml(&packets, "eth").unwrap();
        let proto = to_protocol_def(&eth);

        assert_eq!(proto.name, "eth");
        assert_eq!(proto.min_header_bits, 112); // 14 bytes

        let dst = proto.fields.iter().find(|f| f.name == "eth.dst").unwrap();
        assert_eq!(dst.offset_bits, 0);
        assert_eq!(dst.size_bits, 48);
        assert_eq!(dst.field_type, FieldType::MacAddr);
    }

    #[test]
    fn test_extract_all_protocols_from_pdml() {
        let packets = parse_pdml(SAMPLE_PDML).unwrap();
        let all = extract_all_protocols_from_pdml(&packets);

        // Should find both eth and ip (but not frame/data)
        assert!(all.contains_key("eth"), "should contain eth");
        assert!(all.contains_key("ip"), "should contain ip");
        assert!(!all.contains_key("frame"), "should skip frame pseudo-protocol");

        // Verify the extracted definitions are correct
        let ip = &all["ip"];
        assert_eq!(ip.min_header_bits, 160);
        assert!(!ip.fields.is_empty());

        let eth = &all["eth"];
        assert_eq!(eth.min_header_bits, 112);
    }
}
