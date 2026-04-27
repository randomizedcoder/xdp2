//! Netlink PCAP binary parser.
//!
//! Parses netlink socket diagnostic PCAPs (LinkType 253 / DLT_NETLINK) into
//! structured records with extracted TLV attributes. Used for binary-level
//! validation of inet_diag attribute definitions (tcp_info, bbr_info, etc.)
//! against real wire data from xtcp2's multi-kernel-version PCAP corpus.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

use crate::ir::ProtocolDef;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const PCAP_MAGIC_LE: u32 = 0xa1b2_c3d4;
const PCAP_GLOBAL_HEADER_LEN: usize = 24;
const PCAP_RECORD_HEADER_LEN: usize = 16;
const DLT_NETLINK: u16 = 253;
const NETLINK_COOKED_HEADER_LEN: usize = 16;
const NLMSGHDR_LEN: usize = 16;
const INET_DIAG_MSG_LEN: usize = 72;
const NLMSG_DONE: u16 = 3;
const SOCK_DIAG_BY_FAMILY: u16 = 20;

/// Map inet_diag attribute type IDs to canonical proto-audit protocol names.
pub const ATTR_TYPE_MAP: &[(u16, &str)] = &[
    (1, "NL_Diag_MemInfo"),
    (2, "NL_Diag_TCPInfo"),
    (3, "NL_Diag_VegasInfo"),
    // 4 = cong (string, not a struct)
    // 5 = tos (single byte)
    (7, "NL_Diag_SkMemInfo"),
    // 8 = shutdown (single byte)
    (9, "NL_Diag_DCTCPInfo"),
    (16, "NL_Diag_BBRInfo"),
    // 17 = class_id (u32)
    // 21 = cgroup_id (u64)
    // 22 = sockopt
];

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A parsed netlink message from a PCAP record.
#[derive(Debug, Clone)]
pub struct NetlinkRecord {
    /// Netlink message type (20=SOCK_DIAG_BY_FAMILY, 3=NLMSG_DONE)
    pub nlmsg_type: u16,
    /// Total message length from nlmsghdr
    pub nlmsg_len: u32,
    /// Raw inet_diag_msg bytes (72 bytes), if this is a SOCK_DIAG response
    pub inet_diag: Option<Vec<u8>>,
    /// TLV attributes extracted from the message
    pub attributes: Vec<NetlinkAttribute>,
}

/// A single TLV attribute (RTAttr) extracted from a netlink message.
#[derive(Debug, Clone)]
pub struct NetlinkAttribute {
    /// Attribute type ID (1=meminfo, 2=info/tcp_info, 3=vegas, 7=skmem, etc.)
    pub attr_type: u16,
    /// Raw payload bytes (after the 4-byte RTAttr header)
    pub payload: Vec<u8>,
}

/// Metadata about a discovered xtcp2 PCAP file.
#[derive(Debug, Clone)]
pub struct PcapInfo {
    /// Full path to the .pcap file
    pub path: PathBuf,
    /// Kernel version extracted from directory name (e.g., "6_10_3")
    pub kernel_version: String,
}

/// A deserialized field value from attribute payload bytes.
#[derive(Debug, Clone)]
pub struct FieldValue {
    pub name: String,
    pub value: u64,
    pub offset_bytes: u32,
    pub size_bytes: u32,
}

// ---------------------------------------------------------------------------
// Little-endian helpers
// ---------------------------------------------------------------------------

fn read_u16_le(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([data[offset], data[offset + 1]])
}

fn read_u32_le(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

// ---------------------------------------------------------------------------
// PCAP parser
// ---------------------------------------------------------------------------

/// Parse a PCAP file (DLT_NETLINK = 253) into netlink records.
///
/// Each PCAP record may contain one or more netlink messages (bulk socket
/// dumps have multiple messages per record). Stops at NLMSG_DONE (type=3).
pub fn parse_netlink_pcap(data: &[u8]) -> Result<Vec<NetlinkRecord>> {
    if data.len() < PCAP_GLOBAL_HEADER_LEN {
        anyhow::bail!("PCAP too short for global header");
    }

    // Verify magic number
    let magic = read_u32_le(data, 0);
    if magic != PCAP_MAGIC_LE {
        anyhow::bail!(
            "Not a little-endian PCAP (magic: 0x{:08x}, expected 0x{:08x})",
            magic,
            PCAP_MAGIC_LE
        );
    }

    // Verify link type at offset 20 (2 bytes FCS + 2 bytes link type, or
    // just 4 bytes link_type depending on PCAP version — check last 2 bytes)
    let link_type = read_u16_le(data, 22); // standard PCAP: link_type is at byte 20 as u32LE
    let link_type_u32 = read_u32_le(data, 20);
    let effective_link_type = if link_type == DLT_NETLINK {
        DLT_NETLINK
    } else if (link_type_u32 & 0xFFFF) as u16 == DLT_NETLINK {
        DLT_NETLINK
    } else {
        anyhow::bail!(
            "Not a netlink PCAP (link_type: {}, expected {})",
            link_type_u32,
            DLT_NETLINK
        );
    };
    let _ = effective_link_type;

    let mut records = Vec::new();
    let mut offset = PCAP_GLOBAL_HEADER_LEN;

    while offset + PCAP_RECORD_HEADER_LEN <= data.len() {
        let incl_len = read_u32_le(data, offset + 8) as usize;
        let record_start = offset + PCAP_RECORD_HEADER_LEN;
        let record_end = record_start + incl_len;

        if record_end > data.len() {
            break; // truncated record
        }

        let record_data = &data[record_start..record_end];
        let mut msgs = parse_netlink_messages(record_data)?;
        records.append(&mut msgs);

        offset = record_end;
    }

    Ok(records)
}

/// Parse netlink messages from a single PCAP record payload.
///
/// Layout: 16-byte cooked header → one or more (nlmsghdr + body + attributes).
fn parse_netlink_messages(record: &[u8]) -> Result<Vec<NetlinkRecord>> {
    if record.len() < NETLINK_COOKED_HEADER_LEN {
        return Ok(vec![]);
    }

    let mut records = Vec::new();
    let mut pos = NETLINK_COOKED_HEADER_LEN;

    while pos + NLMSGHDR_LEN <= record.len() {
        let nlmsg_len = read_u32_le(record, pos) as usize;
        let nlmsg_type = read_u16_le(record, pos + 4);

        if nlmsg_len < NLMSGHDR_LEN || pos + nlmsg_len > record.len() {
            break;
        }

        if nlmsg_type == NLMSG_DONE {
            records.push(NetlinkRecord {
                nlmsg_type,
                nlmsg_len: nlmsg_len as u32,
                inet_diag: None,
                attributes: vec![],
            });
            break;
        }

        let mut inet_diag = None;
        let mut attributes = Vec::new();

        if nlmsg_type == SOCK_DIAG_BY_FAMILY {
            let body_start = pos + NLMSGHDR_LEN;

            // Extract inet_diag_msg (72 bytes)
            if body_start + INET_DIAG_MSG_LEN <= pos + nlmsg_len {
                inet_diag = Some(record[body_start..body_start + INET_DIAG_MSG_LEN].to_vec());

                // Parse TLV attributes after inet_diag_msg
                let attr_start = body_start + INET_DIAG_MSG_LEN;
                let attr_end = pos + nlmsg_len;
                attributes = parse_rtattr_chain(&record[attr_start..attr_end]);
            }
        }

        records.push(NetlinkRecord {
            nlmsg_type,
            nlmsg_len: nlmsg_len as u32,
            inet_diag,
            attributes,
        });

        // Advance to next message (4-byte aligned)
        let aligned = (nlmsg_len + 3) & !3;
        pos += aligned;
    }

    Ok(records)
}

/// Parse a chain of RTAttr TLV entries from raw bytes.
///
/// Each RTAttr: 2-byte length (LE), 2-byte type (LE), then payload.
/// Attributes are padded to 4-byte alignment.
fn parse_rtattr_chain(data: &[u8]) -> Vec<NetlinkAttribute> {
    let mut attrs = Vec::new();
    let mut pos = 0;

    while pos + 4 <= data.len() {
        let rta_len = read_u16_le(data, pos) as usize;
        let rta_type = read_u16_le(data, pos + 2);

        if rta_len < 4 || pos + rta_len > data.len() {
            break;
        }

        let payload = data[pos + 4..pos + rta_len].to_vec();
        attrs.push(NetlinkAttribute {
            attr_type: rta_type,
            payload,
        });

        // Advance to next 4-byte aligned boundary
        let aligned = (rta_len + 3) & !3;
        pos += aligned;
    }

    attrs
}

// ---------------------------------------------------------------------------
// Attribute deserialization against IR
// ---------------------------------------------------------------------------

/// Deserialize an attribute payload against an IR ProtocolDef.
///
/// For each field in the protocol definition, extracts the raw bytes from
/// the payload at the declared offset and interprets them as an integer.
/// Handles variable-length payloads (e.g., TCPInfo across kernel versions)
/// by skipping fields that fall beyond the available data.
pub fn deserialize_attribute(payload: &[u8], proto: &ProtocolDef) -> Vec<FieldValue> {
    let mut values = Vec::new();

    for field in &proto.fields {
        if field.size_bits == 0 {
            continue;
        }
        let offset_bytes = field.offset_bits / 8;
        let size_bytes = field.size_bits / 8;

        // Skip fields beyond the available payload (variable-length support)
        if (offset_bytes + size_bytes) as usize > payload.len() {
            continue;
        }

        let start = offset_bytes as usize;
        let end = start + size_bytes as usize;
        let bytes = &payload[start..end];

        let value = match (&field.endian, size_bytes) {
            (_, 1) => bytes[0] as u64,
            (&crate::ir::Endian::Big, 2) => u16::from_be_bytes([bytes[0], bytes[1]]) as u64,
            (_, 2) => u16::from_le_bytes([bytes[0], bytes[1]]) as u64,
            (&crate::ir::Endian::Big, 4) => {
                u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64
            }
            (_, 4) => u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64,
            (&crate::ir::Endian::Big, 8) => u64::from_be_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ]),
            (_, 8) => u64::from_le_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ]),
            _ => {
                // For larger fields (e.g., 16-byte IPv6 addresses), take first 8 bytes
                if bytes.len() >= 8 {
                    u64::from_le_bytes([
                        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6],
                        bytes[7],
                    ])
                } else {
                    0
                }
            }
        };

        values.push(FieldValue {
            name: field.name.clone(),
            value,
            offset_bytes,
            size_bytes,
        });
    }

    values
}

// ---------------------------------------------------------------------------
// PCAP discovery
// ---------------------------------------------------------------------------

/// Find all .pcap files in the xtcp2 testdata directory.
///
/// Expected structure: `$XTCP2_SRC/pkg/xtcpnl/testdata/<kernel_version>/*.pcap`
/// Extracts kernel version from the parent directory name.
pub fn find_xtcp2_pcaps(xtcp2_src: &Path) -> Result<Vec<PcapInfo>> {
    // Support both repo root (append pkg/xtcpnl/testdata) and direct testdata dir
    let candidate = xtcp2_src.join("pkg").join("xtcpnl").join("testdata");
    let testdata_dir = if candidate.is_dir() {
        candidate
    } else if xtcp2_src.is_dir() {
        // Assume we're already pointing at the testdata dir
        xtcp2_src.to_path_buf()
    } else {
        anyhow::bail!(
            "xtcp2 testdata directory not found: {}",
            xtcp2_src.display()
        );
    };

    let mut pcaps = Vec::new();
    collect_pcaps_recursive(&testdata_dir, &testdata_dir, &mut pcaps)
        .context("walking xtcp2 testdata")?;

    pcaps.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(pcaps)
}

fn collect_pcaps_recursive(
    dir: &Path,
    testdata_root: &Path,
    out: &mut Vec<PcapInfo>,
) -> Result<()> {
    let entries = std::fs::read_dir(dir)
        .with_context(|| format!("reading directory: {}", dir.display()))?;

    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_pcaps_recursive(&path, testdata_root, out)?;
        } else if path.extension().and_then(|e| e.to_str()) == Some("pcap") {
            // Extract kernel version from the directory name relative to testdata root
            let kernel_version = path
                .parent()
                .and_then(|p| p.strip_prefix(testdata_root).ok())
                .and_then(|rel| rel.components().next())
                .and_then(|c| c.as_os_str().to_str())
                .unwrap_or("unknown")
                .to_string();

            out.push(PcapInfo {
                path,
                kernel_version,
            });
        }
    }
    Ok(())
}

/// Look up the canonical protocol name for an inet_diag attribute type ID.
pub fn attr_type_to_proto(attr_type: u16) -> Option<&'static str> {
    ATTR_TYPE_MAP
        .iter()
        .find(|(t, _)| *t == attr_type)
        .map(|(_, name)| *name)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{Endian, FieldDef, FieldType, ProtocolDef};

    /// Build a minimal valid PCAP with one netlink SOCK_DIAG record.
    fn make_test_pcap(record_payload: &[u8]) -> Vec<u8> {
        let mut pcap = Vec::new();

        // PCAP global header (24 bytes)
        pcap.extend_from_slice(&PCAP_MAGIC_LE.to_le_bytes()); // magic
        pcap.extend_from_slice(&2u16.to_le_bytes()); // version_major
        pcap.extend_from_slice(&4u16.to_le_bytes()); // version_minor
        pcap.extend_from_slice(&0u32.to_le_bytes()); // reserved1
        pcap.extend_from_slice(&0u32.to_le_bytes()); // reserved2
        pcap.extend_from_slice(&262144u32.to_le_bytes()); // snap_len
        pcap.extend_from_slice(&(DLT_NETLINK as u32).to_le_bytes()); // link_type

        // PCAP record header (16 bytes)
        pcap.extend_from_slice(&0u32.to_le_bytes()); // ts_sec
        pcap.extend_from_slice(&0u32.to_le_bytes()); // ts_usec
        pcap.extend_from_slice(&(record_payload.len() as u32).to_le_bytes()); // incl_len
        pcap.extend_from_slice(&(record_payload.len() as u32).to_le_bytes()); // orig_len

        pcap.extend_from_slice(record_payload);
        pcap
    }

    /// Build a netlink record payload: cooked header + nlmsghdr + inet_diag_msg + attrs.
    fn make_netlink_record(nlmsg_type: u16, attrs: &[u8]) -> Vec<u8> {
        let nlmsg_len = (NLMSGHDR_LEN + INET_DIAG_MSG_LEN + attrs.len()) as u32;
        let mut payload = Vec::new();

        // Cooked header (16 bytes) — simplified
        payload.extend_from_slice(&[0u8; 16]);

        // nlmsghdr (16 bytes)
        payload.extend_from_slice(&nlmsg_len.to_le_bytes()); // len
        payload.extend_from_slice(&nlmsg_type.to_le_bytes()); // type
        payload.extend_from_slice(&0u16.to_le_bytes()); // flags
        payload.extend_from_slice(&1u32.to_le_bytes()); // seq
        payload.extend_from_slice(&1u32.to_le_bytes()); // pid

        // inet_diag_msg (72 bytes) — zeroed
        payload.extend_from_slice(&[0u8; INET_DIAG_MSG_LEN]);

        // attributes
        payload.extend_from_slice(attrs);

        payload
    }

    /// Build an RTAttr TLV: 2-byte len, 2-byte type, payload, padding.
    fn make_rtattr(attr_type: u16, data: &[u8]) -> Vec<u8> {
        let rta_len = 4 + data.len();
        let padded_len = (rta_len + 3) & !3;
        let mut buf = Vec::new();
        buf.extend_from_slice(&(rta_len as u16).to_le_bytes());
        buf.extend_from_slice(&attr_type.to_le_bytes());
        buf.extend_from_slice(data);
        // Padding
        for _ in rta_len..padded_len {
            buf.push(0);
        }
        buf
    }

    #[test]
    fn test_parse_pcap_header() {
        // Valid netlink PCAP
        let record = make_netlink_record(SOCK_DIAG_BY_FAMILY, &[]);
        let pcap = make_test_pcap(&record);
        let records = parse_netlink_pcap(&pcap).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].nlmsg_type, SOCK_DIAG_BY_FAMILY);
        assert!(records[0].inet_diag.is_some());

        // Bad magic
        let mut bad = pcap.clone();
        bad[0] = 0xFF;
        assert!(parse_netlink_pcap(&bad).is_err());

        // Too short
        assert!(parse_netlink_pcap(&[0; 10]).is_err());
    }

    #[test]
    fn test_parse_rtattr_chain() {
        // Two attributes: type=16 (BBRInfo, 20 bytes) + type=1 (MemInfo, 16 bytes)
        let bbr_data = vec![
            0x01, 0x00, 0x00, 0x00, // bbr_bw_lo = 1
            0x02, 0x00, 0x00, 0x00, // bbr_bw_hi = 2
            0x64, 0x00, 0x00, 0x00, // bbr_min_rtt = 100
            0x00, 0x01, 0x00, 0x00, // bbr_pacing_gain = 256
            0x00, 0x01, 0x00, 0x00, // bbr_cwnd_gain = 256
        ];
        let mem_data = vec![
            0x00, 0x10, 0x00, 0x00, // rmem = 4096
            0x00, 0x20, 0x00, 0x00, // wmem = 8192
            0x00, 0x00, 0x00, 0x00, // fmem = 0
            0x00, 0x40, 0x00, 0x00, // tmem = 16384
        ];

        let mut attrs = make_rtattr(16, &bbr_data);
        attrs.extend_from_slice(&make_rtattr(1, &mem_data));

        let record = make_netlink_record(SOCK_DIAG_BY_FAMILY, &attrs);
        let pcap = make_test_pcap(&record);
        let records = parse_netlink_pcap(&pcap).unwrap();

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].attributes.len(), 2);
        assert_eq!(records[0].attributes[0].attr_type, 16); // BBRInfo
        assert_eq!(records[0].attributes[0].payload.len(), 20);
        assert_eq!(records[0].attributes[1].attr_type, 1); // MemInfo
        assert_eq!(records[0].attributes[1].payload.len(), 16);
    }

    #[test]
    fn test_deserialize_bbrinfo() {
        let payload = vec![
            0x01, 0x00, 0x00, 0x00, // bbr_bw_lo = 1
            0x02, 0x00, 0x00, 0x00, // bbr_bw_hi = 2
            0x64, 0x00, 0x00, 0x00, // bbr_min_rtt = 100
            0x00, 0x01, 0x00, 0x00, // bbr_pacing_gain = 256
            0x00, 0x01, 0x00, 0x00, // bbr_cwnd_gain = 256
        ];

        let proto = ProtocolDef::new("NL_Diag_BBRInfo", 160).with_fields(vec![
            FieldDef::new("bbr_bw_lo", 0, 32, FieldType::Uint).with_endian(Endian::Little),
            FieldDef::new("bbr_bw_hi", 32, 32, FieldType::Uint).with_endian(Endian::Little),
            FieldDef::new("bbr_min_rtt", 64, 32, FieldType::Uint).with_endian(Endian::Little),
            FieldDef::new("bbr_pacing_gain", 96, 32, FieldType::Uint).with_endian(Endian::Little),
            FieldDef::new("bbr_cwnd_gain", 128, 32, FieldType::Uint).with_endian(Endian::Little),
        ]);

        let values = deserialize_attribute(&payload, &proto);
        assert_eq!(values.len(), 5);
        assert_eq!(values[0].name, "bbr_bw_lo");
        assert_eq!(values[0].value, 1);
        assert_eq!(values[1].name, "bbr_bw_hi");
        assert_eq!(values[1].value, 2);
        assert_eq!(values[2].name, "bbr_min_rtt");
        assert_eq!(values[2].value, 100);
        assert_eq!(values[3].name, "bbr_pacing_gain");
        assert_eq!(values[3].value, 256);
        assert_eq!(values[4].name, "bbr_cwnd_gain");
        assert_eq!(values[4].value, 256);
    }

    #[test]
    fn test_deserialize_tcpinfo_variable() {
        // Test with a short payload (only 16 bytes, covering first 4 fields)
        let short_payload = vec![
            0x01, // state = 1 (ESTABLISHED)
            0x00, // ca_state = 0
            0x00, // retransmits = 0
            0x00, // probes = 0
            0x03, // backoff = 3
            0x07, // options = 7
            0xA7, // scale_temp (snd_wscale:rcv_wscale packed)
            0x00, // flags_temp
            0xE8, 0x03, 0x00, 0x00, // rto = 1000
            0x28, 0x00, 0x00, 0x00, // ato = 40
        ];

        // Full TCPInfo has 59 fields but we'll define a few for testing
        let proto = ProtocolDef::new("NL_Diag_TCPInfo", 1984)
            .with_variable_length()
            .with_fields(vec![
                FieldDef::new("state", 0, 8, FieldType::Uint).with_endian(Endian::Little),
                FieldDef::new("ca_state", 8, 8, FieldType::Uint).with_endian(Endian::Little),
                FieldDef::new("retransmits", 16, 8, FieldType::Uint).with_endian(Endian::Little),
                FieldDef::new("probes", 24, 8, FieldType::Uint).with_endian(Endian::Little),
                FieldDef::new("backoff", 32, 8, FieldType::Uint).with_endian(Endian::Little),
                FieldDef::new("options", 40, 8, FieldType::Uint).with_endian(Endian::Little),
                FieldDef::new("scale_temp", 48, 8, FieldType::Uint).with_endian(Endian::Little),
                FieldDef::new("flags_temp", 56, 8, FieldType::Uint).with_endian(Endian::Little),
                FieldDef::new("rto", 64, 32, FieldType::Uint).with_endian(Endian::Little),
                FieldDef::new("ato", 96, 32, FieldType::Uint).with_endian(Endian::Little),
                // This field is beyond the short payload — should be skipped
                FieldDef::new("snd_mss", 128, 32, FieldType::Uint).with_endian(Endian::Little),
            ]);

        let values = deserialize_attribute(&short_payload, &proto);
        // Should get 10 fields (not 11 — snd_mss is beyond payload)
        assert_eq!(values.len(), 10);
        assert_eq!(values[0].name, "state");
        assert_eq!(values[0].value, 1);
        assert_eq!(values[4].name, "backoff");
        assert_eq!(values[4].value, 3);
        assert_eq!(values[8].name, "rto");
        assert_eq!(values[8].value, 1000);
        assert_eq!(values[9].name, "ato");
        assert_eq!(values[9].value, 40);
    }

    #[test]
    fn test_nlmsg_done() {
        // Build a record with NLMSG_DONE — parser should stop
        let mut payload = Vec::new();

        // Cooked header (16 bytes)
        payload.extend_from_slice(&[0u8; 16]);

        // nlmsghdr for NLMSG_DONE (type=3, minimal length)
        let nlmsg_len = NLMSGHDR_LEN as u32 + 4; // header + 4-byte error code
        payload.extend_from_slice(&nlmsg_len.to_le_bytes());
        payload.extend_from_slice(&NLMSG_DONE.to_le_bytes());
        payload.extend_from_slice(&0u16.to_le_bytes()); // flags
        payload.extend_from_slice(&1u32.to_le_bytes()); // seq
        payload.extend_from_slice(&1u32.to_le_bytes()); // pid
        payload.extend_from_slice(&0u32.to_le_bytes()); // error code

        let pcap = make_test_pcap(&payload);
        let records = parse_netlink_pcap(&pcap).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].nlmsg_type, NLMSG_DONE);
        assert!(records[0].inet_diag.is_none());
        assert!(records[0].attributes.is_empty());
    }

    #[test]
    fn test_attr_type_to_proto() {
        assert_eq!(attr_type_to_proto(2), Some("NL_Diag_TCPInfo"));
        assert_eq!(attr_type_to_proto(16), Some("NL_Diag_BBRInfo"));
        assert_eq!(attr_type_to_proto(1), Some("NL_Diag_MemInfo"));
        assert_eq!(attr_type_to_proto(7), Some("NL_Diag_SkMemInfo"));
        assert_eq!(attr_type_to_proto(99), None); // unknown
    }

    #[test]
    fn test_multi_message_record() {
        // Build a record with two SOCK_DIAG messages + NLMSG_DONE
        let bbr_attr = make_rtattr(16, &[0u8; 20]); // 20-byte BBRInfo
        let mem_attr = make_rtattr(1, &[0u8; 16]); // 16-byte MemInfo

        let mut payload = Vec::new();

        // Cooked header
        payload.extend_from_slice(&[0u8; 16]);

        // Message 1: SOCK_DIAG with BBRInfo
        let msg1_len = (NLMSGHDR_LEN + INET_DIAG_MSG_LEN + bbr_attr.len()) as u32;
        payload.extend_from_slice(&msg1_len.to_le_bytes());
        payload.extend_from_slice(&SOCK_DIAG_BY_FAMILY.to_le_bytes());
        payload.extend_from_slice(&0u16.to_le_bytes());
        payload.extend_from_slice(&1u32.to_le_bytes());
        payload.extend_from_slice(&1u32.to_le_bytes());
        payload.extend_from_slice(&[0u8; INET_DIAG_MSG_LEN]);
        payload.extend_from_slice(&bbr_attr);

        // Message 2: SOCK_DIAG with MemInfo
        let msg2_len = (NLMSGHDR_LEN + INET_DIAG_MSG_LEN + mem_attr.len()) as u32;
        payload.extend_from_slice(&msg2_len.to_le_bytes());
        payload.extend_from_slice(&SOCK_DIAG_BY_FAMILY.to_le_bytes());
        payload.extend_from_slice(&0u16.to_le_bytes());
        payload.extend_from_slice(&2u32.to_le_bytes());
        payload.extend_from_slice(&1u32.to_le_bytes());
        payload.extend_from_slice(&[0u8; INET_DIAG_MSG_LEN]);
        payload.extend_from_slice(&mem_attr);

        // Message 3: NLMSG_DONE
        let done_len = (NLMSGHDR_LEN + 4) as u32;
        payload.extend_from_slice(&done_len.to_le_bytes());
        payload.extend_from_slice(&NLMSG_DONE.to_le_bytes());
        payload.extend_from_slice(&0u16.to_le_bytes());
        payload.extend_from_slice(&3u32.to_le_bytes());
        payload.extend_from_slice(&1u32.to_le_bytes());
        payload.extend_from_slice(&0u32.to_le_bytes());

        let pcap = make_test_pcap(&payload);
        let records = parse_netlink_pcap(&pcap).unwrap();

        // Should have 3 records: 2 SOCK_DIAG + 1 DONE
        assert_eq!(records.len(), 3);
        assert_eq!(records[0].nlmsg_type, SOCK_DIAG_BY_FAMILY);
        assert_eq!(records[0].attributes.len(), 1);
        assert_eq!(records[0].attributes[0].attr_type, 16);
        assert_eq!(records[1].nlmsg_type, SOCK_DIAG_BY_FAMILY);
        assert_eq!(records[1].attributes.len(), 1);
        assert_eq!(records[1].attributes[0].attr_type, 1);
        assert_eq!(records[2].nlmsg_type, NLMSG_DONE);
    }
}
