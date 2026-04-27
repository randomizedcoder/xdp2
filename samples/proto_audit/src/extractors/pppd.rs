//! pppd source extractor.
//!
//! Extracts PPP protocol definitions from pppd source headers.
//! Unlike kernel/DPDK/nDPI, pppd defines wire formats primarily through
//! `#define` constants rather than packed structs. This extractor:
//!
//! 1. Parses PPP protocol ID constants (PPP_IP, PPP_LCP, etc.) for
//!    dispatch table enrichment
//! 2. Generates fixed-layout IR for the PPP frame header and common
//!    control protocol header (Code + ID + Length)
//!
//! Key source files:
//! - `include/linux/ppp_defs.h` — PPP protocol IDs, frame constants
//! - `lcp.h` — LCP option codes (CI_*) and packet types

use anyhow::Result;
use std::collections::HashMap;
use std::path::Path;

use crate::ir::{Endian, FieldDef, FieldType, ProtocolDef, SourceInfo};

/// A PPP protocol constant parsed from pppd headers.
#[derive(Debug, Clone)]
pub struct PppdConstant {
    /// Define name (e.g., "PPP_IP")
    pub name: String,
    /// Numeric value (e.g., 0x21)
    pub value: u32,
    /// Source file path
    pub file: String,
}

/// Parse `#define PPP_*` constants from ppp_defs.h content.
pub fn parse_ppp_protocol_ids(content: &str, file_path: &str) -> Vec<PppdConstant> {
    let mut constants = Vec::new();
    let re = regex::Regex::new(r"#define\s+(PPP_\w+)\s+(0x[0-9a-fA-F]+|\d+)").unwrap();

    for cap in re.captures_iter(content) {
        let name = cap[1].to_string();
        let val_str = &cap[2];

        // Skip non-protocol constants (sizes, flags, masks, FCS)
        if name.contains("HDRLEN")
            || name.contains("FCSLEN")
            || name.contains("MRU")
            || name.contains("FLAG")
            || name.contains("ESCAPE")
            || name.contains("TRANS")
            || name.contains("ALLSTATIONS")
            || name.contains("UI")
            || name.contains("INITFCS")
            || name.contains("GOODFCS")
            || name.contains("ADDRESS")
            || name.contains("CONTROL")
            || name.contains("PROTOCOL")
        {
            continue;
        }

        let value = if let Some(hex) = val_str.strip_prefix("0x") {
            u32::from_str_radix(hex, 16).unwrap_or(0)
        } else {
            val_str.parse().unwrap_or(0)
        };

        if value > 0 {
            constants.push(PppdConstant {
                name,
                value,
                file: file_path.to_string(),
            });
        }
    }

    constants
}

/// Parse `#define CI_*` option codes from lcp.h content.
pub fn parse_lcp_options(content: &str, file_path: &str) -> Vec<PppdConstant> {
    let mut constants = Vec::new();
    let re = regex::Regex::new(r"#define\s+(CI_\w+)\s+(\d+)").unwrap();

    for cap in re.captures_iter(content) {
        let name = cap[1].to_string();
        let value: u32 = cap[2].parse().unwrap_or(0);
        constants.push(PppdConstant {
            name,
            value,
            file: file_path.to_string(),
        });
    }

    constants
}

/// Build the PPP protocol ID → protocol name mapping from parsed constants.
pub fn protocol_id_map(constants: &[PppdConstant]) -> HashMap<u32, String> {
    let mut map = HashMap::new();
    for c in constants {
        // Convert PPP_IP → "IP", PPP_LCP → "LCP", etc.
        if let Some(suffix) = c.name.strip_prefix("PPP_") {
            map.insert(c.value, suffix.to_string());
        }
    }
    map
}

/// Generate a ProtocolDef for the PPP frame header.
///
/// PPP frame: Address(8) + Control(8) + Protocol(16) = 32 bits / 4 bytes
fn ppp_frame_def(file_path: &str) -> ProtocolDef {
    let fields = vec![
        FieldDef::new("address".to_string(), 0, 8, FieldType::Uint)
            .with_endian(Endian::Na)
            .with_source_name("pppd", "address".to_string()),
        FieldDef::new("control".to_string(), 8, 8, FieldType::Uint)
            .with_endian(Endian::Na)
            .with_source_name("pppd", "control".to_string()),
        FieldDef::new("protocol".to_string(), 16, 16, FieldType::Enum)
            .with_endian(Endian::Big)
            .with_source_name("pppd", "protocol".to_string()),
    ];

    ProtocolDef::new("PPP", 32)
        .with_fields(fields)
        .with_dispatch_field("protocol")
        .with_source(
            "pppd",
            SourceInfo::new("PPP")
                .with_file(file_path)
                .with_field_count(3)
                .with_min_header_bytes(4),
        )
}

/// Generate a ProtocolDef for PPP control protocols (LCP, IPCP, IPv6CP, etc.).
///
/// Common header: Code(8) + Identifier(8) + Length(16) = 32 bits / 4 bytes
fn ppp_control_proto_def(proto_name: &str, file_path: &str) -> ProtocolDef {
    let fields = vec![
        FieldDef::new("code".to_string(), 0, 8, FieldType::Enum)
            .with_endian(Endian::Na)
            .with_source_name("pppd", "code".to_string()),
        FieldDef::new("identifier".to_string(), 8, 8, FieldType::Uint)
            .with_endian(Endian::Na)
            .with_source_name("pppd", "identifier".to_string()),
        FieldDef::new("length".to_string(), 16, 16, FieldType::Uint)
            .with_endian(Endian::Big)
            .with_source_name("pppd", "length".to_string()),
    ];

    ProtocolDef::new(proto_name, 32)
        .with_fields(fields)
        .with_source(
            "pppd",
            SourceInfo::new(proto_name)
                .with_file(file_path)
                .with_field_count(3)
                .with_min_header_bytes(4),
        )
}

/// The set of protocols pppd can provide definitions for.
const PPPD_PROTOCOLS: &[&str] = &[
    "PPP", "LCP", "IPCP", "IPv6CP", "CCP", "ECP", "PAP", "CHAP",
];

/// Extract a ProtocolDef for a named protocol from pppd sources.
///
/// - "PPP" → PPP frame header (Address + Control + Protocol)
/// - "LCP", "IPCP", "IPv6CP", etc. → control protocol header (Code + ID + Length)
pub fn extract_protocol(dir: &Path, proto: &str) -> Result<Option<ProtocolDef>> {
    let ppp_defs = dir.join("include").join("linux").join("ppp_defs.h");
    let file_path = if ppp_defs.exists() {
        ppp_defs.to_string_lossy().to_string()
    } else {
        // Try alternate location
        let alt = dir.join("include").join("ppp_defs.h");
        if alt.exists() {
            alt.to_string_lossy().to_string()
        } else {
            return Ok(None);
        }
    };

    match proto {
        "PPP" => Ok(Some(ppp_frame_def(&file_path))),
        "LCP" | "IPCP" | "IPv6CP" | "CCP" | "ECP" | "PAP" | "CHAP" => {
            Ok(Some(ppp_control_proto_def(proto, &file_path)))
        }
        _ => Ok(None),
    }
}

/// List all protocols that pppd can provide definitions for.
pub fn available_protocols() -> &'static [&'static str] {
    PPPD_PROTOCOLS
}

/// Scan pppd source directory and return protocol constants found.
pub fn scan_pppd_dir(dir: &Path) -> Result<Vec<PppdConstant>> {
    let ppp_defs = dir.join("include").join("linux").join("ppp_defs.h");
    if !ppp_defs.exists() {
        return Ok(Vec::new());
    }

    let content = std::fs::read_to_string(&ppp_defs)?;
    Ok(parse_ppp_protocol_ids(&content, "ppp_defs.h"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PPP_DEFS: &str = r#"
#define PPP_HDRLEN	4
#define PPP_FCSLEN	2
#define PPP_MRU		1500
#define	PPP_ALLSTATIONS	0xff
#define	PPP_UI		0x03
#define	PPP_FLAG	0x7e
#define	PPP_ESCAPE	0x7d
#define	PPP_TRANS	0x20
#define PPP_IP		0x21
#define PPP_AT		0x29
#define PPP_IPX		0x2b
#define	PPP_VJC_COMP	0x2d
#define	PPP_VJC_UNCOMP	0x2f
#define PPP_MP		0x3d
#define PPP_IPV6	0x57
#define PPP_IPCP	0x8021
#define PPP_ATCP	0x8029
#define PPP_IPXCP	0x802b
#define PPP_IPV6CP	0x8057
#define PPP_CCP		0x80fd
#define PPP_ECP		0x8053
#define PPP_LCP		0xc021
#define PPP_PAP		0xc023
#define PPP_LQR		0xc025
#define PPP_CHAP	0xc223
#define PPP_CBCP	0xc029
"#;

    #[test]
    fn test_parse_protocol_ids() {
        let constants = parse_ppp_protocol_ids(PPP_DEFS, "ppp_defs.h");
        // Should skip HDRLEN, FCSLEN, MRU, FLAG, ESCAPE, etc.
        assert!(constants.iter().all(|c| !c.name.contains("HDRLEN")));
        assert!(constants.iter().all(|c| !c.name.contains("FLAG")));
        // Should include protocol IDs
        let ip = constants.iter().find(|c| c.name == "PPP_IP").unwrap();
        assert_eq!(ip.value, 0x21);
        let lcp = constants.iter().find(|c| c.name == "PPP_LCP").unwrap();
        assert_eq!(lcp.value, 0xc021);
    }

    #[test]
    fn test_protocol_id_map() {
        let constants = parse_ppp_protocol_ids(PPP_DEFS, "ppp_defs.h");
        let map = protocol_id_map(&constants);
        assert_eq!(map.get(&0x21), Some(&"IP".to_string()));
        assert_eq!(map.get(&0xc021), Some(&"LCP".to_string()));
        assert_eq!(map.get(&0x57), Some(&"IPV6".to_string()));
    }

    #[test]
    fn test_ppp_frame_def() {
        let def = ppp_frame_def("ppp_defs.h");
        assert_eq!(def.name, "PPP");
        assert_eq!(def.min_header_bits, 32);
        assert_eq!(def.fields.len(), 3);
        assert_eq!(def.fields[0].name, "address");
        assert_eq!(def.fields[1].name, "control");
        assert_eq!(def.fields[2].name, "protocol");
        assert_eq!(def.fields[2].field_type, FieldType::Enum);
        assert_eq!(def.dispatch_field, Some("protocol".to_string()));
    }

    #[test]
    fn test_lcp_def() {
        let def = ppp_control_proto_def("LCP", "lcp.h");
        assert_eq!(def.name, "LCP");
        assert_eq!(def.min_header_bits, 32);
        assert_eq!(def.fields.len(), 3);
        assert_eq!(def.fields[0].name, "code");
        assert_eq!(def.fields[0].field_type, FieldType::Enum);
        assert_eq!(def.fields[2].name, "length");
    }

    #[test]
    fn test_lcp_option_parsing() {
        let lcp_content = r#"
#define CI_VENDOR	0
#define CI_MRU		1
#define CI_ASYNCMAP	2
#define CI_AUTHTYPE	3
#define CI_QUALITY	4
#define CI_MAGICNUMBER	5
"#;
        let options = parse_lcp_options(lcp_content, "lcp.h");
        assert_eq!(options.len(), 6);
        assert_eq!(options[0].name, "CI_VENDOR");
        assert_eq!(options[0].value, 0);
        assert_eq!(options[4].name, "CI_QUALITY");
        assert_eq!(options[4].value, 4);
    }
}
