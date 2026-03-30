//! XDP2 proto_def C header extractor.
//!
//! Parses XDP2 proto_def headers to extract protocol-level metadata:
//! name, min_len, ops (next_proto, len), and variants.
//!
//! XDP2 proto_defs don't define fields directly — they reference kernel
//! structs via `sizeof(struct ...)` and use helper functions that cast
//! to kernel types. So this extractor yields protocol metadata rather
//! than field-level detail.

use anyhow::{Context, Result};
use regex::Regex;
use std::collections::BTreeMap;
use std::path::Path;

use crate::ir::{ProtocolDef, SourceInfo};

/// Metadata extracted from a single XDP2 proto_def.
#[derive(Debug, Clone)]
pub struct Xdp2ProtoDef {
    /// Variable name (e.g., "xdp2_parse_ipv4")
    pub var_name: String,
    /// Display name from .name field (e.g., "IPv4")
    pub display_name: String,
    /// Kernel struct used for sizeof (e.g., "iphdr")
    pub kernel_struct: Option<String>,
    /// Whether it has a .ops.next_proto function
    pub has_next_proto: bool,
    /// The next_proto function name (e.g., "ipv4_proto")
    pub next_proto_fn: Option<String>,
    /// Whether it has a .ops.len function (variable length)
    pub has_len: bool,
    /// The len function name
    pub len_fn: Option<String>,
    /// Whether it's a TLV-based protocol
    pub is_tlv: bool,
    /// Whether it has .overlay = 1
    pub is_overlay: bool,
    /// Source file path (relative to proto_defs/)
    pub file_path: String,
    /// Linux kernel header include (e.g., "linux/ip.h")
    pub kernel_include: Option<String>,
}

/// Extract all proto_defs from a single header file.
pub fn extract_from_file(path: &Path) -> Result<Vec<Xdp2ProtoDef>> {
    let content =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    extract_from_source(&content, path)
}

/// Extract proto_defs from source text.
pub fn extract_from_source(content: &str, path: &Path) -> Result<Vec<Xdp2ProtoDef>> {
    let file_path = path
        .file_name()
        .map(|f| f.to_string_lossy().to_string())
        .unwrap_or_default();

    // Extract kernel includes (e.g., #include <linux/ip.h>)
    let include_re = Regex::new(r#"#include\s+<(linux/[^>]+)>"#)?;
    let kernel_include = include_re
        .captures_iter(content)
        .map(|c| c[1].to_string())
        .next();

    let mut defs = Vec::new();

    // Match xdp2_proto_def structs
    // Pattern: static const struct xdp2_proto_def VARNAME __unused() = {
    //   .name = "NAME",
    //   .min_len = sizeof(struct STRUCT),
    //   ...
    // };
    let def_re = Regex::new(
        r"(?s)static\s+const\s+struct\s+(xdp2_proto_(?:def|tlvs_def))\s+(\w+)\s+__unused\(\)\s*=\s*\{(.*?)\};"
    )?;

    let name_re = Regex::new(r#"\.(?:proto_def\.)?name\s*=\s*"([^"]+)""#)?;
    let sizeof_re = Regex::new(r"sizeof\(struct\s+(\w+)\)")?;
    let next_proto_re = Regex::new(r"\.(?:proto_def\.)?ops\.next_proto\s*=\s*(\w+)")?;
    let len_re = Regex::new(r"\.(?:proto_def\.)?ops\.len\s*=\s*(\w+)")?;
    let overlay_re = Regex::new(r"\.overlay\s*=\s*1")?;

    for cap in def_re.captures_iter(content) {
        let struct_type = &cap[1];
        let var_name = cap[2].to_string();
        let body = &cap[3];

        let display_name = name_re
            .captures(body)
            .map(|c| c[1].to_string())
            .unwrap_or_else(|| var_name.clone());

        let kernel_struct = sizeof_re.captures(body).map(|c| c[1].to_string());

        let next_proto_fn = next_proto_re.captures(body).map(|c| c[1].to_string());
        let has_next_proto = next_proto_fn.is_some();

        let len_fn = len_re.captures(body).map(|c| c[1].to_string());
        let has_len = len_fn.is_some();

        let is_tlv = struct_type == "xdp2_proto_tlvs_def";
        let is_overlay = overlay_re.is_match(body);

        defs.push(Xdp2ProtoDef {
            var_name,
            display_name,
            kernel_struct,
            has_next_proto,
            next_proto_fn,
            has_len,
            len_fn,
            is_tlv,
            is_overlay,
            file_path: file_path.clone(),
            kernel_include: kernel_include.clone(),
        });
    }

    Ok(defs)
}

/// Scan the XDP2 proto_defs directory and extract all definitions.
pub fn scan_proto_defs_dir(proto_defs_dir: &Path) -> Result<Vec<Xdp2ProtoDef>> {
    let mut all_defs = Vec::new();

    fn visit_dir(dir: &Path, base: &Path, all_defs: &mut Vec<Xdp2ProtoDef>) -> Result<()> {
        if !dir.is_dir() {
            return Ok(());
        }
        let mut entries: Vec<_> = std::fs::read_dir(dir)?
            .filter_map(|e| e.ok())
            .collect();
        entries.sort_by_key(|e| e.file_name());

        for entry in entries {
            let path = entry.path();
            if path.is_dir() {
                visit_dir(&path, base, all_defs)?;
            } else if path
                .extension()
                .map_or(false, |e| e == "h")
            {
                let mut file_defs = extract_from_file(&path)?;
                // Adjust file_path to be relative to proto_defs base
                let rel = path
                    .strip_prefix(base)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .to_string();
                for d in &mut file_defs {
                    d.file_path = rel.clone();
                }
                all_defs.append(&mut file_defs);
            }
        }
        Ok(())
    }

    visit_dir(proto_defs_dir, proto_defs_dir, &mut all_defs)?;
    Ok(all_defs)
}

/// Convert an Xdp2ProtoDef into a partial ProtocolDef (XDP2 source only).
pub fn to_protocol_def(xdp2_def: &Xdp2ProtoDef) -> ProtocolDef {
    let min_header_bytes = crate::name_mapping::find_by_xdp2_name(&xdp2_def.var_name)
        .map(|p| p.min_header_bytes)
        .unwrap_or(0);

    let mut notes = Vec::new();
    if xdp2_def.is_tlv {
        notes.push("TLV-based protocol definition".to_string());
    }
    if xdp2_def.is_overlay {
        notes.push("Overlay parse node (version check)".to_string());
    }
    if let Some(ref f) = xdp2_def.next_proto_fn {
        notes.push(format!("next_proto via {}", f));
    }
    if let Some(ref f) = xdp2_def.len_fn {
        notes.push(format!("variable length via {}", f));
    }
    notes.push(
        "Fields come from kernel struct, not defined in proto_def directly".to_string(),
    );

    ProtocolDef {
        name: xdp2_def.display_name.clone(),
        min_header_bits: min_header_bytes * 8,
        is_variable_length: xdp2_def.has_len,
        fields: vec![], // XDP2 doesn't define fields directly
        dispatch_field: None,
        dispatch_table: vec![],
        identifiers: BTreeMap::new(),
        sources: BTreeMap::from([(
            "xdp2".to_string(),
            SourceInfo {
                present: true,
                file_path: Some(xdp2_def.file_path.clone()),
                source_name: xdp2_def.var_name.clone(),
                field_count: 0,
                min_header_bytes,
                notes,
            },
        )]),
        generation_source: None,
        standards: vec![],
        iana_registries: BTreeMap::new(),
        layer: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_IPV4: &str = r#"
#ifndef __PROTO_IPV4_H__
#define __PROTO_IPV4_H__

#include "xdp2/bpf_compat.h"
#include <linux/ip.h>
#include "xdp2/parser.h"

static inline size_t ipv4_len(const void *viph) {
    return ((struct iphdr *)viph)->ihl * 4;
}

static inline int ipv4_proto(const void *viph) {
    return ((struct iphdr *)viph)->protocol;
}

#endif /* __PROTO_IPV4_H__ */

#ifdef XDP2_DEFINE_PARSE_NODE

static const struct xdp2_proto_def xdp2_parse_ipv4 __unused() = {
    .name = "IPv4",
    .min_len = sizeof(struct iphdr),
    .ops.len = ipv4_length,
    .ops.next_proto = ipv4_proto,
};

static const struct xdp2_proto_def xdp2_parse_ipv4_check __unused() = {
    .name = "IPv4-check",
    .min_len = sizeof(struct iphdr),
    .ops.len = ipv4_length_check,
    .ops.next_proto = ipv4_proto,
    .overlay = 1,
};

#endif /* XDP2_DEFINE_PARSE_NODE */
"#;

    #[test]
    fn test_extract_ipv4() {
        let defs =
            extract_from_source(SAMPLE_IPV4, Path::new("ip/proto_ipv4.h")).unwrap();
        assert_eq!(defs.len(), 2);

        let ipv4 = &defs[0];
        assert_eq!(ipv4.var_name, "xdp2_parse_ipv4");
        assert_eq!(ipv4.display_name, "IPv4");
        assert_eq!(ipv4.kernel_struct, Some("iphdr".to_string()));
        assert!(ipv4.has_next_proto);
        assert_eq!(ipv4.next_proto_fn, Some("ipv4_proto".to_string()));
        assert!(ipv4.has_len);
        assert!(!ipv4.is_overlay);
        assert!(!ipv4.is_tlv);
        assert_eq!(ipv4.kernel_include, Some("linux/ip.h".to_string()));

        let check = &defs[1];
        assert_eq!(check.var_name, "xdp2_parse_ipv4_check");
        assert!(check.is_overlay);
    }

    const SAMPLE_TCP: &str = r#"
#include <linux/tcp.h>

#ifdef XDP2_DEFINE_PARSE_NODE

static const struct xdp2_proto_tlvs_def xdp2_parse_tcp_tlvs __unused() = {
    .proto_def.node_type = XDP2_NODE_TYPE_TLVS,
    .proto_def.name = "TCP with TLVs",
    .proto_def.min_len = sizeof(struct tcphdr),
    .proto_def.ops.len = tcp_len,
};

static const struct xdp2_proto_def xdp2_parse_tcp_notlvs __unused() = {
    .name = "TCP without TLVs",
    .min_len = sizeof(struct tcphdr),
    .ops.len = tcp_len,
};

#endif
"#;

    #[test]
    fn test_extract_tcp() {
        let defs =
            extract_from_source(SAMPLE_TCP, Path::new("transport/proto_tcp.h")).unwrap();
        assert_eq!(defs.len(), 2);

        let tlvs = &defs[0];
        assert_eq!(tlvs.var_name, "xdp2_parse_tcp_tlvs");
        assert!(tlvs.is_tlv);
        assert_eq!(tlvs.display_name, "TCP with TLVs");

        let no_tlvs = &defs[1];
        assert_eq!(no_tlvs.var_name, "xdp2_parse_tcp_notlvs");
        assert!(!no_tlvs.is_tlv);
    }

    const SAMPLE_ETHER: &str = r#"
#include <linux/if_ether.h>

#ifdef XDP2_DEFINE_PARSE_NODE

static const struct xdp2_proto_def xdp2_parse_ether __unused() = {
    .name = "Ethernet",
    .min_len = sizeof(struct ethhdr),
    .ops.next_proto = ether_proto,
};

#endif
"#;

    #[test]
    fn test_extract_ether() {
        let defs =
            extract_from_source(SAMPLE_ETHER, Path::new("ethernet/proto_ether.h")).unwrap();
        assert_eq!(defs.len(), 1);

        let eth = &defs[0];
        assert_eq!(eth.var_name, "xdp2_parse_ether");
        assert_eq!(eth.display_name, "Ethernet");
        assert!(eth.has_next_proto);
        assert!(!eth.has_len); // fixed-length header
        assert_eq!(eth.kernel_struct, Some("ethhdr".to_string()));
    }

    #[test]
    fn test_to_protocol_def() {
        let defs =
            extract_from_source(SAMPLE_IPV4, Path::new("ip/proto_ipv4.h")).unwrap();
        let proto = to_protocol_def(&defs[0]);
        assert_eq!(proto.name, "IPv4");
        assert!(proto.is_variable_length);
        assert!(proto.fields.is_empty()); // XDP2 doesn't define fields
        let src = proto.sources.get("xdp2").unwrap();
        assert!(src.present);
        assert_eq!(src.source_name, "xdp2_parse_ipv4");
    }
}
