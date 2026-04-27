//! rdma-core header extractor.
//!
//! Parses rdma-core's libibverbs and libibmad struct definitions to extract
//! InfiniBand protocol field layouts. rdma-core headers use standard C types
//! (`uint8_t`, `__be16`, `__be32`, `__be64`) and `union ibv_gid` (16 bytes).
//!
//! We preprocess the source to normalize these differences, then reuse
//! the kernel struct parser (`parse_kernel_struct` + `to_field_defs_with`)
//! with rdma-specific type mappings loaded from `mappings/rdma.toml`.

use anyhow::Result;
use std::path::Path;

use crate::ir::{ProtocolDef, SourceInfo};
use crate::type_mapping::{self, KernelMappings};

use super::kernel;

/// Preprocess rdma-core header content so the kernel C parser can handle it.
///
/// Normalizes:
/// - `__attribute__((packed))` → stripped
/// - Inlines `union ibv_gid` fields as `uint8_t[16]` for size calculation
fn preprocess_rdma(content: &str) -> String {
    let mut result = String::with_capacity(content.len());

    for line in content.lines() {
        let mut l = line.to_string();

        // Strip __attribute__((packed)) and similar annotations
        l = l.replace("__attribute__((packed))", "");
        l = l.replace("__attribute__ ((packed))", "");

        result.push_str(&l);
        result.push('\n');
    }

    result
}

/// Load rdma-core type mappings (uses KernelMappings schema with rdma types).
pub fn load_rdma_mappings() -> Result<KernelMappings> {
    type_mapping::load_rdma_mappings(None)
}

/// Extract a ProtocolDef from an rdma-core header file for a given struct.
pub fn extract_protocol(
    content: &str,
    struct_name: &str,
    file_path: &str,
) -> Result<Option<ProtocolDef>> {
    let preprocessed = preprocess_rdma(content);

    let ks = match kernel::parse_kernel_struct(&preprocessed, struct_name)? {
        Some(ks) => ks,
        None => return Ok(None),
    };

    let mappings = load_rdma_mappings()?;
    let fields = kernel::to_field_defs_with_content(&ks, &mappings, &preprocessed);
    let total_bits: u32 = fields
        .iter()
        .map(|f| f.offset_bits + f.size_bits)
        .max()
        .unwrap_or(0);
    let field_count = fields.len() as u32;

    Ok(Some(
        ProtocolDef::new(struct_name, total_bits)
            .with_fields(fields)
            .with_source(
                "rdma",
                SourceInfo::new(struct_name)
                    .with_file(file_path)
                    .with_field_count(field_count)
                    .with_min_header_bytes(total_bits / 8),
            ),
    ))
}

/// Scan an rdma-core include directory for protocol struct definitions.
///
/// Returns `(struct_name, header_file)` pairs for each struct found.
pub fn scan_rdma_dir(dir: &Path) -> Result<Vec<(String, String)>> {
    let ib_dir = dir.join("infiniband");
    if !ib_dir.exists() {
        return Ok(Vec::new());
    }

    let mut results = Vec::new();
    let struct_re = regex::Regex::new(r"struct\s+(\w+)\s*\{")?;

    for entry in std::fs::read_dir(&ib_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().map_or(true, |e| e != "h") {
            continue;
        }
        let file_name = format!("infiniband/{}", path.file_name().unwrap().to_string_lossy());
        let content = std::fs::read_to_string(&path)?;
        let preprocessed = preprocess_rdma(&content);

        for cap in struct_re.captures_iter(&preprocessed) {
            let struct_name = cap[1].to_string();
            results.push((struct_name, file_name.clone()));
        }
    }

    results.sort();
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    const RDMA_GRH: &str = r#"
struct ibv_grh {
	__be32			version_tclass_flow;
	__be16			paylen;
	uint8_t			next_hdr;
	uint8_t			hop_limit;
	union ibv_gid		sgid;
	union ibv_gid		dgid;
};
"#;

    const RDMA_UMAD_HDR: &str = r#"
struct umad_hdr {
	uint8_t	 base_version;
	uint8_t	 mgmt_class;
	uint8_t	 class_version;
	uint8_t	 method;
	__be16   status;
	__be16   class_specific;
	__be64   tid;
	__be16   attr_id;
	__be16   resv;
	__be32   attr_mod;
};
"#;

    #[test]
    fn test_extract_rdma_grh() {
        let def = extract_protocol(RDMA_GRH, "ibv_grh", "infiniband/verbs.h")
            .unwrap()
            .unwrap();
        assert_eq!(def.fields.len(), 6);
        assert_eq!(def.min_header_bits, 320); // 40 bytes
        assert_eq!(def.fields[0].name, "version_tclass_flow");
        assert_eq!(def.fields[0].size_bits, 32);
        assert_eq!(def.fields[1].name, "paylen");
        assert_eq!(def.fields[1].size_bits, 16);
        assert_eq!(def.fields[2].name, "next_hdr");
        assert_eq!(def.fields[3].name, "hop_limit");
        assert_eq!(def.fields[4].name, "sgid");
        assert_eq!(def.fields[4].size_bits, 128); // union ibv_gid = 16 bytes
        assert_eq!(def.fields[5].name, "dgid");
        assert_eq!(def.fields[5].size_bits, 128);
    }

    #[test]
    fn test_extract_rdma_umad_hdr() {
        let def = extract_protocol(RDMA_UMAD_HDR, "umad_hdr", "infiniband/umad_types.h")
            .unwrap()
            .unwrap();
        assert_eq!(def.fields.len(), 10);
        assert_eq!(def.min_header_bits, 192); // 24 bytes
        assert_eq!(def.fields[0].name, "base_version");
        assert_eq!(def.fields[0].size_bits, 8);
        assert_eq!(def.fields[6].name, "tid");
        assert_eq!(def.fields[6].size_bits, 64);
    }

    #[test]
    fn test_preprocess_strips_attrs() {
        let input = "struct __attribute__((packed)) foo {";
        let output = preprocess_rdma(input);
        assert!(!output.contains("__attribute__"));
        assert!(output.contains("struct"));
        assert!(output.contains("foo"));
    }
}
