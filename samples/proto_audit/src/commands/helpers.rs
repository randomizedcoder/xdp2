use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

use crate::{
    comparator,
    discovery::{self, DiscoveredProtocol, DiscoveryState, Tier, TierFilter},
    extractors, generator, ir, name_mapping, type_mapping, SourcePaths,
};

/// Try to extract a protocol from a single source. Returns None on failure
/// (missing path, protocol not found) rather than hard error.
pub(super) fn try_extract(
    source: &str,
    proto: &str,
    paths: &SourcePaths,
) -> Option<ir::ProtocolDef> {
    match source {
        "xdp2" => {
            let dir = paths.proto_defs_dir.as_ref()?;
            let all_defs = extractors::xdp2::scan_proto_defs_dir(dir).ok()?;
            // Prefer exact var_name match from the name-mapping table when the
            // protocol carries an `.xdp2(...)` slot — canonical names and
            // display strings often diverge (e.g. "ITCH v5 AddOrder" ↔
            // "xdp2_parse_itch_v5_add_order"), so fuzzy substring matches miss.
            let curated_var = name_mapping::find_by_canonical(proto)
                .and_then(|n| n.xdp2);
            let matching = all_defs
                .iter()
                .find(|d| {
                    if let Some(v) = curated_var {
                        return d.var_name == v;
                    }
                    d.display_name.to_lowercase() == proto.to_lowercase()
                        || d.var_name.to_lowercase().contains(&proto.to_lowercase())
                })?;
            Some(extractors::xdp2::to_protocol_def(matching))
        }
        "kernel" => {
            let names = name_mapping::find_by_canonical(proto);
            // Try struct-based extraction from kernel headers
            let struct_result = (|| -> Option<ir::ProtocolDef> {
                let src = paths.kernel_src.as_ref()?;
                let names = names.as_ref()?;
                let struct_name = names.kernel_struct?;
                let header = names.kernel_header?;
                let header_path = src.join(format!("include/uapi/{}", header));
                let header_path = if header_path.exists() {
                    header_path
                } else {
                    let p = src.join(format!("include/{}", header));
                    if p.exists() { p } else { src.join(header) }
                };
                let content = std::fs::read_to_string(&header_path).ok()?;
                let mut def = extractors::kernel::extract_protocol(&content, struct_name, header)
                    .ok()
                    .flatten()?;
                def.name = names.canonical.to_string();
                def.is_variable_length = names.variable_length;
                Some(def)
            })();
            // Fall back to embedded_proto for kernel-defined protocols without C structs
            // (e.g. SK_MEMINFO which is an array indexed by enum constants)
            struct_result.or_else(|| crate::generator::pcap::embedded_proto(proto))
        }
        "scapy" => {
            let helper = paths
                .scapy_helper
                .clone()
                .unwrap_or_else(|| PathBuf::from("helpers/scapy_dump.py"));
            let names = name_mapping::find_by_canonical(proto);
            let scapy_name = names.as_ref().and_then(|n| n.scapy)?;
            let sp =
                extractors::scapy::run_scapy_helper(&helper, scapy_name, &paths.python).ok()?;
            let mut def = extractors::scapy::to_protocol_def(&sp);
            // Use canonical name, not Scapy class name (e.g., "IPv4" not "IP")
            def.name = proto.to_string();
            Some(def)
        }
        "tshark" => {
            let names = name_mapping::find_by_canonical(proto);
            // OMI Lua path: when the protocol has an OMI Lua dissector + sample
            // PCAP, load the Lua dissector at tshark startup so the trading
            // payload is decoded instead of showing up as opaque `data`.
            if let (Some(lua_rel), Some(pcap_rel), Some(lua_dir), Some(pcaps_dir)) = (
                names.as_ref().and_then(|n| n.omi_lua),
                names.as_ref().and_then(|n| n.omi_pcap),
                paths.omi_lua_dir.as_ref(),
                paths.omi_pcaps_dir.as_ref(),
            ) {
                let outer_proto = names.as_ref().and_then(|n| n.tshark).unwrap_or("data");
                let lua_path = lua_dir.join(lua_rel);
                let pcap_path = pcaps_dir.join(pcap_rel);
                let xml = extractors::tshark::run_tshark_with_lua(
                    &pcap_path, &paths.tshark_bin, 1, &lua_path,
                ).ok()?;
                // If the entry names a per-message PDML field, descend into
                // it so extraction yields only the wire layout of that specific
                // message type (not the whole-packet superset).
                let pdml = if let Some(msg_field) =
                    names.as_ref().and_then(|n| n.omi_tshark_field)
                {
                    extractors::tshark::extract_field_as_proto(&xml, outer_proto, msg_field)?
                } else {
                    let packets = extractors::tshark::parse_pdml(&xml).ok()?;
                    extractors::tshark::extract_protocol_from_pdml(&packets, outer_proto)?
                };
                let mut def = extractors::tshark::to_protocol_def(&pdml);
                def.name = proto.to_string();
                return Some(def);
            }
            let pcap_path = paths.pcap.as_ref()?;
            let dissector = names.as_ref().and_then(|n| n.tshark)?;
            let xml = extractors::tshark::run_tshark(pcap_path, &paths.tshark_bin, 10).ok()?;
            let packets = extractors::tshark::parse_pdml(&xml).ok()?;
            let pdml =
                extractors::tshark::extract_protocol_from_pdml(&packets, dissector)?;
            let mut def = extractors::tshark::to_protocol_def(&pdml);
            // Use canonical name, not tshark dissector name
            def.name = proto.to_string();
            Some(def)
        }
        "etherparse" => {
            let src = paths.etherparse_src.as_ref()?;
            let names = name_mapping::find_by_canonical(proto)?;
            let struct_name = names.etherparse_struct?;
            let source_file = names.etherparse_file?;
            let file_path = src.join(source_file);
            let content = std::fs::read_to_string(&file_path).ok()?;
            let mut def = extractors::etherparse::extract_protocol(
                &content, struct_name, source_file,
            )
            .ok()
            .flatten()?;
            def.name = names.canonical.to_string();
            def.is_variable_length = names.variable_length;
            Some(def)
        }
        "libpcap" => {
            let names = name_mapping::find_by_canonical(proto)?;
            let libpcap_name = names.libpcap_name?;
            let libpcap_file = names.libpcap_file?;
            let mappings = type_mapping::load_libpcap_mappings(None).ok()?;
            let mut def = extractors::libpcap::extract_protocol(
                paths.libpcap_src.as_deref(),
                proto,
                libpcap_name,
                libpcap_file,
                &mappings,
            )
            .ok()
            .flatten()?;
            def.name = names.canonical.to_string();
            def.is_variable_length = names.variable_length;
            Some(def)
        }
        "kaitai" => {
            let kaitai_dir = paths.kaitai_dir.as_ref()?;
            // Prefer curated kaitai_file from name mapping for direct path lookup
            let names = name_mapping::find_by_canonical(proto);
            let ksy_path = if let Some(ksy_file) = names.as_ref().and_then(|n| n.kaitai_file) {
                let path = kaitai_dir.join("network").join(ksy_file);
                if path.exists() { Some(path) } else { None }
            } else {
                // Fall back to scanning and display name match
                let ksy_files = extractors::kaitai::scan_kaitai_dir(kaitai_dir).ok()?;
                let proto_lower = proto.to_lowercase();
                ksy_files.into_iter().find(|(name, _)| {
                    name.to_lowercase() == proto_lower
                }).map(|(_, p)| p)
            }?;
            let result = extractors::kaitai::extract_from_ksy(&ksy_path);
            let mut def = result.ok().flatten()?;
            def.name = proto.to_string();
            Some(def)
        }
        "omi" => {
            let names = name_mapping::find_by_canonical(proto)?;
            let omi_struct = names.omi_struct?;
            let omi_file = names.omi_file?;
            let mappings = type_mapping::load_omi_mappings(None).ok()?;
            let mut def = extractors::omi::extract_protocol(
                paths.omi_cstructs_dir.as_deref(),
                proto,
                omi_struct,
                omi_file,
                &mappings,
            )
            .ok()
            .flatten()?;
            def.name = names.canonical.to_string();
            def.is_variable_length = names.variable_length;
            Some(def)
        }
        "suricata" => {
            let suricata_dir = paths.suricata_dir.as_ref()?;
            // Prefer curated suricata_module from name mapping for targeted extraction
            let names = name_mapping::find_by_canonical(proto);
            let curated_module = names.as_ref().and_then(|n| n.suricata_module);
            let modules = extractors::suricata::scan_suricata_dir(suricata_dir).ok()?;
            let search_modules: Vec<_> = if let Some(cm) = curated_module {
                modules.iter().filter(|(m, _)| m == cm).collect()
            } else {
                modules.iter().collect()
            };
            for (module_name, parser_path) in &search_modules {
                if let Ok(protos) = extractors::suricata::extract_from_file(parser_path, module_name) {
                    for (name, mut def) in protos {
                        if name == proto {
                            def.name = proto.to_string();
                            return Some(def);
                        }
                    }
                }
            }
            None
        }
        "dpdk" => {
            let src = paths.dpdk_src.as_ref()?;
            let names = name_mapping::find_by_canonical(proto)?;
            let struct_name = names.dpdk_struct?;
            let header = names.dpdk_header?;
            let header_path = src.join("lib").join("net").join(header);
            let content = std::fs::read_to_string(&header_path).ok()?;
            let mut def = extractors::dpdk::extract_protocol(&content, struct_name, header)
                .ok()
                .flatten()?;
            def.name = names.canonical.to_string();
            def.is_variable_length = names.variable_length;
            Some(def)
        }
        "ndpi" => {
            let src = paths.ndpi_src.as_ref()?;
            let names = name_mapping::find_by_canonical(proto)?;
            let struct_name = names.ndpi_struct?;
            let header = names.ndpi_header?;
            let header_path = src.join(header);
            let content = std::fs::read_to_string(&header_path).ok()?;
            let mut def = extractors::ndpi::extract_protocol(&content, struct_name, header)
                .ok()
                .flatten()?;
            def.name = names.canonical.to_string();
            def.is_variable_length = names.variable_length;
            Some(def)
        }
        "pppd" => {
            let src = paths.pppd_src.as_ref()?;
            let names = name_mapping::find_by_canonical(proto)?;
            let pppd_proto = names.pppd_proto?;
            let mut def = extractors::pppd::extract_protocol(src, pppd_proto)
                .ok()
                .flatten()?;
            def.name = names.canonical.to_string();
            def.is_variable_length = names.variable_length;
            Some(def)
        }
        "rdma" => {
            let src = paths.rdma_src.as_ref()?;
            let names = name_mapping::find_by_canonical(proto)?;
            let struct_name = names.rdma_struct?;
            let header = names.rdma_header?;
            let header_path = src.join(header);
            let content = std::fs::read_to_string(&header_path).ok()?;
            let mut def = extractors::rdma::extract_protocol(&content, struct_name, header)
                .ok()
                .flatten()?;
            def.name = names.canonical.to_string();
            def.is_variable_length = names.variable_length;
            Some(def)
        }
        "xtcp2" => {
            let src = paths.xtcp2_src.as_ref()?;
            let names = name_mapping::find_by_canonical(proto)?;
            let struct_name = names.xtcp2_struct?;
            let mappings = type_mapping::load_xtcp2_mappings(None).ok()?;
            let mut def = extractors::xtcp2::extract_protocol(src, proto, struct_name, &mappings)
                .ok()
                .flatten()?;
            def.name = names.canonical.to_string();
            def.is_variable_length = names.variable_length;
            Some(def)
        }
        "xdp2_headers" => {
            let src = paths.xdp2_headers_dir.as_ref()?;
            let names = name_mapping::find_by_canonical(proto)?;
            let struct_name = names.xdp2_hdr_struct?;
            let header = names.xdp2_hdr_file?;
            let header_path = src.join(header);
            let content = std::fs::read_to_string(&header_path).ok()?;
            let mut def = extractors::xdp2_headers::extract_protocol(&content, struct_name, header)
                .ok()
                .flatten()?;
            def.name = names.canonical.to_string();
            def.is_variable_length = names.variable_length;
            Some(def)
        }
        "ue_spec" => {
            let names = name_mapping::find_by_canonical(proto)?;
            let ue_spec_id = names.ue_spec_id?;
            let mut def = extractors::ue_spec::extract_protocol(ue_spec_id)?;
            def.name = names.canonical.to_string();
            def.is_variable_length = names.variable_length;
            Some(def)
        }
        _ => None,
    }
}

/// Try to extract a Tier 2 (discovered) protocol from a source.
///
/// For discovered protocols, we use tshark_filter/scapy_class/kernel_struct
/// directly from the discovery record instead of going through name_mapping.
pub(super) fn try_extract_discovered(
    source: &str,
    dp: &DiscoveredProtocol,
    paths: &SourcePaths,
) -> Option<ir::ProtocolDef> {
    match source {
        "tshark" => {
            let pcap_path = paths.pcap.as_ref()?;
            let dissector = dp.tshark_filter.as_deref()?;
            let xml = extractors::tshark::run_tshark(pcap_path, &paths.tshark_bin, 10).ok()?;
            let packets = extractors::tshark::parse_pdml(&xml).ok()?;
            let pdml = extractors::tshark::extract_protocol_from_pdml(&packets, dissector)?;
            let mut def = extractors::tshark::to_protocol_def(&pdml);
            def.name = dp.canonical.clone();
            Some(def)
        }
        "scapy" => {
            let helper = paths
                .scapy_helper
                .clone()
                .unwrap_or_else(|| PathBuf::from("helpers/scapy_dump.py"));
            let scapy_name = dp.scapy_class.as_deref()?;
            let sp =
                extractors::scapy::run_scapy_helper(&helper, scapy_name, &paths.python).ok()?;
            let mut def = extractors::scapy::to_protocol_def(&sp);
            def.name = dp.canonical.clone();
            Some(def)
        }
        "kernel" => {
            let src = paths.kernel_src.as_ref()?;
            let struct_name = dp.kernel_struct.as_deref()?;
            let header = dp.kernel_header.as_deref()?;
            let header_path = src.join(format!("include/uapi/{}", header));
            let header_path = if header_path.exists() {
                header_path
            } else {
                let p = src.join(format!("include/{}", header));
                if p.exists() { p } else { src.join(header) }
            };
            let content = std::fs::read_to_string(&header_path).ok()?;
            let mut def = extractors::kernel::extract_protocol(&content, struct_name, header)
                .ok()
                .flatten()?;
            def.name = dp.canonical.clone();
            Some(def)
        }
        "libpcap" => {
            let libpcap_name = dp.libpcap_name.as_deref()?;
            let libpcap_file = dp.libpcap_file.as_deref()?;
            let mappings = type_mapping::load_libpcap_mappings(None).ok()?;
            let mut def = extractors::libpcap::extract_protocol(
                paths.libpcap_src.as_deref(),
                &dp.canonical,
                libpcap_name,
                libpcap_file,
                &mappings,
            )
            .ok()
            .flatten()?;
            def.name = dp.canonical.clone();
            Some(def)
        }
        "kaitai" => {
            let kaitai_dir = paths.kaitai_dir.as_ref()?;
            let kaitai_id = dp.kaitai_id.as_deref().unwrap_or(&dp.canonical);
            let ksy_files = extractors::kaitai::scan_kaitai_dir(kaitai_dir).ok()?;
            let id_lower = kaitai_id.to_lowercase();
            let matched = ksy_files.iter().find(|(name, _)| {
                name.to_lowercase() == id_lower
            });
            let (_, ksy_path) = matched?;
            let mut def = extractors::kaitai::extract_from_ksy(ksy_path).ok().flatten()?;
            def.name = dp.canonical.clone();
            Some(def)
        }
        // xdp2, etherparse not available for discovered protocols
        _ => None,
    }
}

pub(super) const ALL_SOURCES: &[&str] = &["xdp2", "kernel", "scapy", "tshark", "etherparse", "libpcap", "kaitai", "suricata", "omi", "dpdk", "ndpi", "pppd", "rdma", "xtcp2", "xdp2_headers", "ue_spec"];

pub(super) fn parse_source_list(sources: Option<&str>) -> Vec<String> {
    match sources {
        Some(s) => s.split(',').map(|s| s.trim().to_string()).collect(),
        None => ALL_SOURCES.iter().map(|s| s.to_string()).collect(),
    }
}

/// Build a proto map for PCAP stack construction by walking STACK_ROUTES from
/// target back to the root, extracting each protocol along the way.
pub(super) fn build_proto_map(
    target_proto: &str,
    paths: &SourcePaths,
    discovery_state: &DiscoveryState,
) -> std::collections::BTreeMap<String, ir::ProtocolDef> {
    let mut map = std::collections::BTreeMap::new();
    let discovered_protos = discovery::all_protocols(discovery_state);

    // Walk the route from target to root, collecting all protocol names on the path
    let mut protos_needed: Vec<String> = vec![target_proto.to_string()];
    let mut current = target_proto.to_string();
    for _ in 0..10 {
        if generator::is_root(&current) {
            protos_needed.push(current.clone());
            break;
        }
        // Try curated STACK_ROUTES first
        if let Some((_, parent, _, _)) = generator::stack_route_for(&current) {
            protos_needed.push(parent.to_string());
            current = parent.to_string();
        }
        // Then try discovered routes
        else if let Some(route) = try_discovered_route(&current, discovery_state, &discovered_protos) {
            protos_needed.push(route.parent.clone());
            current = route.parent;
        } else {
            break;
        }
    }

    // Try to extract each protocol from available sources
    for proto_name in &protos_needed {
        if let Some(def) = try_extract("kernel", proto_name, paths)
            .or_else(|| try_extract("scapy", proto_name, paths))
            .or_else(|| try_extract("etherparse", proto_name, paths))
        {
            map.insert(proto_name.to_string(), def);
        }
    }
    map
}

/// Try to find a discovered route for a protocol from the tshark registry.
/// Accepts a pre-built protocol map to avoid rebuilding it on every call.
pub(super) fn try_discovered_route(
    proto: &str,
    state: &DiscoveryState,
    discovered_protos: &std::collections::BTreeMap<String, DiscoveredProtocol>,
) -> Option<discovery::routes::StackRoute> {
    let registry = state.tshark.as_ref()?;
    let dp = discovered_protos.get(proto)?;
    let filter = dp.tshark_filter.as_deref()?;
    discovery::routes::discovered_route(filter, registry)
}

/// Build a rich IR ProtocolDef by extracting from available sources and merging.
/// Prefers kernel fields (most accurate struct layout), supplemented by scapy defaults.
pub(super) fn build_rich_ir(proto: &str, paths: &SourcePaths) -> Result<ir::ProtocolDef> {
    // Try each source in priority order
    let source_priority = ["kernel", "xdp2_headers", "ue_spec", "xtcp2", "omi", "scapy", "tshark", "etherparse"];
    let mut best: Option<ir::ProtocolDef> = None;

    for source in &source_priority {
        if let Some(def) = try_extract(source, proto, paths) {
            if best.as_ref().map_or(true, |b| def.fields.len() > b.fields.len()) {
                best = Some(def);
            }
        }
    }

    // If no extractor produced fields, check embedded_proto definitions
    if best.as_ref().map_or(true, |b| b.fields.is_empty()) {
        if let Some(edef) = crate::generator::pcap::embedded_proto(proto) {
            if !edef.fields.is_empty() {
                let mut edef = edef;
                edef.generation_source = Some("embedded".to_string());
                best = Some(edef);
            }
        }
    }

    let mut def = best.or_else(|| {
        // Fallback: minimal def from name mapping
        let names = name_mapping::find_by_canonical(proto)?;
        let mut def = ir::ProtocolDef::new(names.canonical, names.min_header_bytes * 8);
        if names.variable_length {
            def = def.with_variable_length();
        }
        Some(def)
    })
    .context(format!(
        "Unknown protocol: {}. Use --from-json for custom protocols.",
        proto
    ))?;

    // Inject RFC/IEEE/IANA metadata from curated table
    if let Some(names) = name_mapping::find_by_canonical(proto) {
        inject_standards_metadata(&mut def, &names);
    }

    Ok(def)
}

/// Build a rich IR for a discovered (non-curated) protocol.
/// Priority: scapy batch → tshark PDML batch → tshark registry → per-protocol fallback.
pub(super) fn build_rich_ir_discovered(
    dp: &DiscoveredProtocol,
    batch: &BatchCache,
    paths: &SourcePaths,
) -> Result<ir::ProtocolDef> {
    // Try scapy batch first (highest quality for discovered)
    if let Some(mut def) = batch.get("scapy", dp) {
        def.generation_source = Some("scapy-batch".to_string());
        return Ok(def);
    }

    // Try tshark PDML batch (requires PCAP)
    if let Some(mut def) = batch.get("tshark", dp) {
        def.generation_source = Some("tshark-pdml".to_string());
        return Ok(def);
    }

    // Try tshark registry (no PCAP needed, approximate offsets)
    if let Some(def) = batch.get_from_registry(dp) {
        return Ok(def);
    }

    // Per-protocol fallback: try scapy/tshark extraction individually
    if let Some(mut def) = try_extract_discovered("scapy", dp, paths) {
        def.generation_source = Some("scapy-batch".to_string());
        return Ok(def);
    }
    if let Some(mut def) = try_extract_discovered("tshark", dp, paths) {
        def.generation_source = Some("tshark-pdml".to_string());
        return Ok(def);
    }

    anyhow::bail!(
        "Cannot build IR for discovered protocol '{}' — no source available",
        dp.canonical
    )
}

/// Resolve a protocol name to its canonical form and tshark dissector.
/// For discovered-tier protocols, looks up the discovery state.
pub(super) fn resolve_protocol(
    proto: &str,
    tier_filter: TierFilter,
    discovered_protos: &std::collections::BTreeMap<String, DiscoveredProtocol>,
) -> (String, Option<String>) {
    // First try curated lookup
    if let Some(names) = name_mapping::find_by_canonical(proto) {
        return (
            names.canonical.to_string(),
            names.tshark.map(|s| s.to_string()),
        );
    }

    // Try discovery state for tier=all or tier=discovered
    if tier_filter != TierFilter::Curated {
        if let Some(dp) = discovered_protos.get(proto) {
            return (
                dp.canonical.clone(),
                dp.tshark_filter.clone(),
            );
        }
        // Fuzzy match: try case-insensitive
        let lower = proto.to_lowercase();
        for (canonical, dp) in discovered_protos {
            if canonical.to_lowercase() == lower {
                return (
                    dp.canonical.clone(),
                    dp.tshark_filter.clone(),
                );
            }
        }
    }

    (proto.to_string(), None)
}

/// Pre-loaded batch extraction caches (tshark PDML + Scapy dump-all + tshark registry).
/// Loaded once, reused across all discovered protocol extractions.
pub(super) struct BatchCache {
    /// tshark: dissector_name → ProtocolDef (from parsing PCAP once)
    tshark_cache: Option<std::collections::HashMap<String, ir::ProtocolDef>>,
    /// scapy: class_name → ProtocolDef (from --dump-all once)
    scapy_cache: Option<std::collections::HashMap<String, ir::ProtocolDef>>,
    /// tshark registry: filter_name → ProtocolDef (from `tshark -G fields` metadata)
    tshark_registry_cache: Option<std::collections::HashMap<String, ir::ProtocolDef>>,
}

impl BatchCache {
    /// Load batch caches for discovered-tier extraction.
    pub(crate) fn load(paths: &SourcePaths, discovery_state: &DiscoveryState) -> Self {
        // Batch tshark: run tshark once, parse all protocols from PDML
        let tshark_cache = paths.pcap.as_ref().and_then(|pcap_path| {
            eprintln!("  [batch] Pre-parsing tshark PDML...");
            let xml = extractors::tshark::run_tshark(pcap_path, &paths.tshark_bin, 20).ok()?;
            let packets = extractors::tshark::parse_pdml(&xml).ok()?;
            let cache = extractors::tshark::extract_all_protocols_from_pdml(&packets);
            eprintln!("  [batch] Cached {} tshark protocols", cache.len());
            Some(cache)
        });

        // Batch scapy: run --dump-all once
        let scapy_cache = {
            let helper = paths
                .scapy_helper
                .clone()
                .unwrap_or_else(|| PathBuf::from("helpers/scapy_dump.py"));
            eprintln!("  [batch] Running scapy --dump-all...");
            match extractors::scapy::run_scapy_dump_all(&helper, &paths.python) {
                Ok(cache) => {
                    eprintln!("  [batch] Cached {} scapy protocols", cache.len());
                    Some(cache)
                }
                Err(e) => {
                    eprintln!("  [batch] scapy --dump-all failed: {}", e);
                    None
                }
            }
        };

        // Load PCAP corpus PDML files (pre-extracted at Nix build time)
        let tshark_cache = {
            let mut cache = tshark_cache.unwrap_or_default();
            if let Ok(corpus_dir) = std::env::var("PROTO_AUDIT_PCAP_CORPUS") {
                let corpus_path = std::path::Path::new(&corpus_dir);
                if corpus_path.is_dir() {
                    let before = cache.len();
                    if let Ok(entries) = std::fs::read_dir(corpus_path) {
                        for entry in entries.flatten() {
                            let path = entry.path();
                            if path.extension().and_then(|e| e.to_str()) != Some("xml") {
                                continue;
                            }
                            if let Ok(xml) = std::fs::read_to_string(&path) {
                                if let Ok(packets) = extractors::tshark::parse_pdml(&xml) {
                                    let file_protos =
                                        extractors::tshark::extract_all_protocols_from_pdml(
                                            &packets,
                                        );
                                    for (name, def) in file_protos {
                                        cache.entry(name).or_insert(def);
                                    }
                                }
                            }
                        }
                    }
                    let added = cache.len() - before;
                    if added > 0 {
                        eprintln!(
                            "  [batch] Loaded {} new protocols from PCAP corpus ({} total tshark)",
                            added,
                            cache.len()
                        );
                    }
                }
            }
            if cache.is_empty() {
                None
            } else {
                Some(cache)
            }
        };

        // Build tshark registry cache from DiscoveryState
        let tshark_registry_cache = discovery_state.tshark.as_ref().map(|reg| {
            eprintln!("  [batch] Building tshark registry IR cache...");
            let cache = extractors::tshark_registry::registry_to_ir_map(reg);
            eprintln!("  [batch] Cached {} tshark registry protocols", cache.len());
            cache
        });

        BatchCache {
            tshark_cache,
            scapy_cache,
            tshark_registry_cache,
        }
    }

    /// Look up a protocol from the batch cache by source.
    pub(super) fn get(&self, source: &str, dp: &DiscoveredProtocol) -> Option<ir::ProtocolDef> {
        match source {
            "tshark" => {
                let dissector = dp.tshark_filter.as_deref()?;
                let mut def = self.tshark_cache.as_ref()?.get(dissector)?.clone();
                def.name = dp.canonical.clone();
                Some(def)
            }
            "scapy" => {
                let class_name = dp.scapy_class.as_deref()?;
                let mut def = self.scapy_cache.as_ref()?.get(class_name)?.clone();
                def.name = dp.canonical.clone();
                Some(def)
            }
            _ => None,
        }
    }

    /// Look up a protocol from the tshark registry cache.
    pub(super) fn get_from_registry(&self, dp: &DiscoveredProtocol) -> Option<ir::ProtocolDef> {
        let filter = dp.tshark_filter.as_deref()?;
        let mut def = self.tshark_registry_cache.as_ref()?.get(filter)?.clone();
        def.name = dp.canonical.clone();
        def.generation_source = Some("tshark-registry".to_string());
        Some(def)
    }
}

/// Shared helper: run audit across protocols and sources, return AuditResults.
/// Now tier-aware: includes discovered protocols when tier != "curated".
pub(super) fn run_audit(
    protos: Option<&str>,
    sources: Option<&str>,
    tier: &str,
    discovery_state: &DiscoveryState,
    paths: &SourcePaths,
) -> Vec<ir::AuditResult> {
    let source_list = parse_source_list(sources);
    let tier_filter = TierFilter::from_str(tier);

    // Build the protocol list based on tier
    let proto_list: Vec<(String, Option<DiscoveredProtocol>)> = match protos {
        Some(p) => p
            .split(',')
            .map(|s| (s.trim().to_string(), None))
            .collect(),
        None => {
            if tier_filter == TierFilter::Curated {
                // Curated only: use the existing table
                name_mapping::protocol_table()
                    .iter()
                    .map(|p| (p.canonical.to_string(), None))
                    .collect()
            } else {
                // All or Discovered: merge curated + discovered
                let all_protos = discovery::all_protocols(discovery_state);
                all_protos
                    .into_iter()
                    .filter(|(_, dp)| tier_filter.matches(dp.tier))
                    .map(|(name, dp)| (name, Some(dp)))
                    .collect()
            }
        }
    };

    // Pre-load batch caches: always build tshark registry for fallback,
    // and full batch caches if we have discovered protocols.
    let has_discovered = proto_list
        .iter()
        .any(|(_, dp)| dp.as_ref().map(|d| d.tier == Tier::Discovered).unwrap_or(false));

    let needs_batch = has_discovered
        || source_list.contains(&"tshark".to_string())
        || source_list.contains(&"scapy".to_string());

    let batch = if needs_batch {
        Some(BatchCache::load(paths, discovery_state))
    } else {
        None
    };

    let mut results = Vec::new();
    for (proto, dp_opt) in &proto_list {
        let mut extracted: Vec<(String, ir::ProtocolDef)> = Vec::new();

        // Determine if this is a discovered protocol
        let is_discovered = dp_opt
            .as_ref()
            .map(|dp| dp.tier == Tier::Discovered)
            .unwrap_or(false);

        for source in &source_list {
            let def = if is_discovered {
                // For Tier 2, try batch cache first, then fallback to per-protocol
                let from_cache = dp_opt.as_ref().and_then(|dp| {
                    batch.as_ref().and_then(|b| b.get(source, dp))
                });
                from_cache.or_else(|| {
                    dp_opt
                        .as_ref()
                        .and_then(|dp| try_extract_discovered(source, dp, paths))
                })
            } else {
                // For Tier 1, use curated extraction path.
                // For tshark, fall back to registry when PDML has no data.
                let mut def = try_extract(source, proto, paths);
                // Fall back to batch cache for tshark or scapy
                if def.is_none() && (source == "tshark" || source == "scapy") {
                    if let Some(names) = name_mapping::find_by_canonical(proto) {
                        let dp_stub = DiscoveredProtocol {
                            canonical: proto.to_string(),
                            tshark_filter: names.tshark.map(|s| s.to_string()),
                            scapy_class: names.scapy.map(|s| s.to_string()),
                            kernel_struct: None,
                            kernel_header: None,
                            tier: Tier::Curated,
                            estimated_field_count: 0,
                            min_header_bytes: 0,
                            match_confidence: None,
                            match_method: None,
                            validation_tier: None,
                            libpcap_name: None,
                            libpcap_file: None,
                            kaitai_id: None,
                        };
                        if source == "tshark" {
                            // Try corpus PDML cache first (real packet data),
                            // then fall back to tshark registry (approximate)
                            def = batch.as_ref().and_then(|b| b.get("tshark", &dp_stub));
                            if def.is_none() {
                                def = batch.as_ref().and_then(|b| b.get_from_registry(&dp_stub));
                            }
                        } else {
                            // Scapy: try batch cache (from --dump-all)
                            def = batch.as_ref().and_then(|b| b.get("scapy", &dp_stub));
                        }
                    }
                }
                def
            };

            if let Some(d) = def {
                extracted.push((source.clone(), d));
            }
        }

        if extracted.is_empty() {
            continue;
        }

        let refs: Vec<(&str, &ir::ProtocolDef)> = extracted
            .iter()
            .map(|(name, def)| (name.as_str(), def))
            .collect();
        let mut result = comparator::audit_protocol(proto, &refs);

        // Tag the tier in the protocol name for display
        if is_discovered {
            result.protocol = format!("{} [D]", result.protocol);
        }

        results.push(result);
    }

    results
}

/// Apply --compact and --limit filters to audit results.
pub(super) fn apply_filters(
    results: Vec<ir::AuditResult>,
    compact: bool,
    limit: Option<usize>,
) -> Vec<ir::AuditResult> {
    let mut results = if compact {
        results
            .into_iter()
            .filter(|r| r.total_fields > 0)
            .collect()
    } else {
        results
    };

    if let Some(n) = limit {
        results.truncate(n);
    }

    results
}

/// Truncate a string to max_len, appending "..." if truncated.
pub(super) fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else if max_len > 3 {
        format!("{}...", &s[..max_len - 3])
    } else {
        s[..max_len].to_string()
    }
}

/// Inject RFC/IEEE/IANA metadata and layer classification into a ProtocolDef.
pub(super) fn inject_standards_metadata(def: &mut ir::ProtocolDef, names: &name_mapping::ProtocolNames) {
    // Infer protocol layer
    if def.layer.is_none() {
        def.layer = infer_protocol_layer(names.canonical);
    }

    // Add RFC references
    for (i, rfc_num) in names.rfc_numbers.iter().enumerate() {
        let relationship = if i == 0 {
            ir::StandardRelationship::Defines
        } else {
            ir::StandardRelationship::Updates
        };
        def.standards.push(ir::StandardRef {
            id: format!("RFC {}", rfc_num),
            body: ir::StandardBody::Rfc,
            section: None,
            url: Some(format!("https://www.rfc-editor.org/rfc/rfc{}", rfc_num)),
            relationship,
        });
    }

    // Add IEEE references
    for (i, ieee_std) in names.ieee_standards.iter().enumerate() {
        let relationship = if i == 0 {
            ir::StandardRelationship::Defines
        } else {
            ir::StandardRelationship::Updates
        };
        def.standards.push(ir::StandardRef {
            id: format!("IEEE {}", ieee_std),
            body: ir::StandardBody::Ieee,
            section: None,
            url: None,
            relationship,
        });
    }

    // Add IANA registry reference
    if let Some(registry) = names.iana_registry {
        def.iana_registries
            .insert("dispatch".to_string(), registry.to_string());
        def.standards.push(ir::StandardRef {
            id: format!("IANA {}", registry),
            body: ir::StandardBody::Iana,
            section: None,
            url: Some(format!(
                "https://www.iana.org/assignments/{}",
                registry
            )),
            relationship: ir::StandardRelationship::Registry,
        });
    }
}

/// Infer protocol layer from canonical name (avoids needing per-protocol annotation).
pub(super) fn infer_protocol_layer(name: &str) -> Option<ir::ProtocolLayer> {
    let lower = name.to_lowercase();
    match lower.as_str() {
        // L2
        "ethernet" | "vlan" | "qinq" | "pbb" | "stp" | "rstp" | "lldp" | "lacp"
        | "ieee802.1x" | "macsec" | "sll" | "llc" | "snap" | "pppoe" => {
            Some(ir::ProtocolLayer::L2)
        }
        // L3
        "ipv4" | "ipv6" | "arp" | "rarp" | "icmp" | "icmpv6" | "igmp"
        | "ipv6_routing" | "ipv6_fragment" | "ipv6_hopbyhop" | "ipv6_destination"
        | "ipv6_eh" => Some(ir::ProtocolLayer::L3),
        // L4
        "tcp" | "udp" | "sctp" | "dccp" | "udplite" => Some(ir::ProtocolLayer::L4),
        // Tunnel
        "gre" | "vxlan" | "geneve" | "mpls" | "nsh" | "gtp_u" | "gtp_c" | "l2tp"
        | "wireguard" | "lisp" | "erspan" | "ppp" => Some(ir::ProtocolLayer::Tunnel),
        // Security
        "esp" | "ah" | "ipsec" | "tls" | "dtls" | "ikev2" | "eap" => {
            Some(ir::ProtocolLayer::Security)
        }
        // Management
        "bgp" | "ospf" | "isis" | "rip" | "pim" | "bfd" | "ldp" | "rsvp"
        | "snmp" | "radius" | "diameter" | "ntp" => Some(ir::ProtocolLayer::Management),
        // Industrial / IoT
        "mqtt" | "coap" | "modbus_tcp" | "bacnet" | "dnp3" | "zigbee_nwk"
        | "profinet" | "ethercat" | "can" | "can_fd" => Some(ir::ProtocolLayer::Industrial),
        // Storage
        "fc" | "iscsi" | "nvme_tcp" | "roce" => Some(ir::ProtocolLayer::Storage),
        // L7
        "dns" | "dhcp" | "dhcpv6" | "http" | "http2" | "sip" | "rtp" | "rtcp"
        | "stun" | "amqp" | "kafka" => Some(ir::ProtocolLayer::L7),
        _ => None,
    }
}

/// Classify a protocol into XDP2 implementation tiers.
///
/// - Tier 1 (Core): Already in XDP2 proto_defs — needs field enrichment only
/// - Tier 2 (Production): Common transport/tunnel, has kernel struct, not yet in XDP2
/// - Tier 3 (Specialty): Has fields but no kernel struct, or industrial/IoT
/// - Tier 4 (Exclude): Text-based, stateful, no fixed header (HTTP, SIP, TLS post-handshake)
pub(super) fn classify_xdp2_tier(name: &str, dp: &DiscoveredProtocol) -> &'static str {
    let lower = name.to_lowercase();

    // Known text-based/stateful protocols that don't suit XDP/BPF
    const EXCLUDED: &[&str] = &[
        "http", "http2", "http3", "sip", "smtp", "ftp", "imap", "pop3",
        "ssh", "telnet", "xmpp", "rtsp",
    ];
    if EXCLUDED.iter().any(|e| lower == *e) {
        return "4-exclude";
    }

    // Tier 1: Already has an XDP2 proto_def
    if name_mapping::find_by_canonical(name)
        .map(|n| n.xdp2.is_some())
        .unwrap_or(false)
    {
        return "1-core";
    }

    // Tier 2: Has kernel struct (easy C generation)
    if dp.kernel_struct.is_some() {
        return "2-production";
    }

    // Tier 3: Has fields, no kernel struct
    if dp.estimated_field_count > 0 || dp.tier == Tier::Curated {
        return "3-specialty";
    }

    "4-exclude"
}

pub(super) struct PriorityBreakdown {
    pub(super) xdp2_relevance: f64,
    pub(super) source_coverage: f64,
    pub(super) parseability: f64,
    pub(super) prevalence: f64,
    pub(super) has_xdp2: bool,
    pub(super) has_kernel: bool,
    pub(super) is_fixed_length: bool,
    pub(super) tier: String,
}

pub(super) fn score_protocol(
    name: &str,
    dp: &DiscoveredProtocol,
    xdp2_protos: &std::collections::HashSet<String>,
    dispatch_parents: &std::collections::HashSet<&str>,
) -> PriorityBreakdown {
    let lower = name.to_lowercase();

    // XDP2 relevance (0–40)
    let has_xdp2 = xdp2_protos.contains(&lower);
    let is_dispatch_parent = dispatch_parents.contains(lower.as_str());
    let xdp2_relevance = if has_xdp2 && is_dispatch_parent {
        40.0 // Existing XDP2 protocol + dispatch parent
    } else if has_xdp2 {
        35.0 // Existing XDP2 protocol
    } else if is_dispatch_parent {
        30.0 // Not in XDP2 yet, but is a dispatch parent
    } else if dp.kernel_struct.is_some() {
        20.0 // Has kernel struct = easy to generate
    } else if dp.tier == Tier::Curated {
        15.0 // Curated but no kernel struct
    } else {
        5.0 // Discovered only
    };

    // Source coverage (0–30)
    let mut source_count = 0u32;
    if dp.tshark_filter.is_some() {
        source_count += 1;
    }
    if dp.scapy_class.is_some() {
        source_count += 1;
    }
    if dp.kernel_struct.is_some() {
        source_count += 1;
    }
    if dp.tier == Tier::Curated {
        source_count += 1; // curated = at least one additional source
    }
    let source_coverage = (source_count as f64 / 4.0) * 30.0;

    // Parseability (0–20): fixed-length protocols are BPF-friendly
    let is_fixed = dp.min_header_bytes > 0;
    let has_fields = dp.estimated_field_count > 0 || dp.tier == Tier::Curated;
    let parseability = if is_fixed && has_fields {
        20.0
    } else if has_fields {
        12.0
    } else if is_fixed {
        8.0
    } else {
        2.0
    };

    // Prevalence (0–10): common protocol families score higher
    let prevalence = if matches!(
        lower.as_str(),
        "ethernet" | "ipv4" | "ipv6" | "tcp" | "udp" | "arp" | "icmp" | "dns" | "dhcp" | "vlan"
    ) {
        10.0
    } else if matches!(
        lower.as_str(),
        "gre" | "mpls" | "vxlan" | "geneve" | "sctp" | "icmpv6" | "igmp" | "ospf" | "bgp"
        | "rip" | "ppp" | "pppoe" | "http" | "tls" | "stp" | "lldp" | "ntp"
    ) {
        7.0
    } else if dp.tier == Tier::Curated {
        4.0
    } else {
        1.0
    };

    PriorityBreakdown {
        xdp2_relevance,
        source_coverage,
        parseability,
        prevalence,
        has_xdp2,
        has_kernel: dp.kernel_struct.is_some(),
        is_fixed_length: is_fixed,
        tier: dp.tier.to_string(),
    }
}

// ── Validation Cache ──

/// Cache file for validation results.
/// Stored as a JSON map from protocol name → validation entry.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(super) struct ValidationCacheEntry {
    pub(super) validation_tier: String,
    pub(super) fields_agree: u32,
    pub(super) total_fields: u32,
    pub(super) fields_mismatch: u32,
    pub(super) timestamp: String,
}

/// Default path for the validation cache file.
pub(super) fn validation_cache_path() -> PathBuf {
    std::env::var("PROTO_AUDIT_VALIDATION_CACHE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let mut p = std::env::current_dir().unwrap_or_default();
            p.push("validation_cache.json");
            p
        })
}

pub(super) fn save_validation_result(protocol: &str, result: &ir::AuditResult) -> Result<()> {
    let path = validation_cache_path();
    let mut cache: std::collections::BTreeMap<String, ValidationCacheEntry> =
        if path.exists() {
            let data = std::fs::read_to_string(&path)?;
            serde_json::from_str(&data).unwrap_or_default()
        } else {
            std::collections::BTreeMap::new()
        };

    let tier_str = result
        .validation_tier
        .as_ref()
        .map(|t| t.to_string())
        .unwrap_or_else(|| "Unvalidated".to_string());

    // Don't downgrade: if protocol is already at a higher tier in cache,
    // only overwrite if the new result is equal or better.
    let tier_rank = |s: &str| -> u8 {
        match s {
            "Gold" => 4,
            "Silver" => 3,
            "Bronze" => 2,
            "Unvalidated" => 1,
            _ => 0,
        }
    };
    if let Some(existing) = cache.get(protocol) {
        if tier_rank(&existing.validation_tier) > tier_rank(&tier_str) {
            // Existing result is better — keep it
            return Ok(());
        }
    }

    cache.insert(
        protocol.to_string(),
        ValidationCacheEntry {
            validation_tier: tier_str,
            fields_agree: result.fields_agree,
            total_fields: result.total_fields,
            fields_mismatch: result.fields_mismatch,
            timestamp: chrono_timestamp(),
        },
    );

    std::fs::write(&path, serde_json::to_string_pretty(&cache)?)?;
    Ok(())
}

/// Load the validation cache, returning a map of protocol → ValidationTier.
pub(super) fn load_validation_cache() -> std::collections::BTreeMap<String, discovery::ValidationTier> {
    let path = validation_cache_path();
    if !path.exists() {
        return std::collections::BTreeMap::new();
    }
    let data = match std::fs::read_to_string(&path) {
        Ok(d) => d,
        Err(_) => return std::collections::BTreeMap::new(),
    };
    let cache: std::collections::BTreeMap<String, ValidationCacheEntry> =
        match serde_json::from_str(&data) {
            Ok(c) => c,
            Err(_) => return std::collections::BTreeMap::new(),
        };
    cache
        .into_iter()
        .filter_map(|(name, entry)| {
            let tier = match entry.validation_tier.as_str() {
                "Gold" => discovery::ValidationTier::Gold,
                "Silver" => discovery::ValidationTier::Silver,
                "Bronze" => discovery::ValidationTier::Bronze,
                _ => discovery::ValidationTier::Unvalidated,
            };
            Some((name, tier))
        })
        .collect()
}

pub(super) fn chrono_timestamp() -> String {
    use std::time::SystemTime;
    let dur = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs();
    // Simple epoch-seconds timestamp (precise enough for cache tracking)
    format!("{}", secs)
}

/// Recursively scan files with a given extension, calling `f` with file contents.
pub(super) fn scan_files_recursive(dir: &Path, ext: &str, f: &mut dyn FnMut(&str)) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            scan_files_recursive(&path, ext, f);
        } else if path.extension().map_or(false, |e| e == ext) {
            if let Ok(content) = std::fs::read_to_string(&path) {
                f(&content);
            }
        }
    }
}
