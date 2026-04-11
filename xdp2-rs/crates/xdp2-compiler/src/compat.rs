//! C++ JSON IR compatibility layer.
//!
//! The C++ `xdp2-compiler` (`-o parser.json`) emits JSON with slightly
//! different field names and structure than what the Rust `ParserIr`
//! serde types expect. This module normalizes C++ JSON before parsing.
//!
//! ## C/C++ Cross-Reference
//!
//! | C++ Field | Rust Field | Location |
//! |-----------|------------|----------|
//! | `right-shift` | `shift` | `hdr-length`, `next-proto` |
//! | `start-offset` | `tlv-start-offset` | `tlvs-parse-node` |
//! | `proto-tables[].ents` | `proto-tables[].entries` | proto table entries |
//! | `proto-tables[].ents[].name` | (stripped) | display name, not in Rust IR |
//! | `tlv-nodes` | `tlv-tables` | top-level TLV section |
//! | `file_name` | (stripped) | parser metadata |
//! | `metadata` | (stripped) | metadata transfers |
//! | `counter-actions` | (stripped) | counter action metadata |
//! | `counters` | (stripped) | counter definitions |
//! | `cond-exprs` | (stripped) | conditional expressions |
//! | `next-node` | (stripped) | wildcard next node |
//! | `endian-swap` | (stripped) | next-proto endian swap |

use serde_json::Value;

/// Normalize C++ xdp2-compiler JSON output to match Rust `ParserIr` schema.
///
/// This function performs in-place transformations on the JSON tree to bridge
/// schema differences between the C++ and Rust compilers.
pub fn normalize_cpp_json(raw: &str) -> Result<String, serde_json::Error> {
    let mut root: Value = serde_json::from_str(raw)?;
    normalize_value(&mut root);
    serde_json::to_string_pretty(&root)
}

fn normalize_value(root: &mut Value) {
    let obj = match root.as_object_mut() {
        Some(o) => o,
        None => return,
    };

    // ── Top-level: strip fields Rust IR doesn't model ──────────────
    obj.remove("metadata");
    obj.remove("counters");

    // ── Parsers: strip file_name ───────────────────────────────────
    if let Some(Value::Array(parsers)) = obj.get_mut("parsers") {
        for p in parsers.iter_mut() {
            if let Some(o) = p.as_object_mut() {
                o.remove("file_name");
            }
        }
    }

    // ── Parse nodes ────────────────────────────────────────────────
    if let Some(Value::Array(nodes)) = obj.get_mut("parse-nodes") {
        for node in nodes.iter_mut() {
            normalize_parse_node(node);
        }
    }

    // ── Proto tables: rename "ents" → "entries", strip "name" from entries ──
    if let Some(Value::Array(tables)) = obj.get_mut("proto-tables") {
        for table in tables.iter_mut() {
            normalize_proto_table(table);
        }
    }

    // ── TLV nodes → TLV tables ────────────────────────────────────
    if let Some(tlv_nodes) = obj.remove("tlv-nodes") {
        if let Value::Array(nodes) = tlv_nodes {
            let tables: Vec<Value> = nodes
                .into_iter()
                .map(|mut n| {
                    normalize_tlv_node(&mut n);
                    n
                })
                .collect();
            obj.insert("tlv-tables".to_string(), Value::Array(tables));
        }
    }
}

fn normalize_parse_node(node: &mut Value) {
    let obj = match node.as_object_mut() {
        Some(o) => o,
        None => return,
    };

    // Strip fields Rust doesn't model
    obj.remove("counter-actions");
    obj.remove("cond-exprs");
    obj.remove("next-node");

    // Strip per-node metadata (metadata transfers)
    obj.remove("metadata");

    // ── hdr-length: rename "right-shift" → "shift" ────────────────
    if let Some(hl) = obj.get_mut("hdr-length") {
        rename_field(hl, "right-shift", "shift");
        // Strip flag-fields-length (internal to C++ codegen)
        if let Some(o) = hl.as_object_mut() {
            o.remove("flag-fields-length");
        }
    }

    // ── next-proto: rename "right-shift" → "shift", strip extras ──
    // Extract table name first to avoid double mutable borrow.
    let table_from_np = if let Some(np) = obj.get_mut("next-proto") {
        rename_field(np, "right-shift", "shift");
        if let Some(o) = np.as_object_mut() {
            let table_name = o.remove("table");
            o.remove("endian-swap");
            o.remove("default");
            o.remove("wildcard-node");
            table_name
        } else {
            None
        }
    } else {
        None
    };
    // Move table reference from next-proto up to parse node level.
    if let Some(table_name) = table_from_np {
        obj.insert("table".to_string(), table_name);
    }

    // ── tlvs-parse-node: rename "start-offset" → "tlv-start-offset" ──
    if let Some(tlv) = obj.get_mut("tlvs-parse-node") {
        if let Some(o) = tlv.as_object_mut() {
            // Rename start-offset
            if let Some(val) = o.remove("start-offset") {
                // C++ emits start-offset as an integer; Rust expects tlv-start-offset
                // as a TlvFieldDef. Wrap it if it's a plain integer.
                let wrapped = match val {
                    Value::Number(_) => {
                        // Convert integer to field def with just offset
                        serde_json::json!({
                            "field-off": val,
                            "field-len": 1
                        })
                    }
                    _ => val,
                };
                o.insert("tlv-start-offset".to_string(), wrapped);
            }
            // Strip default/wildcard (handled differently in Rust)
            o.remove("default");
            o.remove("wildcard-node");
            // Rename ents for inline TLV dispatch
            rename_field_in(o, "ents", "table");
            // Strip fields not in Rust TlvsParseNodeDef
            o.remove("max-padding-length");
            o.remove("max-consecutive-padding");
            o.remove("loop-count-exceeded-is-err");
            o.remove("disp-limit-exceeded");
            o.remove("max-non-padding");
            o.remove("padn");
        }
    }

    // ── flag-fields-parse-node: normalize structure ───────────────
    if let Some(ff) = obj.get_mut("flag-fields-parse-node") {
        if let Some(o) = ff.as_object_mut() {
            // C++ uses different field names; strip what Rust doesn't model
            o.remove("flags-reverse-order");
            o.remove("ents");
        }
    }

    // ── handler: C++ wraps in object {name, watchers, blockers}, Rust expects string ──
    if let Some(handler) = obj.get("handler").cloned() {
        if let Some(handler_obj) = handler.as_object() {
            if let Some(name) = handler_obj.get("name") {
                obj.insert("handler".to_string(), name.clone());
            }
        }
    }
}

fn normalize_proto_table(table: &mut Value) {
    let obj = match table.as_object_mut() {
        Some(o) => o,
        None => return,
    };

    // Rename "ents" → "entries"
    if let Some(ents) = obj.remove("ents") {
        if let Value::Array(entries) = ents {
            let cleaned: Vec<Value> = entries
                .into_iter()
                .map(|mut e| {
                    // Strip "name" field (display name, not in Rust ProtoTableEntry)
                    if let Some(o) = e.as_object_mut() {
                        o.remove("name");
                    }
                    e
                })
                .collect();
            obj.insert("entries".to_string(), Value::Array(cleaned));
        }
    }
}

fn normalize_tlv_node(node: &mut Value) {
    let obj = match node.as_object_mut() {
        Some(o) => o,
        None => return,
    };

    // C++ tlv-nodes have "name" and optional "handler", "overlay-node", "metadata"
    // Rust TlvTableDef has "name" and "entries"
    // The overlay-node.ents maps to entries
    if let Some(overlay) = obj.remove("overlay-node") {
        if let Some(overlay_obj) = overlay.as_object() {
            if let Some(ents) = overlay_obj.get("ents") {
                obj.insert("entries".to_string(), ents.clone());
            }
        }
    }

    // Ensure entries exist and normalize field names
    if let Some(Value::Array(entries)) = obj.get_mut("entries") {
        for entry in entries.iter_mut() {
            // C++ TLV ents have "node", Rust TlvTableEntry expects "name"
            if let Some(o) = entry.as_object_mut() {
                if let Some(node_val) = o.remove("node") {
                    if !o.contains_key("name") {
                        o.insert("name".to_string(), node_val);
                    }
                }
            }
        }
    }

    // If no entries from overlay-node, ensure empty entries array
    if !obj.contains_key("entries") {
        obj.insert("entries".to_string(), Value::Array(Vec::new()));
    }

    // Strip metadata (not in Rust TlvTableDef)
    obj.remove("metadata");
    obj.remove("handler");
}

/// Rename a field within a JSON value.
fn rename_field(value: &mut Value, old_name: &str, new_name: &str) {
    if let Some(obj) = value.as_object_mut() {
        if let Some(val) = obj.remove(old_name) {
            obj.insert(new_name.to_string(), val);
        }
    }
}

/// Rename a field within a mutable JSON object map.
fn rename_field_in(
    obj: &mut serde_json::Map<String, Value>,
    old_name: &str,
    new_name: &str,
) {
    if let Some(val) = obj.remove(old_name) {
        obj.insert(new_name.to_string(), val);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::ParserIr;

    #[test]
    fn normalize_right_shift() {
        let cpp_json = r#"{
            "parsers": [{"name": "test", "root-node": "eth", "file_name": "parser.c"}],
            "parse-nodes": [{
                "name": "eth",
                "min-hdr-length": 14,
                "hdr-length": {
                    "field-off": 0,
                    "field-len": 1,
                    "right-shift": 4,
                    "multiplier": 4
                }
            }]
        }"#;

        let normalized = normalize_cpp_json(cpp_json).unwrap();
        let ir = ParserIr::from_json(&normalized).unwrap();
        let eth = ir.find_node("eth").unwrap();
        let hl = eth.hdr_length.as_ref().unwrap();
        assert_eq!(hl.shift, Some(4));
    }

    #[test]
    fn normalize_proto_table_ents() {
        let cpp_json = r#"{
            "parsers": [{"name": "test", "root-node": "eth"}],
            "parse-nodes": [{"name": "eth", "min-hdr-length": 14}],
            "proto-tables": [{
                "name": "eth_table",
                "ents": [
                    {"name": "ipv4", "key": "0x800", "node": "ipv4"},
                    {"name": "ipv6", "key": "0x86dd", "node": "ipv6"}
                ]
            }]
        }"#;

        let normalized = normalize_cpp_json(cpp_json).unwrap();
        let ir = ParserIr::from_json(&normalized).unwrap();
        assert_eq!(ir.proto_tables.len(), 1);
        assert_eq!(ir.proto_tables[0].entries.len(), 2);
        assert_eq!(ir.proto_tables[0].entries[0].node, "ipv4");
    }

    #[test]
    fn strip_unmodeled_fields() {
        let cpp_json = r#"{
            "parsers": [{"name": "test", "root-node": "eth", "file_name": "parser.c"}],
            "parse-nodes": [{
                "name": "eth",
                "min-hdr-length": 14,
                "metadata": {"ents": []},
                "counter-actions": [],
                "cond-exprs": {"ents": []}
            }],
            "metadata": [{"name": "flow_meta"}],
            "counters": [{"name": "counter_1"}]
        }"#;

        let normalized = normalize_cpp_json(cpp_json).unwrap();
        let ir = ParserIr::from_json(&normalized).unwrap();
        assert_eq!(ir.parse_nodes.len(), 1);
        assert_eq!(ir.parse_nodes[0].name, "eth");
    }

    #[test]
    fn normalize_table_from_next_proto() {
        let cpp_json = r#"{
            "parsers": [{"name": "test", "root-node": "eth"}],
            "parse-nodes": [{
                "name": "eth",
                "min-hdr-length": 14,
                "next-proto": {
                    "field-off": 12,
                    "field-len": 2,
                    "table": "ethertype_table",
                    "endian-swap": true
                }
            }],
            "proto-tables": [{
                "name": "ethertype_table",
                "ents": [{"name": "ipv4", "key": "0x800", "node": "ipv4"}]
            }]
        }"#;

        let normalized = normalize_cpp_json(cpp_json).unwrap();
        let ir = ParserIr::from_json(&normalized).unwrap();
        let eth = ir.find_node("eth").unwrap();
        // table reference moved from next-proto to parse node level
        assert_eq!(eth.table.as_deref(), Some("ethertype_table"));
        // next-proto should still exist without the table field
        assert!(eth.next_proto.is_some());
    }

    #[test]
    fn normalize_tlv_nodes_to_tables() {
        let cpp_json = r#"{
            "parsers": [{"name": "test", "root-node": "tcp"}],
            "parse-nodes": [{"name": "tcp", "min-hdr-length": 20}],
            "tlv-nodes": [{
                "name": "tcp_opts",
                "handler": "handle_tcp_opt",
                "overlay-node": {
                    "field-off": 1,
                    "field-len": 1,
                    "ents": [
                        {"key": 2, "node": "tcp_mss"},
                        {"key": 3, "node": "tcp_ws"}
                    ]
                },
                "metadata": {"ents": []}
            }]
        }"#;

        let normalized = normalize_cpp_json(cpp_json).unwrap();
        let ir = ParserIr::from_json(&normalized).unwrap();
        assert_eq!(ir.tlv_tables.len(), 1);
        assert_eq!(ir.tlv_tables[0].name, "tcp_opts");
        assert_eq!(ir.tlv_tables[0].entries.len(), 2);
    }
}
