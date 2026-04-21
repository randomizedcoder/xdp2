//! Parse graph construction and algorithms.
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `VertexProp` | `graph.h:195-323` | `vertex_property` |
//! | `EdgeProp` | `graph.h:325-330` | `edge_property` |
//! | `ParseGraph` | `graph.h:754-757` | `graph_t` (Boost adjacency_list) |
//! | `ParseGraph::from_ir` | `graph_consumer.h` | AST consumer + connect_vertices |
//! | `ParseGraph::back_edges` | `graph.h:back_edges()` | Cycle detection via BFS |
//! | `ParseGraph::vertex_levels` | `graph.h:vertice_levels()` | BFS depth leveling |
//!
//! ## Behavioral Differences
//! - Uses `petgraph::DiGraph` instead of Boost `adjacency_list`.
//! - Graph is built from JSON IR rather than Clang AST.

use std::collections::HashMap;

use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::EdgeRef;

use crate::ir::{self, ParserIr};

/// Vertex (node) properties in the parse graph.
///
/// Reimplements: `vertex_property` in `graph.h:195-323`
#[derive(Debug, Clone)]
pub struct VertexProp {
    pub name: String,
    pub min_hdr_length: usize,
    pub overlay: bool,
    pub encap: bool,
    pub handler: Option<String>,
    pub metadata: Option<String>,
    pub post_handler: Option<String>,
    pub unknown_proto_ret: Option<i32>,
    pub wildcard_proto_node: Option<String>,

    /// Header length extraction (None = fixed at min_hdr_length).
    pub hdr_length: Option<ir::HdrLengthDef>,

    /// Next protocol extraction.
    pub next_proto: Option<ir::NextProtoDef>,

    /// TLV parsing configuration.
    pub tlvs: Option<ir::TlvsParseNodeDef>,

    /// Flag-fields parsing configuration.
    pub flag_fields: Option<ir::FlagFieldsParseNodeDef>,

    /// Array parsing configuration.
    pub array: Option<ir::ArrayParseNodeDef>,
}

/// Edge properties in the parse graph.
///
/// Reimplements: `edge_property` in `graph.h:325-330`
#[derive(Debug, Clone)]
pub struct EdgeProp {
    /// Dispatch key as string (e.g., "0x0800", "6").
    pub key_str: String,
    /// Dispatch key as numeric value.
    pub key_value: i64,
}

/// The parse graph — a directed graph of protocol nodes.
///
/// Reimplements: `graph_t` in `graph.h:754-757`
pub struct ParseGraph {
    pub graph: DiGraph<VertexProp, EdgeProp>,
    /// Map from node name to graph index for fast lookup.
    pub name_to_idx: HashMap<String, NodeIndex>,
    /// Parser configurations.
    pub parsers: Vec<ir::ParserDef>,
    /// Named protocol tables (for reference).
    pub proto_tables: HashMap<String, Vec<ir::ProtoTableEntry>>,
    /// Named TLV tables.
    pub tlv_tables: HashMap<String, Vec<ir::TlvTableEntry>>,
}

impl ParseGraph {
    /// Build a parse graph from Parser IR.
    ///
    /// Reimplements: `graph_consumer` + `connect_vertices()` in
    /// `graph_consumer.h` and `processing_utilities.h`
    pub fn from_ir(ir: &ParserIr) -> Self {
        let mut graph = DiGraph::new();
        let mut name_to_idx = HashMap::new();

        // Phase 1: Create vertices for all parse nodes.
        for node_def in &ir.parse_nodes {
            let prop = VertexProp {
                name: node_def.name.clone(),
                min_hdr_length: node_def.min_hdr_length,
                overlay: node_def.overlay,
                encap: node_def.encap,
                handler: node_def.handler.clone(),
                metadata: node_def.metadata.clone(),
                post_handler: node_def.post_handler.clone(),
                unknown_proto_ret: node_def.unknown_proto_ret,
                wildcard_proto_node: node_def.wildcard_proto_node.clone(),
                hdr_length: node_def.hdr_length.clone(),
                next_proto: node_def.next_proto.clone(),
                tlvs: node_def.tlvs_parse_node.clone(),
                flag_fields: node_def.flag_fields_parse_node.clone(),
                array: node_def.array_parse_node.clone(),
            };
            let idx = graph.add_node(prop);
            name_to_idx.insert(node_def.name.clone(), idx);
        }

        // Build proto table lookup.
        let mut proto_tables: HashMap<String, Vec<ir::ProtoTableEntry>> = HashMap::new();
        for table in &ir.proto_tables {
            proto_tables.insert(table.name.clone(), table.entries.clone());
        }

        // Phase 2: Create edges from dispatch entries.
        // Reimplements: connect_vertices() in processing_utilities.h
        for node_def in &ir.parse_nodes {
            let src_idx = name_to_idx[&node_def.name];

            // Collect entries from inline next_proto and/or named table.
            let mut entries: Vec<&ir::ProtoTableEntry> = Vec::new();

            if let Some(ref np) = node_def.next_proto {
                entries.extend(np.ents.iter());
            }
            if let Some(ref table_name) = node_def.table {
                if let Some(table_entries) = proto_tables.get(table_name) {
                    entries.extend(table_entries.iter());
                }
            }

            for entry in entries {
                if let Some(&dst_idx) = name_to_idx.get(&entry.node) {
                    let key_value = entry.key_value().unwrap_or(0);
                    let key_str = match &entry.key {
                        serde_json::Value::String(s) => s.clone(),
                        serde_json::Value::Number(n) => n.to_string(),
                        _ => String::new(),
                    };
                    graph.add_edge(src_idx, dst_idx, EdgeProp { key_str, key_value });
                }
            }
        }

        // Build TLV table lookup.
        let mut tlv_tables = HashMap::new();
        for table in &ir.tlv_tables {
            tlv_tables.insert(table.name.clone(), table.entries.clone());
        }

        ParseGraph {
            graph,
            name_to_idx,
            parsers: ir.parsers.clone(),
            proto_tables,
            tlv_tables,
        }
    }

    /// Find a vertex by name.
    ///
    /// Reimplements: `find_vertex_by_name()` in `graph.h`
    pub fn find_vertex(&self, name: &str) -> Option<NodeIndex> {
        self.name_to_idx.get(name).copied()
    }

    /// Get vertex properties by name.
    pub fn vertex_prop(&self, name: &str) -> Option<&VertexProp> {
        self.find_vertex(name).map(|idx| &self.graph[idx])
    }

    /// Number of vertices.
    pub fn node_count(&self) -> usize {
        self.graph.node_count()
    }

    /// Number of edges.
    pub fn edge_count(&self) -> usize {
        self.graph.edge_count()
    }

    /// Detect back edges (cycles) using DFS.
    ///
    /// Reimplements: `back_edges()` in `graph.h`
    pub fn has_cycles(&self) -> bool {
        petgraph::algo::is_cyclic_directed(&self.graph)
    }

    /// Compute BFS depth levels from a root node.
    ///
    /// Reimplements: `vertice_levels()` in `graph.h`
    pub fn vertex_levels(&self, root: NodeIndex) -> HashMap<NodeIndex, u32> {
        let mut levels = HashMap::new();
        let mut bfs = petgraph::visit::Bfs::new(&self.graph, root);
        levels.insert(root, 0);

        while let Some(node) = bfs.next(&self.graph) {
            let my_level = levels[&node];
            for edge in self.graph.edges(node) {
                let target = edge.target();
                levels.entry(target).or_insert(my_level + 1);
            }
        }
        levels
    }

    /// Get outgoing edges for a vertex (dispatch table).
    pub fn outgoing_edges(&self, idx: NodeIndex) -> Vec<(&EdgeProp, &VertexProp)> {
        self.graph
            .edges(idx)
            .map(|e| (e.weight(), &self.graph[e.target()]))
            .collect()
    }

    /// Get leaf nodes (nodes with no outgoing edges).
    pub fn leaf_nodes(&self) -> Vec<NodeIndex> {
        self.graph
            .node_indices()
            .filter(|&idx| self.graph.edges(idx).next().is_none())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_ir() -> ParserIr {
        ParserIr::from_json(
            r#"{
            "parsers": [{"name": "test", "root-node": "eth"}],
            "parse-nodes": [
                {"name": "eth", "min-hdr-length": 14, "next-proto": {
                    "field-off": 12, "field-len": 2,
                    "ents": [
                        {"key": "0x0800", "node": "ipv4"},
                        {"key": "0x86DD", "node": "ipv6"}
                    ]
                }},
                {"name": "ipv4", "min-hdr-length": 20, "next-proto": {
                    "field-off": 9, "field-len": 1,
                    "ents": [{"key": 6, "node": "tcp"}, {"key": 17, "node": "udp"}]
                }},
                {"name": "ipv6", "min-hdr-length": 40},
                {"name": "tcp", "min-hdr-length": 20},
                {"name": "udp", "min-hdr-length": 8}
            ]
        }"#,
        )
        .unwrap()
    }

    #[test]
    fn build_graph() {
        let ir = sample_ir();
        let g = ParseGraph::from_ir(&ir);
        assert_eq!(g.node_count(), 5);
        assert_eq!(g.edge_count(), 4); // eth→ipv4, eth→ipv6, ipv4→tcp, ipv4→udp
    }

    #[test]
    fn find_vertex() {
        let g = ParseGraph::from_ir(&sample_ir());
        assert!(g.find_vertex("eth").is_some());
        assert!(g.find_vertex("tcp").is_some());
        assert!(g.find_vertex("nonexistent").is_none());
    }

    #[test]
    fn vertex_properties() {
        let g = ParseGraph::from_ir(&sample_ir());
        let eth = g.vertex_prop("eth").unwrap();
        assert_eq!(eth.min_hdr_length, 14);
        let ipv4 = g.vertex_prop("ipv4").unwrap();
        assert_eq!(ipv4.min_hdr_length, 20);
    }

    #[test]
    fn no_cycles() {
        let g = ParseGraph::from_ir(&sample_ir());
        assert!(!g.has_cycles());
    }

    #[test]
    fn vertex_levels() {
        let g = ParseGraph::from_ir(&sample_ir());
        let root = g.find_vertex("eth").unwrap();
        let levels = g.vertex_levels(root);
        assert_eq!(levels[&root], 0);
        assert_eq!(levels[&g.find_vertex("ipv4").unwrap()], 1);
        assert_eq!(levels[&g.find_vertex("tcp").unwrap()], 2);
    }

    #[test]
    fn leaf_nodes() {
        let g = ParseGraph::from_ir(&sample_ir());
        let leaves = g.leaf_nodes();
        assert_eq!(leaves.len(), 3); // ipv6, tcp, udp
    }

    #[test]
    fn outgoing_edges() {
        let g = ParseGraph::from_ir(&sample_ir());
        let eth_idx = g.find_vertex("eth").unwrap();
        let edges = g.outgoing_edges(eth_idx);
        assert_eq!(edges.len(), 2);
    }

    #[test]
    fn cycle_detection() {
        let ir = ParserIr::from_json(
            r#"{
            "parse-nodes": [
                {"name": "a", "min-hdr-length": 1, "next-proto": {
                    "field-off": 0, "field-len": 1, "ents": [{"key": 1, "node": "b"}]
                }},
                {"name": "b", "min-hdr-length": 1, "next-proto": {
                    "field-off": 0, "field-len": 1, "ents": [{"key": 1, "node": "a"}]
                }}
            ]
        }"#,
        )
        .unwrap();
        let g = ParseGraph::from_ir(&ir);
        assert!(g.has_cycles());
    }
}
