//! Graphviz DOT output for parse graphs.
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `to_dot` | `graph.h:dotify()` | Graphviz export function |
//!
//! ## Behavioral Differences
//! - Uses `petgraph::dot::Dot` for formatting instead of manual string building.
//! - Adds color coding: encap nodes are blue, overlay nodes are green, leaf nodes are red.

use std::fmt::Write as FmtWrite;

use petgraph::visit::EdgeRef;

use crate::graph::ParseGraph;

/// Generate Graphviz DOT representation of the parse graph.
///
/// Reimplements: `dotify()` in `graph.h`
pub fn to_dot(pg: &ParseGraph) -> String {
    let mut out = String::new();
    writeln!(out, "digraph parse_graph {{").unwrap();
    writeln!(out, "    rankdir=LR;").unwrap();
    writeln!(
        out,
        "    node [shape=box, style=filled, fillcolor=lightyellow];"
    )
    .unwrap();
    writeln!(out).unwrap();

    // Nodes
    for idx in pg.graph.node_indices() {
        let v = &pg.graph[idx];
        let color = if v.encap {
            "lightblue"
        } else if v.overlay {
            "lightgreen"
        } else if pg.graph.edges(idx).next().is_none() {
            "lightsalmon"
        } else {
            "lightyellow"
        };
        writeln!(
            out,
            "    {} [label=\"{}\\nmin_len={}\", fillcolor={}];",
            idx.index(),
            v.name,
            v.min_hdr_length,
            color,
        )
        .unwrap();
    }

    writeln!(out).unwrap();

    // Edges
    for edge in pg.graph.edge_references() {
        let e = edge.weight();
        writeln!(
            out,
            "    {} -> {} [label=\"{}\"];",
            edge.source().index(),
            edge.target().index(),
            e.key_str,
        )
        .unwrap();
    }

    writeln!(out, "}}").unwrap();
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::ParserIr;

    #[test]
    fn dot_output() {
        let ir = ParserIr::from_json(
            r#"{
            "parse-nodes": [
                {"name": "eth", "min-hdr-length": 14, "next-proto": {
                    "field-off": 12, "field-len": 2,
                    "ents": [{"key": "0x0800", "node": "ipv4"}]
                }},
                {"name": "ipv4", "min-hdr-length": 20}
            ]
        }"#,
        )
        .unwrap();
        let g = ParseGraph::from_ir(&ir);
        let dot = to_dot(&g);
        assert!(dot.contains("digraph parse_graph"));
        assert!(dot.contains("eth"));
        assert!(dot.contains("ipv4"));
        assert!(dot.contains("0x0800"));
    }
}
