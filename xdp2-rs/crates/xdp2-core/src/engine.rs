//! The runtime parsing engine — main parse loop.
//!
//! This is the single most important file in the Rust reimplementation.
//! It contains `parse()`, the main loop that walks the parse graph
//! node-by-node through a packet.
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `parse()` | `parser.c:461-701` | `__xdp2_parse()` |
//! | `ParseOutput` | (no direct equivalent) | Return value + metadata |
//! | Callback ordering | `parser.c:509-516` | Comment block documenting order |
//!
//! ## Callback Ordering Contract
//!
//! Per-node processing follows this order (matching `parser.c:509-516`):
//!
//! 1. `proto_def.ops.len()` — determine header length
//! 2. `parse_node.ops.extract_metadata()` — extract fields into metadata
//! 3. `parse_node.ops.handler()` — arbitrary per-protocol processing
//! 4. TLV/flag-fields/array sub-parsing (if `node_type != Plain`)
//! 5. `parse_node.ops.post_handler()` — post-processing
//! 6. `proto_def.ops.next_proto()` — determine next protocol number
//! 7. Protocol table lookup — find next node
//!
//! ## Differences from C
//!
//! - `do { ... } while(1)` + `goto out` → `loop { ... break 'parse }` with named label
//! - `void *hdr` pointer arithmetic → `&packet[offset..]` slice windowing
//! - Integer return codes → `Result<ParseOutput, ParseError>`
//! - Bounds checking is automatic via Rust slices (no manual `check_pkt_len`)

use crate::parse_node::ParseNodeDyn;
use crate::parser::Parser;
use crate::types::{CtrlData, CtrlKeyData, ParseError, ParseResult};

/// Output of a successful parse operation.
#[derive(Debug)]
pub struct ParseOutput<M> {
    /// User-defined metadata populated during parsing
    pub metadata: M,
    /// Control data with parse statistics
    pub ctrl: CtrlData,
    /// The final parse result code
    pub result: ParseResult,
}

/// Parse a packet through the parse graph.
///
/// Reimplements: `__xdp2_parse()` in `src/lib/xdp2/parser.c:461-701`
///
/// This is the main entry point for packet parsing. It walks the parse graph
/// starting from the parser's root node, applying protocol operations and
/// callbacks at each node, until it reaches a leaf node, encounters an error,
/// or hits the max_nodes limit.
///
/// # Arguments
/// - `parser`: The parser definition (root node + configuration)
/// - `packet`: Raw packet bytes
///
/// # Returns
/// - `Ok(ParseOutput)` on successful parse (including `StopOkay`)
/// - `Err(ParseError)` on parse failure
///
/// # Callback Ordering
/// At each node, callbacks execute in this order:
/// 1. Length check (min_len, then ops.header_len)
/// 2. extract_metadata
/// 3. handler
/// 4. Sub-structure parsing (TLVs, flag-fields, arrays) — not yet implemented
/// 5. post_handler
/// 6. next_proto → table lookup
pub fn parse<M: Default>(
    parser: &Parser<M>,
    packet: &[u8],
) -> Result<ParseOutput<M>, ParseError> {
    let mut metadata = M::default();
    let mut ctrl = CtrlData {
        key: CtrlKeyData {
            counters: vec![0u8; parser.config.num_counters as usize],
            keys: vec![0u32; parser.config.num_keys as usize],
        },
        ..Default::default()
    };
    ctrl.pkt.pkt_len = packet.len();

    let mut offset: usize = 0;
    let mut node: &dyn ParseNodeDyn<M> = parser.root_node;
    let mut nodes_remaining = parser.config.max_nodes;
    let mut encaps: u8 = 0;

    let result: ParseResult = 'parse: loop {
        let remaining = packet.len().saturating_sub(offset);

        // 1. Check minimum length
        if remaining < node.min_len() {
            return Err(ParseError::Length);
        }
        let hdr = &packet[offset..];

        // Determine actual header length
        let hdr_len = node.header_len(hdr, remaining)?;
        if hdr_len < node.min_len() || hdr_len > remaining {
            return Err(ParseError::Length);
        }

        let hdr_bytes = &hdr[..hdr_len];

        // 2. Extract metadata
        node.extract_metadata(hdr_bytes, hdr_len, &mut metadata, &ctrl);

        // 3. Handler
        node.handler(hdr_bytes, hdr_len, &mut metadata, &ctrl)?;

        // 4. Sub-structure parsing (TLVs, flag-fields, arrays)
        //
        // Reimplements: `switch (parse_node->node_type)` in `parser.c:528-575`
        //
        // Wrapper node types (ParseTlvsNode, ParseFlagFieldsNode, ParseArrayNode)
        // override sub_parse() to dispatch to their respective parsing functions.
        // Plain nodes return Ok(()) immediately.
        node.sub_parse(hdr_bytes, hdr_len, &mut metadata, &ctrl)?;

        // 5. Post-handler
        node.post_handler(hdr_bytes, hdr_len, &mut metadata, &ctrl)?;

        // 6. Determine next protocol
        let proto_table = match node.proto_table() {
            Some(table) => table,
            None => {
                // Leaf node — parsing complete
                break 'parse ParseResult::Okay;
            }
        };

        let proto = match node.next_proto(hdr) {
            Ok(proto) => proto,
            Err(ParseError::UnknownProto) => {
                // next_proto returning UnknownProto means "stop okay" in leaf context
                break 'parse ParseResult::StopOkay;
            }
            Err(e) => return Err(e),
        };

        // Check for special return codes encoded as negative proto values
        if proto < 0 {
            match ParseResult::from_c_code(proto) {
                Some(ParseResult::StopOkay) => break 'parse ParseResult::StopOkay,
                Some(ParseResult::UseWild) => {
                    // Use wildcard node
                    match node.wildcard_node() {
                        Some(wild) => {
                            if !node.is_overlay() {
                                offset += hdr_len;
                            }
                            node = wild;
                            nodes_remaining = nodes_remaining
                                .checked_sub(1)
                                .ok_or(ParseError::MaxNodes)?;
                            ctrl.var.node_cnt += 1;
                            continue;
                        }
                        None => return Err(node.unknown_ret()),
                    }
                }
                _ => {
                    if let Some(err) = ParseError::from_c_code(proto) {
                        return Err(err);
                    }
                    break 'parse ParseResult::StopOkay;
                }
            }
        }

        // 7. Protocol table lookup
        let next_node = proto_table
            .lookup(proto)
            .or_else(|| node.wildcard_node())
            .ok_or(node.unknown_ret())?;

        // Handle encapsulation
        if node.is_encap() {
            encaps += 1;
            if encaps > parser.config.max_encaps as u8 {
                return Err(ParseError::EncapDepth);
            }
            ctrl.var.encaps = encaps;
        }

        // Advance packet pointer (skip for overlay nodes)
        if !node.is_overlay() {
            offset += hdr_len;
        }

        // Check node count limit
        nodes_remaining = nodes_remaining
            .checked_sub(1)
            .ok_or(ParseError::MaxNodes)?;
        ctrl.var.node_cnt += 1;
        node = next_node;
    };

    Ok(ParseOutput {
        metadata,
        ctrl,
        result,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse_node::{ParseNode, ParseNodeOps};
    use crate::parser::{Parser, ParserConfig};
    use crate::proto_def::ProtocolOps;

    struct TestLeafOps;
    impl ProtocolOps for TestLeafOps {
        const MIN_LEN: usize = 4;
        const NAME: &'static str = "TestLeaf";
        fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
            Err(ParseError::UnknownProto)
        }
    }

    #[test]
    fn parse_empty_packet_fails() {
        // Create a minimal parser with just a leaf node
        static LEAF: ParseNode<(), TestLeafOps> = ParseNode {
            proto: TestLeafOps,
            ops: ParseNodeOps {
                extract_metadata: None,
                handler: None,
                post_handler: None,
            },
            proto_table: None,
            wildcard_node: None,
            unknown_ret: ParseError::UnknownProto,
            name: "leaf",
        };

        let parser = Parser {
            name: "test",
            config: ParserConfig::default(),
            root_node: &LEAF,
            parser_type: crate::types::ParserType::Generic,
        };

        let result = parse(&parser, &[]);
        assert_eq!(result.unwrap_err(), ParseError::Length);
    }

    #[test]
    fn parse_leaf_node_succeeds() {
        static LEAF: ParseNode<(), TestLeafOps> = ParseNode {
            proto: TestLeafOps,
            ops: ParseNodeOps {
                extract_metadata: None,
                handler: None,
                post_handler: None,
            },
            proto_table: None,
            wildcard_node: None,
            unknown_ret: ParseError::UnknownProto,
            name: "leaf",
        };

        let parser = Parser {
            name: "test",
            config: ParserConfig::default(),
            root_node: &LEAF,
            parser_type: crate::types::ParserType::Generic,
        };

        // 4 bytes is enough for TestLeafOps (MIN_LEN = 4)
        let result = parse(&parser, &[0u8; 4]).unwrap();
        assert_eq!(result.result, ParseResult::Okay);
    }
}
