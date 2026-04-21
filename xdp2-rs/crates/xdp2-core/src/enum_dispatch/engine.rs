//! Enum-dispatch parse engine — monomorphic counterpart to
//! [`crate::engine::parse`].
//!
//! The loop is identical in shape to the dyn-dispatch engine; only the
//! node reference type changes from `&dyn ParseNodeDyn<M>` to `&N` where
//! `N: NodeOps<M>`. At each dispatch point the compiler emits a direct
//! `match` on the concrete enum instead of a vtable indirect call.

use crate::engine::ParseOutput;
use crate::enum_dispatch::node::NodeOps;
use crate::parser::ParserConfig;
use crate::types::{CtrlData, CtrlKeyData, ParseError, ParseResult};

/// Walk the parse graph starting at `root`, matching
/// [`crate::engine::parse`]'s contract.
///
/// Callers typically wrap this in a `Parser`-shaped struct for API
/// parity; the core engine takes the root directly to keep the generic
/// signature simple.
pub fn parse_enum<M: Default + 'static, N: NodeOps<M>>(
    root: &'static N,
    config: &ParserConfig<M>,
    packet: &[u8],
) -> Result<ParseOutput<M>, ParseError> {
    let mut metadata = M::default();
    let mut ctrl = CtrlData {
        key: CtrlKeyData {
            counters: vec![0u8; config.num_counters as usize],
            keys: vec![0u32; config.num_keys as usize],
        },
        ..Default::default()
    };
    ctrl.pkt.pkt_len = packet.len();

    let mut offset: usize = 0;
    let mut node: &N = root;
    let mut nodes_remaining = config.max_nodes;
    let mut encaps: u8 = 0;

    let result: ParseResult = 'parse: loop {
        let remaining = packet.len().saturating_sub(offset);

        if remaining < node.min_len() {
            return Err(ParseError::Length);
        }
        let hdr = &packet[offset..];

        let hdr_len = node.header_len(hdr, remaining)?;
        if hdr_len < node.min_len() || hdr_len > remaining {
            return Err(ParseError::Length);
        }

        let hdr_bytes = &hdr[..hdr_len];

        node.extract_metadata(hdr_bytes, hdr_len, &mut metadata, &ctrl);
        node.handler(hdr_bytes, hdr_len, &mut metadata, &ctrl)?;
        node.sub_parse(hdr_bytes, hdr_len, &mut metadata, &ctrl)?;
        node.post_handler(hdr_bytes, hdr_len, &mut metadata, &ctrl)?;

        let proto_table = match node.proto_table() {
            Some(table) => table,
            None => break 'parse ParseResult::Okay,
        };

        let proto = match node.next_proto(hdr) {
            Ok(p) => p,
            Err(ParseError::UnknownProto) => break 'parse ParseResult::StopOkay,
            Err(e) => return Err(e),
        };

        if proto < 0 {
            match ParseResult::from_c_code(proto) {
                Some(ParseResult::StopOkay) => break 'parse ParseResult::StopOkay,
                Some(ParseResult::UseWild) => match node.wildcard_node() {
                    Some(wild) => {
                        if !node.is_overlay() {
                            offset += hdr_len;
                        }
                        node = wild;
                        nodes_remaining =
                            nodes_remaining.checked_sub(1).ok_or(ParseError::MaxNodes)?;
                        ctrl.var.node_cnt += 1;
                        continue;
                    }
                    None => return Err(node.unknown_ret()),
                },
                _ => {
                    if let Some(err) = ParseError::from_c_code(proto) {
                        return Err(err);
                    }
                    break 'parse ParseResult::StopOkay;
                }
            }
        }

        let next_node = proto_table
            .lookup(proto)
            .or_else(|| node.wildcard_node())
            .ok_or(node.unknown_ret())?;

        if node.is_encap() {
            encaps += 1;
            if encaps > config.max_encaps as u8 {
                return Err(ParseError::EncapDepth);
            }
            ctrl.var.encaps = encaps;
        }

        if !node.is_overlay() {
            offset += hdr_len;
        }

        nodes_remaining = nodes_remaining.checked_sub(1).ok_or(ParseError::MaxNodes)?;
        ctrl.var.node_cnt += 1;
        node = next_node;
    };

    Ok(ParseOutput {
        metadata,
        ctrl,
        result,
    })
}
