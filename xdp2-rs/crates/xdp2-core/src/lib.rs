//! # xdp2-core — XDP2 Parse Graph Engine
//!
//! Core types, traits, and runtime for the XDP2 packet parsing framework.
//!
//! This crate reimplements the XDP2 parse engine in Rust, providing:
//! - Protocol operation traits ([`ProtocolOps`])
//! - Parse graph node types ([`ParseNode`], [`ProtoTable`])
//! - The main parse loop ([`engine::parse`])
//! - TLV, flag-fields, and array sub-parsing systems
//!
//! ## C/C++ Cross-Reference
//!
//! | Crate Module | C/C++ Source |
//! |-------------|-------------|
//! | `types` | `src/include/xdp2/parser_types.h` (enums, ctrl structs) |
//! | `proto_def` | `src/include/xdp2/parser_types.h:133-161` (proto_def, parse_ops) |
//! | `parse_node` | `src/include/xdp2/parser_types.h:221-281` (parse_node, ops) |
//! | `proto_table` | `src/include/xdp2/parser_types.h:244-257` (proto_table) |
//! | `parser` | `src/include/xdp2/parser_types.h:301-327` (parser, config) |
//! | `engine` | `src/lib/xdp2/parser.c:461-701` (__xdp2_parse) |
//! | `tlvs` | `src/include/xdp2/tlvs.h` + `parser.c:50-296` |
//! | `flag_fields` | `src/include/xdp2/flag_fields.h` + `parser.c:298-358` |
//! | `arrays` | `src/include/xdp2/arrays.h` + `parser.c:360-448` |

pub mod arrays;
pub mod engine;
pub mod flag_fields;
pub mod parse_node;
pub mod parser;
pub mod proto_def;
pub mod proto_table;
pub mod tlvs;
pub mod types;

// Experimental enum-dispatch engine — gated behind the `enum-dispatch`
// feature so the default dyn-dispatch path is unaffected.
#[cfg(feature = "enum-dispatch")]
pub mod enum_dispatch;

// Re-export key types at crate root for convenience
pub use arrays::{ParseArrayNode, parse_array};
pub use engine::{parse, ParseOutput};
pub use flag_fields::{ParseFlagFieldsNode, parse_flag_fields};
pub use parse_node::{ParseNode, ParseNodeDyn, ParseNodeOps};
pub use parser::{Parser, ParserConfig};
pub use proto_def::ProtocolOps;
pub use proto_table::ProtoTable;
pub use tlvs::{ParseTlvsNode, parse_tlvs};
pub use types::{CtrlData, NodeType, ParseError, ParseResult, ParserType};
