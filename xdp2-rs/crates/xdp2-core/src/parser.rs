//! Top-level parser definition — the entry point for parse graph execution.
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `ParserConfig` | `parser_types.h:301-312` | `struct xdp2_parser_config` |
//! | `Parser` | `parser_types.h:320-327` | `struct xdp2_parser` |

use crate::parse_node::ParseNodeDyn;
use crate::types::ParserType;

/// Parser configuration — limits and special nodes.
///
/// Reimplements: `struct xdp2_parser_config` in `parser_types.h:301-312`
pub struct ParserConfig<M: 'static> {
    /// Maximum number of nodes to visit before stopping (prevents infinite loops)
    pub max_nodes: u16,
    /// Maximum encapsulation depth
    pub max_encaps: u16,
    /// Maximum metadata frames (one per encapsulation layer)
    pub max_frames: u16,
    /// Size of the "metameta" header in metadata
    pub metameta_size: usize,
    /// Size of each metadata frame
    pub frame_size: usize,
    /// Number of 8-bit counters available
    pub num_counters: u8,
    /// Number of keys available for inter-node communication
    pub num_keys: u8,
    /// Node called on successful parse completion (optional)
    pub okay_node: Option<&'static dyn ParseNodeDyn<M>>,
    /// Node called on parse failure (optional)
    pub fail_node: Option<&'static dyn ParseNodeDyn<M>>,
    /// Node called at encapsulation boundary (optional)
    pub atencap_node: Option<&'static dyn ParseNodeDyn<M>>,
}

impl<M: 'static> Default for ParserConfig<M> {
    fn default() -> Self {
        Self {
            max_nodes: 32,
            max_encaps: 4,
            max_frames: 8,
            metameta_size: 0,
            frame_size: 0,
            num_counters: 0,
            num_keys: 0,
            okay_node: None,
            fail_node: None,
            atencap_node: None,
        }
    }
}

/// A complete parser definition — root node plus configuration.
///
/// Reimplements: `struct xdp2_parser` in `parser_types.h:320-327`
///
/// The type parameter `M` is the user-defined metadata type. This replaces
/// C's `void *metadata` with compile-time type safety.
pub struct Parser<M: 'static> {
    /// Human-readable parser name
    pub name: &'static str,
    /// Parser configuration (limits, special nodes)
    pub config: ParserConfig<M>,
    /// Root parse node — parsing begins here
    pub root_node: &'static dyn ParseNodeDyn<M>,
    /// Parser algorithm type
    pub parser_type: ParserType,
}
