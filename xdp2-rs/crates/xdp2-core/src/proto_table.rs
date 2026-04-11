//! Protocol table — maps protocol numbers to parse nodes (graph edges).
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `ProtoTableEntry` | `parser_types.h:244-247` | `struct xdp2_proto_table_entry` |
//! | `ProtoTable` | `parser_types.h:254-257` | `struct xdp2_proto_table` |
//! | `ProtoTable::lookup` | `parser.c:38-48` | `lookup_node()` |

use crate::parse_node::ParseNodeDyn;

/// One entry in a protocol table: maps a protocol number to a parse node.
///
/// Reimplements: `struct xdp2_proto_table_entry` in `parser_types.h:244-247`
pub struct ProtoTableEntry<M: 'static> {
    /// Protocol number (e.g., ETH_P_IP = 0x0800, IPPROTO_TCP = 6)
    pub value: i32,
    /// Parse node for this protocol
    pub node: &'static dyn ParseNodeDyn<M>,
}

/// Protocol table mapping protocol numbers to parse nodes.
///
/// Reimplements: `struct xdp2_proto_table` in `parser_types.h:254-257`
///
/// The table is searched via linear scan, matching the C implementation's
/// approach for cache locality with small tables (typically < 16 entries).
pub struct ProtoTable<M: 'static> {
    pub entries: &'static [ProtoTableEntry<M>],
}

impl<M: 'static> ProtoTable<M> {
    /// Look up a parse node by protocol number.
    ///
    /// Reimplements: `lookup_node()` in `src/lib/xdp2/parser.c:38-48`
    ///
    /// Uses linear scan for cache locality, matching the C implementation.
    /// Returns `None` if the protocol number is not found.
    ///
    /// ## Differences from C
    /// - Returns `Option<&dyn ParseNodeDyn>` instead of `struct xdp2_parse_node *`
    ///   (NULL → None)
    pub fn lookup(&self, proto: i32) -> Option<&'static dyn ParseNodeDyn<M>> {
        for entry in self.entries {
            if entry.value == proto {
                return Some(entry.node);
            }
        }
        None
    }

    /// Number of entries in the table.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Convenience macro for building a static protocol table.
///
/// Reimplements: `XDP2_MAKE_PROTO_TABLE` macro in `parser.h:198-205`
///
/// # Example
/// ```ignore
/// static ETHER_TABLE: ProtoTable<MyMeta> = proto_table![
///     (0x0800_i32.to_be(), &IPV4_NODE),
///     (0x86DD_i32.to_be(), &IPV6_NODE),
/// ];
/// ```
#[macro_export]
macro_rules! proto_table {
    ( $( ($value:expr, $node:expr) ),* $(,)? ) => {
        $crate::proto_table::ProtoTable {
            entries: &[
                $( $crate::proto_table::ProtoTableEntry { value: $value, node: $node } ),*
            ]
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_table_returns_none() {
        let table = ProtoTable::<()> { entries: &[] };
        assert!(table.lookup(0x0800).is_none());
        assert!(table.is_empty());
    }
}
