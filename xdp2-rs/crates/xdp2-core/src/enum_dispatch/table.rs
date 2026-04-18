//! Enum-dispatch protocol table. Identical shape to
//! [`crate::proto_table::ProtoTable`] but entries store `&'static N`
//! instead of `&'static dyn ParseNodeDyn`.

use core::marker::PhantomData;

use crate::enum_dispatch::node::NodeOps;

pub struct ProtoTableEntryEnum<M: 'static, N: NodeOps<M>> {
    pub value: i32,
    pub node: &'static N,
    pub _marker: PhantomData<fn() -> M>,
}

pub struct ProtoTableEnum<M: 'static, N: NodeOps<M>> {
    pub entries: &'static [ProtoTableEntryEnum<M, N>],
    pub _marker: PhantomData<fn() -> M>,
}

impl<M: 'static, N: NodeOps<M>> ProtoTableEnum<M, N> {
    /// Linear-scan lookup. Matches the C/dyn implementation — tables are
    /// small (<16 entries) and cache locality beats hashing.
    #[inline]
    pub fn lookup(&self, proto: i32) -> Option<&'static N> {
        for entry in self.entries {
            if entry.value == proto {
                return Some(entry.node);
            }
        }
        None
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Convenience macro for building a static enum-dispatch table.
///
/// ```ignore
/// static IPV4_TABLE: ProtoTableEnum<FlowMeta, BenchNode<FlowMeta>> = proto_table_enum![
///     (6, &BenchNode::Tcp),
///     (17, &BenchNode::Udp),
/// ];
/// ```
#[macro_export]
macro_rules! proto_table_enum {
    ( $( ($value:expr, $node:expr) ),* $(,)? ) => {
        $crate::enum_dispatch::table::ProtoTableEnum {
            entries: &[
                $( $crate::enum_dispatch::table::ProtoTableEntryEnum {
                    value: $value,
                    node: $node,
                    _marker: ::core::marker::PhantomData,
                } ),*
            ],
            _marker: ::core::marker::PhantomData,
        }
    };
}
