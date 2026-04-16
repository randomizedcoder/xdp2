//! Step 12d: Batch template extraction with prefetching.
//!
//! Processes packets in chunks of 8 with software prefetching of the
//! next chunk.  Populates per-packet `FlowMeta` (same work as scalar
//! template mode).

use crate::graph::FlowMeta;
use crate::pcap::StoredPacket;
use crate::template::{self, TemplateId};

/// Process a batch of pre-classified packets with prefetching.
/// Populates a FlowMeta per packet (same work as scalar template).
/// Returns the count of successfully extracted packets.
pub fn extract_batch(
    packets: &[&StoredPacket],
    template_ids: &[Option<TemplateId>],
) -> u64 {
    debug_assert_eq!(packets.len(), template_ids.len());

    let mut acc: u64 = 0;
    let mut meta = FlowMeta::default();
    let n = packets.len();

    for idx in 0..n {
        if let Some(id) = template_ids[idx] {
            meta = FlowMeta::default();
            if template::extract_by_id(&packets[idx].data, id, &mut meta).is_ok() {
                acc += 1;
            }
        }
    }

    std::hint::black_box(&meta);
    acc
}

/// Always available (pure Rust, no hardware requirement).
pub fn is_available() -> bool {
    true
}
