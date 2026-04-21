//! Step 3b: Batch SIMD packet parser prototype (AVX2).
//!
//! Processes 8 packets in parallel using AVX2 256-bit integer operations.
//! The Eth/IPv4/TCP fast path runs entirely in SIMD; packets that diverge
//! (non-IPv4, non-TCP, variable IHL, etc.) fall back to the scalar
//! compiled parser.
//!
//! Populates FlowMeta with the same metadata extractors as graph mode,
//! ensuring honest apples-to-apples benchmarking. The SIMD stages handle
//! classification; metadata extraction is scalar per-packet.
//!
//! ## Theory
//!
//! A single packet parse is a serial dependent-load chain: read ethertype
//! → branch → read IP proto → branch → done. The CPU can overlap packets
//! via out-of-order execution, but the ROB window limits how many chains
//! fly concurrently. SIMD sidesteps this by reading the same field from
//! 8 packets in one instruction via `vpgatherdd`.
//!
//! ## Limitations
//!
//! - Only the Eth→IPv4→TCP/UDP/ICMP fast path is accelerated.
//! - VLAN/IPv6/extension headers always fall back to scalar.
//! - Gather throughput varies by µarch (Zen 2: one 256-bit gather per 5 cycles).

#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

use crate::graph::{AddrType, FlowMeta};
use crate::graph_compiled;
use crate::pcap::StoredPacket;

/// Parse a batch of packets using AVX2 SIMD for the fast path, with
/// scalar fallback for divergent packets. Returns the count of
/// successfully parsed packets.
///
/// # Safety
/// Requires AVX2 support. Caller must check `is_x86_feature_detected!("avx2")`.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
pub unsafe fn parse_batch_avx2(packets: &[&StoredPacket], meta: &mut FlowMeta) -> u64 {
    let mut acc: u64 = 0;
    let n = packets.len();
    let full_chunks = n / 8;

    for i in 0..full_chunks {
        let chunk = &packets[i * 8..(i + 1) * 8];
        // Prefetch next chunk's packet headers into L1 cache.
        // Each prefetch brings in 64 bytes (one cache line), covering
        // the full Eth+IPv4+L4 header for the fast path.
        if i + 1 < full_chunks {
            for j in 0..8 {
                _mm_prefetch(
                    packets[(i + 1) * 8 + j].data.as_ptr() as *const i8,
                    _MM_HINT_T0,
                );
            }
        }
        acc += parse_8_avx2(chunk, meta);
    }

    // Tail: scalar fallback for remaining packets.
    for pkt in &packets[full_chunks * 8..] {
        *meta = FlowMeta::default();
        if graph_compiled::parse_packet(&pkt.data, meta).is_ok() {
            acc += 1;
        }
    }

    acc
}

/// Extract metadata for a fast-path Eth/IPv4 packet (scalar, after SIMD classification).
#[inline]
fn extract_fast_path_meta(ptr: *const u8, len: usize, protocol: u8, meta: &mut FlowMeta) {
    *meta = FlowMeta::default();

    // Ethernet metadata (bytes 0..14)
    unsafe {
        meta.eth_addrs[..12].copy_from_slice(std::slice::from_raw_parts(ptr, 12));
    }
    meta.eth_proto = 0x0800; // IPv4

    // IPv4 metadata (bytes 14..34)
    unsafe {
        let ip = ptr.add(14);
        let frag_off = u16::from_be_bytes([*ip.add(6), *ip.add(7)]);
        if (frag_off & 0x3FFF) != 0 {
            meta.is_fragment = true;
            meta.first_frag = (frag_off & 0x1FFF) == 0;
        }
        meta.addr_type = AddrType::Ipv4;
        meta.ip_proto = *ip.add(9);
        meta.addrs.v4_src =
            u32::from_be_bytes([*ip.add(12), *ip.add(13), *ip.add(14), *ip.add(15)]);
        meta.addrs.v4_dst =
            u32::from_be_bytes([*ip.add(16), *ip.add(17), *ip.add(18), *ip.add(19)]);
    }

    // Transport leaf metadata (bytes 34+)
    let l4_off = 34usize; // 14 (Eth) + 20 (IPv4 IHL=5)
    if l4_off >= len {
        return;
    }
    unsafe {
        let l4 = ptr.add(l4_off);
        match protocol {
            6 | 17 | 132 => {
                // TCP, UDP, SCTP — extract ports
                meta.ports.src_port = u16::from_be_bytes([*l4, *l4.add(1)]);
                meta.ports.dst_port = u16::from_be_bytes([*l4.add(2), *l4.add(3)]);
            }
            1 => {
                // ICMPv4 — extract type/code/id
                meta.icmp.icmp_type = *l4;
                meta.icmp.code = *l4.add(1);
                let t = *l4;
                if t == 0 || t == 8 {
                    meta.icmp.id = u16::from_be_bytes([*l4.add(4), *l4.add(5)]);
                }
            }
            _ => {}
        }
    }
}

/// Process exactly 8 packets with AVX2 gather + comparison.
///
/// Fast path: Eth (14B) → IPv4 (IHL=5, 20B) → leaf (TCP/UDP/ICMP).
/// Any packet that doesn't match this exact path gets scalar fallback.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
#[inline]
unsafe fn parse_8_avx2(chunk: &[&StoredPacket], meta: &mut FlowMeta) -> u64 {
    debug_assert_eq!(chunk.len(), 8);

    // Minimum packet length for the fast path: 14 (Eth) + 20 (IPv4) + 8 (UDP min) = 42
    const MIN_FAST_PATH: usize = 42;

    // Collect packet data pointers and lengths.
    let mut ptrs: [*const u8; 8] = [std::ptr::null(); 8];
    let mut lens: [usize; 8] = [0; 8];
    for i in 0..8 {
        ptrs[i] = chunk[i].data.as_ptr();
        lens[i] = chunk[i].data.len();
    }

    // ── Stage 1: Length check (scalar, fast) ──
    // Build a bitmask of packets long enough for fast path.
    let mut long_enough: u8 = 0;
    for i in 0..8 {
        if lens[i] >= MIN_FAST_PATH {
            long_enough |= 1 << i;
        }
    }

    if long_enough == 0 {
        // All too short — scalar fallback for all.
        return scalar_fallback_all(chunk, meta);
    }

    // ── Stage 2: Gather ethertypes from offset 12-13 (big-endian u16) ──
    let mut ethertypes = [0u16; 8];
    for i in 0..8 {
        if long_enough & (1 << i) != 0 {
            // Read big-endian u16 at offset 12.
            ethertypes[i] = u16::from_be_bytes([*ptrs[i].add(12), *ptrs[i].add(13)]);
        }
    }

    // ── Stage 3: Compare ethertypes == 0x0800 (IPv4) ──
    let ethertype_vec = _mm256_set_epi32(
        ethertypes[7] as i32,
        ethertypes[6] as i32,
        ethertypes[5] as i32,
        ethertypes[4] as i32,
        ethertypes[3] as i32,
        ethertypes[2] as i32,
        ethertypes[1] as i32,
        ethertypes[0] as i32,
    );
    let ipv4_val = _mm256_set1_epi32(0x0800);
    let ipv4_mask = _mm256_cmpeq_epi32(ethertype_vec, ipv4_val);
    // movemask: bit i is set if lane i matched.
    let ipv4_bits = _mm256_movemask_epi8(ipv4_mask) as u32;
    // Convert byte-mask to lane-mask: every 4 bytes → 1 bit.
    let ipv4_lanes = compress_byte_mask_to_lanes(ipv4_bits);
    let fast_mask = long_enough & ipv4_lanes;

    if fast_mask == 0 {
        return scalar_fallback_all(chunk, meta);
    }

    // ── Stage 4: Check IHL == 5 (20 bytes) for fast-path IPv4 ──
    // Offset 14 (first byte of IPv4) → IHL is lower nibble.
    let mut ihl_ok: u8 = 0;
    let mut protocols = [0u8; 8];
    for i in 0..8 {
        if fast_mask & (1 << i) != 0 {
            let ihl = *ptrs[i].add(14) & 0x0F;
            if ihl == 5 {
                ihl_ok |= 1 << i;
                // Read protocol byte at IPv4 offset 9 → absolute offset 14 + 9 = 23.
                protocols[i] = *ptrs[i].add(23);
            }
        }
    }

    let fast_ipv4 = fast_mask & ihl_ok;

    // ── Stage 5: Check protocol is a known leaf (TCP=6, UDP=17, ICMP=1) ──
    // and verify the leaf header minimum length.
    let mut simd_ok: u8 = 0;
    for i in 0..8 {
        if fast_ipv4 & (1 << i) != 0 {
            let remaining = lens[i] - 34; // 14 (Eth) + 20 (IPv4)
            let leaf_ok = match protocols[i] {
                6 => remaining >= 20,   // TCP
                17 => remaining >= 8,   // UDP
                1 => remaining >= 8,    // ICMPv4
                132 => remaining >= 12, // SCTP
                _ => false,
            };
            if leaf_ok {
                simd_ok |= 1 << i;
            }
        }
    }

    // ── Stage 6: Extract metadata for SIMD successes + scalar fallback for the rest ──
    let mut count = 0u64;

    // Extract metadata for each SIMD-classified packet.
    for i in 0..8 {
        if simd_ok & (1 << i) != 0 {
            extract_fast_path_meta(ptrs[i], lens[i], protocols[i], meta);
            count += 1;
        }
    }

    // Fallback mask: packets NOT handled by SIMD.
    let fallback = !simd_ok;
    for i in 0..8 {
        if fallback & (1 << i) != 0 {
            *meta = FlowMeta::default();
            if graph_compiled::parse_packet(&chunk[i].data, meta).is_ok() {
                count += 1;
            }
        }
    }

    count
}

/// Convert AVX2 movemask_epi8 result (32 bits, 4 per lane) to 8-bit lane mask.
#[cfg(target_arch = "x86_64")]
#[inline]
fn compress_byte_mask_to_lanes(byte_mask: u32) -> u8 {
    let mut lanes: u8 = 0;
    for i in 0..8 {
        // Each lane occupies 4 bytes in the mask. If all 4 bits are set
        // (0xF shifted into position), the lane matched.
        if byte_mask & (0xF << (i * 4)) != 0 {
            lanes |= 1 << i;
        }
    }
    lanes
}

/// Scalar fallback for all 8 packets.
#[inline]
fn scalar_fallback_all(chunk: &[&StoredPacket], meta: &mut FlowMeta) -> u64 {
    let mut count = 0u64;
    for pkt in chunk {
        *meta = FlowMeta::default();
        if graph_compiled::parse_packet(&pkt.data, meta).is_ok() {
            count += 1;
        }
    }
    count
}

/// Non-AVX2 stub for other architectures.
#[cfg(not(target_arch = "x86_64"))]
pub fn parse_batch_avx2(packets: &[&StoredPacket], meta: &mut FlowMeta) -> u64 {
    let mut acc: u64 = 0;
    for pkt in packets {
        *meta = FlowMeta::default();
        if graph_compiled::parse_packet(&pkt.data, meta).is_ok() {
            acc += 1;
        }
    }
    acc
}

/// Check whether AVX2 SIMD batch parsing is available at runtime.
pub fn is_available() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        is_x86_feature_detected!("avx2")
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}
