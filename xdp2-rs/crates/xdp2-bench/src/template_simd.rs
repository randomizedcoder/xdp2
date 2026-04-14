//! Step 12d: Batch template SIMD extraction (AVX2).
//!
//! Processes 8 packets at a time using a pre-selected template.
//! Because the template guarantees all field offsets are compile-time
//! constants, there is **no classification pipeline** — the multi-stage
//! gather-compare chain from `simd_batch.rs` (stages 2–5) collapses to:
//!
//!   1. Bounds-check 8 lengths in parallel
//!   2. Gather each field from 8 packets at a fixed offset
//!   3. XOR-reduce for anti-DCE
//!
//! ## Scattered vs Contiguous Memory
//!
//! With PCAP data (this benchmark), packet pointers are scattered on the
//! heap.  AVX2 `vpgatherdd` cannot use absolute 64-bit pointers, so we
//! load fields scalar-into-SIMD (8 × L1-hit loads per field).
//!
//! With AF_XDP UMEM (production), frames are contiguous at predictable
//! offsets (`base + frame_idx * frame_size + field_offset`).  This
//! enables true hardware gather with scale factors — a significant
//! additional speedup that this benchmark cannot demonstrate.

#![allow(dead_code)]

#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

use crate::pcap::StoredPacket;
use crate::template::{self, TemplateId};

/// Process a batch of pre-classified packets using AVX2 template extraction.
/// All packets must have a pre-selected template ID.  Returns the count
/// of successfully extracted packets (for correctness checking).
///
/// # Safety
/// Requires AVX2 support.  Caller must check `is_x86_feature_detected!("avx2")`.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
pub unsafe fn extract_batch_avx2(
    packets: &[&StoredPacket],
    template_ids: &[Option<TemplateId>],
) -> u64 {
    debug_assert_eq!(packets.len(), template_ids.len());

    let mut acc: u64 = 0;
    let mut chunks_pkt = packets.chunks_exact(8);
    let mut chunks_tid = template_ids.chunks_exact(8);

    loop {
        let pkt_chunk = match chunks_pkt.next() {
            Some(c) => c,
            None => break,
        };
        let tid_chunk = chunks_tid.next().unwrap();
        acc = acc.wrapping_add(extract_8_avx2(pkt_chunk, tid_chunk));
    }

    // Tail: scalar fallback for remaining packets.
    for (pkt, tid) in chunks_pkt.remainder().iter().zip(chunks_tid.remainder()) {
        if let Some(id) = tid {
            if let Ok(v) = template::extract_by_id(&pkt.data, *id) {
                acc = acc.wrapping_add(v);
            }
        }
    }

    acc
}

/// Process exactly 8 packets with AVX2 template extraction.
///
/// For homogeneous batches (all same template), this is the fast path:
/// one SIMD bounds check + field gathers at fixed offsets.
/// For mixed batches, falls back to per-packet scalar extraction.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
#[inline]
unsafe fn extract_8_avx2(
    chunk: &[&StoredPacket],
    tids: &[Option<TemplateId>],
) -> u64 {
    debug_assert_eq!(chunk.len(), 8);
    debug_assert_eq!(tids.len(), 8);

    // Collect pointers, lengths, and check template homogeneity.
    let mut ptrs: [*const u8; 8] = [std::ptr::null(); 8];
    let mut lens: [i32; 8] = [0; 8];
    let mut all_same = true;
    let mut first_tid: Option<TemplateId> = None;
    let mut valid_mask: u8 = 0;

    for i in 0..8 {
        ptrs[i] = chunk[i].data.as_ptr();
        lens[i] = chunk[i].data.len() as i32;
        if let Some(id) = tids[i] {
            valid_mask |= 1 << i;
            match first_tid {
                None => first_tid = Some(id),
                Some(fid) => {
                    if std::mem::discriminant(&fid) != std::mem::discriminant(&id) {
                        all_same = false;
                    }
                }
            }
        }
    }

    if valid_mask == 0 {
        return 0;
    }

    // If templates are mixed or some packets have no template, fall back.
    if !all_same || valid_mask != 0xFF {
        return scalar_fallback(chunk, tids);
    }

    let tid = first_tid.unwrap();

    // ── Homogeneous fast path ──
    // All 8 packets have the same template.  SIMD bounds check + field gather.
    match tid {
        TemplateId::EthIpv4Tcp => extract_8_eth_ipv4_tcp(ptrs, lens),
        TemplateId::EthIpv4Udp => extract_8_eth_ipv4_udp(ptrs, lens),
        TemplateId::EthIpv6Tcp => extract_8_eth_ipv6_tcp(ptrs, lens),
    }
}

// ── Per-template batch extractors ──
//
// Each function below handles 8 packets of one template type.
// The pattern is:
//   1. SIMD bounds check (8 lengths vs min_length)
//   2. For each field: load from 8 packets at fixed offset → pack to __m256i
//   3. XOR-reduce all field vectors → horizontal sum → scalar result

/// Batch Eth/IPv4(IHL=5)/TCP extraction for 8 packets.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
#[inline]
unsafe fn extract_8_eth_ipv4_tcp(ptrs: [*const u8; 8], lens: [i32; 8]) -> u64 {
    const MIN_LEN: i32 = 54;

    // ── Stage 1: SIMD bounds check ──
    let len_vec = _mm256_set_epi32(
        lens[7], lens[6], lens[5], lens[4],
        lens[3], lens[2], lens[1], lens[0],
    );
    // cmpgt: lane[i] = 0xFFFFFFFF if lens[i] > MIN_LEN-1 (i.e., lens[i] >= MIN_LEN)
    let ok_mask = _mm256_cmpgt_epi32(len_vec, _mm256_set1_epi32(MIN_LEN - 1));
    let ok_bits = _mm256_movemask_epi8(ok_mask) as u32;

    // If any packet is too short, fall back to scalar for all.
    // (Homogeneous template means all should be long enough; this is a safety check.)
    if ok_bits != 0xFFFF_FFFF {
        let mut count = 0u64;
        for i in 0..8 {
            if lens[i] >= MIN_LEN {
                if let Ok(v) = template::extract_eth_ipv4_tcp(
                    std::slice::from_raw_parts(ptrs[i], lens[i] as usize),
                ) {
                    count = count.wrapping_add(v);
                }
            }
        }
        return count;
    }

    // ── Stage 2: Gather fields at fixed offsets ──
    // Load u32 from each packet at the given offset, pack into __m256i.
    let f0 = gather_u32_8(ptrs, 0);   // dst_mac[0..4]
    let f1 = gather_u16_8(ptrs, 4);   // dst_mac[4..6]
    let f2 = gather_u32_8(ptrs, 6);   // src_mac[0..4]
    let f3 = gather_u16_8(ptrs, 10);  // src_mac[4..6]
    let f4 = gather_u16_8(ptrs, 12);  // ethertype
    let f5 = gather_u8_8(ptrs, 23);   // ip_proto
    let f6 = gather_u32_8(ptrs, 26);  // ip_src
    let f7 = gather_u32_8(ptrs, 30);  // ip_dst
    let f8 = gather_u16_8(ptrs, 34);  // tcp_src_port
    let f9 = gather_u16_8(ptrs, 36);  // tcp_dst_port
    let f10 = gather_u8_8(ptrs, 47);  // tcp_flags

    // ── Stage 3: XOR all fields across all 8 lanes ──
    let mut xor = _mm256_xor_si256(f0, f1);
    xor = _mm256_xor_si256(xor, f2);
    xor = _mm256_xor_si256(xor, f3);
    xor = _mm256_xor_si256(xor, f4);
    xor = _mm256_xor_si256(xor, f5);
    xor = _mm256_xor_si256(xor, f6);
    xor = _mm256_xor_si256(xor, f7);
    xor = _mm256_xor_si256(xor, f8);
    xor = _mm256_xor_si256(xor, f9);
    xor = _mm256_xor_si256(xor, f10);

    // Horizontal reduce: sum all 8 lanes.
    hsum_epi32(xor)
}

/// Batch Eth/IPv4(IHL=5)/UDP extraction for 8 packets.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
#[inline]
unsafe fn extract_8_eth_ipv4_udp(ptrs: [*const u8; 8], lens: [i32; 8]) -> u64 {
    const MIN_LEN: i32 = 42;

    let len_vec = _mm256_set_epi32(
        lens[7], lens[6], lens[5], lens[4],
        lens[3], lens[2], lens[1], lens[0],
    );
    let ok_mask = _mm256_cmpgt_epi32(len_vec, _mm256_set1_epi32(MIN_LEN - 1));
    if _mm256_movemask_epi8(ok_mask) as u32 != 0xFFFF_FFFF {
        let mut count = 0u64;
        for i in 0..8 {
            if lens[i] >= MIN_LEN {
                if let Ok(v) = template::extract_eth_ipv4_udp(
                    std::slice::from_raw_parts(ptrs[i], lens[i] as usize),
                ) {
                    count = count.wrapping_add(v);
                }
            }
        }
        return count;
    }

    let f0 = gather_u32_8(ptrs, 0);
    let f1 = gather_u16_8(ptrs, 4);
    let f2 = gather_u32_8(ptrs, 6);
    let f3 = gather_u16_8(ptrs, 10);
    let f4 = gather_u16_8(ptrs, 12);
    let f5 = gather_u8_8(ptrs, 23);
    let f6 = gather_u32_8(ptrs, 26);
    let f7 = gather_u32_8(ptrs, 30);
    let f8 = gather_u16_8(ptrs, 34);
    let f9 = gather_u16_8(ptrs, 36);

    let mut xor = _mm256_xor_si256(f0, f1);
    xor = _mm256_xor_si256(xor, f2);
    xor = _mm256_xor_si256(xor, f3);
    xor = _mm256_xor_si256(xor, f4);
    xor = _mm256_xor_si256(xor, f5);
    xor = _mm256_xor_si256(xor, f6);
    xor = _mm256_xor_si256(xor, f7);
    xor = _mm256_xor_si256(xor, f8);
    xor = _mm256_xor_si256(xor, f9);

    hsum_epi32(xor)
}

/// Batch Eth/IPv6/TCP extraction for 8 packets.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
#[inline]
unsafe fn extract_8_eth_ipv6_tcp(ptrs: [*const u8; 8], lens: [i32; 8]) -> u64 {
    const MIN_LEN: i32 = 74;

    let len_vec = _mm256_set_epi32(
        lens[7], lens[6], lens[5], lens[4],
        lens[3], lens[2], lens[1], lens[0],
    );
    let ok_mask = _mm256_cmpgt_epi32(len_vec, _mm256_set1_epi32(MIN_LEN - 1));
    if _mm256_movemask_epi8(ok_mask) as u32 != 0xFFFF_FFFF {
        let mut count = 0u64;
        for i in 0..8 {
            if lens[i] >= MIN_LEN {
                if let Ok(v) = template::extract_eth_ipv6_tcp(
                    std::slice::from_raw_parts(ptrs[i], lens[i] as usize),
                ) {
                    count = count.wrapping_add(v);
                }
            }
        }
        return count;
    }

    let f0 = gather_u32_8(ptrs, 0);    // dst_mac[0..4]
    let f1 = gather_u16_8(ptrs, 4);    // dst_mac[4..6]
    let f2 = gather_u32_8(ptrs, 6);    // src_mac[0..4]
    let f3 = gather_u16_8(ptrs, 10);   // src_mac[4..6]
    let f4 = gather_u16_8(ptrs, 12);   // ethertype
    let f5 = gather_u8_8(ptrs, 20);    // ipv6_next_hdr
    let f6 = gather_u32_8(ptrs, 22);   // ipv6_src[0..4]
    let f7 = gather_u32_8(ptrs, 26);   // ipv6_src[4..8]
    let f8 = gather_u32_8(ptrs, 30);   // ipv6_src[8..12]
    let f9 = gather_u32_8(ptrs, 34);   // ipv6_src[12..16]
    let f10 = gather_u32_8(ptrs, 38);  // ipv6_dst[0..4]
    let f11 = gather_u32_8(ptrs, 42);  // ipv6_dst[4..8]
    let f12 = gather_u32_8(ptrs, 46);  // ipv6_dst[8..12]
    let f13 = gather_u32_8(ptrs, 50);  // ipv6_dst[12..16]
    let f14 = gather_u16_8(ptrs, 54);  // tcp_src_port
    let f15 = gather_u16_8(ptrs, 56);  // tcp_dst_port
    let f16 = gather_u8_8(ptrs, 67);   // tcp_flags

    let mut xor = _mm256_xor_si256(f0, f1);
    xor = _mm256_xor_si256(xor, f2);
    xor = _mm256_xor_si256(xor, f3);
    xor = _mm256_xor_si256(xor, f4);
    xor = _mm256_xor_si256(xor, f5);
    xor = _mm256_xor_si256(xor, f6);
    xor = _mm256_xor_si256(xor, f7);
    xor = _mm256_xor_si256(xor, f8);
    xor = _mm256_xor_si256(xor, f9);
    xor = _mm256_xor_si256(xor, f10);
    xor = _mm256_xor_si256(xor, f11);
    xor = _mm256_xor_si256(xor, f12);
    xor = _mm256_xor_si256(xor, f13);
    xor = _mm256_xor_si256(xor, f14);
    xor = _mm256_xor_si256(xor, f15);
    xor = _mm256_xor_si256(xor, f16);

    hsum_epi32(xor)
}

// ── Gather helpers ──
//
// Load a field from 8 packets at a fixed byte offset, zero-extended to i32,
// packed into an __m256i.  With scattered pointers these are scalar loads;
// with contiguous UMEM they could become true vpgatherdd instructions.

/// Gather u32 from 8 packets at byte offset `off`.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
#[inline]
unsafe fn gather_u32_8(ptrs: [*const u8; 8], off: usize) -> __m256i {
    _mm256_set_epi32(
        *(ptrs[7].add(off) as *const i32),
        *(ptrs[6].add(off) as *const i32),
        *(ptrs[5].add(off) as *const i32),
        *(ptrs[4].add(off) as *const i32),
        *(ptrs[3].add(off) as *const i32),
        *(ptrs[2].add(off) as *const i32),
        *(ptrs[1].add(off) as *const i32),
        *(ptrs[0].add(off) as *const i32),
    )
}

/// Gather u16 from 8 packets at byte offset `off`, zero-extended to i32.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
#[inline]
unsafe fn gather_u16_8(ptrs: [*const u8; 8], off: usize) -> __m256i {
    _mm256_set_epi32(
        *(ptrs[7].add(off) as *const u16) as i32,
        *(ptrs[6].add(off) as *const u16) as i32,
        *(ptrs[5].add(off) as *const u16) as i32,
        *(ptrs[4].add(off) as *const u16) as i32,
        *(ptrs[3].add(off) as *const u16) as i32,
        *(ptrs[2].add(off) as *const u16) as i32,
        *(ptrs[1].add(off) as *const u16) as i32,
        *(ptrs[0].add(off) as *const u16) as i32,
    )
}

/// Gather u8 from 8 packets at byte offset `off`, zero-extended to i32.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
#[inline]
unsafe fn gather_u8_8(ptrs: [*const u8; 8], off: usize) -> __m256i {
    _mm256_set_epi32(
        *ptrs[7].add(off) as i32,
        *ptrs[6].add(off) as i32,
        *ptrs[5].add(off) as i32,
        *ptrs[4].add(off) as i32,
        *ptrs[3].add(off) as i32,
        *ptrs[2].add(off) as i32,
        *ptrs[1].add(off) as i32,
        *ptrs[0].add(off) as i32,
    )
}

/// Horizontal sum of 8 × i32 lanes → u64.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
#[inline]
unsafe fn hsum_epi32(v: __m256i) -> u64 {
    // Split 256 → two 128, add them
    let lo = _mm256_castsi256_si128(v);
    let hi = _mm256_extracti128_si256::<1>(v);
    let sum128 = _mm_add_epi32(lo, hi);
    // Horizontal add pairs: [a+b, c+d, ...]
    let sum64 = _mm_hadd_epi32(sum128, sum128);
    let sum32 = _mm_hadd_epi32(sum64, sum64);
    _mm_cvtsi128_si32(sum32) as u32 as u64
}

/// Scalar fallback for mixed-template or partially-valid batches.
#[inline]
fn scalar_fallback(chunk: &[&StoredPacket], tids: &[Option<TemplateId>]) -> u64 {
    let mut acc = 0u64;
    for (pkt, tid) in chunk.iter().zip(tids) {
        if let Some(id) = tid {
            if let Ok(v) = template::extract_by_id(&pkt.data, *id) {
                acc = acc.wrapping_add(v);
            }
        }
    }
    acc
}

/// Check whether AVX2 is available at runtime.
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

/// Non-AVX2 stub for other architectures.
#[cfg(not(target_arch = "x86_64"))]
pub fn extract_batch_avx2(
    packets: &[&StoredPacket],
    template_ids: &[Option<TemplateId>],
) -> u64 {
    let mut acc: u64 = 0;
    for (pkt, tid) in packets.iter().zip(template_ids) {
        if let Some(id) = tid {
            if let Ok(v) = template::extract_by_id(&pkt.data, *id) {
                acc = acc.wrapping_add(v);
            }
        }
    }
    acc
}
