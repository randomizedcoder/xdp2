//! ICMPv6 Neighbor Discovery protocol definitions.
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `Icmpv6NdOptHeader` | `proto_defs/ip/proto_ipv6_nd.h:50-54` | `struct icmpv6_nd_opt` |
//! | `Icmpv6NdNeighHeader` | `proto_ipv6_nd.h:56-59` | `struct icmpv6_nd_neigh_advert` |
//! | `Icmpv6NdSolicitOps` | `proto_ipv6_nd.h:89-99` | `xdp2_parse_icmpv6_nd_solicit` |
//! | `icmpv6_nd_all_len()` | `proto_ipv6_nd.h:65-68` | `icmpv6_nd_all_len()` |
//! | `Icmpv6NdTlvOps` | `proto_ipv6_nd.h:95-98` | TLV ops (len, type, start_offset) |
//!
//! ## Behavioral Differences
//! - None. Byte-for-byte compatible with C implementation.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// ICMPv6 ND option header (2 bytes).
///
/// Reimplements: `struct icmpv6_nd_opt` in `proto_ipv6_nd.h:50-54`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct Icmpv6NdOptHeader {
    /// Option type
    pub opt_type: u8,
    /// Length in units of 8 bytes
    pub len: u8,
}

impl Icmpv6NdOptHeader {
    /// Option length in bytes (len * 8).
    ///
    /// Reimplements: `icmpv6_nd_tlv_len()` in `proto_ipv6_nd.h:70-73`
    pub fn length_bytes(&self) -> usize {
        self.len as usize * 8
    }
}

/// ICMPv6 Neighbor Solicitation/Advertisement header (24 bytes).
///
/// Reimplements: `struct icmpv6_nd_neigh_advert` in `proto_ipv6_nd.h:56-59`
///
/// 8-byte ICMPv6 header + 16-byte target address.
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct Icmpv6NdNeighHeader {
    /// ICMPv6 header (type, code, checksum, flags/reserved)
    pub icmp6_hdr: [u8; 8],
    /// Target IPv6 address
    pub target: [u8; 16],
}

/// ND option types.
pub const ND_OPT_SOURCE_LL_ADDR: u8 = 1;
pub const ND_OPT_TARGET_LL_ADDR: u8 = 2;
pub const ND_OPT_PREFIX_INFO: u8 = 3;
pub const ND_OPT_REDIRECT_HDR: u8 = 4;
pub const ND_OPT_MTU: u8 = 5;

/// ICMPv6 Neighbor Solicitation protocol operations.
///
/// Reimplements: `xdp2_parse_icmpv6_nd_solicit` in `proto_ipv6_nd.h:89-99`
///
/// This is a TLV-based protocol node. The fixed header is 24 bytes
/// (ICMPv6 header + target address), and TLV options follow.
/// Consumes all remaining bytes (overlay-like behavior for the header).
///
/// In the C implementation this is a `proto_tlvs_def` with `node_type = TLVS`.
/// The TLV parsing is handled by the TLV sub-parse system in xdp2-core.
pub struct Icmpv6NdSolicitOps;

impl ProtocolOps for Icmpv6NdSolicitOps {
    const MIN_LEN: usize = 24; // sizeof(struct icmpv6_nd_neigh_advert)
    const NAME: &'static str = "ICMPv6 neighbor solicit";

    /// Consumes all remaining bytes.
    ///
    /// Reimplements: `icmpv6_nd_all_len()` in `proto_ipv6_nd.h:65-68`
    #[inline]
    fn header_len(&self, _hdr: &[u8], maxlen: usize) -> Result<usize, ParseError> {
        Ok(maxlen)
    }

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto) // Leaf (TLV options are sub-parsed)
    }
}

/// TLV operations for ICMPv6 ND options.
///
/// Provides the TLV parsing parameters for use with `ParseTlvsNode`:
/// - `min_len`: 2 bytes (sizeof icmpv6_nd_opt)
/// - `start_offset`: 24 bytes (after the ND header)
/// - `tlv_len`: `len * 8`
/// - `tlv_type`: option type field
pub struct Icmpv6NdTlvOps;

impl Icmpv6NdTlvOps {
    /// Minimum TLV option length.
    ///
    /// Reimplements: `.min_len = sizeof(struct icmpv6_nd_opt)` in `proto_ipv6_nd.h:98`
    pub const MIN_TLV_LEN: usize = 2;

    /// Offset where TLV options begin (after ND header).
    ///
    /// Reimplements: `icmpv6_nd_tlvs_start_offset()` in `proto_ipv6_nd.h:80-83`
    pub const START_OFFSET: usize = 24; // sizeof(struct icmpv6_nd_neigh_advert)

    /// Get TLV type from option header.
    ///
    /// Reimplements: `icmpv6_nd_tlv_type()` in `proto_ipv6_nd.h:75-78`
    pub fn tlv_type(hdr: &[u8]) -> Result<u8, ParseError> {
        let opt = Icmpv6NdOptHeader::ref_from_prefix(hdr)
            .map_err(|_| ParseError::Length)?
            .0;
        Ok(opt.opt_type)
    }

    /// Get TLV length in bytes from option header.
    ///
    /// Reimplements: `icmpv6_nd_tlv_len()` in `proto_ipv6_nd.h:70-73`
    pub fn tlv_len(hdr: &[u8]) -> Result<usize, ParseError> {
        let opt = Icmpv6NdOptHeader::ref_from_prefix(hdr)
            .map_err(|_| ParseError::Length)?
            .0;
        Ok(opt.length_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nd_solicit_consumes_all() {
        let ops = Icmpv6NdSolicitOps;
        assert_eq!(ops.header_len(&[0u8; 64], 64).unwrap(), 64);
        assert_eq!(ops.header_len(&[0u8; 32], 32).unwrap(), 32);
    }

    #[test]
    fn nd_solicit_is_leaf() {
        let ops = Icmpv6NdSolicitOps;
        assert!(ops.next_proto(&[0u8; 24]).is_err());
    }

    #[test]
    fn nd_opt_length() {
        let mut opt = [0u8; 8];
        opt[0] = ND_OPT_SOURCE_LL_ADDR;
        opt[1] = 1; // 1 * 8 = 8 bytes
        let hdr = Icmpv6NdOptHeader::ref_from_prefix(&opt).unwrap().0;
        assert_eq!(hdr.length_bytes(), 8);
    }

    #[test]
    fn nd_tlv_ops() {
        let mut opt = [0u8; 8];
        opt[0] = ND_OPT_TARGET_LL_ADDR;
        opt[1] = 1;
        assert_eq!(
            Icmpv6NdTlvOps::tlv_type(&opt).unwrap(),
            ND_OPT_TARGET_LL_ADDR
        );
        assert_eq!(Icmpv6NdTlvOps::tlv_len(&opt).unwrap(), 8);
    }

    #[test]
    fn nd_start_offset() {
        assert_eq!(Icmpv6NdTlvOps::START_OFFSET, 24);
    }
}
