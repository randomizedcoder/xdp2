//! Miscellaneous tunnel protocol definitions.
//!
//! Contains simpler tunnel protocols that are mostly leaf or fixed-length
//! encapsulation nodes: ERSPAN, GRE-PPTP, GUE, HSR, LISP, LWAPP, NVGRE,
//! PPP, PPPoE, STT, Teredo, TZSP, CAPWAP.
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `ErspanHeader` | `proto_defs/tunnel/proto_erspan.h:38-41` | `struct erspan_base_hdr` |
//! | `ErspanOps` | `proto_erspan.h:51-54` | `xdp2_parse_erspan` |
//! | `GrePptpHeader` | `proto_gre_pptp.h:37-42` | `struct gre_pptp_hdr` |
//! | `GrePptpOps` | `proto_gre_pptp.h:52-55` | `xdp2_parse_gre_pptp` |
//! | `GueHeader` | `proto_gue.h:50-54` | `struct guehdr` |
//! | `GueOps` | `proto_gue.h:70-75` | `xdp2_parse_gue` |
//! | `HsrHeader` | `proto_hsr.h:37-41` | `struct hsr_tag` |
//! | `HsrOps` | `proto_hsr.h:58-62` | `xdp2_parse_hsr` |
//! | `LispHeader` | `proto_lisp.h:38-41` | `struct lisphdr` |
//! | `LispOps` | `proto_lisp.h:68-73` | `xdp2_parse_lisp` |
//! | `LwappHeader` | `proto_lwapp.h:37-42` | `struct lwapp_hdr` |
//! | `LwappOps` | `proto_lwapp.h:52-56` | `xdp2_parse_lwapp` |
//! | `NvgreHeader` | `proto_nvgre.h:37-41` | `struct nvgrehdr` |
//! | `NvgreOps` | `proto_nvgre.h:57-62` | `xdp2_parse_nvgre` |
//! | `PppHeader` | `proto_ppp.h:36-40` | `struct ppp_hdr` |
//! | `PppOps` | `proto_ppp.h:57-61` | `xdp2_parse_ppp` |
//! | `PppoeHeader` | `proto_pppoe.h:32-46` | `struct pppoe_hdr` |
//! | `PppoeOps` | `proto_pppoe.h:66-70` | `xdp2_parse_pppoe` |
//! | `SttHeader` | `proto_stt.h:37-45` | `struct stthdr` |
//! | `SttOps` | `proto_stt.h:61-66` | `xdp2_parse_stt` |
//! | `TeredoHeader` | `proto_teredo.h:39-41` | `struct teredo_hdr` |
//! | `TeredoOps` | `proto_teredo.h:58-63` | `xdp2_parse_teredo` |
//! | `TzspHeader` | `proto_tzsp.h:37-41` | `struct tzsp_hdr` |
//! | `TzspOps` | `proto_tzsp.h:57-62` | `xdp2_parse_tzsp` |
//! | `CapwapHeader` | `proto_capwap.h:38-43` | `struct capwap_hdr` |
//! | `CapwapOps` | `proto_capwap.h:60-65` | `xdp2_parse_capwap` |
//!
//! ## Behavioral Differences
//! - None. Byte-for-byte compatible with C implementation.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

const ETH_P_IP: i32 = 0x0800;
const ETH_P_IPV6: i32 = 0x86DD;
const ETH_P_TEB: i32 = 0x6558;

// ── ERSPAN ──────────────────────────────────────────────────────────────

/// ERSPAN base header (4 bytes).
///
/// Reimplements: `struct erspan_base_hdr` in `proto_erspan.h:38-41`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct ErspanHeader {
    pub ver_vlan: [u8; 2],
    pub cos_en_t_session: [u8; 2],
}

/// ERSPAN protocol operations (leaf).
///
/// Reimplements: `xdp2_parse_erspan` in `proto_erspan.h:51-54`
pub struct ErspanOps;

impl ProtocolOps for ErspanOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "ERSPAN";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

// ── GRE-PPTP ────────────────────────────────────────────────────────────

/// GRE-PPTP header (8 bytes).
///
/// Reimplements: `struct gre_pptp_hdr` in `proto_gre_pptp.h:37-42`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct GrePptpHeader {
    pub flags_version: [u8; 2],
    pub protocol: [u8; 2],
    pub payload_len: [u8; 2],
    pub call_id: [u8; 2],
}

/// GRE-PPTP protocol operations (leaf).
///
/// Reimplements: `xdp2_parse_gre_pptp` in `proto_gre_pptp.h:52-55`
pub struct GrePptpOps;

impl ProtocolOps for GrePptpOps {
    const MIN_LEN: usize = 8;
    const NAME: &'static str = "GRE-PPTP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

// ── GUE ─────────────────────────────────────────────────────────────────

/// GUE header (4 bytes).
///
/// Reimplements: `struct guehdr` in `proto_gue.h:50-54`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct GueHeader {
    /// Version(2) + Hdr len(5) + C(1)
    pub hdrlen_version: u8,
    /// IP protocol (C=0) or control type (C=1)
    pub proto_ctype: u8,
    /// Flags
    pub flags: [u8; 2],
}

/// GUE protocol operations (encap).
///
/// Reimplements: `xdp2_parse_gue` in `proto_gue.h:70-75`
pub struct GueOps;

impl ProtocolOps for GueOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "GUE";
    const ENCAP: bool = true;

    /// Return proto_ctype field (IP protocol number).
    ///
    /// Reimplements: `gue_proto()` in `proto_gue.h:56-59`
    #[inline]
    fn next_proto(&self, hdr: &[u8]) -> Result<i32, ParseError> {
        let gue = GueHeader::ref_from_prefix(hdr)
            .map_err(|_| ParseError::Length)?
            .0;
        Ok(gue.proto_ctype as i32)
    }
}

// ── HSR ─────────────────────────────────────────────────────────────────

/// HSR tag header (6 bytes).
///
/// Reimplements: `struct hsr_tag` in `proto_hsr.h:37-41`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct HsrHeader {
    pub path_and_lsdu_size: [u8; 2],
    pub sequence_nr: [u8; 2],
    pub encap_proto: [u8; 2],
}

impl HsrHeader {
    pub fn encap_proto(&self) -> u16 {
        u16::from_be_bytes(self.encap_proto)
    }
}

/// HSR protocol operations.
///
/// Reimplements: `xdp2_parse_hsr` in `proto_hsr.h:58-62`
pub struct HsrOps;

impl ProtocolOps for HsrOps {
    const MIN_LEN: usize = 6;
    const NAME: &'static str = "HSR";

    /// Return encapsulated EtherType.
    ///
    /// Reimplements: `hsr_proto()` in `proto_hsr.h:44-47`
    #[inline]
    fn next_proto(&self, hdr: &[u8]) -> Result<i32, ParseError> {
        let h = HsrHeader::ref_from_prefix(hdr)
            .map_err(|_| ParseError::Length)?
            .0;
        Ok(h.encap_proto() as i32)
    }
}

// ── LISP ────────────────────────────────────────────────────────────────

/// LISP header (8 bytes).
///
/// Reimplements: `struct lisphdr` in `proto_lisp.h:38-41`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct LispHeader {
    pub flags_nonce: [u8; 4],
    pub lsb: [u8; 4],
}

/// LISP protocol operations (encap).
///
/// Reimplements: `xdp2_parse_lisp` in `proto_lisp.h:68-73`
pub struct LispOps;

impl ProtocolOps for LispOps {
    const MIN_LEN: usize = 8;
    const NAME: &'static str = "LISP";
    const ENCAP: bool = true;

    /// Determine inner protocol from first nibble of payload.
    ///
    /// Reimplements: `lisp_proto()` in `proto_lisp.h:44-57`
    #[inline]
    fn next_proto(&self, hdr: &[u8]) -> Result<i32, ParseError> {
        if hdr.len() < 9 {
            return Err(ParseError::Length);
        }
        let version = hdr[8] >> 4;
        Ok(match version {
            4 => ETH_P_IP,
            6 => ETH_P_IPV6,
            _ => 0,
        })
    }
}

// ── LWAPP ───────────────────────────────────────────────────────────────

/// LWAPP header (6 bytes).
///
/// Reimplements: `struct lwapp_hdr` in `proto_lwapp.h:37-42`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct LwappHeader {
    pub version_flags: u8,
    pub fragment_id: u8,
    pub length: [u8; 2],
    pub status: [u8; 2],
}

/// LWAPP protocol operations (encap leaf — no next protocol dispatch).
///
/// Reimplements: `xdp2_parse_lwapp` in `proto_lwapp.h:52-56`
pub struct LwappOps;

impl ProtocolOps for LwappOps {
    const MIN_LEN: usize = 6;
    const NAME: &'static str = "LWAPP";
    const ENCAP: bool = true;

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

// ── NVGRE ───────────────────────────────────────────────────────────────

/// NVGRE header (8 bytes).
///
/// Reimplements: `struct nvgrehdr` in `proto_nvgre.h:37-41`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct NvgreHeader {
    pub flags_version: [u8; 2],
    pub protocol_type: [u8; 2],
    pub vsid_flowid: [u8; 4],
}

impl NvgreHeader {
    /// VSID (24-bit Virtual Subnet ID).
    pub fn vsid(&self) -> u32 {
        ((self.vsid_flowid[0] as u32) << 16)
            | ((self.vsid_flowid[1] as u32) << 8)
            | (self.vsid_flowid[2] as u32)
    }
}

/// NVGRE protocol operations (encap — always Ethernet).
///
/// Reimplements: `xdp2_parse_nvgre` in `proto_nvgre.h:57-62`
pub struct NvgreOps;

impl ProtocolOps for NvgreOps {
    const MIN_LEN: usize = 8;
    const NAME: &'static str = "NVGRE";
    const ENCAP: bool = true;

    /// Always returns ETH_P_TEB (inner is Ethernet).
    ///
    /// Reimplements: `nvgre_proto()` in `proto_nvgre.h:43-46`
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Ok(ETH_P_TEB)
    }
}

// ── PPP ─────────────────────────────────────────────────────────────────

/// PPP header (4 bytes).
///
/// Reimplements: `struct ppp_hdr` in `proto_ppp.h:36-40`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct PppHeader {
    pub address: u8,
    pub control: u8,
    pub protocol: [u8; 2],
}

impl PppHeader {
    pub fn protocol(&self) -> u16 {
        u16::from_be_bytes(self.protocol)
    }
}

/// PPP protocol operations.
///
/// Reimplements: `xdp2_parse_ppp` in `proto_ppp.h:57-61`
pub struct PppOps;

impl ProtocolOps for PppOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "PPP";

    /// Return PPP protocol field.
    ///
    /// Reimplements: `ppp_proto()` in `proto_ppp.h:42-45`
    #[inline]
    fn next_proto(&self, hdr: &[u8]) -> Result<i32, ParseError> {
        let ppp = PppHeader::ref_from_prefix(hdr)
            .map_err(|_| ParseError::Length)?
            .0;
        Ok(ppp.protocol() as i32)
    }
}

// ── PPPoE ───────────────────────────────────────────────────────────────

/// PPPoE header (8 bytes).
///
/// Reimplements: `struct pppoe_hdr` in `proto_pppoe.h:32-46`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct PppoeHeader {
    /// Version (4 bits) + Type (4 bits)
    pub vertype: u8,
    /// Code
    pub code: u8,
    /// Session ID
    pub sid: [u8; 2],
    /// Length
    pub length: [u8; 2],
    /// PPP protocol
    pub protocol: [u8; 2],
}

impl PppoeHeader {
    pub fn protocol(&self) -> u16 {
        u16::from_be_bytes(self.protocol)
    }

    pub fn session_id(&self) -> u16 {
        u16::from_be_bytes(self.sid)
    }
}

/// PPPoE protocol operations.
///
/// Reimplements: `xdp2_parse_pppoe` in `proto_pppoe.h:66-70`
pub struct PppoeOps;

impl ProtocolOps for PppoeOps {
    const MIN_LEN: usize = 8;
    const NAME: &'static str = "PPPoE";

    /// Return PPP protocol field.
    ///
    /// Reimplements: `pppoe_proto()` in `proto_pppoe.h:51-54`
    #[inline]
    fn next_proto(&self, hdr: &[u8]) -> Result<i32, ParseError> {
        let pppoe = PppoeHeader::ref_from_prefix(hdr)
            .map_err(|_| ParseError::Length)?
            .0;
        Ok(pppoe.protocol() as i32)
    }
}

// ── STT ─────────────────────────────────────────────────────────────────

/// STT header (18 bytes).
///
/// Reimplements: `struct stthdr` in `proto_stt.h:37-45`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct SttHeader {
    pub version: u8,
    pub flags: u8,
    pub l4_offset: u8,
    pub reserved: u8,
    pub max_seg_size: [u8; 2],
    pub pv: [u8; 2],
    pub context_id: [u8; 8],
}

/// STT protocol operations (encap — always Ethernet).
///
/// Reimplements: `xdp2_parse_stt` in `proto_stt.h:61-66`
pub struct SttOps;

impl ProtocolOps for SttOps {
    const MIN_LEN: usize = 18; // sizeof(struct stthdr) = 1+1+1+1+2+2+8 = 16, but with __be64 it's 18
    const NAME: &'static str = "STT";
    const ENCAP: bool = true;

    /// Always returns ETH_P_TEB (inner is Ethernet).
    ///
    /// Reimplements: `stt_proto()` in `proto_stt.h:47-50`
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Ok(ETH_P_TEB)
    }
}

// ── Teredo ──────────────────────────────────────────────────────────────

/// Teredo header (2 bytes).
///
/// Reimplements: `struct teredo_hdr` in `proto_teredo.h:39-41`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct TeredoHeader {
    pub indicator: [u8; 2],
}

/// Teredo protocol operations (encap — always IPv6).
///
/// Reimplements: `xdp2_parse_teredo` in `proto_teredo.h:58-63`
pub struct TeredoOps;

impl ProtocolOps for TeredoOps {
    const MIN_LEN: usize = 2;
    const NAME: &'static str = "Teredo";
    const ENCAP: bool = true;

    /// Always returns ETH_P_IPV6 (inner is IPv6).
    ///
    /// Reimplements: `teredo_proto()` in `proto_teredo.h:44-47`
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Ok(ETH_P_IPV6)
    }
}

// ── TZSP ────────────────────────────────────────────────────────────────

/// TZSP header (4 bytes).
///
/// Reimplements: `struct tzsp_hdr` in `proto_tzsp.h:37-41`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct TzspHeader {
    pub version: u8,
    pub tzsp_type: u8,
    pub encap_proto: [u8; 2],
}

impl TzspHeader {
    pub fn encap_proto(&self) -> u16 {
        u16::from_be_bytes(self.encap_proto)
    }
}

/// TZSP protocol operations (encap).
///
/// Reimplements: `xdp2_parse_tzsp` in `proto_tzsp.h:57-62`
pub struct TzspOps;

impl ProtocolOps for TzspOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "TZSP";
    const ENCAP: bool = true;

    /// Return encapsulated protocol.
    ///
    /// Reimplements: `tzsp_proto()` in `proto_tzsp.h:43-46`
    #[inline]
    fn next_proto(&self, hdr: &[u8]) -> Result<i32, ParseError> {
        let tzsp = TzspHeader::ref_from_prefix(hdr)
            .map_err(|_| ParseError::Length)?
            .0;
        Ok(tzsp.encap_proto() as i32)
    }
}

// ── CAPWAP ──────────────────────────────────────────────────────────────

/// CAPWAP header (4 bytes minimum).
///
/// Reimplements: `struct capwap_hdr` in `proto_capwap.h:38-43`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct CapwapHeader {
    pub preamble: u8,
    pub hlen_rid: u8,
    pub wbid_flags: u8,
    pub frag_id: u8,
}

/// CAPWAP protocol operations (encap — always Ethernet).
///
/// Reimplements: `xdp2_parse_capwap` in `proto_capwap.h:60-65`
pub struct CapwapOps;

impl ProtocolOps for CapwapOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "CAPWAP";
    const ENCAP: bool = true;

    /// Always returns ETH_P_TEB.
    ///
    /// Reimplements: `capwap_proto()` in `proto_capwap.h:46-49`
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Ok(ETH_P_TEB)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ERSPAN
    #[test]
    fn erspan_is_leaf() {
        assert!(ErspanOps.next_proto(&[0u8; 4]).is_err());
    }

    // GRE-PPTP
    #[test]
    fn gre_pptp_is_leaf() {
        assert!(GrePptpOps.next_proto(&[0u8; 8]).is_err());
    }

    // GUE
    #[test]
    fn gue_next_proto() {
        let mut hdr = [0u8; 4];
        hdr[1] = 4; // IPPROTO_IPIP
        assert_eq!(GueOps.next_proto(&hdr).unwrap(), 4);
    }

    #[test]
    fn gue_is_encap() {
        assert!(GueOps::ENCAP);
    }

    // HSR
    #[test]
    fn hsr_next_proto() {
        let mut hdr = [0u8; 6];
        hdr[4..6].copy_from_slice(&0x0800u16.to_be_bytes());
        assert_eq!(HsrOps.next_proto(&hdr).unwrap(), 0x0800);
    }

    // LISP
    #[test]
    fn lisp_inner_ipv4() {
        let mut hdr = [0u8; 9];
        hdr[8] = 0x45;
        assert_eq!(LispOps.next_proto(&hdr).unwrap(), ETH_P_IP);
    }

    #[test]
    fn lisp_inner_ipv6() {
        let mut hdr = [0u8; 9];
        hdr[8] = 0x60;
        assert_eq!(LispOps.next_proto(&hdr).unwrap(), ETH_P_IPV6);
    }

    #[test]
    fn lisp_is_encap() {
        assert!(LispOps::ENCAP);
    }

    // LWAPP
    #[test]
    fn lwapp_is_encap_leaf() {
        assert!(LwappOps::ENCAP);
        assert!(LwappOps.next_proto(&[0u8; 6]).is_err());
    }

    // NVGRE
    #[test]
    fn nvgre_always_teb() {
        assert_eq!(NvgreOps.next_proto(&[0u8; 8]).unwrap(), ETH_P_TEB);
    }

    #[test]
    fn nvgre_is_encap() {
        assert!(NvgreOps::ENCAP);
    }

    #[test]
    fn nvgre_vsid() {
        let mut hdr = [0u8; 8];
        hdr[4] = 0x12;
        hdr[5] = 0x34;
        hdr[6] = 0x56;
        let n = NvgreHeader::ref_from_prefix(&hdr).unwrap().0;
        assert_eq!(n.vsid(), 0x123456);
    }

    // PPP
    #[test]
    fn ppp_next_proto() {
        let mut hdr = [0u8; 4];
        hdr[2..4].copy_from_slice(&0x0021u16.to_be_bytes()); // PPP IPv4
        assert_eq!(PppOps.next_proto(&hdr).unwrap(), 0x0021);
    }

    // PPPoE
    #[test]
    fn pppoe_next_proto() {
        let mut hdr = [0u8; 8];
        hdr[6..8].copy_from_slice(&0x0021u16.to_be_bytes());
        assert_eq!(PppoeOps.next_proto(&hdr).unwrap(), 0x0021);
    }

    // STT
    #[test]
    fn stt_always_teb() {
        assert_eq!(SttOps.next_proto(&[0u8; 18]).unwrap(), ETH_P_TEB);
    }

    #[test]
    fn stt_is_encap() {
        assert!(SttOps::ENCAP);
    }

    // Teredo
    #[test]
    fn teredo_always_ipv6() {
        assert_eq!(TeredoOps.next_proto(&[0u8; 2]).unwrap(), ETH_P_IPV6);
    }

    #[test]
    fn teredo_is_encap() {
        assert!(TeredoOps::ENCAP);
    }

    // TZSP
    #[test]
    fn tzsp_next_proto() {
        let mut hdr = [0u8; 4];
        hdr[2..4].copy_from_slice(&0x0800u16.to_be_bytes());
        assert_eq!(TzspOps.next_proto(&hdr).unwrap(), 0x0800);
    }

    #[test]
    fn tzsp_is_encap() {
        assert!(TzspOps::ENCAP);
    }

    // CAPWAP
    #[test]
    fn capwap_always_teb() {
        assert_eq!(CapwapOps.next_proto(&[0u8; 4]).unwrap(), ETH_P_TEB);
    }

    #[test]
    fn capwap_is_encap() {
        assert!(CapwapOps::ENCAP);
    }
}
