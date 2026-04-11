//! Miscellaneous security protocol definitions (all leaf nodes).
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `EspHeader` | `proto_defs/security/proto_esp.h` | `struct ip_esp_hdr` (linux/ip.h) |
//! | `EspOps` | `proto_esp.h:36-41` | `xdp2_parse_esp` |
//! | `TlsHeader` | `proto_tls.h:38-43` | `struct tls_hdr` |
//! | `TlsOps` | `proto_tls.h:50-55` | `xdp2_parse_tls` |
//! | `DtlsHeader` | `proto_dtls.h:38-46` | `struct dtls_hdr` |
//! | `DtlsOps` | `proto_dtls.h:53-58` | `xdp2_parse_dtls` |
//! | `MacsecHeader` | `proto_macsec.h:39-43` | `struct macsec_sectag` |
//! | `MacsecOps` | `proto_macsec.h:50-55` | `xdp2_parse_macsec` |
//! | `WireguardHeader` | `proto_wireguard.h:38-41` | `struct wireguard_hdr` |
//! | `WireguardOps` | `proto_wireguard.h:48-53` | `xdp2_parse_wireguard` |
//! | `EapHeader` | `proto_eap.h:38-42` | `struct eap_hdr` |
//! | `EapOps` | `proto_eap.h:49-54` | `xdp2_parse_eap` |
//! | `EapolHeader` | `proto_eapol.h:38-41` | `struct eapol_hdr` |
//! | `EapolOps` | `proto_eapol.h:48-53` | `xdp2_parse_eapol` |
//! | `Ikev2Header` | `proto_ikev2.h:38-47` | `struct ikev2hdr` |
//! | `Ikev2Ops` | `proto_ikev2.h:54-59` | `xdp2_parse_ikev2` |
//! | `SshHeader` | `proto_ssh.h:38-41` | `struct ssh_hdr` |
//! | `SshOps` | `proto_ssh.h:48-53` | `xdp2_parse_ssh` |
//! | `KerberosHeader` | `proto_kerberos.h:38-39` | `struct kerberos_hdr` |
//! | `KerberosOps` | `proto_kerberos.h:46-51` | `xdp2_parse_kerberos` |
//! | `OcspHeader` | `proto_ocsp.h:38-39` | `struct ocsp_hdr` |
//! | `OcspOps` | `proto_ocsp.h:46-51` | `xdp2_parse_ocsp` |
//! | `NtlmsspHeader` | `proto_ntlmssp.h:38-42` | `struct ntlmssp_hdr` |
//! | `NtlmsspOps` | `proto_ntlmssp.h:49-54` | `xdp2_parse_ntlmssp` |
//! | `TacacsHeader` | `proto_tacacs.h:38-45` | `struct tacacs_hdr` |
//! | `TacacsOps` | `proto_tacacs.h:52-57` | `xdp2_parse_tacacs` |
//!
//! ## Behavioral Differences
//! - None. All are leaf nodes — byte-for-byte compatible with C implementation.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

// ---------------------------------------------------------------------------
// ESP (Encapsulating Security Payload)
// ---------------------------------------------------------------------------

/// ESP header (8 bytes).
///
/// Reimplements: `struct ip_esp_hdr` (linux/ip.h) referenced in `proto_esp.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct EspHeader {
    pub spi: [u8; 4],
    pub seq_no: [u8; 4],
}

impl EspHeader {
    pub fn spi(&self) -> u32 {
        u32::from_be_bytes(self.spi)
    }
    pub fn seq_no(&self) -> u32 {
        u32::from_be_bytes(self.seq_no)
    }
}

/// ESP protocol operations (leaf).
///
/// Reimplements: `xdp2_parse_esp` in `proto_esp.h:36-41`
pub struct EspOps;

impl ProtocolOps for EspOps {
    const MIN_LEN: usize = 8;
    const NAME: &'static str = "ESP";

    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

// ---------------------------------------------------------------------------
// TLS (Transport Layer Security)
// ---------------------------------------------------------------------------

/// TLS record header (5 bytes).
///
/// Reimplements: `struct tls_hdr` in `proto_tls.h:38-43`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct TlsHeader {
    pub content_type: u8,
    pub version_major: u8,
    pub version_minor: u8,
    pub length: [u8; 2],
}

impl TlsHeader {
    pub fn length(&self) -> u16 {
        u16::from_be_bytes(self.length)
    }
}

/// TLS protocol operations (leaf).
///
/// Reimplements: `xdp2_parse_tls` in `proto_tls.h:50-55`
pub struct TlsOps;

impl ProtocolOps for TlsOps {
    const MIN_LEN: usize = 5;
    const NAME: &'static str = "TLS";

    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

// ---------------------------------------------------------------------------
// DTLS (Datagram Transport Layer Security)
// ---------------------------------------------------------------------------

/// DTLS record header (13 bytes).
///
/// Reimplements: `struct dtls_hdr` in `proto_dtls.h:38-46`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct DtlsHeader {
    pub content_type: u8,
    pub version_major: u8,
    pub version_minor: u8,
    pub epoch: [u8; 2],
    pub sequence: [u8; 6],
    pub length: [u8; 2],
}

impl DtlsHeader {
    pub fn epoch(&self) -> u16 {
        u16::from_be_bytes(self.epoch)
    }
    pub fn length(&self) -> u16 {
        u16::from_be_bytes(self.length)
    }
}

/// DTLS protocol operations (leaf).
///
/// Reimplements: `xdp2_parse_dtls` in `proto_dtls.h:53-58`
pub struct DtlsOps;

impl ProtocolOps for DtlsOps {
    const MIN_LEN: usize = 13;
    const NAME: &'static str = "DTLS";

    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

// ---------------------------------------------------------------------------
// MACsec (IEEE 802.1AE)
// ---------------------------------------------------------------------------

/// MACsec SecTAG header (6 bytes).
///
/// Reimplements: `struct macsec_sectag` in `proto_macsec.h:39-43`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct MacsecHeader {
    pub tci_an: u8,
    pub sl: u8,
    pub pn: [u8; 4],
}

impl MacsecHeader {
    /// TCI field (upper 6 bits).
    pub fn tci(&self) -> u8 {
        self.tci_an >> 2
    }
    /// Association Number (lower 2 bits).
    pub fn an(&self) -> u8 {
        self.tci_an & 0x03
    }
    /// Packet Number.
    pub fn pn(&self) -> u32 {
        u32::from_be_bytes(self.pn)
    }
}

/// MACsec protocol operations (leaf).
///
/// Reimplements: `xdp2_parse_macsec` in `proto_macsec.h:50-55`
pub struct MacsecOps;

impl ProtocolOps for MacsecOps {
    const MIN_LEN: usize = 6;
    const NAME: &'static str = "MACsec";

    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

// ---------------------------------------------------------------------------
// WireGuard
// ---------------------------------------------------------------------------

/// WireGuard header (4 bytes).
///
/// Reimplements: `struct wireguard_hdr` in `proto_wireguard.h:38-41`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct WireguardHeader {
    pub msg_type: u8,
    pub reserved: [u8; 3],
}

/// WireGuard protocol operations (leaf).
///
/// Reimplements: `xdp2_parse_wireguard` in `proto_wireguard.h:48-53`
pub struct WireguardOps;

impl ProtocolOps for WireguardOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "WireGuard";

    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

// ---------------------------------------------------------------------------
// EAP (Extensible Authentication Protocol)
// ---------------------------------------------------------------------------

/// EAP header (4 bytes).
///
/// Reimplements: `struct eap_hdr` in `proto_eap.h:38-42`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct EapHeader {
    pub code: u8,
    pub id: u8,
    pub length: [u8; 2],
}

impl EapHeader {
    pub fn length(&self) -> u16 {
        u16::from_be_bytes(self.length)
    }
}

/// EAP protocol operations (leaf).
///
/// Reimplements: `xdp2_parse_eap` in `proto_eap.h:49-54`
pub struct EapOps;

impl ProtocolOps for EapOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "EAP";

    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

// ---------------------------------------------------------------------------
// EAPOL (IEEE 802.1X)
// ---------------------------------------------------------------------------

/// EAPOL header (4 bytes).
///
/// Reimplements: `struct eapol_hdr` in `proto_eapol.h:38-41`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct EapolHeader {
    pub version: u8,
    pub pkt_type: u8,
    pub body_len: [u8; 2],
}

impl EapolHeader {
    pub fn body_len(&self) -> u16 {
        u16::from_be_bytes(self.body_len)
    }
}

/// EAPOL protocol operations (leaf).
///
/// Reimplements: `xdp2_parse_eapol` in `proto_eapol.h:48-53`
pub struct EapolOps;

impl ProtocolOps for EapolOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "EAPOL";

    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

// ---------------------------------------------------------------------------
// IKEv2 (Internet Key Exchange v2)
// ---------------------------------------------------------------------------

/// IKEv2 header (28 bytes).
///
/// Reimplements: `struct ikev2hdr` in `proto_ikev2.h:38-47`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct Ikev2Header {
    pub initiator_spi: [u8; 8],
    pub responder_spi: [u8; 8],
    pub next_payload: u8,
    pub version: u8,
    pub exchange_type: u8,
    pub flags: u8,
    pub message_id: [u8; 4],
    pub length: [u8; 4],
}

impl Ikev2Header {
    pub fn initiator_spi(&self) -> u64 {
        u64::from_be_bytes(self.initiator_spi)
    }
    pub fn responder_spi(&self) -> u64 {
        u64::from_be_bytes(self.responder_spi)
    }
    pub fn message_id(&self) -> u32 {
        u32::from_be_bytes(self.message_id)
    }
    pub fn length(&self) -> u32 {
        u32::from_be_bytes(self.length)
    }
}

/// IKEv2 protocol operations (leaf).
///
/// Reimplements: `xdp2_parse_ikev2` in `proto_ikev2.h:54-59`
pub struct Ikev2Ops;

impl ProtocolOps for Ikev2Ops {
    const MIN_LEN: usize = 28;
    const NAME: &'static str = "IKEv2";

    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

// ---------------------------------------------------------------------------
// SSH (Secure Shell)
// ---------------------------------------------------------------------------

/// SSH packet header (5 bytes).
///
/// Reimplements: `struct ssh_hdr` in `proto_ssh.h:38-41`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct SshHeader {
    pub packet_length: [u8; 4],
    pub padding_length: u8,
}

impl SshHeader {
    pub fn packet_length(&self) -> u32 {
        u32::from_be_bytes(self.packet_length)
    }
}

/// SSH protocol operations (leaf).
///
/// Reimplements: `xdp2_parse_ssh` in `proto_ssh.h:48-53`
pub struct SshOps;

impl ProtocolOps for SshOps {
    const MIN_LEN: usize = 5;
    const NAME: &'static str = "SSH";

    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

// ---------------------------------------------------------------------------
// Kerberos (RFC 4120)
// ---------------------------------------------------------------------------

/// Kerberos header (1 byte marker).
///
/// Reimplements: `struct kerberos_hdr` in `proto_kerberos.h:38-39`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct KerberosHeader {
    pub marker: u8,
}

/// Kerberos protocol operations (leaf).
///
/// Reimplements: `xdp2_parse_kerberos` in `proto_kerberos.h:46-51`
pub struct KerberosOps;

impl ProtocolOps for KerberosOps {
    const MIN_LEN: usize = 1;
    const NAME: &'static str = "Kerberos";

    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

// ---------------------------------------------------------------------------
// OCSP (Online Certificate Status Protocol)
// ---------------------------------------------------------------------------

/// OCSP header (1 byte marker).
///
/// Reimplements: `struct ocsp_hdr` in `proto_ocsp.h:38-39`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct OcspHeader {
    pub marker: u8,
}

/// OCSP protocol operations (leaf).
///
/// Reimplements: `xdp2_parse_ocsp` in `proto_ocsp.h:46-51`
pub struct OcspOps;

impl ProtocolOps for OcspOps {
    const MIN_LEN: usize = 1;
    const NAME: &'static str = "OCSP";

    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

// ---------------------------------------------------------------------------
// NTLMSSP (NT LAN Manager Security Support Provider)
// ---------------------------------------------------------------------------

/// NTLMSSP header (12 bytes).
///
/// Reimplements: `struct ntlmssp_hdr` in `proto_ntlmssp.h:38-42`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct NtlmsspHeader {
    pub signature: [u8; 8],
    pub message_type: [u8; 4],
}

impl NtlmsspHeader {
    /// Message type (little-endian u32).
    pub fn message_type(&self) -> u32 {
        u32::from_le_bytes(self.message_type)
    }
}

/// NTLMSSP protocol operations (leaf).
///
/// Reimplements: `xdp2_parse_ntlmssp` in `proto_ntlmssp.h:49-54`
pub struct NtlmsspOps;

impl ProtocolOps for NtlmsspOps {
    const MIN_LEN: usize = 12;
    const NAME: &'static str = "NTLMSSP";

    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

// ---------------------------------------------------------------------------
// TACACS+ (Terminal Access Controller Access-Control System Plus)
// ---------------------------------------------------------------------------

/// TACACS+ header (12 bytes).
///
/// Reimplements: `struct tacacs_hdr` in `proto_tacacs.h:38-45`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct TacacsHeader {
    pub major_minor: u8,
    pub pkt_type: u8,
    pub seq_no: u8,
    pub flags: u8,
    pub session_id: [u8; 4],
    pub length: [u8; 4],
}

impl TacacsHeader {
    /// Major version (upper 4 bits).
    pub fn major_version(&self) -> u8 {
        self.major_minor >> 4
    }
    /// Minor version (lower 4 bits).
    pub fn minor_version(&self) -> u8 {
        self.major_minor & 0x0F
    }
    pub fn session_id(&self) -> u32 {
        u32::from_be_bytes(self.session_id)
    }
    pub fn length(&self) -> u32 {
        u32::from_be_bytes(self.length)
    }
}

/// TACACS+ protocol operations (leaf).
///
/// Reimplements: `xdp2_parse_tacacs` in `proto_tacacs.h:52-57`
pub struct TacacsOps;

impl ProtocolOps for TacacsOps {
    const MIN_LEN: usize = 12;
    const NAME: &'static str = "TACACS+";

    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- ESP ---
    #[test]
    fn esp_is_leaf() {
        let ops = EspOps;
        assert!(matches!(ops.next_proto(&[0u8; 8]), Err(ParseError::UnknownProto)));
    }

    #[test]
    fn esp_spi_seq() {
        let mut hdr = [0u8; 8];
        hdr[0..4].copy_from_slice(&0xDEADBEEFu32.to_be_bytes());
        hdr[4..8].copy_from_slice(&42u32.to_be_bytes());
        let esp = EspHeader::ref_from_prefix(&hdr).unwrap().0;
        assert_eq!(esp.spi(), 0xDEADBEEF);
        assert_eq!(esp.seq_no(), 42);
    }

    // --- TLS ---
    #[test]
    fn tls_is_leaf() {
        let ops = TlsOps;
        assert!(matches!(ops.next_proto(&[0u8; 5]), Err(ParseError::UnknownProto)));
    }

    #[test]
    fn tls_header_fields() {
        let mut hdr = [0u8; 5];
        hdr[0] = 23; // application data
        hdr[1] = 3;  // TLS 1.2
        hdr[2] = 3;
        hdr[3..5].copy_from_slice(&1024u16.to_be_bytes());
        let tls = TlsHeader::ref_from_prefix(&hdr).unwrap().0;
        assert_eq!(tls.content_type, 23);
        assert_eq!(tls.version_major, 3);
        assert_eq!(tls.version_minor, 3);
        assert_eq!(tls.length(), 1024);
    }

    // --- DTLS ---
    #[test]
    fn dtls_is_leaf() {
        let ops = DtlsOps;
        assert!(matches!(ops.next_proto(&[0u8; 13]), Err(ParseError::UnknownProto)));
    }

    #[test]
    fn dtls_header_fields() {
        let mut hdr = [0u8; 13];
        hdr[0] = 22; // handshake
        hdr[3..5].copy_from_slice(&1u16.to_be_bytes()); // epoch
        hdr[11..13].copy_from_slice(&512u16.to_be_bytes()); // length
        let dtls = DtlsHeader::ref_from_prefix(&hdr).unwrap().0;
        assert_eq!(dtls.content_type, 22);
        assert_eq!(dtls.epoch(), 1);
        assert_eq!(dtls.length(), 512);
    }

    // --- MACsec ---
    #[test]
    fn macsec_is_leaf() {
        let ops = MacsecOps;
        assert!(matches!(ops.next_proto(&[0u8; 6]), Err(ParseError::UnknownProto)));
    }

    #[test]
    fn macsec_header_fields() {
        let mut hdr = [0u8; 6];
        hdr[0] = 0b10110001; // TCI=0b101100=44, AN=0b01=1
        hdr[1] = 0x20; // SL
        hdr[2..6].copy_from_slice(&100u32.to_be_bytes());
        let m = MacsecHeader::ref_from_prefix(&hdr).unwrap().0;
        assert_eq!(m.tci(), 44);
        assert_eq!(m.an(), 1);
        assert_eq!(m.pn(), 100);
    }

    // --- WireGuard ---
    #[test]
    fn wireguard_is_leaf() {
        let ops = WireguardOps;
        assert!(matches!(ops.next_proto(&[0u8; 4]), Err(ParseError::UnknownProto)));
    }

    #[test]
    fn wireguard_msg_type() {
        let mut hdr = [0u8; 4];
        hdr[0] = 4; // cookie reply
        let wg = WireguardHeader::ref_from_prefix(&hdr).unwrap().0;
        assert_eq!(wg.msg_type, 4);
    }

    // --- EAP ---
    #[test]
    fn eap_is_leaf() {
        let ops = EapOps;
        assert!(matches!(ops.next_proto(&[0u8; 4]), Err(ParseError::UnknownProto)));
    }

    #[test]
    fn eap_header_fields() {
        let mut hdr = [0u8; 4];
        hdr[0] = 1; // request
        hdr[1] = 42; // id
        hdr[2..4].copy_from_slice(&256u16.to_be_bytes());
        let eap = EapHeader::ref_from_prefix(&hdr).unwrap().0;
        assert_eq!(eap.code, 1);
        assert_eq!(eap.id, 42);
        assert_eq!(eap.length(), 256);
    }

    // --- EAPOL ---
    #[test]
    fn eapol_is_leaf() {
        let ops = EapolOps;
        assert!(matches!(ops.next_proto(&[0u8; 4]), Err(ParseError::UnknownProto)));
    }

    #[test]
    fn eapol_header_fields() {
        let mut hdr = [0u8; 4];
        hdr[0] = 2; // version
        hdr[1] = 0; // EAP-Packet
        hdr[2..4].copy_from_slice(&128u16.to_be_bytes());
        let eapol = EapolHeader::ref_from_prefix(&hdr).unwrap().0;
        assert_eq!(eapol.version, 2);
        assert_eq!(eapol.pkt_type, 0);
        assert_eq!(eapol.body_len(), 128);
    }

    // --- IKEv2 ---
    #[test]
    fn ikev2_is_leaf() {
        let ops = Ikev2Ops;
        assert!(matches!(ops.next_proto(&[0u8; 28]), Err(ParseError::UnknownProto)));
    }

    #[test]
    fn ikev2_header_fields() {
        let mut hdr = [0u8; 28];
        hdr[0..8].copy_from_slice(&0x1122334455667788u64.to_be_bytes());
        hdr[20..24].copy_from_slice(&1u32.to_be_bytes());
        hdr[24..28].copy_from_slice(&28u32.to_be_bytes());
        let ike = Ikev2Header::ref_from_prefix(&hdr).unwrap().0;
        assert_eq!(ike.initiator_spi(), 0x1122334455667788);
        assert_eq!(ike.message_id(), 1);
        assert_eq!(ike.length(), 28);
    }

    // --- SSH ---
    #[test]
    fn ssh_is_leaf() {
        let ops = SshOps;
        assert!(matches!(ops.next_proto(&[0u8; 5]), Err(ParseError::UnknownProto)));
    }

    #[test]
    fn ssh_header_fields() {
        let mut hdr = [0u8; 5];
        hdr[0..4].copy_from_slice(&100u32.to_be_bytes());
        hdr[4] = 8;
        let ssh = SshHeader::ref_from_prefix(&hdr).unwrap().0;
        assert_eq!(ssh.packet_length(), 100);
        assert_eq!(ssh.padding_length, 8);
    }

    // --- Kerberos ---
    #[test]
    fn kerberos_is_leaf() {
        let ops = KerberosOps;
        assert!(matches!(ops.next_proto(&[0u8; 1]), Err(ParseError::UnknownProto)));
    }

    // --- OCSP ---
    #[test]
    fn ocsp_is_leaf() {
        let ops = OcspOps;
        assert!(matches!(ops.next_proto(&[0u8; 1]), Err(ParseError::UnknownProto)));
    }

    // --- NTLMSSP ---
    #[test]
    fn ntlmssp_is_leaf() {
        let ops = NtlmsspOps;
        assert!(matches!(ops.next_proto(&[0u8; 12]), Err(ParseError::UnknownProto)));
    }

    #[test]
    fn ntlmssp_header_fields() {
        let mut hdr = [0u8; 12];
        hdr[0..8].copy_from_slice(b"NTLMSSP\0");
        hdr[8..12].copy_from_slice(&1u32.to_le_bytes()); // negotiate
        let n = NtlmsspHeader::ref_from_prefix(&hdr).unwrap().0;
        assert_eq!(&n.signature, b"NTLMSSP\0");
        assert_eq!(n.message_type(), 1);
    }

    // --- TACACS+ ---
    #[test]
    fn tacacs_is_leaf() {
        let ops = TacacsOps;
        assert!(matches!(ops.next_proto(&[0u8; 12]), Err(ParseError::UnknownProto)));
    }

    #[test]
    fn tacacs_header_fields() {
        let mut hdr = [0u8; 12];
        hdr[0] = 0xC1; // major=12, minor=1
        hdr[1] = 1; // authentication
        hdr[4..8].copy_from_slice(&0xAABBCCDDu32.to_be_bytes());
        hdr[8..12].copy_from_slice(&64u32.to_be_bytes());
        let t = TacacsHeader::ref_from_prefix(&hdr).unwrap().0;
        assert_eq!(t.major_version(), 12);
        assert_eq!(t.minor_version(), 1);
        assert_eq!(t.session_id(), 0xAABBCCDD);
        assert_eq!(t.length(), 64);
    }
}
