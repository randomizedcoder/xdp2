//! TCP protocol definition.
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `TcpHeader` | `<linux/tcp.h>` | `struct tcphdr` |
//! | `TcpOps` | `proto_defs/transport/proto_tcp.h` | `xdp2_parse_tcp` |
//! | `TcpOps::header_len` | `proto_tcp.h` | `tcp_len()` |
//!
//! ## Behavioral Differences
//! - None. Byte-for-byte compatible with C implementation.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout, NetworkEndian, U16};

/// TCP header (minimum 20 bytes, variable via data offset).
///
/// Reimplements: `struct tcphdr` from `<linux/tcp.h>`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct TcpHeader {
    /// Source port
    pub source: U16<NetworkEndian>,
    /// Destination port
    pub dest: U16<NetworkEndian>,
    /// Sequence number
    pub seq: [u8; 4],
    /// Acknowledgment number
    pub ack_seq: [u8; 4],
    /// Data offset (4 bits) + reserved (3 bits) + NS flag (1 bit)
    pub doff_reserved: u8,
    /// Flags (CWR, ECE, URG, ACK, PSH, RST, SYN, FIN)
    pub flags: u8,
    /// Window size
    pub window: U16<NetworkEndian>,
    /// Checksum
    pub check: [u8; 2],
    /// Urgent pointer
    pub urg_ptr: [u8; 2],
}

impl TcpHeader {
    /// Data offset in bytes (doff field * 4).
    pub fn data_offset_bytes(&self) -> usize {
        ((self.doff_reserved >> 4) as usize) * 4
    }

    /// Source port (host byte order).
    pub fn src_port(&self) -> u16 {
        self.source.get()
    }

    /// Destination port (host byte order).
    pub fn dst_port(&self) -> u16 {
        self.dest.get()
    }
}

/// TCP protocol operations (leaf node — no next protocol).
///
/// Reimplements: `xdp2_parse_tcp` in `proto_defs/transport/proto_tcp.h`
///
/// Variable-length header (20-60 bytes via data offset field).
/// TCP is typically a leaf node in the parse graph.
pub struct TcpOps;

impl ProtocolOps for TcpOps {
    const MIN_LEN: usize = 20; // sizeof(struct tcphdr)
    const NAME: &'static str = "TCP";

    /// Return header length from data offset field.
    #[inline]
    fn header_len(&self, hdr: &[u8], _maxlen: usize) -> Result<usize, ParseError> {
        let tcp = TcpHeader::ref_from_prefix(hdr)
            .map_err(|_| ParseError::Length)?
            .0;
        Ok(tcp.data_offset_bytes())
    }

    /// TCP is a leaf — no next protocol.
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tcp_header(doff: u8, src_port: u16, dst_port: u16) -> [u8; 20] {
        let mut hdr = [0u8; 20];
        let src = src_port.to_be_bytes();
        let dst = dst_port.to_be_bytes();
        hdr[0] = src[0];
        hdr[1] = src[1];
        hdr[2] = dst[0];
        hdr[3] = dst[1];
        hdr[12] = doff << 4; // data offset in upper 4 bits
        hdr
    }

    #[test]
    fn tcp_standard_header() {
        let hdr = make_tcp_header(5, 12345, 80); // doff=5 → 20 bytes
        let ops = TcpOps;
        assert_eq!(ops.header_len(&hdr, 100).unwrap(), 20);
    }

    #[test]
    fn tcp_with_options() {
        let mut hdr = [0u8; 32];
        hdr[12] = 8 << 4; // doff=8 → 32 bytes
        let ops = TcpOps;
        assert_eq!(ops.header_len(&hdr, 100).unwrap(), 32);
    }

    #[test]
    fn tcp_ports() {
        let hdr = make_tcp_header(5, 12345, 80);
        let tcp = TcpHeader::ref_from_prefix(&hdr).unwrap().0;
        assert_eq!(tcp.src_port(), 12345);
        assert_eq!(tcp.dst_port(), 80);
    }

    #[test]
    fn tcp_is_leaf() {
        let hdr = make_tcp_header(5, 0, 0);
        let ops = TcpOps;
        assert!(ops.next_proto(&hdr).is_err());
    }
}
