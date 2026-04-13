//! SCTP chunk definitions (RFC 9260, Section 3.2).
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `SctpChunkHeader` | `<linux/sctp.h>` | `struct sctp_chunkhdr` |
//! | `SctpChunkTlvOps` | `proto_defs/transport/proto_sctp_chunk.h:77-85` | `xdp2_parse_sctp_chunks` |
//! | `sctp_chunk_len()` | `proto_sctp_chunk.h:51-57` | `sctp_chunk_len()` |
//! | `sctp_chunk_type()` | `proto_sctp_chunk.h:59-62` | `sctp_chunk_type()` |
//! | `sctp_chunks_start_offset()` | `proto_sctp_chunk.h:64-67` | `sctp_chunks_start_offset()` |
//!
//! ## Behavioral Differences
//! - None. Byte-for-byte compatible with C implementation.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// SCTP chunk types.
pub const SCTP_CID_DATA: u8 = 0;
pub const SCTP_CID_INIT: u8 = 1;
pub const SCTP_CID_INIT_ACK: u8 = 2;
pub const SCTP_CID_SACK: u8 = 3;
pub const SCTP_CID_HEARTBEAT: u8 = 4;
pub const SCTP_CID_HEARTBEAT_ACK: u8 = 5;
pub const SCTP_CID_ABORT: u8 = 6;
pub const SCTP_CID_SHUTDOWN: u8 = 7;
pub const SCTP_CID_SHUTDOWN_ACK: u8 = 8;
pub const SCTP_CID_ERROR: u8 = 9;
pub const SCTP_CID_COOKIE_ECHO: u8 = 10;
pub const SCTP_CID_COOKIE_ACK: u8 = 11;
pub const SCTP_CID_FWD_TSN: u8 = 0xC0;

/// SCTP chunk header (4 bytes).
///
/// Reimplements: `struct sctp_chunkhdr` from `<linux/sctp.h>`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct SctpChunkHeader {
    /// Chunk type
    pub chunk_type: u8,
    /// Chunk flags
    pub flags: u8,
    /// Chunk length (includes header, NOT padded)
    pub length: [u8; 2],
}

impl SctpChunkHeader {
    /// Chunk type.
    ///
    /// Reimplements: `sctp_chunk_type()` in `proto_sctp_chunk.h:59-62`
    pub fn chunk_type(&self) -> u8 {
        self.chunk_type
    }

    /// Chunk length including header (from length field).
    pub fn chunk_length(&self) -> u16 {
        u16::from_be_bytes(self.length)
    }

    /// Chunk length rounded up to 4-byte boundary.
    ///
    /// Reimplements: `sctp_chunk_len()` in `proto_sctp_chunk.h:51-57`
    pub fn padded_length(&self) -> usize {
        (self.chunk_length() as usize + 3) & !3
    }
}

/// TLV operations for SCTP chunk parsing.
///
/// Reimplements: `xdp2_parse_sctp_chunks` in `proto_sctp_chunk.h:77-85`
///
/// In the C implementation this is a `proto_tlvs_def` with `node_type = TLVS`.
/// Chunks start after the 12-byte SCTP common header.
pub struct SctpChunkTlvOps;

impl SctpChunkTlvOps {
    /// Minimum chunk size.
    pub const MIN_CHUNK_LEN: usize = 4; // sizeof(struct sctp_chunkhdr)

    /// Offset where chunks begin (after SCTP common header).
    ///
    /// Reimplements: `sctp_chunks_start_offset()` in `proto_sctp_chunk.h:64-67`
    pub const START_OFFSET: usize = 12; // sizeof(struct sctphdr)

    /// Get chunk type from header.
    ///
    /// Reimplements: `sctp_chunk_type()` in `proto_sctp_chunk.h:59-62`
    pub fn chunk_type(hdr: &[u8]) -> Result<u8, ParseError> {
        let chunk = SctpChunkHeader::ref_from_prefix(hdr)
            .map_err(|_| ParseError::Length)?
            .0;
        Ok(chunk.chunk_type())
    }

    /// Get chunk length (padded to 4-byte boundary).
    ///
    /// Reimplements: `sctp_chunk_len()` in `proto_sctp_chunk.h:51-57`
    pub fn chunk_len(hdr: &[u8]) -> Result<usize, ParseError> {
        let chunk = SctpChunkHeader::ref_from_prefix(hdr)
            .map_err(|_| ParseError::Length)?
            .0;
        Ok(chunk.padded_length())
    }
}

/// SCTP with chunks protocol operations.
///
/// Reimplements the base proto_def within `xdp2_parse_sctp_chunks`
/// in `proto_sctp_chunk.h:79`.
///
/// This represents the SCTP-with-TLV-chunks variant. The header is the
/// standard 12-byte SCTP header; chunk TLVs follow at offset 12.
pub struct SctpWithChunksOps;

impl ProtocolOps for SctpWithChunksOps {
    const MIN_LEN: usize = 12; // sizeof(struct sctphdr)
    const NAME: &'static str = "SCTP with chunks";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto) // TLV sub-parsing handles chunks
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_chunk(chunk_type: u8, length: u16) -> [u8; 4] {
        let mut hdr = [0u8; 4];
        hdr[0] = chunk_type;
        hdr[2..4].copy_from_slice(&length.to_be_bytes());
        hdr
    }

    #[test]
    fn chunk_type_extraction() {
        let hdr = make_chunk(SCTP_CID_DATA, 16);
        assert_eq!(SctpChunkTlvOps::chunk_type(&hdr).unwrap(), SCTP_CID_DATA);
    }

    #[test]
    fn chunk_length_padded() {
        // length=17 → padded to 20
        let hdr = make_chunk(SCTP_CID_DATA, 17);
        assert_eq!(SctpChunkTlvOps::chunk_len(&hdr).unwrap(), 20);
    }

    #[test]
    fn chunk_length_already_aligned() {
        // length=16 → stays 16
        let hdr = make_chunk(SCTP_CID_DATA, 16);
        assert_eq!(SctpChunkTlvOps::chunk_len(&hdr).unwrap(), 16);
    }

    #[test]
    fn chunk_start_offset() {
        assert_eq!(SctpChunkTlvOps::START_OFFSET, 12);
    }

    #[test]
    fn sctp_with_chunks_is_leaf() {
        let ops = SctpWithChunksOps;
        assert!(ops.next_proto(&[0u8; 12]).is_err());
    }
}
