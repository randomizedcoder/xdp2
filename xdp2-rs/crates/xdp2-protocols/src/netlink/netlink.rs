//! Netlink message header (RFC 3549) protocol definition.
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `NetlinkHeader` | `proto_defs/netlink/proto_netlink.h` | `struct nlmsghdr` |
//! | `NetlinkOps` | `proto_netlink.h:68-72` | `xdp2_parse_netlink` |
//! | `NetlinkOps::next_proto` | `proto_netlink.h:54-57` | `netlink_proto()` |
//!
//! ## Behavioral Differences
//! - None. Byte-for-byte compatible with C implementation.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// Netlink message header (16 bytes).
///
/// Reimplements: `struct nlmsghdr` in `proto_netlink.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct NetlinkHeader {
    pub nlmsg_len: [u8; 4],
    pub nlmsg_type: [u8; 2],
    pub nlmsg_flags: [u8; 2],
    pub nlmsg_seq: [u8; 4],
    pub nlmsg_pid: [u8; 4],
}

impl NetlinkHeader {
    pub fn nlmsg_len(&self) -> u32 {
        u32::from_le_bytes(self.nlmsg_len)
    }
    pub fn nlmsg_type(&self) -> u16 {
        u16::from_le_bytes(self.nlmsg_type)
    }
    pub fn nlmsg_flags(&self) -> u16 {
        u16::from_le_bytes(self.nlmsg_flags)
    }
    pub fn nlmsg_seq(&self) -> u32 {
        u32::from_le_bytes(self.nlmsg_seq)
    }
    pub fn nlmsg_pid(&self) -> u32 {
        u32::from_le_bytes(self.nlmsg_pid)
    }
}

/// Netlink protocol operations.
///
/// Reimplements: `xdp2_parse_netlink` in `proto_netlink.h:68-72`
///
/// Dispatches on `nlmsg_type` field.
pub struct NetlinkOps;

impl ProtocolOps for NetlinkOps {
    const MIN_LEN: usize = 16;
    const NAME: &'static str = "Netlink";

    /// Return nlmsg_type for dispatch.
    ///
    /// Reimplements: `netlink_proto()` in `proto_netlink.h:54-57`
    #[inline]
    fn next_proto(&self, hdr: &[u8]) -> Result<i32, ParseError> {
        let nl = NetlinkHeader::ref_from_prefix(hdr)
            .map_err(|_| ParseError::Length)?
            .0;
        Ok(nl.nlmsg_type() as i32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_netlink(msg_type: u16) -> [u8; 16] {
        let mut hdr = [0u8; 16];
        hdr[4..6].copy_from_slice(&msg_type.to_le_bytes());
        hdr
    }

    #[test]
    fn netlink_dispatch() {
        let ops = NetlinkOps;
        assert_eq!(ops.next_proto(&make_netlink(0x10)).unwrap(), 0x10);
        assert_eq!(ops.next_proto(&make_netlink(1)).unwrap(), 1); // NLMSG_NOOP
    }

    #[test]
    fn netlink_short() {
        let ops = NetlinkOps;
        assert!(ops.next_proto(&[0u8; 4]).is_err());
    }
}
