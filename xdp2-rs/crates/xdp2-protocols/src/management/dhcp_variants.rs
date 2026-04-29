//! DHCP option protocol definitions (leaf nodes).
//!
//! These correspond to Gold-tier protocols: DHCP_Option and DHCPv6_Option,
//! representing individual option TLVs within DHCP/DHCPv6 messages.

use xdp2_core::{ParseError, ProtocolOps};

// ---------------------------------------------------------------------------
// DHCP_Option
// ---------------------------------------------------------------------------

/// DHCP option operations (leaf).
pub struct DhcpOptionOps;

impl ProtocolOps for DhcpOptionOps {
    const MIN_LEN: usize = 2;
    const NAME: &'static str = "DHCP_Option";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

// ---------------------------------------------------------------------------
// DHCPv6_Option
// ---------------------------------------------------------------------------

/// DHCPv6 option operations (leaf).
pub struct Dhcpv6OptionOps;

impl ProtocolOps for Dhcpv6OptionOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "DHCPv6_Option";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dhcp_option_is_leaf() {
        assert!(matches!(
            DhcpOptionOps.next_proto(&[0u8; 2]),
            Err(ParseError::UnknownProto)
        ));
    }

    #[test]
    fn dhcpv6_option_is_leaf() {
        assert!(matches!(
            Dhcpv6OptionOps.next_proto(&[0u8; 4]),
            Err(ParseError::UnknownProto)
        ));
    }
}
