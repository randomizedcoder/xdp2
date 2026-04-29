//! HCI variant protocol definitions (leaf nodes).
//!
//! HCI_CMD corresponds to the Gold-tier proto-audit entry for the
//! HCI command packet type with its 3-byte minimum header.

use xdp2_core::{ParseError, ProtocolOps};

// ---------------------------------------------------------------------------
// HCI_CMD
// ---------------------------------------------------------------------------

/// HCI command operations (leaf).
pub struct HciCmdOps;

impl ProtocolOps for HciCmdOps {
    const MIN_LEN: usize = 3;
    const NAME: &'static str = "HCI_CMD";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hci_cmd_is_leaf() {
        assert!(matches!(
            HciCmdOps.next_proto(&[0u8; 3]),
            Err(ParseError::UnknownProto)
        ));
    }
}
