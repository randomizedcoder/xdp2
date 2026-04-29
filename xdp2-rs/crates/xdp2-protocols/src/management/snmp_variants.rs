//! SNMP variant protocol leaf definitions.

use xdp2_core::{ParseError, ProtocolOps};

/// SNMP Trap protocol operations (leaf, MIN_LEN = 1).
pub struct SnmpTrapOps;
impl ProtocolOps for SnmpTrapOps {
    const MIN_LEN: usize = 1;
    const NAME: &'static str = "SNMP_Trap";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// SNMPv3 protocol operations (leaf, MIN_LEN = 1).
pub struct Snmpv3Ops;
impl ProtocolOps for Snmpv3Ops {
    const MIN_LEN: usize = 1;
    const NAME: &'static str = "SNMPv3";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// sFlow v5 protocol operations (leaf, MIN_LEN = 28).
pub struct SflowV5Ops;
impl ProtocolOps for SflowV5Ops {
    const MIN_LEN: usize = 28;
    const NAME: &'static str = "SFLOW_V5";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}
