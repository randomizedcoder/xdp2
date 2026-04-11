//! Core types, return codes, and control data structures.
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `ParseError` | `parser_types.h:59-95` | `XDP2_STOP_*` enum constants |
//! | `ParseResult` | `parser_types.h:60-68` | `XDP2_OKAY`, `XDP2_STOP_OKAY`, etc. |
//! | `NodeType` | `parser_types.h:108-117` | `enum xdp2_parser_node_type` |
//! | `ParserType` | `parser_types.h:98-105` | `enum xdp2_parser_type` |
//! | `CtrlVarData` | `parser_types.h:186-194` | `struct xdp2_ctrl_var_data` |
//! | `CtrlPacketData` | `parser_types.h:174-184` | `struct xdp2_ctrl_packet_data` |
//! | `CtrlKeyData` | `parser_types.h:196-200` | `struct xdp2_ctrl_key_data` |
//! | `CtrlData` | `parser_types.h:202-206` | `struct xdp2_ctrl_data` |

/// Parser return codes indicating successful completion.
///
/// Reimplements: `parser_types.h:60-68` (`XDP2_OKAY` through `XDP2_STOP_SUB_NODE_OKAY`)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseResult {
    /// Parsing completed successfully (XDP2_OKAY = 0)
    Okay,
    /// Use wildcard node (XDP2_OKAY_USE_WILD = -2)
    UseWild,
    /// Use alternate wildcard node (XDP2_OKAY_USE_ALT_WILD = -3)
    UseAltWild,
    /// Okay, stop parsing (XDP2_STOP_OKAY = -4)
    StopOkay,
    /// Stop parsing current node (XDP2_STOP_NODE_OKAY = -5)
    StopNodeOkay,
    /// Stop parsing current sub-node (XDP2_STOP_SUB_NODE_OKAY = -6)
    StopSubNodeOkay,
}

/// Parser error codes indicating failure conditions.
///
/// Reimplements: `parser_types.h:70-95` (`XDP2_STOP_FAIL` through `XDP2_STOP_THREADS_FAIL`)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    /// General failure (XDP2_STOP_FAIL = -12)
    Fail,
    /// Header too short (XDP2_STOP_LENGTH = -13)
    Length,
    /// Unknown protocol number (XDP2_STOP_UNKNOWN_PROTO = -14)
    UnknownProto,
    /// Maximum encapsulation depth exceeded (XDP2_STOP_ENCAP_DEPTH = -15)
    EncapDepth,
    /// Unknown TLV type (XDP2_STOP_UNKNOWN_TLV = -16)
    UnknownTlv,
    /// TLV length error (XDP2_STOP_TLV_LENGTH = -17)
    TlvLength,
    /// Bad flag value (XDP2_STOP_BAD_FLAG = -18)
    BadFlag,
    /// Comparison failure (XDP2_STOP_FAIL_CMP = -19)
    FailCmp,
    /// Loop count exceeded (XDP2_STOP_LOOP_CNT = -20)
    LoopCount,
    /// TLV padding error (XDP2_STOP_TLV_PADDING = -21)
    TlvPadding,
    /// Option limit exceeded (XDP2_STOP_OPTION_LIMIT = -22)
    OptionLimit,
    /// Maximum nodes exceeded (XDP2_STOP_MAX_NODES = -23)
    MaxNodes,
    /// Compare stop (XDP2_STOP_COMPARE = -24)
    Compare,
    /// Bad extract (XDP2_STOP_BAD_EXTRACT = -25)
    BadExtract,
    /// Bad counter (XDP2_STOP_BAD_CNTR = -26)
    BadCounter,
    /// Counter stops (XDP2_STOP_CNTR1..7 = -27..-33)
    Counter(u8),
    /// Thread failure (XDP2_STOP_THREADS_FAIL = -34)
    ThreadsFail,
}

impl ParseError {
    /// Convert from C-style integer return code.
    ///
    /// Reimplements: implicit integer-to-enum mapping in `parser_types.h:70-95`
    pub fn from_c_code(code: i32) -> Option<Self> {
        match code {
            -12 => Some(Self::Fail),
            -13 => Some(Self::Length),
            -14 => Some(Self::UnknownProto),
            -15 => Some(Self::EncapDepth),
            -16 => Some(Self::UnknownTlv),
            -17 => Some(Self::TlvLength),
            -18 => Some(Self::BadFlag),
            -19 => Some(Self::FailCmp),
            -20 => Some(Self::LoopCount),
            -21 => Some(Self::TlvPadding),
            -22 => Some(Self::OptionLimit),
            -23 => Some(Self::MaxNodes),
            -24 => Some(Self::Compare),
            -25 => Some(Self::BadExtract),
            -26 => Some(Self::BadCounter),
            -33..=-27 => Some(Self::Counter((-code - 27) as u8 + 1)),
            -34 => Some(Self::ThreadsFail),
            _ => None,
        }
    }

    /// Convert to C-style integer return code.
    pub fn to_c_code(self) -> i32 {
        match self {
            Self::Fail => -12,
            Self::Length => -13,
            Self::UnknownProto => -14,
            Self::EncapDepth => -15,
            Self::UnknownTlv => -16,
            Self::TlvLength => -17,
            Self::BadFlag => -18,
            Self::FailCmp => -19,
            Self::LoopCount => -20,
            Self::TlvPadding => -21,
            Self::OptionLimit => -22,
            Self::MaxNodes => -23,
            Self::Compare => -24,
            Self::BadExtract => -25,
            Self::BadCounter => -26,
            Self::Counter(n) => -(27 + (n.saturating_sub(1)) as i32),
            Self::ThreadsFail => -34,
        }
    }
}

impl ParseResult {
    /// Convert from C-style integer return code.
    ///
    /// Reimplements: implicit integer-to-enum mapping in `parser_types.h:60-68`
    pub fn from_c_code(code: i32) -> Option<Self> {
        match code {
            0 => Some(Self::Okay),
            -2 => Some(Self::UseWild),
            -3 => Some(Self::UseAltWild),
            -4 => Some(Self::StopOkay),
            -5 => Some(Self::StopNodeOkay),
            -6 => Some(Self::StopSubNodeOkay),
            _ => None,
        }
    }

    /// Convert to C-style integer return code.
    pub fn to_c_code(self) -> i32 {
        match self {
            Self::Okay => 0,
            Self::UseWild => -2,
            Self::UseAltWild => -3,
            Self::StopOkay => -4,
            Self::StopNodeOkay => -5,
            Self::StopSubNodeOkay => -6,
        }
    }
}

/// Classify a C-style return code as either a result or error.
///
/// In C, return codes >= 0 are protocol numbers, 0 to -6 are okay/stop codes,
/// and <= -12 are errors. Values -1, -7 to -11 are unused/reserved.
pub fn classify_return_code(code: i32) -> Result<ParseResult, ParseError> {
    if code >= 0 {
        Ok(ParseResult::Okay)
    } else if let Some(result) = ParseResult::from_c_code(code) {
        Ok(result)
    } else if let Some(error) = ParseError::from_c_code(code) {
        Err(error)
    } else {
        Err(ParseError::Fail)
    }
}

/// Parse node type — determines which sub-parsing system is used.
///
/// Reimplements: `enum xdp2_parser_node_type` in `parser_types.h:108-117`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NodeType {
    /// Plain node, no sub-structure (XDP2_NODE_TYPE_PLAIN)
    #[default]
    Plain,
    /// TLVs node with sub-structure for TLV parsing (XDP2_NODE_TYPE_TLVS)
    Tlvs,
    /// Flag-fields node (XDP2_NODE_TYPE_FLAG_FIELDS)
    FlagFields,
    /// Array node (XDP2_NODE_TYPE_ARRAY)
    Array,
}

/// Parser algorithm type.
///
/// Reimplements: `enum xdp2_parser_type` in `parser_types.h:98-105`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ParserType {
    /// Non-optimized loop parser (XDP2_GENERIC)
    #[default]
    Generic,
    /// Optimized generated parser (XDP2_OPTIMIZED)
    Optimized,
    /// XDP/eBPF parser (XDP2_XDP)
    Xdp,
}

/// Variable parsing state tracked during parse execution.
///
/// Reimplements: `struct xdp2_ctrl_var_data` in `parser_types.h:186-194`
#[derive(Debug, Clone, Default)]
pub struct CtrlVarData {
    /// Return code from last operation
    pub ret_code: i8,
    /// Number of encapsulations seen
    pub encaps: u8,
    /// Number of nodes visited
    pub node_cnt: u8,
    /// Number of TLV nesting levels
    pub tlv_levels: u8,
    /// Packet checksum to header start
    pub pkt_csum: u16,
    /// Checksum of current header
    pub hdr_csum: u16,
}

/// Per-packet data provided by the caller.
///
/// Reimplements: `struct xdp2_ctrl_packet_data` in `parser_types.h:174-184`
#[derive(Debug, Clone, Default)]
pub struct CtrlPacketData {
    /// Full length of packet
    pub pkt_len: usize,
    /// Sequence number per interface
    pub seqno: u32,
    /// Received timestamp
    pub timestamp: u32,
    /// Received port number
    pub in_port: u32,
    /// Interface/VRF ID
    pub vrf_id: u32,
    /// Checksum over packet
    pub pkt_csum: u16,
    /// Flags
    pub flags: u16,
}

/// Key/counter data for inter-node communication.
///
/// Reimplements: `struct xdp2_ctrl_key_data` in `parser_types.h:196-200`
#[derive(Debug, Clone, Default)]
pub struct CtrlKeyData {
    /// Array of 8-bit counters
    pub counters: Vec<u8>,
    /// Array of keys for passing between nodes
    pub keys: Vec<u32>,
}

/// Centralized control data for a parse operation.
///
/// Reimplements: `struct xdp2_ctrl_data` in `parser_types.h:202-206`
#[derive(Debug, Clone, Default)]
pub struct CtrlData {
    pub var: CtrlVarData,
    pub pkt: CtrlPacketData,
    pub key: CtrlKeyData,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_error_c_code_roundtrip() {
        let codes = [
            -12, -13, -14, -15, -16, -17, -18, -19, -20, -21, -22, -23, -24,
            -25, -26, -27, -28, -29, -30, -31, -32, -33, -34,
        ];
        for code in codes {
            let err = ParseError::from_c_code(code).unwrap_or_else(|| {
                panic!("Failed to parse error code {code}")
            });
            assert_eq!(err.to_c_code(), code, "Roundtrip failed for {code}");
        }
    }

    #[test]
    fn parse_result_c_code_roundtrip() {
        let codes = [0, -2, -3, -4, -5, -6];
        for code in codes {
            let result = ParseResult::from_c_code(code).unwrap();
            assert_eq!(result.to_c_code(), code);
        }
    }

    #[test]
    fn classify_positive_is_okay() {
        assert_eq!(classify_return_code(6).unwrap(), ParseResult::Okay);
        assert_eq!(classify_return_code(0).unwrap(), ParseResult::Okay);
    }

    #[test]
    fn classify_negative_errors() {
        assert!(classify_return_code(-13).is_err());
        assert_eq!(
            classify_return_code(-13).unwrap_err(),
            ParseError::Length
        );
    }
}
