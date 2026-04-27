//! UE Specification v1.0.2 field definition extractor.
//!
//! Provides an independent second source for UET protocol field layouts,
//! transcribed from the authoritative wire-format tables in the
//! Ultra Ethernet Specification v1.0.2, Section 3.
//!
//! PDS: Tables 3-31 through 3-42
//! SES: Tables 3-8 through 3-13
//!
//! Cross-validating these against the C header extractor (`xdp2_headers`)
//! enables Silver-tier confidence for UET protocols.

use crate::ir::{FieldDef, ProtocolDef, SourceInfo};

/// A spec-derived field definition.
struct SpecField {
    name: &'static str,
    bits: u32,
}

/// A spec-derived protocol header definition.
struct SpecHeader {
    /// Display name
    name: &'static str,
    /// UE spec table reference (e.g., "Table 3-35")
    table_ref: &'static str,
    /// Fields in wire order
    fields: &'static [SpecField],
}

const fn sf(name: &'static str, bits: u32) -> SpecField {
    SpecField { name, bits }
}

// ── PDS headers (Tables 3-31 through 3-42) ──

/// Table 3-31: UET Entropy Header
static PDS_ENTROPY: SpecHeader = SpecHeader {
    name: "UET Entropy Header",
    table_ref: "Table 3-31",
    fields: &[
        sf("entropy", 16),
        sf("reserved", 16),
    ],
};

/// Table 3-32: PDS Prologue
static PDS_PROLOGUE: SpecHeader = SpecHeader {
    name: "UET-PDS Prologue",
    table_ref: "Table 3-32",
    fields: &[
        sf("type", 5),
        sf("next_hdr_ctrl", 4),
        sf("flags", 7),
    ],
};

/// Table 3-33: RUD/ROD Request
static PDS_RUD_ROD_REQUEST: SpecHeader = SpecHeader {
    name: "UET-PDS RUD/ROD Request",
    table_ref: "Table 3-33",
    fields: &[
        sf("type", 5),
        sf("next_hdr", 4),
        sf("rsvd1", 2),
        sf("retrans", 1),
        sf("ackreq", 1),
        sf("syn", 1),
        sf("rsvd2", 2),
        sf("clear_psn_offset", 16),
        sf("psn", 32),
        sf("spdcid", 16),
        sf("dpdcid", 16),
    ],
};

/// Table 3-34: RUD/ROD Request with CC
static PDS_RUD_ROD_REQUEST_CC: SpecHeader = SpecHeader {
    name: "UET-PDS RUD/ROD Request with CC",
    table_ref: "Table 3-34",
    fields: &[
        sf("type", 5),
        sf("next_hdr", 4),
        sf("rsvd1", 2),
        sf("retrans", 1),
        sf("ackreq", 1),
        sf("syn", 1),
        sf("rsvd2", 2),
        sf("clear_psn_offset", 16),
        sf("psn", 32),
        sf("spdcid", 16),
        sf("dpdcid", 16),
        sf("ccc_id", 8),
        sf("credit_target", 24),
    ],
};

/// Table 3-35: ACK
static PDS_ACK: SpecHeader = SpecHeader {
    name: "UET-PDS ACK",
    table_ref: "Table 3-35",
    fields: &[
        sf("type", 5),
        sf("next_hdr", 4),
        sf("rsvd1", 1),
        sf("ecn_marked", 1),
        sf("retrans", 1),
        sf("probe", 1),
        sf("request", 2),
        sf("rsvd2", 1),
        sf("ack_psn_offset", 16),
        sf("cack_psn", 32),
        sf("spdcid", 16),
        sf("dpdcid", 16),
    ],
};

/// Table 3-36: ACK with CC (NSCC variant shown; Credit variant has same size)
static PDS_ACK_CC: SpecHeader = SpecHeader {
    name: "UET-PDS ACK CC",
    table_ref: "Table 3-36",
    fields: &[
        sf("type", 5),
        sf("next_hdr", 4),
        sf("rsvd1", 1),
        sf("ecn_marked", 1),
        sf("retrans", 1),
        sf("probe", 1),
        sf("request", 2),
        sf("rsvd2", 1),
        sf("ack_psn_offset", 16),
        sf("cack_psn", 32),
        sf("spdcid", 16),
        sf("dpdcid", 16),
        sf("cc_type", 4),
        sf("cc_flags", 4),
        sf("mpr", 8),
        sf("sack_psn_offset", 16),
        sf("sack_bitmap", 64),
        sf("ack_cc_state", 64),
    ],
};

/// Table 3-37: ACK with CCX
static PDS_ACK_CCX: SpecHeader = SpecHeader {
    name: "UET-PDS ACK CC Extended",
    table_ref: "Table 3-37",
    fields: &[
        sf("type", 5),
        sf("next_hdr", 4),
        sf("rsvd1", 1),
        sf("ecn_marked", 1),
        sf("retrans", 1),
        sf("probe", 1),
        sf("request", 2),
        sf("rsvd2", 1),
        sf("ack_psn_offset", 16),
        sf("cack_psn", 32),
        sf("spdcid", 16),
        sf("dpdcid", 16),
        sf("ccx_type", 4),
        sf("cc_flags", 4),
        sf("mpr", 8),
        sf("sack_psn_offset", 16),
        sf("sack_bitmap", 64),
        sf("ack_cc_state", 64),
    ],
};

/// Table 3-38: Control Packet
static PDS_CONTROL_PKT: SpecHeader = SpecHeader {
    name: "UET-PDS Control Packet",
    table_ref: "Table 3-38",
    fields: &[
        sf("type", 5),
        sf("ctl_type", 4),
        sf("rsvd1", 1),
        sf("rsvd_isrod", 1),
        sf("retrans", 1),
        sf("ackreq", 1),
        sf("syn", 1),
        sf("rsvd2", 2),
        sf("probe_opaque", 16),
        sf("psn", 32),
        sf("spdcid", 16),
        sf("dpdcid", 16),
        sf("payload", 32),
    ],
};

/// Table 3-39: RUDI Request/Response
static PDS_RUDI_REQ_RESP: SpecHeader = SpecHeader {
    name: "UET-PDS RUDI Request/Response",
    table_ref: "Table 3-39",
    fields: &[
        sf("type", 5),
        sf("next_hdr", 4),
        sf("rsvd1", 1),
        sf("ecn_marked", 1),
        sf("retrans", 1),
        sf("rsvd2", 4),
        sf("rsvd3", 16),
        sf("pkt_id", 32),
    ],
};

/// Table 3-40: NACK
static PDS_NACK: SpecHeader = SpecHeader {
    name: "UET-PDS NACK",
    table_ref: "Table 3-40",
    fields: &[
        sf("type", 5),
        sf("next_hdr", 4),
        sf("rsvd1", 1),
        sf("ecn_marked", 1),
        sf("retrans", 1),
        sf("nack_type", 1),
        sf("rsvd2", 3),
        sf("nack_code", 8),
        sf("vendor_code", 8),
        sf("nack_psn", 32),
        sf("spdcid", 16),
        sf("dpdcid", 16),
        sf("payload", 32),
    ],
};

/// Table 3-41: NACK with CCX
static PDS_NACK_CCX: SpecHeader = SpecHeader {
    name: "UET-PDS NACK CCX",
    table_ref: "Table 3-41",
    fields: &[
        sf("type", 5),
        sf("next_hdr", 4),
        sf("rsvd1", 1),
        sf("ecn_marked", 1),
        sf("retrans", 1),
        sf("nack_type", 1),
        sf("rsvd2", 3),
        sf("nack_code", 8),
        sf("vendor_code", 8),
        sf("nack_psn", 32),
        sf("spdcid", 16),
        sf("dpdcid", 16),
        sf("payload", 32),
        sf("nccx_type", 4),
        sf("nccx_ccx_state1", 4),
        sf("nack_ccx_state2", 56),
    ],
};

/// Table 3-42: UUD Request
static PDS_UUD_REQ: SpecHeader = SpecHeader {
    name: "UET-PDS UUD Request",
    table_ref: "Table 3-42",
    fields: &[
        sf("type", 5),
        sf("next_hdr", 4),
        sf("flags", 7),
        sf("rsvd", 16),
    ],
};

// ── SES headers (Tables 3-8 through 3-13) ──

/// Table 3-8/3-9: SES Common Header (used by standard, medium, small requests)
static SES_COMMON_HDR: SpecHeader = SpecHeader {
    name: "UET-SES Common Header",
    table_ref: "Table 3-8",
    fields: &[
        sf("rsvd1", 2),
        sf("opcode", 6),
        sf("version", 2),
        sf("delivery_complete", 1),
        sf("initiator_error", 1),
        sf("relative_addressing", 1),
        sf("hdr_data_present", 1),
        sf("end_of_msg", 1),
        sf("start_of_msg", 1),
        sf("message_id", 16),
        sf("ri_generation", 8),
        sf("job_id", 24),
        sf("rsvd2", 4),
        sf("pid_on_fep", 12),
        sf("rsvd3", 4),
        sf("resource_index", 12),
    ],
};

/// Table 3-9: SES Standard Request Header
static SES_REQUEST_STD: SpecHeader = SpecHeader {
    name: "UET-SES Standard Request",
    table_ref: "Table 3-9",
    fields: &[
        // common_hdr (96 bits)
        sf("rsvd1", 2),
        sf("opcode", 6),
        sf("version", 2),
        sf("delivery_complete", 1),
        sf("initiator_error", 1),
        sf("relative_addressing", 1),
        sf("hdr_data_present", 1),
        sf("end_of_msg", 1),
        sf("start_of_msg", 1),
        sf("message_id", 16),
        sf("ri_generation", 8),
        sf("job_id", 24),
        sf("rsvd2", 4),
        sf("pid_on_fep", 12),
        sf("rsvd3", 4),
        sf("resource_index", 12),
        // std-specific fields
        sf("buffer_offset", 64),
        sf("initiator", 32),
        sf("memory_key", 64),
        sf("header_data", 64),
        sf("request_length", 32),
    ],
};

/// Table 3-10: SES Small Request Header
static SES_REQUEST_SMALL: SpecHeader = SpecHeader {
    name: "UET-SES Small Request",
    table_ref: "Table 3-10",
    fields: &[
        // common_hdr (96 bits)
        sf("rsvd1", 2),
        sf("opcode", 6),
        sf("version", 2),
        sf("delivery_complete", 1),
        sf("initiator_error", 1),
        sf("relative_addressing", 1),
        sf("hdr_data_present", 1),
        sf("end_of_msg", 1),
        sf("start_of_msg", 1),
        sf("message_id", 16),
        sf("ri_generation", 8),
        sf("job_id", 24),
        sf("rsvd2", 4),
        sf("pid_on_fep", 12),
        sf("rsvd3", 4),
        sf("resource_index", 12),
        // small-specific fields
        sf("buffer_offset", 64),
    ],
};

/// SES Medium Request Header
static SES_REQUEST_MEDIUM: SpecHeader = SpecHeader {
    name: "UET-SES Medium Request",
    table_ref: "Table 3-10",
    fields: &[
        // common_hdr (96 bits)
        sf("rsvd1", 2),
        sf("opcode", 6),
        sf("version", 2),
        sf("delivery_complete", 1),
        sf("initiator_error", 1),
        sf("relative_addressing", 1),
        sf("hdr_data_present", 1),
        sf("end_of_msg", 1),
        sf("start_of_msg", 1),
        sf("message_id", 16),
        sf("ri_generation", 8),
        sf("job_id", 24),
        sf("rsvd2", 4),
        sf("pid_on_fep", 12),
        sf("rsvd3", 4),
        sf("resource_index", 12),
        // medium-specific fields
        sf("buffer_offset", 64),
        sf("initiator", 32),
        sf("memory_key", 64),
    ],
};

/// Table 3-11: SES Common Response Header
static SES_COMMON_RESPONSE: SpecHeader = SpecHeader {
    name: "UET-SES Common Response",
    table_ref: "Table 3-11",
    fields: &[
        sf("list", 2),
        sf("opcode", 6),
        sf("ver", 2),
        sf("return_code", 6),
        sf("message_id", 16),
        sf("ri_generation", 8),
        sf("job_id", 24),
    ],
};

/// SES No-Data Response Header
static SES_NODATA_RESPONSE: SpecHeader = SpecHeader {
    name: "UET-SES No-Data Response",
    table_ref: "Table 3-11",
    fields: &[
        sf("list", 2),
        sf("opcode", 6),
        sf("ver", 2),
        sf("return_code", 6),
        sf("message_id", 16),
        sf("ri_generation", 8),
        sf("job_id", 24),
        sf("modified_length", 32),
    ],
};

/// Table 3-12: SES Response with Data
static SES_WITH_DATA_RESPONSE: SpecHeader = SpecHeader {
    name: "UET-SES Response with Data",
    table_ref: "Table 3-12",
    fields: &[
        sf("list", 2),
        sf("opcode", 6),
        sf("ver", 2),
        sf("return_code", 6),
        sf("message_id", 16),
        sf("ri_generation", 8),
        sf("job_id", 24),
        sf("read_request_message_id", 16),
        sf("rsvd2", 4),
        sf("payload_length", 12),
        sf("modified_length", 32),
        sf("message_offset", 32),
    ],
};

/// Table 3-13: SES Response with Small Data
static SES_WITH_SMALL_DATA_RESPONSE: SpecHeader = SpecHeader {
    name: "UET-SES Response with Small Data",
    table_ref: "Table 3-13",
    fields: &[
        sf("list", 2),
        sf("opcode", 6),
        sf("ver", 2),
        sf("return_code", 6),
        sf("rsvd1", 2),
        sf("payload_length", 14),
        sf("rsvd2", 8),
        sf("job_id", 24),
        sf("original_request_psn", 32),
    ],
};

/// SES Base Header (opcode/version switching)
static SES_BASE_HDR: SpecHeader = SpecHeader {
    name: "UET-SES Base Header",
    table_ref: "Table 3-8",
    fields: &[
        sf("rsvd1", 2),
        sf("opcode", 6),
        sf("version", 2),
        sf("rsvd2", 6),
        sf("flags", 8),
    ],
};

/// SES Rendezvous Extension Header
static SES_RENDEZVOUS_EXT: SpecHeader = SpecHeader {
    name: "UET-SES Rendezvous Extension",
    table_ref: "Table 3-9",
    fields: &[
        sf("eager_length", 32),
        sf("ri_generation", 8),
        sf("pid_on_fep", 12),
        sf("resource_index", 12),
    ],
};

/// SES Atomic Operation Extension Header
static SES_ATOMIC_OP_EXT: SpecHeader = SpecHeader {
    name: "UET-SES Atomic Op Extension",
    table_ref: "Table 3-9",
    fields: &[
        sf("atomic_code", 8),
        sf("atomic_datatype", 8),
        sf("semantic_control", 8),
        sf("rsvd2", 8),
    ],
};

/// All spec definitions, keyed by ue_spec_id.
static SPEC_DEFS: &[(&str, &SpecHeader)] = &[
    // PDS
    ("pds_entropy", &PDS_ENTROPY),
    ("pds_prologue", &PDS_PROLOGUE),
    ("pds_rud_rod_request", &PDS_RUD_ROD_REQUEST),
    ("pds_rud_rod_request_cc", &PDS_RUD_ROD_REQUEST_CC),
    ("pds_ack", &PDS_ACK),
    ("pds_ack_cc", &PDS_ACK_CC),
    ("pds_ack_ccx", &PDS_ACK_CCX),
    ("pds_control_pkt", &PDS_CONTROL_PKT),
    ("pds_rudi_req_resp", &PDS_RUDI_REQ_RESP),
    ("pds_nack", &PDS_NACK),
    ("pds_nack_ccx", &PDS_NACK_CCX),
    ("pds_uud_req", &PDS_UUD_REQ),
    // SES
    ("ses_base_hdr", &SES_BASE_HDR),
    ("ses_common_hdr", &SES_COMMON_HDR),
    ("ses_request_std", &SES_REQUEST_STD),
    ("ses_request_small", &SES_REQUEST_SMALL),
    ("ses_request_medium", &SES_REQUEST_MEDIUM),
    ("ses_common_response", &SES_COMMON_RESPONSE),
    ("ses_nodata_response", &SES_NODATA_RESPONSE),
    ("ses_with_data_response", &SES_WITH_DATA_RESPONSE),
    ("ses_with_small_data_response", &SES_WITH_SMALL_DATA_RESPONSE),
    ("ses_rendezvous_ext", &SES_RENDEZVOUS_EXT),
    ("ses_atomic_op_ext", &SES_ATOMIC_OP_EXT),
];

/// Convert a SpecHeader into a ProtocolDef.
fn spec_to_protocol_def(id: &str, spec: &SpecHeader) -> ProtocolDef {
    let mut fields = Vec::new();
    let mut offset: u32 = 0;

    for sf in spec.fields {
        fields.push(FieldDef {
            name: sf.name.to_string(),
            offset_bits: offset,
            size_bits: sf.bits,
            ..Default::default()
        });
        offset += sf.bits;
    }

    let total_bits = offset;
    let field_count = fields.len() as u32;

    ProtocolDef::new(spec.name, total_bits)
        .with_fields(fields)
        .with_source(
            "ue_spec",
            SourceInfo::new(id)
                .with_file(spec.table_ref)
                .with_field_count(field_count)
                .with_min_header_bytes(total_bits / 8),
        )
}

/// Extract a ProtocolDef from the embedded spec definitions.
///
/// `ue_spec_id` is the identifier from the name mapping table
/// (e.g., "pds_ack", "ses_common_hdr").
pub fn extract_protocol(ue_spec_id: &str) -> Option<ProtocolDef> {
    SPEC_DEFS
        .iter()
        .find(|(id, _)| *id == ue_spec_id)
        .map(|(id, spec)| spec_to_protocol_def(id, spec))
}

/// List all available spec definition IDs.
pub fn available_ids() -> Vec<&'static str> {
    SPEC_DEFS.iter().map(|(id, _)| *id).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pds_ack_fields() {
        let def = extract_protocol("pds_ack").unwrap();
        assert_eq!(def.min_header_bits, 96); // 12 bytes
        assert_eq!(def.fields.len(), 12);
        assert_eq!(def.fields[0].name, "type");
        assert_eq!(def.fields[0].size_bits, 5);
    }

    #[test]
    fn test_pds_entropy() {
        let def = extract_protocol("pds_entropy").unwrap();
        assert_eq!(def.min_header_bits, 32); // 4 bytes
        assert_eq!(def.fields.len(), 2);
    }

    #[test]
    fn test_pds_prologue() {
        let def = extract_protocol("pds_prologue").unwrap();
        assert_eq!(def.min_header_bits, 16); // 2 bytes
        assert_eq!(def.fields.len(), 3);
    }

    #[test]
    fn test_pds_ack_cc() {
        let def = extract_protocol("pds_ack_cc").unwrap();
        assert_eq!(def.min_header_bits, 256); // 32 bytes
    }

    #[test]
    fn test_pds_ack_ccx() {
        let def = extract_protocol("pds_ack_ccx").unwrap();
        assert_eq!(def.min_header_bits, 256); // 32 bytes
    }

    #[test]
    fn test_pds_nack() {
        let def = extract_protocol("pds_nack").unwrap();
        assert_eq!(def.min_header_bits, 128); // 16 bytes
    }

    #[test]
    fn test_pds_nack_ccx() {
        let def = extract_protocol("pds_nack_ccx").unwrap();
        assert_eq!(def.min_header_bits, 192); // 24 bytes
    }

    #[test]
    fn test_pds_uud_req() {
        let def = extract_protocol("pds_uud_req").unwrap();
        assert_eq!(def.min_header_bits, 32); // 4 bytes
    }

    #[test]
    fn test_ses_common_hdr() {
        let def = extract_protocol("ses_common_hdr").unwrap();
        assert_eq!(def.min_header_bits, 96); // 12 bytes
    }

    #[test]
    fn test_ses_request_std() {
        let def = extract_protocol("ses_request_std").unwrap();
        // 12 bytes common + 8+4+8+8+4 = 44 bytes
        assert_eq!(def.min_header_bits, 352);
    }

    #[test]
    fn test_ses_with_data_response() {
        let def = extract_protocol("ses_with_data_response").unwrap();
        // 8 bytes common_response + 2+2+4+4 = 20 bytes
        assert_eq!(def.min_header_bits, 160);
    }

    #[test]
    fn test_ses_with_small_data_response() {
        let def = extract_protocol("ses_with_small_data_response").unwrap();
        // list:2+opcode:6+ver:2+return_code:6+rsvd1:2+payload_length:14+rsvd2:8+job_id:24+original_request_psn:32 = 96
        assert_eq!(def.min_header_bits, 96); // 12 bytes
    }

    #[test]
    fn test_all_defs_have_valid_sizes() {
        for (id, _) in SPEC_DEFS {
            let def = extract_protocol(id).unwrap();
            assert!(
                def.min_header_bits % 8 == 0,
                "{} has non-byte-aligned size: {} bits",
                id,
                def.min_header_bits
            );
            assert!(def.min_header_bits > 0, "{} has zero size", id);
        }
    }

    #[test]
    fn test_unknown_id_returns_none() {
        assert!(extract_protocol("nonexistent").is_none());
    }

    #[test]
    fn test_field_offsets_are_sequential() {
        for (id, _) in SPEC_DEFS {
            let def = extract_protocol(id).unwrap();
            let mut expected_offset = 0;
            for f in &def.fields {
                assert_eq!(
                    f.offset_bits, expected_offset,
                    "{}: field {} has offset {} but expected {}",
                    id, f.name, f.offset_bits, expected_offset
                );
                expected_offset += f.size_bits;
            }
        }
    }
}
