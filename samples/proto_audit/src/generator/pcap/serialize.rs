//! PCAP serialization: header encoding, fixups, and PCAP file generation.

use std::collections::BTreeMap;

use crate::ir::{FieldDef, FieldType, ProtocolDef};

use super::routing::{
    build_protocol_stack, is_root, load_pcap_template, upper_pdu_preamble,
    PcapTemplate, StackLayer, STACK_ROUTES, UPPER_PDU_DISSECTORS,
};

/// Output from PCAP generation.
pub struct PcapOutput {
    /// Complete PCAP file bytes (global header + record header + packet)
    pub pcap_bytes: Vec<u8>,
    /// Raw packet bytes (no PCAP framing)
    pub packet_bytes: Vec<u8>,
    /// Protocols in encapsulation order (e.g., ["Ethernet", "IPv4", "TCP"])
    pub stack: Vec<String>,
    /// PCAP Data Link Type used for this packet
    pub link_type: u32,
}

/// Generate a complete PCAP file containing one packet for the target protocol.
pub fn generate_pcap(
    target_proto: &ProtocolDef,
    all_protos: &BTreeMap<String, ProtocolDef>,
) -> Result<PcapOutput, String> {
    let discovery_state = crate::discovery::DiscoveryState::load_from_env();
    generate_pcap_with_discovery(target_proto, all_protos, &discovery_state)
}

/// Generate a PCAP with an externally-provided DiscoveryState (avoids reloading).
pub fn generate_pcap_with_discovery(
    target_proto: &ProtocolDef,
    all_protos: &BTreeMap<String, ProtocolDef>,
    discovery_state: &crate::discovery::DiscoveryState,
) -> Result<PcapOutput, String> {
    // Pre-build the protocol map once for discovery route lookups
    let discovered_protos = crate::discovery::all_protocols(discovery_state);

    // Try PCAP template first — templates contain valid protocol content
    // (e.g., real DHCP Discover, NTP query, BGP OPEN) that tshark can dissect,
    // whereas synthetic generation produces zero-filled payloads that tshark
    // often can't identify as the target protocol.
    // Skip templates only for protocols whose ONLY route is UpperPDU
    // (no TCP/UDP/Ethernet alternative). Protocols with both UpperPDU and
    // normal STACK_ROUTES benefit from templates since the normal route
    // is preferred by build_protocol_stack.
    let has_non_upper_pdu_route = STACK_ROUTES.iter().any(|(child, parent, _, _)| {
        *child == target_proto.name && *parent != "UpperPDU"
    });
    let is_upper_pdu_only = UPPER_PDU_DISSECTORS
        .iter()
        .any(|(proto, _)| *proto == target_proto.name)
        && !has_non_upper_pdu_route;
    if !is_upper_pdu_only {
        if let Some(tmpl) = load_pcap_template(&target_proto.name) {
            return Ok(PcapOutput {
                pcap_bytes: tmpl.pcap_bytes,
                packet_bytes: tmpl.packet_bytes,
                stack: vec![format!("template:{}", target_proto.name)],
                link_type: tmpl.link_type,
            });
        }
    }

    // Fall back to synthetic stack construction
    let result = match build_protocol_stack(&target_proto.name, all_protos, discovery_state, &discovered_protos) {
        Ok(r) => r,
        Err(e) => {
            return Err(e);
        }
    };
    let link_type = result.link_type;

    // Serialize each layer
    let mut packet = Vec::new();
    let stack_names: Vec<String> = result.layers.iter().map(|l| l.proto_name.clone()).collect();

    for (i, layer) in result.layers.iter().enumerate() {
        if i == 0 && layer.proto_name == "UpperPDU" {
            // UpperPDU root: emit TLV preamble instead of serializing a header
            let target_name = stack_names.last().map(|s| s.as_str()).unwrap_or("");
            let dissector = UPPER_PDU_DISSECTORS
                .iter()
                .find(|(proto, _)| *proto == target_name)
                .map(|(_, d)| *d)
                .unwrap_or("data");
            packet.extend_from_slice(&upper_pdu_preamble(dissector));
        } else {
            let header = serialize_header(&layer.proto_def, &layer.overrides);
            packet.extend_from_slice(&header);
        }
    }

    // Fixup: IPv4 total_length and checksum
    fixup_ipv4(&mut packet, &result.layers);
    // Fixup: IPv6 payload_length
    fixup_ipv6(&mut packet, &result.layers);
    // Fixup: UDP length
    fixup_udp_length(&mut packet, &result.layers);
    // Fixup: 802.3 length field
    fixup_802_3_length(&mut packet, &result.layers);

    // Build PCAP file
    let mut pcap = Vec::new();
    pcap.extend_from_slice(&pcap_global_header(link_type));
    pcap.extend_from_slice(&pcap_record_header(packet.len() as u32));
    pcap.extend_from_slice(&packet);

    Ok(PcapOutput {
        pcap_bytes: pcap,
        packet_bytes: packet,
        stack: stack_names,
        link_type,
    })
}

/// Serialize one protocol header to bytes.
pub fn serialize_header(proto: &ProtocolDef, overrides: &BTreeMap<String, u64>) -> Vec<u8> {
    let byte_len = (proto.min_header_bits + 7) / 8;
    let mut buf = vec![0u8; byte_len as usize];

    for field in &proto.fields {
        if field.offset_bits + field.size_bits > proto.min_header_bits {
            continue; // skip fields beyond minimum header
        }
        let value = select_field_value(field, overrides);
        pack_field(&mut buf, field, value);
    }

    buf
}

/// Choose a value for a field: override > default_value > type-based default > 0.
pub(super) fn select_field_value(field: &FieldDef, overrides: &BTreeMap<String, u64>) -> u64 {
    // Check overrides (match by field name or any source name)
    if let Some(&val) = overrides.get(&field.name) {
        return val;
    }
    for src_name in field.source_names.values() {
        if let Some(&val) = overrides.get(src_name) {
            return val;
        }
    }

    // Check default_value
    if let Some(ref dv) = field.default_value {
        if let Some(val) = parse_int_value(dv) {
            return val;
        }
    }

    // Type-based defaults
    match field.field_type {
        FieldType::Ipv4Addr => {
            let name_lower = field.name.to_lowercase();
            if name_lower.contains("src") || name_lower.contains("source") {
                // 10.0.0.1
                return u64::from(u32::from_be_bytes([10, 0, 0, 1]));
            }
            // 10.0.0.2
            u64::from(u32::from_be_bytes([10, 0, 0, 2]))
        }
        FieldType::Ipv6Addr => {
            // We handle IPv6 specially in pack_field since it's 128 bits
            // Return 0 here; pack_field will use embedded addresses
            0
        }
        FieldType::MacAddr => {
            let name_lower = field.name.to_lowercase();
            if name_lower.contains("src") || name_lower.contains("source") {
                // 02:00:00:00:00:01
                return 0x020000000001;
            }
            // 02:00:00:00:00:02
            0x020000000002
        }
        FieldType::Uint if field.is_length => {
            // Compute from min_header_bits if multiplier is set
            if let Some(mult) = field.length_multiplier {
                if mult > 0 {
                    return (field.offset_bits + field.size_bits) as u64 / 8 / mult as u64;
                }
            }
            0
        }
        FieldType::Flags | FieldType::Pad => 0,
        _ => 0,
    }
}

/// Parse an integer from a string (supports decimal, 0x hex, 0b binary).
pub(super) fn parse_int_value(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else if let Some(bin) = s.strip_prefix("0b") {
        u64::from_str_radix(bin, 2).ok()
    } else {
        s.parse::<u64>().ok()
    }
}

/// Pack a single field value into a byte buffer at the correct bit offset.
/// Network order: MSB-first within each byte.
pub fn pack_field(buf: &mut [u8], field: &FieldDef, value: u64) {
    let offset = field.offset_bits as usize;
    let size = field.size_bits as usize;

    if size == 0 || offset + size > buf.len() * 8 {
        return;
    }

    // Special handling for IPv6 addresses (128 bits)
    if field.field_type == FieldType::Ipv6Addr && size == 128 {
        pack_ipv6_addr(buf, offset, field);
        return;
    }

    // Special handling for MAC addresses (48 bits)
    if field.field_type == FieldType::MacAddr && size == 48 {
        let bytes = value.to_be_bytes();
        let start_byte = offset / 8;
        // MAC is in the lower 6 bytes of u64
        buf[start_byte..start_byte + 6].copy_from_slice(&bytes[2..8]);
        return;
    }

    // Byte-aligned fast path
    if offset % 8 == 0 && size % 8 == 0 {
        let start_byte = offset / 8;
        let num_bytes = size / 8;
        if num_bytes <= 8 {
            let be_bytes = value.to_be_bytes();
            let src_start = 8 - num_bytes;
            buf[start_byte..start_byte + num_bytes].copy_from_slice(&be_bytes[src_start..]);
        } else {
            // Large field (>64 bits): zero-fill, write low 8 bytes at the end
            let end = start_byte + num_bytes;
            let buf_len = buf.len();
            let clamped_end = end.min(buf_len);
            for i in start_byte..clamped_end {
                buf[i] = 0;
            }
            let be_bytes = value.to_be_bytes();
            let write_start = end.saturating_sub(8);
            if write_start < clamped_end {
                let copy_len = clamped_end - write_start;
                let src_start = 8 - copy_len;
                buf[write_start..clamped_end].copy_from_slice(&be_bytes[src_start..src_start + copy_len]);
            }
        }
        return;
    }

    // Bitfield path: pack MSB-first
    for i in 0..size {
        let bit_val = (value >> (size - 1 - i)) & 1;
        let target_bit = offset + i;
        let byte_idx = target_bit / 8;
        let bit_in_byte = 7 - (target_bit % 8); // MSB-first
        if bit_val == 1 {
            buf[byte_idx] |= 1 << bit_in_byte;
        }
    }
}

/// Pack an IPv6 address into the buffer. Uses fd00::1 for src, fd00::2 for dst.
pub(super) fn pack_ipv6_addr(buf: &mut [u8], offset: usize, field: &FieldDef) {
    let start_byte = offset / 8;
    let name_lower = field.name.to_lowercase();
    let addr: [u8; 16] = if name_lower.contains("src") || name_lower.contains("source") {
        // fd00::1
        [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
    } else {
        // fd00::2
        [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]
    };
    buf[start_byte..start_byte + 16].copy_from_slice(&addr);
}

/// Fixup IPv4 total_length and header checksum after all layers are serialized.
pub(super) fn fixup_ipv4(packet: &mut [u8], stack: &[StackLayer]) {
    let mut ipv4_offset: Option<usize> = None;
    let mut byte_offset = 0usize;

    for layer in stack {
        if layer.proto_name == "IPv4" {
            ipv4_offset = Some(byte_offset);
        }
        byte_offset += (layer.proto_def.min_header_bits as usize + 7) / 8;
    }

    if let Some(off) = ipv4_offset {
        // Ensure version=4 in upper nibble and IHL=5 in lower nibble of byte 0.
        // When IR comes from tshark, these sub-byte fields are byte-aligned
        // and would otherwise produce invalid headers (version=0 or version=5).
        packet[off] = 0x45;

        let total_len = (packet.len() - off) as u16;
        // total_length is at offset 16 bits (2 bytes) from IPv4 header start
        packet[off + 2] = (total_len >> 8) as u8;
        packet[off + 3] = (total_len & 0xFF) as u8;

        // Zero checksum field first (at offset 80 bits = 10 bytes)
        packet[off + 10] = 0;
        packet[off + 11] = 0;

        // Compute and set checksum over 20-byte IPv4 header
        let cksum = ipv4_checksum(&packet[off..off + 20]);
        packet[off + 10] = (cksum >> 8) as u8;
        packet[off + 11] = (cksum & 0xFF) as u8;
    }
}

/// IPv4 header checksum (RFC 791): ones-complement sum of 16-bit words.
pub fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for i in (0..header.len()).step_by(2) {
        let word = if i + 1 < header.len() {
            ((header[i] as u32) << 8) | (header[i + 1] as u32)
        } else {
            (header[i] as u32) << 8
        };
        sum += word;
    }
    // Fold carry
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Fixup IPv6 payload_length after all layers are serialized.
pub(super) fn fixup_ipv6(packet: &mut [u8], stack: &[StackLayer]) {
    let mut ipv6_offset: Option<usize> = None;
    let mut byte_offset = 0usize;

    for layer in stack {
        if layer.proto_name == "IPv6" {
            ipv6_offset = Some(byte_offset);
        }
        byte_offset += (layer.proto_def.min_header_bits as usize + 7) / 8;
    }

    if let Some(off) = ipv6_offset {
        // payload_length = packet_len - ipv6_offset - 40 (IPv6 header is 40 bytes)
        let payload_len = (packet.len() - off - 40) as u16;
        // payload_length is at offset 32 bits (4 bytes) from IPv6 header start
        packet[off + 4] = (payload_len >> 8) as u8;
        packet[off + 5] = (payload_len & 0xFF) as u8;

        // Ensure a valid IPv6 first-word. When IR comes from tshark PDML the
        // sub-byte fields (version=4b, tclass=8b, flow_label=20b) are flattened
        // into byte-aligned fields, so byte 0 ends up holding version in the
        // lower nibble (invalid header). Force the four header bytes to encode
        // version=6 with traffic_class=0 and flow_label=0 — round-trip still
        // succeeds because the output path applies the same fixup.
        packet[off] = 0x60;
        packet[off + 1] = 0x00;
        packet[off + 2] = 0x00;
        packet[off + 3] = 0x00;
    }
}

/// Fixup UDP length field after all layers are serialized.
pub(super) fn fixup_udp_length(packet: &mut [u8], stack: &[StackLayer]) {
    let mut udp_offset: Option<usize> = None;
    let mut byte_offset = 0usize;

    for layer in stack {
        if layer.proto_name == "UDP" {
            udp_offset = Some(byte_offset);
        }
        byte_offset += (layer.proto_def.min_header_bits as usize + 7) / 8;
    }

    if let Some(off) = udp_offset {
        // UDP length = packet_len - udp_offset (includes UDP header + payload)
        let udp_len = (packet.len() - off) as u16;
        // length field is at offset 32 bits (4 bytes) from UDP header start
        packet[off + 4] = (udp_len >> 8) as u8;
        packet[off + 5] = (udp_len & 0xFF) as u8;
    }
}

/// Fixup 802.3 Ethernet length field (bytes 12-13 = payload length).
pub(super) fn fixup_802_3_length(packet: &mut [u8], stack: &[StackLayer]) {
    if stack.is_empty() || stack[0].proto_name != "Ethernet_802_3" {
        return;
    }
    if packet.len() > 14 {
        let payload_len = (packet.len() - 14) as u16;
        packet[12] = (payload_len >> 8) as u8;
        packet[13] = (payload_len & 0xFF) as u8;
    }
}

/// PCAP global header: magic, version 2.4, snaplen 65535, parameterized linktype.
pub(super) fn pcap_global_header(link_type: u32) -> [u8; 24] {
    let mut hdr = [0u8; 24];
    // Magic number (little-endian PCAP)
    hdr[0..4].copy_from_slice(&0xA1B2C3D4u32.to_le_bytes());
    // Version 2.4
    hdr[4..6].copy_from_slice(&2u16.to_le_bytes());
    hdr[6..8].copy_from_slice(&4u16.to_le_bytes());
    // thiszone, sigfigs = 0
    // snaplen = 65535
    hdr[16..20].copy_from_slice(&65535u32.to_le_bytes());
    // linktype
    hdr[20..24].copy_from_slice(&link_type.to_le_bytes());
    hdr
}

/// PCAP record header: timestamp=0, captured_len=original_len=packet_len.
pub(super) fn pcap_record_header(packet_len: u32) -> [u8; 16] {
    let mut hdr = [0u8; 16];
    // ts_sec, ts_usec = 0
    // incl_len
    hdr[8..12].copy_from_slice(&packet_len.to_le_bytes());
    // orig_len
    hdr[12..16].copy_from_slice(&packet_len.to_le_bytes());
    hdr
}

pub fn hex_dump(bytes: &[u8]) -> String {
    let mut out = String::new();
    for (i, chunk) in bytes.chunks(16).enumerate() {
        out.push_str(&format!("{:04x}  ", i * 16));
        for (j, byte) in chunk.iter().enumerate() {
            out.push_str(&format!("{:02x} ", byte));
            if j == 7 {
                out.push(' ');
            }
        }
        // Pad if short line
        if chunk.len() < 16 {
            let pad = (16 - chunk.len()) * 3 + if chunk.len() <= 8 { 1 } else { 0 };
            for _ in 0..pad {
                out.push(' ');
            }
        }
        out.push(' ');
        for byte in chunk {
            if byte.is_ascii_graphic() || *byte == b' ' {
                out.push(*byte as char);
            } else {
                out.push('.');
            }
        }
        out.push('\n');
    }
    out
}
