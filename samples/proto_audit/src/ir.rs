//! Intermediate Representation for protocol definitions.
//!
//! The IR captures a canonical protocol definition assembled from multiple
//! authoritative sources (XDP2, Linux kernel, Scapy, tshark). Each source
//! may define fields differently — the IR normalizes offsets, sizes, and
//! types so cross-source comparison is straightforward.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Standards body that published a protocol specification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum StandardBody {
    /// IETF Request for Comments
    Rfc,
    /// IEEE standard
    Ieee,
    /// IANA registry
    Iana,
    /// Other standards body (ITU, ETSI, etc.)
    Other(String),
}

/// Relationship between a standard and a protocol definition.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum StandardRelationship {
    /// This standard defines the protocol
    Defines,
    /// This standard updates the protocol
    Updates,
    /// This standard obsoletes a prior definition
    Obsoletes,
    /// This is an IANA registry reference
    Registry,
}

/// A reference to an authoritative standard (RFC, IEEE, IANA registry).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StandardRef {
    /// Standard identifier: "RFC 791", "IEEE 802.1Q-2022", etc.
    pub id: String,
    /// Which standards body
    pub body: StandardBody,
    /// Relevant section within the standard
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub section: Option<String>,
    /// URL to the standard
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// How this standard relates to the protocol
    pub relationship: StandardRelationship,
}

/// Protocol layer classification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProtocolLayer {
    /// Data link layer (Ethernet, VLAN, etc.)
    L2,
    /// Network layer (IPv4, IPv6, etc.)
    L3,
    /// Transport layer (TCP, UDP, etc.)
    L4,
    /// Session/presentation/application
    L7,
    /// Tunneling / encapsulation
    Tunnel,
    /// Security (IPsec, MACsec, etc.)
    Security,
    /// Management / control plane
    Management,
    /// Industrial / IoT
    Industrial,
    /// Storage / SAN
    Storage,
}

/// A single protocol header field.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FieldDef {
    /// Canonical field name (consensus across sources)
    pub name: String,
    /// Bit offset from protocol header start
    pub offset_bits: u32,
    /// Field width in bits
    pub size_bits: u32,
    /// Semantic type
    pub field_type: FieldType,
    /// Byte order (Na for sub-byte or single-byte fields)
    pub endian: Endian,
    /// Human-readable description
    #[serde(default)]
    pub description: String,
    /// This field carries the "next protocol" identifier
    #[serde(default)]
    pub is_dispatch: bool,
    /// This field controls variable header length
    #[serde(default)]
    pub is_length: bool,
    /// If is_length: actual_bytes = field_value * multiplier
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub length_multiplier: Option<u32>,
    /// How each source names this field.
    /// Keys: "xdp2", "kernel", "scapy", "tshark"
    #[serde(default)]
    pub source_names: BTreeMap<String, String>,
    /// Default value from source (e.g., "4", "0x0800", "0")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_value: Option<String>,
    /// Names for individual flag bits (e.g., ["Reserved", "DF", "MF"])
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flag_names: Option<Vec<String>>,
}

/// Semantic type of a protocol field.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FieldType {
    /// Unsigned integer
    Uint,
    /// Signed integer
    Sint,
    /// Raw byte sequence
    Bytes,
    /// IPv4 address (32 bits)
    Ipv4Addr,
    /// IPv6 address (128 bits)
    Ipv6Addr,
    /// MAC address (48 bits)
    MacAddr,
    /// Individual bit flags
    Flags,
    /// Enumerated value (protocol number, ethertype, etc.)
    Enum,
    /// Reserved / padding
    Pad,
}

/// Byte order of a field.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Endian {
    /// Network byte order (most protocols)
    Big,
    /// Little-endian (some L2, USB, etc.)
    Little,
    /// Sub-byte or single-byte field (endianness not applicable)
    Na,
}

impl Default for FieldDef {
    fn default() -> Self {
        FieldDef {
            name: String::new(),
            offset_bits: 0,
            size_bits: 0,
            field_type: FieldType::Uint,
            endian: Endian::Na,
            description: String::new(),
            is_dispatch: false,
            is_length: false,
            length_multiplier: None,
            source_names: BTreeMap::new(),
            default_value: None,
            flag_names: None,
        }
    }
}

impl FieldDef {
    /// Create a new FieldDef with the required fields; everything else is defaulted.
    pub fn new(name: impl Into<String>, offset_bits: u32, size_bits: u32, field_type: FieldType) -> Self {
        FieldDef {
            name: name.into(),
            offset_bits,
            size_bits,
            field_type,
            ..Default::default()
        }
    }

    pub fn with_endian(mut self, endian: Endian) -> Self {
        self.endian = endian;
        self
    }

    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    pub fn with_source_name(mut self, source: impl Into<String>, name: impl Into<String>) -> Self {
        self.source_names.insert(source.into(), name.into());
        self
    }

    pub fn with_dispatch(mut self) -> Self {
        self.is_dispatch = true;
        self
    }

    pub fn with_length(mut self, multiplier: Option<u32>) -> Self {
        self.is_length = true;
        self.length_multiplier = multiplier;
        self
    }

    pub fn with_default_value(mut self, val: impl Into<String>) -> Self {
        self.default_value = Some(val.into());
        self
    }

    pub fn with_flag_names(mut self, names: Vec<String>) -> Self {
        self.flag_names = Some(names);
        self
    }
}

impl SourceInfo {
    /// Create a SourceInfo marking a source as present.
    pub fn new(source_name: impl Into<String>) -> Self {
        SourceInfo {
            present: true,
            file_path: None,
            source_name: source_name.into(),
            field_count: 0,
            min_header_bytes: 0,
            notes: vec![],
        }
    }

    pub fn with_file(mut self, path: impl Into<String>) -> Self {
        self.file_path = Some(path.into());
        self
    }

    pub fn with_field_count(mut self, count: u32) -> Self {
        self.field_count = count;
        self
    }

    pub fn with_min_header_bytes(mut self, bytes: u32) -> Self {
        self.min_header_bytes = bytes;
        self
    }

    pub fn with_note(mut self, note: impl Into<String>) -> Self {
        self.notes.push(note.into());
        self
    }
}

impl ProtocolDef {
    /// Create a minimal ProtocolDef with name and header size.
    pub fn new(name: impl Into<String>, min_header_bits: u32) -> Self {
        ProtocolDef {
            name: name.into(),
            min_header_bits,
            is_variable_length: false,
            fields: vec![],
            dispatch_field: None,
            dispatch_table: vec![],
            identifiers: BTreeMap::new(),
            sources: BTreeMap::new(),
            generation_source: None,
            standards: vec![],
            iana_registries: BTreeMap::new(),
            layer: None,
            repeats: vec![],
        }
    }

    pub fn with_fields(mut self, fields: Vec<FieldDef>) -> Self {
        self.fields = fields;
        self
    }

    /// Attach a repeating group and pre-expand `fields` to a representative
    /// number of instances so the flat consumers (comparator, serializer,
    /// generators) see a complete, concrete header. The prefix already present
    /// in `self.fields` is kept; the expansion is appended after it.
    pub fn with_repeat(mut self, group: RepeatGroup) -> Self {
        self.repeats.push(group);
        self.fields = self.expand_repeats();
        // The representative expansion defines the concrete header size, so
        // grow min_header_bits to cover it (the pcap serializer only emits
        // fields within min_header_bits). Mark the header variable-length.
        let max_end = self
            .fields
            .iter()
            .map(|f| f.offset_bits + f.size_bits)
            .max()
            .unwrap_or(self.min_header_bits);
        if max_end > self.min_header_bits {
            self.min_header_bits = max_end;
        }
        self.is_variable_length = true;
        self
    }

    /// Produce the flat field list: the fixed prefix fields (those entirely
    /// before the first repeat's `start_bits`) followed by `sample_count`
    /// concrete copies of each repeat group's element and its terminator.
    ///
    /// Fixed-size elements advance by `element_size`; length-driven elements
    /// advance by the element's declared span (the max end of its fields,
    /// which for a representative instance equals the encoded length).
    pub fn expand_repeats(&self) -> Vec<FieldDef> {
        if self.repeats.is_empty() {
            return self.fields.clone();
        }
        // Keep only prefix fields that end at or before the earliest repeat.
        let first_start = self.repeats.iter().map(|r| r.start_bits).min().unwrap_or(0);
        let mut out: Vec<FieldDef> = self
            .fields
            .iter()
            .filter(|f| f.offset_bits + f.size_bits <= first_start)
            .cloned()
            .collect();

        for group in &self.repeats {
            let elem_span = group
                .element
                .iter()
                .map(|f| f.offset_bits + f.size_bits)
                .max()
                .unwrap_or(0);
            let step = match &group.element_size {
                ElementSize::Fixed(bits) => *bits,
                // For a representative instance the declared field span is the
                // element length; the length field is honoured at serialize time.
                ElementSize::LengthField { .. } => elem_span,
            };
            let mut cursor = group.start_bits;
            for i in 0..group.sample_count {
                for f in &group.element {
                    let mut nf = f.clone();
                    nf.offset_bits = cursor + f.offset_bits;
                    if group.sample_count > 1 {
                        nf.name = format!("{}_{}", f.name, i);
                    }
                    out.push(nf);
                }
                cursor += step.max(1);
            }
            // Append the terminator field, if any, after the last element.
            if let RepeatTerm::EndMark { size_bits, .. } = &group.terminator {
                out.push(
                    FieldDef::new(
                        format!("{}_end_mark", group.name),
                        cursor,
                        *size_bits,
                        FieldType::Uint,
                    )
                    .with_endian(Endian::Big),
                );
            }
        }
        out
    }

    pub fn with_variable_length(mut self) -> Self {
        self.is_variable_length = true;
        self
    }

    pub fn with_dispatch_field(mut self, field: impl Into<String>) -> Self {
        self.dispatch_field = Some(field.into());
        self
    }

    pub fn with_dispatch_table(mut self, table: Vec<DispatchEntry>) -> Self {
        self.dispatch_table = table;
        self
    }

    pub fn with_identifier(mut self, key: impl Into<String>, values: Vec<u32>) -> Self {
        self.identifiers.insert(key.into(), values);
        self
    }

    pub fn with_source(mut self, name: impl Into<String>, info: SourceInfo) -> Self {
        self.sources.insert(name.into(), info);
        self
    }

    pub fn with_standards(mut self, standards: Vec<StandardRef>) -> Self {
        self.standards = standards;
        self
    }

    pub fn with_iana_registry(mut self, field: impl Into<String>, url: impl Into<String>) -> Self {
        self.iana_registries.insert(field.into(), url.into());
        self
    }

    pub fn with_layer(mut self, layer: ProtocolLayer) -> Self {
        self.layer = Some(layer);
        self
    }
}

/// Maps a dispatch field value to a next protocol.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DispatchEntry {
    /// Field value (e.g., 0x0800, 6, 17)
    pub value: u32,
    /// Target protocol canonical name
    pub protocol: String,
    /// Which sources define this binding
    #[serde(default)]
    pub sources: Vec<String>,
}

/// Canonical protocol definition assembled from multiple sources.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProtocolDef {
    /// Canonical name: "IPv4", "TCP", "Ethernet"
    pub name: String,
    /// Minimum header size in bits
    pub min_header_bits: u32,
    /// Can header exceed minimum?
    #[serde(default)]
    pub is_variable_length: bool,
    /// Ordered fields (by bit offset)
    #[serde(default)]
    pub fields: Vec<FieldDef>,

    /// Which field carries next protocol identifier (None for leaf protocols)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dispatch_field: Option<String>,
    /// Protocol dispatch table
    #[serde(default)]
    pub dispatch_table: Vec<DispatchEntry>,

    /// How this protocol is identified from parent protocols.
    /// e.g., {"ethertype": [2048], "ip_proto": [6]}
    #[serde(default)]
    pub identifiers: BTreeMap<String, Vec<u32>>,

    /// Per-source metadata
    #[serde(default)]
    pub sources: BTreeMap<String, SourceInfo>,

    /// How this IR was generated: "curated", "scapy-batch", "tshark-pdml", "tshark-registry"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generation_source: Option<String>,

    /// Normative standard references (RFCs, IEEE standards, IANA registries)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub standards: Vec<StandardRef>,

    /// Dispatch field → IANA registry URL mapping
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub iana_registries: BTreeMap<String, String>,

    /// Protocol layer classification
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub layer: Option<ProtocolLayer>,

    /// Repeating field groups (TLV chains, vector-attribute lists, options).
    /// Additive metadata: the flat `fields` view stays authoritative and is
    /// pre-expanded to a representative instance count via `expand_repeats`,
    /// so comparison/serialization/most generators need no repeat awareness.
    /// Faithful-codegen generators (kaitai, scapy) consult this to emit real
    /// repetition constructs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub repeats: Vec<RepeatGroup>,
}

/// A repeating group of fields within a protocol header (TLV chain, vector
/// attributes, options list).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RepeatGroup {
    /// Group name, e.g. "tlv", "message", "vector_attribute".
    pub name: String,
    /// Bit offset (from header start) where the repetition begins, i.e. just
    /// after the fixed prefix fields.
    pub start_bits: u32,
    /// The fields of ONE element, with offsets relative to the element start.
    pub element: Vec<FieldDef>,
    /// How the byte size of each element is determined.
    pub element_size: ElementSize,
    /// How the repetition terminates.
    pub terminator: RepeatTerm,
    /// Representative number of instances used to pre-expand `fields` and to
    /// generate the sample PCAP template.
    pub sample_count: u32,
}

/// How the byte size of one repeat-group element is determined.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ElementSize {
    /// Every element is exactly this many bits.
    Fixed(u32),
    /// Element size is driven by a length field within the element:
    /// `bytes = <name>.value * multiplier` (covering the whole element).
    LengthField { name: String, multiplier: u32 },
}

/// How a repeating group knows when to stop.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RepeatTerm {
    /// A fixed count carried by a named prefix field.
    Count { field: String },
    /// Repeat until `<field>.value * multiplier` bytes have been consumed.
    Length { field: String, multiplier: u32 },
    /// Repeat until a sentinel of `size_bits` equal to `value` appears
    /// (e.g. the MRP/MRPDU End Mark 0x0000).
    EndMark { size_bits: u32, value: u64 },
    /// Repeat to the end of the packet / parent length.
    ToEnd,
}

/// What one source says about this protocol.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SourceInfo {
    /// Whether this source has a definition for the protocol
    pub present: bool,
    /// Path to the source file (if applicable)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_path: Option<String>,
    /// Source-specific name: "xdp2_parse_ipv4" / "IP" / "iphdr" / "ip"
    #[serde(default)]
    pub source_name: String,
    /// Number of fields defined by this source
    #[serde(default)]
    pub field_count: u32,
    /// Minimum header size in bytes
    #[serde(default)]
    pub min_header_bytes: u32,
    /// Additional notes
    #[serde(default)]
    pub notes: Vec<String>,
}

/// Result of comparing a field across sources.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FieldComparison {
    /// Canonical field name
    pub name: String,
    /// Bit offset (consensus or first-seen)
    pub offset_bits: u32,
    /// Field width in bits
    pub size_bits: u32,
    /// Which sources fully agree (offset+size+type+endian)
    pub sources_agree: Vec<String>,
    /// Which sources structurally agree (offset+size match, type/endian may differ)
    #[serde(default)]
    pub sources_structural: Vec<String>,
    /// Which sources disagree (with details)
    pub mismatches: Vec<FieldMismatch>,
}

/// A specific mismatch between sources for a field.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FieldMismatch {
    pub source: String,
    pub field: String,
    pub expected: String,
    pub actual: String,
}

/// Overall audit result for a protocol.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuditResult {
    pub protocol: String,
    pub sources_present: Vec<String>,
    pub sources_missing: Vec<String>,
    pub field_comparisons: Vec<FieldComparison>,
    pub total_fields: u32,
    pub fields_agree: u32,
    /// Fields where sources match on offset+size but disagree on type/endian
    #[serde(default)]
    pub fields_type_differ: u32,
    pub fields_mismatch: u32,
    pub fields_missing: u32,
    /// Validation quality tier (computed from audit results)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validation_tier: Option<crate::discovery::ValidationTier>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_ipv4() -> ProtocolDef {
        ProtocolDef::new("IPv4", 160)
            .with_variable_length()
            .with_fields(vec![
                FieldDef::new("version", 0, 4, FieldType::Uint)
                    .with_description("IP version (always 4)")
                    .with_source_name("kernel", "version")
                    .with_source_name("scapy", "version")
                    .with_source_name("tshark", "ip.version"),
                FieldDef::new("ihl", 4, 4, FieldType::Uint)
                    .with_description("Internet Header Length (in 32-bit words)")
                    .with_length(Some(4))
                    .with_source_name("kernel", "ihl")
                    .with_source_name("scapy", "ihl")
                    .with_source_name("tshark", "ip.hdr_len"),
                FieldDef::new("tos", 8, 8, FieldType::Uint)
                    .with_description("Type of Service / DSCP + ECN")
                    .with_source_name("kernel", "tos")
                    .with_source_name("scapy", "tos")
                    .with_source_name("tshark", "ip.dsfield"),
                FieldDef::new("total_length", 16, 16, FieldType::Uint)
                    .with_endian(Endian::Big)
                    .with_description("Total packet length in bytes")
                    .with_source_name("kernel", "tot_len")
                    .with_source_name("scapy", "len")
                    .with_source_name("tshark", "ip.len"),
                FieldDef::new("identification", 32, 16, FieldType::Uint)
                    .with_endian(Endian::Big)
                    .with_description("Fragment identification")
                    .with_source_name("kernel", "id")
                    .with_source_name("scapy", "id")
                    .with_source_name("tshark", "ip.id"),
                FieldDef::new("flags", 48, 3, FieldType::Flags)
                    .with_description("IP flags (Reserved, DF, MF)")
                    .with_source_name("kernel", "frag_off(high bits)")
                    .with_source_name("scapy", "flags")
                    .with_source_name("tshark", "ip.flags"),
                FieldDef::new("fragment_offset", 51, 13, FieldType::Uint)
                    .with_endian(Endian::Big)
                    .with_description("Fragment offset (in 8-byte units)")
                    .with_source_name("kernel", "frag_off(low bits)")
                    .with_source_name("scapy", "frag")
                    .with_source_name("tshark", "ip.frag_offset"),
                FieldDef::new("ttl", 64, 8, FieldType::Uint)
                    .with_description("Time to Live")
                    .with_source_name("kernel", "ttl")
                    .with_source_name("scapy", "ttl")
                    .with_source_name("tshark", "ip.ttl"),
                FieldDef::new("protocol", 72, 8, FieldType::Enum)
                    .with_description("Next-layer protocol number")
                    .with_dispatch()
                    .with_source_name("kernel", "protocol")
                    .with_source_name("scapy", "proto")
                    .with_source_name("tshark", "ip.proto")
                    .with_source_name("xdp2", "protocol"),
                FieldDef::new("checksum", 80, 16, FieldType::Uint)
                    .with_endian(Endian::Big)
                    .with_description("Header checksum")
                    .with_source_name("kernel", "check")
                    .with_source_name("scapy", "chksum")
                    .with_source_name("tshark", "ip.checksum"),
                FieldDef::new("src_addr", 96, 32, FieldType::Ipv4Addr)
                    .with_endian(Endian::Big)
                    .with_description("Source IP address")
                    .with_source_name("kernel", "saddr")
                    .with_source_name("scapy", "src")
                    .with_source_name("tshark", "ip.src")
                    .with_source_name("xdp2", "saddr"),
                FieldDef::new("dst_addr", 128, 32, FieldType::Ipv4Addr)
                    .with_endian(Endian::Big)
                    .with_description("Destination IP address")
                    .with_source_name("kernel", "daddr")
                    .with_source_name("scapy", "dst")
                    .with_source_name("tshark", "ip.dst")
                    .with_source_name("xdp2", "daddr"),
            ])
            .with_dispatch_field("protocol")
            .with_dispatch_table(vec![
                DispatchEntry { value: 1, protocol: "ICMP".into(), sources: vec!["kernel".into(), "scapy".into(), "tshark".into()] },
                DispatchEntry { value: 6, protocol: "TCP".into(), sources: vec!["kernel".into(), "scapy".into(), "tshark".into()] },
                DispatchEntry { value: 17, protocol: "UDP".into(), sources: vec!["kernel".into(), "scapy".into(), "tshark".into()] },
                DispatchEntry { value: 47, protocol: "GRE".into(), sources: vec!["kernel".into(), "scapy".into(), "tshark".into()] },
            ])
            .with_identifier("ethertype", vec![2048])
            .with_source("xdp2", SourceInfo::new("xdp2_parse_ipv4")
                .with_file("ip/proto_ipv4.h")
                .with_min_header_bytes(20)
                .with_note("Fields come from kernel struct iphdr, not defined in proto_def directly"))
            .with_source("kernel", SourceInfo::new("iphdr")
                .with_file("include/uapi/linux/ip.h")
                .with_field_count(12)
                .with_min_header_bytes(20))
            .with_source("scapy", SourceInfo::new("IP")
                .with_file("scapy/layers/inet.py")
                .with_field_count(13)
                .with_min_header_bytes(20))
            .with_source("tshark", SourceInfo::new("ip")
                .with_field_count(12)
                .with_min_header_bytes(20))
    }

    #[test]
    fn test_ir_json_roundtrip() {
        let proto = sample_ipv4();
        let json = serde_json::to_string_pretty(&proto).unwrap();
        let parsed: ProtocolDef = serde_json::from_str(&json).unwrap();
        assert_eq!(proto, parsed);
    }

    #[test]
    fn test_ir_field_count() {
        let proto = sample_ipv4();
        assert_eq!(proto.fields.len(), 12);
    }

    #[test]
    fn test_repeat_group_expand_and_roundtrip() {
        // A 1-byte prefix version, then a repeated {type(8), length(8)} TLV
        // header, 2 sample instances, terminated by a 16-bit end mark.
        let proto = ProtocolDef::new("MRPDU_TEST", 8)
            .with_fields(vec![FieldDef::new("version", 0, 8, FieldType::Uint)])
            .with_repeat(RepeatGroup {
                name: "tlv".into(),
                start_bits: 8,
                element: vec![
                    FieldDef::new("type", 0, 8, FieldType::Uint),
                    FieldDef::new("length", 8, 8, FieldType::Uint),
                ],
                element_size: ElementSize::Fixed(16),
                terminator: RepeatTerm::EndMark { size_bits: 16, value: 0 },
                sample_count: 2,
            });
        // prefix(1) + 2*(type,length) + end_mark
        let names: Vec<&str> = proto.fields.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["version", "type_0", "length_0", "type_1", "length_1", "tlv_end_mark"]
        );
        // Offsets: version@0, elem0 @8/16, elem1 @24/32, end_mark @40.
        let by = |n: &str| proto.fields.iter().find(|f| f.name == n).unwrap().offset_bits;
        assert_eq!((by("type_0"), by("length_0")), (8, 16));
        assert_eq!((by("type_1"), by("length_1")), (24, 32));
        assert_eq!(by("tlv_end_mark"), 40);

        // The repeats metadata survives a JSON round trip.
        let json = serde_json::to_string_pretty(&proto).unwrap();
        let parsed: ProtocolDef = serde_json::from_str(&json).unwrap();
        assert_eq!(proto, parsed);
        assert_eq!(parsed.repeats.len(), 1);
    }

    #[test]
    fn test_ir_dispatch_field() {
        let proto = sample_ipv4();
        assert_eq!(proto.dispatch_field, Some("protocol".to_string()));
        let dispatch = proto
            .fields
            .iter()
            .find(|f| f.is_dispatch)
            .expect("should have dispatch field");
        assert_eq!(dispatch.name, "protocol");
        assert_eq!(dispatch.offset_bits, 72);
        assert_eq!(dispatch.size_bits, 8);
    }

    #[test]
    fn test_ir_length_field() {
        let proto = sample_ipv4();
        let ihl = proto
            .fields
            .iter()
            .find(|f| f.is_length)
            .expect("should have length field");
        assert_eq!(ihl.name, "ihl");
        assert_eq!(ihl.length_multiplier, Some(4));
    }

    #[test]
    fn test_ir_total_bits() {
        let proto = sample_ipv4();
        let last = proto.fields.last().unwrap();
        let total = last.offset_bits + last.size_bits;
        assert_eq!(total, 160); // 20 bytes
        assert_eq!(proto.min_header_bits, 160);
    }

    #[test]
    fn test_ir_source_names() {
        let proto = sample_ipv4();
        let src_addr = proto.fields.iter().find(|f| f.name == "src_addr").unwrap();
        assert_eq!(src_addr.source_names.get("kernel"), Some(&"saddr".into()));
        assert_eq!(src_addr.source_names.get("scapy"), Some(&"src".into()));
        assert_eq!(src_addr.source_names.get("tshark"), Some(&"ip.src".into()));
    }

    #[test]
    fn test_ir_identifiers() {
        let proto = sample_ipv4();
        assert_eq!(proto.identifiers.get("ethertype"), Some(&vec![2048]));
    }
}
