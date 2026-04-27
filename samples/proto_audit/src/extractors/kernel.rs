//! Linux kernel UAPI header extractor.
//!
//! Parses kernel C struct definitions to extract field-level detail:
//! field names, types, sizes, bit widths, and byte order annotations.
//!
//! Targets the highly consistent UAPI header format:
//! ```c
//! struct iphdr {
//! #if defined(__LITTLE_ENDIAN_BITFIELD)
//!     __u8    ihl:4, version:4;
//! #elif defined(__BIG_ENDIAN_BITFIELD)
//!     __u8    version:4, ihl:4;
//! #endif
//!     __u8    tos;
//!     __be16  tot_len;
//!     ...
//! };
//! ```

use anyhow::Result;
use regex::Regex;

use crate::ir::{Endian, FieldDef, FieldType, ProtocolDef, SourceInfo};
use crate::type_mapping::{self, KernelMappings};

/// Body of an anonymous inline union or struct.
#[derive(Debug, Clone)]
pub struct AnonymousBody {
    /// "union" or "struct"
    pub kind: String,
    /// Raw body text (for debugging)
    pub body: String,
    /// Parsed sub-fields
    pub fields: Vec<KernelField>,
}

/// A raw field parsed from a kernel struct.
#[derive(Debug, Clone)]
pub struct KernelField {
    /// C type (e.g., "__be16", "__u8", "struct in6_addr")
    pub c_type: String,
    /// Field name
    pub name: String,
    /// Bitfield width (None for regular fields)
    pub bitfield_width: Option<u32>,
    /// Array size (None for non-arrays)
    pub array_size: Option<u32>,
    /// Anonymous inline union/struct body (None for regular fields)
    pub anon_body: Option<AnonymousBody>,
}

/// Metadata for a parsed kernel struct.
#[derive(Debug, Clone)]
pub struct KernelStruct {
    pub name: String,
    pub fields: Vec<KernelField>,
    pub file_path: String,
    /// Whether the struct uses __BIG_ENDIAN_BITFIELD ordering
    pub has_endian_bitfield: bool,
}

/// Map a kernel C type to its size in bits using loaded mappings.
fn c_type_bits(ty: &str, mappings: &KernelMappings) -> Option<u32> {
    mappings.type_bits(ty)
}

/// Determine endianness from kernel type annotation using loaded mappings.
fn c_type_endian(ty: &str, mappings: &KernelMappings) -> Endian {
    mappings.type_endian(ty)
}

/// Determine the semantic field type from the C type and field name.
///
/// Checks mapping overrides first, then falls back to name-pattern heuristics.
fn infer_field_type(c_type: &str, name: &str, bits: u32, mappings: &KernelMappings) -> FieldType {
    // 1. Check JSON field_type_overrides first
    if let Some(ft) = mappings.field_type_override(name, bits) {
        return ft;
    }

    // 2. Address types by name pattern
    if name.contains("addr") || name == "src" || name == "dst" || name == "saddr" || name == "daddr"
    {
        if bits == 32 {
            return FieldType::Ipv4Addr;
        }
        if bits == 128 {
            return FieldType::Ipv6Addr;
        }
    }
    if name.contains("h_dest") || name.contains("h_source") || name.contains("mac") {
        if bits == 48 {
            return FieldType::MacAddr;
        }
    }

    // 3. Signed types (but not __sum16 which is a checksum, not signed)
    if c_type.starts_with("__s") && !c_type.starts_with("__sum") {
        return FieldType::Sint;
    }

    // 4. Padding/reserved
    if name.contains("pad") || name.contains("reserved") || name.starts_with("__") {
        return FieldType::Pad;
    }

    FieldType::Uint
}

/// Parse a kernel struct definition from source text.
///
/// Handles:
/// - Regular fields: `__be16 tot_len;`
/// - Bitfields: `__u8 ihl:4, version:4;`
/// - Endian-conditional bitfields: `#if defined(__BIG_ENDIAN_BITFIELD)`
/// - Arrays: `__u8 h_dest[ETH_ALEN];`
pub fn parse_kernel_struct(content: &str, struct_name: &str) -> Result<Option<KernelStruct>> {
    let escaped = regex::escape(struct_name);

    // Find the start of a struct definition using regex, then extract body
    // with brace counting (to handle nested structs/unions).
    let start_patterns = [
        format!(r"struct\s+{}\s*\{{", escaped),          // struct X {
        format!(r"typedef\s+struct\s+{}\s*\{{", escaped), // typedef struct X {
        format!(r"typedef\s+struct\s*\{{"),                // typedef struct { ... } X;
    ];

    let mut body = None;
    for (i, pat) in start_patterns.iter().enumerate() {
        let re = Regex::new(pat)?;
        if let Some(m) = re.find(content) {
            // For anonymous typedef, verify the name appears after closing brace
            let after_open = m.end();
            // Count braces to find matching close
            let mut depth = 1i32;
            let mut close_pos = None;
            for (j, ch) in content[after_open..].char_indices() {
                match ch {
                    '{' => depth += 1,
                    '}' => {
                        depth -= 1;
                        if depth == 0 {
                            close_pos = Some(after_open + j);
                            break;
                        }
                    }
                    _ => {}
                }
            }
            if let Some(close) = close_pos {
                // For anonymous typedef pattern, verify the name follows
                if i == 2 {
                    let after_close = content[close + 1..].trim_start();
                    let name_re = Regex::new(&format!(r"^{}\s*;", escaped))?;
                    if !name_re.is_match(after_close) {
                        continue; // Not the right typedef
                    }
                }
                body = Some(content[after_open..close].to_string());
                break;
            }
        }
    }

    let body = match body {
        Some(b) => b,
        None => return Ok(None),
    };

    let has_endian_bitfield = body.contains("__BIG_ENDIAN_BITFIELD");

    // We parse the __BIG_ENDIAN_BITFIELD section if present (network byte order),
    // otherwise parse all fields
    let parse_body = if has_endian_bitfield {
        // Line-by-line state machine: include non-conditional lines and
        // only the __BIG_ENDIAN_BITFIELD section of conditional blocks
        let mut result = String::new();
        let mut in_conditional = false;
        let mut in_big_endian = false;

        for line in body.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("#if") && line.contains("__LITTLE_ENDIAN_BITFIELD") {
                in_conditional = true;
                in_big_endian = false;
            } else if trimmed.starts_with("#if") && line.contains("__BIG_ENDIAN_BITFIELD") {
                in_conditional = true;
                in_big_endian = true;
            } else if in_conditional && trimmed.starts_with("#elif") {
                in_big_endian = line.contains("__BIG_ENDIAN_BITFIELD");
            } else if in_conditional && trimmed.starts_with("#else") {
                in_big_endian = false;
            } else if in_conditional && trimmed.starts_with("#endif") {
                in_conditional = false;
                in_big_endian = false;
            } else if !in_conditional || in_big_endian {
                result.push_str(line);
                result.push('\n');
            }
        }
        result
    } else {
        body.clone()
    };

    let fields = parse_struct_fields(&parse_body)?;

    Ok(Some(KernelStruct {
        name: struct_name.to_string(),
        fields,
        file_path: String::new(),
        has_endian_bitfield,
    }))
}

/// Preprocess struct body to unwrap __struct_group() macros.
///
/// `__struct_group(TAG, NAME, ATTRS, MEMBERS)` is a kernel macro that
/// creates an anonymous struct group. We strip the wrapper and inline
/// the MEMBERS so the field parser can see them normally.
fn unwrap_struct_group(body: &str) -> String {
    let mut result = body.to_string();

    while let Some(start) = result.find("__struct_group(") {
        let after_open = start + "__struct_group(".len();
        // Count parentheses to find matching close
        let mut depth = 1;
        let mut end = after_open;
        for (i, ch) in result[after_open..].char_indices() {
            match ch {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        end = after_open + i;
                        break;
                    }
                }
                _ => {}
            }
        }

        // Inside: TAG, NAME, ATTRS, MEMBERS
        // We need the MEMBERS part (everything after the 3rd comma at depth 0)
        let inner = &result[after_open..end];
        let mut comma_count = 0;
        let mut member_start = 0;
        let mut pdepth = 0;
        for (i, ch) in inner.char_indices() {
            match ch {
                '(' => pdepth += 1,
                ')' => pdepth -= 1,
                ',' if pdepth == 0 => {
                    comma_count += 1;
                    if comma_count == 3 {
                        member_start = i + 1;
                        break;
                    }
                }
                _ => {}
            }
        }

        let members = &inner[member_start..];
        // Also skip the trailing ");" or just ")"
        let replacement_end = if result[end..].starts_with(");") {
            end + 2
        } else {
            end + 1
        };

        result = format!("{}{}{}", &result[..start], members, &result[replacement_end..]);
    }

    result
}

/// Strip C inline comments (`/* ... */`) from a single line.
fn strip_inline_comments(line: &str) -> String {
    let mut result = String::with_capacity(line.len());
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '/' && chars.peek() == Some(&'*') {
            chars.next(); // consume '*'
            // Skip until closing */
            loop {
                match chars.next() {
                    Some('*') if chars.peek() == Some(&'/') => {
                        chars.next(); // consume '/'
                        break;
                    }
                    None => break,
                    _ => {}
                }
            }
        } else {
            result.push(c);
        }
    }
    result
}

/// Parse individual fields from a struct body.
fn parse_struct_fields(body: &str) -> Result<Vec<KernelField>> {
    let mut fields = Vec::new();

    // Step 0a: Unwrap __struct_group() macros
    let body = unwrap_struct_group(body);

    // Step 0b: Normalize inline bodies — if the body is a single line (common
    // when parsing anonymous inline union/struct bodies), insert newlines
    // after semicolons at brace depth 0 so the statement accumulator can split.
    // Must skip semicolons inside /* ... */ comments.
    let body = {
        let mut result = String::with_capacity(body.len());
        let mut depth = 0i32;
        let mut in_comment = false;
        let mut chars = body.chars().peekable();
        while let Some(ch) = chars.next() {
            result.push(ch);
            if in_comment {
                if ch == '*' && chars.peek() == Some(&'/') {
                    result.push(chars.next().unwrap()); // consume '/'
                    in_comment = false;
                }
            } else {
                match ch {
                    '/' if chars.peek() == Some(&'*') => {
                        result.push(chars.next().unwrap()); // consume '*'
                        in_comment = true;
                    }
                    '{' => depth += 1,
                    '}' => depth -= 1,
                    ';' if depth <= 0 => result.push('\n'),
                    _ => {}
                }
            }
        }
        result
    };

    // Step 1: Filter out preprocessor directives and comments, join continuation lines.
    // Track brace depth so that semicolons inside anonymous inline unions/structs
    // don't split them into separate statements.
    // Also track #if 0 / #endif blocks to skip dead-code fields.
    let mut statements = Vec::new();
    let mut current = String::new();
    let mut if0_depth: u32 = 0;
    let mut brace_depth: i32 = 0;

    for line in body.lines() {
        let trimmed = line.trim();

        // Track #if 0 / #endif to skip dead-code blocks
        if trimmed.starts_with("#if") && (trimmed.contains("0") && !trimmed.contains("defined")) {
            if0_depth += 1;
            continue;
        }
        if if0_depth > 0 {
            if trimmed.starts_with("#if") {
                if0_depth += 1;
            } else if trimmed.starts_with("#endif") {
                if0_depth -= 1;
            }
            continue;
        }

        if trimmed.starts_with('#')
            || trimmed.starts_with("/*")
            || trimmed.starts_with("*")
            || trimmed.starts_with("//")
            || trimmed.is_empty()
        {
            continue;
        }

        // Strip inline /* ... */ comments before processing
        let cleaned = strip_inline_comments(trimmed);
        let cleaned = cleaned.trim();
        if cleaned.is_empty() {
            continue;
        }

        // Track brace depth for anonymous inline unions/structs
        for ch in cleaned.chars() {
            match ch {
                '{' => brace_depth += 1,
                '}' => brace_depth -= 1,
                _ => {}
            }
        }

        current.push(' ');
        current.push_str(cleaned);

        // A statement is complete when we see `;` at brace depth 0
        // (semicolons inside anonymous union/struct bodies don't end the outer statement)
        if cleaned.ends_with(';') && brace_depth <= 0 {
            statements.push(current.trim().to_string());
            current.clear();
            brace_depth = 0; // reset for safety
        }
        // Otherwise it's a continuation (multi-line bitfield, or inside anon union/struct)
    }

    let bitfield_re = Regex::new(r"(\w+)\s*:\s*(\d+)")?;
    let array_re = Regex::new(r"(\w+)\s*\[\s*(\w+)\s*\]")?;

    // Known multi-word C types
    let multi_word_types = [
        "unsigned char",
        "unsigned short",
        "unsigned int",
        "unsigned long",
        "signed char",
        "signed short",
        "signed int",
        "signed long",
    ];

    for stmt in &statements {
        // Remove trailing semicolon
        let stmt = stmt.trim_end_matches(';').trim();

        // Try to split into TYPE and REST
        let (c_type, rest) = 'split: {
            // Try multi-word types first
            for mwt in &multi_word_types {
                if stmt.starts_with(mwt) {
                    let rest = stmt[mwt.len()..].trim();
                    break 'split (mwt.to_string(), rest.to_string());
                }
            }
            // Single-word type: first token
            let mut parts = stmt.splitn(2, |c: char| c.is_whitespace());
            let ty = parts.next().unwrap_or("").to_string();
            let rest = parts.next().unwrap_or("").trim().to_string();
            (ty, rest)
        };

        if c_type.is_empty() || rest.is_empty() {
            continue;
        }
        // Handle struct/union fields (named types and anonymous inline)
        let (c_type, rest) = if c_type == "struct" || c_type == "union" {
            let kind = c_type.clone();
            let rest_trimmed = rest.trim_start();
            if rest_trimmed.starts_with('{') {
                // Anonymous inline: `union { __be16 id; __be32 gateway; } un;`
                // Find matching close brace (handle nested braces)
                let mut depth = 0i32;
                let mut body_end = None;
                for (i, ch) in rest_trimmed.char_indices() {
                    match ch {
                        '{' => depth += 1,
                        '}' => {
                            depth -= 1;
                            if depth == 0 {
                                body_end = Some(i);
                                break;
                            }
                        }
                        _ => {}
                    }
                }
                let body_end = match body_end {
                    Some(i) => i,
                    None => continue,
                };
                let body = &rest_trimmed[1..body_end];
                let after_close = rest_trimmed[body_end + 1..].trim().trim_end_matches(';').trim();
                if after_close.is_empty() {
                    continue;
                }
                let field_name = after_close.to_string();
                // Parse the inner body recursively to get sub-fields
                if let Ok(inner_fields) = parse_struct_fields(body) {
                    // Compute size: union → max, struct → sum
                    // We can't fully resolve here (no mappings), so store as
                    // a special __anon type with the inner fields encoded.
                    // The size will be resolved in to_field_defs_with_content().
                    // For now, store the kind and body so we can resolve later.
                    let synthetic_type = format!("__anon_{}_{}", kind, field_name);
                    // Store body in the field for later resolution
                    fields.push(KernelField {
                        c_type: synthetic_type,
                        name: field_name,
                        bitfield_width: None,
                        array_size: None,
                        anon_body: Some(AnonymousBody {
                            kind: kind.to_string(),
                            body: body.to_string(),
                            fields: inner_fields,
                        }),
                    });
                }
                continue;
            } else {
                // Named type: `struct icmp6hdr mld_hdr;` or `union ib_gid sgid;`
                let mut parts = rest.splitn(2, |c: char| c.is_whitespace());
                let type_name = parts.next().unwrap_or("").to_string();
                let field_rest = parts.next().unwrap_or("").trim().to_string();
                if type_name.is_empty() || field_rest.is_empty() {
                    continue;
                }
                (type_name, field_rest)
            }
        } else {
            (c_type, rest)
        };

        // Parse comma-separated field list (handles bitfields across continuations)
        for part in rest.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }

            if let Some(bf_cap) = bitfield_re.captures(part) {
                fields.push(KernelField {
                    c_type: c_type.clone(),
                    name: bf_cap[1].to_string(),
                    bitfield_width: Some(bf_cap[2].parse()?),
                    array_size: None,
                    anon_body: None,
                });
            } else if let Some(arr_cap) = array_re.captures(part) {
                let size_str = &arr_cap[2];
                let size = match size_str {
                    "ETH_ALEN" => 6,
                    "MRP_DOMAIN_UUID_LENGTH" => 16,
                    "MRP_OUI_LENGTH" => 3,
                    "MRP_MANUFACTURE_DATA_LENGTH" => 2,
                    _ => size_str.parse().unwrap_or(1),
                };
                fields.push(KernelField {
                    c_type: c_type.clone(),
                    name: arr_cap[1].to_string(),
                    bitfield_width: None,
                    array_size: Some(size),
                    anon_body: None,
                });
            } else {
                // Plain field name
                let name = part.split_whitespace().next().unwrap_or(part);
                if !name.is_empty() && name.chars().all(|c| c.is_alphanumeric() || c == '_') {
                    fields.push(KernelField {
                        c_type: c_type.clone(),
                        name: name.to_string(),
                        bitfield_width: None,
                        array_size: None,
                        anon_body: None,
                    });
                }
            }
        }
    }

    Ok(fields)
}

/// Resolve the bit size of a KernelField, handling anonymous bodies and
/// nested types via content lookup.
fn resolve_field_bits(
    kf: &KernelField,
    mappings: &KernelMappings,
    content: Option<&str>,
    depth: u32,
) -> u32 {
    if let Some(bw) = kf.bitfield_width {
        return bw;
    }
    if let Some(arr) = kf.array_size {
        return resolve_type_bits(&kf.c_type, mappings, content, depth).unwrap_or(8) * arr;
    }
    if let Some(ref anon) = kf.anon_body {
        return resolve_anonymous_body_size(anon, mappings, content, depth);
    }
    resolve_type_bits(&kf.c_type, mappings, content, depth).unwrap_or(0)
}

/// Resolve bit size for a C type name — TOML first, then content search.
fn resolve_type_bits(
    c_type: &str,
    mappings: &KernelMappings,
    content: Option<&str>,
    depth: u32,
) -> Option<u32> {
    // Try TOML tables (type_bits, struct_sizes, union_sizes)
    if let Some(bits) = mappings.type_bits(c_type) {
        return Some(bits);
    }
    // Try resolving from content (find struct/union definition)
    if let Some(content) = content {
        if let Some(bits) = resolve_nested_size(content, c_type, "struct", mappings, depth) {
            return Some(bits);
        }
        if let Some(bits) = resolve_nested_size(content, c_type, "union", mappings, depth) {
            return Some(bits);
        }
    }
    None
}

/// Find a named struct/union definition in `content` and compute its size.
///
/// For structs: sum of field sizes. For unions: max of field sizes.
/// Max recursion depth = 4 to prevent infinite loops.
fn resolve_nested_size(
    content: &str,
    type_name: &str,
    kind: &str,
    mappings: &KernelMappings,
    depth: u32,
) -> Option<u32> {
    if depth >= 4 {
        return None;
    }
    // Find the definition: `struct type_name { ... }` or `union type_name { ... }`
    // Use brace counting instead of non-greedy regex (handles nested braces).
    let start_pattern = format!(
        r"{}\s+{}\s*\{{",
        regex::escape(kind),
        regex::escape(type_name)
    );
    let re = Regex::new(&start_pattern).ok()?;
    let m = re.find(content)?;
    let after_open = m.end();
    let mut brace_depth = 1i32;
    let mut close_pos = None;
    for (j, ch) in content[after_open..].char_indices() {
        match ch {
            '{' => brace_depth += 1,
            '}' => {
                brace_depth -= 1;
                if brace_depth == 0 {
                    close_pos = Some(after_open + j);
                    break;
                }
            }
            _ => {}
        }
    }
    let body = &content[after_open..close_pos?];
    let inner_fields = parse_struct_fields(body).ok()?;

    let sizes: Vec<u32> = inner_fields
        .iter()
        .map(|f| resolve_field_bits(f, mappings, Some(content), depth + 1))
        .collect();

    if sizes.is_empty() {
        return None;
    }

    if kind == "union" {
        sizes.into_iter().max()
    } else {
        Some(sizes.into_iter().sum())
    }
}

/// Compute the size of an anonymous inline union/struct body.
fn resolve_anonymous_body_size(
    anon: &AnonymousBody,
    mappings: &KernelMappings,
    content: Option<&str>,
    depth: u32,
) -> u32 {
    if depth >= 4 {
        return 0;
    }
    let sizes: Vec<u32> = anon
        .fields
        .iter()
        .map(|f| resolve_field_bits(f, mappings, content, depth + 1))
        .collect();

    if sizes.is_empty() {
        return 0;
    }

    if anon.kind == "union" {
        sizes.into_iter().max().unwrap_or(0)
    } else {
        sizes.into_iter().sum()
    }
}

/// Convert a KernelStruct to field-level IR definitions.
///
/// Uses loaded mappings for type/endian inference. Call
/// `to_field_defs_default()` for embedded defaults (tests/convenience).
pub fn to_field_defs(ks: &KernelStruct) -> Vec<FieldDef> {
    let mappings = type_mapping::load_kernel_mappings(None)
        .expect("embedded kernel mappings should always parse");
    to_field_defs_with(ks, &mappings)
}

/// Convert using explicit mappings (no content-aware resolution).
pub fn to_field_defs_with(ks: &KernelStruct, mappings: &KernelMappings) -> Vec<FieldDef> {
    build_field_defs(ks, mappings, None)
}

/// Convert using explicit mappings + file content for nested type resolution.
pub fn to_field_defs_with_content(
    ks: &KernelStruct,
    mappings: &KernelMappings,
    content: &str,
) -> Vec<FieldDef> {
    build_field_defs(ks, mappings, Some(content))
}

/// Core field definition builder (shared by with/without content variants).
fn build_field_defs(
    ks: &KernelStruct,
    mappings: &KernelMappings,
    content: Option<&str>,
) -> Vec<FieldDef> {
    let mut fields = Vec::new();
    let mut offset_bits: u32 = 0;
    let mut prev_was_bitfield = false;

    for kf in &ks.fields {
        let bits = resolve_field_bits(kf, mappings, content, 0);

        if bits == 0 {
            continue; // Unknown type, skip
        }

        let is_bitfield = kf.bitfield_width.is_some();

        // C struct alignment: after a bitfield group, pad to byte boundary,
        // then align the next non-bitfield to its natural alignment.
        if !is_bitfield && prev_was_bitfield {
            // Round up to next byte boundary (end of bitfield storage unit)
            offset_bits = (offset_bits + 7) & !7;
            // Natural alignment: field aligns to min(field_size, 64) bits
            if bits >= 16 {
                let align = std::cmp::min(bits, 64);
                offset_bits = (offset_bits + align - 1) & !(align - 1);
            }
        }

        prev_was_bitfield = is_bitfield;

        let endian = if kf.bitfield_width.is_some() || bits <= 8 {
            Endian::Na
        } else if let Some(arr) = kf.array_size {
            // Check array endian overrides (e.g., MAC addresses)
            mappings
                .array_endian_override(&kf.c_type, arr)
                .unwrap_or_else(|| c_type_endian(&kf.c_type, mappings))
        } else if kf.anon_body.is_some() {
            // Anonymous inline union/struct — treat as opaque, no endian
            Endian::Na
        } else {
            c_type_endian(&kf.c_type, mappings)
        };

        let field_type = infer_field_type(&kf.c_type, &kf.name, bits, mappings);

        fields.push(
            FieldDef::new(kf.name.clone(), offset_bits, bits, field_type)
                .with_endian(endian)
                .with_source_name("kernel", kf.name.clone()),
        );

        offset_bits += bits;
    }

    fields
}

/// Extract a full ProtocolDef from a kernel header for a given struct.
pub fn extract_protocol(
    content: &str,
    struct_name: &str,
    file_path: &str,
) -> Result<Option<ProtocolDef>> {
    let mappings = type_mapping::load_kernel_mappings(None)
        .expect("embedded kernel mappings should always parse");
    let ks = match parse_kernel_struct(content, struct_name)? {
        Some(ks) => ks,
        None => return Ok(None),
    };

    let fields = to_field_defs_with_content(&ks, &mappings, content);
    let total_bits: u32 = fields.iter().map(|f| f.offset_bits + f.size_bits).max().unwrap_or(0);
    let field_count = fields.len() as u32;

    Ok(Some(ProtocolDef::new(struct_name, total_bits)
        .with_fields(fields)
        .with_source("kernel", SourceInfo::new(struct_name)
            .with_file(file_path)
            .with_field_count(field_count)
            .with_min_header_bytes(total_bits / 8))))
}

#[cfg(test)]
mod tests {
    use super::*;

    const IPHDR: &str = r#"
struct iphdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
    __u8    ihl:4,
        version:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
    __u8    version:4,
        ihl:4;
#else
#error  "Please fix <asm/byteorder.h>"
#endif
    __u8    tos;
    __be16  tot_len;
    __be16  id;
    __be16  frag_off;
    __u8    ttl;
    __u8    protocol;
    __sum16 check;
    __be32  saddr;
    __be32  daddr;
};
"#;

    #[test]
    fn test_parse_iphdr() {
        let ks = parse_kernel_struct(IPHDR, "iphdr").unwrap().unwrap();
        assert_eq!(ks.name, "iphdr");
        assert!(ks.has_endian_bitfield);

        // Should have: version:4, ihl:4, tos, tot_len, id, frag_off, ttl, protocol, check, saddr, daddr
        assert!(ks.fields.len() >= 10, "got {} fields", ks.fields.len());

        // Check bitfield parsing (big-endian section)
        let version = &ks.fields[0];
        assert_eq!(version.name, "version");
        assert_eq!(version.bitfield_width, Some(4));

        let ihl = &ks.fields[1];
        assert_eq!(ihl.name, "ihl");
        assert_eq!(ihl.bitfield_width, Some(4));
    }

    #[test]
    fn test_iphdr_field_defs() {
        let ks = parse_kernel_struct(IPHDR, "iphdr").unwrap().unwrap();
        let fields = to_field_defs(&ks);

        // version at offset 0, 4 bits
        let version = fields.iter().find(|f| f.name == "version").unwrap();
        assert_eq!(version.offset_bits, 0);
        assert_eq!(version.size_bits, 4);
        assert_eq!(version.endian, Endian::Na);

        // ihl at offset 4, 4 bits
        let ihl = fields.iter().find(|f| f.name == "ihl").unwrap();
        assert_eq!(ihl.offset_bits, 4);
        assert_eq!(ihl.size_bits, 4);

        // tos at offset 8, 8 bits
        let tos = fields.iter().find(|f| f.name == "tos").unwrap();
        assert_eq!(tos.offset_bits, 8);
        assert_eq!(tos.size_bits, 8);

        // tot_len at offset 16, 16 bits, big-endian
        let tot_len = fields.iter().find(|f| f.name == "tot_len").unwrap();
        assert_eq!(tot_len.offset_bits, 16);
        assert_eq!(tot_len.size_bits, 16);
        assert_eq!(tot_len.endian, Endian::Big);

        // check (__sum16) at offset 80, 16 bits, big-endian (network-order checksum)
        let check = fields.iter().find(|f| f.name == "check").unwrap();
        assert_eq!(check.offset_bits, 80);
        assert_eq!(check.size_bits, 16);
        assert_eq!(check.endian, Endian::Big);

        // saddr at offset 96, 32 bits, Ipv4Addr
        let saddr = fields.iter().find(|f| f.name == "saddr").unwrap();
        assert_eq!(saddr.offset_bits, 96);
        assert_eq!(saddr.size_bits, 32);
        assert_eq!(saddr.field_type, FieldType::Ipv4Addr);
    }

    const ETHHDR: &str = r#"
struct ethhdr {
    unsigned char   h_dest[ETH_ALEN];
    unsigned char   h_source[ETH_ALEN];
    __be16          h_proto;
} __attribute__((packed));
"#;

    #[test]
    fn test_parse_ethhdr() {
        let ks = parse_kernel_struct(ETHHDR, "ethhdr").unwrap().unwrap();
        assert_eq!(ks.fields.len(), 3);

        assert_eq!(ks.fields[0].name, "h_dest");
        assert_eq!(ks.fields[0].array_size, Some(6));

        assert_eq!(ks.fields[1].name, "h_source");
        assert_eq!(ks.fields[1].array_size, Some(6));

        assert_eq!(ks.fields[2].name, "h_proto");
        assert_eq!(ks.fields[2].c_type, "__be16");
    }

    #[test]
    fn test_ethhdr_field_defs() {
        let ks = parse_kernel_struct(ETHHDR, "ethhdr").unwrap().unwrap();
        let fields = to_field_defs(&ks);

        let h_dest = &fields[0];
        assert_eq!(h_dest.offset_bits, 0);
        assert_eq!(h_dest.size_bits, 48);
        assert_eq!(h_dest.field_type, FieldType::MacAddr); // h_dest → MAC address
        assert_eq!(h_dest.endian, Endian::Big); // MAC addresses are network byte order

        let h_proto = &fields[2];
        assert_eq!(h_proto.offset_bits, 96);
        assert_eq!(h_proto.size_bits, 16);
        assert_eq!(h_proto.endian, Endian::Big);
    }

    #[test]
    fn test_extract_protocol() {
        let proto = extract_protocol(IPHDR, "iphdr", "include/uapi/linux/ip.h")
            .unwrap()
            .unwrap();
        assert_eq!(proto.name, "iphdr");
        assert!(proto.fields.len() >= 10);
        let src = proto.sources.get("kernel").unwrap();
        assert!(src.present);
        assert_eq!(src.min_header_bytes, 20);
    }

    /// Test parsing iphdr with __struct_group wrapping saddr/daddr
    /// (as found in modern kernel headers like glibc 2.42+)
    const IPHDR_STRUCT_GROUP: &str = r#"
struct iphdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8	ihl:4,
		version:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
	__u8	version:4,
  		ihl:4;
#else
#error	"Please fix <asm/byteorder.h>"
#endif
	__u8	tos;
	__be16	tot_len;
	__be16	id;
	__be16	frag_off;
	__u8	ttl;
	__u8	protocol;
	__sum16	check;
	__struct_group(/* no tag */, addrs, /* no attrs */,
		__be32	saddr;
		__be32	daddr;
	);
	/*The options start here. */
};
"#;

    #[test]
    fn test_parse_iphdr_struct_group() {
        let ks = parse_kernel_struct(IPHDR_STRUCT_GROUP, "iphdr")
            .unwrap()
            .unwrap();
        assert_eq!(ks.fields.len(), 11, "expected 11 fields, got {:?}",
            ks.fields.iter().map(|f| &f.name).collect::<Vec<_>>());

        let saddr = ks.fields.iter().find(|f| f.name == "saddr").expect("saddr missing");
        assert_eq!(saddr.c_type, "__be32");

        let daddr = ks.fields.iter().find(|f| f.name == "daddr").expect("daddr missing");
        assert_eq!(daddr.c_type, "__be32");
    }

    #[test]
    fn test_iphdr_struct_group_field_defs() {
        let ks = parse_kernel_struct(IPHDR_STRUCT_GROUP, "iphdr")
            .unwrap()
            .unwrap();
        let fields = to_field_defs(&ks);

        // saddr at offset 96, 32 bits
        let saddr = fields.iter().find(|f| f.name == "saddr").unwrap();
        assert_eq!(saddr.offset_bits, 96);
        assert_eq!(saddr.size_bits, 32);
        assert_eq!(saddr.field_type, FieldType::Ipv4Addr);

        // daddr at offset 128, 32 bits
        let daddr = fields.iter().find(|f| f.name == "daddr").unwrap();
        assert_eq!(daddr.offset_bits, 128);
        assert_eq!(daddr.size_bits, 32);
        assert_eq!(daddr.field_type, FieldType::Ipv4Addr);

        // Total: 160 bits = 20 bytes
        let total = fields.last().map(|f| f.offset_bits + f.size_bits).unwrap_or(0);
        assert_eq!(total, 160);
    }

    /// Test parsing arphdr with inline comments and #if 0 dead code.
    const ARPHDR: &str = r#"
struct arphdr {
	__be16		ar_hrd;		/* format of hardware address	*/
	__be16		ar_pro;		/* format of protocol address	*/
	unsigned char	ar_hln;		/* length of hardware address	*/
	unsigned char	ar_pln;		/* length of protocol address	*/
	__be16		ar_op;		/* ARP opcode (command)		*/

#if 0
	 /*
	  *	 Ethernet looks like this : This bit is variable sized however...
	  */
	unsigned char		ar_sha[ETH_ALEN];	/* sender hardware address	*/
	unsigned char		ar_sip[4];		/* sender IP address		*/
	unsigned char		ar_tha[ETH_ALEN];	/* target hardware address	*/
	unsigned char		ar_tip[4];		/* target IP address		*/
#endif

};
"#;

    #[test]
    fn test_parse_arphdr_inline_comments() {
        let ks = parse_kernel_struct(ARPHDR, "arphdr").unwrap().unwrap();
        assert_eq!(
            ks.fields.len(),
            5,
            "expected 5 fields (ar_hrd, ar_pro, ar_hln, ar_pln, ar_op), got {:?}",
            ks.fields.iter().map(|f| &f.name).collect::<Vec<_>>()
        );

        assert_eq!(ks.fields[0].name, "ar_hrd");
        assert_eq!(ks.fields[0].c_type, "__be16");
        assert_eq!(ks.fields[1].name, "ar_pro");
        assert_eq!(ks.fields[2].name, "ar_hln");
        assert_eq!(ks.fields[2].c_type, "unsigned char");
        assert_eq!(ks.fields[3].name, "ar_pln");
        assert_eq!(ks.fields[4].name, "ar_op");
    }

    #[test]
    fn test_arphdr_field_defs() {
        let ks = parse_kernel_struct(ARPHDR, "arphdr").unwrap().unwrap();
        let fields = to_field_defs(&ks);
        assert_eq!(fields.len(), 5);

        // ar_hrd: 0..16 big-endian, Enum (via mapping override)
        assert_eq!(fields[0].offset_bits, 0);
        assert_eq!(fields[0].size_bits, 16);
        assert_eq!(fields[0].endian, Endian::Big);
        assert_eq!(fields[0].field_type, FieldType::Enum);

        // ar_pro: Enum (via mapping override)
        assert_eq!(fields[1].field_type, FieldType::Enum);

        // ar_op at offset 48, 16 bits, Enum (via mapping override)
        assert_eq!(fields[4].offset_bits, 48);
        assert_eq!(fields[4].size_bits, 16);
        assert_eq!(fields[4].field_type, FieldType::Enum);

        // Total: 64 bits = 8 bytes
        let total = fields.last().map(|f| f.offset_bits + f.size_bits).unwrap_or(0);
        assert_eq!(total, 64);
    }

    #[test]
    fn test_iphdr_protocol_field_is_enum() {
        let ks = parse_kernel_struct(IPHDR, "iphdr").unwrap().unwrap();
        let fields = to_field_defs(&ks);
        let protocol = fields.iter().find(|f| f.name == "protocol").unwrap();
        assert_eq!(protocol.field_type, FieldType::Enum);
    }

    const VLANHDR: &str = r#"
struct vlan_hdr {
    __be16  h_vlan_TCI;
    __be16  h_vlan_encapsulated_proto;
};
"#;

    #[test]
    fn test_vlanhdr_field_types() {
        let ks = parse_kernel_struct(VLANHDR, "vlan_hdr").unwrap().unwrap();
        let fields = to_field_defs(&ks);
        assert_eq!(fields.len(), 2);

        // h_vlan_TCI → Flags (packed PCP + DEI + VID)
        assert_eq!(fields[0].name, "h_vlan_TCI");
        assert_eq!(fields[0].field_type, FieldType::Flags);
        assert_eq!(fields[0].endian, Endian::Big);

        // h_vlan_encapsulated_proto → Enum (EtherType)
        assert_eq!(fields[1].name, "h_vlan_encapsulated_proto");
        assert_eq!(fields[1].field_type, FieldType::Enum);
        assert_eq!(fields[1].endian, Endian::Big);
    }

    const ICMPHDR: &str = r#"
struct icmphdr {
    __u8    type;
    __u8    code;
    __sum16 checksum;
    __be16  id;
    __be16  sequence;
};
"#;

    #[test]
    fn test_icmphdr_field_types() {
        let ks = parse_kernel_struct(ICMPHDR, "icmphdr").unwrap().unwrap();
        let fields = to_field_defs(&ks);

        let type_field = fields.iter().find(|f| f.name == "type").unwrap();
        assert_eq!(type_field.field_type, FieldType::Enum);

        let code_field = fields.iter().find(|f| f.name == "code").unwrap();
        assert_eq!(code_field.field_type, FieldType::Enum);

        let checksum = fields.iter().find(|f| f.name == "checksum").unwrap();
        assert_eq!(checksum.endian, Endian::Big); // __sum16 → Big
    }

    #[test]
    fn test_ethhdr_h_proto_is_enum() {
        let ks = parse_kernel_struct(ETHHDR, "ethhdr").unwrap().unwrap();
        let fields = to_field_defs(&ks);
        let h_proto = fields.iter().find(|f| f.name == "h_proto").unwrap();
        assert_eq!(h_proto.field_type, FieldType::Enum);
    }

    #[test]
    fn test_mld_msg_embedded_structs() {
        let mld_h = r#"
struct mld_msg {
    struct icmp6hdr      mld_hdr;
    struct in6_addr      mld_mca;
};
"#;
        let ks = parse_kernel_struct(mld_h, "mld_msg").unwrap().unwrap();
        assert_eq!(ks.fields.len(), 2);
        assert_eq!(ks.fields[0].name, "mld_hdr");
        assert_eq!(ks.fields[0].c_type, "icmp6hdr");
        assert_eq!(ks.fields[1].name, "mld_mca");
        assert_eq!(ks.fields[1].c_type, "in6_addr");

        let fields = to_field_defs(&ks);
        assert_eq!(fields.len(), 2);
        // icmp6hdr = 64 bits (from struct_sizes)
        assert_eq!(fields[0].size_bits, 64);
        assert_eq!(fields[0].offset_bits, 0);
        // in6_addr = 128 bits (from struct_sizes)
        assert_eq!(fields[1].size_bits, 128);
        assert_eq!(fields[1].offset_bits, 64);
    }

    #[test]
    fn test_nested_struct_resolution_from_content() {
        // gre_base_hdr is defined in the same content — resolve via content lookup
        let content = r#"
struct gre_base_hdr {
    __be16 flags;
    __be16 protocol;
};

struct gre_full_hdr {
    struct gre_base_hdr gre_hd;
    __be16 key_high;
    __be16 key_low;
};
"#;
        let ks = parse_kernel_struct(content, "gre_full_hdr").unwrap().unwrap();
        let mappings = type_mapping::load_kernel_mappings(None).unwrap();
        let fields = to_field_defs_with_content(&ks, &mappings, content);

        assert_eq!(fields.len(), 3);
        // gre_hd resolved from content: flags(16) + protocol(16) = 32 bits
        assert_eq!(fields[0].name, "gre_hd");
        assert_eq!(fields[0].size_bits, 32);
        assert_eq!(fields[0].offset_bits, 0);
        // key_high at offset 32
        assert_eq!(fields[1].name, "key_high");
        assert_eq!(fields[1].offset_bits, 32);
    }

    #[test]
    fn test_nested_union_resolution_from_content() {
        // union ib_gid is defined in the same content
        let content = r#"
union ib_gid {
    __u8 raw[16];
};

struct ib_grh {
    __be32 version_tclass_flow;
    __be16 paylen;
    __u8   nxthdr;
    __u8   hoplmt;
    union ib_gid sgid;
    union ib_gid dgid;
};
"#;
        let ks = parse_kernel_struct(content, "ib_grh").unwrap().unwrap();
        let mappings = type_mapping::load_kernel_mappings(None).unwrap();
        let fields = to_field_defs_with_content(&ks, &mappings, content);

        // version_tclass_flow(32) + paylen(16) + nxthdr(8) + hoplmt(8) + sgid(128) + dgid(128)
        assert_eq!(fields.len(), 6);
        let sgid = fields.iter().find(|f| f.name == "sgid").unwrap();
        assert_eq!(sgid.size_bits, 128);
        assert_eq!(sgid.offset_bits, 64);
        let dgid = fields.iter().find(|f| f.name == "dgid").unwrap();
        assert_eq!(dgid.size_bits, 128);
        assert_eq!(dgid.offset_bits, 192);
    }

    #[test]
    fn test_anonymous_inline_union() {
        // icmphdr-style: anonymous inline union
        let content = r#"
struct icmphdr {
    __u8    type;
    __u8    code;
    __sum16 checksum;
    union {
        struct {
            __be16  id;
            __be16  sequence;
        } echo;
        __be32  gateway;
        __u8    reserved[4];
    } un;
};
"#;
        let ks = parse_kernel_struct(content, "icmphdr").unwrap().unwrap();
        assert!(ks.fields.iter().any(|f| f.name == "un"), "un field missing from parsed fields");
        let mappings = type_mapping::load_kernel_mappings(None).unwrap();
        let fields = to_field_defs_with_content(&ks, &mappings, content);

        // type(8) + code(8) + checksum(16) + un(32) = 64 bits
        assert_eq!(fields.len(), 4, "fields: {:?}", fields.iter().map(|f| &f.name).collect::<Vec<_>>());
        let un = fields.iter().find(|f| f.name == "un").unwrap();
        assert_eq!(un.size_bits, 32); // max(echo=32, gateway=32, reserved=32) = 32
        assert_eq!(un.offset_bits, 32);
    }

    #[test]
    fn test_toml_fallback_for_nested_struct() {
        // in6_addr is not defined in content, falls back to TOML struct_sizes
        let content = r#"
struct ipv6hdr {
    __be32 vtf;
    __be16 payload_len;
    __u8   nexthdr;
    __u8   hop_limit;
    struct in6_addr saddr;
    struct in6_addr daddr;
};
"#;
        let ks = parse_kernel_struct(content, "ipv6hdr").unwrap().unwrap();
        let mappings = type_mapping::load_kernel_mappings(None).unwrap();
        let fields = to_field_defs_with_content(&ks, &mappings, content);

        let saddr = fields.iter().find(|f| f.name == "saddr").unwrap();
        assert_eq!(saddr.size_bits, 128); // From TOML: in6_addr = 128
        let daddr = fields.iter().find(|f| f.name == "daddr").unwrap();
        assert_eq!(daddr.size_bits, 128);
    }

    #[test]
    fn test_recursion_depth_limit() {
        // Circular reference: struct A contains struct B, struct B contains struct A
        let content = r#"
struct circular_a {
    struct circular_b inner;
};

struct circular_b {
    struct circular_a inner;
};
"#;
        let ks = parse_kernel_struct(content, "circular_a").unwrap().unwrap();
        let mappings = type_mapping::load_kernel_mappings(None).unwrap();
        // Should not panic — just skip unresolvable fields
        let fields = to_field_defs_with_content(&ks, &mappings, content);
        assert_eq!(fields.len(), 0); // inner is unresolvable, skipped
    }

    #[test]
    fn test_unknown_nested_skipped() {
        // Unknown type that's not in content or TOML
        let content = r#"
struct foo {
    __u8 tag;
    struct completely_unknown_type payload;
    __u16 trailer;
};
"#;
        let ks = parse_kernel_struct(content, "foo").unwrap().unwrap();
        let mappings = type_mapping::load_kernel_mappings(None).unwrap();
        let fields = to_field_defs_with_content(&ks, &mappings, content);

        assert_eq!(fields.len(), 2); // tag + trailer (payload skipped)
        assert_eq!(fields[0].name, "tag");
        assert_eq!(fields[1].name, "trailer");
        // trailer offset: tag(8) + payload(skipped) = 8
        assert_eq!(fields[1].offset_bits, 8);
    }

    #[test]
    fn test_typedef_struct_parsing() {
        let content = r#"
typedef struct lacpdu {
    __u8    subtype;
    __u8    version_number;
    __u8    tlv_type_actor;
    __u8    actor_info_len;
} __packed lacpdu_t;
"#;
        let ks = parse_kernel_struct(content, "lacpdu").unwrap().unwrap();
        assert_eq!(ks.fields.len(), 4);
        assert_eq!(ks.fields[0].name, "subtype");
    }

    #[test]
    fn test_union_named_type_via_toml() {
        // union ib_gid resolved via TOML union_sizes (not content)
        let content = r#"
struct ib_grh {
    __be32 version_tclass_flow;
    union ib_gid sgid;
    union ib_gid dgid;
};
"#;
        let ks = parse_kernel_struct(content, "ib_grh").unwrap().unwrap();
        assert_eq!(ks.fields.len(), 3);
        assert_eq!(ks.fields[1].name, "sgid");
        assert_eq!(ks.fields[1].c_type, "ib_gid");
        // Resolve via TOML union_sizes
        let mappings = type_mapping::load_kernel_mappings(None).unwrap();
        let fields = to_field_defs_with(&ks, &mappings);
        let sgid = fields.iter().find(|f| f.name == "sgid").unwrap();
        assert_eq!(sgid.size_bits, 128);
    }

    #[test]
    fn test_strip_inline_comments_with_semicolon() {
        let line = "unsigned char\t\trtm_protocol;\t/* Routing protocol; see below\t*/";
        let stripped = strip_inline_comments(line);
        assert!(
            !stripped.contains("below"),
            "comment not fully stripped: {:?}",
            stripped
        );
        assert!(
            stripped.contains("rtm_protocol"),
            "field name lost: {:?}",
            stripped
        );
    }

    #[test]
    fn test_rtmsg_all_fields_parsed() {
        // Use concat! to avoid string continuation confusion
        let content = concat!(
            "struct rtmsg {\n",
            "\tunsigned char\t\trtm_family;\n",
            "\tunsigned char\t\trtm_dst_len;\n",
            "\tunsigned char\t\trtm_src_len;\n",
            "\tunsigned char\t\trtm_tos;\n",
            "\n",
            "\tunsigned char\t\trtm_table;\t/* Routing table id */\n",
            "\tunsigned char\t\trtm_protocol;\t/* Routing protocol; see below\t*/\n",
            "\tunsigned char\t\trtm_scope;\t/* See below */\t\n",
            "\tunsigned char\t\trtm_type;\t/* See below\t*/\n",
            "\n",
            "\tunsigned\t\trtm_flags;\n",
            "};\n",
        );
        let ks = parse_kernel_struct(content, "rtmsg").unwrap().unwrap();
        let field_names: Vec<&str> = ks.fields.iter().map(|f| f.name.as_str()).collect();
        assert!(
            field_names.contains(&"rtm_scope"),
            "rtm_scope missing from parsed fields: {:?}",
            field_names
        );
        assert_eq!(ks.fields.len(), 9, "expected 9 fields, got {:?}", field_names);
    }
}
