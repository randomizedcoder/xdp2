//! Flag-fields parsing system.
//!
//! Flag-fields encode optional data fields whose presence is indicated by
//! bit flags in a header word. The fields are fixed-length and ordered by
//! flag position (e.g., GRE v0, GUE).
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `FlagField` | `flag_fields.h:64-68` | `struct xdp2_flag_field` |
//! | `FlagFields` | `flag_fields.h:78-81` | `struct xdp2_flag_fields` |
//! | `flag_fields_offset()` | `flag_fields.h:116-130` | `xdp2_flag_fields_offset()` |
//! | `flag_fields_length()` | `flag_fields.h:107-113` | `xdp2_flag_fields_length()` |
//! | `flag_fields_check_invalid()` | `flag_fields.h:133-136` | `xdp2_flag_fields_check_invalid()` |

/// One descriptor for a flag-field.
///
/// Reimplements: `struct xdp2_flag_field` in `flag_fields.h:64-68`
#[derive(Debug, Clone, Copy)]
pub struct FlagField {
    /// Protocol flag value
    pub flag: u32,
    /// Mask to apply (0 means use flag as mask)
    pub mask: u32,
    /// Size of the corresponding data field in bytes
    pub size: usize,
}

/// A set of flag-field descriptors for one protocol.
///
/// Reimplements: `struct xdp2_flag_fields` in `flag_fields.h:78-81`
pub struct FlagFields {
    pub fields: &'static [FlagField],
}

impl FlagFields {
    /// Compute the byte offset of a particular flag's data field.
    ///
    /// Reimplements: `__xdp2_flag_fields_offset()` in `flag_fields.h:84-101`
    ///
    /// Scans all fields before `targ_idx`, summing the sizes of present fields.
    fn offset_of(&self, targ_idx: usize, flags: u32) -> usize {
        let mut offset = 0;
        for i in 0..targ_idx {
            let field = &self.fields[i];
            let mask = if field.mask != 0 { field.mask } else { field.flag };
            if (flags & mask) == field.flag {
                offset += field.size;
            }
        }
        offset
    }

    /// Compute the total length of optional fields present given a flag word.
    ///
    /// Reimplements: `xdp2_flag_fields_length()` in `flag_fields.h:107-113`
    ///
    /// This is equivalent to the offset of the theoretical field after the last one.
    pub fn length(&self, flags: u32) -> usize {
        self.offset_of(self.fields.len(), flags)
    }

    /// Determine the byte offset of a specific flag's data field.
    ///
    /// Reimplements: `xdp2_flag_fields_offset()` in `flag_fields.h:116-130`
    ///
    /// Returns `None` if the flag is not set (C returns -1).
    pub fn offset(&self, targ_idx: usize, flags: u32) -> Option<usize> {
        if targ_idx >= self.fields.len() {
            return None;
        }
        let field = &self.fields[targ_idx];
        let mask = if field.mask != 0 { field.mask } else { field.flag };
        if (flags & mask) != field.flag {
            return None; // Flag not set
        }
        Some(self.offset_of(targ_idx, flags))
    }

    /// Check if any illegal flags are set.
    ///
    /// Reimplements: `xdp2_flag_fields_check_invalid()` in `flag_fields.h:133-136`
    pub fn check_invalid(&self, flags: u32, valid_mask: u32) -> bool {
        (flags & !valid_mask) != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // GRE v0 flag-fields (simplified)
    // Bit 15 (0x8000): Checksum present (4 bytes: checksum + reserved)
    // Bit 13 (0x2000): Key present (4 bytes)
    // Bit 12 (0x1000): Sequence present (4 bytes)
    static GRE_FLAGS: FlagFields = FlagFields {
        fields: &[
            FlagField { flag: 0x8000, mask: 0, size: 4 }, // checksum
            FlagField { flag: 0x2000, mask: 0, size: 4 }, // key
            FlagField { flag: 0x1000, mask: 0, size: 4 }, // sequence
        ],
    };

    #[test]
    fn no_flags_set() {
        assert_eq!(GRE_FLAGS.length(0x0000), 0);
    }

    #[test]
    fn all_flags_set() {
        assert_eq!(GRE_FLAGS.length(0x8000 | 0x2000 | 0x1000), 12);
    }

    #[test]
    fn key_only() {
        let flags = 0x2000;
        assert_eq!(GRE_FLAGS.length(flags), 4);
        // Key is at index 1, but checksum (index 0) is not present
        assert_eq!(GRE_FLAGS.offset(1, flags), Some(0));
    }

    #[test]
    fn checksum_and_key() {
        let flags = 0x8000 | 0x2000;
        assert_eq!(GRE_FLAGS.length(flags), 8);
        // Checksum at offset 0
        assert_eq!(GRE_FLAGS.offset(0, flags), Some(0));
        // Key at offset 4 (after checksum)
        assert_eq!(GRE_FLAGS.offset(1, flags), Some(4));
        // Sequence not present
        assert_eq!(GRE_FLAGS.offset(2, flags), None);
    }

    #[test]
    fn invalid_flags() {
        let valid_mask = 0x8000 | 0x2000 | 0x1000;
        assert!(!GRE_FLAGS.check_invalid(0x2000, valid_mask));
        assert!(GRE_FLAGS.check_invalid(0x0001, valid_mask));
    }
}
