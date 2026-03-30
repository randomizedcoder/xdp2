//! IANA registry loader and dispatch table validator.
//!
//! Loads pre-parsed IANA JSON files (from `helpers/parse_iana.py`) and validates
//! protocol dispatch tables against authoritative IANA assignments.

use std::collections::HashMap;
use std::path::Path;

/// A single IANA protocol number entry.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct ProtocolNumber {
    pub number: u64,
    pub keyword: String,
    pub description: String,
}

/// A single IANA EtherType entry.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct EtherTypeEntry {
    pub ethertype: u64,
    pub hex: String,
    pub description: String,
}

/// A single IANA service port entry.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct ServicePort {
    pub name: String,
    pub port: u64,
    pub protocol: String,
    pub description: String,
}

/// All loaded IANA registries.
#[derive(Debug, Default)]
pub struct IanaRegistries {
    /// IP protocol numbers (next-header values)
    pub protocol_numbers: HashMap<u64, ProtocolNumber>,
    /// IEEE 802 EtherType values
    pub ethertypes: HashMap<u64, EtherTypeEntry>,
    /// TCP/UDP/SCTP service port assignments
    pub service_ports: HashMap<String, ServicePort>,
}

/// Validation result for a single dispatch entry.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DispatchValidation {
    pub protocol: String,
    pub dispatch_field: String,
    pub value: u64,
    pub iana_keyword: Option<String>,
    pub iana_description: Option<String>,
    pub status: DispatchStatus,
}

/// Whether a dispatch value matches IANA records.
#[derive(Debug, Clone, serde::Serialize)]
pub enum DispatchStatus {
    /// Value found in IANA registry and matches
    Confirmed,
    /// Value found in IANA registry but mapped to different protocol
    Mismatch { iana_name: String },
    /// Value not found in IANA registry
    NotInRegistry,
    /// No IANA registry available for this dispatch type
    NoRegistry,
}

impl IanaRegistries {
    /// Load all registries from a directory containing the JSON files.
    pub fn load(dir: &Path) -> anyhow::Result<Self> {
        let mut registries = IanaRegistries::default();

        let proto_path = dir.join("protocol_numbers.json");
        if proto_path.exists() {
            let content = std::fs::read_to_string(&proto_path)?;
            let raw: HashMap<String, ProtocolNumber> = serde_json::from_str(&content)?;
            registries.protocol_numbers = raw
                .into_values()
                .map(|p| (p.number, p))
                .collect();
        }

        let ether_path = dir.join("ethertypes.json");
        if ether_path.exists() {
            let content = std::fs::read_to_string(&ether_path)?;
            let raw: HashMap<String, EtherTypeEntry> = serde_json::from_str(&content)?;
            registries.ethertypes = raw
                .into_values()
                .map(|e| (e.ethertype, e))
                .collect();
        }

        let svc_path = dir.join("service_ports.json");
        if svc_path.exists() {
            let content = std::fs::read_to_string(&svc_path)?;
            registries.service_ports = serde_json::from_str(&content)?;
        }

        Ok(registries)
    }

    /// Look up an IP protocol number.
    pub fn lookup_protocol_number(&self, number: u64) -> Option<&ProtocolNumber> {
        self.protocol_numbers.get(&number)
    }

    /// Look up an EtherType value.
    pub fn lookup_ethertype(&self, ethertype: u64) -> Option<&EtherTypeEntry> {
        self.ethertypes.get(&ethertype)
    }

    /// Look up a service port.
    pub fn lookup_service_port(&self, port: u64, transport: &str) -> Option<&ServicePort> {
        let key = format!("{}/{}", port, transport);
        self.service_ports.get(&key)
    }

    /// Validate a dispatch value against the appropriate IANA registry.
    ///
    /// `dispatch_type` is the semantic type: "ether_type", "protocol" (IP),
    /// "dst_port", "next_header", etc.
    pub fn validate_dispatch(
        &self,
        protocol: &str,
        dispatch_type: &str,
        value: u64,
    ) -> DispatchValidation {
        match dispatch_type {
            "ether_type" => {
                if self.ethertypes.is_empty() {
                    return DispatchValidation {
                        protocol: protocol.to_string(),
                        dispatch_field: dispatch_type.to_string(),
                        value,
                        iana_keyword: None,
                        iana_description: None,
                        status: DispatchStatus::NoRegistry,
                    };
                }
                match self.ethertypes.get(&value) {
                    Some(entry) => DispatchValidation {
                        protocol: protocol.to_string(),
                        dispatch_field: dispatch_type.to_string(),
                        value,
                        iana_keyword: Some(entry.hex.clone()),
                        iana_description: Some(entry.description.clone()),
                        status: DispatchStatus::Confirmed,
                    },
                    None => DispatchValidation {
                        protocol: protocol.to_string(),
                        dispatch_field: dispatch_type.to_string(),
                        value,
                        iana_keyword: None,
                        iana_description: None,
                        status: DispatchStatus::NotInRegistry,
                    },
                }
            }
            "protocol" | "next_header" => {
                if self.protocol_numbers.is_empty() {
                    return DispatchValidation {
                        protocol: protocol.to_string(),
                        dispatch_field: dispatch_type.to_string(),
                        value,
                        iana_keyword: None,
                        iana_description: None,
                        status: DispatchStatus::NoRegistry,
                    };
                }
                match self.protocol_numbers.get(&value) {
                    Some(entry) => DispatchValidation {
                        protocol: protocol.to_string(),
                        dispatch_field: dispatch_type.to_string(),
                        value,
                        iana_keyword: Some(entry.keyword.clone()),
                        iana_description: Some(entry.description.clone()),
                        status: DispatchStatus::Confirmed,
                    },
                    None => DispatchValidation {
                        protocol: protocol.to_string(),
                        dispatch_field: dispatch_type.to_string(),
                        value,
                        iana_keyword: None,
                        iana_description: None,
                        status: DispatchStatus::NotInRegistry,
                    },
                }
            }
            "dst_port" => {
                if self.service_ports.is_empty() {
                    return DispatchValidation {
                        protocol: protocol.to_string(),
                        dispatch_field: dispatch_type.to_string(),
                        value,
                        iana_keyword: None,
                        iana_description: None,
                        status: DispatchStatus::NoRegistry,
                    };
                }
                // Try TCP first, then UDP
                let entry = self
                    .lookup_service_port(value, "tcp")
                    .or_else(|| self.lookup_service_port(value, "udp"));
                match entry {
                    Some(svc) => DispatchValidation {
                        protocol: protocol.to_string(),
                        dispatch_field: dispatch_type.to_string(),
                        value,
                        iana_keyword: Some(svc.name.clone()),
                        iana_description: Some(svc.description.clone()),
                        status: DispatchStatus::Confirmed,
                    },
                    None => DispatchValidation {
                        protocol: protocol.to_string(),
                        dispatch_field: dispatch_type.to_string(),
                        value,
                        iana_keyword: None,
                        iana_description: None,
                        status: DispatchStatus::NotInRegistry,
                    },
                }
            }
            _ => DispatchValidation {
                protocol: protocol.to_string(),
                dispatch_field: dispatch_type.to_string(),
                value,
                iana_keyword: None,
                iana_description: None,
                status: DispatchStatus::NoRegistry,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_dispatch_no_registry() {
        let reg = IanaRegistries::default();
        let v = reg.validate_dispatch("IPv4", "protocol", 6);
        assert!(matches!(v.status, DispatchStatus::NoRegistry));
    }

    #[test]
    fn test_validate_protocol_number() {
        let mut reg = IanaRegistries::default();
        reg.protocol_numbers.insert(
            6,
            ProtocolNumber {
                number: 6,
                keyword: "TCP".to_string(),
                description: "Transmission Control".to_string(),
            },
        );
        let v = reg.validate_dispatch("IPv4", "protocol", 6);
        assert!(matches!(v.status, DispatchStatus::Confirmed));
        assert_eq!(v.iana_keyword, Some("TCP".to_string()));
    }

    #[test]
    fn test_validate_ethertype() {
        let mut reg = IanaRegistries::default();
        reg.ethertypes.insert(
            0x0800,
            EtherTypeEntry {
                ethertype: 0x0800,
                hex: "0x0800".to_string(),
                description: "Internet Protocol version 4".to_string(),
            },
        );
        let v = reg.validate_dispatch("Ethernet", "ether_type", 0x0800);
        assert!(matches!(v.status, DispatchStatus::Confirmed));
    }

    #[test]
    fn test_validate_not_in_registry() {
        let mut reg = IanaRegistries::default();
        reg.protocol_numbers.insert(
            6,
            ProtocolNumber {
                number: 6,
                keyword: "TCP".to_string(),
                description: "Transmission Control".to_string(),
            },
        );
        let v = reg.validate_dispatch("IPv4", "protocol", 255);
        assert!(matches!(v.status, DispatchStatus::NotInRegistry));
    }

    #[test]
    fn test_validate_service_port() {
        let mut reg = IanaRegistries::default();
        reg.service_ports.insert(
            "53/udp".to_string(),
            ServicePort {
                name: "domain".to_string(),
                port: 53,
                protocol: "udp".to_string(),
                description: "Domain Name Server".to_string(),
            },
        );
        let v = reg.validate_dispatch("UDP", "dst_port", 53);
        assert!(matches!(v.status, DispatchStatus::Confirmed));
        assert_eq!(v.iana_keyword, Some("domain".to_string()));
    }
}
