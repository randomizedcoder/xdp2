//! Security protocol family.
//!
//! ## C/C++ Cross-Reference
//! Source directory: `src/include/xdp2/proto_defs/security/`

pub mod ah;
pub mod misc;

pub use ah::{AhHeader, AhOps};
pub use misc::{
    DtlsHeader, DtlsOps, EapHeader, EapOps, EapolHeader, EapolOps, EspHeader, EspOps,
    Ikev2Header, Ikev2Ops, KerberosHeader, KerberosOps, MacsecHeader, MacsecOps, NtlmsspHeader,
    NtlmsspOps, OcspHeader, OcspOps, SshHeader, SshOps, TacacsHeader, TacacsOps, TlsHeader,
    TlsOps, WireguardHeader, WireguardOps,
};
