//! Industrial / Control protocol definitions.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// Modbus TCP header (7 bytes). Reimplements: `struct modbus_tcp_hdr` in `proto_modbus.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct ModbusHeader {
    pub transaction_id: [u8; 2],
    pub protocol_id: [u8; 2],
    pub length: [u8; 2],
    pub unit_id: u8,
}
pub struct ModbusOps;
impl ProtocolOps for ModbusOps {
    const MIN_LEN: usize = 7;
    const NAME: &'static str = "Modbus";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
}

/// Profinet header (2 bytes). Reimplements: `struct profinet_hdr` in `proto_profinet.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct ProfinetHeader {
    pub frame_id: [u8; 2],
}
pub struct ProfinetOps;
impl ProtocolOps for ProfinetOps {
    const MIN_LEN: usize = 2;
    const NAME: &'static str = "Profinet";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
}

/// CoAP header (4 bytes). Reimplements: `struct coap_hdr` in `proto_coap.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct CoapHeader {
    pub ver_type_tkl: u8,
    pub code: u8,
    pub message_id: [u8; 2],
}
pub struct CoapOps;
impl ProtocolOps for CoapOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "CoAP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
}

/// DNP3 header (10 bytes). Reimplements: `struct dnp3_hdr` in `proto_dnp3.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct Dnp3Header {
    pub start: [u8; 2],
    pub length: u8,
    pub control: u8,
    pub dest: [u8; 2],
    pub src: [u8; 2],
    pub crc: [u8; 2],
}
pub struct Dnp3Ops;
impl ProtocolOps for Dnp3Ops {
    const MIN_LEN: usize = 10;
    const NAME: &'static str = "DNP3";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
}

/// BACnet header (4 bytes). Reimplements: `struct bacnet_hdr` in `proto_bacnet.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct BacnetHeader {
    pub type_flags: u8,
    pub reserved: u8,
    pub length: [u8; 2],
}
pub struct BacnetOps;
impl ProtocolOps for BacnetOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "BACnet";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
}

/// CIP header (2 bytes). Reimplements: `struct cip_hdr` in `proto_cip.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct CipHeader {
    pub service: u8,
    pub path_size: u8,
}
pub struct CipOps;
impl ProtocolOps for CipOps {
    const MIN_LEN: usize = 2;
    const NAME: &'static str = "CIP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
}

/// IEC GOOSE header (8 bytes). Reimplements: `struct iec_goose_hdr` in `proto_iec_goose.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct IecGooseHeader {
    pub appid: [u8; 2],
    pub length: [u8; 2],
    pub reserved1: [u8; 2],
    pub reserved2: [u8; 2],
}
pub struct IecGooseOps;
impl ProtocolOps for IecGooseOps {
    const MIN_LEN: usize = 8;
    const NAME: &'static str = "IEC GOOSE";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
}

/// IEC SV header (8 bytes). Reimplements: `struct iec_sv_hdr` in `proto_iec_sv.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct IecSvHeader {
    pub appid: [u8; 2],
    pub length: [u8; 2],
    pub reserved1: [u8; 2],
    pub reserved2: [u8; 2],
}
pub struct IecSvOps;
impl ProtocolOps for IecSvOps {
    const MIN_LEN: usize = 8;
    const NAME: &'static str = "IEC SV";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
}

/// IEC MMS header (2 bytes). Reimplements: `struct iec_mms_hdr` in `proto_iec_mms.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct IecMmsHeader {
    pub tag: u8,
    pub length: u8,
}
pub struct IecMmsOps;
impl ProtocolOps for IecMmsOps {
    const MIN_LEN: usize = 2;
    const NAME: &'static str = "IEC MMS";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
}

/// EtherNet/IP header (24 bytes). Reimplements: `struct enip_hdr` in `proto_enip.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct EnipHeader {
    pub command: [u8; 2],
    pub length: [u8; 2],
    pub session_handle: [u8; 4],
    pub status: [u8; 4],
    pub sender_context: [u8; 8],
    pub options: [u8; 4],
}
pub struct EnipOps;
impl ProtocolOps for EnipOps {
    const MIN_LEN: usize = 24;
    const NAME: &'static str = "EtherNet/IP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modbus_is_leaf() {
        assert!(matches!(ModbusOps.next_proto(&[0u8; 7]), Err(ParseError::UnknownProto)));
    }
}
