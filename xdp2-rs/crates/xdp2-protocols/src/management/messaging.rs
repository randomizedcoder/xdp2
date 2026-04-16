//! Messaging / Middleware protocol definitions.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// MQTT header (2 bytes). Reimplements: `struct mqtt_hdr` in `proto_mqtt.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct MqttHeader {
    pub type_flags: u8,
    pub remaining_len: u8,
}
pub struct MqttOps;
impl ProtocolOps for MqttOps {
    const MIN_LEN: usize = 2;
    const NAME: &'static str = "MQTT";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
}

/// AMQP header (8 bytes). Reimplements: `struct amqp_hdr` in `proto_amqp.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct AmqpHeader {
    pub literal: [u8; 4],
    pub proto_id: u8,
    pub major: u8,
    pub minor: u8,
    pub revision: u8,
}
pub struct AmqpOps;
impl ProtocolOps for AmqpOps {
    const MIN_LEN: usize = 8;
    const NAME: &'static str = "AMQP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
}

/// Kafka header (12 bytes). Reimplements: `struct kafka_hdr` in `proto_kafka.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct KafkaHeader {
    pub length: [u8; 4],
    pub api_key: [u8; 2],
    pub api_version: [u8; 2],
    pub correlation_id: [u8; 4],
}
pub struct KafkaOps;
impl ProtocolOps for KafkaOps {
    const MIN_LEN: usize = 12;
    const NAME: &'static str = "Kafka";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
}

/// Redis header (1 byte marker). Reimplements: `struct redis_hdr` in `proto_redis.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct RedisHeader { pub marker: u8 }
pub struct RedisOps;
impl ProtocolOps for RedisOps {
    const MIN_LEN: usize = 1;
    const NAME: &'static str = "Redis";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
}

/// Memcache header (24 bytes). Reimplements: `struct memcache_hdr` in `proto_memcache.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct MemcacheHeader {
    pub magic: u8,
    pub opcode: u8,
    pub key_len: [u8; 2],
    pub extras_len: u8,
    pub data_type: u8,
    pub status: [u8; 2],
    pub total_body_len: [u8; 4],
    pub opaque: [u8; 4],
    pub cas: [u8; 8],
}
pub struct MemcacheOps;
impl ProtocolOps for MemcacheOps {
    const MIN_LEN: usize = 24;
    const NAME: &'static str = "Memcache";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
}

/// ZeroMQ header (1 byte marker). Reimplements: `struct zeromq_hdr` in `proto_zeromq.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct ZeromqHeader { pub marker: u8 }
pub struct ZeromqOps;
impl ProtocolOps for ZeromqOps {
    const MIN_LEN: usize = 1;
    const NAME: &'static str = "ZeroMQ";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mqtt_is_leaf() {
        assert!(matches!(MqttOps.next_proto(&[0u8; 2]), Err(ParseError::UnknownProto)));
    }

    #[test]
    fn kafka_is_leaf() {
        assert!(matches!(KafkaOps.next_proto(&[0u8; 12]), Err(ParseError::UnknownProto)));
    }
}
