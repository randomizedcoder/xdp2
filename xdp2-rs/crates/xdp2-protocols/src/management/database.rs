//! Database protocol leaf definitions.

use xdp2_core::{ParseError, ProtocolOps};

/// MySQL protocol operations (leaf, MIN_LEN = 4).
pub struct MysqlOps;
impl ProtocolOps for MysqlOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "MySQL";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// PostgreSQL protocol operations (leaf, MIN_LEN = 5).
pub struct PostgresqlOps;
impl ProtocolOps for PostgresqlOps {
    const MIN_LEN: usize = 5;
    const NAME: &'static str = "PostgreSQL";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// MongoDB protocol operations (leaf, MIN_LEN = 16).
pub struct MongodbOps;
impl ProtocolOps for MongodbOps {
    const MIN_LEN: usize = 16;
    const NAME: &'static str = "MongoDB";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// Cassandra protocol operations (leaf, MIN_LEN = 9).
pub struct CassandraOps;
impl ProtocolOps for CassandraOps {
    const MIN_LEN: usize = 9;
    const NAME: &'static str = "Cassandra";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// Elasticsearch protocol operations (leaf, MIN_LEN = 4).
pub struct ElasticsearchOps;
impl ProtocolOps for ElasticsearchOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "Elasticsearch";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}
