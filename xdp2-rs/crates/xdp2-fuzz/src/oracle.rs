//! Cross-mode consistency oracle.
//!
//! Runs the same packet through all parser modes and checks for divergence.
//! Any disagreement between modes is a bug — they should produce identical
//! results for identical input.

use xdp2_bench::flow_meta::FlowMeta;
use xdp2_bench::graph;
use xdp2_bench::graph_compiled;
use xdp2_bench::graph_mono;
use xdp2_core::{ParseError, Parser};

/// Result of running one packet through all parser modes.
#[derive(Debug)]
pub struct OracleResult {
    /// Graph engine: Ok(FlowMeta) or Err(ParseError)
    pub graph: Result<FlowMeta, ParseError>,
    /// Mono parser: Ok(FlowMeta) or Err(ParseError)
    pub mono: Result<FlowMeta, ParseError>,
    /// Compiled parser: Ok(FlowMeta) or Err(ParseError)
    pub compiled: Result<FlowMeta, ParseError>,
    /// Whether all modes agree on success/failure and metadata
    pub consistent: bool,
}

/// Run one packet through all 3 parser modes and compare results.
///
/// The graph engine returns `ParseOutput<FlowMeta>` (with control data);
/// mono and compiled return `Result<(), ParseError>` + separately populated
/// `&mut FlowMeta`. This function normalizes both to `Result<FlowMeta, ParseError>`.
pub fn run_oracle(parser: &Parser<FlowMeta>, pkt: &[u8]) -> OracleResult {
    // Graph engine
    let graph = match graph::parse_packet(parser, pkt) {
        Ok(output) => Ok(output.metadata),
        Err(e) => Err(e),
    };

    // Mono parser
    let mono = {
        let mut meta = FlowMeta::default();
        match graph_mono::parse_packet_mono(pkt, &mut meta) {
            Ok(()) => Ok(meta),
            Err(e) => Err(e),
        }
    };

    // Compiled parser
    let compiled = {
        let mut meta = FlowMeta::default();
        match graph_compiled::parse_packet(pkt, &mut meta) {
            Ok(()) => Ok(meta),
            Err(e) => Err(e),
        }
    };

    // Check consistency
    let consistent = check_consistency(&graph, &mono, &compiled);

    OracleResult { graph, mono, compiled, consistent }
}

/// Check whether all 3 results agree.
///
/// Agreement means:
/// - All succeed or all fail (we allow different error variants since the
///   engines may detect different errors first for the same malformed packet)
/// - On success: FlowMeta fields are identical
fn check_consistency(
    graph: &Result<FlowMeta, ParseError>,
    mono: &Result<FlowMeta, ParseError>,
    compiled: &Result<FlowMeta, ParseError>,
) -> bool {
    match (graph, mono, compiled) {
        // All succeed: compare metadata
        (Ok(g), Ok(m), Ok(c)) => g == m && m == c,
        // All fail: consistent (different error codes are acceptable)
        (Err(_), Err(_), Err(_)) => true,
        // Mixed success/failure: inconsistent
        _ => false,
    }
}

/// Assert oracle consistency, panicking with a detailed message on failure.
///
/// Use this in fuzz targets: `assert_oracle(parser, data)`.
pub fn assert_oracle(parser: &Parser<FlowMeta>, pkt: &[u8]) {
    let result = run_oracle(parser, pkt);
    if !result.consistent {
        panic!(
            "Oracle inconsistency for {}-byte packet!\n\
             Graph:    {:?}\n\
             Mono:     {:?}\n\
             Compiled: {:?}",
            pkt.len(),
            result.graph.as_ref().map(|_| "Ok(...)").unwrap_or("Err(...)"),
            result.mono.as_ref().map(|_| "Ok(...)").unwrap_or("Err(...)"),
            result.compiled.as_ref().map(|_| "Ok(...)").unwrap_or("Err(...)"),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parser() -> Parser<FlowMeta> {
        graph::make_parser()
    }

    #[test]
    fn oracle_empty_packet() {
        let result = run_oracle(&parser(), &[]);
        assert!(result.consistent);
        assert!(result.graph.is_err());
        assert!(result.mono.is_err());
        assert!(result.compiled.is_err());
    }

    #[test]
    fn oracle_valid_ipv4_tcp() {
        // Eth(IPv4) + IPv4(TCP) + TCP
        #[rustfmt::skip]
        let pkt = [
            // Ethernet: dst, src, ethertype=0x0800
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,
            0x08, 0x00,
            // IPv4: ver=4, ihl=5, tot_len=40, proto=6(TCP)
            0x45, 0x00, 0x00, 0x28,
            0x00, 0x01, 0x00, 0x00,
            0x40, 0x06, 0x00, 0x00,
            0x0A, 0x00, 0x00, 0x01, // src 10.0.0.1
            0x0A, 0x00, 0x00, 0x02, // dst 10.0.0.2
            // TCP: src=80, dst=12345, doff=5
            0x00, 0x50, 0x30, 0x39,
            0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00,
            0x50, 0x02, 0x20, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];
        let result = run_oracle(&parser(), &pkt);
        assert!(result.consistent, "Oracle divergence on valid IPv4/TCP packet");
        assert!(result.graph.is_ok());
    }

    #[test]
    fn oracle_truncated_packet() {
        // Valid Ethernet header but truncated IPv4
        let pkt = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,
            0x08, 0x00,
            0x45, 0x00, // only 2 bytes of IPv4
        ];
        let result = run_oracle(&parser(), &pkt);
        assert!(result.consistent, "Oracle divergence on truncated packet");
    }

    #[test]
    fn oracle_all_zeros() {
        let pkt = [0u8; 64];
        let result = run_oracle(&parser(), &pkt);
        assert!(result.consistent, "Oracle divergence on all-zero packet");
    }

    #[test]
    fn oracle_all_ones() {
        let pkt = [0xFFu8; 64];
        let result = run_oracle(&parser(), &pkt);
        assert!(result.consistent, "Oracle divergence on all-0xFF packet");
    }

    #[test]
    fn oracle_single_byte() {
        for b in 0..=255u8 {
            let pkt = [b];
            let result = run_oracle(&parser(), &[b]);
            assert!(result.consistent, "Oracle divergence on single byte {:#04x}", b);
            assert!(result.graph.is_err());
            let _ = pkt;
        }
    }
}
