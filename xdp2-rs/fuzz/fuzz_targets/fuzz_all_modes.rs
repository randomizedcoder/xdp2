#![no_main]
//! Fuzz all parser modes independently (no consistency check).
//! Asserts: no panics for any input across graph, mono, compiled, and templates.
use libfuzzer_sys::fuzz_target;
use xdp2_bench::flow_meta::FlowMeta;
use xdp2_bench::graph;
use xdp2_bench::graph_compiled;
use xdp2_bench::graph_mono;
use xdp2_bench::template;
use xdp2_core::Parser;

thread_local! {
    static PARSER: Parser<FlowMeta> = graph::make_parser();
}

fuzz_target!(|data: &[u8]| {
    // Graph engine
    PARSER.with(|parser| {
        let _ = graph::parse_packet(parser, data);
    });

    // Mono parser
    {
        let mut meta = FlowMeta::default();
        let _ = graph_mono::parse_packet_mono(data, &mut meta);
    }

    // Compiled parser
    {
        let mut meta = FlowMeta::default();
        let _ = graph_compiled::parse_packet(data, &mut meta);
    }

    // Template: classify and extract if a template matches
    if let Some(id) = template::select_template_id(data) {
        let mut meta = FlowMeta::default();
        let _ = template::extract_by_id(data, id, &mut meta);
    }
});
