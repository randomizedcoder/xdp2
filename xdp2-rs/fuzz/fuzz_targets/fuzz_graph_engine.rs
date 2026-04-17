#![no_main]
use libfuzzer_sys::fuzz_target;
use xdp2_bench::flow_meta::FlowMeta;
use xdp2_bench::graph;
use xdp2_core::Parser;

thread_local! {
    static PARSER: Parser<FlowMeta> = graph::make_parser();
}

fuzz_target!(|data: &[u8]| {
    PARSER.with(|parser| {
        let _ = graph::parse_packet(parser, data);
    });
});
