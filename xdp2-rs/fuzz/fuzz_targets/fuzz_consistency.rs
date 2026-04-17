#![no_main]
use libfuzzer_sys::fuzz_target;
use xdp2_bench::flow_meta::FlowMeta;
use xdp2_bench::graph;
use xdp2_core::Parser;
use xdp2_fuzz::oracle;

thread_local! {
    static PARSER: Parser<FlowMeta> = graph::make_parser();
}

fuzz_target!(|data: &[u8]| {
    PARSER.with(|parser| {
        oracle::assert_oracle(parser, data);
    });
});
