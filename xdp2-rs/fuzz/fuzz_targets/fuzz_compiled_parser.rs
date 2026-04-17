#![no_main]
use libfuzzer_sys::fuzz_target;
use xdp2_bench::flow_meta::FlowMeta;
use xdp2_bench::graph_compiled;

fuzz_target!(|data: &[u8]| {
    let mut meta = FlowMeta::default();
    let _ = graph_compiled::parse_packet(data, &mut meta);
});
