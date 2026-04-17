//! xdp2-bench library — exports parser modules for fuzzing and testing.

pub mod flow_meta;
pub mod extractors;
pub mod graph;
pub mod graph_compiled;
pub mod graph_mono;
pub mod nodes;
pub mod template;
pub mod template_plain;
pub mod template_vlan;
pub mod template_qinq;
pub mod template_gre;
pub mod template_ipip;
pub mod simd_batch;
pub mod template_simd;
pub mod pcap;
