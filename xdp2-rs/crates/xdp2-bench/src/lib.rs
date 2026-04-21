//! xdp2-bench library — exports parser modules for fuzzing and testing.

pub mod extractors;
pub mod flow_meta;
pub mod graph;
pub mod graph_compiled;
#[cfg(feature = "graph-enum")]
pub mod graph_enum;
pub mod graph_mono;
pub mod nodes;
pub mod pcap;
pub mod simd_batch;
pub mod template;
pub mod template_gre;
pub mod template_ipip;
pub mod template_plain;
pub mod template_qinq;
pub mod template_simd;
pub mod template_vlan;
