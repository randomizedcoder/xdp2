#!/usr/bin/env -S cargo +stable -Zscript
//! Generate seed corpus files for cargo-fuzz targets.
//! Run: cargo run --manifest-path fuzz/generate_seeds.rs
//! Or just: rustc fuzz/generate_seeds.rs -o /tmp/gen && /tmp/gen

fn main() {
    // Inline the seed generation to avoid dependency issues with the script runner.
    // These match xdp2_fuzz::seed_corpus::generate_seeds().
    let seeds: Vec<(&str, Vec<u8>)> = vec![
        ("empty", vec![]),
        ("one_byte", vec![0x42]),
        ("all_zeros_64", vec![0u8; 64]),
        ("all_ones_64", vec![0xFFu8; 64]),
        ("all_zeros_1500", vec![0u8; 1500]),
        ("all_ones_1500", vec![0xFFu8; 1500]),
        // Minimal Eth + IPv4 + TCP
        ("eth_ipv4_tcp", {
            let mut p = vec![0u8; 54];
            p[12] = 0x08; // ethertype = 0x0800
            p[14] = 0x45; // IPv4, IHL=5
            p[16] = 0x00; p[17] = 0x28; // total_len=40
            p[23] = 6;    // protocol=TCP
            p[26] = 10; p[30] = 10; p[33] = 2; // src/dst IPs
            p[46] = 0x50; // TCP doff=5
            p
        }),
        // Minimal Eth + IPv4 + UDP
        ("eth_ipv4_udp", {
            let mut p = vec![0u8; 42];
            p[12] = 0x08;
            p[14] = 0x45;
            p[16] = 0x00; p[17] = 0x1C; // total_len=28
            p[23] = 17;   // protocol=UDP
            p[26] = 10; p[30] = 10; p[33] = 2;
            p[38] = 0x00; p[39] = 0x08; // UDP len=8
            p
        }),
        // Minimal ARP
        ("eth_arp", {
            let mut p = vec![0u8; 42];
            p[12] = 0x08; p[13] = 0x06;
            p[14] = 0x00; p[15] = 0x01; // hw=ethernet
            p[16] = 0x08; p[17] = 0x00; // proto=IPv4
            p[18] = 6; p[19] = 4;       // hw_len, proto_len
            p[20] = 0x00; p[21] = 0x01; // op=request
            p
        }),
    ];

    let dir = "fuzz/corpus/seed_packets";
    std::fs::create_dir_all(dir).unwrap();
    for (name, data) in &seeds {
        let path = format!("{}/{}", dir, name);
        std::fs::write(&path, data).unwrap();
        println!("Wrote {} ({} bytes)", path, data.len());
    }
}
