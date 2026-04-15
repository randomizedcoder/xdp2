<img src="../images/xdp2-big.png" alt="XDP2 logo"/>

# XDP2: A Lecture Series on Parse-Graph-Based Packet Processing

This document describes the design and implementation of XDP2 in enough detail
that a reader could reimplement it from scratch. It is structured as a series
of twelve lectures (0--11), each covering one major phase or topic. The intended
audience is third-year computer science students with background in C, data
structures, and basic networking (OSI model, Ethernet, IP, TCP/UDP). Lectures
9 and 10 cover porting XDP2 from C/C++ to Rust. Lecture 11 covers
measurement-driven performance optimization of the Rust implementation.

## Table of Contents

| Lecture | Topic |
|---------|-------|
| [Lecture 0](lecture00-xdp2-overview.md) | Orientation and Motivation |
| [Lecture 1](lecture01-protocol-definitions.md) | Protocol Definitions -- The Vocabulary of Parsing |
| [Lecture 2](lecture02-parse-graph.md) | Parse Nodes, Protocol Tables, and Parsers -- Building the Graph |
| [Lecture 3](lecture03-runtime-engine.md) | The Runtime Parsing Engine -- Walking the Graph |
| [Lecture 4](lecture04-metadata-extraction.md) | Metadata Extraction and Advanced Node Types |
| [Lecture 5](lecture05-compiler.md) | The Optimizing Compiler -- From Graph to Linear Code |
| [Lecture 6](lecture06-xdp-ebpf.md) | The XDP/eBPF Target -- Kernel-Space Parsing |
| [Lecture 7](lecture07-worked-examples.md) | Worked Examples -- Packets Walking the Parse Graph |
| [Lecture 8](lecture08-testing.md) | Testing and Clean-Room Reimplementation Guide |
| [Lecture 9](lecture09-rust-runtime.md) | Porting the Runtime -- C to Rust |
| [Lecture 10](lecture10-rust-compiler.md) | Porting the Compiler and XDP Target -- C++ to Rust |
| [Lecture 11](lecture11-performance.md) | High-Performance Parsing -- From 158 ns/pkt to 2 ns/pkt |

---

*XDP2 is developed by Tom Herbert and contributors. BSD-2-Clause-FreeBSD
license. Contact: xdp2@lists.linux.dev*
