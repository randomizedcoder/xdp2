# Step 7: AF_XDP Integration Plan

Feed the Rust parser at line rate from a real NIC, bypassing the kernel
networking stack entirely.  AF_XDP (Address Family XDP) provides zero-copy
packet delivery from NIC → userspace via shared memory (UMEM), with the
XDP program acting as a fast-path classifier that decides which packets
to redirect.

This document describes the architecture, how it builds on the existing
XDP sample infrastructure, the implementation plan, and how to test in
software (microvms) before hardware arrives.

## At a Glance

```
  ┌──────────┐   XDP_REDIRECT    ┌──────────┐    mmap'd     ┌─────────────┐
  │   NIC    │ ─────────────────▶ │ XSKMAP   │ ──────────── │  Rust       │
  │ (X710)   │   bpf_redirect_map│ (AF_XDP)  │   UMEM ring  │  Parser     │
  └──────────┘                    └──────────┘    buffers     │ (compiled/  │
       │                                │                     │  template)  │
       │  XDP program                   │                     └─────────────┘
       │  classifies packet,            │
       │  optionally extracts           ▼
       │  metadata, then              RX ring
       │  redirects to XSKMAP        descriptors
       │                              (offset,len)
       ▼
  Other packets → XDP_PASS → kernel stack (normal path)
```

**Key property:** Packets in the UMEM are contiguous fixed-size frames
(typically 2048 or 4096 bytes), laid out at predictable offsets.  This is
exactly the memory layout the batch SIMD template extractor (Step 12d)
needs — gather indices become simple arithmetic rather than scattered
pointers.

## Current XDP Infrastructure

### Existing Samples

XDP2 already has four XDP flow tracker samples in `samples/xdp/`:

| Sample | Description | Key Feature |
|--------|-------------|-------------|
| `flow_tracker_simple` | Minimal XDP 5-tuple tracker | Basic parse graph invocation |
| `flow_tracker_combo` | Full-featured tracker + userspace parser | Reusable parser in kernel + userspace |
| `flow_tracker_tlvs` | TLV field extraction (TCP options, etc.) | Variable-length field parsing |
| `flow_tracker_tmpl` | Template macro variant | Cleanest — uses `XDP2_XDP_MAKE_PARSER_PROGRAM` |

All use XDP_PASS (packets continue to kernel stack).  None use
XDP_REDIRECT or AF_XDP — that is the gap this step fills.

### How the Existing XDP Programs Work

The `flow_tracker_combo` sample (`samples/xdp/flow_tracker_combo/`) is the
most complete reference:

**Kernel side** (`flow_tracker.xdp.c`):
1. XDP program entry receives `xdp_md` (packet pointer + length)
2. `XDP2_XDP_MAKE_PARSER_PROGRAM` macro generates parser + tail-call chain
3. Parser extracts metadata into `xdp2_metadata_all` (232 bytes):
   - IP addresses (v4/v6), ports, protocol, fragment info, TCP options
4. Custom `flow_track()` callback updates a BPF hash map (5-tuple → counter)
5. Returns `XDP_PASS`

**Maps created by the template** (`xdp_tmpl.h`):
- `ctx_map`: `BPF_MAP_TYPE_PERCPU_ARRAY` — per-CPU parser state (232B)
- `parsers`: `BPF_MAP_TYPE_PROG_ARRAY` — tail-call dispatch for complex headers
- `flowtracker`: `BPF_MAP_TYPE_HASH` — 5-tuple flow counters

**Userspace side** (`flow_parser.c`):
- Reads PCAP files via `xdp2_pcap_readpkt()`
- Calls `xdp2_parse()` with same parser definition → identical metadata extraction
- Prints extracted addresses, ports, TCP options

**Build** (`Makefile`):
```
xdp2-compiler -I$(INCDIR) -i parser.c -o parser.xdp.h   # BPF header
clang -target bpf -c flow_tracker.xdp.c                  # BPF bytecode
gcc -c flow_parser.c                                      # Userspace binary
```

### Microvm Test Infrastructure

VMs are defined in `nix/microvms/` with:
- **Architectures:** x86_64 (KVM), aarch64 (QEMU TCG), riscv64 (QEMU TCG)
- **Networking:** QEMU user-mode NAT (`-netdev user`) on virtio eth0
- **Consoles:** Serial (23500+) and virtio (23501+) via TCP sockets
- **Automation:** Expect scripts for command execution and service verification
- **Lifecycle:** Build → boot → verify BPF → verify XDP → shutdown

Current limitation: user-mode networking does not support raw packet
injection from host.  AF_XDP testing will need TAP device bridging
(see Testing section).

---

## Architecture: AF_XDP Parser Feed

### New Sample: `af_xdp_parser`

A new sample that combines:
1. **Kernel XDP program** — classifies packets and redirects to AF_XDP
2. **Rust userspace reader** — reads from XSKMAP, feeds the Rust parser

```
samples/
  xdp/
    af_xdp_parser/          ← NEW
      parser.c              # Parser definition (reuse from flow_tracker_combo)
      af_xdp_parser.xdp.c  # Kernel XDP: classify + XDP_REDIRECT to XSKMAP
      Makefile              # Build BPF bytecode
```

```
xdp2-rs/
  crates/
    xdp2-af-xdp/           ← NEW crate
      src/
        lib.rs              # AF_XDP socket setup, UMEM management, ring ops
        umem.rs             # UMEM allocation and frame management
        socket.rs           # XSK socket creation and binding
        rx.rs               # RX ring consumer (packet reader)
    xdp2-bench/
      src/
        af_xdp.rs           ← NEW module (--mode af-xdp benchmark)
```

### Kernel XDP Program

Based on `flow_tracker_tmpl` with two key changes:

1. **Add XSKMAP** for AF_XDP socket binding:
```c
struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);       // one per RX queue
    __type(key, __u32);
    __type(value, __u32);          // XSK file descriptor
} xsks_map SEC(".maps");
```

2. **Replace XDP_PASS with XDP_REDIRECT**:
```c
static int process_packet(struct xdp_md *ctx,
                          struct xdp2_metadata_all *meta) {
    // Optionally: store extracted metadata in XDP metadata area
    // (bpf_xdp_adjust_meta) for userspace to read without re-parsing

    // Redirect to AF_XDP socket bound to this RX queue
    return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, XDP_PASS);
    // Fallback: XDP_PASS if no socket bound to this queue
}
```

**Optional optimization:** The XDP program can write extracted metadata
(5-tuple, offsets) into the XDP metadata area via `bpf_xdp_adjust_meta()`.
Userspace reads this pre-extracted data instead of re-parsing — combining
kernel-side classification with userspace template extraction.

### Rust AF_XDP Userspace

**Crate: `xdp2-af-xdp`**

Core abstraction: UMEM + XSK socket lifecycle.

```rust
/// A UMEM region: contiguous mmap'd memory shared between kernel and userspace.
pub struct Umem {
    area: *mut u8,
    frame_size: usize,   // 2048 or 4096
    frame_count: usize,
    fill_ring: FillRing,
    comp_ring: CompRing,
}

/// An AF_XDP socket bound to one (ifindex, queue_id) pair.
pub struct XskSocket {
    fd: RawFd,
    rx_ring: RxRing,
    tx_ring: TxRing,  // for TX path, not needed initially
    umem: Arc<Umem>,
}

/// Read a batch of packets from the RX ring.
/// Returns slice descriptors (offset into UMEM + length).
pub fn recv_batch(&mut self, batch: &mut [RxDesc], max: usize) -> usize;

/// Return frames to the fill ring after processing.
pub fn release_frames(&mut self, frames: &[u64]);
```

**Dependency options:**
- **`libbpf-rs`** — most mature, official libbpf bindings, includes XSK helpers
- **`aya`** — pure Rust eBPF framework, growing AF_XDP support
- **Raw syscalls** — `socket(AF_XDP, SOCK_RAW, 0)` + `setsockopt` + `mmap` directly

Recommendation: start with `libbpf-rs` for XSK helpers, since the kernel
XDP program is already compiled via clang (not aya's Rust-native BPF).

### Parser Integration

The key connection: UMEM frames are contiguous, fixed-size buffers at
predictable addresses.  Each frame starts at `umem_base + frame_idx * frame_size`.

```rust
fn process_batch(xsk: &mut XskSocket, parser: &PacketTemplate) {
    let mut descs = [RxDesc::default(); 64];
    let n = xsk.recv_batch(&mut descs, 64);

    for desc in &descs[..n] {
        let pkt = unsafe {
            std::slice::from_raw_parts(
                xsk.umem_ptr().add(desc.addr as usize),
                desc.len as usize,
            )
        };

        // Template extraction — all offsets are compile-time constants
        if let Ok(metadata) = template::extract_eth_ipv4_tcp(pkt) {
            // Process metadata...
        }
    }

    xsk.release_frames(&descs[..n].iter().map(|d| d.addr).collect::<Vec<_>>());
}
```

**Batch SIMD opportunity (Step 12d):** Because UMEM frames are contiguous
and fixed-size, gather indices for 8 packets are:
```
base + desc[0].addr + field_offset
base + desc[1].addr + field_offset
...
base + desc[7].addr + field_offset
```
With fixed `frame_size`, this becomes `base + (start + i * frame_size) + offset`
— a single `vpgatherdd` with scale factor, far more efficient than the
scattered-pointer gathers in the current `simd_batch.rs`.

---

## NIC Queue Steering and Template Selection

When combined with ntuple filters (Step 12e-f), the full pipeline is:

```
  NIC (X710, i40e driver)
    │
    │  ethtool -N eth0 flow-type tcp4 action 0    → Queue 0 = Eth/IPv4/TCP
    │  ethtool -N eth0 flow-type udp4 action 1    → Queue 1 = Eth/IPv4/UDP
    │  ethtool -N eth0 flow-type tcp6 action 2    → Queue 2 = Eth/IPv6/TCP
    │
    ▼
  XDP program
    │  classify + XDP_REDIRECT to XSKMAP[queue_index]
    ▼
  AF_XDP socket (per queue)
    │  UMEM frame → known template (queue determines type)
    ▼
  Rust template extractor
    │  One bounds check + fixed-offset reads
    │  No branches, no graph walk
    ▼
  Application logic
```

Each AF_XDP socket binds to one queue.  The queue number selects the
template.  Zero runtime classification in userspace.

---

## Implementation Steps

### Phase 1: AF_XDP Foundation (software, microvms)

| Step | Description | Deliverable |
|------|-------------|-------------|
| 7a | Create `xdp2-af-xdp` crate with UMEM + XSK socket abstractions | `crates/xdp2-af-xdp/` |
| 7b | Create `af_xdp_parser` XDP sample (XSKMAP + XDP_REDIRECT) | `samples/xdp/af_xdp_parser/` |
| 7c | Nix build target for new sample | `nix/xdp-samples.nix` update |
| 7d | Basic loopback test: XDP → AF_XDP → Rust parser → stdout | Integration test |
| 7e | Microvm test with TAP networking + traffic injection | `nix/microvms/` update |

### Phase 2: Performance Integration

| Step | Description | Deliverable |
|------|-------------|-------------|
| 7f | `--mode af-xdp` in xdp2-bench (read from socket, time parsing) | bench integration |
| 7g | Multi-queue support (one XSK per queue, one thread per socket) | Parallel RX |
| 7h | Batch processing: read N frames, parse batch, release batch | Amortize syscall overhead |
| 7i | Connect template extraction (Step 12) — queue → template mapping | Template selector |

### Phase 3: Hardware Validation (X710)

| Step | Description | Deliverable |
|------|-------------|-------------|
| 7j | X710 setup: driver (i40e), firmware, AF_XDP native mode | Hardware bring-up |
| 7k | ntuple filter configuration (Step 12f) | `scripts/setup-queue-templates.sh` |
| 7l | Line-rate benchmark: traffic generator → X710 → AF_XDP → Rust parser | Production numbers |
| 7m | Multi-queue + multi-thread scaling test | Throughput ceiling |

---

## Testing Strategy

### Software Testing (Before Hardware)

**1. Loopback test (simplest):**
```bash
# Inside microvm or dev machine with root
ip link set dev lo xdpgeneric obj af_xdp_parser.xdp.o
# Rust AF_XDP reader binds to lo, queue 0
# Generate traffic: ping 127.0.0.1 or scapy
```

**2. veth pair test (more realistic):**
```bash
ip link add veth0 type veth peer name veth1
ip link set veth0 up
ip link set veth1 up
ip addr add 10.0.0.1/24 dev veth0
ip addr add 10.0.0.2/24 dev veth1

# Attach XDP to veth1
ip link set dev veth1 xdpgeneric obj af_xdp_parser.xdp.o

# Rust reader binds to veth1 AF_XDP socket
# Send traffic from veth0:
tcpreplay -i veth0 test.pcap
```

**3. Microvm test (automated, reproducible):**

Update VM networking from user-mode to TAP:
```nix
# In mkVm.nix — new option for AF_XDP-capable VMs
interfaces = [{
  type = "tap";
  id = "vm-eth0";
  mac = constants.tapConfig.mac;
}];
```

Host sends packets via the TAP interface; VM's XDP program redirects
to AF_XDP; Rust reader inside VM processes and reports results.

Add to lifecycle:
- Phase 3b: Load AF_XDP XDP program + bind XSK socket
- Phase 4b: Inject traffic from host via TAP, verify Rust parser output

### Hardware Testing (X710)

**NIC: Intel X710 (i40e driver)**
- AF_XDP native mode (zero-copy): `ethtool -K eth0 xdp on`
- ntuple filters: `ethtool -N eth0 flow-type tcp4 action 0`
- Flow Director: up to 8K rules, supports IHL=5 byte matching

**Traffic generator options:**
- **TRex** — DPDK-based, line-rate generation from a second machine
- **pktgen** (kernel) — single-machine loopback testing
- **tcpreplay** — PCAP replay at configurable rates
- **scapy** — low-rate scripted generation for correctness testing

**Benchmark protocol:**
1. Configure ntuple rules for target templates
2. Start Rust AF_XDP reader (one thread per queue)
3. Generate traffic at increasing rates
4. Measure: packets/sec received, parse latency, drop rate
5. Compare to PCAP-based benchmark numbers

---

## Rust AF_XDP Crate Design

### Dependencies

```toml
[dependencies]
libbpf-rs = "0.24"     # XSK helpers, BPF program loading
libbpf-sys = "1.4"     # Raw FFI for xsk_* functions
nix = { version = "0.29", features = ["socket", "mman"] }  # mmap, socket
```

### UMEM Layout

```
┌─────────────────────────────────────────────────────────┐
│                    UMEM (mmap'd)                        │
│                                                         │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐     ┌────────┐│
│  │ Frame 0  │ │ Frame 1  │ │ Frame 2  │ ... │Frame N ││
│  │ 4096B    │ │ 4096B    │ │ 4096B    │     │ 4096B  ││
│  │          │ │          │ │          │     │        ││
│  │ pkt data │ │ pkt data │ │ pkt data │     │pkt data││
│  │ + padding│ │ + padding│ │ + padding│     │+padding││
│  └──────────┘ └──────────┘ └──────────┘     └────────┘│
└─────────────────────────────────────────────────────────┘

Fill Ring:  userspace → kernel  (empty frames available for RX)
Comp Ring:  kernel → userspace  (frames TX'd, ready for reuse)
RX Ring:    kernel → userspace  (received packet descriptors)
TX Ring:    userspace → kernel  (packets to transmit)
```

Frame addresses are `frame_index * frame_size`.  With 4096-byte frames
and 8192 frames, UMEM is 32 MB — fits in L3 on most server CPUs.

### Ring Operations (Zero-Copy Path)

```rust
// Hot path: poll RX ring, process packets, refill
loop {
    // 1. Read batch from RX ring (kernel wrote descriptors)
    let n = xsk.rx_ring.peek(batch_size);
    for i in 0..n {
        let desc = xsk.rx_ring.desc(i);
        let pkt = umem.frame(desc.addr, desc.len);

        // 2. Parse with template extractor (all offsets constant)
        let result = template::extract_eth_ipv4_tcp(pkt);
        // ... application logic ...
    }
    xsk.rx_ring.release(n);

    // 3. Refill fill ring (return processed frames to kernel)
    let refill = xsk.fill_ring.available();
    for i in 0..refill.min(n) {
        xsk.fill_ring.push(recycled_addrs[i]);
    }
}
```

**Syscall amortization:** `recvfrom()` or `poll()` only needed when RX
ring is empty.  Busy-poll mode (`SO_PREFER_BUSY_POLL`) avoids syscalls
entirely on supported kernels.

---

## Relationship to Other Steps

| Step | Relationship |
|------|-------------|
| Step 9 (compiled parser) | AF_XDP feeds packets to the compiled parser — same parse function, different input source |
| Step 11 (batch SIMD) | UMEM contiguity enables efficient gathers — the scattered-pointer problem from simd_batch.rs disappears |
| Step 12a-c (template extraction) | AF_XDP queue number selects the template — zero runtime classification |
| Step 12d (batch template SIMD) | UMEM frames at predictable addresses → `vpgatherdd` with scale factor |
| Step 12e (queue-template binding) | Maps queue_index → PacketTemplate, driven by NIC ntuple rules |

---

## Open Questions

| Question | Notes |
|----------|-------|
| **libbpf-rs vs aya vs raw?** | libbpf-rs is most mature for XSK; aya is growing but XSK support is newer. Start with libbpf-rs, consider aya later for pure-Rust stack. |
| **XDP native vs generic mode?** | Native mode (zero-copy) requires driver support (i40e has it). Generic mode (`xdpgeneric`) works on any interface but adds a copy. Use generic for veth/loopback testing, native for X710. |
| **Frame size: 2048 vs 4096?** | 2048 saves memory and improves cache utilization for typical packets (<1500B). 4096 needed for jumbo frames. Start with 4096 for safety, optimize later. |
| **Busy-poll vs interrupt-driven?** | Busy-poll gives lowest latency but burns a core. Interrupt-driven is more efficient at low rates. Make configurable. |
| **XDP metadata area?** | `bpf_xdp_adjust_meta()` can prepend extracted metadata before the packet. Userspace reads metadata without re-parsing. Worth implementing for the template extraction path. |
| **Nix packaging of libbpf-rs?** | libbpf-rs depends on libbpf (C library) + libelf + zlib. Nix has all of these. May need `cargoHash` update and `nativeBuildInputs` additions. |

---

## References

- `samples/xdp/flow_tracker_combo/` — closest existing XDP sample (kernel + userspace)
- `samples/xdp/flow_tracker_tmpl/` — template macro variant (cleanest kernel code)
- `src/include/xdp2/xdp_tmpl.h` — `XDP2_XDP_MAKE_PARSER_PROGRAM` macro, map definitions
- `src/include/xdp2/parser_metadata.h` — `xdp2_metadata_all` struct (232B)
- `nix/microvms/mkVm.nix` — VM definition, networking, kernel config
- `nix/microvms/default.nix` — lifecycle test phases
- `nix/xdp-samples.nix` — BPF bytecode compilation pattern
- `xdp2-rs/docs/hardware-classified-extraction.md` — template extraction concept (Step 12)
- `xdp2-rs/docs/performance-maximization-plan.md` — parent performance plan
