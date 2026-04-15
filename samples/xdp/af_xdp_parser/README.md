# AF_XDP Parser Sample

XDP program that classifies packets using the XDP2 parse graph and redirects
them to AF_XDP sockets for zero-copy delivery to userspace.

## Architecture

```
NIC -> XDP program (classify) -> XDP_REDIRECT -> XSKMAP -> UMEM -> Rust parser
                              \-> XDP_PASS -> kernel stack (unrecognized packets)
```

## Build

```bash
make XDP2DIR=/path/to/xdp2/install
```

## Usage

```bash
# 1. Load XDP program (generic mode for testing)
sudo ip link set dev eth0 xdpgeneric obj af_xdp_parser.xdp.o sec xdp

# 2. Start Rust AF_XDP reader (populates xsks_map automatically)
sudo xdp2-bench --mode af-xdp --interface eth0 --queue 0 --duration 10

# 3. Send traffic (from another terminal or machine)
ping 10.0.0.2
# or: tcpreplay -i veth0 test.pcap

# 4. Unload XDP program
sudo ip link set dev eth0 xdp off
```

## Testing with veth pair

```bash
# Create veth pair
sudo ip link add veth0 type veth peer name veth1
sudo ip link set veth0 up
sudo ip link set veth1 up
sudo ip addr add 10.0.0.1/24 dev veth0
sudo ip addr add 10.0.0.2/24 dev veth1

# Load XDP on veth1
sudo ip link set dev veth1 xdpgeneric obj af_xdp_parser.xdp.o sec xdp

# Run reader on veth1
sudo xdp2-bench --mode af-xdp --interface veth1 --queue 0 --duration 10

# Send traffic via veth0
sudo tcpreplay -i veth0 test.pcap
```

## BPF Maps

| Map | Type | Description |
|-----|------|-------------|
| `xsks_map` | XSKMAP | AF_XDP socket FDs, keyed by RX queue index |
| `af_xdp_stats` | PERCPU_ARRAY | Redirect/pass/fail counters |
| `ctx_map` | PERCPU_ARRAY | Per-CPU parser state (from XDP2 template) |
| `parsers` | PROG_ARRAY | Tail-call dispatch (from XDP2 template) |

## Statistics

Read per-CPU stats via bpftool:
```bash
sudo bpftool map dump pinned /sys/fs/bpf/af_xdp_stats
```

Keys: 0 = redirected, 1 = passed to kernel, 2 = parse failed.
