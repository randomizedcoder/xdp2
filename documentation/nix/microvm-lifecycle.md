# MicroVM Lifecycle Management

This document describes the VM lifecycle check system for XDP2 MicroVM testing.

## Overview

The lifecycle system provides individual scripts to check each phase of a MicroVM's lifecycle. Each script polls at a configurable interval until a condition is met or a timeout is reached. This enables:

- **Automated testing** - Run VMs in CI pipelines with proper health checks
- **Debugging** - Run individual phases to isolate issues
- **Orchestration** - Build custom test workflows by combining phases

## Lifecycle Phases

```
┌─────────────────────────────────────────────────────────────────┐
│                      VM Lifecycle                                │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   ┌──────────┐    ┌──────────┐    ┌──────────┐                  │
│   │  Phase 0 │───▶│  Phase 1 │───▶│  Phase 2 │                  │
│   │  Build   │    │  Process │    │  Serial  │                  │
│   │          │    │  Started │    │  Ready   │                  │
│   └──────────┘    └──────────┘    └──────────┘                  │
│                                        │                         │
│                                        ▼                         │
│   ┌──────────┐    ┌──────────┐    ┌───────────┐                 │
│   │  Phase 4 │◀───│  Phase 3 │◀───│ Phase 2b  │                 │
│   │  eBPF    │    │  Service │    │  Virtio   │                 │
│   │  Status  │    │  Ready   │    │  Ready    │                 │
│   └──────────┘    └──────────┘    └───────────┘                 │
│        │                                                         │
│        ▼                                                         │
│   ┌──────────┐    ┌───────────┐                                 │
│   │  Phase 5 │───▶│  Phase 6  │                                 │
│   │ Shutdown │    │ Wait Exit │                                 │
│   └──────────┘    └───────────┘                                 │
│                        │                                         │
│                        ▼                                         │
│                ┌───────────────┐                                │
│                │  Force Kill   │                                │
│                │  (fallback)   │                                │
│                └───────────────┘                                │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Scripts Reference

### Phase 0: Build VM

```bash
nix run .#xdp2-lifecycle-0-build
```

Builds the VM derivation using `nix build`. This can take significant time if derivations need to be built from scratch (kernel, systemd, etc.).

- **Timeout:** 600 seconds (10 minutes)
- **Exit 0:** Build completed successfully
- **Exit 1:** Build failed or timed out

### Phase 1: Check Process Started

```bash
nix run .#xdp2-lifecycle-1-check-process
```

Polls `ps` for the VM process name (`xdp2-test-x86-64`). This confirms QEMU has started.

- **Timeout:** 5 seconds
- **Exit 0:** Process found
- **Exit 1:** Timeout reached

### Phase 2: Check Serial Console

```bash
nix run .#xdp2-lifecycle-2-check-serial
```

Polls TCP port 23500 (serial console). This confirms early boot has completed and the kernel has initialized the serial driver.

- **Timeout:** 30 seconds
- **Exit 0:** Port is listening
- **Exit 1:** Timeout reached

### Phase 2b: Check Virtio Console

```bash
nix run .#xdp2-lifecycle-2b-check-virtio
```

Polls TCP port 23501 (virtio console). This confirms virtio drivers have loaded and the fast console is available.

- **Timeout:** 45 seconds
- **Exit 0:** Port is listening
- **Exit 1:** Timeout reached

### Phase 3: Verify Self-Test Service

```bash
nix run .#xdp2-lifecycle-3-verify-ebpf-loaded
```

Uses expect-based terminal automation with native stream monitoring to detect service completion via the virtio console. This confirms the self-test service has run.

**Detection method:**
1. Quick initial check with `systemctl is-active` (handles already-completed case)
2. If service is still `activating`, switches to `journalctl -f` stream monitoring
3. Uses expect's native pattern matching for immediate detection of completion
4. Reports progress at configurable intervals (default: every 2 seconds)

**Advantages over polling:**
- Immediate detection when service completes (no polling delay)
- Lower CPU usage (passive wait on stream vs active polling loop)
- Less terminal noise (single journalctl command vs repeated systemctl calls)

**Timing output:**
- `connect`: Time to establish connection and get shell prompt
- `Time`: Detection latency (typically ~40ms for systemctl query)
- `total`: Total script execution time

- **Timeout:** 60 seconds
- **Exit 0:** Service completed (active or inactive for oneshot)
- **Exit 1:** Timeout or service failed

### Phase 4: Verify eBPF/XDP Status

```bash
nix run .#xdp2-lifecycle-4-verify-ebpf-running
```

Uses expect-based terminal automation to check eBPF/XDP status via the virtio console:

1. **`bpftool net show`** - Shows XDP programs attached to interfaces
2. **`ip link show eth0`** - Shows if interface has XDP mode attached
3. **`bpftool prog list`** - Lists all loaded BPF programs with IDs
4. **BTF check** - Verifies `/sys/kernel/btf/vmlinux` exists

- **Exit 0:** All checks complete (informational output)
- **Exit 1:** Virtio console not available

### Phase 5: Shutdown

```bash
nix run .#xdp2-lifecycle-5-shutdown
```

Sends `poweroff` command via the virtio console to initiate graceful shutdown.

- **Exit 0:** Command sent (does not wait for shutdown)

### Phase 6: Wait for Exit

```bash
nix run .#xdp2-lifecycle-6-wait-exit
```

Polls `ps` until the VM process disappears.

- **Timeout:** 30 seconds
- **Exit 0:** Process exited
- **Exit 1:** Timeout reached (process still running)

### Force Kill (Fallback)

```bash
nix run .#xdp2-lifecycle-force-kill
```

Forcefully terminates the VM process using `pkill`:
1. Sends SIGTERM
2. Waits 2 seconds
3. Sends SIGKILL if still running

Use this when graceful shutdown fails or hangs.

### Full Lifecycle Test

```bash
nix run .#xdp2-lifecycle-full-test
```

Runs all phases in sequence:
1. Phase 0: Builds the VM (`nix build .#microvm-x86_64`)
2. Phase 1: Starts the VM and verifies process
3. Phase 2: Waits for serial console
4. Phase 2b: Waits for virtio console
5. Phase 3: Verifies self-test service (expect-based)
6. Phase 4: Checks eBPF/XDP status (expect-based)
7. Phase 5: Sends shutdown command
8. Phase 6: Waits for clean exit

Reports results with colored output (PASS/FAIL/INFO).

**Timing Summary**: At the end of the test, a timing summary table is printed showing millisecond-resolution timing for each phase:

```
  Timing Summary
  ─────────────────────────────────────
  Phase                     Time (ms)
  ─────────────────────────────────────
  0: Build VM                    4066
  1: Start VM                      54
  2: Serial Console                 6
  2b: Virtio Console                6
  3: Service Verification       20771
  4: eBPF Status                42351
  5: Shutdown                    2782
  6: Wait Exit                   1003
  ─────────────────────────────────────
  TOTAL                         71057
  ─────────────────────────────────────
```

This helps identify performance bottlenecks and track improvements.

## Expect-Based Tools

These tools use Tcl/Expect for reliable terminal interaction with proper output buffering and hostname-based prompt matching.

### Run Single Command

```bash
nix run .#xdp2-vm-expect-run -- "uname -a"
nix run .#xdp2-vm-expect-run -- "bpftool prog list" 30
nix run .#xdp2-vm-expect-run -- "dmesg | tail -20" 10 100  # debug level 100
```

Runs a single command in the VM and captures output cleanly.

### Debug VM

```bash
nix run .#xdp2-vm-debug-expect
nix run .#xdp2-vm-debug-expect -- 100  # debug level
```

Runs a series of diagnostic commands:
- Kernel version
- Hostname
- Self-test service status
- BTF availability
- bpftool version
- Network interfaces
- Loaded BPF programs
- Memory usage
- Uptime

### Verify Service

```bash
nix run .#xdp2-vm-expect-verify-service
nix run .#xdp2-vm-expect-verify-service -- 60 2  # timeout, progress interval
```

Monitors the self-test service using native stream monitoring until completion. Used by Phase 3.

The second argument (default: 2) controls the progress reporting interval - how often "Waiting..." messages are displayed during stream monitoring.

## Configuration

Timeouts and polling interval are defined in `nix/microvms/constants.nix`:

```nix
rec {
  # Polling interval (seconds)
  pollInterval = 1;

  # Per-phase timeouts (seconds)
  timeouts = {
    build = 600;         # Phase 0 (10 minutes)
    processStart = 5;    # Phase 1
    serialReady = 30;    # Phase 2
    virtioReady = 45;    # Phase 2b
    serviceReady = 60;   # Phase 3
    command = 5;         # Individual command timeout
    shutdown = 30;       # Phase 6
  };
}
```

The VM process name and hostname are derived from:
```nix
archHostname = {
  x86_64 = "x86-64";  # Hyphen, not underscore (valid hostname)
  aarch64 = "aarch64";
  riscv64 = "riscv64";
  riscv32 = "riscv32";
};

getHostname = arch: "xdp2-test-${archHostname.${arch}}";
# Results in: xdp2-test-x86-64
```

## Console Ports

Port allocation scheme starting at 23500:

| Architecture | Serial Port | Virtio Port | Console Devices |
|--------------|-------------|-------------|-----------------|
| x86_64       | 23500       | 23501       | ttyS0, hvc0     |
| aarch64      | 23510       | 23511       | ttyS0, hvc0     |
| riscv64      | 23520       | 23521       | ttyS0, hvc0     |
| riscv32      | 23530       | 23531       | ttyS0, hvc0     |

| Port Type | Purpose |
|-----------|---------|
| Serial (ttyS0) | Early boot messages, kernel panics |
| Virtio (hvc0) | Fast interactive shell, commands |

## Network Interface

The VM includes a network interface for XDP testing:

- **Interface name:** `eth0`
- **Type:** QEMU user networking (NAT to host)
- **MAC:** `52:54:00:12:34:56`

XDP programs can be attached to this interface inside the VM.

## Usage Examples

### Basic Test Run

```bash
# Build and start VM
nix build .#microvm-x86_64
./result/bin/microvm-run &

# Run lifecycle checks
nix run .#xdp2-lifecycle-1-check-process
nix run .#xdp2-lifecycle-2-check-serial
nix run .#xdp2-lifecycle-2b-check-virtio
nix run .#xdp2-lifecycle-3-verify-ebpf-loaded
nix run .#xdp2-lifecycle-4-verify-ebpf-running

# Shutdown
nix run .#xdp2-lifecycle-5-shutdown
nix run .#xdp2-lifecycle-6-wait-exit || nix run .#xdp2-lifecycle-force-kill
```

### CI Pipeline Script

```bash
#!/usr/bin/env bash
set -euo pipefail

# Run full lifecycle test
if nix run .#xdp2-lifecycle-full-test; then
    echo "All lifecycle checks passed"
    exit 0
else
    echo "Lifecycle test failed, cleaning up..."
    nix run .#xdp2-lifecycle-force-kill || true
    exit 1
fi
```

### Debug a Stuck VM

```bash
# Check if VM is running
nix run .#xdp2-vm-status

# Try graceful shutdown
nix run .#xdp2-lifecycle-5-shutdown

# Wait a bit, then force kill if needed
sleep 5
nix run .#xdp2-lifecycle-force-kill
```

### Interactive Debugging

```bash
# Start VM
nix build .#microvm-x86_64
./result/bin/microvm-run &

# Wait for boot
nix run .#xdp2-lifecycle-2b-check-virtio

# Run diagnostic commands via expect (reliable output)
nix run .#xdp2-vm-debug-expect

# Or run specific commands
nix run .#xdp2-vm-expect-run -- "bpftool prog list"
nix run .#xdp2-vm-expect-run -- "ip link show eth0"

# Connect interactively (raw terminal)
nix run .#xdp2-vm-login-virtio
# (Now you're in the VM shell)

# When done, exit and shutdown
nix run .#xdp2-lifecycle-5-shutdown
nix run .#xdp2-lifecycle-6-wait-exit
```

### Check eBPF/XDP Status

```bash
# After VM is running, check XDP status
nix run .#xdp2-vm-expect-run -- "bpftool net show"
nix run .#xdp2-vm-expect-run -- "ip -d link show eth0"
nix run .#xdp2-vm-expect-run -- "bpftool prog list"
```

## Output Format

Each script outputs progress during polling. The full lifecycle test uses millisecond-resolution timing:

```
--- Phase 1: Start VM (timeout: 5 s) ---
  PASS: VM process 'xdp2-test-x86-64' running (found in 54ms)

--- Phase 2: Check Serial Console (timeout: 30 s) ---
  PASS: Serial console available (ready in 6ms)

--- Phase 3: Verify Self-Test Service (timeout: 60 s) ---
=== Verify Self-Test Service ===
Port: 23501
Timeout: 60s (progress every 1s)

  Prompt ready (connect: 16400ms)
PASS: Service already completed
  Detection: systemctl (active)
  Time: 42ms (total: 16442ms)
  PASS: Self-test service completed (phase: 20771ms)
```

Phase 4 output example:

```
--- Phase 4: Verify eBPF/XDP Status ---
  Checking XDP on interfaces...
  PASS: XDP program(s) attached
  Checking interface eth0...
  INFO: Interface eth0 ready (no XDP attached yet)
  Checking loaded BPF programs...
  PASS: 122 BPF program(s) loaded
    33: lsm  name restrict_filesystems  tag e8932b6bae2b9745  gpl
    43: cgroup_skb  name sd_fw_egress  tag 7dc8126e8768ea37  gpl
    ...
  Checking BTF...
  PASS: BTF available at /sys/kernel/btf/vmlinux
```

Exit codes:
- **0** - Phase completed successfully
- **1** - Phase failed (timeout or error)

## Expect Scripts

The expect scripts in `nix/microvms/scripts/` provide reliable terminal automation:

| Script | Purpose |
|--------|---------|
| `vm-expect.exp` | Run single command with output capture |
| `vm-debug.exp` | Run diagnostic command series |
| `vm-verify-service.exp` | Stream-based service monitoring |

Features:
- Hostname-based prompt matching (`root@xdp2-test-x86-64:...#`)
- Line-by-line output buffering (handles large outputs)
- ANSI escape code stripping
- Configurable timeouts and debug levels
- Native stream monitoring with `journalctl -f` (vm-verify-service.exp)

### Stream Monitoring Architecture

The `vm-verify-service.exp` script uses a dual-phase approach:

```
Phase 1: Quick Status Check
┌─────────────────────────────────────┐
│ systemctl is-active                 │
│   ├─ active/inactive → exit 0       │
│   ├─ failed → exit 1                │
│   └─ activating → Phase 2           │
└─────────────────────────────────────┘

Phase 2: Stream Monitoring
┌─────────────────────────────────────┐
│ journalctl -fu xdp2-self-test       │
│   ├─ "SUCCESS" pattern → exit 0     │
│   ├─ "FAIL" pattern → exit 1        │
│   ├─ timeout (progress) → continue  │
│   └─ overall timeout → exit 1       │
└─────────────────────────────────────┘
```

Key techniques:
- **Pattern ordering**: Specific patterns (SUCCESS, FAIL) before general `\r\n` catch-all
- **Buffer management**: `\r\n` pattern consumes unmatched lines, keeping buffer small
- **Timer preservation**: `exp_continue -continue_timer` preserves timeout when consuming lines
- **Progress reporting**: `exp_continue` (without flag) resets timeout in timeout handler

## See Also

- [MicroVM Implementation Phase 1](./microvm-implementation-phase1.md) - Implementation plan
- [MicroVM Implementation Log](./microvm-implementation-phase1-log.md) - Progress log
- [MicroVM eBPF Test Design](./microvm-ebpf-test-design.md) - Comprehensive design document
