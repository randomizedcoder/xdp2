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
│   ┌──────────┐    ┌──────────┐    ┌───────────┐                 │
│   │  Phase 1 │───▶│  Phase 2 │───▶│ Phase 2b  │                 │
│   │  Process │    │  Serial  │    │  Virtio   │                 │
│   │  Started │    │  Ready   │    │  Ready    │                 │
│   └──────────┘    └──────────┘    └───────────┘                 │
│        │                               │                         │
│        │                               ▼                         │
│        │              ┌──────────┐    ┌───────────┐             │
│        │              │  Phase 4 │◀───│  Phase 3  │             │
│        │              │  eBPF    │    │  Service  │             │
│        │              │  Running │    │  Ready    │             │
│        │              └──────────┘    └───────────┘             │
│        │                   │                                     │
│        │                   ▼                                     │
│        │              ┌──────────┐    ┌───────────┐             │
│        │              │  Phase 5 │───▶│  Phase 6  │             │
│        │              │ Shutdown │    │ Wait Exit │             │
│        │              └──────────┘    └───────────┘             │
│        │                                   │                     │
│        │                                   ▼                     │
│        │                          ┌───────────────┐             │
│        └─────────────────────────▶│  Force Kill   │             │
│              (on timeout)         │  (fallback)   │             │
│                                   └───────────────┘             │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Scripts Reference

### Phase 1: Check Process Started

```bash
nix run .#xdp2-lifecycle-1-check-process
```

Polls `ps` for the VM process name (`xdp2-test-x86_64`). This confirms QEMU has started.

- **Timeout:** 5 seconds
- **Exit 0:** Process found
- **Exit 1:** Timeout reached

### Phase 2: Check Serial Console

```bash
nix run .#xdp2-lifecycle-2-check-serial
```

Polls TCP port 5000 (serial console). This confirms early boot has completed and the kernel has initialized the serial driver.

- **Timeout:** 30 seconds
- **Exit 0:** Port is listening
- **Exit 1:** Timeout reached

### Phase 2b: Check Virtio Console

```bash
nix run .#xdp2-lifecycle-2b-check-virtio
```

Polls TCP port 5001 (virtio console). This confirms virtio drivers have loaded and the fast console is available.

- **Timeout:** 45 seconds
- **Exit 0:** Port is listening
- **Exit 1:** Timeout reached

### Phase 3: Verify eBPF Loaded

```bash
nix run .#xdp2-lifecycle-3-verify-ebpf-loaded
```

Polls the `xdp2-self-test.service` systemd unit via the virtio console. This confirms the self-test service has run.

- **Timeout:** 60 seconds
- **Exit 0:** Service completed (active or inactive for oneshot)
- **Exit 1:** Timeout or service failed

### Phase 4: Verify eBPF Running

```bash
nix run .#xdp2-lifecycle-4-verify-ebpf-running
```

Checks eBPF infrastructure via the virtio console:
- BTF available at `/sys/kernel/btf/vmlinux`
- `bpftool` command works
- Network interface (`eth0`) is present for XDP attachment

- **Exit 0:** All checks pass
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
1. Builds the VM (`nix build .#microvm-x86_64`)
2. Starts the VM
3. Runs phases 1 through 6
4. Reports results with colored output

## Configuration

Timeouts and polling interval are defined in `nix/microvms/constants.nix`:

```nix
{
  # Polling interval (seconds)
  pollInterval = 1;

  # Per-phase timeouts (seconds)
  timeouts = {
    processStart = 5;    # Phase 1
    serialReady = 30;    # Phase 2
    virtioReady = 45;    # Phase 2b
    serviceReady = 60;   # Phase 3
    command = 5;         # Individual command timeout
    shutdown = 30;       # Phase 6
  };
}
```

The VM process name is derived from:
```nix
getProcessName = arch: "xdp2-test-${arch}";
# Results in: xdp2-test-x86_64
```

## Console Ports

| Port | Console | Device | Purpose |
|------|---------|--------|---------|
| 5000 | Serial | ttyS0 | Early boot messages, kernel panics |
| 5001 | Virtio | hvc0 | Fast interactive shell, commands |

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

# Connect interactively
nix run .#xdp2-vm-console
# (Now you're in the VM shell)

# When done, exit and shutdown
nix run .#xdp2-lifecycle-5-shutdown
nix run .#xdp2-lifecycle-6-wait-exit
```

## Output Format

Each script outputs progress during polling:

```
=== Lifecycle Phase 2: Check Serial Console ===
Port: 5000 (ttyS0)
Timeout: 30 seconds (polling every 1 s)

  Polling... (1/30 s)
  Polling... (2/30 s)
  Polling... (3/30 s)
PASS: Serial console available on port 5000
  Time to serial ready: 3 seconds
```

Exit codes:
- **0** - Phase completed successfully
- **1** - Phase failed (timeout or error)

## See Also

- [MicroVM Implementation Phase 1](./microvm-implementation-phase1.md) - Implementation plan
- [MicroVM Implementation Log](./microvm-implementation-phase1-log.md) - Progress log
- [MicroVM eBPF Test Design](./microvm-ebpf-test-design.md) - Comprehensive design document
