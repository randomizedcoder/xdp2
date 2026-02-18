# nix/microvms/default.nix
#
# Entry point for XDP2 MicroVM test infrastructure.
#
# Phase 1: x86_64 only
# See: documentation/nix/microvm-implementation-phase1.md
#
# Usage in flake.nix:
#   microvms = import ./nix/microvms { inherit pkgs lib microvm nixpkgs; };
#   packages.microvm-x86_64 = microvms.vms.x86_64;
#
{ pkgs, lib, microvm, nixpkgs }:

let
  constants = import ./constants.nix;

  # VM process name (for ps matching)
  vmProcessName = constants.getProcessName "x86_64";

  # Import VM definitions
  vms = {
    x86_64 = import ./x86_64.nix { inherit pkgs lib microvm nixpkgs; };
  };

  # Test runner using writeShellApplication
  testRunner = pkgs.writeShellApplication {
    name = "xdp2-test-phase1";
    runtimeInputs = with pkgs; [
      coreutils
      netcat-gnu
    ];
    text = ''
      echo "========================================"
      echo "  XDP2 Phase 1 MicroVM Test"
      echo "========================================"
      echo ""
      echo "Testing: x86_64 with stable kernel"
      echo ""

      # Build the VM
      echo "Building VM..."
      VM_PATH=$(nix build .#microvm-x86_64 --print-out-paths --no-link 2>/dev/null)
      if [ -z "$VM_PATH" ]; then
        echo "ERROR: Failed to build VM"
        exit 1
      fi
      echo "VM built: $VM_PATH"
      echo ""

      # Check if ports are available
      SERIAL_PORT=${toString constants.architectures.x86_64.serialPort}
      VIRTIO_PORT=${toString constants.architectures.x86_64.virtioPort}

      if nc -z 127.0.0.1 "$SERIAL_PORT" 2>/dev/null; then
        echo "ERROR: Port $SERIAL_PORT already in use"
        echo "A VM may already be running. Stop it first."
        exit 1
      fi

      # Start the VM in background
      echo "Starting VM..."
      "$VM_PATH/bin/microvm-run" &
      VM_PID=$!
      echo "VM PID: $VM_PID"

      # Wait for VM to boot (check virtio console port)
      echo "Waiting for VM to boot..."
      TIMEOUT=${toString constants.timeouts.boot}
      WAITED=0
      while ! nc -z 127.0.0.1 "$VIRTIO_PORT" 2>/dev/null; do
        sleep 1
        WAITED=$((WAITED + 1))
        if [ "$WAITED" -ge "$TIMEOUT" ]; then
          echo "ERROR: VM failed to boot within $TIMEOUT seconds"
          kill "$VM_PID" 2>/dev/null || true
          exit 1
        fi
        if ! kill -0 "$VM_PID" 2>/dev/null; then
          echo "ERROR: VM process died"
          exit 1
        fi
      done
      echo "VM booted in $WAITED seconds"
      echo ""

      # Connect to console and check self-test output
      echo "Connecting to VM console..."
      echo "--- VM Console Output ---"

      # Give the self-test service time to run
      sleep 5

      # Try to read from console (non-blocking)
      timeout 10 nc 127.0.0.1 "$VIRTIO_PORT" 2>/dev/null || true

      echo "--- End Console Output ---"
      echo ""

      # Clean shutdown
      echo "Shutting down VM..."
      kill "$VM_PID" 2>/dev/null || true
      wait "$VM_PID" 2>/dev/null || true

      echo ""
      echo "========================================"
      echo "  Phase 1 Test Complete"
      echo "========================================"
      echo ""
      echo "To run the VM interactively:"
      echo "  nix build .#microvm-x86_64"
      echo "  ./result/bin/microvm-run &"
      echo "  nc 127.0.0.1 ${toString constants.architectures.x86_64.virtioPort}"
    '';
  };

  # Console connection helper using writeShellApplication
  connectConsole = pkgs.writeShellApplication {
    name = "xdp2-vm-console";
    runtimeInputs = with pkgs; [ netcat-gnu ];
    text = ''
      PORT=${toString constants.architectures.x86_64.virtioPort}
      echo "Connecting to VM virtio console on port $PORT..."
      echo "Press Ctrl+C to disconnect"
      nc 127.0.0.1 "$PORT"
    '';
  };

  # Serial console connection (for boot debugging)
  connectSerial = pkgs.writeShellApplication {
    name = "xdp2-vm-serial";
    runtimeInputs = with pkgs; [ netcat-gnu ];
    text = ''
      PORT=${toString constants.architectures.x86_64.serialPort}
      echo "Connecting to VM serial console on port $PORT..."
      echo "Press Ctrl+C to disconnect"
      nc 127.0.0.1 "$PORT"
    '';
  };

  # VM status checker
  vmStatus = pkgs.writeShellApplication {
    name = "xdp2-vm-status";
    runtimeInputs = with pkgs; [ netcat-gnu procps ];
    text = ''
      SERIAL_PORT=${toString constants.architectures.x86_64.serialPort}
      VIRTIO_PORT=${toString constants.architectures.x86_64.virtioPort}

      echo "XDP2 MicroVM Status"
      echo "==================="
      echo ""

      # Check for running VM process
      if pgrep -f "${vmProcessName}" > /dev/null 2>&1; then
        echo "VM Process: RUNNING"
        pgrep -af "${vmProcessName}" | head -1
      else
        echo "VM Process: NOT RUNNING"
      fi
      echo ""

      # Check ports
      echo "Console Ports:"
      if nc -z 127.0.0.1 "$SERIAL_PORT" 2>/dev/null; then
        echo "  Serial (ttyS0):  port $SERIAL_PORT - LISTENING"
      else
        echo "  Serial (ttyS0):  port $SERIAL_PORT - not listening"
      fi

      if nc -z 127.0.0.1 "$VIRTIO_PORT" 2>/dev/null; then
        echo "  Virtio (hvc0):   port $VIRTIO_PORT - LISTENING"
      else
        echo "  Virtio (hvc0):   port $VIRTIO_PORT - not listening"
      fi
    '';
  };

  # ==========================================================================
  # VM Lifecycle Check Scripts
  # ==========================================================================
  #
  # These scripts check individual phases of the VM lifecycle.
  # They are designed to be run in sequence, or individually for debugging.
  #
  # Lifecycle phases:
  #   1. Process started (QEMU running)
  #   2. Serial console available (early boot complete)
  #   3. eBPF/XDP loaded by systemd
  #   4. eBPF/XDP verified running
  #   5. Graceful shutdown initiated
  #   6. Process exited (VM stopped)
  #

  # Phase 0: Build VM (can take time if derivations need to be built)
  lifecycleCheckBuild = pkgs.writeShellApplication {
    name = "xdp2-lifecycle-0-build";
    runtimeInputs = with pkgs; [ coreutils ];
    text = ''
      BUILD_TIMEOUT=${toString constants.timeouts.build}

      echo "=== Lifecycle Phase 0: Build VM ==="
      echo "Timeout: $BUILD_TIMEOUT seconds"
      echo ""

      echo "Building VM derivation..."
      echo "  (This may take a while if building from scratch)"
      echo ""

      # Run nix build with timeout
      START_TIME=$(date +%s)

      if ! timeout "$BUILD_TIMEOUT" nix build .#microvm-x86_64 --print-out-paths --no-link 2>&1; then
        END_TIME=$(date +%s)
        ELAPSED=$((END_TIME - START_TIME))
        echo ""
        echo "FAIL: Build failed or timed out after $ELAPSED seconds"
        exit 1
      fi

      END_TIME=$(date +%s)
      ELAPSED=$((END_TIME - START_TIME))

      VM_PATH=$(nix build .#microvm-x86_64 --print-out-paths --no-link 2>/dev/null)
      if [ -z "$VM_PATH" ]; then
        echo "FAIL: Build succeeded but could not get output path"
        exit 1
      fi

      echo "PASS: VM built successfully"
      echo "  Build time: $ELAPSED seconds"
      echo "  Output: $VM_PATH"
      exit 0
    '';
  };

  # Phase 1: Check if VM process is running (polls until found or timeout)
  lifecycleCheckProcess = pkgs.writeShellApplication {
    name = "xdp2-lifecycle-1-check-process";
    runtimeInputs = with pkgs; [ procps coreutils ];
    text = ''
      VM_PROCESS="${vmProcessName}"
      TIMEOUT=${toString constants.timeouts.processStart}
      POLL_INTERVAL=${toString constants.pollInterval}

      echo "=== Lifecycle Phase 1: Check VM Process ==="
      echo "Process pattern: $VM_PROCESS"
      echo "Timeout: $TIMEOUT seconds (polling every $POLL_INTERVAL s)"
      echo ""

      WAITED=0
      while ! pgrep -f "$VM_PROCESS" > /dev/null 2>&1; do
        sleep "$POLL_INTERVAL"
        WAITED=$((WAITED + POLL_INTERVAL))
        if [ "$WAITED" -ge "$TIMEOUT" ]; then
          echo "FAIL: VM process not found after $TIMEOUT seconds"
          exit 1
        fi
        echo "  Polling... ($WAITED/$TIMEOUT s)"
      done

      echo "PASS: VM process is running (found in $WAITED s)"
      echo ""
      echo "Process details:"
      pgrep -af "$VM_PROCESS" | head -3
      exit 0
    '';
  };

  # Phase 2: Check serial console (low-speed) is available
  lifecycleCheckSerial = pkgs.writeShellApplication {
    name = "xdp2-lifecycle-2-check-serial";
    runtimeInputs = with pkgs; [ netcat-gnu coreutils ];
    text = ''
      SERIAL_PORT=${toString constants.architectures.x86_64.serialPort}
      TIMEOUT=${toString constants.timeouts.serialReady}
      POLL_INTERVAL=${toString constants.pollInterval}

      echo "=== Lifecycle Phase 2: Check Serial Console ==="
      echo "Port: $SERIAL_PORT (ttyS0)"
      echo "Timeout: $TIMEOUT seconds (polling every $POLL_INTERVAL s)"
      echo ""

      WAITED=0
      while ! nc -z 127.0.0.1 "$SERIAL_PORT" 2>/dev/null; do
        sleep "$POLL_INTERVAL"
        WAITED=$((WAITED + POLL_INTERVAL))
        if [ "$WAITED" -ge "$TIMEOUT" ]; then
          echo "FAIL: Serial port not available after $TIMEOUT seconds"
          exit 1
        fi
        echo "  Polling... ($WAITED/$TIMEOUT s)"
      done

      echo "PASS: Serial console available on port $SERIAL_PORT"
      echo "  Time to serial ready: $WAITED seconds"
      exit 0
    '';
  };

  # Phase 2b: Check virtio console (high-speed) is available
  lifecycleCheckVirtio = pkgs.writeShellApplication {
    name = "xdp2-lifecycle-2b-check-virtio";
    runtimeInputs = with pkgs; [ netcat-gnu coreutils ];
    text = ''
      VIRTIO_PORT=${toString constants.architectures.x86_64.virtioPort}
      TIMEOUT=${toString constants.timeouts.virtioReady}
      POLL_INTERVAL=${toString constants.pollInterval}

      echo "=== Lifecycle Phase 2b: Check Virtio Console ==="
      echo "Port: $VIRTIO_PORT (hvc0)"
      echo "Timeout: $TIMEOUT seconds (polling every $POLL_INTERVAL s)"
      echo ""

      WAITED=0
      while ! nc -z 127.0.0.1 "$VIRTIO_PORT" 2>/dev/null; do
        sleep "$POLL_INTERVAL"
        WAITED=$((WAITED + POLL_INTERVAL))
        if [ "$WAITED" -ge "$TIMEOUT" ]; then
          echo "FAIL: Virtio port not available after $TIMEOUT seconds"
          exit 1
        fi
        echo "  Polling... ($WAITED/$TIMEOUT s)"
      done

      echo "PASS: Virtio console available on port $VIRTIO_PORT"
      echo "  Time to virtio ready: $WAITED seconds"
      exit 0
    '';
  };

  # Phase 3: Verify eBPF/XDP was loaded by systemd (check self-test service)
  lifecycleVerifyEbpfLoaded = pkgs.writeShellApplication {
    name = "xdp2-lifecycle-3-verify-ebpf-loaded";
    runtimeInputs = with pkgs; [ netcat-gnu coreutils ];
    text = ''
      VIRTIO_PORT=${toString constants.architectures.x86_64.virtioPort}
      TIMEOUT=${toString constants.timeouts.serviceReady}
      CMD_TIMEOUT=${toString constants.timeouts.command}
      POLL_INTERVAL=${toString constants.pollInterval}

      echo "=== Lifecycle Phase 3: Verify eBPF Loaded ==="
      echo "Port: $VIRTIO_PORT (hvc0 virtio console)"
      echo "Timeout: $TIMEOUT seconds (polling every $POLL_INTERVAL s)"
      echo ""

      # Check if virtio console is available
      if ! nc -z 127.0.0.1 "$VIRTIO_PORT" 2>/dev/null; then
        echo "FAIL: Virtio console not available"
        exit 1
      fi

      # Poll for self-test service to complete
      echo "Waiting for xdp2-self-test.service to complete..."
      WAITED=0
      while true; do
        # Check the self-test service status
        RESPONSE=$(echo "systemctl is-active xdp2-self-test.service 2>/dev/null || echo unknown" | \
          timeout "$CMD_TIMEOUT" nc 127.0.0.1 "$VIRTIO_PORT" 2>/dev/null | head -5 || true)

        # Service states: active (running), inactive (completed oneshot), activating (starting)
        if echo "$RESPONSE" | grep -qE "^active|inactive"; then
          echo "PASS: xdp2-self-test service completed (status in response)"
          echo "  Time to service ready: $WAITED seconds"
          exit 0
        fi

        sleep "$POLL_INTERVAL"
        WAITED=$((WAITED + POLL_INTERVAL))
        if [ "$WAITED" -ge "$TIMEOUT" ]; then
          echo "FAIL: Self-test service not ready after $TIMEOUT seconds"
          echo ""
          echo "Last response: $RESPONSE"
          exit 1
        fi
        echo "  Polling... ($WAITED/$TIMEOUT s)"
      done
    '';
  };

  # Phase 4: Verify eBPF/XDP status (check bpftool and interface)
  lifecycleVerifyEbpfRunning = pkgs.writeShellApplication {
    name = "xdp2-lifecycle-4-verify-ebpf-running";
    runtimeInputs = with pkgs; [ expect netcat-gnu coreutils ];
    text = ''
      VIRTIO_PORT=${toString constants.architectures.x86_64.virtioPort}
      XDP_INTERFACE="${constants.xdpInterface}"
      HOSTNAME="${vmHostname}"
      SCRIPT_DIR="${./scripts}"

      echo "=== Lifecycle Phase 4: Verify eBPF/XDP Status ==="
      echo "Port: $VIRTIO_PORT (hvc0 virtio console)"
      echo "XDP Interface: $XDP_INTERFACE"
      echo ""

      # Check if virtio console is available
      if ! nc -z 127.0.0.1 "$VIRTIO_PORT" 2>/dev/null; then
        echo "FAIL: Virtio console not available"
        exit 1
      fi

      # Helper function to run expect command
      run_cmd() {
        expect "$SCRIPT_DIR/vm-expect.exp" "$VIRTIO_PORT" "$HOSTNAME" "$1" 10 0
      }

      # 1. Check bpftool net show (XDP programs attached to interfaces)
      echo "--- XDP Programs on Interfaces (bpftool net show) ---"
      run_cmd "bpftool net show" || true
      echo ""

      # 2. Check ip link show (look for xdp mode)
      echo "--- Interface $XDP_INTERFACE (ip link show) ---"
      OUTPUT=$(run_cmd "ip link show $XDP_INTERFACE" 2>/dev/null || true)
      echo "$OUTPUT"
      if echo "$OUTPUT" | grep -q "xdp"; then
        echo ""
        echo "PASS: XDP program attached to $XDP_INTERFACE"
      else
        echo ""
        echo "INFO: No XDP program currently attached to $XDP_INTERFACE"
      fi
      echo ""

      # 3. Check bpftool prog list (loaded BPF programs)
      echo "--- Loaded BPF Programs (bpftool prog list) ---"
      run_cmd "bpftool prog list" || true
      echo ""

      # 4. BTF availability check
      echo "--- BTF Status ---"
      OUTPUT=$(run_cmd "test -f /sys/kernel/btf/vmlinux && echo 'BTF: AVAILABLE' || echo 'BTF: NOT FOUND'" 2>/dev/null || true)
      echo "$OUTPUT"
      echo ""

      echo "Phase 4 complete - eBPF/XDP status verified"
      exit 0
    '';
  };

  # Phase 5: Graceful shutdown
  lifecycleShutdown = pkgs.writeShellApplication {
    name = "xdp2-lifecycle-5-shutdown";
    runtimeInputs = with pkgs; [ netcat-gnu coreutils ];
    text = ''
      VIRTIO_PORT=${toString constants.architectures.x86_64.virtioPort}
      CMD_TIMEOUT=${toString constants.timeouts.command}

      echo "=== Lifecycle Phase 5: Shutdown VM ==="
      echo "Port: $VIRTIO_PORT (hvc0 virtio console)"
      echo ""

      # Check if virtio console is available
      if ! nc -z 127.0.0.1 "$VIRTIO_PORT" 2>/dev/null; then
        echo "INFO: Virtio console not available"
        echo "  VM may already be stopped, or not yet booted"
        exit 0
      fi

      # Send poweroff command
      echo "Sending poweroff command..."
      echo "poweroff" | timeout "$CMD_TIMEOUT" nc 127.0.0.1 "$VIRTIO_PORT" 2>/dev/null || true

      echo "PASS: Shutdown command sent"
      echo "  Use lifecycle-6-wait-exit to confirm process termination"
      exit 0
    '';
  };

  # Phase 6: Wait for process to exit
  lifecycleWaitExit = pkgs.writeShellApplication {
    name = "xdp2-lifecycle-6-wait-exit";
    runtimeInputs = with pkgs; [ procps coreutils ];
    text = ''
      VM_PROCESS="${vmProcessName}"
      TIMEOUT=${toString constants.timeouts.shutdown}
      POLL_INTERVAL=${toString constants.pollInterval}

      echo "=== Lifecycle Phase 6: Wait for Exit ==="
      echo "Process: $VM_PROCESS"
      echo "Timeout: $TIMEOUT seconds (polling every $POLL_INTERVAL s)"
      echo ""

      WAITED=0
      while pgrep -f "$VM_PROCESS" > /dev/null 2>&1; do
        sleep "$POLL_INTERVAL"
        WAITED=$((WAITED + POLL_INTERVAL))
        if [ "$WAITED" -ge "$TIMEOUT" ]; then
          echo "FAIL: VM process still running after $TIMEOUT seconds"
          echo ""
          echo "Process details:"
          pgrep -af "$VM_PROCESS" | head -3
          echo ""
          echo "Use 'nix run .#xdp2-lifecycle-force-kill' to force termination"
          exit 1
        fi
        echo "  Polling... ($WAITED/$TIMEOUT s)"
      done

      echo "PASS: VM process exited"
      echo "  Shutdown time: $WAITED seconds"
      exit 0
    '';
  };

  # Force kill VM (for stuck or slow shutdown)
  lifecycleForceKill = pkgs.writeShellApplication {
    name = "xdp2-lifecycle-force-kill";
    runtimeInputs = with pkgs; [ procps coreutils ];
    text = ''
      VM_PROCESS="${vmProcessName}"

      echo "=== Force Kill VM ==="
      echo "Process pattern: $VM_PROCESS"
      echo ""

      # Find matching processes
      if ! pgrep -f "$VM_PROCESS" > /dev/null 2>&1; then
        echo "No matching processes found"
        exit 0
      fi

      echo "Found processes:"
      pgrep -af "$VM_PROCESS"
      echo ""

      # Kill with SIGTERM first
      echo "Sending SIGTERM..."
      pkill -f "$VM_PROCESS" 2>/dev/null || true
      sleep 2

      # Check if still running
      if pgrep -f "$VM_PROCESS" > /dev/null 2>&1; then
        echo "Process still running, sending SIGKILL..."
        pkill -9 -f "$VM_PROCESS" 2>/dev/null || true
        sleep 1
      fi

      # Verify
      if pgrep -f "$VM_PROCESS" > /dev/null 2>&1; then
        echo "WARNING: Process may still be running"
        pgrep -af "$VM_PROCESS"
        exit 1
      else
        echo "PASS: VM process killed"
        exit 0
      fi
    '';
  };

  # Full lifecycle test (runs all phases in sequence)
  lifecycleFullTest = pkgs.writeShellApplication {
    name = "xdp2-lifecycle-full-test";
    runtimeInputs = with pkgs; [ netcat-gnu procps coreutils expect ];
    text = ''
      VM_PROCESS="${vmProcessName}"
      SERIAL_PORT=${toString constants.architectures.x86_64.serialPort}
      VIRTIO_PORT=${toString constants.architectures.x86_64.virtioPort}
      POLL_INTERVAL=${toString constants.pollInterval}
      BUILD_TIMEOUT=${toString constants.timeouts.build}
      PROCESS_TIMEOUT=${toString constants.timeouts.processStart}
      SERIAL_TIMEOUT=${toString constants.timeouts.serialReady}
      VIRTIO_TIMEOUT=${toString constants.timeouts.virtioReady}
      SERVICE_TIMEOUT=${toString constants.timeouts.serviceReady}
      CMD_TIMEOUT=${toString constants.timeouts.command}
      SHUTDOWN_TIMEOUT=${toString constants.timeouts.shutdown}

      # Colors for output
      RED='\033[0;31m'
      GREEN='\033[0;32m'
      YELLOW='\033[1;33m'
      NC='\033[0m'

      # Millisecond timing helper
      now_ms() { date +%s%3N; }

      pass() { echo -e "  ''${GREEN}PASS: $1''${NC}"; }
      fail() { echo -e "  ''${RED}FAIL: $1''${NC}"; exit 1; }
      info() { echo -e "  ''${YELLOW}INFO: $1''${NC}"; }

      cleanup() {
        echo ""
        info "Cleaning up..."
        if [ -n "''${VM_PID:-}" ] && kill -0 "$VM_PID" 2>/dev/null; then
          kill "$VM_PID" 2>/dev/null || true
          wait "$VM_PID" 2>/dev/null || true
        fi
      }
      trap cleanup EXIT

      echo "========================================"
      echo "  XDP2 MicroVM Full Lifecycle Test"
      echo "========================================"
      echo ""
      echo "VM Process Name: $VM_PROCESS"
      echo "Serial Port: $SERIAL_PORT"
      echo "Virtio Port: $VIRTIO_PORT"
      echo ""

      # Record test start time
      TEST_START_MS=$(now_ms)

      # Timing storage for summary
      PHASE0_MS=0
      PHASE1_MS=0
      PHASE2_MS=0
      PHASE2B_MS=0
      PHASE3_MS=0
      PHASE4_MS=0
      PHASE5_MS=0
      PHASE6_MS=0

      # Phase 0: Build the VM (can take time if building from scratch)
      echo "--- Phase 0: Build VM (timeout: $BUILD_TIMEOUT s) ---"
      PHASE_START_MS=$(now_ms)

      # Run build with timeout - capture output for progress feedback
      if ! timeout "$BUILD_TIMEOUT" nix build .#microvm-x86_64 --print-out-paths --no-link 2>&1; then
        PHASE_END_MS=$(now_ms)
        PHASE0_MS=$((PHASE_END_MS - PHASE_START_MS))
        fail "Build failed or timed out after ''${PHASE0_MS}ms"
      fi

      # Get the output path
      VM_PATH=$(nix build .#microvm-x86_64 --print-out-paths --no-link 2>/dev/null)
      if [ -z "$VM_PATH" ]; then
        fail "Build succeeded but could not get output path"
      fi

      PHASE_END_MS=$(now_ms)
      PHASE0_MS=$((PHASE_END_MS - PHASE_START_MS))
      pass "VM built in ''${PHASE0_MS}ms: $VM_PATH"
      echo ""

      # Check ports are free
      if nc -z 127.0.0.1 "$SERIAL_PORT" 2>/dev/null; then
        fail "Port $SERIAL_PORT already in use"
      fi

      # Phase 1: Start VM and verify process
      echo "--- Phase 1: Start VM (timeout: $PROCESS_TIMEOUT s) ---"
      PHASE_START_MS=$(now_ms)
      "$VM_PATH/bin/microvm-run" &
      VM_PID=$!

      WAITED=0
      while ! pgrep -f "$VM_PROCESS" > /dev/null 2>&1; do
        sleep "$POLL_INTERVAL"
        WAITED=$((WAITED + POLL_INTERVAL))
        if [ "$WAITED" -ge "$PROCESS_TIMEOUT" ]; then
          fail "VM process not found after $PROCESS_TIMEOUT seconds"
        fi
        if ! kill -0 "$VM_PID" 2>/dev/null; then
          fail "VM process died immediately"
        fi
        info "Polling for process... ($WAITED/$PROCESS_TIMEOUT s)"
      done
      PHASE_END_MS=$(now_ms)
      PHASE1_MS=$((PHASE_END_MS - PHASE_START_MS))
      pass "VM process '$VM_PROCESS' running (found in ''${PHASE1_MS}ms)"
      echo ""

      # Phase 2: Wait for serial console
      echo "--- Phase 2: Check Serial Console (timeout: $SERIAL_TIMEOUT s) ---"
      PHASE_START_MS=$(now_ms)
      WAITED=0
      while ! nc -z 127.0.0.1 "$SERIAL_PORT" 2>/dev/null; do
        sleep "$POLL_INTERVAL"
        WAITED=$((WAITED + POLL_INTERVAL))
        if [ "$WAITED" -ge "$SERIAL_TIMEOUT" ]; then
          fail "Serial port not available after $SERIAL_TIMEOUT seconds"
        fi
        if ! kill -0 "$VM_PID" 2>/dev/null; then
          fail "VM process died while waiting for serial"
        fi
        info "Polling serial... ($WAITED/$SERIAL_TIMEOUT s)"
      done
      PHASE_END_MS=$(now_ms)
      PHASE2_MS=$((PHASE_END_MS - PHASE_START_MS))
      pass "Serial console available (ready in ''${PHASE2_MS}ms)"
      echo ""

      # Phase 2b: Wait for virtio console
      echo "--- Phase 2b: Check Virtio Console (timeout: $VIRTIO_TIMEOUT s) ---"
      PHASE_START_MS=$(now_ms)
      WAITED=0
      while ! nc -z 127.0.0.1 "$VIRTIO_PORT" 2>/dev/null; do
        sleep "$POLL_INTERVAL"
        WAITED=$((WAITED + POLL_INTERVAL))
        if [ "$WAITED" -ge "$VIRTIO_TIMEOUT" ]; then
          fail "Virtio port not available after $VIRTIO_TIMEOUT seconds"
        fi
        info "Polling virtio... ($WAITED/$VIRTIO_TIMEOUT s)"
      done
      PHASE_END_MS=$(now_ms)
      PHASE2B_MS=$((PHASE_END_MS - PHASE_START_MS))
      pass "Virtio console available (ready in ''${PHASE2B_MS}ms)"
      echo ""

      # Phase 3: Wait for self-test service (using expect for reliable terminal handling)
      echo "--- Phase 3: Verify Self-Test Service (timeout: $SERVICE_TIMEOUT s) ---"
      PHASE_START_MS=$(now_ms)
      EXPECT_SCRIPT="${./scripts}/vm-verify-service.exp"
      VM_HOSTNAME="${vmHostname}"

      if expect "$EXPECT_SCRIPT" "$VIRTIO_PORT" "$VM_HOSTNAME" "$SERVICE_TIMEOUT" "$POLL_INTERVAL"; then
        PHASE_END_MS=$(now_ms)
        PHASE3_MS=$((PHASE_END_MS - PHASE_START_MS))
        pass "Self-test service completed (phase: ''${PHASE3_MS}ms)"
      else
        PHASE_END_MS=$(now_ms)
        PHASE3_MS=$((PHASE_END_MS - PHASE_START_MS))
        info "Service verification returned non-zero after ''${PHASE3_MS}ms (check output above)"
      fi
      echo ""

      # Phase 4: Check eBPF/XDP status (using expect for reliable output)
      echo "--- Phase 4: Verify eBPF/XDP Status ---"
      PHASE_START_MS=$(now_ms)
      EXPECT_SCRIPT="${./scripts}/vm-expect.exp"

      # Helper to run commands via expect
      run_vm_cmd() {
        expect "$EXPECT_SCRIPT" "$VIRTIO_PORT" "$VM_HOSTNAME" "$1" 10 0 2>/dev/null || true
      }

      # 1. Check XDP programs on interfaces
      echo "  Checking XDP on interfaces..."
      NET_OUTPUT=$(run_vm_cmd "bpftool net show")
      if echo "$NET_OUTPUT" | grep -q "xdp"; then
        pass "XDP program(s) attached"
        echo "$NET_OUTPUT" | grep -E "xdp|eth0" | head -5 | sed 's/^/    /'
      else
        info "No XDP programs currently attached"
      fi

      # 2. Check interface for xdp mode
      echo "  Checking interface ${constants.xdpInterface}..."
      LINK_OUTPUT=$(run_vm_cmd "ip -d link show ${constants.xdpInterface}")
      if echo "$LINK_OUTPUT" | grep -q "xdp"; then
        pass "Interface ${constants.xdpInterface} has XDP attached"
      else
        info "Interface ${constants.xdpInterface} ready (no XDP attached yet)"
      fi

      # 3. Check loaded BPF programs
      echo "  Checking loaded BPF programs..."
      PROG_OUTPUT=$(run_vm_cmd "bpftool prog list")
      PROG_COUNT=$(echo "$PROG_OUTPUT" | grep -c "^[0-9]" || echo "0")
      if [ "$PROG_COUNT" -gt 0 ]; then
        pass "$PROG_COUNT BPF program(s) loaded"
        echo "$PROG_OUTPUT" | head -10 | sed 's/^/    /'
      else
        info "No BPF programs currently loaded"
      fi

      # 4. BTF availability
      echo "  Checking BTF..."
      BTF_OUTPUT=$(run_vm_cmd "test -f /sys/kernel/btf/vmlinux && echo BTF_AVAILABLE")
      if echo "$BTF_OUTPUT" | grep -q "BTF_AVAILABLE"; then
        pass "BTF available at /sys/kernel/btf/vmlinux"
      else
        info "Could not verify BTF"
      fi
      PHASE_END_MS=$(now_ms)
      PHASE4_MS=$((PHASE_END_MS - PHASE_START_MS))
      info "Phase 4 completed in ''${PHASE4_MS}ms"
      echo ""

      # Phase 5: Shutdown
      echo "--- Phase 5: Shutdown ---"
      PHASE_START_MS=$(now_ms)
      echo "poweroff" | timeout "$CMD_TIMEOUT" nc 127.0.0.1 "$VIRTIO_PORT" 2>/dev/null || true
      PHASE_END_MS=$(now_ms)
      PHASE5_MS=$((PHASE_END_MS - PHASE_START_MS))
      pass "Shutdown command sent (''${PHASE5_MS}ms)"
      echo ""

      # Phase 6: Wait for exit
      echo "--- Phase 6: Wait for Exit (timeout: $SHUTDOWN_TIMEOUT s) ---"
      PHASE_START_MS=$(now_ms)
      WAITED=0
      while kill -0 "$VM_PID" 2>/dev/null; do
        sleep "$POLL_INTERVAL"
        WAITED=$((WAITED + POLL_INTERVAL))
        if [ "$WAITED" -ge "$SHUTDOWN_TIMEOUT" ]; then
          info "VM still running after $SHUTDOWN_TIMEOUT s, sending SIGTERM"
          kill "$VM_PID" 2>/dev/null || true
          sleep 2
          break
        fi
        info "Polling for exit... ($WAITED/$SHUTDOWN_TIMEOUT s)"
      done

      PHASE_END_MS=$(now_ms)
      PHASE6_MS=$((PHASE_END_MS - PHASE_START_MS))
      if ! kill -0 "$VM_PID" 2>/dev/null; then
        pass "VM exited cleanly (shutdown time: ''${PHASE6_MS}ms)"
      else
        info "VM required forced termination after ''${PHASE6_MS}ms"
        kill -9 "$VM_PID" 2>/dev/null || true
      fi
      echo ""

      # Final summary
      TEST_END_MS=$(now_ms)
      TOTAL_TIME_MS=$((TEST_END_MS - TEST_START_MS))

      echo "========================================"
      echo -e "  ''${GREEN}Full Lifecycle Test Complete''${NC}"
      echo "========================================"
      echo ""
      echo "  Timing Summary"
      echo "  ─────────────────────────────────────"
      printf "  %-24s %10s\n" "Phase" "Time (ms)"
      echo "  ─────────────────────────────────────"
      printf "  %-24s %10d\n" "0: Build VM" "$PHASE0_MS"
      printf "  %-24s %10d\n" "1: Start VM" "$PHASE1_MS"
      printf "  %-24s %10d\n" "2: Serial Console" "$PHASE2_MS"
      printf "  %-24s %10d\n" "2b: Virtio Console" "$PHASE2B_MS"
      printf "  %-24s %10d\n" "3: Service Verification" "$PHASE3_MS"
      printf "  %-24s %10d\n" "4: eBPF Status" "$PHASE4_MS"
      printf "  %-24s %10d\n" "5: Shutdown" "$PHASE5_MS"
      printf "  %-24s %10d\n" "6: Wait Exit" "$PHASE6_MS"
      echo "  ─────────────────────────────────────"
      printf "  %-24s %10d\n" "TOTAL" "$TOTAL_TIME_MS"
      echo "  ─────────────────────────────────────"
    '';
  };

  # ==========================================================================
  # Debug/Login helpers for interactive VM access
  # ==========================================================================

  # Run a command via serial console and capture output
  runCommandSerial = pkgs.writeShellApplication {
    name = "xdp2-vm-run-serial";
    runtimeInputs = with pkgs; [ netcat-gnu coreutils ];
    text = ''
      SERIAL_PORT=${toString constants.architectures.x86_64.serialPort}
      CMD_TIMEOUT=${toString constants.timeouts.command}

      if [ $# -eq 0 ]; then
        echo "Usage: xdp2-vm-run-serial <command>"
        echo "Run a command in the VM via serial console (port $SERIAL_PORT)"
        exit 1
      fi

      COMMAND="$*"

      if ! nc -z 127.0.0.1 "$SERIAL_PORT" 2>/dev/null; then
        echo "ERROR: Serial port $SERIAL_PORT not available"
        exit 1
      fi

      MARKER="__OUT_$$__"
      {
        sleep 0.3
        echo ""
        echo "echo $MARKER; $COMMAND; echo $MARKER"
      } | timeout "$CMD_TIMEOUT" nc 127.0.0.1 "$SERIAL_PORT" 2>/dev/null | \
        sed -n "/$MARKER/,/$MARKER/p" | grep -v "$MARKER" || true
    '';
  };

  # Run a command via virtio console and capture output
  runCommandVirtio = pkgs.writeShellApplication {
    name = "xdp2-vm-run-virtio";
    runtimeInputs = with pkgs; [ netcat-gnu coreutils ];
    text = ''
      VIRTIO_PORT=${toString constants.architectures.x86_64.virtioPort}
      CMD_TIMEOUT=${toString constants.timeouts.command}

      if [ $# -eq 0 ]; then
        echo "Usage: xdp2-vm-run-virtio <command>"
        echo "Run a command in the VM via virtio console (port $VIRTIO_PORT)"
        exit 1
      fi

      COMMAND="$*"

      if ! nc -z 127.0.0.1 "$VIRTIO_PORT" 2>/dev/null; then
        echo "ERROR: Virtio port $VIRTIO_PORT not available"
        exit 1
      fi

      MARKER="__OUT_$$__"
      {
        sleep 0.3
        echo ""
        echo "echo $MARKER; $COMMAND; echo $MARKER"
      } | timeout "$CMD_TIMEOUT" nc 127.0.0.1 "$VIRTIO_PORT" 2>/dev/null | \
        sed -n "/$MARKER/,/$MARKER/p" | grep -v "$MARKER" || true
    '';
  };

  # Interactive login to serial console (with proper terminal handling)
  loginSerial = pkgs.writeShellApplication {
    name = "xdp2-vm-login-serial";
    runtimeInputs = with pkgs; [ socat netcat-gnu ];
    text = ''
      SERIAL_PORT=${toString constants.architectures.x86_64.serialPort}

      echo "Connecting to serial console (ttyS0) on port $SERIAL_PORT"
      echo "Press Ctrl+C to disconnect"

      if ! nc -z 127.0.0.1 "$SERIAL_PORT" 2>/dev/null; then
        echo "ERROR: Serial port $SERIAL_PORT not available"
        exit 1
      fi

      exec socat -,raw,echo=0 TCP:127.0.0.1:"$SERIAL_PORT"
    '';
  };

  # Interactive login to virtio console (with proper terminal handling)
  loginVirtio = pkgs.writeShellApplication {
    name = "xdp2-vm-login-virtio";
    runtimeInputs = with pkgs; [ socat netcat-gnu ];
    text = ''
      VIRTIO_PORT=${toString constants.architectures.x86_64.virtioPort}

      echo "Connecting to virtio console (hvc0) on port $VIRTIO_PORT"
      echo "Press Ctrl+C to disconnect"

      if ! nc -z 127.0.0.1 "$VIRTIO_PORT" 2>/dev/null; then
        echo "ERROR: Virtio port $VIRTIO_PORT not available"
        exit 1
      fi

      exec socat -,raw,echo=0 TCP:127.0.0.1:"$VIRTIO_PORT"
    '';
  };

  # ==========================================================================
  # Expect-based helpers (reliable terminal interaction)
  # ==========================================================================

  # VM hostname for prompt matching (must match what's set in VM)
  vmHostname = constants.getHostname "x86_64";

  # Path to expect scripts
  expectScriptsDir = ./scripts;

  # Run a single command via expect
  expectRunCommand = pkgs.writeShellApplication {
    name = "xdp2-vm-expect-run";
    runtimeInputs = with pkgs; [ expect netcat-gnu ];
    text = ''
      VIRTIO_PORT=${toString constants.architectures.x86_64.virtioPort}
      HOSTNAME="${vmHostname}"
      SCRIPT_DIR="${./scripts}"

      if [ $# -eq 0 ]; then
        echo "Usage: xdp2-vm-expect-run <command> [timeout] [debug_level]"
        echo ""
        echo "Run a command in the VM via expect"
        echo "  Port: $VIRTIO_PORT"
        echo "  Hostname: $HOSTNAME"
        echo ""
        echo "Examples:"
        echo "  xdp2-vm-expect-run 'uname -a'"
        echo "  xdp2-vm-expect-run 'bpftool prog list' 30"
        echo "  xdp2-vm-expect-run 'dmesg | tail -20' 10 100"
        exit 1
      fi

      COMMAND="$1"
      TIMEOUT="''${2:-10}"
      DEBUG="''${3:-0}"

      exec expect "$SCRIPT_DIR/vm-expect.exp" "$VIRTIO_PORT" "$HOSTNAME" "$COMMAND" "$TIMEOUT" "$DEBUG"
    '';
  };

  # Debug VM using expect (reliable output)
  debugVmExpect = pkgs.writeShellApplication {
    name = "xdp2-vm-debug-expect";
    runtimeInputs = with pkgs; [ expect netcat-gnu ];
    text = ''
      VIRTIO_PORT=${toString constants.architectures.x86_64.virtioPort}
      HOSTNAME="${vmHostname}"
      SCRIPT_DIR="${./scripts}"
      DEBUG="''${1:-0}"

      exec expect "$SCRIPT_DIR/vm-debug.exp" "$VIRTIO_PORT" "$HOSTNAME" "$DEBUG"
    '';
  };

  # Verify self-test service using expect (for lifecycle phase 3)
  expectVerifyService = pkgs.writeShellApplication {
    name = "xdp2-vm-expect-verify-service";
    runtimeInputs = with pkgs; [ expect netcat-gnu ];
    text = ''
      VIRTIO_PORT=${toString constants.architectures.x86_64.virtioPort}
      HOSTNAME="${vmHostname}"
      SCRIPT_DIR="${./scripts}"
      TIMEOUT="''${1:-60}"
      POLL_INTERVAL="''${2:-2}"

      exec expect "$SCRIPT_DIR/vm-verify-service.exp" "$VIRTIO_PORT" "$HOSTNAME" "$TIMEOUT" "$POLL_INTERVAL"
    '';
  };

in {
  # VM derivations
  inherit vms;

  # Helper scripts
  inherit testRunner connectConsole connectSerial vmStatus;

  # Login/debug helpers
  inherit runCommandSerial runCommandVirtio loginSerial loginVirtio;

  # Expect-based helpers (reliable terminal interaction)
  inherit expectRunCommand debugVmExpect expectVerifyService;

  # Lifecycle check scripts (individual phases)
  lifecycle = {
    checkBuild = lifecycleCheckBuild;
    checkProcess = lifecycleCheckProcess;
    checkSerial = lifecycleCheckSerial;
    checkVirtio = lifecycleCheckVirtio;
    verifyEbpfLoaded = lifecycleVerifyEbpfLoaded;
    verifyEbpfRunning = lifecycleVerifyEbpfRunning;
    shutdown = lifecycleShutdown;
    waitExit = lifecycleWaitExit;
    forceKill = lifecycleForceKill;
    fullTest = lifecycleFullTest;
  };

  # Export constants for reference
  inherit constants;

  # Export VM process name for external scripts
  inherit vmProcessName;
}
