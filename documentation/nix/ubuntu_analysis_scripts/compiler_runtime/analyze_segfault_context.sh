#!/bin/bash
# analyze_segfault_context.sh
# Capture core dumps and stack traces for segfault analysis

set -e

# Output file
OUTPUT_FILE="segfault_context_$(date +%Y%m%d_%H%M%S).txt"

echo "=== Segfault Context Analysis ===" > "$OUTPUT_FILE"
echo "Generated: $(date)" >> "$OUTPUT_FILE"
echo "Host: $(hostname)" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"

# Check if we're in the xdp2 project directory
XDP2_ROOT=""
if [ -f "src/tools/compiler/src/main.cpp" ]; then
    XDP2_ROOT="$(pwd)"
elif [ -f "../../../src/tools/compiler/src/main.cpp" ]; then
    XDP2_ROOT="$(cd ../../../ && pwd)"
elif [ -f "../../../../src/tools/compiler/src/main.cpp" ]; then
    XDP2_ROOT="$(cd ../../../../ && pwd)"
else
    echo "ERROR: Cannot find xdp2 project root directory" >> "$OUTPUT_FILE"
    echo "Please run this script from within the xdp2 project or its subdirectories" >> "$OUTPUT_FILE"
    cat "$OUTPUT_FILE"
    exit 1
fi

echo "XDP2 project root: $XDP2_ROOT" >> "$OUTPUT_FILE"
cd "$XDP2_ROOT"

# Check core dump settings
echo "=== Core Dump Configuration ===" >> "$OUTPUT_FILE"
echo "ulimit -c: $(ulimit -c)" >> "$OUTPUT_FILE"
echo "Core pattern: $(cat /proc/sys/kernel/core_pattern 2>/dev/null || echo 'not accessible')" >> "$OUTPUT_FILE"
echo "Core uses PID: $(cat /proc/sys/kernel/core_uses_pid 2>/dev/null || echo 'not accessible')" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"

# Check for existing core dumps
echo "=== Existing Core Dumps ===" >> "$OUTPUT_FILE"
CORE_FILES=$(find . -name "core*" -o -name "*.core" 2>/dev/null)
if [ -n "$CORE_FILES" ]; then
    echo "Core dump files found:" >> "$OUTPUT_FILE"
    echo "$CORE_FILES" | sed 's/^/  /' >> "$OUTPUT_FILE"

    # Analyze the most recent core dump
    LATEST_CORE=$(echo "$CORE_FILES" | xargs ls -t | head -1)
    if [ -n "$LATEST_CORE" ]; then
        echo "Latest core dump: $LATEST_CORE" >> "$OUTPUT_FILE"
        echo "  Size: $(ls -lh "$LATEST_CORE" | awk '{print $5}')" >> "$OUTPUT_FILE"
        echo "  Modified: $(ls -l "$LATEST_CORE" | awk '{print $6, $7, $8}')" >> "$OUTPUT_FILE"

        # Try to get basic info from core dump
        if command -v file >/dev/null 2>&1; then
            echo "  File type: $(file "$LATEST_CORE")" >> "$OUTPUT_FILE"
        fi
    fi
else
    echo "No core dump files found" >> "$OUTPUT_FILE"
fi
echo "" >> "$OUTPUT_FILE"

# Check for gdb availability
echo "=== GDB Analysis ===" >> "$OUTPUT_FILE"
if command -v gdb >/dev/null 2>&1; then
    echo "gdb available: $(command -v gdb)" >> "$OUTPUT_FILE"
    echo "gdb version: $(gdb --version | head -1)" >> "$OUTPUT_FILE"

    # If we have a core dump and xdp2-compiler, try to analyze
    if [ -n "$LATEST_CORE" ] && [ -f "src/tools/compiler/xdp2-compiler" ]; then
        echo "Attempting gdb analysis of core dump..." >> "$OUTPUT_FILE"

        # Create a gdb script for analysis
        GDB_SCRIPT="/tmp/gdb_analysis_$$.gdb"
        cat > "$GDB_SCRIPT" << 'EOF'
set pagination off
bt
info registers
info proc mappings
info threads
quit
EOF

        # Run gdb analysis
        timeout 30s gdb -batch -x "$GDB_SCRIPT" src/tools/compiler/xdp2-compiler "$LATEST_CORE" 2>&1 | sed 's/^/  /' >> "$OUTPUT_FILE" || {
            echo "  GDB analysis failed or timed out" >> "$OUTPUT_FILE"
        }

        # Clean up
        rm -f "$GDB_SCRIPT"
    else
        echo "Cannot run gdb analysis:" >> "$OUTPUT_FILE"
        if [ -z "$LATEST_CORE" ]; then
            echo "  - No core dump available" >> "$OUTPUT_FILE"
        fi
        if [ ! -f "src/tools/compiler/xdp2-compiler" ]; then
            echo "  - xdp2-compiler not found" >> "$OUTPUT_FILE"
        fi
    fi
else
    echo "gdb: NOT FOUND" >> "$OUTPUT_FILE"
fi
echo "" >> "$OUTPUT_FILE"

# Check system logs for segfault information
echo "=== System Log Analysis ===" >> "$OUTPUT_FILE"
if [ -f /var/log/syslog ]; then
    echo "Recent segfault entries in syslog:" >> "$OUTPUT_FILE"
    grep -i "segfault\|segmentation fault" /var/log/syslog | tail -5 | sed 's/^/  /' >> "$OUTPUT_FILE" || echo "  No segfault entries found" >> "$OUTPUT_FILE"
elif [ -f /var/log/messages ]; then
    echo "Recent segfault entries in messages:" >> "$OUTPUT_FILE"
    grep -i "segfault\|segmentation fault" /var/log/messages | tail -5 | sed 's/^/  /' >> "$OUTPUT_FILE" || echo "  No segfault entries found" >> "$OUTPUT_FILE"
else
    echo "System logs not accessible" >> "$OUTPUT_FILE"
fi
echo "" >> "$OUTPUT_FILE"

# Check for dmesg entries
echo "=== Kernel Messages ===" >> "$OUTPUT_FILE"
if command -v dmesg >/dev/null 2>&1; then
    echo "Recent kernel messages about segfaults:" >> "$OUTPUT_FILE"
    dmesg | grep -i "segfault\|segmentation fault" | tail -5 | sed 's/^/  /' >> "$OUTPUT_FILE" || echo "  No segfault entries found" >> "$OUTPUT_FILE"
else
    echo "dmesg not available" >> "$OUTPUT_FILE"
fi
echo "" >> "$OUTPUT_FILE"

# Memory information
echo "=== Memory Information ===" >> "$OUTPUT_FILE"
if [ -f /proc/meminfo ]; then
    echo "Memory status:" >> "$OUTPUT_FILE"
    grep -E "MemTotal|MemFree|MemAvailable|SwapTotal|SwapFree" /proc/meminfo | sed 's/^/  /' >> "$OUTPUT_FILE"
else
    echo "Memory information not accessible" >> "$OUTPUT_FILE"
fi
echo "" >> "$OUTPUT_FILE"

# Process limits
echo "=== Process Limits ===" >> "$OUTPUT_FILE"
echo "Current process limits:" >> "$OUTPUT_FILE"
ulimit -a | sed 's/^/  /' >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"

# Check for address sanitizer or other debugging tools
echo "=== Debugging Tools Status ===" >> "$OUTPUT_FILE"
if [ -f "src/tools/compiler/xdp2-compiler" ]; then
    echo "xdp2-compiler binary analysis:" >> "$OUTPUT_FILE"

    # Check if binary was compiled with debug symbols
    if command -v objdump >/dev/null 2>&1; then
        if objdump -h src/tools/compiler/xdp2-compiler | grep -q "\.debug"; then
            echo "  Debug symbols: PRESENT" >> "$OUTPUT_FILE"
        else
            echo "  Debug symbols: NOT PRESENT" >> "$OUTPUT_FILE"
        fi
    fi

    # Check for address sanitizer
    if strings src/tools/compiler/xdp2-compiler | grep -q "asan"; then
        echo "  Address sanitizer: ENABLED" >> "$OUTPUT_FILE"
    else
        echo "  Address sanitizer: NOT ENABLED" >> "$OUTPUT_FILE"
    fi

    # Check for other sanitizers
    if strings src/tools/compiler/xdp2-compiler | grep -q "msan\|tsan\|ubsan"; then
        echo "  Other sanitizers: ENABLED" >> "$OUTPUT_FILE"
    else
        echo "  Other sanitizers: NOT ENABLED" >> "$OUTPUT_FILE"
    fi
else
    echo "xdp2-compiler binary not found for analysis" >> "$OUTPUT_FILE"
fi
echo "" >> "$OUTPUT_FILE"

echo "Segfault context analysis complete. Results saved to: $OUTPUT_FILE"
cat "$OUTPUT_FILE"
