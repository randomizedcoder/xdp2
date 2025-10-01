#!/bin/bash
# analyze_memory_layout.sh
# Compare memory layouts between environments

set -e

# Output file
OUTPUT_FILE="memory_layout_$(date +%Y%m%d_%H%M%S).txt"

echo "=== Memory Layout Analysis ===" > "$OUTPUT_FILE"
echo "Generated: $(date)" >> "$OUTPUT_FILE"
echo "Host: $(hostname)" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"

# System memory information
echo "=== System Memory Information ===" >> "$OUTPUT_FILE"
if [ -f /proc/meminfo ]; then
    echo "Memory details:" >> "$OUTPUT_FILE"
    cat /proc/meminfo | sed 's/^/  /' >> "$OUTPUT_FILE"
else
    echo "Memory information not accessible" >> "$OUTPUT_FILE"
fi
echo "" >> "$OUTPUT_FILE"

# Virtual memory statistics
echo "=== Virtual Memory Statistics ===" >> "$OUTPUT_FILE"
if [ -f /proc/vmstat ]; then
    echo "VM statistics:" >> "$OUTPUT_FILE"
    cat /proc/vmstat | sed 's/^/  /' >> "$OUTPUT_FILE"
else
    echo "VM statistics not accessible" >> "$OUTPUT_FILE"
fi
echo "" >> "$OUTPUT_FILE"

# Memory mapping information
echo "=== Memory Mapping Information ===" >> "$OUTPUT_FILE"
if [ -f /proc/self/maps ]; then
    echo "Current process memory maps:" >> "$OUTPUT_FILE"
    head -20 /proc/self/maps | sed 's/^/  /' >> "$OUTPUT_FILE"
    echo "  ... (showing first 20 entries)" >> "$OUTPUT_FILE"
else
    echo "Memory maps not accessible" >> "$OUTPUT_FILE"
fi
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
    echo "XDP2 project root not found - skipping binary analysis" >> "$OUTPUT_FILE"
    cat "$OUTPUT_FILE"
    exit 0
fi

echo "XDP2 project root: $XDP2_ROOT" >> "$OUTPUT_FILE"
cd "$XDP2_ROOT"

# Analyze xdp2-compiler binary memory layout
echo "=== xdp2-compiler Binary Memory Layout ===" >> "$OUTPUT_FILE"
if [ -f "src/tools/compiler/xdp2-compiler" ]; then
    echo "Binary found: src/tools/compiler/xdp2-compiler" >> "$OUTPUT_FILE"

    # Get binary sections
    if command -v objdump >/dev/null 2>&1; then
        echo "Binary sections:" >> "$OUTPUT_FILE"
        objdump -h src/tools/compiler/xdp2-compiler | sed 's/^/  /' >> "$OUTPUT_FILE"
    fi

    # Get symbol table
    if command -v nm >/dev/null 2>&1; then
        echo "Symbol table (first 20 entries):" >> "$OUTPUT_FILE"
        nm src/tools/compiler/xdp2-compiler | head -20 | sed 's/^/  /' >> "$OUTPUT_FILE"
    fi

    # Check for Python symbols
    if command -v strings >/dev/null 2>&1; then
        echo "Python-related strings in binary:" >> "$OUTPUT_FILE"
        strings src/tools/compiler/xdp2-compiler | grep -i python | head -10 | sed 's/^/  /' >> "$OUTPUT_FILE" || echo "  No Python strings found" >> "$OUTPUT_FILE"
    fi

else
    echo "xdp2-compiler binary not found" >> "$OUTPUT_FILE"
fi
echo "" >> "$OUTPUT_FILE"

# Process memory limits
echo "=== Process Memory Limits ===" >> "$OUTPUT_FILE"
echo "Current process limits:" >> "$OUTPUT_FILE"
ulimit -a | grep -E "(memory|stack|data)" | sed 's/^/  /' >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"

# Check for address space layout randomization
echo "=== Address Space Layout Randomization ===" >> "$OUTPUT_FILE"
if [ -f /proc/sys/kernel/randomize_va_space ]; then
    ASLR_VALUE=$(cat /proc/sys/kernel/randomize_va_space)
    echo "ASLR setting: $ASLR_VALUE" >> "$OUTPUT_FILE"
    case $ASLR_VALUE in
        0) echo "  ASLR: DISABLED" >> "$OUTPUT_FILE" ;;
        1) echo "  ASLR: CONSERVATIVE (stack, vdso, heap)" >> "$OUTPUT_FILE" ;;
        2) echo "  ASLR: FULL (stack, vdso, heap, mmap, brk)" >> "$OUTPUT_FILE" ;;
        *) echo "  ASLR: UNKNOWN VALUE" >> "$OUTPUT_FILE" ;;
    esac
else
    echo "ASLR setting not accessible" >> "$OUTPUT_FILE"
fi
echo "" >> "$OUTPUT_FILE"

# Check for memory protection features
echo "=== Memory Protection Features ===" >> "$OUTPUT_FILE"
if [ -f /proc/cpuinfo ]; then
    echo "CPU features related to memory protection:" >> "$OUTPUT_FILE"
    grep -E "(nx|smep|smap|pae)" /proc/cpuinfo | head -5 | sed 's/^/  /' >> "$OUTPUT_FILE" || echo "  No memory protection features found" >> "$OUTPUT_FILE"
fi
echo "" >> "$OUTPUT_FILE"

# Library loading information
echo "=== Library Loading Information ===" >> "$OUTPUT_FILE"
if [ -f /etc/ld.so.conf ]; then
    echo "Dynamic linker configuration:" >> "$OUTPUT_FILE"
    cat /etc/ld.so.conf | sed 's/^/  /' >> "$OUTPUT_FILE"
fi

if [ -d /etc/ld.so.conf.d ]; then
    echo "Additional linker configuration files:" >> "$OUTPUT_FILE"
    ls -la /etc/ld.so.conf.d/ | sed 's/^/  /' >> "$OUTPUT_FILE"
fi
echo "" >> "$OUTPUT_FILE"

# Check for memory-related environment variables
echo "=== Memory-Related Environment Variables ===" >> "$OUTPUT_FILE"
for var in MALLOC_CHECK_ MALLOC_PERTURB_ MALLOC_TRIM_THRESHOLD_ MALLOC_MMAP_THRESHOLD_ MALLOC_MMAP_MAX_; do
    if [ -n "${!var}" ]; then
        echo "$var: ${!var}" >> "$OUTPUT_FILE"
    fi
done
echo "" >> "$OUTPUT_FILE"

# Check for Python memory-related settings
echo "=== Python Memory Settings ===" >> "$OUTPUT_FILE"
if command -v python3 >/dev/null 2>&1; then
    echo "Python memory-related information:" >> "$OUTPUT_FILE"
    python3 -c "import sys; print('  Max recursion depth:', sys.getrecursionlimit())" >> "$OUTPUT_FILE"
    python3 -c "import resource; print('  Memory limit:', resource.getrlimit(resource.RLIMIT_AS))" >> "$OUTPUT_FILE"
    python3 -c "import resource; print('  Data limit:', resource.getrlimit(resource.RLIMIT_DATA))" >> "$OUTPUT_FILE"
    python3 -c "import resource; print('  Stack limit:', resource.getrlimit(resource.RLIMIT_STACK))" >> "$OUTPUT_FILE"
fi
echo "" >> "$OUTPUT_FILE"

echo "Memory layout analysis complete. Results saved to: $OUTPUT_FILE"
cat "$OUTPUT_FILE"
