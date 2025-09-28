#!/bin/bash
# analyze_library_paths.sh
# Map library locations and linking configurations

set -e

# Output file
OUTPUT_FILE="library_paths_$(date +%Y%m%d_%H%M%S).txt"

echo "=== Library Paths Analysis ===" > "$OUTPUT_FILE"
echo "Generated: $(date)" >> "$OUTPUT_FILE"
echo "Host: $(hostname)" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"

# System library paths
echo "=== System Library Paths ===" >> "$OUTPUT_FILE"
echo "/lib: $(ls -la /lib 2>/dev/null | wc -l) items" >> "$OUTPUT_FILE"
echo "/usr/lib: $(ls -la /usr/lib 2>/dev/null | wc -l) items" >> "$OUTPUT_FILE"
echo "/usr/local/lib: $(ls -la /usr/local/lib 2>/dev/null | wc -l) items" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"

# Environment library paths
echo "=== Environment Library Paths ===" >> "$OUTPUT_FILE"
echo "LD_LIBRARY_PATH: ${LD_LIBRARY_PATH:-'not set'}" >> "$OUTPUT_FILE"
echo "LIBRARY_PATH: ${LIBRARY_PATH:-'not set'}" >> "$OUTPUT_FILE"
echo "PKG_CONFIG_PATH: ${PKG_CONFIG_PATH:-'not set'}" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"

# Check for specific libraries
echo "=== Key Library Locations ===" >> "$OUTPUT_FILE"
for lib in libboost libpcap libelf libbpf libpython; do
    echo "Searching for $lib..." >> "$OUTPUT_FILE"
    find /lib /usr/lib /usr/local/lib -name "*${lib}*" 2>/dev/null | head -5 | sed 's/^/  /' >> "$OUTPUT_FILE"
    if [ $? -ne 0 ]; then
        echo "  No $lib libraries found" >> "$OUTPUT_FILE"
    fi
done
echo "" >> "$OUTPUT_FILE"

# pkg-config information
echo "=== pkg-config Information ===" >> "$OUTPUT_FILE"
if command -v pkg-config >/dev/null 2>&1; then
    echo "pkg-config: $(command -v pkg-config)" >> "$OUTPUT_FILE"
    echo "Version: $(pkg-config --version)" >> "$OUTPUT_FILE"
    echo "" >> "$OUTPUT_FILE"

    # Check for key packages
    for pkg in boost libpcap libelf libbpf python3; do
        if pkg-config --exists "$pkg" 2>/dev/null; then
            echo "$pkg package found:" >> "$OUTPUT_FILE"
            echo "  Version: $(pkg-config --modversion "$pkg")" >> "$OUTPUT_FILE"
            echo "  Cflags: $(pkg-config --cflags "$pkg")" >> "$OUTPUT_FILE"
            echo "  Libs: $(pkg-config --libs "$pkg")" >> "$OUTPUT_FILE"
        else
            echo "$pkg: NOT FOUND via pkg-config" >> "$OUTPUT_FILE"
        fi
    done
else
    echo "pkg-config: NOT FOUND" >> "$OUTPUT_FILE"
fi
echo "" >> "$OUTPUT_FILE"

# Dynamic linker information
echo "=== Dynamic Linker Information ===" >> "$OUTPUT_FILE"
if [ -f /etc/ld.so.conf ]; then
    echo "ld.so.conf contents:" >> "$OUTPUT_FILE"
    cat /etc/ld.so.conf | sed 's/^/  /' >> "$OUTPUT_FILE"
fi

if [ -d /etc/ld.so.conf.d ]; then
    echo "ld.so.conf.d files:" >> "$OUTPUT_FILE"
    ls -la /etc/ld.so.conf.d/ | sed 's/^/  /' >> "$OUTPUT_FILE"
fi
echo "" >> "$OUTPUT_FILE"

# Check for specific xdp2-related libraries
echo "=== XDP2 Related Libraries ===" >> "$OUTPUT_FILE"
for lib in libxdp2 libcli libsiphash libcrc libflowdis liblzf libmurmur3hash libparselite; do
    echo "Searching for $lib..." >> "$OUTPUT_FILE"
    find /lib /usr/lib /usr/local/lib -name "*${lib}*" 2>/dev/null | head -3 | sed 's/^/  /' >> "$OUTPUT_FILE"
    if [ $? -ne 0 ]; then
        echo "  No $lib libraries found" >> "$OUTPUT_FILE"
    fi
done
echo "" >> "$OUTPUT_FILE"

# Python library paths
echo "=== Python Library Paths ===" >> "$OUTPUT_FILE"
if command -v python3 >/dev/null 2>&1; then
    echo "Python library search paths:" >> "$OUTPUT_FILE"
    python3 -c "import sys; [print('  ' + p) for p in sys.path]" >> "$OUTPUT_FILE"
    echo "" >> "$OUTPUT_FILE"

    echo "Python site-packages:" >> "$OUTPUT_FILE"
    python3 -c "import site; [print('  ' + p) for p in site.getsitepackages()]" >> "$OUTPUT_FILE"
fi
echo "" >> "$OUTPUT_FILE"

echo "Library paths analysis complete. Results saved to: $OUTPUT_FILE"
cat "$OUTPUT_FILE"
