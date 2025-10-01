#!/bin/bash
# analyze_package_versions.sh
# Extract exact versions of all installed packages relevant to xdp2

set -e

# Output file
OUTPUT_FILE="package_versions_$(date +%Y%m%d_%H%M%S).txt"

echo "=== Package Versions Analysis ===" > "$OUTPUT_FILE"
echo "Generated: $(date)" >> "$OUTPUT_FILE"
echo "Host: $(hostname)" >> "$OUTPUT_FILE"
echo "OS: $(lsb_release -d 2>/dev/null | cut -f2 || uname -a)" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"

# Core build packages
echo "=== Core Build Packages ===" >> "$OUTPUT_FILE"
for pkg in build-essential gcc g++ clang clang++ make cmake pkg-config; do
    if command -v "$pkg" >/dev/null 2>&1; then
        echo "$pkg: $(command -v "$pkg")" >> "$OUTPUT_FILE"
        if [[ "$pkg" =~ ^(gcc|g\+\+|clang|clang\+\+)$ ]]; then
            echo "  Version: $($pkg --version | head -1)" >> "$OUTPUT_FILE"
        fi
    else
        echo "$pkg: NOT FOUND" >> "$OUTPUT_FILE"
    fi
done
echo "" >> "$OUTPUT_FILE"

# Development libraries
echo "=== Development Libraries ===" >> "$OUTPUT_FILE"
for pkg in libboost-all-dev libpcap-dev libelf-dev libbpf-dev; do
    if dpkg -l "$pkg" 2>/dev/null | grep -q "^ii"; then
        VERSION=$(dpkg -l "$pkg" | grep "^ii" | awk '{print $3}')
        echo "$pkg: $VERSION" >> "$OUTPUT_FILE"
    else
        echo "$pkg: NOT INSTALLED" >> "$OUTPUT_FILE"
    fi
done
echo "" >> "$OUTPUT_FILE"

# LLVM/Clang packages
echo "=== LLVM/Clang Packages ===" >> "$OUTPUT_FILE"
for pkg in llvm llvm-dev libclang-dev clang-tools; do
    if dpkg -l "$pkg" 2>/dev/null | grep -q "^ii"; then
        VERSION=$(dpkg -l "$pkg" | grep "^ii" | awk '{print $3}')
        echo "$pkg: $VERSION" >> "$OUTPUT_FILE"
    else
        echo "$pkg: NOT INSTALLED" >> "$OUTPUT_FILE"
    fi
done
echo "" >> "$OUTPUT_FILE"

# Python packages
echo "=== Python Packages ===" >> "$OUTPUT_FILE"
if command -v python3 >/dev/null 2>&1; then
    echo "python3: $(command -v python3)" >> "$OUTPUT_FILE"
    echo "  Version: $(python3 --version)" >> "$OUTPUT_FILE"
    echo "  Path: $(python3 -c 'import sys; print(sys.executable)')" >> "$OUTPUT_FILE"

    # Check for scapy
    if python3 -c "import scapy" 2>/dev/null; then
        SCAPY_VERSION=$(python3 -c "import scapy; print(scapy.__version__)")
        echo "  scapy: $SCAPY_VERSION" >> "$OUTPUT_FILE"
    else
        echo "  scapy: NOT AVAILABLE" >> "$OUTPUT_FILE"
    fi
else
    echo "python3: NOT FOUND" >> "$OUTPUT_FILE"
fi
echo "" >> "$OUTPUT_FILE"

# Kernel tools
echo "=== Kernel Tools ===" >> "$OUTPUT_FILE"
KERNEL_VERSION=$(uname -r)
echo "Kernel version: $KERNEL_VERSION" >> "$OUTPUT_FILE"

if dpkg -l "linux-tools-$KERNEL_VERSION" 2>/dev/null | grep -q "^ii"; then
    VERSION=$(dpkg -l "linux-tools-$KERNEL_VERSION" | grep "^ii" | awk '{print $3}')
    echo "linux-tools-$KERNEL_VERSION: $VERSION" >> "$OUTPUT_FILE"
else
    echo "linux-tools-$KERNEL_VERSION: NOT INSTALLED" >> "$OUTPUT_FILE"
fi
echo "" >> "$OUTPUT_FILE"

# Additional tools
echo "=== Additional Tools ===" >> "$OUTPUT_FILE"
for tool in bison flex graphviz tar xz git; do
    if command -v "$tool" >/dev/null 2>&1; then
        echo "$tool: $(command -v "$tool")" >> "$OUTPUT_FILE"
        if [[ "$tool" =~ ^(bison|flex|graphviz|git)$ ]]; then
            echo "  Version: $($tool --version | head -1)" >> "$OUTPUT_FILE"
        fi
    else
        echo "$tool: NOT FOUND" >> "$OUTPUT_FILE"
    fi
done
echo "" >> "$OUTPUT_FILE"

# Library paths
echo "=== Library Search Paths ===" >> "$OUTPUT_FILE"
echo "LD_LIBRARY_PATH: ${LD_LIBRARY_PATH:-'not set'}" >> "$OUTPUT_FILE"
echo "PKG_CONFIG_PATH: ${PKG_CONFIG_PATH:-'not set'}" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"

# System information
echo "=== System Information ===" >> "$OUTPUT_FILE"
echo "Architecture: $(uname -m)" >> "$OUTPUT_FILE"
echo "Distribution: $(lsb_release -si 2>/dev/null || echo 'Unknown')" >> "$OUTPUT_FILE"
echo "Release: $(lsb_release -sr 2>/dev/null || echo 'Unknown')" >> "$OUTPUT_FILE"
echo "Codename: $(lsb_release -sc 2>/dev/null || echo 'Unknown')" >> "$OUTPUT_FILE"

echo "Package versions analysis complete. Results saved to: $OUTPUT_FILE"
cat "$OUTPUT_FILE"
