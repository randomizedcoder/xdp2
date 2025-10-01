#!/bin/bash
# analyze_compiler_config.sh
# Document compiler flags, paths, and configurations

set -e

# Output file
OUTPUT_FILE="compiler_config_$(date +%Y%m%d_%H%M%S).txt"

echo "=== Compiler Configuration Analysis ===" > "$OUTPUT_FILE"
echo "Generated: $(date)" >> "$OUTPUT_FILE"
echo "Host: $(hostname)" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"

# Check for common compilers
echo "=== Available Compilers ===" >> "$OUTPUT_FILE"
for compiler in gcc g++ clang clang++; do
    if command -v "$compiler" >/dev/null 2>&1; then
        echo "$compiler: $(command -v "$compiler")" >> "$OUTPUT_FILE"
        echo "  Version: $($compiler --version | head -1)" >> "$OUTPUT_FILE"

        # Get compiler flags and paths
        if [[ "$compiler" =~ ^(gcc|g\+\+)$ ]]; then
            echo "  Target: $($compiler -dumpmachine)" >> "$OUTPUT_FILE"
            echo "  Sysroot: $($compiler -print-sysroot 2>/dev/null || echo 'not available')" >> "$OUTPUT_FILE"
        fi

        if [[ "$compiler" =~ ^(clang|clang\+\+)$ ]]; then
            echo "  Target: $($compiler -dumpmachine)" >> "$OUTPUT_FILE"
            echo "  Resource Dir: $($compiler -print-resource-dir 2>/dev/null || echo 'not available')" >> "$OUTPUT_FILE"
        fi
    else
        echo "$compiler: NOT FOUND" >> "$OUTPUT_FILE"
    fi
done
echo "" >> "$OUTPUT_FILE"

# Environment variables
echo "=== Compiler Environment Variables ===" >> "$OUTPUT_FILE"
for var in CC CXX HOST_CC HOST_CXX CFLAGS CXXFLAGS CPPFLAGS LDFLAGS; do
    if [ -n "${!var}" ]; then
        echo "$var: ${!var}" >> "$OUTPUT_FILE"
    else
        echo "$var: not set" >> "$OUTPUT_FILE"
    fi
done
echo "" >> "$OUTPUT_FILE"

# Include paths
echo "=== Include Paths ===" >> "$OUTPUT_FILE"
if command -v gcc >/dev/null 2>&1; then
    echo "GCC include paths:" >> "$OUTPUT_FILE"
    gcc -E -v -x c - < /dev/null 2>&1 | grep -E "^ /" | sed 's/^/  /' >> "$OUTPUT_FILE"
fi
echo "" >> "$OUTPUT_FILE"

# Library paths
echo "=== Library Paths ===" >> "$OUTPUT_FILE"
if command -v gcc >/dev/null 2>&1; then
    echo "GCC library paths:" >> "$OUTPUT_FILE"
    gcc -print-search-dirs 2>/dev/null | grep libraries | sed 's/libraries: =/  /' | tr ':' '\n' | sed 's/^/    /' >> "$OUTPUT_FILE"
fi
echo "" >> "$OUTPUT_FILE"

# LLVM/Clang specific
echo "=== LLVM/Clang Configuration ===" >> "$OUTPUT_FILE"
if command -v llvm-config >/dev/null 2>&1; then
    echo "llvm-config: $(command -v llvm-config)" >> "$OUTPUT_FILE"
    echo "  Version: $(llvm-config --version)" >> "$OUTPUT_FILE"
    echo "  Prefix: $(llvm-config --prefix)" >> "$OUTPUT_FILE"
    echo "  Include Dir: $(llvm-config --includedir)" >> "$OUTPUT_FILE"
    echo "  Library Dir: $(llvm-config --libdir)" >> "$OUTPUT_FILE"
else
    echo "llvm-config: NOT FOUND" >> "$OUTPUT_FILE"
fi
echo "" >> "$OUTPUT_FILE"

# Python development
echo "=== Python Development Configuration ===" >> "$OUTPUT_FILE"
if command -v python3 >/dev/null 2>&1; then
    echo "Python development paths:" >> "$OUTPUT_FILE"
    python3 -c "import sysconfig; print('  Include dir:', sysconfig.get_path('include'))" >> "$OUTPUT_FILE"
    python3 -c "import sysconfig; print('  Library dir:', sysconfig.get_path('stdlib'))" >> "$OUTPUT_FILE"
    python3 -c "import sysconfig; print('  Config dir:', sysconfig.get_path('platlib'))" >> "$OUTPUT_FILE"
fi
echo "" >> "$OUTPUT_FILE"

echo "Compiler configuration analysis complete. Results saved to: $OUTPUT_FILE"
cat "$OUTPUT_FILE"
