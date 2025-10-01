#!/bin/bash
# analyze_compiler_runtime.sh
# Test xdp2-compiler with debug flags and runtime analysis

set -e

# Output file
OUTPUT_FILE="compiler_runtime_$(date +%Y%m%d_%H%M%S).txt"

echo "=== xdp2-compiler Runtime Analysis ===" > "$OUTPUT_FILE"
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

# Check if xdp2-compiler exists
echo "=== xdp2-compiler Binary Analysis ===" >> "$OUTPUT_FILE"
if [ -f "src/tools/compiler/xdp2-compiler" ]; then
    echo "xdp2-compiler found: $(pwd)/src/tools/compiler/xdp2-compiler" >> "$OUTPUT_FILE"

    # Get binary information
    echo "Binary information:" >> "$OUTPUT_FILE"
    echo "  Size: $(ls -lh src/tools/compiler/xdp2-compiler | awk '{print $5}')" >> "$OUTPUT_FILE"
    echo "  Permissions: $(ls -l src/tools/compiler/xdp2-compiler | awk '{print $1}')" >> "$OUTPUT_FILE"
    echo "  Last modified: $(ls -l src/tools/compiler/xdp2-compiler | awk '{print $6, $7, $8}')" >> "$OUTPUT_FILE"

    # Check if it's executable
    if [ -x "src/tools/compiler/xdp2-compiler" ]; then
        echo "  Executable: YES" >> "$OUTPUT_FILE"

        # Get help output
        echo "  Help output:" >> "$OUTPUT_FILE"
        timeout 10s ./src/tools/compiler/xdp2-compiler --help 2>&1 | sed 's/^/    /' >> "$OUTPUT_FILE" || echo "    Help command failed or timed out" >> "$OUTPUT_FILE"

        # Check dependencies
        echo "  Dependencies:" >> "$OUTPUT_FILE"
        if command -v ldd >/dev/null 2>&1; then
            ldd src/tools/compiler/xdp2-compiler | sed 's/^/    /' >> "$OUTPUT_FILE"
        else
            echo "    ldd not available" >> "$OUTPUT_FILE"
        fi

    else
        echo "  Executable: NO" >> "$OUTPUT_FILE"
    fi
else
    echo "xdp2-compiler: NOT FOUND" >> "$OUTPUT_FILE"
    echo "Expected location: $(pwd)/src/tools/compiler/xdp2-compiler" >> "$OUTPUT_FILE"
fi
echo "" >> "$OUTPUT_FILE"

# Check for test files
echo "=== Test Files Analysis ===" >> "$OUTPUT_FILE"
TEST_PARSER_DIR="src/test/parser"
if [ -d "$TEST_PARSER_DIR" ]; then
    echo "Test parser directory found: $TEST_PARSER_DIR" >> "$OUTPUT_FILE"

    # Look for parser.c files
    PARSER_FILES=$(find "$TEST_PARSER_DIR" -name "parser.c" 2>/dev/null)
    if [ -n "$PARSER_FILES" ]; then
        echo "Parser.c files found:" >> "$OUTPUT_FILE"
        echo "$PARSER_FILES" | sed 's/^/  /' >> "$OUTPUT_FILE"

        # Try to find a simple parser for testing
        SIMPLE_PARSER=""
        for parser in $PARSER_FILES; do
            # Look for a simple parser (smaller file size)
            if [ -z "$SIMPLE_PARSER" ] || [ $(stat -c%s "$parser") -lt $(stat -c%s "$SIMPLE_PARSER") ]; then
                SIMPLE_PARSER="$parser"
            fi
        done

        if [ -n "$SIMPLE_PARSER" ]; then
            echo "Selected simple parser for testing: $SIMPLE_PARSER" >> "$OUTPUT_FILE"
            echo "  Size: $(stat -c%s "$SIMPLE_PARSER") bytes" >> "$OUTPUT_FILE"
        fi
    else
        echo "No parser.c files found in test directory" >> "$OUTPUT_FILE"
    fi
else
    echo "Test parser directory not found: $TEST_PARSER_DIR" >> "$OUTPUT_FILE"
fi
echo "" >> "$OUTPUT_FILE"

# Environment analysis
echo "=== Runtime Environment Analysis ===" >> "$OUTPUT_FILE"
echo "Current working directory: $(pwd)" >> "$OUTPUT_FILE"
echo "PATH: $PATH" >> "$OUTPUT_FILE"
echo "LD_LIBRARY_PATH: ${LD_LIBRARY_PATH:-'not set'}" >> "$OUTPUT_FILE"
echo "PYTHONPATH: ${PYTHONPATH:-'not set'}" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"

# Check for debugging tools
echo "=== Debugging Tools Availability ===" >> "$OUTPUT_FILE"
for tool in gdb valgrind strace ltrace; do
    if command -v "$tool" >/dev/null 2>&1; then
        echo "$tool: $(command -v "$tool")" >> "$OUTPUT_FILE"
        echo "  Version: $($tool --version 2>&1 | head -1)" >> "$OUTPUT_FILE"
    else
        echo "$tool: NOT FOUND" >> "$OUTPUT_FILE"
    fi
done
echo "" >> "$OUTPUT_FILE"

# Test basic xdp2-compiler functionality (if available)
if [ -x "src/tools/compiler/xdp2-compiler" ] && [ -n "$SIMPLE_PARSER" ]; then
    echo "=== Basic Functionality Test ===" >> "$OUTPUT_FILE"
    echo "Testing xdp2-compiler with simple parser..." >> "$OUTPUT_FILE"

    # Create a temporary output directory
    TEMP_DIR="/tmp/xdp2_test_$$"
    mkdir -p "$TEMP_DIR"

    # Try to run xdp2-compiler with timeout
    echo "Command: ./src/tools/compiler/xdp2-compiler -I src/include -o $TEMP_DIR/test_output.c -i $SIMPLE_PARSER" >> "$OUTPUT_FILE"

    timeout 30s ./src/tools/compiler/xdp2-compiler -I src/include -o "$TEMP_DIR/test_output.c" -i "$SIMPLE_PARSER" 2>&1 | sed 's/^/  /' >> "$OUTPUT_FILE" || {
        EXIT_CODE=$?
        if [ $EXIT_CODE -eq 124 ]; then
            echo "  RESULT: TIMEOUT (30 seconds)" >> "$OUTPUT_FILE"
        elif [ $EXIT_CODE -eq 139 ]; then
            echo "  RESULT: SEGMENTATION FAULT (exit code 139)" >> "$OUTPUT_FILE"
        else
            echo "  RESULT: FAILED (exit code $EXIT_CODE)" >> "$OUTPUT_FILE"
        fi
    }

    # Check if output was generated
    if [ -f "$TEMP_DIR/test_output.c" ]; then
        echo "  Output file generated: YES" >> "$OUTPUT_FILE"
        echo "  Output size: $(stat -c%s "$TEMP_DIR/test_output.c") bytes" >> "$OUTPUT_FILE"
    else
        echo "  Output file generated: NO" >> "$OUTPUT_FILE"
    fi

    # Clean up
    rm -rf "$TEMP_DIR"
else
    echo "=== Basic Functionality Test ===" >> "$OUTPUT_FILE"
    echo "Cannot test xdp2-compiler functionality:" >> "$OUTPUT_FILE"
    if [ ! -x "src/tools/compiler/xdp2-compiler" ]; then
        echo "  - xdp2-compiler not found or not executable" >> "$OUTPUT_FILE"
    fi
    if [ -z "$SIMPLE_PARSER" ]; then
        echo "  - No test parser files found" >> "$OUTPUT_FILE"
    fi
fi
echo "" >> "$OUTPUT_FILE"

echo "Compiler runtime analysis complete. Results saved to: $OUTPUT_FILE"
cat "$OUTPUT_FILE"
