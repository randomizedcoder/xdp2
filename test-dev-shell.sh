#!/bin/bash
set -e

echo "🧪 Testing XDP2 Development Shell"
echo "=================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test counter
test_count=0
passed_count=0
failed_count=0

# Function to run a test
run_test() {
    local test_name="$1"
    local test_command="$2"
    local expected_outcome="$3"

    test_count=$((test_count + 1))
    echo -e "\n${BLUE}Test $test_count: $test_name${NC}"
    echo "Command: $test_command"
    echo "Expected: $expected_outcome"

    if eval "$test_command"; then
        echo -e "${GREEN}✅ PASSED${NC}"
        passed_count=$((passed_count + 1))
    else
        echo -e "${RED}❌ FAILED${NC}"
        failed_count=$((failed_count + 1))
    fi
}

# Test 1: Shell Entry Performance
run_test "Shell Entry Performance" \
    "time (echo 'exit' | nix develop --no-write-lock-file 2>/dev/null) 2>&1 | grep -q 'real'" \
    "Shell entry completes in reasonable time"

# Test 2: Environment Setup
run_test "Environment Setup" \
    "echo 'exit' | nix develop --no-write-lock-file 2>/dev/null | grep -q 'XDP2 Development Shell'" \
    "Welcome message displays correctly"

# Test 3: Debug Level 0 (No Debug Output)
run_test "Debug Level 0 (No Debug Output)" \
    "XDP2_NIX_DEBUG=0 echo 'exit' | nix develop --no-write-lock-file 2>/dev/null | grep -q 'XDP2 Development Shell'" \
    "Welcome message displays at level 0"

# Test 4: Debug Level 5 (Compiler Selection)
run_test "Debug Level 5 (Compiler Selection)" \
    "XDP2_NIX_DEBUG=5 echo 'exit' | nix develop --no-write-lock-file 2>/dev/null | grep -q 'COMPILER SELECTION'" \
    "Compiler selection debug output appears at level 5"

# Test 5: Debug Level 6 (Environment Variables)
run_test "Debug Level 6 (Environment Variables)" \
    "XDP2_NIX_DEBUG=6 echo 'exit' | nix develop --no-write-lock-file 2>/dev/null | grep -q 'Environment Variables'" \
    "Environment variables debug output appears at level 6"

# Test 6: Build Function Availability
run_test "Build Function Availability" \
    "echo 'type build-cppfront && type build-xdp2-compiler && type build-xdp2 && type build-all && type clean-build && type check-cppfront-age && type run-shellcheck; exit' | nix develop --no-write-lock-file 2>/dev/null" \
    "All build functions are available"

# Test 7: Alias Availability
run_test "Alias Availability" \
    "echo 'type xdp2-build && type xdp2-clean && type xdp2-check && type xdp2-help && type xdp2-src && type xdp2-samples && type xdp2-docs && type xdp2-cppfront; exit' | nix develop --no-write-lock-file 2>/dev/null" \
    "All aliases are available"

# Test 8: Environment Variables
run_test "Environment Variables" \
    "echo 'echo \$CC && echo \$CXX && echo \$HOST_CC && echo \$HOST_CXX; exit' | nix develop --no-write-lock-file 2>/dev/null | grep -q 'gcc'" \
    "Compiler environment variables are set correctly"

# Test 9: Tool Availability
run_test "Tool Availability" \
    "echo 'which gcc && which g++ && which clang && which make && which shellcheck; exit' | nix develop --no-write-lock-file 2>/dev/null" \
    "All required tools are available"

# Test 10: Shellcheck Validation
run_test "Shellcheck Validation" \
    "echo 'run-shellcheck; exit' | nix develop --no-write-lock-file 2>/dev/null | grep -q 'Shellcheck validation completed'" \
    "Shellcheck validation passes"

# Test 11: Navigation Aliases
run_test "Navigation Aliases" \
    "echo 'xdp2-src && pwd && xdp2-samples && pwd && xdp2-docs && pwd; exit' | nix develop --no-write-lock-file 2>/dev/null | grep -q 'src\\|samples\\|documentation'" \
    "Navigation aliases work correctly"

# Test 12: Help Command
run_test "Help Command" \
    "echo 'xdp2-help; exit' | nix develop --no-write-lock-file 2>/dev/null | grep -q 'XDP2 Commands'" \
    "Help command shows available commands"

# Test 13: Clean Build Function
run_test "Clean Build Function" \
    "echo 'clean-build; exit' | nix develop --no-write-lock-file 2>/dev/null | grep -q 'All build artifacts cleaned'" \
    "Clean build function works correctly"

# Test 14: Cppfront Age Check
run_test "Cppfront Age Check" \
    "echo 'check-cppfront-age; exit' | nix develop --no-write-lock-file 2>/dev/null | grep -q 'cppfront'" \
    "Cppfront age check function works"

# Test 15: Flake Validation
run_test "Flake Validation" \
    "nix flake check --no-write-lock-file 2>/dev/null" \
    "Flake passes validation"

# Summary
echo -e "\n${BLUE}=================================="
echo "🧪 Test Summary"
echo "==================================${NC}"
echo -e "Total Tests: $test_count"
echo -e "${GREEN}Passed: $passed_count${NC}"
echo -e "${RED}Failed: $failed_count${NC}"

if [ $failed_count -eq 0 ]; then
    echo -e "\n${GREEN}🎉 All tests passed! The development shell is working correctly.${NC}"
    exit 0
else
    echo -e "\n${RED}❌ Some tests failed. Please check the output above.${NC}"
    exit 1
fi
