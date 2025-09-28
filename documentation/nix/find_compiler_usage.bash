#!/usr/bin/bash

# Script to find the files with compiler usage within the xdp2 project
#
# This script is intended to find the different compiler usages within the xdp2 project,
# so that the nix development environment can be configured to use the correct compilers.
#
# The script searches for both direct binary usage and variable usage patterns
# that are documented in the "Compiler Usage by File/Directory" table in nix.md

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== XDP2 Compiler Usage Finder ===${NC}"
echo "Searching for compiler usage patterns in the xdp2 project..."
echo

# Direct compiler binary names (as they appear in Makefiles)
list_of_compiler_binaries=("gcc" "clang" "clang++" "g++")

# Makefile variable names (both usage and assignment)
list_of_compiler_variables=("CC" "CXX" "HOST_CC" "HOST_CXX" "XCC")

# Additional compiler-related variables
list_of_compiler_config_vars=("HOST_LLVM_CONFIG" "XDP2_CLANG_VERSION" "XDP2_CLANG_RESOURCE_PATH")

# Function to search for patterns with context
search_with_context() {
    local pattern="$1"
    local description="$2"
    local color="$3"

    echo -e "${color}=== $description ===${NC}"
    echo "Searching for: $pattern"
    echo

    # Search in Makefiles with line numbers and context
    local matches
    matches=$(find . -name "Makefile" -type f -exec grep -Hn "$pattern" {} \; 2>/dev/null)
    if [ -n "$matches" ]; then
        echo "$matches"
        echo -e "${GREEN}Found matches above${NC}"
    else
        echo -e "${YELLOW}No matches found${NC}"
    fi
    echo
}

# Function to search for variable assignments
search_variable_assignments() {
    local var="$1"
    local description="$2"
    local color="$3"

    echo -e "${color}=== $description ===${NC}"
    echo "Searching for variable assignments: $var"
    echo

    # Search for variable assignments (CC=, CC :=, etc.)
    local matches
    matches=$(find . -name "Makefile" -type f -exec grep -Hn "$var\s*[=:]" {} \; 2>/dev/null)
    if [ -n "$matches" ]; then
        echo "$matches"
        echo -e "${GREEN}Found variable assignments above${NC}"
    else
        echo -e "${YELLOW}No variable assignments found${NC}"
    fi
    echo
}

# Function to search for variable usage
search_variable_usage() {
    local var="$1"
    local description="$2"
    local color="$3"

    echo -e "${color}=== $description ===${NC}"
    echo "Searching for variable usage: \$$var"
    echo

    # Search for variable usage ($(CC), $(HOST_CC), etc.)
    if find . -name "Makefile" -type f -exec grep -Hn "\$($var)" {} \; | head -20; then
        echo -e "${GREEN}Found variable usage above${NC}"
    else
        echo -e "${YELLOW}No variable usage found${NC}"
    fi
    echo
}

# Search for direct compiler binary usage
for compiler in "${list_of_compiler_binaries[@]}"; do
    search_with_context "$compiler" "Direct Binary Usage: $compiler" "$YELLOW"
done

# Search for compiler variable assignments
for var in "${list_of_compiler_variables[@]}"; do
    search_variable_assignments "$var" "Variable Assignment: $var" "$GREEN"
done

# Search for compiler variable usage
for var in "${list_of_compiler_variables[@]}"; do
    search_variable_usage "$var" "Variable Usage: $var" "$BLUE"
done

# Search for additional compiler configuration variables
for var in "${list_of_compiler_config_vars[@]}"; do
    search_with_context "$var" "Compiler Config Variable: $var" "$RED"
done

echo -e "${BLUE}=== Summary ===${NC}"
echo "Search completed. The results above show:"
echo "1. Direct compiler binary usage (gcc, clang, etc.)"
echo "2. Compiler variable assignments (CC=, HOST_CC=, etc.)"
echo "3. Compiler variable usage (\$(CC), \$(HOST_CC), etc.)"
echo "4. Compiler configuration variables"
echo
echo "Use this output to update the 'Compiler Usage by File/Directory' table in nix.md"
echo "when the xdp2 project makes changes to compiler usage patterns."