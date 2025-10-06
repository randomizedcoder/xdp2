#!/bin/bash
set -e

echo "🧪 Simple XDP2 Development Shell Test"
echo "====================================="

# Test 1: Basic shell entry
echo "Test 1: Basic shell entry"
if echo "exit" | nix develop --no-write-lock-file 2>/dev/null >/dev/null; then
    echo "✅ Shell entry works"
else
    echo "❌ Shell entry failed"
    exit 1
fi

# Test 2: Flake validation
echo "Test 2: Flake validation"
if nix flake check --no-write-lock-file 2>/dev/null; then
    echo "✅ Flake validation passes"
else
    echo "❌ Flake validation failed"
    exit 1
fi

# Test 3: Environment variables
echo "Test 3: Environment variables"
if echo "echo \$CC; exit" | nix develop --no-write-lock-file 2>/dev/null | grep -q "gcc"; then
    echo "✅ Environment variables set correctly"
else
    echo "❌ Environment variables not set correctly"
    exit 1
fi

# Test 4: Build functions available
echo "Test 4: Build functions available"
if echo "type build-cppfront; exit" | nix develop --no-write-lock-file 2>/dev/null | grep -q "function"; then
    echo "✅ Build functions are available"
else
    echo "❌ Build functions not available"
    exit 1
fi

# Test 5: Aliases available
echo "Test 5: Aliases available"
if echo "type xdp2-build; exit" | nix develop --no-write-lock-file 2>/dev/null | grep -q "alias"; then
    echo "✅ Aliases are available"
else
    echo "❌ Aliases not available"
    exit 1
fi

echo ""
echo "🎉 All basic tests passed! The development shell is working correctly."
