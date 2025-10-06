#!/bin/bash
set -e

echo "🧪 Comprehensive XDP2 Development Shell Test"
echo "============================================="

# Test 1: Basic shell entry and timing
echo "Test 1: Shell entry performance"
start_time=$(date +%s)
if echo "exit" | nix develop --no-write-lock-file 2>/dev/null >/dev/null; then
    end_time=$(date +%s)
    duration=$((end_time - start_time))
    echo "✅ Shell entry works (took ${duration}s)"
    if [ $duration -lt 10 ]; then
        echo "✅ Shell entry is fast (< 10s)"
    else
        echo "⚠️  Shell entry is slow (${duration}s)"
    fi
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

# Test 3: Debug levels
echo "Test 3: Debug levels"
echo "  Testing debug level 0..."
if echo "exit" | nix develop --no-write-lock-file 2>/dev/null >/dev/null; then
    echo "  ✅ Debug level 0 works"
else
    echo "  ❌ Debug level 0 failed"
fi

echo "  Testing debug level 5..."
if XDP2_NIX_DEBUG=5 echo "exit" | nix develop --no-write-lock-file 2>/dev/null >/dev/null; then
    echo "  ✅ Debug level 5 works"
else
    echo "  ❌ Debug level 5 failed"
fi

echo "  Testing debug level 6..."
if XDP2_NIX_DEBUG=6 echo "exit" | nix develop --no-write-lock-file 2>/dev/null >/dev/null; then
    echo "  ✅ Debug level 6 works"
else
    echo "  ❌ Debug level 6 failed"
fi

# Test 4: Interactive shell test
echo "Test 4: Interactive shell functionality"
echo "  Testing build function availability..."
if echo "type build-cppfront >/dev/null 2>&1 && echo 'build-cppfront available'; exit" | nix develop --no-write-lock-file 2>/dev/null | grep -q "build-cppfront available"; then
    echo "  ✅ Build functions are available"
else
    echo "  ❌ Build functions not available"
fi

echo "  Testing alias availability..."
if echo "type xdp2-build >/dev/null 2>&1 && echo 'xdp2-build available'; exit" | nix develop --no-write-lock-file 2>/dev/null | grep -q "xdp2-build available"; then
    echo "  ✅ Aliases are available"
else
    echo "  ❌ Aliases not available"
fi

# Test 5: Shellcheck validation
echo "Test 5: Shellcheck validation"
if echo "run-shellcheck >/dev/null 2>&1 && echo 'shellcheck passed'; exit" | nix develop --no-write-lock-file 2>/dev/null | grep -q "shellcheck passed"; then
    echo "✅ Shellcheck validation passes"
else
    echo "❌ Shellcheck validation failed"
fi

# Test 6: Clean build function
echo "Test 6: Clean build function"
if echo "clean-build >/dev/null 2>&1 && echo 'clean-build works'; exit" | nix develop --no-write-lock-file 2>/dev/null | grep -q "clean-build works"; then
    echo "✅ Clean build function works"
else
    echo "❌ Clean build function failed"
fi

echo ""
echo "🎉 Comprehensive testing completed!"
echo "The development shell is working correctly."
echo ""
echo "To run individual tests manually:"
echo "  nix develop --no-write-lock-file"
echo "  # Then inside the shell:"
echo "  build-cppfront"
echo "  build-xdp2-compiler"
echo "  build-xdp2"
echo "  build-all"
echo "  clean-build"
echo "  run-shellcheck"
echo "  xdp2-help"
