#!/usr/bin/env bash

# Test script to debug Boost.System compilation issues
# Based on the check_boostsystem() function from src/configure

echo "=== Boost.System Debug Test ==="
echo "Testing Boost.System compilation in Nix environment"
echo

# Create temporary directory
TMPDIR=$(mktemp -d)
echo "Using temporary directory: $TMPDIR"
echo

# Create the test program (same as check_boostsystem)
echo "Creating test program..."
cat >$TMPDIR/systemtest.cpp <<EOF
#include <boost/system/error_code.hpp>

int main(int argc, char **argv)
{
	{
		boost::system::error_code ec;
	}
	return (0);
}
EOF

echo "Test program created at: $TMPDIR/systemtest.cpp"
echo "Contents:"
cat $TMPDIR/systemtest.cpp
echo

# Check environment variables
echo "=== Environment Variables ==="
echo "HOST_CXX: ${HOST_CXX:-'not set'}"
echo "CC: ${CC:-'not set'}"
echo "CXX: ${CXX:-'not set'}"
echo "PKG_CONFIG_PATH: ${PKG_CONFIG_PATH:-'not set'}"
echo "LD_LIBRARY_PATH: ${LD_LIBRARY_PATH:-'not set'}"

# Set default compiler if not set
if [ -z "$HOST_CXX" ]; then
    if command -v clang++ >/dev/null 2>&1; then
        HOST_CXX=clang++
        echo "Using default HOST_CXX: clang++"
    elif command -v g++ >/dev/null 2>&1; then
        HOST_CXX=g++
        echo "Using default HOST_CXX: g++"
    else
        echo "❌ No C++ compiler found!"
        exit 1
    fi
fi
echo

# Check if we can find boost headers
echo "=== Boost Headers Check ==="
echo "Looking for boost/system/error_code.hpp..."
find /nix/store -name "error_code.hpp" -path "*/boost/system/*" 2>/dev/null | head -3
echo

# Check if we can find boost libraries
echo "=== Boost Libraries Check ==="
echo "Looking for libboost_system..."
find /nix/store -name "libboost_system*" 2>/dev/null | head -3
echo

# Try to compile with different approaches
echo "=== Compilation Tests ==="

# Test 1: Basic compilation (same as configure script)
echo "Test 1: Basic compilation with -lboost_system"
echo "Command: $HOST_CXX -o $TMPDIR/systemtest $TMPDIR/systemtest.cpp -lboost_system"
$HOST_CXX -o $TMPDIR/systemtest $TMPDIR/systemtest.cpp -lboost_system 2>&1
if [ $? -eq 0 ]; then
    echo "✅ Test 1: SUCCESS"
else
    echo "❌ Test 1: FAILED"
fi
echo

# Test 2: With verbose output
echo "Test 2: Compilation with verbose output"
echo "Command: $HOST_CXX -v -o $TMPDIR/systemtest2 $TMPDIR/systemtest.cpp -lboost_system"
$HOST_CXX -v -o $TMPDIR/systemtest2 $TMPDIR/systemtest.cpp -lboost_system 2>&1
if [ $? -eq 0 ]; then
    echo "✅ Test 2: SUCCESS"
else
    echo "❌ Test 2: FAILED"
fi
echo

# Test 3: Try to find boost with pkg-config
echo "Test 3: Using pkg-config to find boost"
if command -v pkg-config >/dev/null 2>&1; then
    echo "pkg-config found, checking for boost..."
    pkg-config --list-all | grep boost || echo "No boost packages found in pkg-config"
    echo "Trying: pkg-config --cflags --libs boost-system"
    BOOST_FLAGS=$(pkg-config --cflags --libs boost-system 2>/dev/null)
    if [ $? -eq 0 ]; then
        echo "Boost flags from pkg-config: $BOOST_FLAGS"
        echo "Command: $HOST_CXX -o $TMPDIR/systemtest3 $TMPDIR/systemtest.cpp $BOOST_FLAGS"
        $HOST_CXX -o $TMPDIR/systemtest3 $TMPDIR/systemtest.cpp $BOOST_FLAGS 2>&1
        if [ $? -eq 0 ]; then
            echo "✅ Test 3: SUCCESS with pkg-config"
        else
            echo "❌ Test 3: FAILED with pkg-config"
        fi
    else
        echo "❌ Test 3: pkg-config couldn't find boost-system"
    fi
else
    echo "❌ Test 3: pkg-config not found"
fi
echo

# Test 4: Try with explicit include and library paths
echo "Test 4: With explicit paths"
BOOST_INCLUDE=$(find /nix/store -name "boost" -type d -path "*/include/*" | grep -v clang-tidy | head -1)
BOOST_LIB=$(find /nix/store -name "libboost_system.so" | head -1 | xargs dirname)
if [ -n "$BOOST_INCLUDE" ] && [ -n "$BOOST_LIB" ]; then
    echo "Boost include path: $BOOST_INCLUDE"
    echo "Boost lib path: $BOOST_LIB"
    echo "Command: $HOST_CXX -I$BOOST_INCLUDE -L$BOOST_LIB -o $TMPDIR/systemtest4 $TMPDIR/systemtest.cpp -lboost_system"
    $HOST_CXX -I$BOOST_INCLUDE -L$BOOST_LIB -o $TMPDIR/systemtest4 $TMPDIR/systemtest.cpp -lboost_system 2>&1
    if [ $? -eq 0 ]; then
        echo "✅ Test 4: SUCCESS with explicit paths"
    else
        echo "❌ Test 4: FAILED with explicit paths"
    fi
else
    echo "❌ Test 4: Could not find boost include or lib paths"
fi
echo

# Cleanup
echo "=== Cleanup ==="
rm -rf $TMPDIR
echo "Temporary directory cleaned up"
echo
echo "=== Test Complete ==="
