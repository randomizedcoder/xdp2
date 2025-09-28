# nix_configure.nix

# Introduction

This document describes the challenges with using the xdp2 configure script in a nix environment.

## Summary of the configure script

The XDP2 configure script is a custom bash-based configuration system (not autoconf) that performs several key phases:

### Configuration Phases

1. **Platform Detection** (lines 249-288)
   - Discovers available platforms from `../platforms/` directory
   - Sets default platform to "default" or uses `--platform` argument
   - Sources platform-specific configuration from `../platforms/$PLATFORM/src/configure`

2. **Command Line Parsing** (lines 295-309)
   - Processes arguments like `--compiler`, `--arch`, `--installdir`, `--build-opt-parser`
   - Sets up environment variables based on arguments
   - Configures pkg-config path if specified

3. **Architecture Detection** (lines 349-425)
   - Determines target architecture from command line, `TARGET_ARCH`, or `uname -m`
   - Creates symbolic links to architecture-specific headers
   - Falls back to generic architecture if specific one not found

4. **Compiler Setup** (lines 338-444)
   - Configures primary compilers (`CC`, `CXX`) and host compilers (`HOST_CC`, `HOST_CXX`)
   - Sets up LLVM configuration tool path
   - Generates Makefile rules for different compilation modes

5. **Dependency Detection** (lines 450-456)
   - **Library Tests**: Compiles test programs to verify library availability
   - **Tool Tests**: Checks for required tools using `command -v`

### Detection Mechanisms

**Library Detection**: Creates temporary C/C++ test programs that:
- Include required headers (e.g., `#include <boost/system/error_code.hpp>`)
- Link against required libraries (e.g., `-lboost_system`)
- Compile using `$HOST_CXX` with library flags
- Exit with error if compilation/linking fails

**Tool Detection**: Uses `command -v` to check if tools exist in PATH

**Architecture Detection**: Uses `uname -m` as fallback, with command-line override capability

**Platform Detection**: Scans filesystem for available platform configurations

The script generates a `config.mk` file containing all detected settings and Makefile rules for the build system.

## Challenge 1: Clang/LLVM Configuration

### The Problem

After resolving the shebang issues, the next challenge was that the XDP2 configure script couldn't find clang/llvm tools:

**Error observed:**
```
./configure: line 165: /usr/bin/llvm-config: No such file or directory
Clang library missing or broken!
```

**Root cause:** The configure script expects clang/llvm tools to be in standard system locations like `/usr/bin/llvm-config`, but in Nix environments, these tools are located in the Nix store.

### The Solution: Environment Variables + Correct Package

The XDP2 configure script is designed to use environment variables. The `check_clang_lib()` function uses:
- `$HOST_CXX` for the C++ compiler
- `$HOST_LLVM_CONFIG` for the LLVM configuration tool

**Implementation in flake.nix:**
```nix
# Add llvm.dev to build inputs (not just llvm)
buildTools = with pkgs; [ gnumake pkg-config bison flex llvm.dev ];

# Set environment variable in configurePhase
configurePhase = ''
  export HOST_LLVM_CONFIG=${pkgs.llvm.dev}/bin/llvm-config
  ./configure --build-opt-parser --installdir $out
'';
```

**Key insight:** `llvm-config` is not in the `llvm` package but in `llvm.dev` (development package).

### Why This Approach Works

- **Uses existing design**: The configure script already supports environment variables
- **No source changes**: Keeps original source files unchanged
- **Correct packages**: Uses `llvm.dev` which contains `llvm-config`
- **Build-time configuration**: Sets environment variables during the build process

## Challenge 2: Clang Library Compilation Test

### The Problem

After fixing the `llvm-config` issue, the next challenge is that the `check_clang_lib()` function fails:

**Error observed:**
```
Clang library missing or broken!
```

**Root cause:** The `check_clang_lib()` function tries to compile a test program using:
- `$HOST_CXX` (C++ compiler)
- `$HOST_LLVM_CONFIG --ldflags --cxxflags` (LLVM flags)
- `-lclang -lLLVM -lclang-cpp` (clang libraries)

The compilation test fails because the clang libraries are not available in the build environment.

### The Solution: Add Clang Libraries + Set HOST_CXX

The issue is that we need:
1. **Clang libraries in buildInputs**: The `-lclang -lLLVM -lclang-cpp` libraries need to be available for linking
2. **HOST_CXX=clang**: The configure script defaults `HOST_CXX` to `g++`, but we need it to use `clang` for the clang library test
3. **Consistent environment variables**: The build derivation needs the same environment variables as the devShell

**Implementation in flake.nix:**
```nix
# Add clang to buildInputs (for libraries)
buildInputs = allRuntimeLibs ++ [ pkgs.clang ];

# Set HOST_CXX in configurePhase
configurePhase = ''
  export HOST_LLVM_CONFIG=${pkgs.llvm.dev}/bin/llvm-config
  export HOST_CXX=clang
  ./configure --build-opt-parser --installdir $out
'';
```

### Why This Approach Works

- **Provides clang libraries**: Adding `clang` to `buildInputs` makes the clang libraries available for linking
- **Uses clang compiler**: Setting `HOST_CXX=clang` ensures the test uses the clang compiler
- **Consistent with devShell**: Matches the environment variables set in the development shell
- **Follows existing pattern**: Uses the same environment variable approach that worked for `llvm-config`
- **Simplified approach**: Using `allPackages` for both `nativeBuildInputs` and `buildInputs` eliminates complexity

**Result:** ✅ The clang library compilation test now passes!

## Challenge 3: Boost.System Library

### The Problem

After fixing the clang library issue, the next challenge is that the configure script can't find Boost.System:

**Error observed:**
```
Boost.System missing or broken!
```

**Root cause:** The `check_boostsystem()` function tries to compile a test program that:
- Includes Boost.System headers: `#include <boost/system/error_code.hpp>`
- Links against the boost_system library: `-lboost_system`

The compilation fails, indicating either the Boost.System headers or the `libboost_system` library isn't available in the build environment.

### Analysis of the Problem

The configure script's `check_boostsystem()` function:
```bash
check_boostsystem()
{
    # Creates test program with boost/system/error_code.hpp
    $HOST_CXX -o $TMPDIR/systemtest $TMPDIR/systemtest.cpp -lboost_system
    # Fails if compilation or linking fails
}
```

**What we've tried:**
1. ✅ **Changed `boost` to `boost.dev`**: Still failed with same error
2. ✅ **Added both `boost.dev` and `boost.out`**: Still failed with same error
3. ✅ **Added `CPPFLAGS` and `LDFLAGS`**: Still failed with same error

**Investigation results:**
- ✅ **Headers are available**: `boost/system/error_code.hpp` exists in `boost-1.87.0-dev`
- ✅ **Libraries are available**: `libboost_system.so` exists in the boost packages
- ✅ **Manual compilation works**: When we provide explicit `-I` and `-L` flags, compilation succeeds
- ❌ **Configure script still fails**: The `check_boostsystem()` test still fails

**Root cause identified:**
The `check_boostsystem()` function uses `$HOST_CXX` directly without respecting `CPPFLAGS` and `LDFLAGS` environment variables. The compiler can't find the Boost headers because they're not in the default include search path.

### Current Approach: Environment Variables

We're currently trying to use standard compiler environment variables:
- **`CPPFLAGS`**: For include paths (`-I` flags)
- **`CXXFLAGS`**: For C++ compiler flags
- **`LDFLAGS`**: For linker flags (`-L` flags)

**Current implementation in flake.nix:**
```nix
# Set as derivation attributes
CPPFLAGS = "-I${pkgs.boost.dev}/include";
CXXFLAGS = "-I${pkgs.boost.dev}/include";
LDFLAGS = "-L${pkgs.boost.out}/lib";

# Also export in configurePhase
configurePhase = ''
  export HOST_LLVM_CONFIG=${pkgs.llvm.dev}/bin/llvm-config
  export HOST_CXX=clang
  export CPPFLAGS="-I${pkgs.boost.dev}/include"
  export CXXFLAGS="-I${pkgs.boost.dev}/include"
  export LDFLAGS="-L${pkgs.boost.out}/lib"
  ./configure --build-opt-parser --installdir $out
'';
```

### Alternative Approaches Considered

1. **`substituteInPlace` approach**: Modify the configure script to add required flags
   - **Issue**: Complex patterns with tabs, spaces, and line continuations are hard to match exactly

2. **Wrapper script approach**: Create a wrapper for `$HOST_CXX` that includes necessary flags
   - **Advantage**: Simpler and more maintainable than pattern matching

3. **pkg-config integration**: Use pkg-config to find boost packages
   - **Issue**: Boost packages not found in pkg-config

### Next Steps

The current approach using environment variables should work if the configure script respects them. If not, we may need to try the wrapper script approach or investigate why the environment variables aren't being respected by the configure script.

## configure_nix experiment

As an experiment, there is the new file `./src/configure_nix` which is a modified version of the configure script that is more compatible with the Nix environment.

### Targeted Changes for Nix Compatibility

Based on our analysis of the challenges, we will make **small, targeted changes** to `./src/configure_nix` to address the specific Nix compatibility issues:

#### 1. **Fix Boost Library Detection** (Lines 99-121, 51-73, 75-97, 123-145)

**Problem**: The Boost check functions (`check_boostsystem`, `check_boostwave`, `check_boostthread`, `check_boostfilesystem`) use `$HOST_CXX` directly without respecting standard compiler environment variables.

**Solution**: Modify the compilation commands to include Nix-specific include and library paths:

```bash
# Current (problematic):
$HOST_CXX -o $TMPDIR/systemtest $TMPDIR/systemtest.cpp -lboost_system

# Nix-compatible:
$HOST_CXX -I${NIX_BOOST_DEV}/include -L${NIX_BOOST_OUT}/lib -o $TMPDIR/systemtest $TMPDIR/systemtest.cpp -lboost_system
```

**Files to modify**:
- `check_boostsystem()` (line 112)
- `check_boostwave()` (line 64)
- `check_boostthread()` (line 88)
- `check_boostfilesystem()` (line 136)

#### 2. **Fix LLVM Configuration Path** (Line 434)

**Problem**: Hardcoded fallback to `/usr/bin/llvm-config` which doesn't exist in Nix.

**Solution**: Use environment variable with better fallback:

```bash
# Current (problematic):
: ${HOST_LLVM_CONFIG:="/usr/bin/llvm-config"}

# Nix-compatible:
: ${HOST_LLVM_CONFIG:="${NIX_LLVM_CONFIG:-llvm-config}"}
```

#### 3. **Fix Clang Library Test** (Line 165)

**Problem**: The `check_clang_lib()` function may need additional include paths for Nix.

**Solution**: Add Nix-specific include paths if available:

```bash
# Current:
$HOST_CXX -o $TMPDIR/clang_lib $TMPDIR/clang_lib.cpp `$HOST_LLVM_CONFIG --ldflags --cxxflags` -lclang -lLLVM -lclang-cpp

# Nix-compatible (if needed):
$HOST_CXX ${NIX_CLANG_INCLUDES:-} -o $TMPDIR/clang_lib $TMPDIR/clang_lib.cpp `$HOST_LLVM_CONFIG --ldflags --cxxflags` -lclang -lLLVM -lclang-cpp
```

### Implementation Strategy

1. **Environment Variable Approach**: Use Nix-provided environment variables for paths
2. **Minimal Changes**: Only modify the specific compilation commands that fail
3. **Backward Compatibility**: Changes should not break non-Nix environments
4. **Conditional Logic**: Use environment variable checks to apply Nix-specific paths only when needed

### Expected Benefits

- **Eliminates Boost.System errors** by providing correct include/library paths
- **Maintains compatibility** with standard Linux environments
- **Reduces Nix flake complexity** by moving path resolution into the configure script
- **Provides clear debugging** by making Nix-specific paths explicit in the configure script

This approach addresses the root cause of the Nix compatibility issues while keeping changes minimal and targeted to the specific problems we've identified.

## New Environment Variables for configure_nix

The `configure_nix` script introduces several new environment variables to provide Nix-specific paths for library detection. These variables are designed to be set by the Nix build environment and are optional - the script will work in non-Nix environments when these variables are not set.

### Environment Variables

| Variable | Purpose | Example Value | Used In |
|----------|---------|---------------|---------|
| `NIX_BOOST_DEV` | Path to Boost development headers | `/nix/store/...-boost-1.87.0-dev` | All Boost check functions |
| `NIX_BOOST_OUT` | Path to Boost runtime libraries | `/nix/store/...-boost-1.87.0/lib` | All Boost check functions |
| `NIX_LLVM_CONFIG` | Path to llvm-config tool | `/nix/store/...-llvm-18.1.0-dev/bin/llvm-config` | LLVM configuration setup |
| `NIX_CLANG_INCLUDES` | Additional Clang include paths | `-I/nix/store/...-clang-18.1.0/include` | Clang library test |

### Usage in Nix Environment

These variables should be set in the Nix flake's `configurePhase` or `shellHook`:

```nix
configurePhase = ''
  export NIX_BOOST_DEV=${pkgs.boost.dev}
  export NIX_BOOST_OUT=${pkgs.boost.out}
  export NIX_LLVM_CONFIG=${pkgs.llvm.dev}/bin/llvm-config
  export NIX_CLANG_INCLUDES="-I${pkgs.clang}/include"
  ./configure_nix --build-opt-parser --installdir $out
'';
```

### Conditional Logic

The script uses bash parameter expansion to conditionally include these paths:

- **`${VAR:-default}`**: Use `default` if `VAR` is unset or empty
- **`${VAR:+value}`**: Use `value` if `VAR` is set and non-empty, otherwise use nothing

**Examples:**
```bash
# If NIX_BOOST_DEV is set to "/nix/store/abc-boost-dev"
${NIX_BOOST_DEV:+-I$NIX_BOOST_DEV/include}
# Expands to: -I/nix/store/abc-boost-dev/include

# If NIX_BOOST_DEV is unset
${NIX_BOOST_DEV:+-I$NIX_BOOST_DEV/include}
# Expands to: (empty string)
```

### Backward Compatibility

- **Non-Nix environments**: When these variables are not set, the script behaves exactly like the original `configure` script
- **Standard Linux systems**: No changes to existing build processes
- **Docker/CI environments**: Works with or without these variables set

### Benefits

1. **Explicit path resolution**: Makes Nix store paths visible in the configure script
2. **Easier debugging**: Can see exactly which paths are being used
3. **Reduced flake complexity**: Moves path resolution logic into the configure script
4. **Maintainable**: Clear separation between Nix-specific and generic logic