# Configure on ubuntu without nix

## Introduction

This document (configure-on-ubuntu-without-nix.md) describes the challenges with using the xdp2 configure script on ubuntu without nix.

## Solution (Quick Reference)

**Problem**: Configure script fails with "Clang library missing or broken!" error.

**Root Cause**: The script defaults to `/usr/bin/llvm-config` which doesn't exist on Ubuntu 24.04 with `llvm-20` packages. The actual tool is `/usr/bin/llvm-config-20`.

**Solution (Automatic)**: The configure script has been updated to automatically detect versioned `llvm-config` tools. If `/usr/bin/llvm-config` doesn't exist, it will search for `llvm-config-20`, `llvm-config-19`, etc. in PATH.

**Solution (Manual)**: If automatic detection doesn't work, use the versioned tool explicitly:

```bash
export HOST_LLVM_CONFIG=/usr/bin/llvm-config-20
./configure
```

Or use the command-line argument:

```bash
./configure --llvm-config /usr/bin/llvm-config-20
```

**See**: [Step 3a findings](#step-3a-check-the-actual-llvm-20-package-critical-) for details.

## Status Summary

### ✅ Completed Changes

1. **Auto-detection of versioned llvm-config tools**: The configure script now automatically detects and uses versioned `llvm-config` tools (e.g., `llvm-config-20`) when the default `/usr/bin/llvm-config` doesn't exist.

2. **Verification of llvm-config tools**: The script verifies that each `llvm-config` tool works by testing `--version` before using it, ensuring the tool is functional.

3. **Validation of user-provided HOST_LLVM_CONFIG**: If `HOST_LLVM_CONFIG` is explicitly set (via environment variable or command-line), it is validated before use.

4. **Error annotation**: Added error messages to identify which part of `check_clang_lib()` is failing.

### ⚠️ Current Issue

**Status**: Detection is working, but compilation still fails due to missing library.

**Current Error** (with `--debug-level 7`):
```
[DEBUG-1] Tool Detection: Selected llvm-config-20 (version 20.1.2)
[DEBUG-1] Tool Detection: Using HOST_LLVM_CONFIG=/usr/bin/llvm-config-20
[DEBUG-4] Clang.Lib: llvm-config --ldflags: -L/usr/lib/llvm-20/lib
[DEBUG-4] Clang.Lib: llvm-config --cxxflags: -I/usr/lib/llvm-20/include -std=c++17 ...
[DEBUG-5] Clang.Lib: Full command: g++ -o ... -L/usr/lib/llvm-20/lib ... -lclang -lLLVM -lclang-cpp
/usr/bin/ld: cannot find -lclang-cpp: No such file or directory
collect2: error: ld returned 1 exit status
```

**Analysis**:
- ✅ `llvm-config-20` is successfully detected and working
- ✅ Include paths are correct: `-I/usr/lib/llvm-20/include`
- ✅ Library search path is set: `-L/usr/lib/llvm-20/lib`
- ❌ **Root cause identified**: The linker cannot find `libclang-cpp` library
- The compilation command is correct, but `libclang-cpp.so` (or `libclang-cpp.a`) doesn't exist in the expected location

**Discovery**:
- The compilation command uses `-lclang-cpp` which tells the linker to look for `libclang-cpp.so` or `libclang-cpp.a`
- The library path `-L/usr/lib/llvm-20/lib` is set correctly
- The linker error indicates the library file itself is missing

**Next Steps**:
- Investigate what clang libraries actually exist in `/usr/lib/llvm-20/lib`
- Check if `libclang-cpp` is provided by a different package or has a different name
- Verify which packages provide clang libraries on Ubuntu 24.04

### ✅ Completed Improvements

**Debugging Infrastructure**: Successfully implemented `--debug-level` option (0-7, syslog-style):
- **Level 0**: No debug output (default) ✅
- **Level 1-2**: Basic information (detected tools, paths) ✅
- **Level 3-4**: Command execution details ✅
- **Level 5-6**: Full command output, environment variables ✅
- **Level 7**: Maximum verbosity (all intermediate steps, test program contents) ✅

**Results**: The debugging infrastructure successfully revealed:
- ✅ Which `llvm-config` tool is being used
- ✅ The exact compilation command being executed
- ✅ The actual compilation error: `/usr/bin/ld: cannot find -lclang-cpp: No such file or directory`
- ✅ Library paths and include paths being used

## Background

To ensure xdp2 works on a non-Nix managed system, a ubuntu system was created and packages were manually installed per the main README.md.  The intention is to allow easy comparision of the nix development shell verse a "native" Ubuntu system.

We have x2 ubuntu versioning sytles to test.

The first is with no version specified.  These seems to default to a version 18 of clang.
```
sudo apt install -y build-essential gcc gcc-multilib pkg-config bison flex \
    libboost-all-dev libpcap-dev python3-scapy graphviz libelf-dev libbpf-dev


sudo apt-get install -y libelf-dev clang clang-tools libclang-dev llvm llvm-dev libbpf-dev linux-tools-$(uname -r)
```

Then we have a versioned instance, where we are testing version 20.

When ./src/configure didn't immediately work, I tried upgrading from clang 18, which is the default, to clang 20 by doing this.

```
sudo apt-get install -y build-essential gcc gcc-multilib pkg-config bison flex libboost-all-dev libpcap-dev python3-scapy

sudo apt-get install -y graphviz

sudo apt-get install -y sudo apt install -y llvm-20-dev clang-20 libclang-20-dev clang-tools-20 lld-20 linux-tools-$(uname -r)
```

## Configure script

We already have detailed analysis of the configure script in ./nix_configure.md

## Error

```
das@ubuntu2404-no-nix:~/xdp2/src$ ./configure


Platform is default
Architecture is x86_64
Architecture includes for x86_64 not found, using generic
Target Architecture is
COMPILER is gcc
Clang library missing or broken!
das@ubuntu2404-no-nix:~/xdp2/src$
```

## Analysis

### Findings - Initial Investigation

**Initial Discovery**: `llvm-config` existed and was functional on the system, but there was a version mismatch:

```
das@ubuntu2404-no-nix:~/xdp2/src$ llvm-config
usage: llvm-config <OPTION>... [<COMPONENT>...]
...
das@ubuntu2404-no-nix:~/xdp2/src$ which llvm-config
/usr/bin/llvm-config
das@ubuntu2404-no-nix:~/xdp2/src$ llvm-config --version
18.1.3
```

**Initial Observations**:
1. `llvm-config` existed and worked (version 18.1.3)
2. Version mismatch between `llvm-config` (v18) and installed `clang-20` packages
3. Installing `clang-20` and `llvm-20` packages did not update the default `llvm-config` to version 20

### Findings - Fresh Install Investigation

**Critical Discovery**: On a fresh Ubuntu 24.04 install with only `llvm-20` packages, `llvm-config` is **completely missing**:

```
das@ubuntu2404-no-nix:~$ llvm-config --version
Command 'llvm-config' not found, but can be installed with:
sudo apt install llvm

das@ubuntu2404-no-nix:~$ apt search llvm-20
llvm-20/noble-updates,now 1:20.1.2-0ubuntu1~24.04.2 amd64 [installed]
  Modular compiler and toolchain technologies

llvm-20-dev/noble-updates,now 1:20.1.2-0ubuntu1~24.04.2 amd64 [installed,automatic]
  Modular compiler and toolchain technologies, libraries and headers

llvm-20-tools/noble-updates,now 1:20.1.2-0ubuntu1~24.04.2 amd64 [installed,automatic]
  Modular compiler and toolchain technologies, tools

das@ubuntu2404-no-nix:~$ dpkg --list llvm-20
ii  llvm-20        1:20.1.2-0ubuntu1~24.04.2 amd64        Modular compiler and toolchain technologies
```

**Complete LLVM-20 Package List**:
```
das@ubuntu2404-no-nix:~$ apt search llvm | grep llvm | grep 20
libllvm-20-ocaml-dev/noble-updates 1:20.1.2-0ubuntu1~24.04.2 amd64
libllvm20/noble-updates,now 1:20.1.2-0ubuntu1~24.04.2 amd64 [installed,automatic]
llvm-20/noble-updates,now 1:20.1.2-0ubuntu1~24.04.2 amd64 [installed]
llvm-20-dev/noble-updates,now 1:20.1.2-0ubuntu1~24.04.2 amd64 [installed,automatic]
llvm-20-doc/noble-updates 1:20.1.2-0ubuntu1~24.04.2 all
llvm-20-examples/noble-updates 1:20.1.2-0ubuntu1~24.04.2 all
llvm-20-linker-tools/noble-updates,now 1:20.1.2-0ubuntu1~24.04.2 amd64 [installed,automatic]
llvm-20-runtime/noble-updates,now 1:20.1.2-0ubuntu1~24.04.2 amd64 [installed,automatic]
llvm-20-tools/noble-updates,now 1:20.1.2-0ubuntu1~24.04.2 amd64 [installed,automatic]
```

**Critical Observations**:
1. **`llvm-config` is missing**: The command doesn't exist, despite `llvm-20` being installed
2. **Package structure difference**: Unlike the `llvm` package (which provides `llvm-config`), the `llvm-20` package does NOT provide `llvm-config` in the default PATH
3. **`llvm-20-tools` is installed**: This package is marked as `[installed,automatic]`, suggesting it was auto-installed as a dependency. **This is the key package to investigate** - it likely contains `llvm-config-20` or other LLVM tools
4. **Multiple llvm-20 packages installed**: The system has `llvm-20`, `llvm-20-dev`, `llvm-20-tools`, `llvm-20-linker-tools`, and `llvm-20-runtime` all installed
5. **System suggests `llvm` package**: The error message suggests installing `llvm` (which would be version 18), not `llvm-20`
6. **Package appears healthy**: `dpkg --list` shows `ii` status (installed and configured), so the package installation itself seems fine

**Root Cause Hypothesis**:
- The `llvm-20` package structure differs from the `llvm` package:
  - `llvm` package provides `/usr/bin/llvm-config` (unversioned)
  - `llvm-20` package may provide `/usr/bin/llvm-config-20` (versioned) OR may not provide `llvm-config` at all
- The configure script defaults to `/usr/bin/llvm-config` which doesn't exist when only versioned packages are installed
- This explains why the configure script fails: it can't find the tool it's looking for

**Implications**:
- The issue is NOT a version mismatch, but a **missing tool** - `llvm-config` doesn't exist
- The `llvm-20` package structure is different from `llvm` package
- We need to either:
  1. Install the `llvm` package (which provides `llvm-config` but is version 18)
  2. Find and use `llvm-config-20` if it exists
  3. Understand what files `llvm-20-tools` actually provides
  4. Modify the configure script or use environment variables to point to the correct tool

## Hypothesis

Based on the configure script analysis in `./nix_configure.md`, the error observed, and the fresh install findings, the hypothesis is:

**The configure script is failing because `llvm-config` doesn't exist when only versioned LLVM packages (`llvm-20`) are installed:**

1. **Missing `llvm-config` tool**: The configure script defaults to `/usr/bin/llvm-config` (line 461-463), but this file doesn't exist when only `llvm-20` packages are installed. The `llvm-20` package structure differs from the `llvm` package:
   - `llvm` package provides `/usr/bin/llvm-config` (unversioned, defaults to version 18)
   - `llvm-20` package likely provides `/usr/bin/llvm-config-20` (versioned) OR may not provide `llvm-config` at all
   - The configure script fails at `check_clang_lib()` because it can't execute the missing `llvm-config` command

2. **Package structure difference**: Ubuntu's versioned LLVM packages (`llvm-20`, `clang-20`) use a different naming convention than the default packages (`llvm`, `clang`). Installing versioned packages doesn't create unversioned symlinks by default, which the configure script expects.

3. **Hidden execution error**: The `check_clang_lib()` function (line 165) suppresses all output with `> /dev/null 2>&1`, so when `llvm-config` doesn't exist, the script fails silently with "Clang library missing or broken!" without showing the actual "command not found" error.

4. **Environment variable not set**: The script checks if `HOST_LLVM_CONFIG` is set (line 461), and if not, defaults to `/usr/bin/llvm-config`. If this file doesn't exist, the backtick expansion `\`$HOST_LLVM_CONFIG --ldflags --cxxflags\`` fails, causing the compilation command to fail.

5. **Potential solution paths**:
   - Install the `llvm` package (provides `llvm-config` but is version 18, may conflict with clang-20)
   - Use `llvm-config-20` if it exists by setting `HOST_LLVM_CONFIG=/usr/bin/llvm-config-20`
   - Investigate what `llvm-20-tools` package actually provides
   - Modify the configure script to search for versioned tools

**Most likely root cause**: The configure script tries to execute `/usr/bin/llvm-config` which doesn't exist, causing the `check_clang_lib()` function to fail. The error message "Clang library missing or broken!" is misleading - the actual issue is that `llvm-config` command is missing.

## Investigation steps

The following steps will help diagnose and resolve the missing `llvm-config` issue:

### Step 1: Check if llvm-config-20 exists
- The most important first step - verify if the versioned tool exists:
  ```bash
  which llvm-config-20
  /usr/bin/llvm-config-20 --version 2>/dev/null || echo "llvm-config-20 not found"
  ls -la /usr/bin/llvm-config* 2>/dev/null
  ```
- This will tell us if Ubuntu provides a versioned `llvm-config-20` tool.

### Step 2: Check what files llvm-20-tools provides (CRITICAL) ✅

**Finding**: `llvm-20-tools` package does NOT provide `llvm-config-20`!

The package provides versioned tools in `/usr/bin/`:
- `/usr/bin/FileCheck-20`
- `/usr/bin/UnicodeNameMappingGenerator-20`
- `/usr/bin/count-20`
- `/usr/bin/llvm-ctxprof-util-20`
- `/usr/bin/not-20`
- `/usr/bin/split-file-20`
- `/usr/bin/yaml-bench-20`

**Key Observation**: All tools in `/usr/bin/` are versioned with `-20` suffix, but `llvm-config-20` is **NOT** in the list.

The package also contains:
- Unversioned tools in `/usr/lib/llvm-20/bin/` (not in PATH)
- Lit test framework files in `/usr/lib/llvm-20/build/utils/lit/`
- Opt-viewer tools in `/usr/lib/llvm-20/share/opt-viewer/`

**Conclusion**: `llvm-config-20` is not provided by `llvm-20-tools`. We need to check other packages or find an alternative solution.

### Step 3: Check what files llvm-20-dev provides ✅

**Finding**: `llvm-20-dev` only provides a header file, not the executable:
- `/usr/include/llvm-20/llvm/Config/llvm-config.h` (header file only)

**Conclusion**: `llvm-20-dev` does NOT contain the `llvm-config` executable.

### Step 3a: Check the actual llvm-20 package (CRITICAL) ✅

**Finding**: `llvm-config-20` EXISTS and works!

```
das@ubuntu2404-no-nix:~$ which llvm-config-20
/usr/bin/llvm-config-20
das@ubuntu2404-no-nix:~$ /usr/bin/llvm-config-20 --version
20.1.2
```

**Root Cause Identified**:
- The configure script defaults to `/usr/bin/llvm-config` (which doesn't exist)
- The actual tool is `/usr/bin/llvm-config-20` (which exists and works)
- The script needs to be told to use the versioned tool

**Solution Implemented**: The configure script has been updated with automatic detection:
- First checks if `/usr/bin/llvm-config` exists
- If not, automatically searches for versioned variants (`llvm-config-20`, `llvm-config-19`, `llvm-config-18`, etc.) in PATH
- Uses the first versioned tool found, or falls back to default if none found

**Manual Solution** (if automatic detection doesn't work):
- Set environment variable: `export HOST_LLVM_CONFIG=/usr/bin/llvm-config-20`
- Or use command-line argument: `./configure --llvm-config /usr/bin/llvm-config-20`

### Step 4: Check what the unversioned llvm package provides
- For comparison, see what the default `llvm` package would provide (if installed):
  ```bash
  apt show llvm | grep -A 5 "Provides:"
  apt-file list llvm 2>/dev/null | grep llvm-config
  ```
- Or check if `llvm` is installed:
  ```bash
  dpkg -l | grep "^ii.*llvm[^-]"
  ```
- This shows the difference between `llvm` and `llvm-20` package structures.

### Step 5: Search for llvm-config in all installed packages
- Find any llvm-config files from installed packages:
  ```bash
  for pkg in $(dpkg -l | grep -E "^ii.*llvm" | awk '{print $2}'); do
    echo "=== $pkg ==="
    dpkg -L $pkg 2>/dev/null | grep llvm-config
  done
  ```
- This comprehensive search will find any `llvm-config` files regardless of package.

### Step 6: Check installed LLVM/Clang package versions
- List all installed LLVM and Clang packages:
  ```bash
  dpkg -l | grep -E "(llvm|clang)" | awk '{print $2, $3}'
  ```
- Verify which packages are actually installed and their versions.

### Step 7: Expose the actual error
- Modify `check_clang_lib()` temporarily to see the actual error:
  - Remove or comment out `> /dev/null 2>&1` on line 165 of `src/configure`
  - Run `./configure` again to see the actual error
  - This will reveal whether it's "command not found", missing headers, library linking issue, etc.

### Step 8: Test with llvm-config-20 (if found in Step 1)
- If `llvm-config-20` exists, test using it explicitly:
  ```bash
  export HOST_LLVM_CONFIG=/usr/bin/llvm-config-20
  export HOST_CXX=clang++-20
  ./configure
  ```
- Or use the command-line argument:
  ```bash
  ./configure --llvm-config /usr/bin/llvm-config-20
  ```

### Step 9: Test with full path to found llvm-config (if found in Step 5)
- If Step 5 found an `llvm-config` file in an unexpected location, use it:
  ```bash
  export HOST_LLVM_CONFIG=/path/to/found/llvm-config
  ./configure
  ```

### Step 10: Test installing llvm package (creates baseline)
- As a baseline test, install the default `llvm` package to see if it resolves the issue:
  ```bash
  sudo apt install llvm
  which llvm-config
  llvm-config --version
  ./configure
  ```
- **Note**: This will install LLVM 18, which may conflict with clang-20, but will help confirm the hypothesis.

### Step 11: Test manual compilation (once llvm-config is found)
- Once we identify the correct `llvm-config` tool, test manual compilation:
  ```bash
  cat > /tmp/test_clang.cpp << 'EOF'
  #include <clang/Frontend/CompilerInstance.h>
  int main() { return 0; }
  EOF

  # Test with the found llvm-config (replace with actual path/command)
  clang++-20 -o /tmp/test_clang /tmp/test_clang.cpp \
    $(llvm-config-20 --ldflags --cxxflags) \
    -lclang -lLLVM -lclang-cpp
  ```
- This verifies that the clang libraries and headers work with the llvm-config tool.

### Step 12: Verify clang development headers
- Check which version of clang headers are installed:
  ```bash
  find /usr/include -name "clang" -type d 2>/dev/null
  ls -la /usr/include/clang-c/ 2>/dev/null
  cat /usr/include/clang-c/Index.h 2>/dev/null | head -20 | grep -i "version\|clang"
  ```
- Verify headers are version 20 and match the clang libraries.

### Step 13: Check for recent changes
- Review git history to see if there were recent changes to clang detection:
  ```bash
  git log --oneline --all --grep="clang\|llvm\|HOST_LLVM" -- src/configure
  git diff HEAD~10..HEAD -- src/configure | grep -A5 -B5 "HOST_LLVM\|check_clang"
  ```

### Step 14: Compare with working Nix environment
- Compare the working Nix configuration (from `./nix_configure.md`) with the Ubuntu setup:
  - What environment variables are set in Nix?
  - What paths are used for LLVM tools?
  - How is `HOST_CXX` configured?
  - What LLVM version does Nix use?

### Expected outcomes

**Step 2 Result**: ✅ **Confirmed** - `llvm-20-tools` does NOT provide `llvm-config-20`
- This is a critical finding - the expected tool is missing from the tools package

**Step 3 Result**: ✅ **Confirmed** - `llvm-20-dev` only provides header files, not the executable

**Package Installation Status**: ✅ **Confirmed** - `llvm-20` package is properly installed
- The `dpkg --list` output shows `ii` status which means **"installed and configured"** (first `i` = installed, second `i` = configured)
- This is **GOOD** - the package is correctly installed, not broken
- The uppercase letters in the header are just field labels, not errors

**Step 3a Result**: ✅ **SOLUTION FOUND** - `llvm-config-20` exists and works!
- Tool location: `/usr/bin/llvm-config-20`
- Version: 20.1.2
- The tool is provided by `llvm-20` package (version 20.1.2-0ubuntu1~24.04.2)
- **Root cause**: Configure script defaults to `/usr/bin/llvm-config` (doesn't exist), but the tool is `/usr/bin/llvm-config-20` (exists)

**Step 3a Result**: ✅ **SOLUTION FOUND**
- **Tool found**: `/usr/bin/llvm-config-20` (version 20.1.2)
- **Solution**: Use the versioned tool explicitly:
  ```bash
  export HOST_LLVM_CONFIG=/usr/bin/llvm-config-20
  ./configure
  ```
  Or use command-line argument:
  ```bash
  ./configure --llvm-config /usr/bin/llvm-config-20
  ```
- **Next step**: Test if this resolves the configure script error

**If Step 5 finds `llvm-config` in an unexpected location**:
- Solution: Use the full path found in those steps
- May indicate a package installation issue or Ubuntu package structure difference

**If no `llvm-config` is found at all in llvm-20 packages**:
- Solution options:
  1. Install `llvm` package (provides `llvm-config` but is version 18, may cause version conflicts)
  2. Create a symlink: `sudo ln -s /path/to/llvm-config-20 /usr/bin/llvm-config` (if llvm-config-20 exists)
  3. Modify the configure script to search for versioned tools
  4. File a bug report with Ubuntu about missing llvm-config in llvm-20 package

**If Step 7 shows "command not found" error**:
- Confirms the hypothesis - the script can't find `llvm-config`
- Need to provide the correct path via environment variable or command-line argument

**If Step 8 works with `llvm-config-20`**:
- Solution: Document the need to use `--llvm-config /usr/bin/llvm-config-20` or set `HOST_LLVM_CONFIG`
- Consider modifying configure script to auto-detect versioned tools

**If Step 10 works with `llvm` package installed**:
- Confirms that `llvm` package provides `llvm-config` but `llvm-20` does not
- Need to decide: use `llvm` (v18) or find a way to use `llvm-20` with proper configuration

## Planned: Debugging Infrastructure

### Problem Statement

The configure script currently suppresses error output, making it difficult to diagnose compilation failures. We need a way to progressively enable debugging output without modifying the script each time.

### Proposed Solution: Debug Level System

Add a `--debug-level` option to the configure script with levels 0-7 (similar to syslog levels):

**Debug Levels**:
- **Level 0** (default): No debug output - production mode
- **Level 1-2**: Basic information
  - Detected tools and paths
  - Environment variables
  - Package versions
- **Level 3-4**: Command execution details
  - Commands being executed
  - Tool detection results
  - Configuration decisions
- **Level 5-6**: Full command output
  - Compilation commands with full flags
  - Command exit codes
  - Library and include paths
  - Test program contents
- **Level 7**: Maximum verbosity
  - All intermediate steps
  - Full environment dumps
  - All test program source code
  - All command output (including errors)
  - Step-by-step execution flow

### Implementation Plan

#### Step 1: Add Debug Function

Add a debug function at the top of the script:
```bash
debug_print() {
    local level=$1
    shift
    if [ "${CONFIGURE_DEBUG_LEVEL:-0}" -ge "$level" ]; then
        echo "[DEBUG-$level] $*" >&2
    fi
}
```

#### Step 2: Add Command-Line Option

Add `--debug-level` option to the argument parsing:
```bash
"--debug-level") CONFIGURE_DEBUG_LEVEL=$2; shift;;
```

#### Step 3: Add Debug Points Throughout Script

Key locations to add debugging:
1. **Tool detection**: Show which tools are being checked and found
2. **Environment variables**: Display detected/passed variables
3. **Compilation tests**: Show exact commands being executed
4. **Library checks**: Display library paths and flags
5. **Error conditions**: Show why checks are failing

#### Step 4: Progressive Error Visibility

Modify compilation checks to show errors based on debug level:
- Level 0-2: Suppress errors (current behavior)
- Level 3-4: Show error summary
- Level 5-6: Show full error output
- Level 7: Show everything including intermediate files

### Example Debug Output Structure

```bash
# Level 1-2 example
[DEBUG-1] Detected HOST_LLVM_CONFIG=/usr/bin/llvm-config-20
[DEBUG-1] Detected HOST_CXX=g++

# Level 3-4 example
[DEBUG-3] Executing: g++ -o /tmp/clang_lib /tmp/clang_lib.cpp `llvm-config-20 --ldflags --cxxflags` -lclang -lLLVM -lclang-cpp
[DEBUG-3] llvm-config-20 --ldflags: -L/usr/lib/x86_64-linux-gnu/...
[DEBUG-3] llvm-config-20 --cxxflags: -I/usr/include/llvm-20/...

# Level 5-6 example
[DEBUG-5] Full compilation command:
g++ -I/usr/include/llvm-20/llvm/include -I/usr/include/llvm-20/clang/include \
    -L/usr/lib/x86_64-linux-gnu -o /tmp/clang_lib /tmp/clang_lib.cpp \
    -lclang -lLLVM -lclang-cpp
[DEBUG-5] Compilation exit code: 1
[DEBUG-5] Error output:
error: clang/Frontend/CompilerInstance.h: No such file or directory

# Level 7 example
[DEBUG-7] Test program contents:
#include <clang/Frontend/CompilerInstance.h>
...
[DEBUG-7] Environment: HOST_CXX=g++, HOST_LLVM_CONFIG=/usr/bin/llvm-config-20
[DEBUG-7] All environment variables:
...
```

### Benefits

1. **Progressive debugging**: Start with minimal output, increase as needed
2. **No code modification**: Change debug level without editing script
3. **Consistent format**: All debug output follows same pattern
4. **Easy troubleshooting**: Can see exactly what's happening at each step
5. **Production safe**: Default level 0 maintains current behavior

### Priority Debug Points for check_clang_lib()

1. **Level 1**: Show which `llvm-config` tool is being used ✅
2. **Level 3**: Show the compilation command being executed ✅
3. **Level 4**: Show the expanded flags from `llvm-config` ✅
4. **Level 5**: Show the actual compilation error (remove output suppression) ✅
5. **Level 7**: Show the test program source code and full environment ✅

**Status**: All debug points implemented and working correctly!

## Latest Discovery: Missing libclang-cpp Library

### Error Identified

**Root Cause**: The linker cannot find `libclang-cpp` library:

```
/usr/bin/ld: cannot find -lclang-cpp: No such file or directory
```

**Compilation Command** (from debug output):
```bash
g++ -o config.eO2LgM/clang_lib config.eO2LgM/clang_lib.cpp \
    -L/usr/lib/llvm-20/lib \
    -I/usr/lib/llvm-20/include -std=c++17 ... \
    -lclang -lLLVM -lclang-cpp
```

**Source of the Problem**: The `-lclang-cpp` flag is **hardcoded** in the configure script at lines 215, 223, 229, and 235 in `src/configure`:

```bash
# Line 215, 223, 229, 235 in check_clang_lib()
$HOST_CXX ... $LLVM_LDFLAGS $LLVM_CXXFLAGS -lclang -lLLVM -lclang-cpp
```

**Why it fails**:
- The script correctly uses `llvm-config --ldflags` and `--cxxflags` for paths and compiler flags
- **But** it manually hardcodes `-lclang -lLLVM -lclang-cpp` instead of using `llvm-config --libs`
- On Ubuntu, the library is versioned as `libclang-cpp20.so`, so `-lclang-cpp` doesn't match
- The script should use `llvm-config --libs clang` to get the correct library names for the installed LLVM version

**What's Working**:
- ✅ `llvm-config-20` is found and working (version 20.1.2)
- ✅ Include paths are correct: `-I/usr/lib/llvm-20/include`
- ✅ Library search path is set: `-L/usr/lib/llvm-20/lib`
- ✅ Other libraries (`-lclang`, `-lLLVM`) are likely available

**What's Failing**:
- ❌ `libclang-cpp` library cannot be found by the linker
- The library file `libclang-cpp.so` or `libclang-cpp.a` doesn't exist in `/usr/lib/llvm-20/lib`

### Hypothesis

**The `libclang-cpp` library is missing from the installed packages**:

1. **Package structure issue**: The `libclang-cpp` library might not be provided by the `llvm-20` or `clang-20` packages installed on Ubuntu 24.04
2. **Different package name**: The library might be in a separate package (e.g., `libclang-cpp20` or similar)
3. **Different library name**: The library might have a different name (e.g., versioned like `libclang-cpp20.so`)
4. **Missing development package**: The library might be in a development package that wasn't installed

**Most likely**: `libclang-cpp` is provided by a package that wasn't installed, or it has a versioned name that doesn't match the unversioned `-lclang-cpp` linker flag.

### Package Discovery

**Key Finding**: `libclang-cpp20` package is installed (automatic dependency):
```
libclang-cpp20/noble-updates,now 1:20.1.2-0ubuntu1~24.04.2 amd64 [installed,automatic]
  C++ interface to the Clang library

libclang-cpp20-dev/noble-updates 1:20.1.2-0ubuntu1~24.04.2 amd64
  C++ interface to the Clang library
```

**Implications**:
- ✅ The runtime library (`libclang-cpp20`) is installed
- ❓ The development package (`libclang-cpp20-dev`) may or may not be needed
- ⚠️ The library is likely **versioned** (e.g., `libclang-cpp20.so` instead of `libclang-cpp.so`)
- The linker flag `-lclang-cpp` won't find `libclang-cpp20.so` automatically

### Recommended Next Steps

#### Step 1: Verify the library file exists and check its name
```bash
# Check in the llvm-20 lib directory
ls -la /usr/lib/llvm-20/lib/libclang-cpp* 2>/dev/null

# Check in the standard library directory
ls -la /usr/lib/x86_64-linux-gnu/libclang-cpp* 2>/dev/null

# Check what files are in the installed package
dpkg -L libclang-cpp20 | grep -E "\.so"
```

**Expected**: Should find `libclang-cpp20.so` (versioned name)

#### Step 2: Check what llvm-config reports for libraries
```bash
# Check what libraries llvm-config recommends
llvm-config-20 --libs clang

# Check actual library file paths
llvm-config-20 --libfiles clang

# Check if it includes clang-cpp
llvm-config-20 --components | grep -i cpp
llvm-config-20 --libs clang-cpp
```

**Expected**: `llvm-config-20 --libs clang` should provide the correct library flags including the versioned name

#### Step 3: Test if using llvm-config --libs works
```bash
# Get the actual library flags from llvm-config
LLVM_LIBS=$(llvm-config-20 --libs clang)
LLVM_LDFLAGS=$(llvm-config-20 --ldflags)
LLVM_CXXFLAGS=$(llvm-config-20 --cxxflags)

# Test compilation with llvm-config output
echo '#include <clang/Frontend/CompilerInstance.h>
int main() { return 0; }' > /tmp/test_clang.cpp

g++ -o /tmp/test_clang /tmp/test_clang.cpp $LLVM_LDFLAGS $LLVM_CXXFLAGS $LLVM_LIBS
```

**Expected**: This should work if `llvm-config` provides the correct library names

#### Step 4: Check if we need the -dev package
```bash
# Check what's in the dev package
dpkg -L libclang-cpp20-dev 2>/dev/null | head -20

# Check if headers are needed
find /usr -name "clang-cpp" -type d 2>/dev/null
```

**Expected**: The -dev package likely contains headers, but runtime library should be sufficient for linking

#### Step 5: Identify the solution approach
Based on the results:
- **If `llvm-config-20 --libs clang` works**: Use `llvm-config` output instead of hardcoded `-lclang-cpp`
- **If library exists as `libclang-cpp20.so`**: Either use `-lclang-cpp20` or create symlink/workaround
- **If `llvm-config` doesn't include clang-cpp**: May need to add it manually or install dev package

### Expected Outcomes and Solutions

#### Solution Path A: Use llvm-config output (Recommended)
**If Step 2 shows `llvm-config-20 --libs clang` includes the correct libraries**:
- **Solution**: Modify `check_clang_lib()` in `src/configure` to use `llvm-config --libs clang` instead of hardcoded `-lclang -lLLVM -lclang-cpp`
- **Implementation**: Replace manual library specification with `llvm-config` output
- **Why**: `llvm-config` knows the correct library names and versions for each LLVM installation

#### Solution Path B: Use versioned library name
**If Step 1 finds `libclang-cpp20.so` but `llvm-config` doesn't include it**:
- **Solution**: Change `-lclang-cpp` to `-lclang-cpp20` in the configure script
- **Implementation**: Extract version from `llvm-config --version` and use versioned library name
- **Why**: Ubuntu packages use versioned library names to allow multiple LLVM versions

#### Solution Path C: Install dev package
**If Step 4 shows headers or additional components are needed**:
- **Solution**: Install `libclang-cpp20-dev` package
- **Implementation**: `sudo apt install libclang-cpp20-dev`
- **Why**: May be needed if the library requires additional components or headers

#### Solution Path D: Hybrid approach
**If `llvm-config --libs clang` works but doesn't include clang-cpp**:
- **Solution**: Use `llvm-config --libs clang` for base libraries, then add `-lclang-cpp20` separately
- **Implementation**: Combine both approaches
- **Why**: May be needed if clang-cpp is a separate component

### Most Likely Solution

Based on the package discovery, **Solution Path A is most likely**:
- The `libclang-cpp20` package is installed (runtime library exists)
- `llvm-config` should be aware of the correct library names
- The configure script should use `llvm-config --libs clang` instead of hardcoded library flags
- This approach is more portable and works across different LLVM versions and distributions

---

## Implementation: Using llvm-config --libs (Attempt 1)

### Changes Made

**Updated `check_clang_lib()` function** in `src/configure`:
- ✅ Removed hardcoded library flags: `-lclang -lLLVM -lclang-cpp`
- ✅ Added dynamic library detection: Uses `llvm-config --libs clang` to get library flags
- ✅ Added fallback logic: If `--libs clang` fails, tries `--libs` without component
- ✅ Added error handling: Validates that `llvm-config` returns library flags
- ✅ Added debug output: Shows library flags at debug level 4

### Test Results

#### Test 1: Ubuntu 24.04 with LLVM 20 (Versioned Packages)

**System**: Ubuntu 24.04 with `llvm-20` packages installed
**llvm-config**: `/usr/bin/llvm-config-20` (version 20.1.2)

**Debug Output**:
```
[DEBUG-1] Tool Detection: Selected llvm-config-20 (version 20.1.2)
[DEBUG-4] Clang.Lib: llvm-config --ldflags: -L/usr/lib/llvm-20/lib
[DEBUG-4] Clang.Lib: llvm-config --cxxflags: -I/usr/lib/llvm-20/include -std=c++17 ...
[DEBUG-1] Clang.Lib: Warning: llvm-config --libs clang failed, trying without component
[DEBUG-4] Clang.Lib: llvm-config --libs clang: -lLLVM-20
[DEBUG-5] Clang.Lib: Full command: g++ -o ... -L/usr/lib/llvm-20/lib ... -lLLVM-20
/usr/bin/ld: ... undefined reference to `clang::tooling::CommonOptionsParser::create(...)'
collect2: error: ld returned 1 exit status
```

**Result**: ✅ Tool detection works, ❌ Compilation fails due to missing clang libraries

#### Test 2: Ubuntu 24.04 with LLVM 18 (Non-Versioned Packages)

**System**: Ubuntu 24.04 with default `llvm` packages (version 18)
**llvm-config**: `/usr/bin/llvm-config` (version 18.1.3)

**Debug Output**:
```
[DEBUG-1] Tool Detection: Selected llvm-config (version 18.1.3)
[DEBUG-4] Clang.Lib: llvm-config --ldflags: -L/usr/lib/llvm-18/lib
[DEBUG-4] Clang.Lib: llvm-config --cxxflags: -I/usr/lib/llvm-18/include -std=c++17 ...
[DEBUG-1] Clang.Lib: Warning: llvm-config --libs clang failed, trying without component
[DEBUG-4] Clang.Lib: llvm-config --libs clang: -lLLVM-18
[DEBUG-5] Clang.Lib: Full command: g++ -o ... -L/usr/lib/llvm-18/lib ... -lLLVM-18
/usr/bin/ld: ... undefined reference to `clang::tooling::CommonOptionsParser::create(...)'
collect2: error: ld returned 1 exit status
```

**Result**: ✅ Tool detection works, ❌ Compilation fails due to missing clang libraries (same error as Test 1)

#### Test Results Summary

**Good News**:
- ✅ **Auto-detection works for both systems**: The configure script correctly detects both versioned (`llvm-config-20`) and non-versioned (`llvm-config`) tools
- ✅ **Consistent behavior**: Both systems fail at the same point with the same error
- ✅ **Version handling**: The script correctly handles both LLVM 18 and LLVM 20

**Bad News**:
- ❌ **Same root cause**: Both systems fail because `llvm-config --libs` only returns core LLVM libraries (`-lLLVM-18` or `-lLLVM-20`), not clang-specific libraries
- ❌ **Missing clang libraries**: The linker cannot find clang symbols because clang libraries are not included

**Implication**: The solution (adding clang libraries manually) should work for both versioned and non-versioned systems. We need to:
1. Use `llvm-config --libs` for core LLVM libraries (works for both)
2. Manually add clang libraries with version detection (extract version from `llvm-config --version` to construct correct library names)

### Observations

1. **`llvm-config --libs clang` failed**: The command returned an error, triggering the fallback
2. **Fallback returned only core LLVM**: `llvm-config --libs` (without component) returned `-lLLVM-20` only
3. **Missing clang libraries**: The compilation fails with undefined references to clang-specific symbols:
   - `clang::tooling::CommonOptionsParser::create(...)`
   - This is a clang library function, not an LLVM core function
4. **Incomplete library set**: `-lLLVM-20` alone is insufficient - we need clang-specific libraries too
5. **Component recognition issue**: "clang" may not be recognized as a valid component by `llvm-config-20`

### Hypothesis

**The `llvm-config --libs clang` command is failing because "clang" is not recognized as a component, and the fallback `--libs` only returns core LLVM libraries, not clang-specific libraries**:

1. **Component name mismatch**: `llvm-config-20` may not recognize "clang" as a component name
   - Ubuntu's LLVM packaging might use different component names
   - May need to specify components differently (e.g., individual component names, or use `--components` to see available ones)

2. **Separate library requirement**: Clang libraries (like `libclang-cpp20`, `libclang`) may need to be requested separately
   - Core LLVM (`-lLLVM-20`) provides LLVM infrastructure
   - Clang libraries provide clang-specific functionality (parsing, tooling, etc.)
   - These might be separate components or require explicit specification

3. **Library discovery issue**: The fallback `llvm-config --libs` only returns what's needed for basic LLVM, not clang tooling
   - We need to discover the correct component names or library flags for clang
   - May need to check available components and use appropriate ones

**Most likely**: We need to either:
- Find the correct component name(s) for clang libraries in `llvm-config-20`
- Manually add clang libraries (`-lclang-cpp20`, `-lclang`) in addition to `llvm-config --libs` output
- Use `llvm-config --components` to see what's available and construct the library list appropriately

### Investigation Results (Step 1-2)

**Test Output**:
```bash
$ llvm-config-20 --version
20.1.2

$ llvm-config-20 --libs clang
llvm-config: unknown component name: clang

$ llvm-config-20 --libs core
-lLLVM-20

$ llvm-config-20 --libs core analysis transformutils
-lLLVM-20
```

**Key Findings**:
1. ✅ **Confirmed**: "clang" is NOT a recognized component name by `llvm-config-20`
   - Error: `llvm-config: unknown component name: clang`
   - This explains why `--libs clang` failed in our implementation

2. ✅ **Monolithic LLVM library**: Multiple LLVM components (core, analysis, transformutils) all return `-lLLVM-20`
   - This suggests Ubuntu's LLVM 20 is built as a monolithic library
   - Individual component libraries may not be available separately

3. ✅ **Only core LLVM provided**: `llvm-config --libs` commands only return the base `-lLLVM-20` library
   - Clang-specific libraries are NOT included in `llvm-config` output
   - We need to find clang libraries separately

**Implication**: Clang libraries (`libclang-cpp20`, `libclang`) are separate from the core LLVM library and are not managed by `llvm-config --libs`. We need to manually add them to the linker command.

### Recommended Next Steps

#### Step 1: Check available components in llvm-config-20
```bash
llvm-config-20 --components
llvm-config-20 --components | grep -i clang
```

**Status**: ⏳ Pending - Need to run this to see all available components

**Expected**: Will show what component names are recognized. Based on previous findings, "clang" is NOT in the list, but we may see other component names that could help.

#### Step 2: Check what libraries actually exist in the system
```bash
# Check what clang libraries are actually installed
ls -la /usr/lib/llvm-20/lib/libclang* 2>/dev/null
ls -la /usr/lib/x86_64-linux-gnu/libclang* 2>/dev/null
dpkg -L libclang-cpp20 | grep -E "\.so"
dpkg -L libclang-20-dev | grep -E "\.so"
```

**Status**: ⏳ Pending - Need to run this to see actual library files

**Expected**: Will show what clang library files exist and their exact names (e.g., `libclang-cpp20.so`, `libclang.so`, etc.)

#### Step 3: Test manual compilation with discovered libraries
```bash
# Get base LLVM libraries from llvm-config
LLVM_LIBS=$(llvm-config-20 --libs)
LLVM_LDFLAGS=$(llvm-config-20 --ldflags)
LLVM_CXXFLAGS=$(llvm-config-20 --cxxflags)

# Try adding clang libraries manually
g++ -o /tmp/test_clang /tmp/test_clang.cpp \
    $LLVM_LDFLAGS \
    $LLVM_CXXFLAGS \
    $LLVM_LIBS \
    -lclang-cpp20 -lclang

# Or try with version detection
LLVM_VER=$(llvm-config-20 --version | cut -d. -f1)
g++ -o /tmp/test_clang /tmp/test_clang.cpp \
    $LLVM_LDFLAGS \
    $LLVM_CXXFLAGS \
    $LLVM_LIBS \
    -lclang-cpp${LLVM_VER} -lclang
```

**Status**: ⏳ Pending - Need to run this to verify compilation works

**Expected**: Will determine if we need to combine `llvm-config --libs` with manual clang library flags, and what the correct library names are

#### Step 4: Update configure script based on findings
Based on Step 1-4 results:
- **If specific component names work**: Update script to use those component names
- **If manual library flags needed**: Update script to combine `llvm-config --libs` with clang-specific libraries
- **If component discovery needed**: Add logic to query available components and select appropriate ones

### Expected Outcomes and Solutions

**Based on Investigation Results**:

**Most Likely Solution**: Since `llvm-config --libs clang` fails and `llvm-config --libs` only returns `-lLLVM-20`, we need to:

1. **Use `llvm-config --libs` for core LLVM**: Get base LLVM library flags
2. **Manually add clang libraries**: Append clang-specific libraries to the linker command
3. **Handle versioning**: Extract LLVM version to construct correct library names (e.g., `-lclang-cpp20`)

**Implementation Approach**:
```bash
# Get base LLVM libraries from llvm-config
LLVM_LIBS=$(llvm-config-20 --libs)

# Extract version for versioned library names
LLVM_MAJOR_VER=$(llvm-config-20 --version | cut -d. -f1)

# Add clang libraries manually
LLVM_LIBS="$LLVM_LIBS -lclang-cpp${LLVM_MAJOR_VER} -lclang"
```

**Alternative Approach** (if versioned names don't work):
- Try unversioned first: `-lclang-cpp -lclang`
- Fallback to versioned if that fails: `-lclang-cpp20 -lclang`

**If Step 2 shows different library names**:
- Update the library names based on what actually exists in `/usr/lib/llvm-20/lib/`
- May need to check for symlinks or different naming conventions

**Next Implementation**:
- Update `check_clang_lib()` to combine `llvm-config --libs` with manual clang library flags
- Add version detection to construct correct library names
- Test on both versioned (Ubuntu LLVM 20) and non-versioned (Ubuntu LLVM 18, Nix) systems

**Testing Strategy**:
- ✅ **Test 1**: Ubuntu with LLVM 20 (versioned packages) - Tool detection works, same error
- ✅ **Test 2**: Ubuntu with LLVM 18 (non-versioned packages) - Tool detection works, same error
- ⏳ **Test 3**: After fix, verify both systems compile successfully
- ⏳ **Test 4**: Verify Nix system still works (regression test)