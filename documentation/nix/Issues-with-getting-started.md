# Issues with getting-started.md

## Introduction

This is a working document capturing the issues with the ./documents/getting-started.md guide for the xdp2 project.

This document will be used to capture details of multiple defects.  Each defect will capture:
- Details of the defect
- Hypothesis of what's causing the defect.  There could be at least x2
- Next steps to invetigate and resolve

New defect will be added to the bottom, so we there is a working history to avoid fixing the same problem multiple times.

## Defects

### Defect 1

The second step of the "Make" step is failing, for both no version and version packages.  Could this be an issue with configure.sh creating config.mk incorrectly, or something else?

ubuntu no version
```
das@ubuntu2404-no-nix-no-version:~/xdp2/src$ make clean
das@ubuntu2404-no-nix-no-version:~/xdp2/src$ make

tools
    CC       get_uet_udp_port
    CC       get_falcon_udp_port
    CC       get_sue_udp_port
include/xdp2gen/llvm/patterns.h2... ok (mixed Cpp1/Cpp2, Cpp2 code passes safety checks)

include/xdp2gen/ast-consumer/patterns.h2... ok (mixed Cpp1/Cpp2, Cpp2 code passes safety checks)

    CXX      src/main.o
    CXX      src/template.o
    EMBED    ../../templates/xdp2/c_def.cpp
    CXX      ../../templates/xdp2/c_def.o
    EMBED    ../../templates/xdp2/xdp_def.cpp
    CXX      ../../templates/xdp2/xdp_def.o
    EMBED    ../../templates/xdp2/common_parser.cpp
    CXX      ../../templates/xdp2/common_parser.o
/usr/bin/ld: cannot find -lclang-cpp: No such file or directory
collect2: error: ld returned 1 exit status
make[2]: *** [Makefile:41: xdp2-compiler] Error 1
make[1]: *** [Makefile:14: compiler] Error 2
make: *** [Makefile:77: all] Error 2
das@ubuntu2404-no-nix-no-version:~/xdp2/src$ llvm-config --version
18.1.3
das@ubuntu2404-no-nix-no-version:~/xdp2/src$
```

ubuntu with version packages
```
das@ubuntu2404-no-nix:~/xdp2/src$ make clean
das@ubuntu2404-no-nix:~/xdp2/src$ make

tools
    CC       get_uet_udp_port
    CC       get_falcon_udp_port
    CC       get_sue_udp_port
include/xdp2gen/llvm/patterns.h2... ok (mixed Cpp1/Cpp2, Cpp2 code passes safety checks)

include/xdp2gen/ast-consumer/patterns.h2... ok (mixed Cpp1/Cpp2, Cpp2 code passes safety checks)

    CXX      src/main.o
    CXX      src/template.o
    EMBED    ../../templates/xdp2/c_def.cpp
    CXX      ../../templates/xdp2/c_def.o
    EMBED    ../../templates/xdp2/xdp_def.cpp
    CXX      ../../templates/xdp2/xdp_def.o
    EMBED    ../../templates/xdp2/common_parser.cpp
    CXX      ../../templates/xdp2/common_parser.o
/usr/bin/ld: cannot find -lclang-cpp: No such file or directory
collect2: error: ld returned 1 exit status
make[2]: *** [Makefile:41: xdp2-compiler] Error 1
make[1]: *** [Makefile:14: compiler] Error 2
make: *** [Makefile:77: all] Error 2
das@ubuntu2404-no-nix:~/xdp2/src$ llvm-config-20 --version
20.1.2
das@ubuntu2404-no-nix:~/xdp2/src$

```

**Debug output from configure.sh:**

Ubuntu with version packages (llvm-20):
```
das@ubuntu2404-no-nix:~/xdp2/src$ ./configure.sh --debug-level 4

Platform is default
Architecture is x86_64
Architecture includes for x86_64 not found, using generic
Target Architecture is
COMPILER is gcc
[DEBUG-1] Tool Detection: Starting llvm-config detection
[DEBUG-2] Tool Detection: Auto-detecting llvm-config...
[DEBUG-3] Tool Detection: Checking for llvm-config
[DEBUG-3] Tool Detection: Checking for llvm-config-20
[DEBUG-3] Tool Detection: Found llvm-config-20 at /usr/bin/llvm-config-20
[DEBUG-1] Tool Detection: Selected llvm-config-20 (version 20.1.2)
LLVM_VER:20.1.2
[DEBUG-1] Tool Detection: Using HOST_LLVM_CONFIG=/usr/bin/llvm-config-20
HOST_LLVM_CONFIG:/usr/bin/llvm-config-20
[DEBUG-1] Configuration: Platform=default, Architecture=x86_64, Compiler=gcc
[DEBUG-1] Clang.Lib: Starting check
[DEBUG-4] Clang.Lib: HOST_CXX=g++
[DEBUG-4] Clang.Lib: HOST_LLVM_CONFIG=/usr/bin/llvm-config-20
[DEBUG-4] Clang.Lib: llvm-config --ldflags: -L/usr/lib/llvm-20/lib
[DEBUG-4] Clang.Lib: llvm-config --cxxflags: -I/usr/lib/llvm-20/include -std=c++17   -fno-exceptions -funwind-tables -D_GNU_SOURCE -D__STDC_CONSTANT_MACROS -D__STDC_FORMAT_MACROS -D__STDC_LIMIT_MACROS
[DEBUG-4] Clang.Lib: llvm-config --libdir: /usr/lib/llvm-20/lib
[DEBUG-4] Clang.Lib: llvm-config --libs: -lLLVM-20
[DEBUG-4] Clang.Lib: Found clang-cpp: libclang-cpp.so.20.1 -> using full path
[DEBUG-4] Clang.Lib: Found clangTooling: libclangTooling.a -> -lclangTooling
[DEBUG-3] Clang.Lib: Discovered clang libraries: /usr/lib/llvm-20/lib/libclang-cpp.so.20.1 -lclangTooling
[DEBUG-3] Clang.Lib: Attempting link with discovered libs: /usr/lib/llvm-20/lib/libclang-cpp.so.20.1 -lclangTooling
[DEBUG-1] Clang.Lib: Check PASSED with libraries: /usr/lib/llvm-20/lib/libclang-cpp.so.20.1 -lclangTooling
XDP2_CLANG_VERSION=20.1.2
XDP2_C_INCLUDE_PATH=/usr/lib/llvm-20/lib/clang/20/include
XDP2_CLANG_RESOURCE_PATH=/usr/lib/llvm-20/lib/clang/20
```

Ubuntu with no version packages (llvm-18):
```
das@ubuntu2404-no-nix-no-version:~/xdp2/src$ ./configure.sh --debug-level 4

Platform is default
Architecture is x86_64
Architecture includes for x86_64 not found, using generic
Target Architecture is
COMPILER is gcc
[DEBUG-1] Tool Detection: Starting llvm-config detection
[DEBUG-2] Tool Detection: Auto-detecting llvm-config...
[DEBUG-3] Tool Detection: Checking for llvm-config
[DEBUG-3] Tool Detection: Found llvm-config at /usr/bin/llvm-config
[DEBUG-1] Tool Detection: Selected llvm-config (version 18.1.3)
LLVM_VER:18.1.3
[DEBUG-1] Tool Detection: Using HOST_LLVM_CONFIG=/usr/bin/llvm-config
HOST_LLVM_CONFIG:/usr/bin/llvm-config
[DEBUG-1] Configuration: Platform=default, Architecture=x86_64, Compiler=gcc
[DEBUG-1] Clang.Lib: Starting check
[DEBUG-4] Clang.Lib: HOST_CXX=g++
[DEBUG-4] Clang.Lib: HOST_LLVM_CONFIG=/usr/bin/llvm-config
[DEBUG-4] Clang.Lib: llvm-config --ldflags: -L/usr/lib/llvm-18/lib
[DEBUG-4] Clang.Lib: llvm-config --cxxflags: -I/usr/lib/llvm-18/include -std=c++17   -fno-exceptions -funwind-tables -D_GNU_SOURCE -D__STDC_CONSTANT_MACROS -D__STDC_FORMAT_MACROS -D__STDC_LIMIT_MACROS
[DEBUG-4] Clang.Lib: llvm-config --libdir: /usr/lib/llvm-18/lib
[DEBUG-4] Clang.Lib: llvm-config --libs: -lLLVM-18
[DEBUG-4] Clang.Lib: Found clang-cpp: libclang-cpp.so.18.1 -> using full path
[DEBUG-4] Clang.Lib: Found clangTooling: libclangTooling.a -> -lclangTooling
[DEBUG-3] Clang.Lib: Discovered clang libraries: /usr/lib/llvm-18/lib/libclang-cpp.so.18.1 -lclangTooling
[DEBUG-3] Clang.Lib: Attempting link with discovered libs: /usr/lib/llvm-18/lib/libclang-cpp.so.18.1 -lclangTooling
[DEBUG-1] Clang.Lib: Check PASSED with libraries: /usr/lib/llvm-18/lib/libclang-cpp.so.18.1 -lclangTooling
XDP2_CLANG_VERSION=18.1.3
XDP2_C_INCLUDE_PATH=/usr/lib/llvm-18/lib/clang/18/include
XDP2_CLANG_RESOURCE_PATH=/usr/lib/llvm-18/lib/clang/18
```

#### Hypothesis

**Primary Hypothesis (CONFIRMED):**
The `configure.sh` script successfully discovers the correct clang library flags during its `check_clang_lib()` function, but this information is **not written to `config.mk`**. The `src/tools/compiler/Makefile` then falls back to a hardcoded default value `CLANG_LIBS ?= -lclang -lLLVM -lclang-cpp` that fails because:
- The discovered libraries use **full paths** to versioned libraries (e.g., `/usr/lib/llvm-20/lib/libclang-cpp.so.20.1` or `/usr/lib/llvm-18/lib/libclang-cpp.so.18.1`)
- There are **no symlinks** from `libclang-cpp.so` to the versioned libraries, so the `-lclang-cpp` linker flag cannot resolve the library

**Confirmed Evidence from Debug Output:**
1. ✅ `check_clang_lib()` **successfully discovers** the correct libraries:
   - Ubuntu llvm-20: `/usr/lib/llvm-20/lib/libclang-cpp.so.20.1 -lclangTooling`
   - Ubuntu llvm-18: `/usr/lib/llvm-18/lib/libclang-cpp.so.18.1 -lclangTooling`
2. ✅ The check **PASSES** during configure (both systems show `[DEBUG-1] Clang.Lib: Check PASSED`)
3. ✅ The discovered libraries use **full paths** because no symlink exists (debug shows "using full path")
4. ❌ The discovered library information is **not written to `config.mk`** - no `CLANG_LIBS` variable is output
5. ❌ The Makefile uses hardcoded `CLANG_LIBS ?= -lclang -lLLVM -lclang-cpp` which fails with `/usr/bin/ld: cannot find -lclang-cpp`

**Root Cause:**
- In `src/configure.sh`, the `check_clang_lib()` function stores discovered libraries in `CLANG_LIBS_FOUND` (local variable)
- This variable is only used internally to test compilation
- After the function returns successfully, the discovered value is **lost** - it's never written to `config.mk`
- The Makefile's hardcoded default expects `-lclang-cpp` which doesn't exist (only versioned full paths exist)

#### Next steps

1. ✅ **Verify the hypothesis:** (COMPLETED)
   - ✅ `check_clang_lib()` successfully discovers clang libraries on both systems
   - ✅ Libraries discovered: full paths to versioned libraries (no symlinks exist)
   - ✅ `CLANG_LIBS` is **NOT** present in `config.mk` (confirmed - this is the bug)

2. **Fix the root cause:**
   - Modify `check_clang_lib()` in `configure.sh` to store the discovered `CLANG_LIBS_FOUND` value in a global variable (e.g., `CLANG_LIBS_DISCOVERED`) before the function returns
   - After `check_clang_lib()` is called (around line 707), write the discovered value to `config.mk` as `CLANG_LIBS := <discovered_value>`
   - **Important**: The discovered value from debug output shows:
     - Ubuntu llvm-20: `/usr/lib/llvm-20/lib/libclang-cpp.so.20.1 -lclangTooling`
     - Ubuntu llvm-18: `/usr/lib/llvm-18/lib/libclang-cpp.so.18.1 -lclangTooling`
   - Note: The Makefile currently expects `-lclang -lLLVM -lclang-cpp`, but the discovered libraries use full paths for clang-cpp. Need to verify if `-lclang` is still needed or if it's provided by the full path library. The `-lLLVM` is already provided by `LLVM_LIBS` in the Makefile (from `llvm-config --libdir`).

3. **Update the Makefile (if needed):**
   - Review `src/tools/compiler/Makefile` to ensure it properly uses the `CLANG_LIBS` variable from `config.mk`
   - Consider whether the hardcoded default should be kept as a fallback or removed entirely

4. ✅ **Test the fix:** (COMPLETED)
   - ✅ Tested on both Ubuntu systems (with and without versioned packages)
   - ✅ `make` succeeds after the fix
   - ✅ The generated `config.mk` contains the correct `CLANG_LIBS` value
   - ✅ `xdp2-compiler` is successfully built

**Status: RESOLVED** - Fix implemented in `configure.sh` to write discovered `CLANG_LIBS` to `config.mk`.

### Defect 2

The ports_parser sample fails to compile because it cannot find the `xdp2/parser.h` header file. The error occurs when trying to build the sample parser without having run `make install` first.

**Error output:**
```
das@ubuntu2404-no-nix-no-version:~/xdp2/samples/parser/ports_parser$ make
gcc -I/usr/include -g   -c -o parser.o parser.c
parser.c:42:10: fatal error: xdp2/parser.h: No such file or directory
   42 | #include "xdp2/parser.h"
      |          ^~~~~~~~~~~~~~~
compilation terminated.
make: *** [<builtin>: parser.o] Error 1
```

**Context:**
- The sample Makefile (`samples/parser/ports_parser/Makefile`) defaults `XDP2DIR` to `/usr`
- It sets `INCDIR=$(XDP2DIR)/include`, which becomes `/usr/include` by default
- The compiler uses `-I$(INCDIR)` which results in `-I/usr/include`
- The header file `xdp2/parser.h` exists in the source tree at `src/include/xdp2/parser.h`
- However, the headers are not installed to `/usr/include` because `make install` has not been run
- The getting-started.md guide doesn't mention running `make install` before trying the samples

#### Hypothesis

**Primary Hypothesis:**
The getting-started.md guide is missing a step to either:
1. Run `make install` to install headers and libraries to the default location (`/usr`), OR
2. Set `XDP2DIR` environment variable to point to the source tree or install directory when building samples

**Supporting Evidence:**
1. The sample Makefile has a comment indicating `XDP2DIR` can be set: `# Set XDP2DIR to the install directory for XDP2 like make XDP2DIR=~/xdp2/install`
2. The header file exists in the source tree at `src/include/xdp2/parser.h`
3. The default `XDP2DIR=/usr` assumes a system-wide installation
4. The getting-started.md guide shows building `xdp2-compiler` but doesn't show `make install` before trying samples
5. The error shows the compiler is looking in `/usr/include` which is the default when `XDP2DIR=/usr`

**Alternative Hypothesis:**
The sample Makefile should default to using the source tree location instead of `/usr`, but this is less likely since the comment suggests it's designed to work with an install directory.

#### Next steps

1. **Verify the hypothesis:**
   - Check if `make install` installs headers to the expected location
   - Verify what `INSTALLDIR` defaults to in `config.mk` (likely `../../install/x86_64` based on the Makefile)
   - Test if setting `XDP2DIR` to the source tree works: `make XDP2DIR=~/xdp2/src`
   - Test if running `make install` first resolves the issue

2. **Determine the best solution:**
   - Option A: Update getting-started.md to include `make install` step before trying samples
   - Option B: Update getting-started.md to show setting `XDP2DIR` to point to source tree (e.g., `make XDP2DIR=~/xdp2/src`)
   - Option C: Modify the sample Makefile to auto-detect the source tree location if headers aren't found in default location
   - Option D: Combination - show both options in the guide

3. **Update the documentation:**
   - Add the missing step(s) to getting-started.md
   - Ensure the guide clearly explains where headers need to be located
   - Consider adding a note about the `XDP2DIR` variable and when to use it

4. **Test the fix:**
   - Verify the sample builds successfully after following the updated guide
   - Test both approaches (install vs. setting XDP2DIR) to ensure both work