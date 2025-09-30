# xdp2 nix development environment

## Introduction

This document ( nix_compile_errors_2025_09_30.md ) describes the nix development environment for the xdp2 project.

The flake.nix in the root of the folder has been created to try to compile the code in ./src/

## Nix development environment

The nix development environment is described in the nix.md document.

The ./documentation/xdp.md describes the overall project.

The ./documentation/xdp2-compiler.md explains the xd2 compiler.

## Current error

```
[das@l:~/Downloads/xdp2]$ nix develop
warning: Git tree '/home/das/Downloads/xdp2' is dirty
error: builder for '/nix/store/18gssjrjckgqxhi9k0w30h02qp2dr9qp-xdp2-build-dev.drv' failed with exit code 2;
       last 25 log lines:
       >     LINK     test_timer
       >     CC       test_pvbuf.o
       >     LINK     test_pvbuf
       >     CC       core-flowdis.o
       >     CC       core-xdp2.o
       >     CC       core-parselite.o
       >     CC       core-null.o
       >     CC       in-tcpdump.o
       >     CC       in-raw.o
       >     CC       in-pcap.o
       >     CC       in-fuzz.o
       >     CC       out-text.o
       >     CC       out-err.o
       >     CC       out-null.o
       >     CC       cores.o
       >     CC       imethods.o
       >     CC       main.o
       >     CC       omethods.o
       >     CC       main.o
       >     CC       print_meta.o
       >     CC       tables.o
       >     CC       parser.o
       > static const struct xdp2_proto_table_entry __falcon_version_table[] = {{.value = 1, .node = &<recovery-expr>(falcon_v1_node)}}make[2]: *** [Makefile:35: parser.p.c] Segmentation fault (core dumped)
       > make[1]: *** [Makefile:11: parse_dump] Error 2
       > make: *** [Makefile:74: all] Error 2
       For full logs, run:
         nix log /nix/store/18gssjrjckgqxhi9k0w30h02qp2dr9qp-xdp2-build-dev.drv
error: 1 dependencies of derivation '/nix/store/38fh752nwd89s41akhyvgzcx0cdgx2n7-nix-shell-env.drv' failed to build

[das@l:~/Downloads/xdp2]$ nix log /nix/store/18gssjrjckgqxhi9k0w30h02qp2dr9qp-xdp2-build-dev.drv
Running phase: unpackPhase
@nix { "action": "setPhase", "phase": "unpackPhase" }
unpacking source archive /nix/store/fbhc5vrk7pwfk3krzrmzq9r2pqgjaqj2-514xvldk5ry6n60ppa460prs2g09pma2-source
source root is 514xvldk5ry6n60ppa460prs2g09pma2-source
Running phase: patchPhase
@nix { "action": "setPhase", "phase": "patchPhase" }
Running phase: updateAutotoolsGnuConfigScriptsPhase
@nix { "action": "setPhase", "phase": "updateAutotoolsGnuConfigScriptsPhase" }
Running phase: configurePhase
@nix { "action": "setPhase", "phase": "configurePhase" }


Platform is default
Architecture is x86_64
Architecture includes for x86_64 not found, using generic
Target Architecture is
COMPILER is gcc
XDP2_CLANG_VERSION=20.1.8
XDP2_C_INCLUDE_PATH=/nix/store/d3bv4bj7klgfc1w1x01d91a1f4g7ywga-llvm-20.1.8-lib/lib/clang/20/include
XDP2_CLANG_RESOURCE_PATH=/nix/store/d3bv4bj7klgfc1w1x01d91a1f4g7ywga-llvm-20.1.8-lib/lib/clang/20

=== config.mk contents ===
# Generated config based on --build-opt-parser
ifneq ($(TOP_LEVEL_MAKE),y)
# user can control verbosity similar to kernel builds (e.g., V=1)
ifeq ("$(origin V)", "command line")
        VERBOSE = $(V)
endif
ifndef VERBOSE
        VERBOSE = 0
endif
ifeq ($(VERBOSE),1)
        Q =
else
        Q = @
endif

ifeq ($(VERBOSE), 0)
        QUIET_EMBED    = @echo '    EMBED    '$@;
        QUIET_CC       = @echo '    CC       '$@;
        QUIET_CXX      = @echo '    CXX      '$@;
        QUIET_AR       = @echo '    AR       '$@;
        QUIET_ASM      = @echo '    ASM      '$@;
        QUIET_XDP2    = @echo '    XDP2    '$@;
        QUIET_LINK     = @echo '    LINK     '$@;
        QUIET_INSTALL  = @echo '    INSTALL  '$(TARGETS);
endif
PKG_CONFIG_PATH=/nix/store/rz4bmcm8dwsy7ylx6rhffkwkqn6n8srn-ncurses-6.5-dev/lib/pkgconfig:/nix/store/29mcvdnd9s6sp46cjmqm0pfg4xs56rik-zlib-1.3.1-dev/lib/pkgconfig:/nix/store/20cck0r5dvh21c4w7wy8j3f7cc6wb5k2-boost-1.87.0-dev/lib/pkgconfig:/nix/store/0crnzrvmjwvsn2z13v82w71k9nvwafbd-libpcap-1.10.5/lib/pkgconfig:/nix/store/nsr3sad722q5b6r2xgc0iiwiqca3ili6-libelf-0.8.13/lib/pkgconfig:/nix/store/8jgnmlzb820a1bkff5bkwl1qi681qz7n-libbpf-1.6.2/lib/pkgconfig:/nix/store/j0438064c6zc94gr6xk6mkfvpaxxk8kd-python3-3.13>
PATH_ARG=""
CFLAGS_PYTHON=`$(PKG_CONFIG) $(PATH_ARG) --cflags python3-embed`
LDFLAGS_PYTHON=`$(PKG_CONFIG) $(PATH_ARG) --libs python3-embed`
CAT=cat
CC_ISA_EXT_FLAGS :=
ASM_ISA_EXT_FLAGS :=
C_MARCH_FLAGS :=
ASM_MARCH_FLAGS :=
HOST_CC := gcc
HOST_CXX := g++
CC_ELF :=
LDLIBS =
LDLIBS += $(LDLIBS_LOCAL) -ldl
LDLIBS_STATIC =
LDLIBS_STATIC += $(LDLIBS_LOCAL) -ldl
TEST_TARGET_STATIC = $(TEST_TARGET:%=%_static)
OBJ = $(TEST_TARGET:%=%.o)
STATIC_OBJ = $(TEST_TARGET_STATIC:%=%.o)
TARGETS = $(TEST_TARGET)
PKG_CONFIG := pkg-config
TARGET_ARCH :=
XDP2_ARCH := x86_64
XDP2_CFLAGS += -DARCH_x86_64

CC := gcc
LD := ld
CXX := g++
HOST_LLVM_CONFIG := /nix/store/hmmni7ynqhn65mxmssgif5g5baxr03h7-llvm-20.1.8-dev/bin/llvm-config
LLVM_CONFIG := llvm-config
LDFLAGS :=
PYTHON := python3
HAVE_SCAPY:=y
ifneq ($(USE_HOST_TOOLS),y)
%.o: %.c
        $(QUIET_CC)$(CC) $(CFLAGS) $(XDP2_CFLAGS) $(EXTRA_CFLAGS) $(C_MARCH_FLAGS)\
                                        -c -o $@ $<
%_static.o: %.c
        $(QUIET_CC)$(CC) $(CFLAGS) $(XDP2_CFLAGS) $(EXTRA_CFLAGS) -DXDP2_NO_DYNAMIC $(C_MARCH_FLAGS)\
                                        -c -o $@ $<
%.o: %.cpp
        $(QUIET_CXX)$(CXX) $(CXXFLAGS) $(EXTRA_CXXFLAGS) $(C_MARCH_FLAGS)\
                                                -c -o $@ $<
%.o: %.s
        $(QUIET_ASM)$(CC) $(ASM_MARCH_FLAGS)\
                                        -c -o $@ $<
else
%.o: %.c
        $(QUIET_CC)$(HOST_CC) $(CFLAGS) $(XDP2_CFLAGS) $(EXTRA_CFLAGS) -c -o $@ $<
%.o: %.cpp
        $(QUIET_CXX)$(HOST_CXX) $(XDP2_CXXFLAGS) $(CXXFLAGS) $(EXTRA_CXXFLAGS)          \
                                                -c -o $@ $<
endif

XDP2_CLANG_VERSION=20.1.8
XDP2_C_INCLUDE_PATH=/nix/store/d3bv4bj7klgfc1w1x01d91a1f4g7ywga-llvm-20.1.8-lib/lib/clang/20/include
XDP2_CLANG_RESOURCE_PATH=/nix/store/d3bv4bj7klgfc1w1x01d91a1f4g7ywga-llvm-20.1.8-lib/lib/clang/20


endif # !TOP_LEVEL_MAKE

INSTALLDIR ?= /nix/store/a4aj5gxcm1ib3kw1dys93l5r0q0469bb-xdp2-build-dev
INSTALLTARNAME ?= install.tgz
BUILD_OPT_PARSER ?= y
CONFIG_DEFINES :=
=== End config.mk ===
Running phase: buildPhase
@nix { "action": "setPhase", "phase": "buildPhase" }
=== Building cppfront-compiler v0.3.0 with Nix-controlled toolchain ===
make: Entering directory '/build/514xvldk5ry6n60ppa460prs2g09pma2-source/thirdparty/cppfront'
g++ -std=c++20 source/cppfront.cpp -o cppfront-compiler
make: Leaving directory '/build/514xvldk5ry6n60ppa460prs2g09pma2-source/thirdparty/cppfront'
=== cppfront-compiler version ===

cppfront compiler v0.3.0   Build 8B10:1325
Copyright(c) Herb Sutter   All rights reserved

SPDX-License-Identifier: CC-BY-NC-ND-4.0
  No commercial use
  No forks/derivatives
  Note: This license emphasizes that this is a personal
        experiment; it will be upgraded if that changes

Absolutely no warranty - try at your own risk
=== End cppfront version ===
=== Linking Analysis: cppfront-compiler ===
File type:
../thirdparty/cppfront/cppfront-compiler: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), dynamically linked, interpreter /nix/store/776irwlgfb65a782cxmyk61pck460fs9-glibc-2.40-66/lib/ld-linux-x86-64.so.2, for GNU/Linux 3.10.0, not stripped
Dynamic library dependencies:
        linux-vdso.so.1 (0x00007ffff7fc4000)
        libstdc++.so.6 => /nix/store/41ym1jm1b7j3rhglk82gwg9jml26z1km-gcc-14.3.0-lib/lib/libstdc++.so.6 (0x00007ffff7c00000)
        libm.so.6 => /nix/store/776irwlgfb65a782cxmyk61pck460fs9-glibc-2.40-66/lib/libm.so.6 (0x00007ffff7ed4000)
        libgcc_s.so.1 => /nix/store/41ym1jm1b7j3rhglk82gwg9jml26z1km-gcc-14.3.0-lib/lib/libgcc_s.so.1 (0x00007ffff7ea6000)
        libc.so.6 => /nix/store/776irwlgfb65a782cxmyk61pck460fs9-glibc-2.40-66/lib/libc.so.6 (0x00007ffff7800000)
        /nix/store/776irwlgfb65a782cxmyk61pck460fs9-glibc-2.40-66/lib/ld-linux-x86-64.so.2 => /nix/store/776irwlgfb65a782cxmyk61pck460fs9-glibc-2.40-66/lib64/ld-linux-x86-64.so.2 (0x00007ffff7fc6000)
=== End linking analysis ===
SUCCESS: cppfront-compiler v0.3.0 built with Nix toolchain
=== Starting main build with linking analysis ===

tools
    CC       get_uet_udp_port
WARNING: Could not retrieve the OS's nameserver !
WARNING: Could not retrieve the OS's nameserver !
    CC       get_falcon_udp_port
WARNING: Could not retrieve the OS's nameserver !
    CC       get_sue_udp_port
WARNING: Could not retrieve the OS's nameserver !
include/xdp2gen/llvm/patterns.h2... ok (mixed Cpp1/Cpp2, Cpp2 code passes safety checks)

include/xdp2gen/ast-consumer/patterns.h2... ok (mixed Cpp1/Cpp2, Cpp2 code passes safety checks)

    CXX      src/main.o
In file included from /nix/store/20cck0r5dvh21c4w7wy8j3f7cc6wb5k2-boost-1.87.0-dev/include/boost/wave/wave_config.hpp:17,
                 from /nix/store/20cck0r5dvh21c4w7wy8j3f7cc6wb5k2-boost-1.87.0-dev/include/boost/wave.hpp:16,
                 from src/main.cpp:45:
/nix/store/20cck0r5dvh21c4w7wy8j3f7cc6wb5k2-boost-1.87.0-dev/include/boost/detail/atomic_count.hpp:10:1: note: '#pragma message: This header is deprecated. Use <boost/smart_ptr/detail/atomic_count.hpp> instead.'
   10 | BOOST_HEADER_DEPRECATED("<boost/smart_ptr/detail/atomic_count.hpp>")
      | ^~~~~~~~~~~~~~~~~~~~~~~
In file included from src/main.cpp:50:
include/xdp2gen/python_generators.h: In function 'int xdp2gen::python::generate_root_parser_c(std::string, std::string, xdp2gen::graph_t, std::vector<xdp2gen::parser<boost::adjacency_list<boost::vecS, boost::vecS, boost::directedS, xdp2gen::vertex_property, xdp2gen::edge_property, boost::no_property, boost::vecS> > >, xdp2gen::clang_ast::metadata_record)':
include/xdp2gen/python_generators.h:533:26: warning: 'void Py_SetProgramName(const wchar_t*)' is deprecated [-Wdeprecated-declarations]
  533 |         Py_SetProgramName(program_name.get());
      |         ~~~~~~~~~~~~~~~~~^~~~~~~~~~~~~~~~~~~~
In file included from /nix/store/829wb290i87wngxlh404klwxql5v18p4-python3-3.13.7/include/python3.13/Python.h:124,
                 from include/xdp2gen/python_generators.h:36:
/nix/store/829wb290i87wngxlh404klwxql5v18p4-python3-3.13.7/include/python3.13/pylifecycle.h:37:38: note: declared here
   37 | Py_DEPRECATED(3.11) PyAPI_FUNC(void) Py_SetProgramName(const wchar_t *);
      |                                      ^~~~~~~~~~~~~~~~~
include/xdp2gen/python_generators.h: In function 'int xdp2gen::python::generate_root_parser_xdp_c(std::string, std::string, xdp2gen::graph_t, std::vector<xdp2gen::parser<boost::adjacency_list<boost::vecS, boost::vecS, boost::directedS, xdp2gen::vertex_property, xdp2gen::edge_property, boost::no_property, boost::vecS> > >, xdp2gen::clang_ast::metadata_record)':
include/xdp2gen/python_generators.h:578:26: warning: 'void Py_SetProgramName(const wchar_t*)' is deprecated [-Wdeprecated-declarations]
  578 |         Py_SetProgramName(program_name.get());
      |         ~~~~~~~~~~~~~~~~~^~~~~~~~~~~~~~~~~~~~
/nix/store/829wb290i87wngxlh404klwxql5v18p4-python3-3.13.7/include/python3.13/pylifecycle.h:37:38: note: declared here
   37 | Py_DEPRECATED(3.11) PyAPI_FUNC(void) Py_SetProgramName(const wchar_t *);
      |                                      ^~~~~~~~~~~~~~~~~
    CXX      src/template.o
    EMBED    ../../templates/xdp2/c_def.cpp
    CXX      ../../templates/xdp2/c_def.o
    EMBED    ../../templates/xdp2/xdp_def.cpp
    CXX      ../../templates/xdp2/xdp_def.o
    EMBED    ../../templates/xdp2/common_parser.cpp
    CXX      ../../templates/xdp2/common_parser.o

include
    MACROGEN _pmacro_gen.h
    TBL_INC  _stable.h
    TBL_INC  _dtable.h

lib
    CC       cli.o
    AR       libcli.a
    CC       siphash.o
    CC       libsiphash.so
    AR       libsiphash.a
    CC       crc16.o
    CC       crc32c.o
    CC       crc64.o
    CC       crcspeed.o
    CC       libcrc.so
    AR       libcrc.a
    CC       flow_dissector.o
    AR       libflowdis.a
    CC       lzf_compress.o
    CC       lzf_decompress.o
    CC       liblzf_compress.so
    AR       liblzf_compress.a
    CC       liblzf_decompress.so
    AR       liblzf_decompress.a
    CC       murmur3_hash.o
    CC       libmurmur3hash.so
    AR       libmurmur3hash.a
    CC       vstruct.o
    CC       timer.o
    CC       cli.o
    CC       pcap.o
    CC       packets_helpers.o
    CC       dtable.o
    CC       obj_allocator.o
    CC       pvbuf.o
    CC       pvpkt.o
    CC       config_functions.o
    CC       parser.o
    CC       accelerator.o
    CC       locks.o
    CC       parsers/parser_big.o
    CC       parsers/parser_simple_hash.o
    AR       libxdp2.a
    CC       parser.o
    AR       libparselite.a

test
    CC       test_vstructs.o
    LINK     test_vstructs
    CC       test_switch.o
    LINK     test_switch
    CC       test_table.o
    CC       sftable_plain.o
    CC       sftable_tern.o
    CC       sftable_lpm.o
    CC       dftable_plain.o
    CC       dftable_tern.o
    CC       dftable_lpm.o
    CC       stable_plain.o
    CC       stable_tern.o
    CC       stable_lpm.o
    CC       dtable_plain.o
    CC       dtable_tern.o
    CC       dtable_lpm.o
    LINK     test_tables
    CC       test_timer.o
    LINK     test_timer
    CC       test_pvbuf.o
    LINK     test_pvbuf
    CC       core-flowdis.o
    CC       core-xdp2.o
    CC       core-parselite.o
    CC       core-null.o
    CC       in-tcpdump.o
    CC       in-raw.o
    CC       in-pcap.o
    CC       in-fuzz.o
    CC       out-text.o
    CC       out-err.o
    CC       out-null.o
    CC       cores.o
    CC       imethods.o
    CC       main.o
    CC       omethods.o
    CC       main.o
    CC       print_meta.o
    CC       tables.o
    CC       parser.o
static const struct xdp2_proto_table_entry __falcon_version_table[] = {{.value = 1, .node = &<recovery-expr>(falcon_v1_node)}}make[2]: *** [Makefile:35: parser.p.c] Segmentation fault (core dumped)
make[1]: *** [Makefile:11: parse_dump] Error 2
make: *** [Makefile:74: all] Error 2

[das@l:~/Downloads/xdp2]$
```

## Analysis and Next Steps

Based on the comprehensive analysis of the error logs, documentation, and codebase, I can provide detailed insights into the root cause and potential solutions for the `nix develop` compilation failure.

### Root Cause Analysis

The segmentation fault occurs during the **test build phase**, specifically when the `xdp2-compiler` attempts to generate optimized parser code from `src/test/parse_dump/parser.c`. This is **not** a fundamental build system issue, but rather a runtime issue with the XDP2 compiler's code generation process.

#### Key Findings:

1. **Build System Works Correctly**:
   - The main XDP2 build completes successfully
   - All libraries (libxdp2, libcli, libsiphash, etc.) build without issues
   - The `xdp2-compiler` itself builds and links correctly
   - cppfront v0.3.0 builds successfully with the Nix toolchain

2. **Segfault Location**:
   - **File**: `src/test/parse_dump/Makefile:35`
   - **Command**: `$(XDP2_COMPILER) -I$(SRCDIR)/include -o parser.p.c -i parser.c`
   - **Process**: XDP2 compiler processing a large, complex parser file (1,219 lines, 37,695 bytes)

3. **Dual Compiler Architecture**:
   - **HOST_CXX** (clang++): Used to build the `xdp2-compiler` tool (needs LLVM integration)
   - **CC** (gcc): Used to build final libraries and applications
   - This architecture is working correctly - the issue is in the generated tool's runtime behavior

4. **Python Integration Issue**:
   - The `xdp2-compiler` uses an embedded Python interpreter for code generation
   - The segfault occurs in the Python code generation process (`generate_root_parser_c` function)
   - The error message shows malformed C code generation: `&<recovery-expr>(falcon_v1_node)`

### Detailed Next Steps for Debugging

#### Phase 1: Immediate Debugging (High Priority)

1. **Enable Core Dumps and Debugging**:
   ```bash
   # In the nix develop shell
   ulimit -c unlimited
   export XDP2_COMPILER_DEBUG=1
   make clean
   make 2>&1 | tee build.log
   ```

2. **Analyze the Core Dump**:
   ```bash
   # If core dump is generated
   gdb --batch --ex run --ex bt --ex quit ./tools/compiler/xdp2-compiler core
   ```

3. **Test with Smaller Input Files**:
   - Create a minimal parser.c file to isolate the issue
   - Test if the segfault is related to file size/complexity
   - Compare behavior with Ubuntu environment

#### Phase 2: Python Environment Investigation (Medium Priority)

4. **Python Environment Analysis**:
   ```bash
   # Check Python version and paths in nix environment
   python3 --version
   python3 -c "import sys; print(sys.path)"
   python3 -c "import sysconfig; print(sysconfig.get_paths())"

   # Test Python embedding
   python3 -c "import ctypes; print('Python embedding works')"
   ```

5. **Python Library Compatibility**:
   - The `xdp2-compiler` uses `Py_SetProgramName()` which is deprecated in Python 3.11+
   - Check if this deprecation warning is causing runtime issues
   - Consider patching the Python integration code

6. **Template Generation Debugging**:
   ```bash
   # Test the Python template generation directly
   cd src/test/parse_dump
   python3 -c "
   import sys
   sys.path.append('../../tools/compiler')
   # Test template generation functions
   "
   ```

#### Phase 3: Compiler Toolchain Investigation (Medium Priority)

7. **LLVM/Clang Version Compatibility**:
   - Current setup uses LLVM 20.1.8
   - Test with different LLVM versions (19.x, 21.x)
   - Check if the issue is version-specific

8. **Memory and Resource Limits**:
   ```bash
   # Check if it's a memory issue
   free -h
   # Monitor memory usage during compilation
   watch -n 1 'ps aux | grep xdp2-compiler'
   ```

#### Phase 4: Alternative Solutions (Lower Priority)

9. **Skip Problematic Test**:
   - Modify the build to skip the `parse_dump` test
   - Focus on getting the main build working first
   - Add the test back once the core issue is resolved

10. **Use Ubuntu Toolchain in Nix**:
    - Create a hybrid environment using Ubuntu's gcc/clang versions
    - Test if the issue is Nix-specific vs. toolchain-specific

11. **Static Linking Approach**:
    - Try building `xdp2-compiler` with static linking
    - This might resolve Python library conflicts

#### Phase 5: Long-term Solutions (Future Work)

12. **Update Python Integration**:
    - Replace deprecated `Py_SetProgramName()` calls
    - Update to modern Python C API usage
    - Add proper error handling for Python embedding

13. **Improve Error Handling**:
    - Add better error reporting in the XDP2 compiler
    - Implement graceful fallbacks for code generation failures
    - Add validation for generated code before writing to files

### Recommended Immediate Action Plan

1. **Start with Phase 1** - Enable debugging and analyze core dumps
2. **If no core dump**, proceed to **Phase 2** - Python environment investigation
3. **Test with minimal input** to isolate the issue
4. **Compare with Ubuntu environment** to identify Nix-specific problems

### Expected Outcomes

- **Best case**: Identify a simple configuration issue that can be fixed with environment variables or patches
- **Likely case**: Find a Python library compatibility issue that requires code updates
- **Worst case**: Discover a fundamental incompatibility that requires significant refactoring

The good news is that the main XDP2 build system is working correctly, and this appears to be a test-specific issue that doesn't prevent the core functionality from being built and used.