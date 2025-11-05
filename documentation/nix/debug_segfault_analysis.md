# xdp2-compiler Segfault Analysis

## Current Finding

**Segfault Location**: `clang::TagType::getDecl()` from `libclang-cpp.so.20.1`

**Key Observation**: The Nix store paths for libraries are not in `LD_LIBRARY_PATH`, but GDB is finding them. This suggests the binary uses rpath (runtime library search path) rather than relying on `LD_LIBRARY_PATH`.

## Immediate Next Steps

### 1. Get Full Backtrace

In gdb, run:
```
(gdb) bt full
(gdb) thread apply all bt
(gdb) info registers
(gdb) frame 0
(gdb) info frame
```

### 2. Check How Binary is Linked

```bash
# Check rpath and library dependencies
readelf -d ../../tools/compiler/xdp2-compiler | grep -E "(RPATH|NEEDED|RUNPATH)"

# Check what libraries are actually linked
ldd ../../tools/compiler/xdp2-compiler | grep -E "(clang|LLVM)"

# Check DT_RPATH/DT_RUNPATH specifically
objdump -p ../../tools/compiler/xdp2-compiler | grep -E "(RPATH|RUNPATH)"
```

### 3. Check Library Loading at Runtime

```bash
# See what libraries are actually loaded
LD_DEBUG=libs ../../tools/compiler/xdp2-compiler -I../../include -o parsers/parser_big.p.c -i parsers/parser_big.c 2>&1 | grep -E "(clang|LLVM|libclang)" | tail -20
```

### 4. Verify Library Versions

```bash
# Check what version of libclang-cpp is being used
ls -la /nix/store/ar9afnik87wldrqad2fdz1kz1znpsj45-clang-20.1.8-lib/lib/libclang-cpp.so*

# Check if there are multiple versions
find /nix/store -name "libclang-cpp.so*" 2>/dev/null | head -5
```

### 5. Check Library Dependencies

```bash
# Check what libclang-cpp depends on
ldd /nix/store/ar9afnik87wldrqad2fdz1kz1znpsj45-clang-20.1.8-lib/lib/libclang-cpp.so.20.1 | head -20
```

## Understanding the Issue

The segfault in `clang::TagType::getDecl()` suggests:

1. **Null Pointer Dereference**: The `TagType` object might be invalid or pointing to freed memory
2. **ABI Mismatch**: The Clang library version might be incompatible with how xdp2-compiler uses it
3. **Library Loading Issue**: The library might not be fully initialized or loaded correctly

## Complete GDB Session

Run this complete gdb session to capture all information:

```bash
cd src/lib/xdp2
gdb --args ../../tools/compiler/xdp2-compiler -I../../include -o parsers/parser_big.p.c -i parsers/parser_big.c

# In gdb:
(gdb) set pagination off
(gdb) set print pretty on
(gdb) run
(gdb) bt full
(gdb) thread apply all bt full
(gdb) info registers
(gdb) frame 0
(gdb) info frame
(gdb) list
(gdb) up  # Go up the call stack
(gdb) bt  # Show backtrace again
(gdb) frame 1  # Go to calling frame
(gdb) info frame
(gdb) list
(gdb) quit
```

## What to Look For

### In the Backtrace:

1. **Call sequence**: What function in xdp2-compiler called into Clang?
2. **Function arguments**: What was passed to `clang::TagType::getDecl()`?
3. **Frame 0 details**: The exact state when the crash occurred

### In Library Analysis:

1. **Multiple Clang versions**: Are there multiple versions of Clang libraries that might conflict?
2. **Missing dependencies**: Are all required Clang library dependencies present?
3. **RPATH vs RUNPATH**: How is the binary finding its libraries?

## Potential Root Causes

Based on the segfault location:

1. **Invalid AST Node**: The `TagType` object might be from a corrupted or incomplete AST
2. **Memory Corruption**: Something might have corrupted the Clang AST before this call
3. **Thread Safety**: If Clang AST is being accessed from multiple threads unsafely
4. **Version Mismatch**: The Clang library version might have changed in a way that breaks compatibility

## Next Steps After Analysis

1. **Share the full backtrace** - especially frames showing xdp2-compiler code calling into Clang
2. **Check if there's a pattern** - does it always crash at the same point in the parser file?
3. **Try with a simpler parser** - does it crash with simpler parser files too?
4. **Check Clang version compatibility** - was this working with a different Clang version?

