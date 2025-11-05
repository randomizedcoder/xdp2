# Debugging xdp2-compiler Segmentation Fault

## Quick Start: Enable Core Dumps and Use GDB

### Step 1: Enable Core Dumps

```bash
# In the nix develop shell
ulimit -c unlimited

# Verify core dumps are enabled
ulimit -c
# Should output: unlimited
```

### Step 2: Run with GDB (Recommended Method)

```bash
cd src/lib/xdp2

# Start gdb with xdp2-compiler
gdb --args ../../tools/compiler/xdp2-compiler -I../../include -o parsers/parser_big.p.c -i parsers/parser_big.c

# In gdb, set up for debugging:
(gdb) set pagination off
(gdb) handle SIGSEGV nostop noprint  # Don't stop on segfault initially
(gdb) run

# When it crashes, you'll see the error. Now get detailed info:
(gdb) bt                    # Full backtrace
(gdb) bt 20                 # Extended backtrace (20 frames)
(gdb) info registers        # CPU register values
(gdb) info locals           # Local variables (if available)
(gdb) info args             # Function arguments
(gdb) frame 0               # Go to top frame
(gdb) list                  # Show source code around crash point
(gdb) print $pc             # Print program counter
(gdb) x/10i $pc             # Disassemble 10 instructions around PC
```

### Step 3: Get Detailed Backtrace with Symbol Information

```bash
# Run once to ensure debug symbols are available
gdb --args ../../tools/compiler/xdp2-compiler -I../../include -o parsers/parser_big.p.c -i parsers/parser_big.c

(gdb) set environment LD_LIBRARY_PATH=$LD_LIBRARY_PATH
(gdb) run
(gdb) bt full               # Full backtrace with local variables
(gdb) thread apply all bt   # If multi-threaded, backtrace all threads
```

### Step 4: Examine the Crashing Frame

```bash
# After running and getting backtrace, examine the frame where it crashed:
(gdb) frame 0               # or frame N where N is the frame number
(gdb) info frame            # Detailed frame information
(gdb) info locals           # Local variables in that frame
(gdb) info args             # Function arguments
(gdb) list                  # Show source code
(gdb) print variable_name   # Print specific variables
(gdb) print *pointer        # Dereference pointers (if safe)
```

## Alternative: Use Core Dump Analysis

If you prefer to analyze after the fact:

```bash
# First, ensure core dumps are enabled
ulimit -c unlimited

# Run the command (it will crash and create core dump)
cd src/lib/xdp2
../../tools/compiler/xdp2-compiler -I../../include -o parsers/parser_big.p.c -i parsers/parser_big.c

# Find the core dump (usually in current directory or /tmp)
ls -lah core*  # or ls -lah /tmp/core*

# Analyze the core dump
gdb ../../tools/compiler/xdp2-compiler core
# or if core dump is elsewhere:
gdb ../../tools/compiler/xdp2-compiler /path/to/core

# Then in gdb:
(gdb) bt
(gdb) bt full
(gdb) info registers
```

## Advanced Debugging Techniques

### 1. Trace System Calls

```bash
# Use strace to see system calls before crash
strace -o /tmp/xdp2-strace.log \
  ../../tools/compiler/xdp2-compiler -I../../include -o parsers/parser_big.p.c -i parsers/parser_big.c

# Look at the end of the log for the last system calls
tail -50 /tmp/xdp2-strace.log
```

### 2. Trace Library Calls

```bash
# Use ltrace to see library function calls
ltrace -o /tmp/xdp2-ltrace.log \
  ../../tools/compiler/xdp2-compiler -I../../include -o parsers/parser_big.p.c -i parsers/parser_big.c

# Look at the end of the log
tail -50 /tmp/xdp2-ltrace.log
```

### 3. Check Library Loading

```bash
# See what libraries are being loaded
LD_DEBUG=libs ../../tools/compiler/xdp2-compiler -I../../include -o parsers/parser_big.p.c -i parsers/parser_big.c 2>&1 | tail -100

# Or check linked libraries
ldd ../../tools/compiler/xdp2-compiler | grep -E "(clang|LLVM)"
```

### 4. Run with Valgrind (Memory Debugger)

```bash
# Valgrind can catch memory errors before they cause segfaults
valgrind --tool=memcheck --leak-check=full --show-leak-kinds=all \
  --track-origins=yes --verbose \
  ../../tools/compiler/xdp2-compiler -I../../include -o parsers/parser_big.p.c -i parsers/parser_big.c

# Or simpler:
valgrind --tool=memcheck \
  ../../tools/compiler/xdp2-compiler -I../../include -o parsers/parser_big.p.c -i parsers/parser_big.c
```

### 5. Enable Verbose Output from xdp2-compiler

```bash
# The xdp2-compiler may have verbose/debug flags
../../tools/compiler/xdp2-compiler --help  # Check available options

# Try with verbose flag if available
../../tools/compiler/xdp2-compiler -v -I../../include -o parsers/parser_big.p.c -i parsers/parser_big.c

# Or enable debug output
export XDP2_COMPILER_DEBUG=1
../../tools/compiler/xdp2-compiler -I../../include -o parsers/parser_big.p.c -i parsers/parser_big.c
```

## Recommended Workflow

### Complete Debugging Session

```bash
# 1. Enable core dumps
ulimit -c unlimited

# 2. Start gdb with full debugging
cd src/lib/xdp2
gdb --args ../../tools/compiler/xdp2-compiler -I../../include -o parsers/parser_big.p.c -i parsers/parser_big.c

# 3. In gdb, run these commands:
(gdb) set pagination off
(gdb) set print pretty on
(gdb) set print elements 0
(gdb) set print null-stop on
(gdb) run

# 4. When it crashes, capture all information:
(gdb) bt full > /tmp/xdp2-backtrace.txt
(gdb) info registers >> /tmp/xdp2-backtrace.txt
(gdb) info frame >> /tmp/xdp2-backtrace.txt
(gdb) thread apply all bt full >> /tmp/xdp2-backtrace.txt

# 5. Examine the crashing frame:
(gdb) frame 0
(gdb) info frame
(gdb) list
(gdb) print $pc
(gdb) x/20i $pc

# 6. Look at variables in the crashing frame:
(gdb) info locals
(gdb) info args

# 7. If it's a pointer dereference, check the pointer:
# (Be careful - printing invalid pointers might crash gdb)
(gdb) print pointer_variable
(gdb) print *pointer_variable  # Only if pointer is valid
```

## What to Look For

### In the Backtrace:

1. **Clang library calls**: Look for `clang::` or `clang::TagType::getDecl()` (from previous investigation)
2. **xdp2-compiler code**: Look for `xdp2_graph_consumer::_process_xdp2_parse_node()` or similar
3. **Null pointer dereferences**: Check if `$pc` (program counter) is near 0x0 or a small value
4. **Stack corruption**: If backtrace looks corrupted, it might be stack overflow

### In Registers:

1. **RIP/EIP** (instruction pointer): Shows exact address where crash occurred
2. **RSP/ESP** (stack pointer): Check if stack pointer is reasonable
3. **RAX/EAX** (accumulator): Often contains return values or function arguments
4. **RDI/EDI, RSI/ESI, RDX/EDX, RCX/ECX**: Function arguments on x86-64

### Common Patterns:

1. **Null pointer dereference**:
   - `$pc` is near 0x0 or small address
   - Error mentions "accessing address 0x..."

2. **Stack overflow**:
   - Backtrace shows very deep recursion
   - Stack pointer is at unusual address

3. **Library version mismatch**:
   - Backtrace shows calls into library code that look wrong
   - Symbols don't match expected function signatures

## Quick One-Liner for Full Analysis

```bash
cd src/lib/xdp2 && \
ulimit -c unlimited && \
gdb --batch --ex "set pagination off" \
    --ex "run" \
    --ex "bt full" \
    --ex "info registers" \
    --ex "info frame" \
    --ex "thread apply all bt" \
    --ex "quit" \
    --args ../../tools/compiler/xdp2-compiler \
        -I../../include \
        -o parsers/parser_big.p.c \
        -i parsers/parser_big.c \
    2>&1 | tee /tmp/xdp2-segfault-analysis.txt
```

This will create a complete analysis file at `/tmp/xdp2-segfault-analysis.txt`.

## Next Steps After Getting the Backtrace

1. **Share the backtrace** for analysis
2. **Compare with previous backtrace** from `nix_compile_errors_2025_09_30.md` (if available)
3. **Check if it's in Clang library code** or xdp2-compiler code
4. **Identify the specific function** and line causing the crash
5. **Check if it's a known issue** with the LLVM/Clang version being used

## Troubleshooting GDB Issues

### If GDB Can't Find Symbols:

```bash
# Check if binary has debug symbols
file ../../tools/compiler/xdp2-compiler
readelf -S ../../tools/compiler/xdp2-compiler | grep debug

# If no debug symbols, rebuild with debug info:
# (This would require modifying the build, but might be needed)
```

### If GDB Can't Load Libraries:

```bash
# Set library path in gdb
(gdb) set environment LD_LIBRARY_PATH=$LD_LIBRARY_PATH
(gdb) set solib-search-path /nix/store/...  # Path to Nix libraries
```

### If Core Dumps Aren't Created:

```bash
# Check core dump settings
cat /proc/sys/kernel/core_pattern

# Check core dump size limit
ulimit -c

# Some systems require core dumps to be in specific locations
# Check if core dumps go to systemd journal or apport
```

