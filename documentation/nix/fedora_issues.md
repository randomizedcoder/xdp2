# Fedora-Specific Build Issues

This document outlines a segmentation fault issue encountered when building the XDP2 project within the Nix development shell on Fedora systems.

## 1. Problem Description

When running the `build-all` or `build-xdp2` command inside the Nix development shell on a Fedora host, the build process fails with a segmentation fault. This issue does not occur on other Linux distributions like NixOS or Ubuntu, indicating a platform-specific problem.

### Error Log

The build fails during the `build-xdp2` step, specifically when trying to generate `parsers/parser_big.p.c`.

```bash
make[2]: *** [Makefile:37: parsers/parser_big.p.c] Segmentation fault (core dumped)
make[1]: *** [Makefile:11: xdp2] Error 2
make: *** [Makefile:74: all] Error 2
✗ ERROR: xdp2 project make failed
   Check the error messages above for details
```

This error points to a failure during the execution of the `xdp2-compiler` tool.

## 2. Root Cause Analysis

At first glance, this seems like a Nix isolation failure, where a library from the host Fedora system might be interfering with the Nix environment. However, a deeper investigation reveals that Nix's isolation is working as expected.

### Where the Fault Occurs

The segmentation fault does **not** happen during the compilation of the `xdp2-compiler` itself. The `xdp2-compiler` binary is built successfully. The fault occurs when the `xdp2-compiler` is **executed** to process a C source file and generate a new one.

The relevant rule in `src/lib/xdp2/Makefile.mk` is:
```makefile
# src/lib/xdp2/Makefile.mk, line 37
$(PARSERCSEXT): %.p.c: %.c
	$(XDP2_COMPILER) -I$(SRCDIR)/include -o $@ -i $<
```

This means the `xdp2-compiler` process is crashing while it's running.

### The `xdp2-compiler`

The `xdp2-compiler` is a complex C++ application that uses `libclang` to parse C source code. The crash occurs within `libclang`'s internals, which strongly points to an incomplete or incorrect initialization of the Clang/LLVM environment at runtime.

The GDB backtrace confirms the crash is not related to the embedded Python interpreter, but is happening deep inside `libclang-cpp.so`. This is a classic symptom of a library failing to load one of its own internal components, resulting in a null pointer dereference later on.

### Why Fedora?

Given that the exact same Nix packages are used on NixOS, Ubuntu, and Fedora, and that it only fails on Fedora, we must look at what is different in the host environment that could interfere with the Nix runtime.

Initial theories about SELinux or fundamental kernel/glibc incompatibilities have been proven incorrect. Disabling SELinux with `setenforce 0` did not resolve the issue. The focus must now shift to the most likely remaining culprit: the host system's dynamic linker configuration.

1.  **Dynamic Linker (`dlopen`) Interference (High Probability)**: While an executable's interpreter and `rpath` are correctly set by Nix to point to the Nix store, libraries like `libclang` can use `dlopen()` to load plugins or other components at runtime. The search paths for `dlopen` can be influenced by the host system's dynamic linker configuration (e.g., `/etc/ld.so.conf`). It is highly probable that on Fedora, `libclang` is attempting to `dlopen` a component, but the Fedora host's linker configuration is causing it to find and load an incompatible system library from `/usr/lib64` instead of the correct one from the Nix store. This would lead to an ABI mismatch and a subsequent crash.

2.  **Environment Inconsistencies**: A comparison of `nix print-dev-env` output from the working Ubuntu, NixOS, and failing Fedora systems shows that the environments are virtually identical. All critical variables (`PATH`, `LD_LIBRARY_PATH`, `NIX_LDFLAGS`, etc.) and Nix store paths are consistent. This confirms the issue is not a simple misconfiguration in the `flake.nix` but a subtle runtime interaction with the host.

The previous fix on Ubuntu (`llvm-config-wrapped`) solved a similar problem where Clang couldn't find its own headers. This reinforces the idea that the root cause is not a bug in the application's logic, but an environmental issue where the Clang/LLVM toolchain cannot correctly assemble itself at runtime on a Fedora host.

Even though `ldd` confirms that `xdp2-compiler` links only against libraries in the `/nix/store`, these libraries ultimately make system calls to the host kernel and interact with the host's `glibc` at a low level.

## 3. Investigation Plan

To definitively identify the root cause, a systematic debugging approach is required.

### Step 1: Isolate the `xdp2-compiler`

Run the `xdp2-compiler` manually on the problematic file to confirm the failure outside of the `make` process.

```bash
# Enter the dev shell
nix develop

# Navigate to the compiler's directory
cd src/tools/compiler

# Run the compiler on the file that causes the segfault
./xdp2-compiler -I ../../include -i ../../lib/xdp2/parsers/parser_big.c -o parser_big.p.c
```

This will confirm if the crash is consistently reproducible.

### Step 2: Debug with GDB

Run the `xdp2-compiler` under the GNU Debugger (GDB) to get a backtrace at the moment of the crash. This is the most critical step to find the exact line of code causing the fault.

```bash
# Inside the dev shell
cd src/tools/compiler

# Run under GDB
gdb --args ./xdp2-compiler -I ../../include -i ../../lib/xdp2/parsers/parser_big.c -o parser_big.p.c

# Inside GDB, run the program
(gdb) run

# After the crash, get the backtrace
(gdb) bt
```

The backtrace will show the function call stack, likely pointing to a function within the Python interpreter, `libclang`, or the interaction between them.

### Step 3: Check for Memory Corruption with Valgrind

This step was considered but has been ruled out as a primary cause. The fact that the exact same code runs successfully on NixOS and Ubuntu virtual machines on the same physical hardware makes a memory corruption bug in the application code extremely unlikely. A systematic failure on a single platform points to an environmental or configuration difference, not a random memory error.

The focus should remain on dynamic library resolution differences between Fedora and other distributions.

The tools `strace` and `ltrace` are already included in the `flake.nix` and are the correct tools for investigating this class of problem.

## 4. Proposed Solutions

Based on the investigation, one of the following solutions will likely be necessary.

### Solution A: Improve Error Handling in `xdp2-compiler`

While the root cause is environmental, the application's resilience can be improved. A segmentation fault is an uncontrolled crash. Instead of segfaulting when `libclang` fails to initialize properly, the `xdp2-compiler` could be modified to detect the initialization failure and exit gracefully with a clear error message.

This involves adding defensive checks around the Clang API calls to verify that objects are valid before they are used. This would not fix the underlying Fedora issue, but it would make the application more robust and provide much better diagnostics than a core dump.

This is a good software engineering practice but is secondary to finding the root cause of the environmental failure.

### Solution B: Adjust Nix Environment

If the issue is an ABI incompatibility, we might need to adjust the Nix packages.

-   **Use `LD_DEBUG`**: Running the failing command with `LD_DEBUG=libs ./xdp2-compiler ...` will trace the dynamic linker's activity and show exactly which libraries are being loaded (or failing to load), which can expose if a host library is being incorrectly pulled in.
-   **Use a Different `llvmPackages` Version**: The current `llvmPackages_20` might have a specific bug. Testing with `llvmPackages_19` or a newer one could resolve the issue.
-   **Disable Hardening**: The `hardeningDisable = [ "all" ]` flag in `flake.nix` is already set, which is good. We should confirm it's being applied correctly.

### Solution C: Fedora-Specific Workaround (Last Resort)

If a general fix is not possible, we could apply a workaround only for Fedora. This is not ideal as it complicates the Nix configuration.

```nix
# In flake.nix
let
  isFedora = pkgs.stdenv.isLinux && (builtins.match ".*fedora.*" pkgs.stdenv.hostPlatform.system != null);
in
{
  # Conditionally apply a different package or flag if isFedora
}
```

This should only be considered if the root cause is confirmed to be an unfixable issue in the Fedora environment itself.

## 5. Next Steps (Revised)

1.  **Trace System Calls (Primary Task)**: Use `strace` to monitor for file access calls (`openat`) that might indicate a library is being searched for in the wrong location. This is the most direct way to see if the process is trying to access libraries outside of `/nix/store`.
    ```bash
    strace -o /tmp/strace.log -f -e trace=open,openat ./xdp2-compiler -I ../../include -i ../../lib/xdp2/parsers/parser_big.c -o parser_big.p.c
    ```
   After it crashes, inspect the log: `grep -v "/nix/store" /tmp/strace.log | grep openat`.
2.  **Trace Library Calls**: If `strace` is inconclusive, use `ltrace` to specifically trace calls to `dlopen`. This will show if `libclang` is attempting to dynamically load other libraries by name.
    ```bash
    ltrace -o /tmp/ltrace.log -e "dlopen" ./xdp2-compiler -I ../../include -i ../../lib/xdp2/parsers/parser_big.c -o parser_big.p.c
    ```
3.  **Analyze and Fix**: Based on the findings, adjust the Nix environment to ensure the dynamic linker resolves all paths correctly, potentially by using a wrapper or modifying `LD_LIBRARY_PATH` further.