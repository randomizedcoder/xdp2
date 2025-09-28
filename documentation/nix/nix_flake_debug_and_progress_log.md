# Nix flake debug and progress log

## Introduction

This document is a working document to capture the process of creating the debugging a flake.nix for the xdp2 project.

The intention of the document is to capture key learnings as we work through the flake.nix development process.  This will allow us to ensure we do not go in loops.

We will work in an interative way, reading logs and capturing insights, and then suggest changes.  We will then retest, reevaulate, and repeat.  Most importantly, we will keep this document up to date.

# Status 1

The `nix develop` command is currently failing during the build of the `xdp2-build` derivation.

### Error Analysis

The build log clearly shows the failure occurs during the `buildPhase`:

```
Running phase: buildPhase
...
sh: line 1: ../../../thirdparty/cppfront/cppfront-compiler: cannot execute: required file not found
make[2]: *** [Makefile:49: gen-patterns-cpp] Error 127
make[1]: *** [Makefile:14: compiler] Error 2
make: *** [Makefile:74: all] Error 2
```

This indicates a build-ordering problem. The main `make` command tries to execute `cppfront-compiler` before it has been built.

### Hypothesis

The `preBuild` phase in `flake.nix`, which was designed to compile `cppfront-compiler` as a prerequisite, is not functioning as expected. It's either not running correctly or failing silently.

### Next Steps

The immediate priority is to add verbose debugging to the `preBuild` phase in `flake.nix` to understand why `cppfront-compiler` is not being successfully compiled. We need to:
1.  Confirm that the `preBuild` phase is being executed.
2.  See the exact commands being run within it.
3.  Capture any errors from the `make` command for `cppfront`.

### Implementation

Verbose debugging has been added to the `preBuild` phase in `flake.nix`. A critical insight was that overriding the `buildPhase` (e.g., `buildPhase = "make";`) prevents the `preBuild` hook from running.

The `buildPhase` override has been removed. The default `buildPhase` is already `make`, and by using the default, we ensure that the `preBuild` hook is executed correctly before the main build starts.

We are now ready to re-test and analyze the new, more verbose build log.

# Status 2

```
[das@l:~/Downloads/xdp2]$ nix develop
warning: Git tree '/home/das/Downloads/xdp2' is dirty
error: builder for '/nix/store/gcahi9l6hnmdaiqnsn8c9pbavzgd4a0c-xdp2-build-dev.drv' failed with exit code 2;
       last 25 log lines:
       > + shift
       > + local 'hooksSlice=failureHooks[@]'
       > + local hook
       > + for hook in "_callImplicitHook 0 $hookName" ${!hooksSlice+"${!hooksSlice}"}
       > + _logHook failureHook '_callImplicitHook 0 failureHook'
       > + [[ -z 2 ]]
       > + local hookKind=failureHook
       > + local 'hookExpr=_callImplicitHook 0 failureHook'
       > + shift 2
       > + declare -F '_callImplicitHook 0 failureHook'
       > + type -p '_callImplicitHook 0 failureHook'
       > + [[ _callImplicitHook 0 failureHook != _callImplicitHook* ]]
       > + _eval '_callImplicitHook 0 failureHook'
       > + declare -F '_callImplicitHook 0 failureHook'
       > + eval '_callImplicitHook 0 failureHook'
       > ++ _callImplicitHook 0 failureHook
       > ++ local def=0
       > ++ local hookName=failureHook
       > ++ declare -F failureHook
       > ++ type -p failureHook
       > ++ '[' -n '' ']'
       > ++ return 0
       > + return 0
       > + '[' -n '' ']'
       > + return 2
       For full logs, run:
         nix log /nix/store/gcahi9l6hnmdaiqnsn8c9pbavzgd4a0c-xdp2-build-dev.drv
error: 1 dependencies of derivation '/nix/store/bxc9mq13d318hp2gpplx2j9rhn7n1wv8-nix-shell-env.drv' failed to build

[das@l:~/Downloads/xdp2]$ nix log /nix/store/gcahi9l6hnmdaiqnsn8c9pbavzgd4a0c-xdp2-build-dev.drv
Running phase: unpackPhase
@nix { "action": "setPhase", "phase": "unpackPhase" }
unpacking source archive /nix/store/fkgb624q3diws53fj5mqbckf0lvs6nhc-dhy0x051jqv8m31gj0r742d4vvbppfmy-source
source root is dhy0x051jqv8m31gj0r742d4vvbppfmy-source
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

Running phase: buildPhase
@nix { "action": "setPhase", "phase": "buildPhase" }
+++++ echo '--- Building cppfront-compiler dependency ---'
--- Building cppfront-compiler dependency ---
+++++ echo 'Contents of ../thirdparty/cppfront before make:'
Contents of ../thirdparty/cppfront before make:
+++++ ls -la ../thirdparty/cppfront
total 5440
drwxr-xr-x 4 nixbld nixbld    4096 Jan  1  1970 .
drwxr-xr-x 5 nixbld nixbld    4096 Jan  1  1970 ..
-rw-r--r-- 1 nixbld nixbld     253 Jan  1  1970 .gitignore
-rw-r--r-- 1 nixbld nixbld    5756 Jan  1  1970 CODE_OF_CONDUCT.md
-rw-r--r-- 1 nixbld nixbld    1027 Jan  1  1970 CONTRIBUTING.md
-rw-r--r-- 1 nixbld nixbld     530 Jan  1  1970 LICENSE
-rw-r--r-- 1 nixbld nixbld     255 Jan  1  1970 Makefile
-rw-r--r-- 1 nixbld nixbld   19485 Jan  1  1970 README.md
-rwxr-xr-x 1 nixbld nixbld 5508904 Jan  1  1970 cppfront-compiler
drwxr-xr-x 2 nixbld nixbld    4096 Jan  1  1970 include
drwxr-xr-x 2 nixbld nixbld    4096 Jan  1  1970 source
+++++ make -C ../thirdparty/cppfront V=1 CXX=/nix/store/8s647qbgn3yy2l52ykznsh0xkvgcrqhx-clang-wrapper-20.1.8/bin/clang++
make: Entering directory '/build/dhy0x051jqv8m31gj0r742d4vvbppfmy-source/thirdparty/cppfront'
g++ -std=c++20 source/cppfront.cpp -o cppfront-compiler
In file included from source/cpp2util.h:1,
                 from source/match.h:4,
                 from source/to_cpp1.h:21,
                 from source/cppfront.cpp:18:
source/../include/cpp2util.h:10051:33: error: 'function' in namespace 'std' does not name a template type
source/../include/cpp2util.h:10017:1: note: 'std::function' is defined in header '<functional>'; this is probably fixable by adding '#include <functional>'
source/../include/cpp2util.h:10055:9: error: 'attrs_type' does not name a type
source/../include/cpp2util.h:10300:14: error: 'unordered_map' is not a member of 'std'
source/../include/cpp2util.h:10017:1: note: 'std::unordered_map' is defined in header '<unordered_map>'; this is probably fixable by adding '#include <unordered_map>'
source/../include/cpp2util.h:10300:38: error: wrong number of template arguments (4, should be 3)
In file included from /nix/store/82kmz7r96navanrc2fgckh2bamiqrgsw-gcc-14.3.0/include/c++/14.3.0/bits/stl_pair.h:60,
                 from /nix/store/82kmz7r96navanrc2fgckh2bamiqrgsw-gcc-14.3.0/include/c++/14.3.0/bits/stl_algobase.h:64,
                 from /nix/store/82kmz7r96navanrc2fgckh2bamiqrgsw-gcc-14.3.0/include/c++/14.3.0/algorithm:60,
                 from source/../include/cpp2util.h:232:
/nix/store/82kmz7r96navanrc2fgckh2bamiqrgsw-gcc-14.3.0/include/c++/14.3.0/type_traits:2715:11: note: provided for 'template<bool _Cond, class _Iftrue, class _Iffalse> using std::conditional_t = typename std::conditional::type'
 2715 |     using conditional_t = typename conditional<_Cond, _Iftrue, _Iffalse>::type;
      |           ^~~~~~~~~~~~~
source/../include/cpp2util.h:10297:40: error: '<expression error>' in namespace 'std' does not name a type
source/../include/cpp2util.h:10305:14: error: 'unordered_map' is not a member of 'std'
source/../include/cpp2util.h:10305:14: note: 'std::unordered_map' is defined in header '<unordered_map>'; this is probably fixable by adding '#include <unordered_map>'
source/../include/cpp2util.h:10305:40: error: wrong number of template arguments (4, should be 3)
/nix/store/82kmz7r96navanrc2fgckh2bamiqrgsw-gcc-14.3.0/include/c++/14.3.0/type_traits:2715:11: note: provided for 'template<bool _Cond, class _Iftrue, class _Iffalse> using std::conditional_t = typename std::conditional::type'
 2715 |     using conditional_t = typename conditional<_Cond, _Iftrue, _Iffalse>::type;
      |           ^~~~~~~~~~~~~
source/../include/cpp2util.h:10302:38: error: '<expression error>' in namespace 'std' does not name a type
source/../include/cpp2util.h:10308:5: error: 'parent_container_type' does not name a type
source/../include/cpp2util.h:10309:5: error: 'size_container_type' does not name a type
source/../include/cpp2util.h: In member function 'bool cpp2::disjoint_sets<Type, ValueIsIndex>::check_integrity_make(type)':
source/../include/cpp2util.h:10320:22: error: 'parent' was not declared in this scope
source/../include/cpp2util.h:10324:17: error: 'parent' was not declared in this scope
source/../include/cpp2util.h:10329:17: error: 'parent' was not declared in this scope
source/../include/cpp2util.h: In member function 'bool cpp2::disjoint_sets<Type, ValueIsIndex>::check_integrity_find(type)':
source/../include/cpp2util.h:10345:22: error: 'parent' was not declared in this scope
source/../include/cpp2util.h:10349:17: error: 'parent' was not declared in this scope
source/../include/cpp2util.h:10353:18: error: 'parent' was not declared in this scope
source/../include/cpp2util.h: In constructor 'cpp2::disjoint_sets<Type, ValueIsIndex>::disjoint_sets(size_t) requires  ValueIsIndex':
source/../include/cpp2util.h:10365:11: error: class 'cpp2::disjoint_sets<Type, ValueIsIndex>' does not have any field named 'parent'
source/../include/cpp2util.h:10365:34: error: class 'cpp2::disjoint_sets<Type, ValueIsIndex>' does not have any field named 'size'
source/../include/cpp2util.h: In member function 'void cpp2::disjoint_sets<Type, ValueIsIndex>::make_set(type)':
source/../include/cpp2util.h:10370:13: error: 'parent' was not declared in this scope
source/../include/cpp2util.h:10371:13: error: 'size' was not declared in this scope
source/../include/cpp2util.h:10371:13: note: suggested alternatives:
In file included from /nix/store/82kmz7r96navanrc2fgckh2bamiqrgsw-gcc-14.3.0/include/c++/14.3.0/array:44,
                 from /nix/store/82kmz7r96navanrc2fgckh2bamiqrgsw-gcc-14.3.0/include/c++/14.3.0/format:43,
                 from source/../include/cpp2util.h:243:
/nix/store/82kmz7r96navanrc2fgckh2bamiqrgsw-gcc-14.3.0/include/c++/14.3.0/bits/range_access.h:272:5: note:   'std::size'
  272 |     size(const _Tp (&)[_Nm]) noexcept
      |     ^~~~
In file included from /nix/store/82kmz7r96navanrc2fgckh2bamiqrgsw-gcc-14.3.0/include/c++/14.3.0/bits/ranges_algobase.h:38,
                 from /nix/store/82kmz7r96navanrc2fgckh2bamiqrgsw-gcc-14.3.0/include/c++/14.3.0/bits/ranges_algo.h:38,
                 from /nix/store/82kmz7r96navanrc2fgckh2bamiqrgsw-gcc-14.3.0/include/c++/14.3.0/algorithm:63:
/nix/store/82kmz7r96navanrc2fgckh2bamiqrgsw-gcc-14.3.0/include/c++/14.3.0/bits/ranges_base.h:491:46: note:   'std::ranges::_Cpo::size'
  491 |     inline constexpr ranges::__access::_Size size{};
      |                                              ^~~~
/nix/store/82kmz7r96navanrc2fgckh2bamiqrgsw-gcc-14.3.0/include/c++/14.3.0/bits/ranges_base.h:307:10: note:   'std::ranges::__access::size'
  307 |     void size() = delete;
      |          ^~~~
source/../include/cpp2util.h: In member function 'cpp2::disjoint_sets<Type, ValueIsIndex>::type cpp2::disjoint_sets<Type, ValueIsIndex>::find_set(type)':
source/../include/cpp2util.h:10379:29: error: 'parent' was not declared in this scope
source/../include/cpp2util.h:10385:17: error: 'parent' was not declared in this scope
source/../include/cpp2util.h: In member function 'void cpp2::disjoint_sets<Type, ValueIsIndex>::union_set(type, type)':
source/../include/cpp2util.h:10397:24: error: 'size' was not declared in this scope
source/../include/cpp2util.h:10397:24: note: suggested alternatives:
/nix/store/82kmz7r96navanrc2fgckh2bamiqrgsw-gcc-14.3.0/include/c++/14.3.0/bits/range_access.h:272:5: note:   'std::size'
  272 |     size(const _Tp (&)[_Nm]) noexcept
      |     ^~~~
/nix/store/82kmz7r96navanrc2fgckh2bamiqrgsw-gcc-14.3.0/include/c++/14.3.0/bits/ranges_base.h:491:46: note:   'std::ranges::_Cpo::size'
  491 |     inline constexpr ranges::__access::_Size size{};
      |                                              ^~~~
/nix/store/82kmz7r96navanrc2fgckh2bamiqrgsw-gcc-14.3.0/include/c++/14.3.0/bits/ranges_base.h:307:10: note:   'std::ranges::__access::size'
  307 |     void size() = delete;
      |          ^~~~
source/../include/cpp2util.h:10401:17: error: 'parent' was not declared in this scope
source/../include/cpp2util.h:10404:17: error: 'parent' was not declared in this scope
make: *** [Makefile:12: compiler] Error 1
make: Leaving directory '/build/dhy0x051jqv8m31gj0r742d4vvbppfmy-source/thirdparty/cppfront'
+ exitHandler
+ exitCode=2
+ set +e
+ '[' -n '' ']'
+ ((  2 != 0  ))
+ runHook failureHook
+ local hookName=failureHook
+ shift
+ local 'hooksSlice=failureHooks[@]'
+ local hook
+ for hook in "_callImplicitHook 0 $hookName" ${!hooksSlice+"${!hooksSlice}"}
+ _logHook failureHook '_callImplicitHook 0 failureHook'
+ [[ -z 2 ]]
+ local hookKind=failureHook
+ local 'hookExpr=_callImplicitHook 0 failureHook'
+ shift 2
+ declare -F '_callImplicitHook 0 failureHook'
+ type -p '_callImplicitHook 0 failureHook'
+ [[ _callImplicitHook 0 failureHook != _callImplicitHook* ]]
+ _eval '_callImplicitHook 0 failureHook'
+ declare -F '_callImplicitHook 0 failureHook'
+ eval '_callImplicitHook 0 failureHook'
++ _callImplicitHook 0 failureHook
++ local def=0
++ local hookName=failureHook
++ declare -F failureHook
++ type -p failureHook
++ '[' -n '' ']'
++ return 0
+ return 0
+ '[' -n '' ']'
+ return 2

[das@l:~/Downloads/xdp2]$
```

# Observations from the logs

The verbose debugging in the `preBuild` phase worked perfectly! We can now see exactly what is happening.

1.  **`preBuild` is running**: The `--- Building cppfront-compiler dependency ---` message confirms the phase is executing.
2.  **Pathing is correct**: The `ls -la ../thirdparty/cppfront` command succeeds, confirming we are in the `src` directory and the relative path is correct.
3.  **`make` is using the wrong compiler**: This is the critical discovery. The log shows:
    ```
    +++++ make -C ../thirdparty/cppfront V=1 CXX=/nix/store/8s647qbgn3yy2l52ykznsh0xkvgcrqhx-clang-wrapper-20.1.8/bin/clang++
    make: Entering directory '...'
    g++ -std=c++20 source/cppfront.cpp -o cppfront-compiler
    ```
    Even though we are explicitly passing `CXX=clang++` to the `make` command, it is ignoring it and using `g++` instead.
4.  **Compilation fails with `g++`**: The `cppfront` source code fails to compile with `g++`, throwing errors like `error: 'function' in namespace 'std' does not name a template type`. This strongly suggests it has a hard dependency on the Clang/LLVM toolchain and its C++ standard library implementation.

# Hypothesis

The `cppfront` `Makefile` is ignoring the `CXX` variable passed on the command line. This is because it includes `../../src/config.mk`, which is generated by the `configure` script.

The `configure` script itself contains the line `echo "HOST_CXX := g++" >> $CONFIG`, which hardcodes `g++` as the host compiler into `config.mk`. This Makefile variable assignment (`:=`) takes precedence over any environment variables or command-line arguments we pass to `make`.

This directly conflicts with the project's requirements:
1.  The `cppfront` compiler (a host tool) must be built with `clang++`.
2.  The `xdp2-compiler` (another host tool) also requires `clang++` for its LLVM integration.
3.  The `configure` script uses the `HOST_CXX` variable specifically for these host tools.

Therefore, the root cause of the failure is that the `configure` script is incorrectly forcing the use of `g++` for a tool that requires `clang++`.

# Proposed Next steps

The solution is to fix the `configure` script so that it generates a `config.mk` file that correctly sets `HOST_CXX` to `clang++`.

1.  **Modify the `configurePhase` in `flake.nix`**: We are already setting `export HOST_CXX=clang++` in this phase. However, the `configure` script itself contains `HOST_CXX := g++` which might be overriding our environment variable.
2.  **Patch the `configure` script**: The most robust solution is to use `substituteInPlace` in the `patchPhase` of our `flake.nix` to change the line `echo "HOST_CXX := g++" >> $CONFIG` to `echo "HOST_CXX := clang++" >> $CONFIG` directly in the `src/configure` script. This guarantees that the generated `config.mk` will have the correct compiler setting.
3.  **Simplify the `preBuild` command**: Once the `config.mk` is correct, we should no longer need to pass `CXX="${llvmP.clang}/bin/clang++"` on the `make` command line in the `preBuild` phase, as it will be correctly picked up from the included `config.mk`.

This approach will fix the root cause of the problem by ensuring the correct compiler is used to build the `cppfront-compiler` dependency.
