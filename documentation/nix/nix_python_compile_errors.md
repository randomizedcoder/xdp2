# Python compile errors


Log of "nix develop" build:
```
[das@l:~/Downloads/xdp2]$ nix develop
warning: Git tree '/home/das/Downloads/xdp2' is dirty
error: builder for '/nix/store/rks8rif48pxlkkv2d4nfm6c17h550a62-xdp2-build-dev.drv' failed with exit code 2;
       last 25 log lines:
       >       | ^
       > /nix/store/829wb290i87wngxlh404klwxql5v18p4-python3-3.13.7/include/python3.13/pyport.h:251:54: note: expanded from macro 'Py_DEPRECATED'
       >   251 | #define Py_DEPRECATED(VERSION_UNUSED) __attribute__((__deprecated__))
       >       |                                                      ^
       > In file included from src/main.cpp:56:
       > include/xdp2gen/ast-consumer/graph_consumer.h:1228:9: warning: add explicit braces to avoid dangling else [-Wdangling-else]
       >  1228 |                     } else if (field_name == "overlay_table") {
       >       |                       ^
       > In file included from src/main.cpp:61:
       > In file included from include/xdp2gen/json/metadata.h:32:
       > ../../../thirdparty/json/include/nlohmann/json.hpp:4748:35: warning: identifier '_json' preceded by whitespace in a literal operator declaration is deprecated [-Wdeprecated-literal-operator]
       >  4748 | inline nlohmann::json operator "" _json(const char* s, std::size_t n)
       >       |                       ~~~~~~~~~~~~^~~~~
       >       |                       operator""_json
       > ../../../thirdparty/json/include/nlohmann/json.hpp:4756:49: warning: identifier '_json_pointer' preceded by whitespace in a literal operator declaration is deprecated [-Wdeprecated-literal-operator]
       >  4756 | inline nlohmann::json::json_pointer operator "" _json_pointer(const char* s, std::size_t n)
       >       |                                     ~~~~~~~~~~~~^~~~~~~~~~~~~
       >       |                                     operator""_json_pointer
       > src/main.cpp:358:23: error: no member named 'has_value' in 'std::experimental::optional<std::vector<std::basic_string<char>>>'
       >   358 |     if (include_paths.has_value()) {
       >       |         ~~~~~~~~~~~~~ ^
       > 7 warnings and 1 error generated.
       > make[2]: *** [../../config.mk:76: src/main.o] Error 1
       > make[1]: *** [Makefile:14: compiler] Error 2
       > make: *** [Makefile:74: all] Error 2
       For full logs, run:
         nix log /nix/store/rks8rif48pxlkkv2d4nfm6c17h550a62-xdp2-build-dev.drv
error: 1 dependencies of derivation '/nix/store/byj01w5aw5cl8wfrfghgnfjrglfriajp-nix-shell-env.drv' failed to build

[das@l:~/Downloads/xdp2]$

[das@l:~/Downloads/xdp2]$ nix log /nix/store/rks8rif48pxlkkv2d4nfm6c17h550a62-xdp2-build-dev.drv
Running phase: unpackPhase
@nix { "action": "setPhase", "phase": "unpackPhase" }
unpacking source archive /nix/store/swj0wpskl0nhk199mzkkxhirfmmw93gb-xqm2v0c403lfivzs6bhq8kc77frkhsrl-source
source root is xqm2v0c403lfivzs6bhq8kc77frkhsrl-source
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
--- Building cppfront-compiler dependency ---
make: Entering directory '/build/xqm2v0c403lfivzs6bhq8kc77frkhsrl-source/thirdparty/cppfront'
clang++ -std=c++20 source/cppfront.cpp -o cppfront-compiler
In file included from source/cppfront.cpp:18:
In file included from source/to_cpp1.h:21:
In file included from source/match.h:6:
source/parse.h:6995:18: warning: using the result of an assignment as a condition without parentheses [-Wparentheses]
 6995 |         while (a = match_arrow()) {
      |                ~~^~~~~~~~~~~~~~~
source/parse.h:6995:18: note: place parentheses around the assignment to silence this warning
 6995 |         while (a = match_arrow()) {
      |                  ^
      |                (                )
source/parse.h:6995:18: note: use '==' to turn this assignment into an equality comparison
 6995 |         while (a = match_arrow()) {
      |                  ^
      |                  ==
source/parse.h:7017:18: warning: using the result of an assignment as a condition without parentheses [-Wparentheses]
 7017 |         while (e = match_expression()) {
      |                ~~^~~~~~~~~~~~~~~~~~~~
source/parse.h:7017:18: note: place parentheses around the assignment to silence this warning
 7017 |         while (e = match_expression()) {
      |                  ^
      |                (                     )
source/parse.h:7017:18: note: use '==' to turn this assignment into an equality comparison
 7017 |         while (e = match_expression()) {
      |                  ^
      |                  ==
In file included from source/cppfront.cpp:18:
In file included from source/to_cpp1.h:21:
source/match.h:1709:19: warning: using the result of an assignment as a condition without parentheses [-Wparentheses]
 1709 |     while (ip_opt = loop_cond()) {
      |            ~~~~~~~^~~~~~~~~~~~~
source/match.h:1709:19: note: place parentheses around the assignment to silence this warning
 1709 |     while (ip_opt = loop_cond()) {
      |                   ^
      |            (                   )
source/match.h:1709:19: note: use '==' to turn this assignment into an equality comparison
 1709 |     while (ip_opt = loop_cond()) {
      |                   ^
      |                   ==
3 warnings generated.
make: Leaving directory '/build/xqm2v0c403lfivzs6bhq8kc77frkhsrl-source/thirdparty/cppfront'
build flags: SHELL=/nix/store/q7sqwn7i6w2b67adw0bmix29pxg85x3w-bash-5.3p3/bin/bash

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
In file included from src/main.cpp:50:
include/xdp2gen/python_generators.h:136:5: warning: explicitly defaulted copy constructor is implicitly deleted [-Wdefaulted-function-deleted]
  136 |     tuple(tuple const &) = default;
      |     ^
include/xdp2gen/python_generators.h:144:21: note: copy constructor of 'tuple' is implicitly deleted because field 'tuple_obj' has a deleted copy constructor
  144 |     python_object_t tuple_obj;
      |                     ^
/nix/store/82kmz7r96navanrc2fgckh2bamiqrgsw-gcc-14.3.0/include/c++/14.3.0/bits/unique_ptr.h:517:7: note: 'unique_ptr' has been explicitly marked deleted here
  517 |       unique_ptr(const unique_ptr&) = delete;
      |       ^
include/xdp2gen/python_generators.h:136:28: note: replace 'default' with 'delete'
  136 |     tuple(tuple const &) = default;
      |                            ^~~~~~~
      |                            delete
include/xdp2gen/python_generators.h:164:5: warning: explicitly defaulted copy constructor is implicitly deleted [-Wdefaulted-function-deleted]
  164 |     list(list const &) = default;
      |     ^
include/xdp2gen/python_generators.h:190:21: note: copy constructor of 'list' is implicitly deleted because field 'list_obj' has a deleted copy constructor
  190 |     python_object_t list_obj;
      |                     ^
/nix/store/82kmz7r96navanrc2fgckh2bamiqrgsw-gcc-14.3.0/include/c++/14.3.0/bits/unique_ptr.h:517:7: note: 'unique_ptr' has been explicitly marked deleted here
  517 |       unique_ptr(const unique_ptr&) = delete;
      |       ^
include/xdp2gen/python_generators.h:164:26: note: replace 'default' with 'delete'
  164 |     list(list const &) = default;
      |                          ^~~~~~~
      |                          delete
include/xdp2gen/python_generators.h:533:9: warning: 'Py_SetProgramName' is deprecated [-Wdeprecated-declarations]
  533 |         Py_SetProgramName(program_name.get());
      |         ^
/nix/store/829wb290i87wngxlh404klwxql5v18p4-python3-3.13.7/include/python3.13/pylifecycle.h:37:1: note: 'Py_SetProgramName' has been explicitly marked deprecated here
   37 | Py_DEPRECATED(3.11) PyAPI_FUNC(void) Py_SetProgramName(const wchar_t *);
      | ^
/nix/store/829wb290i87wngxlh404klwxql5v18p4-python3-3.13.7/include/python3.13/pyport.h:251:54: note: expanded from macro 'Py_DEPRECATED'
  251 | #define Py_DEPRECATED(VERSION_UNUSED) __attribute__((__deprecated__))
      |                                                      ^
In file included from src/main.cpp:50:
include/xdp2gen/python_generators.h:578:9: warning: 'Py_SetProgramName' is deprecated [-Wdeprecated-declarations]
  578 |         Py_SetProgramName(program_name.get());
      |         ^
/nix/store/829wb290i87wngxlh404klwxql5v18p4-python3-3.13.7/include/python3.13/pylifecycle.h:37:1: note: 'Py_SetProgramName' has been explicitly marked deprecated here
   37 | Py_DEPRECATED(3.11) PyAPI_FUNC(void) Py_SetProgramName(const wchar_t *);
      | ^
/nix/store/829wb290i87wngxlh404klwxql5v18p4-python3-3.13.7/include/python3.13/pyport.h:251:54: note: expanded from macro 'Py_DEPRECATED'
  251 | #define Py_DEPRECATED(VERSION_UNUSED) __attribute__((__deprecated__))
      |                                                      ^
In file included from src/main.cpp:56:
include/xdp2gen/ast-consumer/graph_consumer.h:1228:9: warning: add explicit braces to avoid dangling else [-Wdangling-else]
 1228 |                     } else if (field_name == "overlay_table") {
      |                       ^
In file included from src/main.cpp:61:
In file included from include/xdp2gen/json/metadata.h:32:
../../../thirdparty/json/include/nlohmann/json.hpp:4748:35: warning: identifier '_json' preceded by whitespace in a literal operator declaration is deprecated [-Wdeprecated-literal-operator]
 4748 | inline nlohmann::json operator "" _json(const char* s, std::size_t n)
      |                       ~~~~~~~~~~~~^~~~~
      |                       operator""_json
../../../thirdparty/json/include/nlohmann/json.hpp:4756:49: warning: identifier '_json_pointer' preceded by whitespace in a literal operator declaration is deprecated [-Wdeprecated-literal-operator]
 4756 | inline nlohmann::json::json_pointer operator "" _json_pointer(const char* s, std::size_t n)
      |                                     ~~~~~~~~~~~~^~~~~~~~~~~~~
      |                                     operator""_json_pointer
src/main.cpp:358:23: error: no member named 'has_value' in 'std::experimental::optional<std::vector<std::basic_string<char>>>'
  358 |     if (include_paths.has_value()) {
      |         ~~~~~~~~~~~~~ ^
7 warnings and 1 error generated.
make[2]: *** [../../config.mk:76: src/main.o] Error 1
make[1]: *** [Makefile:14: compiler] Error 2
make: *** [Makefile:74: all] Error 2

[das@l:~/Downloads/xdp2]$
```



More python errors

```

[das@l:~/Downloads/xdp2]$ nix develop
warning: Git tree '/home/das/Downloads/xdp2' is dirty
error: builder for '/nix/store/lfdipc3b5bjiaazc4xy4kkpriyz3pmvw-xdp2-build-dev.drv' failed with exit code 2;
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
         nix log /nix/store/lfdipc3b5bjiaazc4xy4kkpriyz3pmvw-xdp2-build-dev.drv
error: 1 dependencies of derivation '/nix/store/fch0fcjmirjfpyrzpm98qhskq34qq823-nix-shell-env.drv' failed to build

[das@l:~/Downloads/xdp2]$ nix log /nix/store/lfdipc3b5bjiaazc4xy4kkpriyz3pmvw-xdp2-build-dev.drv
Running phase: unpackPhase
@nix { "action": "setPhase", "phase": "unpackPhase" }
unpacking source archive /nix/store/gz2n3sipbrssdpx38bgnr4ynbsppbhyz-5mrfb6mhivg9i1cdd3jvv120r0hjldag-source
source root is 5mrfb6mhivg9i1cdd3jvv120r0hjldag-source
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
--- Building cppfront-compiler dependency ---
make: Entering directory '/build/5mrfb6mhivg9i1cdd3jvv120r0hjldag-source/thirdparty/cppfront'
clang++ -std=c++20 source/cppfront.cpp -o cppfront-compiler
In file included from source/cppfront.cpp:18:
In file included from source/to_cpp1.h:21:
In file included from source/match.h:6:
source/parse.h:6995:18: warning: using the result of an assignment as a condition without parentheses [-Wparentheses]
 6995 |         while (a = match_arrow()) {
      |                ~~^~~~~~~~~~~~~~~
source/parse.h:6995:18: note: place parentheses around the assignment to silence this warning
 6995 |         while (a = match_arrow()) {
      |                  ^
      |                (                )
source/parse.h:6995:18: note: use '==' to turn this assignment into an equality comparison
 6995 |         while (a = match_arrow()) {
      |                  ^
      |                  ==
source/parse.h:7017:18: warning: using the result of an assignment as a condition without parentheses [-Wparentheses]
 7017 |         while (e = match_expression()) {
      |                ~~^~~~~~~~~~~~~~~~~~~~
source/parse.h:7017:18: note: place parentheses around the assignment to silence this warning
 7017 |         while (e = match_expression()) {
      |                  ^
      |                (                     )
source/parse.h:7017:18: note: use '==' to turn this assignment into an equality comparison
 7017 |         while (e = match_expression()) {
      |                  ^
      |                  ==
In file included from source/cppfront.cpp:18:
In file included from source/to_cpp1.h:21:
source/match.h:1709:19: warning: using the result of an assignment as a condition without parentheses [-Wparentheses]
 1709 |     while (ip_opt = loop_cond()) {
      |            ~~~~~~~^~~~~~~~~~~~~
source/match.h:1709:19: note: place parentheses around the assignment to silence this warning
 1709 |     while (ip_opt = loop_cond()) {
      |                   ^
      |            (                   )
source/match.h:1709:19: note: use '==' to turn this assignment into an equality comparison
 1709 |     while (ip_opt = loop_cond()) {
      |                   ^
      |                   ==
3 warnings generated.
make: Leaving directory '/build/5mrfb6mhivg9i1cdd3jvv120r0hjldag-source/thirdparty/cppfront'
build flags: SHELL=/nix/store/q7sqwn7i6w2b67adw0bmix29pxg85x3w-bash-5.3p3/bin/bash

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
In file included from src/main.cpp:50:
include/xdp2gen/python_generators.h:136:5: warning: explicitly defaulted copy constructor is implicitly deleted [-Wdefaulted-function-deleted]
  136 |     tuple(tuple const &) = default;
      |     ^
include/xdp2gen/python_generators.h:144:21: note: copy constructor of 'tuple' is implicitly deleted because field 'tuple_obj' has a deleted copy constructor
  144 |     python_object_t tuple_obj;
      |                     ^
/nix/store/82kmz7r96navanrc2fgckh2bamiqrgsw-gcc-14.3.0/include/c++/14.3.0/bits/unique_ptr.h:517:7: note: 'unique_ptr' has been explicitly marked deleted here
  517 |       unique_ptr(const unique_ptr&) = delete;
      |       ^
include/xdp2gen/python_generators.h:136:28: note: replace 'default' with 'delete'
  136 |     tuple(tuple const &) = default;
      |                            ^~~~~~~
      |                            delete
include/xdp2gen/python_generators.h:164:5: warning: explicitly defaulted copy constructor is implicitly deleted [-Wdefaulted-function-deleted]
  164 |     list(list const &) = default;
      |     ^
include/xdp2gen/python_generators.h:190:21: note: copy constructor of 'list' is implicitly deleted because field 'list_obj' has a deleted copy constructor
  190 |     python_object_t list_obj;
      |                     ^
/nix/store/82kmz7r96navanrc2fgckh2bamiqrgsw-gcc-14.3.0/include/c++/14.3.0/bits/unique_ptr.h:517:7: note: 'unique_ptr' has been explicitly marked deleted here
  517 |       unique_ptr(const unique_ptr&) = delete;
      |       ^
include/xdp2gen/python_generators.h:164:26: note: replace 'default' with 'delete'
  164 |     list(list const &) = default;
      |                          ^~~~~~~
      |                          delete
include/xdp2gen/python_generators.h:533:9: warning: 'Py_SetProgramName' is deprecated [-Wdeprecated-declarations]
  533 |         Py_SetProgramName(program_name.get());
      |         ^
/nix/store/829wb290i87wngxlh404klwxql5v18p4-python3-3.13.7/include/python3.13/pylifecycle.h:37:1: note: 'Py_SetProgramName' has been explicitly marked deprecated here
   37 | Py_DEPRECATED(3.11) PyAPI_FUNC(void) Py_SetProgramName(const wchar_t *);
      | ^
/nix/store/829wb290i87wngxlh404klwxql5v18p4-python3-3.13.7/include/python3.13/pyport.h:251:54: note: expanded from macro 'Py_DEPRECATED'
  251 | #define Py_DEPRECATED(VERSION_UNUSED) __attribute__((__deprecated__))
      |                                                      ^
In file included from src/main.cpp:50:
include/xdp2gen/python_generators.h:578:9: warning: 'Py_SetProgramName' is deprecated [-Wdeprecated-declarations]
  578 |         Py_SetProgramName(program_name.get());
      |         ^
/nix/store/829wb290i87wngxlh404klwxql5v18p4-python3-3.13.7/include/python3.13/pylifecycle.h:37:1: note: 'Py_SetProgramName' has been explicitly marked deprecated here
   37 | Py_DEPRECATED(3.11) PyAPI_FUNC(void) Py_SetProgramName(const wchar_t *);
      | ^
/nix/store/829wb290i87wngxlh404klwxql5v18p4-python3-3.13.7/include/python3.13/pyport.h:251:54: note: expanded from macro 'Py_DEPRECATED'
  251 | #define Py_DEPRECATED(VERSION_UNUSED) __attribute__((__deprecated__))
      |                                                      ^
In file included from src/main.cpp:56:
include/xdp2gen/ast-consumer/graph_consumer.h:1228:9: warning: add explicit braces to avoid dangling else [-Wdangling-else]
 1228 |                     } else if (field_name == "overlay_table") {
      |                       ^
In file included from src/main.cpp:61:
In file included from include/xdp2gen/json/metadata.h:32:
../../../thirdparty/json/include/nlohmann/json.hpp:4748:35: warning: identifier '_json' preceded by whitespace in a literal operator declaration is deprecated [-Wdeprecated-literal-operator]
 4748 | inline nlohmann::json operator "" _json(const char* s, std::size_t n)
      |                       ~~~~~~~~~~~~^~~~~
      |                       operator""_json
../../../thirdparty/json/include/nlohmann/json.hpp:4756:49: warning: identifier '_json_pointer' preceded by whitespace in a literal operator declaration is deprecated [-Wdeprecated-literal-operator]
 4756 | inline nlohmann::json::json_pointer operator "" _json_pointer(const char* s, std::size_t n)
      |                                     ~~~~~~~~~~~~^~~~~~~~~~~~~
      |                                     operator""_json_pointer
7 warnings generated.
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

+4. Root Cause: The error occurs when make tries to generate the parser.p.c file. This step is executed by the xdp2-compiler that we just successfully built. This means the xdp2-compiler is compiling correctly but crashing at runtime when it tries to process a C file (parser.c) to generate a new one (parser.p.c). + +## Hypothesis + +The segmentation fault is likely caused by a runtime issue within the xdp2-compiler when it interacts with the Python interpreter for code generation. + +1. Python Interaction: The xdp2-compiler uses an embedded Python interpreter to run code generation scripts. +2. Environment Mismatch: There might be a mismatch between the Python environment the xdp2-compiler was linked against and the environment it's running in. Specifically, the pythonWithScapy package we created in flake.nix might be causing an issue. While it provides the necessary scapy module for the development shell, it might be creating an environment that conflicts with the xdp2-compiler's runtime expectations. +3. Simplification: The xdp2-build derivation itself does not need scapy. It only needs the standard Python 3 development headers and libraries. The scapy dependency is only for the interactive nix develop shell. + +The most likely solution is to simplify the Python dependency for the xdp2-build derivation. We should use the standard pkgs.python3 for the build derivation's buildInputs and keep pythonWithScapy only for the devShells.default. This separation ensures the compiler is built against a clean, standard Python, which should prevent the runtime segfault.


# Even more python errors

```
[das@l:~/Downloads/xdp2]$ nix develop
warning: Git tree '/home/das/Downloads/xdp2' is dirty
error: builder for '/nix/store/pdky2qa0hk3qv4fcgwmhxncnfx76ihx3-xdp2-build-dev.drv' failed with exit code 2;
       last 25 log lines:
       > source/match.h:1709:19: warning: using the result of an assignment as a condition without parentheses [-Wparentheses]
       >  1709 |     while (ip_opt = loop_cond()) {
       >       |            ~~~~~~~^~~~~~~~~~~~~
       > source/match.h:1709:19: note: place parentheses around the assignment to silence this warning
       >  1709 |     while (ip_opt = loop_cond()) {
       >       |                   ^
       >       |            (                   )
       > source/match.h:1709:19: note: use '==' to turn this assignment into an equality comparison
       >  1709 |     while (ip_opt = loop_cond()) {
       >       |                   ^
       >       |                   ==
       > 3 warnings generated.
       > make: Leaving directory '/build/0w6a59g8gs5lsl9yjn895wlqx421rg2j-source/thirdparty/cppfront'
       > build flags: SHELL=/nix/store/q7sqwn7i6w2b67adw0bmix29pxg85x3w-bash-5.3p3/bin/bash
       >
       > tools
       >     CC       get_uet_udp_port
       > Traceback (most recent call last):
       >   File "/build/0w6a59g8gs5lsl9yjn895wlqx421rg2j-source/src/tools/packets/uet/make_uet_pds.py", line 1, in <module>
       >     from scapy.all import *
       > ModuleNotFoundError: No module named 'scapy'
       > make[3]: *** [Makefile:10: uet_pds.pcap] Error 1
       > make[2]: *** [Makefile:10: uet] Error 2
       > make[1]: *** [Makefile:14: packets] Error 2
       > make: *** [Makefile:74: all] Error 2
       For full logs, run:
         nix log /nix/store/pdky2qa0hk3qv4fcgwmhxncnfx76ihx3-xdp2-build-dev.drv
error: 1 dependencies of derivation '/nix/store/ilrr0rddwz5qzkbxak9irxppq8w0yil4-nix-shell-env.drv' failed to build

[das@l:~/Downloads/xdp2]$ nix log /nix/store/pdky2qa0hk3qv4fcgwmhxncnfx76ihx3-xdp2-build-dev.drv
Running phase: unpackPhase
@nix { "action": "setPhase", "phase": "unpackPhase" }
unpacking source archive /nix/store/hjh9gdgmiw3vszs158askpanw28ns3g9-0w6a59g8gs5lsl9yjn895wlqx421rg2j-source
source root is 0w6a59g8gs5lsl9yjn895wlqx421rg2j-source
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
--- Building cppfront-compiler dependency ---
make: Entering directory '/build/0w6a59g8gs5lsl9yjn895wlqx421rg2j-source/thirdparty/cppfront'
clang++ -std=c++20 source/cppfront.cpp -o cppfront-compiler
In file included from source/cppfront.cpp:18:
In file included from source/to_cpp1.h:21:
In file included from source/match.h:6:
source/parse.h:6995:18: warning: using the result of an assignment as a condition without parentheses [-Wparentheses]
 6995 |         while (a = match_arrow()) {
      |                ~~^~~~~~~~~~~~~~~
source/parse.h:6995:18: note: place parentheses around the assignment to silence this warning
 6995 |         while (a = match_arrow()) {
      |                  ^
      |                (                )
source/parse.h:6995:18: note: use '==' to turn this assignment into an equality comparison
 6995 |         while (a = match_arrow()) {
      |                  ^
      |                  ==
source/parse.h:7017:18: warning: using the result of an assignment as a condition without parentheses [-Wparentheses]
 7017 |         while (e = match_expression()) {
      |                ~~^~~~~~~~~~~~~~~~~~~~
source/parse.h:7017:18: note: place parentheses around the assignment to silence this warning
 7017 |         while (e = match_expression()) {
      |                  ^
      |                (                     )
source/parse.h:7017:18: note: use '==' to turn this assignment into an equality comparison
 7017 |         while (e = match_expression()) {
      |                  ^
      |                  ==
In file included from source/cppfront.cpp:18:
In file included from source/to_cpp1.h:21:
source/match.h:1709:19: warning: using the result of an assignment as a condition without parentheses [-Wparentheses]
 1709 |     while (ip_opt = loop_cond()) {
      |            ~~~~~~~^~~~~~~~~~~~~
source/match.h:1709:19: note: place parentheses around the assignment to silence this warning
 1709 |     while (ip_opt = loop_cond()) {
      |                   ^
      |            (                   )
source/match.h:1709:19: note: use '==' to turn this assignment into an equality comparison
 1709 |     while (ip_opt = loop_cond()) {
      |                   ^
      |                   ==
3 warnings generated.
make: Leaving directory '/build/0w6a59g8gs5lsl9yjn895wlqx421rg2j-source/thirdparty/cppfront'
build flags: SHELL=/nix/store/q7sqwn7i6w2b67adw0bmix29pxg85x3w-bash-5.3p3/bin/bash

tools
    CC       get_uet_udp_port
Traceback (most recent call last):
  File "/build/0w6a59g8gs5lsl9yjn895wlqx421rg2j-source/src/tools/packets/uet/make_uet_pds.py", line 1, in <module>
    from scapy.all import *
ModuleNotFoundError: No module named 'scapy'
make[3]: *** [Makefile:10: uet_pds.pcap] Error 1
make[2]: *** [Makefile:10: uet] Error 2
make[1]: *** [Makefile:14: packets] Error 2
make: *** [Makefile:74: all] Error 2

[das@l:~/Downloads/xdp2]$
```

## Analysis of "# Even more python errors" Logs

### Key Observations

1. **Build Progress**: The build has progressed significantly from the previous errors:
   - The `cppfront-compiler` builds successfully (with warnings but no errors)
   - The `xdp2-compiler` (main.cpp) now compiles successfully - the previous `std::experimental::optional` error has been resolved
   - Most of the core libraries and test programs build successfully

2. **New Error Location**: The failure now occurs much later in the build process, specifically in the packet generation tools:
   ```
   File "/build/.../src/tools/packets/uet/make_uet_pds.py", line 1, in <module>
       from scapy.all import *
   ModuleNotFoundError: No module named 'scapy'
   ```

3. **Build Context**: The error occurs when building the `uet` packet generation tool, which requires Python with the `scapy` library to generate test packet capture files.

4. **Environment Issue**: The build derivation is using a clean `python3` (as intended per the previous analysis), but the packet generation scripts require `scapy`, which is not available in the build environment.

### Root Cause Analysis

The issue stems from a **separation of concerns** problem in the Nix flake configuration:

1. **Build vs. Development Environment**: The `xdp2-build` derivation correctly uses a clean `python3` for building the core compiler and libraries, but the build process also includes packet generation tools that require `scapy`.

2. **Missing Dependency**: The packet generation tools (`make_uet_pds.py`, `make_falcon_pds.py`, `make_sue_pds.py`) are part of the build process but require `scapy` to generate test data files.

3. **Build Process Integration**: These Python scripts are called during the `make` process to generate `.pcap` files that are used by the test suite, making them part of the build dependencies rather than just development tools.

### Hypothesis

The build is failing because the packet generation tools require `scapy` during the build process, but the `xdp2-build` derivation only includes a clean `python3` without additional packages.

**Solution**: The `xdp2-build` derivation needs to include `scapy` in its Python environment since the packet generation tools are part of the build process, not just development tools. This means we need to modify the `buildInputs` in the `xdp2-build` derivation to use `pythonWithScapy` instead of plain `python3`.

The separation between build and development environments should be:
- **Build environment**: `python3` with `scapy` (for packet generation during build)
- **Development environment**: `python3` with `scapy` (for interactive development)

Both environments need the same Python packages since the build process includes tools that require `scapy`.

## Additional python challenges

```
[das@l:~/Downloads/xdp2]$ nix develop
warning: Git tree '/home/das/Downloads/xdp2' is dirty
error: builder for '/nix/store/6gb10m5y0h1iqghzy0h411npz28xlj26-xdp2-build-dev.drv' failed with exit code 2;
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
         nix log /nix/store/6gb10m5y0h1iqghzy0h411npz28xlj26-xdp2-build-dev.drv
error: 1 dependencies of derivation '/nix/store/ab5j8mpjfw8wnxclbp7gw0z4hijp7lj3-nix-shell-env.drv' failed to build

[das@l:~/Downloads/xdp2]$ nix log /nix/store/6gb10m5y0h1iqghzy0h411npz28xlj26-xdp2-build-dev.drv
Running phase: unpackPhase
@nix { "action": "setPhase", "phase": "unpackPhase" }
unpacking source archive /nix/store/4dlnm209xvj87rrglmxxybw73wxy04hd-9bs145r47ai5ksmmgi4bhl3p5435nvgq-source
source root is 9bs145r47ai5ksmmgi4bhl3p5435nvgq-source
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
--- Building cppfront-compiler dependency ---
make: Entering directory '/build/9bs145r47ai5ksmmgi4bhl3p5435nvgq-source/thirdparty/cppfront'
clang++ -std=c++20 source/cppfront.cpp -o cppfront-compiler
In file included from source/cppfront.cpp:18:
In file included from source/to_cpp1.h:21:
In file included from source/match.h:6:
source/parse.h:6995:18: warning: using the result of an assignment as a condition without parentheses [-Wparentheses]
 6995 |         while (a = match_arrow()) {
      |                ~~^~~~~~~~~~~~~~~
source/parse.h:6995:18: note: place parentheses around the assignment to silence this warning
 6995 |         while (a = match_arrow()) {
      |                  ^
      |                (                )
source/parse.h:6995:18: note: use '==' to turn this assignment into an equality comparison
 6995 |         while (a = match_arrow()) {
      |                  ^
      |                  ==
source/parse.h:7017:18: warning: using the result of an assignment as a condition without parentheses [-Wparentheses]
 7017 |         while (e = match_expression()) {
      |                ~~^~~~~~~~~~~~~~~~~~~~
source/parse.h:7017:18: note: place parentheses around the assignment to silence this warning
 7017 |         while (e = match_expression()) {
      |                  ^
      |                (                     )
source/parse.h:7017:18: note: use '==' to turn this assignment into an equality comparison
 7017 |         while (e = match_expression()) {
      |                  ^
      |                  ==
In file included from source/cppfront.cpp:18:
In file included from source/to_cpp1.h:21:
source/match.h:1709:19: warning: using the result of an assignment as a condition without parentheses [-Wparentheses]
 1709 |     while (ip_opt = loop_cond()) {
      |            ~~~~~~~^~~~~~~~~~~~~
source/match.h:1709:19: note: place parentheses around the assignment to silence this warning
 1709 |     while (ip_opt = loop_cond()) {
      |                   ^
      |            (                   )
source/match.h:1709:19: note: use '==' to turn this assignment into an equality comparison
 1709 |     while (ip_opt = loop_cond()) {
      |                   ^
      |                   ==
3 warnings generated.
make: Leaving directory '/build/9bs145r47ai5ksmmgi4bhl3p5435nvgq-source/thirdparty/cppfront'
build flags: SHELL=/nix/store/q7sqwn7i6w2b67adw0bmix29pxg85x3w-bash-5.3p3/bin/bash

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
In file included from src/main.cpp:50:
include/xdp2gen/python_generators.h:136:5: warning: explicitly defaulted copy constructor is implicitly deleted [-Wdefaulted-function-deleted]
  136 |     tuple(tuple const &) = default;
      |     ^
include/xdp2gen/python_generators.h:144:21: note: copy constructor of 'tuple' is implicitly deleted because field 'tuple_obj' has a deleted copy constructor
  144 |     python_object_t tuple_obj;
      |                     ^
/nix/store/82kmz7r96navanrc2fgckh2bamiqrgsw-gcc-14.3.0/include/c++/14.3.0/bits/unique_ptr.h:517:7: note: 'unique_ptr' has been explicitly marked deleted here
  517 |       unique_ptr(const unique_ptr&) = delete;
      |       ^
include/xdp2gen/python_generators.h:136:28: note: replace 'default' with 'delete'
  136 |     tuple(tuple const &) = default;
      |                            ^~~~~~~
      |                            delete
include/xdp2gen/python_generators.h:164:5: warning: explicitly defaulted copy constructor is implicitly deleted [-Wdefaulted-function-deleted]
  164 |     list(list const &) = default;
      |     ^
include/xdp2gen/python_generators.h:190:21: note: copy constructor of 'list' is implicitly deleted because field 'list_obj' has a deleted copy constructor
  190 |     python_object_t list_obj;
      |                     ^
/nix/store/82kmz7r96navanrc2fgckh2bamiqrgsw-gcc-14.3.0/include/c++/14.3.0/bits/unique_ptr.h:517:7: note: 'unique_ptr' has been explicitly marked deleted here
  517 |       unique_ptr(const unique_ptr&) = delete;
      |       ^
include/xdp2gen/python_generators.h:164:26: note: replace 'default' with 'delete'
  164 |     list(list const &) = default;
      |                          ^~~~~~~
      |                          delete
include/xdp2gen/python_generators.h:533:9: warning: 'Py_SetProgramName' is deprecated [-Wdeprecated-declarations]
  533 |         Py_SetProgramName(program_name.get());
      |         ^
/nix/store/829wb290i87wngxlh404klwxql5v18p4-python3-3.13.7/include/python3.13/pylifecycle.h:37:1: note: 'Py_SetProgramName' has been explicitly marked deprecated here
   37 | Py_DEPRECATED(3.11) PyAPI_FUNC(void) Py_SetProgramName(const wchar_t *);
      | ^
/nix/store/829wb290i87wngxlh404klwxql5v18p4-python3-3.13.7/include/python3.13/pyport.h:251:54: note: expanded from macro 'Py_DEPRECATED'
  251 | #define Py_DEPRECATED(VERSION_UNUSED) __attribute__((__deprecated__))
      |                                                      ^
In file included from src/main.cpp:50:
include/xdp2gen/python_generators.h:578:9: warning: 'Py_SetProgramName' is deprecated [-Wdeprecated-declarations]
  578 |         Py_SetProgramName(program_name.get());
      |         ^
/nix/store/829wb290i87wngxlh404klwxql5v18p4-python3-3.13.7/include/python3.13/pylifecycle.h:37:1: note: 'Py_SetProgramName' has been explicitly marked deprecated here
   37 | Py_DEPRECATED(3.11) PyAPI_FUNC(void) Py_SetProgramName(const wchar_t *);
      | ^
/nix/store/829wb290i87wngxlh404klwxql5v18p4-python3-3.13.7/include/python3.13/pyport.h:251:54: note: expanded from macro 'Py_DEPRECATED'
  251 | #define Py_DEPRECATED(VERSION_UNUSED) __attribute__((__deprecated__))
      |                                                      ^
In file included from src/main.cpp:56:
include/xdp2gen/ast-consumer/graph_consumer.h:1228:9: warning: add explicit braces to avoid dangling else [-Wdangling-else]
 1228 |                     } else if (field_name == "overlay_table") {
      |                       ^
In file included from src/main.cpp:61:
In file included from include/xdp2gen/json/metadata.h:32:
../../../thirdparty/json/include/nlohmann/json.hpp:4748:35: warning: identifier '_json' preceded by whitespace in a literal operator declaration is deprecated [-Wdeprecated-literal-operator]
 4748 | inline nlohmann::json operator "" _json(const char* s, std::size_t n)
      |                       ~~~~~~~~~~~~^~~~~
      |                       operator""_json
../../../thirdparty/json/include/nlohmann/json.hpp:4756:49: warning: identifier '_json_pointer' preceded by whitespace in a literal operator declaration is deprecated [-Wdeprecated-literal-operator]
 4756 | inline nlohmann::json::json_pointer operator "" _json_pointer(const char* s, std::size_t n)
      |                                     ~~~~~~~~~~~~^~~~~~~~~~~~~
      |                                     operator""_json_pointer
7 warnings generated.
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