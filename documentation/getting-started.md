# Getting started with XDP2

## Introduction

This document is a guide to getting started with XDP2

It is intended for developers who are new to XDP2 and want to learn how to use it to program network devices

This document covers both:
- "native" ( no nix )
- with Nix

## Prerequisites

We are assuming access to a Ubuntu 22.04.3 LTS machine

We also assume you have updated the packages ( because you are security concious )
```
sudo apt update
sudo apt --yes upgrade
```

Walkthrough machine has details:
```
das@ubuntu2404-no-nix:~/xdp2/src$ cat /etc/lsb-release
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=24.04
DISTRIB_CODENAME=noble
DISTRIB_DESCRIPTION="Ubuntu 24.04.3 LTS"
das@ubuntu2404-no-nix:~/xdp2/src$ uname -a
Linux ubuntu2404-no-nix 6.8.0-87-generic #88-Ubuntu SMP PREEMPT_DYNAMIC Sat Oct 11 09:28:41 UTC 2025 x86_64 x86_64 x86_64 GNU/Linux
```

## Native usage

This section covers getting started with xdp2 using native Ubuntu ( without Nix )

### Overview of the steps

1. Package installs
2. git clone
3. ./configure.sh
3.5 make clean
4. make cppfront
5. make
6. make install
7. ports_parser example


### Walkthrough

#### 1. Package installs

**Ubuntu Packages** Ubuntu has x2 forms of packages: un-numbered / numbered

The most simple method is using no version specified.  These seems to default to a version 18 of clang (as of 2025 November).  ./src/configure was designed for this style of package names.
```
sudo apt --yes install build-essential gcc gcc-multilib pkg-config bison flex \
    libboost-all-dev libpcap-dev python3-scapy graphviz libelf-dev libbpf-dev

sudo apt-get --yes install llvm-dev clang libclang-dev clang-tools lld
sudo apt-get --yes install linux-tools-$(uname -r)
```

Ubuntu also has other specific versions available.  We have been testing with version 20, but 17 and 19 is available also (untested currently).

(Unfortunately?) the names of important binaries, like /usr/bin/llvm-config change to /usr/bin/llvm-config-20.

Originally, the ./src/configure script didn't work with the versioned packages.  There is an experimental ./src/configure.sh which adds the extra complexity of supporting the unverioned and versioned forms.

```
sudo apt install --yes build-essential gcc gcc-multilib pkg-config bison flex \
    libboost-all-dev libpcap-dev python3-scapy graphviz libelf-dev libbpf-dev

sudo apt-get --yes install llvm-20-dev clang-20 libclang-20-dev clang-tools-20 lld-20
sudo apt-get --yes install linux-tools-$(uname -r)
```

This walk through is designed to support both styles, so you are welcome to choose which you would prefer.


#### 2. git clone

We will assume starting in your home directory "~".

```
git clone https://github.com/xdp2/xdp2.git
```

#### 3. configure.sh

For this walk through, use the ".sh" version of configure

```
cd ~xdp2/src
./configure.sh
```

**Debugging configure** To allow debugging configure.sh, it supports an arugment --debug-level, which takes integer 0-7 (liek syslog levels).
```
cd ~xdp2/src
./configure.sh --debug-level 7
```

Example outputs

Ubuntu with no versions:
```
das@ubuntu2404-no-nix-no-version:~/xdp2/src$ ./configure.sh


Platform is default
Architecture is x86_64
Architecture includes for x86_64 not found, using generic
Target Architecture is
COMPILER is gcc
LLVM_VER:18.1.3
HOST_LLVM_CONFIG:/usr/bin/llvm-config
XDP2_CLANG_VERSION=18.1.3
XDP2_C_INCLUDE_PATH=/usr/lib/llvm-18/lib/clang/18/include
XDP2_CLANG_RESOURCE_PATH=/usr/lib/llvm-18/lib/clang/18

das@ubuntu2404-no-nix-no-version:~/xdp2/src$

```

Ubuntu with versions, example with 20:
```
das@ubuntu2404-no-nix:~/xdp2/src$ ./configure.sh


Platform is default
Architecture is x86_64
Architecture includes for x86_64 not found, using generic
Target Architecture is
COMPILER is gcc
LLVM_VER:20.1.2
HOST_LLVM_CONFIG:/usr/bin/llvm-config-20
XDP2_CLANG_VERSION=20.1.2
XDP2_C_INCLUDE_PATH=/usr/lib/llvm-20/lib/clang/20/include
XDP2_CLANG_RESOURCE_PATH=/usr/lib/llvm-20/lib/clang/20

das@ubuntu2404-no-nix:~/xdp2/src$
```

configure.sh with debug-level 4
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

das@ubuntu2404-no-nix:~/xdp2/src$
```

If you succeed at using xdp2 on something other than ubuntu, please let us know! ( Please note xdp2 with nix on Fedora _is_ tested )

#### 3.3 make clean

It will never hurt to run `make clean` before all of this ;)
```
cd ~/xdp2/src/
make clean
```

#### 4. make cppfront

xdp2 uses an old version of cppfront, which should be built before anything else, as this is a dependancy.

```
cd ~/xdp2/thirdparty/cppfront
make
```

Example from ubuntu no versions
```
das@ubuntu2404-no-nix-no-version:~/xdp2/src$ cd ~/xdp2/thirdparty/cppfront
das@ubuntu2404-no-nix-no-version:~/xdp2/thirdparty/cppfront$ make
g++ -std=c++20 source/cppfront.cpp -o cppfront-compiler
das@ubuntu2404-no-nix-no-version:~/xdp2/thirdparty/cppfront$ ls -la
total 5208
drwxr-xr-x 4 das das    4096 Nov  6 17:56 .
drwxr-xr-x 5 das das    4096 Oct  2 00:22 ..
-rw-r--r-- 1 das das    5756 Oct  2 00:22 CODE_OF_CONDUCT.md
-rw-r--r-- 1 das das    1027 Oct  2 00:22 CONTRIBUTING.md
-rwxrwxr-x 1 das das 5270624 Nov  6 17:56 cppfront-compiler                  <------------
-rw-r--r-- 1 das das     253 Oct  2 00:22 .gitignore
drwxr-xr-x 2 das das    4096 Nov  5 05:14 include
-rw-r--r-- 1 das das     530 Oct  2 00:22 LICENSE
-rw-r--r-- 1 das das     255 Oct  2 00:22 Makefile
-rw-r--r-- 1 das das   19485 Oct  2 00:22 README.md
drwxr-xr-x 2 das das    4096 Oct  2 00:22 source
das@ubuntu2404-no-nix-no-version:~/xdp2/thirdparty/cppfront$ sha256sum cppfront-compiler
d941dd0c74f37377770f9e3a4aefaa43df7403a9b24215d3256a4e62863ba482  cppfront-compiler
das@ubuntu2404-no-nix-no-version:~/xdp2/thirdparty/cppfront$
```

Ubuntu llvm20
```
das@ubuntu2404-no-nix:~/xdp2/thirdparty/cppfront$ sha256sum cppfront-compiler
26d37f784f43a7766e5f892c49a7337e7e0b7858d4fd3b65dec59e8c23846569  cppfront-compiler
```

#### 5. make
Once cppfront is compiled, it's time to build xdp2

```
cd ~/xdp2/src
make clean
make
```

Example output
```
das@ubuntu2404-no-nix-no-version:~/xdp2/src$ make

tools
include/xdp2gen/llvm/patterns.h2... ok (mixed Cpp1/Cpp2, Cpp2 code passes safety checks)

include/xdp2gen/ast-consumer/patterns.h2... ok (mixed Cpp1/Cpp2, Cpp2 code passes safety checks)

...
    LINK     test_bitmap
    CC       main.o
    CC       cli.o
    CC       test_packets_rx.o
    CC       test_packets_tx.o
    CC       test_packets.o
    LINK     test_uet
    CC       main.o
    CC       cli.o
    CC       test_packets_rx.o
    CC       test_packets_tx.o
    CC       test_packets.o
    LINK     test_falcon
das@ubuntu2404-no-nix-no-version:~/xdp2/src$
das@ubuntu2404-no-nix-no-version:~/xdp2/src$ ls -la ./tools/compiler/xdp2-compiler
-rwxrwxr-x 1 das das 38783152 Nov  6 19:46 ./tools/compiler/xdp2-compiler
das@ubuntu2404-no-nix-no-version:~/xdp2/src$ file ./tools/compiler/xdp2-compiler
./tools/compiler/xdp2-compiler: ELF 64-bit LSB pie executable, x86-64, version 1 (GNU/Linux), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=5003d9629f8319c0c7fcdbfb3abae7c215c540d2, for GNU/Linux 3.2.0, with debug_info, not stripped
das@ubuntu2404-no-nix-no-version:~/xdp2/src$ sha256sum ./tools/compiler/xdp2-compiler
5ee68877f374f9493b4e156cdc554b571dcf25d4096710388eba82dd0a70f5e0  ./tools/compiler/xdp2-compiler
```

```
das@ubuntu2404-no-nix:~/xdp2/src$ make

tools
include/xdp2gen/llvm/patterns.h2... ok (mixed Cpp1/Cpp2, Cpp2 code passes safety checks)

include/xdp2gen/ast-consumer/patterns.h2... ok (mixed Cpp1/Cpp2, Cpp2 code passes safety checks)

...
    LINK     test_bitmap
    CC       main.o
    CC       cli.o
    CC       test_packets_rx.o
    CC       test_packets_tx.o
    CC       test_packets.o
    LINK     test_uet
    CC       main.o
    CC       cli.o
    CC       test_packets_rx.o
    CC       test_packets_tx.o
    CC       test_packets.o
    LINK     test_falcon
das@ubuntu2404-no-nix:~/xdp2/src$
das@ubuntu2404-no-nix:~/xdp2/src$ ls -la ./tools/compiler/xdp2-compiler
-rwxrwxr-x 1 das das 39306864 Nov  6 19:46 ./tools/compiler/xdp2-compiler
das@ubuntu2404-no-nix:~/xdp2/src$ file ./tools/compiler/xdp2-compiler
./tools/compiler/xdp2-compiler: ELF 64-bit LSB pie executable, x86-64, version 1 (GNU/Linux), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=c7409d48c698a5a871307d8369fdf15d881d5d7d, for GNU/Linux 3.2.0, with debug_info, not stripped
das@ubuntu2404-no-nix:~/xdp2/src$ sha256sum ./tools/compiler/xdp2-compiler
b21e4b9f3074b25d8c62c2ed8f12aedecf2bf3d96881cc18c0d75459452cc7e6  ./tools/compiler/xdp2-compiler
das@ubuntu2404-no-nix:~/xdp2/src$
```

#### 6. make install

The default INSTALLDIR is `../install/x86_64` from `src/`, which resolves to `~/xdp2/install/x86_64/` (keeps everything in the xdp2 repository directory).

```
cd ~/xdp2/src
make install
```

```
das@ubuntu2404-no-nix-no-version:~$ cd ~/xdp2/src
das@ubuntu2404-no-nix-no-version:~/xdp2/src$ make install

tools
include/xdp2gen/llvm/patterns.h2... ok (mixed Cpp1/Cpp2, Cpp2 code passes safety checks)

include/xdp2gen/ast-consumer/patterns.h2... ok (mixed Cpp1/Cpp2, Cpp2 code passes safety checks)

...

test
    INSTALL  test_vstructs
    INSTALL  test_switch
    INSTALL
    INSTALL  test_timer
    INSTALL  test_pvbuf
    INSTALL  test_parser
    INSTALL
    INSTALL  test_accel
    INSTALL
    INSTALL  test_bitmap
    INSTALL
    INSTALL

xdp2 installed into directory: /home/das/xdp2/src/../install/x86_64
das@ubuntu2404-no-nix-no-version:~/xdp2/src$
```

#### 7. ports_parser example

With xdp2-compiler built and installed, we can now try using one of the sample parsers.

Let's try the "ports_parser".  Refer to the README.md in that folder for info about this sample.

**Important:** The sample Makefile needs to know where xdp2 is installed. Set `XDP2DIR` to point to your installation directory (without the architecture suffix).

```
cd ~/xdp2/samples/parser/ports_parser/
make XDP2DIR=~/xdp2/install/x86_64
```

If you used a custom installation location, adjust the path accordingly:
```
make XDP2DIR=~/xdp2/install
```

Example output:
```
das@ubuntu2404-no-nix-no-version:~/xdp2/samples/parser/ports_parser$ make XDP2DIR=~/xdp2/install/x86_64
gcc -I/home/das/xdp2/install/x86_64/include -g   -c -o parser.o parser.c
~/xdp2/install/x86_64/bin/xdp2-compiler -I/home/das/xdp2/install/x86_64/include -i parser.c -o parser.p.c
gcc -I/home/das/xdp2/install/x86_64/include -g -L/home/das/xdp2/install/x86_64/lib -o parser parser.p.c -lpcap -lxdp2 -lcli -lsiphash
das@ubuntu2404-no-nix-no-version:~/xdp2/samples/parser/ports_parser$ ls -la parser
-rwxrwxr-x 1 das das 123456 Nov  6 20:00 parser
```


## Nix usage

This section covers how to get started with xdp2 using the Nix development environment.

<Note to auther: Complete "native method" before starting on Nix usage>