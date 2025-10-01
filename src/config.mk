# Generated config based on /home/das/Downloads/xdp2/src/include
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
PKG_CONFIG_PATH=/nix/store/ahxj2q2mrl9z2k77ahqsl9j4zxq1wf84-gnumake-4.4.1/lib/pkgconfig:/nix/store/05h9vfzhqf7l6w1xczixici2ldw9y788-pkg-config-wrapper-0.29.2/lib/pkgconfig:/nix/store/zvldknl5f3k9n63r8xbnzvcysnzj1y4r-bison-3.8.2/lib/pkgconfig:/nix/store/wi25yzr6aq8rgpx8pi4b8z16qifjfd79-flex-2.6.4/lib/pkgconfig:/nix/store/ddx7976jyll30xjbasghv9jailswprcp-bash-interactive-5.3p3/lib/pkgconfig:/nix/store/8ksax0a2mxglr5hlkj2dzl556jx7xqn5-coreutils-9.7/lib/pkgconfig:/nix/store/pmhkmqy0vxk47r6ndh0azybhf6gs6k25-gnused-4.9/lib/pkgconfig:/nix/store/03nvbw411p097h6yxjghc33rbcrjfb9d-gawk-5.3.2/lib/pkgconfig:/nix/store/8av8pfs7bnyc6hqj764ns4z1fnr9bva1-gnutar-1.35/lib/pkgconfig:/nix/store/y9kgzp85ykrhd7l691w4djx121qygy68-xz-5.8.1-bin/lib/pkgconfig:/nix/store/q1zaii9cirbfpmwr7d86hpppql3kjcpf-git-2.51.0/lib/pkgconfig:/nix/store/x0cccj6ww4hkl1hlirx60f32r13dvfmf-boost-1.87.0/lib/pkgconfig:/nix/store/0crnzrvmjwvsn2z13v82w71k9nvwafbd-libpcap-1.10.5/lib/pkgconfig:/nix/store/nsr3sad722q5b6r2xgc0iiwiqca3ili6-libelf-0.8.13/lib/pkgconfig:/nix/store/8jgnmlzb820a1bkff5bkwl1qi681qz7n-libbpf-1.6.2/lib/pkgconfig:/nix/store/j0438064c6zc94gr6xk6mkfvpaxxk8kd-python3-3.13.7-env/lib/pkgconfig:/nix/store/75py9rqxqdb0csqh117an1z4v3zhrkhp-graphviz-12.2.1/lib/pkgconfig:/nix/store/vyadya85hn91wc4rmpymajdzdczcbyza-bpftools-6.16/lib/pkgconfig:/nix/store/95k9rsn1zsw1yvir8mj824ldhf90i4qw-gcc-wrapper-14.3.0/lib/pkgconfig:/nix/store/8s647qbgn3yy2l52ykznsh0xkvgcrqhx-clang-wrapper-20.1.8/lib/pkgconfig:/nix/store/hmmni7ynqhn65mxmssgif5g5baxr03h7-llvm-20.1.8-dev/lib/pkgconfig:/nix/store/6hjcxmzir9ihn3fpnvr8cjcj3shadif3-clang-20.1.8/lib/pkgconfig:/nix/store/04nifjzcpvsbrqd5kshaa0rgm1qv2i2r-glibc-multi-2.40-66-bin/lib/pkgconfig:/nix/store/knqxcy8amfk2jwxc02s4620xsk1h9z8s-gdb-16.3/lib/pkgconfig:/nix/store/qc0345zy040ajz04fjwyds2p0016xyn4-valgrind-3.25.1/lib/pkgconfig:/nix/store/wvm8121hc9ci41b9jqic5jsainb8gwag-strace-6.16/lib/pkgconfig:/nix/store/i2scjmsq4r9wlw1caac7cxambbhvpvfy-ltrace-0.7.91/lib/pkgconfig
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

CC := clang
LD := ld
CXX := clang++
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
	$(QUIET_CXX)$(HOST_CXX) $(XDP2_CXXFLAGS) $(CXXFLAGS) $(EXTRA_CXXFLAGS)		\
						-c -o $@ $<
endif

XDP2_CLANG_VERSION=20.1.8
XDP2_C_INCLUDE_PATH=/nix/store/d3bv4bj7klgfc1w1x01d91a1f4g7ywga-llvm-20.1.8-lib/lib/clang/20/include
XDP2_CLANG_RESOURCE_PATH=/nix/store/d3bv4bj7klgfc1w1x01d91a1f4g7ywga-llvm-20.1.8-lib/lib/clang/20


endif # !TOP_LEVEL_MAKE

INSTALLDIR ?= /home/das/Downloads/xdp2/src/../../install/x86_64
INSTALLTARNAME ?= install.tgz
BUILD_OPT_PARSER ?= y
CONFIG_DEFINES := 
