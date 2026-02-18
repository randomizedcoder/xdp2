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
	QUIET_XDP2     = @echo '    XDP2    '$@;
	QUIET_LINK     = @echo '    LINK     '$@;
	QUIET_INSTALL  = @echo '    INSTALL  '$(TARGETS);
endif
PKG_CONFIG_PATH=/nix/store/ahxj2q2mrl9z2k77ahqsl9j4zxq1wf84-gnumake-4.4.1/lib/pkgconfig:/nix/store/05h9vfzhqf7l6w1xczixici2ldw9y788-pkg-config-wrapper-0.29.2/lib/pkgconfig:/nix/store/zvldknl5f3k9n63r8xbnzvcysnzj1y4r-bison-3.8.2/lib/pkgconfig:/nix/store/wi25yzr6aq8rgpx8pi4b8z16qifjfd79-flex-2.6.4/lib/pkgconfig:/nix/store/ddx7976jyll30xjbasghv9jailswprcp-bash-interactive-5.3p3/lib/pkgconfig:/nix/store/8ksax0a2mxglr5hlkj2dzl556jx7xqn5-coreutils-9.7/lib/pkgconfig:/nix/store/pmhkmqy0vxk47r6ndh0azybhf6gs6k25-gnused-4.9/lib/pkgconfig:/nix/store/03nvbw411p097h6yxjghc33rbcrjfb9d-gawk-5.3.2/lib/pkgconfig:/nix/store/8av8pfs7bnyc6hqj764ns4z1fnr9bva1-gnutar-1.35/lib/pkgconfig:/nix/store/y9kgzp85ykrhd7l691w4djx121qygy68-xz-5.8.1-bin/lib/pkgconfig:/nix/store/q1zaii9cirbfpmwr7d86hpppql3kjcpf-git-2.51.0/lib/pkgconfig:/nix/store/95k9rsn1zsw1yvir8mj824ldhf90i4qw-gcc-wrapper-14.3.0/lib/pkgconfig:/nix/store/vx1ga7l00zqag61nxxavyjigs1x2x523-clang-wrapper-18.1.8/lib/pkgconfig:/nix/store/kq2c1l6z4yhcgqmq8s1l42pn59s7fprk-llvm-18.1.8-dev/lib/pkgconfig:/nix/store/aidm29mma2l47ym7d9iw21qhkwzdmij2-lld-18.1.8/lib/pkgconfig:/nix/store/x0cccj6ww4hkl1hlirx60f32r13dvfmf-boost-1.87.0/lib/pkgconfig:/nix/store/0crnzrvmjwvsn2z13v82w71k9nvwafbd-libpcap-1.10.5/lib/pkgconfig:/nix/store/nsr3sad722q5b6r2xgc0iiwiqca3ili6-libelf-0.8.13/lib/pkgconfig:/nix/store/8jgnmlzb820a1bkff5bkwl1qi681qz7n-libbpf-1.6.2/lib/pkgconfig:/nix/store/y589d4y7c17qz31h8in8ak2lgrk6cq3b-linux-headers-6.16/lib/pkgconfig:/nix/store/j0438064c6zc94gr6xk6mkfvpaxxk8kd-python3-3.13.7-env/lib/pkgconfig:/nix/store/zlbphgbd2fr2kx4g2l80sa87k37ya583-llvm-18.1.8/lib/pkgconfig:/nix/store/8ccr25bcrn19af1kyc9jxlyd13s0fhyr-clang-18.1.8/lib/pkgconfig:/nix/store/8ccr25bcrn19af1kyc9jxlyd13s0fhyr-clang-18.1.8/lib/pkgconfig:/nix/store/knqxcy8amfk2jwxc02s4620xsk1h9z8s-gdb-16.3/lib/pkgconfig:/nix/store/qc0345zy040ajz04fjwyds2p0016xyn4-valgrind-3.25.1/lib/pkgconfig:/nix/store/wvm8121hc9ci41b9jqic5jsainb8gwag-strace-6.16/lib/pkgconfig:/nix/store/i2scjmsq4r9wlw1caac7cxambbhvpvfy-ltrace-0.7.91/lib/pkgconfig:/nix/store/04nifjzcpvsbrqd5kshaa0rgm1qv2i2r-glibc-multi-2.40-66-bin/lib/pkgconfig:/nix/store/vyadya85hn91wc4rmpymajdzdczcbyza-bpftools-6.16/lib/pkgconfig:/nix/store/a8pmxxi4j75ybqymr66x1j0dwl181z0m-bpftrace-0.23.5/lib/pkgconfig:/nix/store/msfrwcn1ayb8rgr4w63s3pgwfpb5mvxi-bcc-0.35.0/lib/pkgconfig:/nix/store/fq20h52bzhj02mcapfgi6xy3shmmnwwb-perf-linux-6.16.8/lib/pkgconfig:/nix/store/9gqwkh5kyrb28kzxwwqbc31m07bb6shj-pahole-1.30/lib/pkgconfig:/nix/store/75py9rqxqdb0csqh117an1z4v3zhrkhp-graphviz-12.2.1/lib/pkgconfig:/nix/store/ayfrkdpk1sygzwwjqh19gcp5sfh557zd-shellcheck-0.10.0-bin/lib/pkgconfig:/nix/store/37559vsv1np7varkxgz0m30via15xwzj-clang-tools-18.1.8/lib/pkgconfig:/nix/store/s2vam2pqx9bla4ah1ycf6f7g9n3i388v-jp2a-1.3.2/lib/pkgconfig:/nix/store/008h0z2m22alg2v8kcdcw4v0f7c39lmm-glibc-locales-2.40-66/lib/pkgconfig
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
HOST_CLANG := clang
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

CC := /nix/store/95k9rsn1zsw1yvir8mj824ldhf90i4qw-gcc-wrapper-14.3.0/bin/gcc
LD := ld
CXX := /nix/store/95k9rsn1zsw1yvir8mj824ldhf90i4qw-gcc-wrapper-14.3.0/bin/g++
HOST_LLVM_CONFIG := /nix/store/ads25hghh8nj390scswchsf8syjdmzkn-llvm-config-wrapped/bin/llvm-config
LLVM_CONFIG := llvm-config
LDFLAGS := 
PYTHON := python3
HAVE_SCAPY:=y
CLANG_LIBS := -lLLVM-18 -lclang-cpp -lclangTooling
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
%.ll: %.c
	$(QUIET_CC)$(HOST_CLANG) $(CFLAGS) $(XDP2_CFLAGS) $(EXTRA_CFLAGS) $(C_MARCH_FLAGS)\
					-S $< -emit-llvm

XDP2_CLANG_VERSION=18.1.8
XDP2_C_INCLUDE_PATH=/nix/store/sffcqagzacjh4vl3x0m85kbcr4qkvj8s-clang-18.1.8-lib/lib/clang/18/include
XDP2_CLANG_RESOURCE_PATH=/nix/store/sffcqagzacjh4vl3x0m85kbcr4qkvj8s-clang-18.1.8-lib/lib/clang/18


endif # !TOP_LEVEL_MAKE

INSTALLDIR ?= /home/das/Downloads/xdp2/src/../install/x86_64
INSTALLTARNAME ?= install.tgz
BUILD_OPT_PARSER ?= y
BUILD_PARSER_JSON ?= 
NO_BUILD_COMPILER ?= 
CONFIG_DEFINES := 
