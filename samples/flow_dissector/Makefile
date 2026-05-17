# Makefile for BPF flow dissector sample
#
# Builds:
#   flow_dissector.bpf.o  -- XDP2 BPF flow dissector program
#   benchmark             -- Userspace benchmark (xdp2 vs kernel flowdis)
#   bpf_flow.kern.o       -- Kernel BPF flow dissector (vendored from linux selftests)
#   benchmark_bpf         -- BPF benchmark (BPF_PROG_TEST_RUN, requires root)
#
# Set XDP2DIR to the install directory for XDP2:
#   make XDP2DIR=~/xdp2/install
#
# The benchmark requires flowdis headers which may not be in the install
# directory. Set XDP2_SRCDIR to the xdp2 source tree root if needed:
#   make XDP2DIR=~/xdp2/install XDP2_SRCDIR=~/xdp2/src
#

XDP2DIR ?= /usr
XDP2_SRCDIR ?= ../../src

INCDIR= $(XDP2DIR)/include
LIBDIR= $(XDP2DIR)/lib
BINDIR= $(XDP2DIR)/bin

XCC= clang
XCFLAGS= -I$(INCDIR)
XCFLAGS+= -std=gnu11 -g -O2
XLDFLAGS=

CC= gcc
CFLAGS= -I$(INCDIR) -I$(XDP2_SRCDIR)/include
CFLAGS+= -std=gnu11 -g -O2
LDFLAGS= -L$(LIBDIR) -Wl,-rpath,$(LIBDIR)

TARGETS= flow_dissector.bpf.o benchmark
BPF_TARGETS= bpf_flow.kern.o fast_bpf/fast_flow.bpf.o benchmark_bpf \
	     fast_bpf/parity_test
TMPFILES= parser.xdp.h parser.p.c parser.p.h parser.mono.c parser.mono.ll \
	  parser.o parser_xdp.o fast_bpf/fast_flow.bpf.o fast_bpf/parity_test

# Header fragments included by parser.c (must trigger rebuild on change)
PARSER_HDRS= flow_dissector_metadata.h flow_dissector_proto_defs.h \
	     flow_dissector_nodes.h flow_dissector_nodes_l2.h \
	     flow_dissector_tables.h flow_dissector_parsers.h \
	     graph_ieee80211.h graph_bluetooth.h graph_infiniband.h \
	     graph_netlink.h graph_misc.h

.PHONY: all bpf
all: $(TARGETS)

# BPF targets require libbpf and clang with BPF target support
bpf: $(BPF_TARGETS)

# XDP2 compiler: generate BPF parser header
parser.xdp.h: parser_xdp.c parser.c $(PARSER_HDRS) parser_xdp.o
	$(BINDIR)/xdp2-compiler -I$(INCDIR) -i $< -o $@

# XDP2 compiler: generate userspace parser source
parser.p.c: parser.c $(PARSER_HDRS) parser.o
	$(BINDIR)/xdp2-compiler -I$(INCDIR) -i $< -o $@

# LLVM IR for parser.c. xdp2-compiler's metadata_transfers / next_proto_info
# analysis (R2) walks this IR to extract per-vertex bit-offsets and
# extract_metadata layouts. Without -l, those per-vertex IR fields stay
# empty and the mono template falls back to indirect calls. Always
# uses -DUSE_GENERATED_MONO so the IR matches the .mono.c view of
# parser.c (mono.h excluded).
parser.mono.ll: parser.c $(PARSER_HDRS)
	$(CC) $(CFLAGS) -DUSE_GENERATED_MONO=1 -emit-llvm -S -o $@ $<

# XDP2 compiler: generate monolithic userspace parser (R3.3).
# -DUSE_GENERATED_MONO=1 tells xdp2-compiler's clang front-end to skip
# the include of flow_dissector_mono.h while building the IR, so the
# generated mono parser does not collide with the hand-written
# reference's same-named XDP2_PARSER_MONO declaration.
# -l parser.mono.ll feeds the LLVM IR pass (R2) so per-vertex
# metadata_transfers / next_proto_info populate; the template then
# inlines extract_metadata (R3.3.4) and next_proto (R3.3.5).
parser.mono.c: parser.c parser.mono.ll $(PARSER_HDRS) parser.o
	$(BINDIR)/xdp2-compiler -I$(INCDIR) -DUSE_GENERATED_MONO=1 \
		-l parser.mono.ll -i $< -o $@

# BPF flow dissector object (xdp2-compiler-generated slow path).
# Needs the same NIX_HARDENING_ENABLE= + -D__x86_64__ workaround as
# the bpf_flow.kern.o / fast_flow.bpf.o recipes below, otherwise Nix's
# cc-wrapper injects -fzero-call-used-regs (unsupported for -target bpf)
# and glibc pulls in 32-bit stubs (gnu/stubs-32.h missing).
flow_dissector.bpf.o: flow_dissector.bpf.c parser.xdp.h common.h
	NIX_HARDENING_ENABLE= $(XCC) -x c -target bpf \
		-D__TARGET_ARCH_$(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/') \
		-D__x86_64__ -Wno-unused-command-line-argument \
		$(XCFLAGS) $(XLDFLAGS) -c -o $@ $<

# Userspace benchmark: links xdp2 parser + kernel flowdis
#
# Phase O1.B optimisation (2026-05-08): link libxdp2 STATICALLY so
# LTO can inline lookup_node() and the per-protocol node next_proto()
# calls across what was the .so boundary. Net win on Zen 1: ~20-30
# ns/pkt vs the previous shared-link form per
# perf-results/asm/2026-05-08/asm-comparison-baseline.md Phase O1.B.
# libcli, libflowdis, libsiphash stay shared (out of hot path).
#
# R3.3.3: USE_GENERATED_MONO=1 swaps the hand-written reference for
# the compiler-emitted parser.mono.c. The conditional include in
# parser.c keys off the same macro, so both TUs (benchmark.c and the
# parser.mono.c include of parser.c) agree on which mono definition
# is live. Retired in R3.3.7.
ifdef USE_GENERATED_MONO
CFLAGS += -DUSE_GENERATED_MONO=1
benchmark: benchmark.c parser.p.c parser.mono.c common.h pcap_loader.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ benchmark.c parser.p.c parser.mono.c \
		-lpcap -Wl,-Bstatic -lxdp2 -Wl,-Bdynamic \
		-lcli -lflowdis -lsiphash
else
benchmark: benchmark.c parser.p.c common.h pcap_loader.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ benchmark.c parser.p.c \
		-lpcap -Wl,-Bstatic -lxdp2 -Wl,-Bdynamic \
		-lcli -lflowdis -lsiphash
endif

# Kernel BPF flow dissector (vendored from linux selftests)
# NIX_HARDENING_ENABLE= disables Nix cc-wrapper hardening flags that are
# incompatible with -target bpf. -D__x86_64__ prevents glibc from pulling
# in 32-bit stubs when cross-compiling to BPF.
bpf_flow.kern.o: kern_bpf/bpf_flow.c
	NIX_HARDENING_ENABLE= $(XCC) -x c -target bpf \
		-D__TARGET_ARCH_$(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/') \
		-D__x86_64__ -Wno-unused-command-line-argument \
		$(XCFLAGS) -c -o $@ $<

# xdp2-flow-ebpf fast-path dissector (see super-flow-dissector-plan.md §5).
# Same clang invocation as bpf_flow.kern.o — stock headers, no CO-RE yet.
fast_bpf/fast_flow.bpf.o: fast_bpf/fast_flow.bpf.c
	NIX_HARDENING_ENABLE= $(XCC) -x c -target bpf \
		-D__TARGET_ARCH_$(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/') \
		-D__x86_64__ -Wno-unused-command-line-argument \
		$(XCFLAGS) -c -o $@ $<

# BPF benchmark binary (requires libbpf, needs root to run)
benchmark_bpf: benchmark_bpf.c pcap_loader.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< -lpcap -lxdp2 -lcli -lsiphash -lbpf -lelf -lz

# D4 coverage-parity test: fast-path hits must match an oracle
# (upstream bpf_flow.kern.o today; slow-path fallback once D6 lands).
# Needs the same BPF runtime deps as benchmark_bpf.
fast_bpf/parity_test: fast_bpf/parity_test.c pcap_loader.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< -lpcap -lxdp2 -lcli -lsiphash -lbpf -lelf -lz

.PHONY: clean
clean:
	@rm -f $(TARGETS) $(BPF_TARGETS) $(TMPFILES)
