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
# XCFLAGS — clang flags for BPF object files. Stays at -O2 because the
# kernel BPF verifier + JIT have specific instruction-shape expectations
# that aggressive flags like -O3 / -march=native can break.
XCFLAGS= -I$(INCDIR)
XCFLAGS+= -std=gnu11 -g -O2
XLDFLAGS=

CC= gcc
# CFLAGS — gcc flags for the userspace benchmark and the
# parser.{p,mono}.c TUs. Aggressive optimisation here because this is the
# hot parsing loop measured on the perf matrix:
#   -O3            full inliner + vectoriser + loop unroller
#   -march=native  use the host's full ISA (Zen 1 on hp2/hp5: BMI2,
#                  AVX, etc.). Build runs on the target host via the
#                  matrix-runner rsync-then-build flow, so native is
#                  safe — each host gets its own binary.
#   -flto          cross-TU inlining; benchmark.c can inline through
#                  parser.p.c + parser.mono.c. Already paired with
#                  the static-link of libxdp2 (-Wl,-Bstatic -lxdp2)
#                  per the Phase O1.B note below.
#   -fno-plt       drop PLT indirection for external calls (libpcap,
#                  libflowdis). Small but measurable on parsing-
#                  heavy code.
# Investigation 2026-05-19 ("perf-results/2026-05-19-r3.4-complete/
# investigation-mono-vs-rust.md") identified the prior `-O2` vs rust's
# `release + lto=fat + codegen-units=1 + target-cpu=native` asymmetry as
# the dominant cause of the 50 ns c-xdp2-mono vs rust-mono gap on
# tunnel-heavy workloads.
CFLAGS= -I$(INCDIR) -I$(XDP2_SRCDIR)/include
CFLAGS+= -std=gnu11 -g -O3 -march=native -flto -fno-plt
LDFLAGS= -L$(LIBDIR) -Wl,-rpath,$(LIBDIR) -flto

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
# empty and the mono template falls back to indirect calls.
#
# clang (XCC), not gcc — -emit-llvm needs LLVM. -isystem flags
# mirror what xdp2-compiler's clang-tool-config.cpp sets up from
# XDP2_*_INCLUDE_PATH env vars; required in Nix because bare clang
# doesn't pick up the cc-wrapper's defaults, and a local build can
# set the same env vars to get the same paths.
parser.mono.ll: parser.c $(PARSER_HDRS)
	$(XCC) -std=gnu11 -O2 -emit-llvm -S \
		-I$(INCDIR) -I$(XDP2_SRCDIR)/include \
		$(if $(XDP2_C_INCLUDE_PATH),-isystem $(XDP2_C_INCLUDE_PATH)) \
		$(if $(XDP2_GLIBC_INCLUDE_PATH),-isystem $(XDP2_GLIBC_INCLUDE_PATH)) \
		$(if $(XDP2_LINUX_HEADERS_PATH),-isystem $(XDP2_LINUX_HEADERS_PATH)) \
		-o $@ $<

# XDP2 compiler: generate monolithic userspace parser (R3.3).
# -l parser.mono.ll feeds the LLVM IR pass (R2) so per-vertex
# metadata_transfers / next_proto_info populate; the template then
# inlines extract_metadata (R3.3.4b, IR-coverage gated) and
# next_proto (R3.3.5b).
parser.mono.c: parser.c parser.mono.ll $(PARSER_HDRS) parser.o
	$(BINDIR)/xdp2-compiler -I$(INCDIR) -l parser.mono.ll -i $< -o $@

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
# R3.3.7: parser.mono.c is the canonical mono parser (R3 codegen
# template output, gated on R3.3.4b's IR-coverage check). The
# hand-written reference at flow_dissector_mono.h was retired
# once the generator matched it on parity AND perf. parser.c's
# XDP2_PARSER calls are suppressed in the parser.mono.c TU via
# XDP2_PARSERS_SKIP (src/include/xdp2/parser.h) so the two TUs
# don't collide on the base xdp2_parser_X pointers.
benchmark: benchmark.c parser.p.c parser.mono.c common.h pcap_loader.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ benchmark.c parser.p.c parser.mono.c \
		-lpcap -Wl,-Bstatic -lxdp2 -Wl,-Bdynamic \
		-lcli -lflowdis -lsiphash

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
