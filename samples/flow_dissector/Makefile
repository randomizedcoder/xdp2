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
BPF_TARGETS= bpf_flow.kern.o benchmark_bpf
TMPFILES= parser.xdp.h parser.p.c parser.p.h parser.o parser_xdp.o

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

# BPF flow dissector object
flow_dissector.bpf.o: flow_dissector.bpf.c parser.xdp.h common.h
	$(XCC) -x c -target bpf -I$(INCDIR) $(XCFLAGS) $(XLDFLAGS) -c -o $@ $<

# Userspace benchmark: links xdp2 parser + kernel flowdis
benchmark: benchmark.c parser.p.c common.h pcap_loader.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ benchmark.c parser.p.c \
		-lpcap -lxdp2 -lcli -lflowdis -lsiphash

# Kernel BPF flow dissector (vendored from linux selftests)
# NIX_HARDENING_ENABLE= disables Nix cc-wrapper hardening flags that are
# incompatible with -target bpf. -D__x86_64__ prevents glibc from pulling
# in 32-bit stubs when cross-compiling to BPF.
bpf_flow.kern.o: kern_bpf/bpf_flow.c
	NIX_HARDENING_ENABLE= $(XCC) -x c -target bpf \
		-D__TARGET_ARCH_$(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/') \
		-D__x86_64__ -Wno-unused-command-line-argument \
		$(XCFLAGS) -c -o $@ $<

# BPF benchmark binary (requires libbpf, needs root to run)
benchmark_bpf: benchmark_bpf.c pcap_loader.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< -lpcap -lxdp2 -lcli -lsiphash -lbpf -lelf -lz

.PHONY: clean
clean:
	@rm -f $(TARGETS) $(BPF_TARGETS) $(TMPFILES)
