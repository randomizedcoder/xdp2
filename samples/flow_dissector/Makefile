# Makefile for BPF flow dissector sample
#
# Builds:
#   flow_dissector.bpf.o  -- BPF flow dissector program
#   benchmark             -- Userspace benchmark (xdp2 vs kernel flowdis)
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
XCFLAGS+= -g -O2
XLDFLAGS=

CC= gcc
CFLAGS= -I$(INCDIR) -I$(XDP2_SRCDIR)/include
CFLAGS+= -g -O2
LDFLAGS= -L$(LIBDIR) -Wl,-rpath,$(LIBDIR)

TARGETS= flow_dissector.bpf.o benchmark
TMPFILES= parser.xdp.h parser.p.c parser.p.h parser.o

.PHONY: all
all: $(TARGETS)

# XDP2 compiler: generate BPF parser header
parser.xdp.h: parser.c parser.o
	$(BINDIR)/xdp2-compiler -I$(INCDIR) -i $< -o $@

# XDP2 compiler: generate userspace parser source
parser.p.c: parser.c parser.o
	$(BINDIR)/xdp2-compiler -I$(INCDIR) -i $< -o $@

# BPF flow dissector object
flow_dissector.bpf.o: flow_dissector.bpf.c parser.xdp.h common.h
	$(XCC) -x c -target bpf -I$(INCDIR) $(XCFLAGS) $(XLDFLAGS) -c -o $@ $<

# Userspace benchmark: links xdp2 parser + kernel flowdis
benchmark: benchmark.c parser.p.c common.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ benchmark.c parser.p.c \
		-lpcap -lxdp2 -lflowdis -lsiphash

.PHONY: clean
clean:
	@rm -f $(TARGETS) $(TMPFILES)
