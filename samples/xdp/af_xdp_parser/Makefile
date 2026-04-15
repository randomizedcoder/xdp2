# Makefile for AF_XDP parser sample
#
# Builds the BPF XDP program that classifies packets and redirects
# them to AF_XDP sockets via XSKMAP.
#
# Set XDP2DIR to the install directory for XDP2:
#	make XDP2DIR=~/xdp2/install

XDP2DIR ?= /usr

INCDIR= $(XDP2DIR)/include
LIBDIR= $(XDP2DIR)/lib
BINDIR= $(XDP2DIR)/bin
CC= clang
CFLAGS= -I$(INCDIR)
CFLAGS+= -g -O2
LDFLAGS=

TARGETS= af_xdp_parser.xdp.o
TMPFILES= parser.xdp.h parser.o

.PHONY: all
all: $(TARGETS)

# Build parser.o first to catch compilation errors before running xdp2-compiler
parser.xdp.h: parser.c parser.o
	$(BINDIR)/xdp2-compiler -I$(INCDIR) -i $< -o $@

af_xdp_parser.xdp.o: af_xdp_parser.xdp.c parser.xdp.h
	$(CC) -x c -target bpf $(CFLAGS) $(LDFLAGS) -c -o $@ $<

.PHONY: clean
clean:
	@rm -f $(TARGETS) $(TMPFILES)
