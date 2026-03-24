include ../../../config.mk

INCDIR=$(INSTALLDIR)$(HDRDIR)/xdp2/proto_defs

SUBDIRS = ethernet ip transport tunnel security management storage \
          wireless bluetooth infiniband can netlink legacy other

.PHONY: all
all:

.PHONY: install
install:
	@for dir in $(SUBDIRS); do \
	    $(INSTALL) -m 0755 -d $(INCDIR)/$$dir; \
	    $(QUIET_INSTALL)$(INSTALL) -m 0644 $$dir/proto_*.h $(INCDIR)/$$dir/; \
	done

.PHONY: clean
clean:
