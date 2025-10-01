include ../config.mk

TOPTARGETS := all clean install

SUBDIRS = vstructs switch tables timer pvbuf parser
# TEMPORARILY SKIPPED: parse_dump (still causes segfault with complex parser.c)
# SUBDIRS += parse_dump
SUBDIRS += accelerator router bitmaps

$(TOPTARGETS) : $(SUBDIRS)

$(SUBDIRS):
	@make -C $@ $(MAKECMDGOALS)

.PHONY: $(TOPTARGETS) $(SUBDIRS)

