VERSION		= 0.2
CFLAGS		+= -g -Wall -Wextra
CPPFLAGS	+= $(shell pkg-config fuse --cflags) -DFUSE_USE_VERSION=26 \
		   -D_XOPEN_SOURCE=500 -MMD -MP -DVERSION=\"$(VERSION)\" \
		   -Ilibio
LDFLAGS		+= $(shell pkg-config fuse --libs)
SRCS		= compat.c error.c fuse.c hash.c main.c net.c pack.c
OBJDIR		:= obj-$(shell uname -s)-$(shell uname -r)
OBJS		:= $(SRCS:%.c=$(OBJDIR)/%.o)

.PHONY: all
all: $(OBJDIR) multifs
multifs: $(OBJS) libio/src/libio.a
	$(LINK.c) -o $@ $^

$(OBJDIR)/%.o: %.c Makefile
	$(COMPILE.c) $(OUTPUT_OPTION) $<

$(OBJDIR):
	mkdir -p $(OBJDIR)

.PHONY: libio/src/libio.a
libio/src/libio.a:
	cd libio/src && make

-include $(SRCS:%.c=$(OBJDIR)/%.d)

.PHONY: clean
clean:
	cd libio/src && make clean
	rm -f *~ core *.core multifs
	rm -rf $(OBJDIR)
