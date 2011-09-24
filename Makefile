VERSION		= 0.1
CFLAGS		+= -g -Wall -Wextra
CPPFLAGS	+= $(shell pkg-config fuse --cflags) -DFUSE_USE_VERSION=26 \
		   -D_XOPEN_SOURCE=500 -MMD -MP -DVERSION=\"$(VERSION)\"
LDFLAGS		+= $(shell pkg-config fuse --libs)
SRCS		= compat.c err.c fuse.c hash.c main.c net.c pack.c
OBJDIR		:= obj-$(shell uname -s)-$(shell uname -r)
OBJS		:= $(SRCS:%.c=$(OBJDIR)/%.o)

all: $(OBJDIR) multifs
multifs: $(OBJS)
	$(LINK.c) -o $@ $^

$(OBJDIR)/%.o: %.c Makefile
	$(COMPILE.c) $(OUTPUT_OPTION) $<

$(OBJDIR):
	mkdir -p $(OBJDIR)

-include $(SRCS:%.c=$(OBJDIR)/%.d)

clean:
	rm -f *~ core *.core multifs
	rm -rf $(OBJDIR)
