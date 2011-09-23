VERSION		= 0.1
CFLAGS		+= -g -Wall -Wextra
CPPFLAGS	+= -I/opt/local/include -D_FILE_OFFSET_BITS=64 -D_XOPEN_SOURCE=500 -DFUSE_USE_VERSION=26 -DVERSION=\"$(VERSION)\"
LDFLAGS		+= -L/opt/local/lib -lfuse

all: multifs
multifs: main.o pack.o hash.o net.o fuse.o err.o compat.o
	$(LINK.c) -o $@ $^

clean:
	rm -f *~ *.o core *.core multifs
