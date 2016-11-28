PROGS = esptun
LIBNETMAP =

CLEANFILES = $(PROGS) *.o

SRCDIR ?= ..
VPATH = $(SRCDIR)/src

INCLUDEDIR ?= ../include
NETMAPDIR ?= $(INCLUDEDIR)/netmap
SOQUEDIR ?= $(INCLUDEDIR)/soque
ESPIODIR ?= $(INCLUDEDIR)/espio

NO_MAN=
CFLAGS = -O2 -pipe
CFLAGS += -Werror -Wall -Wunused-function
CFLAGS += -I $(NETMAPDIR)/sys -I $(NETMAPDIR)/apps/include
CFLAGS += -I $(SOQUEDIR)/src
CFLAGS += -I $(ESPIODIR)/src
CFLAGS += -Wextra

LDLIBS += -ldl
ifeq ($(shell uname),Linux)
	LDLIBS += -lrt	# on linux
endif

PREFIX ?= /usr/local

all: $(PROGS)

clean:
	-@rm -rf $(CLEANFILES)

.PHONY: install
install: $(PROGS:%=install-%)

install-%:
	install -D $* $(DESTDIR)/$(PREFIX)/bin/$*
