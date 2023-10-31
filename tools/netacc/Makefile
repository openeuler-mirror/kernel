# SPDX-License-Identifier: GPL-2.0

INSTALL ?= install
CLANG ?= clang
CC ?= gcc
BPFTOOL ?= bpftool
TOPDIR ?= ../..
MKFLAGS = -I$(TOPDIR)/tools/lib -I$(TOPDIR)/tools/include/uapi/
LDLIBBPF = -L$(TOPDIR)/tools/lib/bpf/ -l:libbpf.a

all:
	$(CLANG) -O2 -g -Wall -target bpf $(MKFLAGS) -c netaccsockmap.c -o netaccsockmap.o
	$(BPFTOOL) gen skeleton netaccsockmap.o > netaccsockmap.skel.h
	$(CC) -O2 -g -Wall $(MKFLAGS) netacc.c -o netacc $(LDLIBBPF) -lelf -lz

clean:
	rm -f netacc
	rm -f netaccsockmap.skel.h
	rm -f *.o

install:
	mkdir -p $(INSTALL_ROOT)/usr/sbin/tuned_acc/
	$(INSTALL) -m 755 net-acc $(INSTALL_ROOT)/usr/sbin/
	$(INSTALL) -m 755 netacc $(INSTALL_ROOT)/usr/sbin/tuned_acc/
