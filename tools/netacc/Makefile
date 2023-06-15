# SPDX-License-Identifier: GPL-2.0

INSTALL ?= install
CLANG ?= clang
CC ?= gcc
BPFTOOL ?= bpftool
TOPDIR = ../..
MKFLAGS = -I$(TOPDIR)/tools/lib
LDLIBBPF = -L$(TOPDIR)/tools/lib/bpf/ -l:libbpf.a

all:
	$(CLANG) -O2 -g -Wall -target bpf $(MKFLAGS) -c redissockmap.c -o redissockmap.o
	$(BPFTOOL) gen skeleton redissockmap.o > redis_acc.skel.h
	$(CC) -O2 -g -Wall $(MKFLAGS) redis_acc.c -o redis_acc $(LDLIBBPF) -lelf -lz

clean:
	rm -f redis_acc
	rm -f redis_acc.skel.h
	rm -f *.o

install:
	mkdir -p $(INSTALL_ROOT)/usr/sbin/tuned_acc/
	$(INSTALL) -m 755 net-acc $(INSTALL_ROOT)/usr/sbin/
	$(INSTALL) -m 755 redis_acc $(INSTALL_ROOT)/usr/sbin/tuned_acc/
