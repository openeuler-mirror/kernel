# SPDX-License-Identifier: GPL-2.0

include Makefile.arch

INSTALL ?= install
CLANG ?= clang
CC ?= gcc

BPFTOOL ?= bpftool
KERNEL_DIR ?= ../../../

MKFLAGS = -I$(KERNEL_DIR)/tools/lib -I$(KERNEL_DIR)/tools/include/uapi/ \
	-D__BPF_TRACING__ -D__TARGET_ARCH_${SRCARCH}
LDLIBBPF = -L$(KERNEL_DIR)/tools/lib/bpf/ -l:libbpf.a

all:
	$(CLANG) -O2 -g -Wall -target bpf -I. ${MKFLAGS} -c spe-mem-sampling-record.bpf.c -o spe-mem-sampling-record.bpf.o
	$(BPFTOOL) gen skeleton spe-mem-sampling-record.bpf.o > spe-mem-sampling-record.skel.h
	$(CC) -O2 -g -Wall ${MKFLAGS} spe-mem-sampling-record.user.c -o spe-mem-sampling-record ${LDLIBBPF} -lelf -lz --static

clean:
	rm -f spe-mem-sampling-record
	rm -f vmlinux.h
	rm -f *.o
	rm -f *.skel.h
