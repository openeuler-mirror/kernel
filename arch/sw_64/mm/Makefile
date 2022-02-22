# SPDX-License-Identifier: GPL-2.0
#
# Makefile for the linux sw_64-specific parts of the memory manager.
#

#ccflags-y := -Werror

obj-y	:= init.o fault.o  physaddr.o mmap.o

obj-$(CONFIG_NUMA)	+= numa.o
obj-$(CONFIG_HUGETLB_PAGE)      += hugetlbpage.o
obj-$(CONFIG_TRANSPARENT_HUGEPAGE)      += thp.o
