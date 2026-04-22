
# SPDX-License-Identifier: GPL-2.0
#
# Makefile for the Linux kernel UB device drivers.
#
ccflags-y += -I$(src)

ubagg-objs := ubagg_bitmap.o \
ubagg_log.o \
ubagg_seg.o \
ubagg_hash_table.o \
ubagg_ioctl.o \
ubagg_topo_info.o \
ubagg_netlink.o \
ubagg_main.o \
ubagg_jetty.o

obj-$(CONFIG_UB_URMA) += ubagg.o
